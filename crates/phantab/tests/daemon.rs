//! The service over real HTTP: who may call, the routes, the bridge
//! upgrade, the single-instance lock and a clean stop.
// Test helpers fail by panicking, like the tests themselves (clippy.toml allows it only inside #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::{Runtime, fake_extension, request, try_rpc, upgrade, wait_until};
use serde_json::{Value, json};

#[test]
fn service_rejects_untrusted_callers_and_starts_without_a_browser() {
    let rt = Runtime::new();
    rt.write_config(&json!({ "profileDirectory": "test" }));
    let svc = rt.serve();
    let (port, token) = (svc.endpoint.port, svc.endpoint.token.clone());
    let auth = format!("Bearer {token}");
    assert_eq!(request(port, "POST", "/rpc", &[], b"{}").unwrap().status, 403);
    let untrusted = request(
        port,
        "POST",
        "/rpc",
        &[("Origin", "https://untrusted.invalid"), ("Authorization", &auth)],
        b"{}",
    )
    .unwrap();
    assert_eq!(untrusted.status, 403);
    let state = svc.rpc("status", &json!({}), "test");
    assert_eq!(state["result"]["connected"], json!(false));
    assert_eq!(state["result"]["lastError"], Value::Null);
    // Only the native host, with the bearer token and no Origin, may join as the bridge.
    assert_eq!(upgrade(port, &[], "/bridge").0, 403);
    assert_eq!(
        upgrade(port, &[("Authorization", &auth), ("Origin", "https://untrusted.invalid")], "/bridge").0,
        403
    );
    assert_eq!(upgrade(port, &[("Authorization", &auth), ("Upgrade", "websocket")], "/bridge").0, 403);
    assert_eq!(upgrade(port, &[("Authorization", &auth)], "/other").0, 403);
    assert_eq!(upgrade(port, &[("Authorization", &auth)], "/bridge").0, 101);
    let denied = request(
        port,
        "POST",
        "/viewer",
        &[("Authorization", "Bearer wrong"), ("Content-Type", "application/json")],
        br#"{"action":"frame"}"#,
    )
    .unwrap();
    assert_eq!(denied.status, 400);
    assert_eq!(denied.json(), json!({ "error": "This handoff has ended." }));
}

/// An early reject (403 for host, origin or token) is answered before the body is read. Closing over
/// those unread bytes made the OS send RST, and on Windows the RST discarded the 403 the client had
/// already received (CI: `ConnectionReset` on macOS, `ConnectionAborted` on Windows). The service now
/// drains the body first, so every reply arrives whole.
#[test]
fn early_rejections_always_deliver_the_whole_reply() {
    let rt = Runtime::new();
    let svc = rt.serve();
    let port = svc.endpoint.port;
    let bulk = vec![b' '; 16 * 1024];
    for i in 0..200 {
        let body: &[u8] = if i % 2 == 0 { b"{}" } else { &bulk };
        let unauthorized =
            request(port, "POST", "/rpc", &[], body).unwrap_or_else(|e| panic!("iteration {i}: {e}"));
        assert_eq!(unauthorized.status, 403, "iteration {i}");
        assert_eq!(unauthorized.json(), json!({ "error": "Unauthorized" }), "iteration {i}");
        let foreign = request(port, "POST", "/rpc", &[("Host", "evil.example")], body)
            .unwrap_or_else(|e| panic!("iteration {i}: {e}"));
        assert_eq!(foreign.status, 403, "iteration {i}");
        assert_eq!(foreign.json(), json!({ "error": "Invalid host" }), "iteration {i}");
    }
    // The body arrives after the service has decided: without the drain it closed first and the late
    // body drew the RST.
    for i in 0..20 {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let head = format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        stream.write_all(b"{}").unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap_or_else(|e| panic!("late body {i}: {e}"));
        let text = String::from_utf8_lossy(&raw);
        assert!(text.starts_with("HTTP/1.1 403"), "late body {i}: {text}");
        assert!(text.ends_with(r#"{"error":"Unauthorized"}"#), "late body {i}: {text}");
    }
}

/// SR-8, R14, L3: a `/viewer` key that views no handoff is answered before any body is read, and a body
/// that stalls is given up on, so neither can hold the service.
#[test]
fn an_unknown_viewer_key_reads_no_body_and_a_stalled_body_times_out() {
    let rt = Runtime::new();
    let svc = rt.serve();
    let (port, token) = (svc.endpoint.port, svc.endpoint.token.clone());
    let stalled = |path: &str, auth: &str, sent: &[u8]| {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(40))).unwrap();
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {auth}\r\nContent-Length: 100\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(sent).unwrap();
        let started = Instant::now();
        // The reply is one Content-Length response; read until its body is in.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        while !String::from_utf8_lossy(&raw).ends_with('}') {
            let n = stream.read(&mut chunk).unwrap_or_else(|e| panic!("{path}: no reply: {e}"));
            assert!(n > 0, "{path}: closed with no reply");
            raw.extend_from_slice(&chunk[..n]);
        }
        (String::from_utf8_lossy(&raw).into_owned(), started.elapsed())
    };
    let (reply, took) = stalled("/viewer", "not-a-viewer-key", b"");
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(reply.ends_with(r#"{"error":"This handoff has ended."}"#), "{reply}");
    assert!(took < Duration::from_secs(8), "answered only after {took:?}, so the body was waited for");
    let (reply, took) = stalled("/rpc", &token, b"{");
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(reply.ends_with(r#"{"error":"Request body timed out"}"#), "{reply}");
    assert!(took >= Duration::from_secs(9) && took < Duration::from_secs(30), "{took:?}");
    // The service is still there for a real call.
    assert_eq!(try_rpc(port, &token, "status", &json!({}), "test").unwrap().status, 200);
}

/// SR-8, R14, L3: the remote view's listener answers a `/viewer` key that views no link before any body
/// is read, as the local one does. It reaches the service only through the owner's route (Host and
/// identity checked first), so the request carries both.
#[test]
fn the_remote_listener_reads_no_body_for_an_unknown_viewer_key() {
    let rt = Runtime::new();
    let remote = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    rt.write_config(&json!({
        "profileDirectory": "test",
        "remoteViewer": {
            "listen": format!("127.0.0.1:{remote}"),
            "publicBaseUrl": "http://mypc.test:8490/",
            "trustedIdentity": { "header": "Tailscale-User-Login", "equals": "owner@example.test" },
        },
    }));
    let svc = rt.serve();
    let mut stream = None;
    assert!(wait_until(Duration::from_secs(10), || {
        stream = TcpStream::connect(("127.0.0.1", remote)).ok();
        stream.is_some()
    }));
    let mut stream = stream.unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(40))).unwrap();
    let head = "POST /viewer HTTP/1.1\r\nHost: mypc.test:8490\r\nTailscale-User-Login: owner@example.test\r\n\
                Authorization: Bearer not-a-link-token\r\nContent-Length: 100\r\n\r\n";
    stream.write_all(head.as_bytes()).unwrap();
    let started = Instant::now();
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    while !String::from_utf8_lossy(&raw).ends_with('}') {
        let n = stream.read(&mut chunk).unwrap_or_else(|e| panic!("no reply: {e}"));
        assert!(n > 0, "closed with no reply: {}", String::from_utf8_lossy(&raw));
        raw.extend_from_slice(&chunk[..n]);
    }
    let reply = String::from_utf8_lossy(&raw);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(reply.ends_with(r#"{"error":"This handoff has ended."}"#), "{reply}");
    let took = started.elapsed();
    assert!(took < Duration::from_secs(8), "answered only after {took:?}, so the body was waited for");
    // The refusal did not take the service down: the local listener still answers.
    assert_eq!(
        try_rpc(svc.endpoint.port, &svc.endpoint.token, "status", &json!({}), "test").unwrap().status,
        200
    );
}

#[test]
fn routes_headers_and_request_checks() {
    let rt = Runtime::new();
    let svc = rt.serve();
    let (port, token) = (svc.endpoint.port, svc.endpoint.token.clone());
    let auth = format!("Bearer {token}");

    let health = request(port, "GET", "/health", &[], b"").unwrap();
    assert_eq!(health.status, 200);
    assert_eq!(
        health.json(),
        json!({ "service": "phantab", "version": env!("CARGO_PKG_VERSION"), "protocol": 1 })
    );
    assert_eq!(health.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(health.header("x-content-type-options").as_deref(), Some("nosniff"));
    assert_eq!(health.header("referrer-policy").as_deref(), Some("no-referrer"));

    let view = request(port, "GET", "/view", &[], b"").unwrap();
    assert_eq!(view.status, 200);
    assert!(view.header("content-security-policy").unwrap().contains("frame-ancestors 'none'"));
    assert!(String::from_utf8_lossy(&view.body).contains("Return to agent"));

    // A page on another host name (DNS rebinding) is refused before anything else.
    assert_eq!(
        request(port, "GET", "/health", &[("Host", "evil.example")], b"").unwrap().json(),
        json!({ "error": "Invalid host" })
    );
    let same_origin = format!("http://127.0.0.1:{port}");
    assert_eq!(request(port, "GET", "/health", &[("Origin", &same_origin)], b"").unwrap().status, 200);
    assert_eq!(request(port, "GET", "/rpc", &[("Authorization", &auth)], b"").unwrap().status, 404);
    assert_eq!(
        request(port, "POST", "/rpc", &[("Authorization", "Bearer nope")], b"{}").unwrap().json(),
        json!({ "error": "Unauthorized" })
    );

    let call = |body: &[u8]| request(port, "POST", "/rpc", &[("Authorization", &auth)], body).unwrap();
    assert_eq!(
        call(br#"{"method":"toString","client":"x"}"#).json(),
        json!({ "error": "Invalid method or client" })
    );
    assert_eq!(call(br#"{"method":"status"}"#).json(), json!({ "error": "Invalid method or client" }));
    let long = json!({ "method": "status", "client": "x".repeat(151) }).to_string();
    assert_eq!(call(long.as_bytes()).json(), json!({ "error": "Invalid method or client" }));
    // SR-6 / SR-26: a client id is 1 to 150 characters.
    let empty = json!({ "method": "status", "client": "" }).to_string();
    assert_eq!(call(empty.as_bytes()).json(), json!({ "error": "Invalid method or client" }));
    let longest = json!({ "method": "heartbeat", "client": "x".repeat(150) }).to_string();
    assert_eq!(call(longest.as_bytes()).json(), json!({ "result": { "ok": true } }));
    assert_eq!(call(b"").json(), json!({ "error": "Unexpected end of JSON input" }));
    let big = vec![b' '; 65_537];
    let too_large = call(&big);
    assert_eq!(too_large.status, 400);
    assert_eq!(too_large.json(), json!({ "error": "Request too large" }));

    let status = svc.rpc("status", &json!({}), "test")["result"].clone();
    let keys: Vec<&str> = status.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "connected",
            "profile",
            "profileVerified",
            "agentPages",
            "lastError",
            "lastDisconnect",
            "connectionPolicy",
            "protocol",
            "source",
            "pid"
        ]
    );
    assert_eq!(status["pid"], json!(svc.endpoint.pid));
    assert_eq!(svc.rpc("heartbeat", &json!({}), "test"), json!({ "result": { "ok": true } }));
    assert_eq!(svc.rpc("disconnect", &json!({}), "test"), json!({ "result": { "retainedForResume": true } }));
    assert_eq!(svc.rpc("release", &json!({}), "test"), json!({ "result": { "released": true } }));
    assert_eq!(svc.rpc("pages", &json!({}), "test"), json!({ "result": [] }));
    assert_eq!(
        svc.rpc("open", &json!({ "url": "file:///etc/passwd" }), "test"),
        json!({ "error": "Only HTTP(S) website URLs are accepted." })
    );

    // The endpoint is the only place the token lives; health and status never carry it.
    assert!(!String::from_utf8_lossy(&health.body).contains(&token));
    assert!(!status.to_string().contains(&token));
}

#[test]
fn untrusted_hosts_near_miss_tokens_and_the_hello() {
    let rt = Runtime::new();
    let svc = rt.serve();
    let (port, token) = (svc.endpoint.port, svc.endpoint.token.clone());
    // SR-2: only `127.0.0.1:<port>` exactly.
    for host in [
        format!("localhost:{port}"),
        "127.0.0.1".to_owned(),
        format!("127.0.0.1:{}", port ^ 1),
        String::new(),
    ] {
        let reply = request(port, "GET", "/health", &[("Host", &host)], b"").unwrap();
        assert_eq!((reply.status, reply.json()), (403, json!({ "error": "Invalid host" })), "Host: {host}");
    }
    let mut bare = TcpStream::connect(("127.0.0.1", port)).unwrap();
    bare.write_all(b"GET /health HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    bare.read_to_end(&mut raw).unwrap();
    let raw = String::from_utf8_lossy(&raw);
    assert!(
        raw.starts_with("HTTP/1.1 403") && raw.ends_with(r#"{"error":"Invalid host"}"#),
        "no Host: {raw}"
    );
    // SR-1: loopback IPv4 only.
    assert!(TcpStream::connect(("::1", port)).is_err());
    // SR-4: every near miss of the token gets the same answer.
    for wrong in [
        format!("Bearer {}", &token[..token.len() - 1]),
        format!("Bearer {token}0"),
        // (A trailing space is HTTP whitespace the parser trims, so it is not a different token.)
        format!("Bearer  {token}"),
        format!("Bearer {}", token.to_uppercase()),
        format!("bearer {token}"),
        token.clone(),
        String::new(),
    ] {
        let reply = request(port, "POST", "/rpc", &[("Authorization", &wrong)], b"{}").unwrap();
        assert_eq!(
            (reply.status, reply.json()),
            (403, json!({ "error": "Unauthorized" })),
            "{}",
            wrong.len()
        );
    }
    // SR-13: the hello proves the token without carrying it.
    let nonce = "ab".repeat(32);
    let hello = request(port, "GET", &format!("/hello?nonce={nonce}"), &[], b"").unwrap();
    assert_eq!(hello.status, 200);
    let proof = hello.json()["proof"].as_str().unwrap().to_owned();
    assert!(phantab::hello::verify(&token, &phantab::hello::from_hex(&nonce).unwrap(), &proof));
    assert!(!String::from_utf8_lossy(&hello.body).contains(&token));
    assert_eq!(request(port, "GET", "/hello?nonce=ab", &[], b"").unwrap().status, 400);
    assert_eq!(request(port, "GET", "/hello", &[], b"").unwrap().status, 400);
}

#[test]
fn the_engine_lists_tabs_through_a_fake_extension() {
    let rt = Runtime::new();
    rt.install_extension_in_profile();
    let svc = rt.serve();
    let auth = format!("Bearer {}", svc.endpoint.token);
    let (code, stream) = upgrade(svc.endpoint.port, &[("Authorization", &auth)], "/bridge");
    assert_eq!(code, 101);
    let viewer = format!("http://127.0.0.1:{}/view#x", svc.endpoint.port);
    let _ext = fake_extension(stream.unwrap(), "one", move |m| match m["op"].as_str() {
        Some("tabs") => json!({ "id": m["id"], "result": [
            { "tabId": 7, "title": "Example", "url": "https://example.com/" },
            { "tabId": 8, "title": "Settings", "url": "chrome://settings" },
            { "tabId": 9, "title": "View", "url": viewer },
        ] }),
        _ => json!({ "id": m["id"], "error": "nope" }),
    });
    assert!(wait_until(
        Duration::from_secs(5),
        || svc.rpc("status", &json!({}), "test")["result"]["connected"] == json!(true)
    ));
    let status = svc.rpc("connect", &json!({}), "test")["result"].clone();
    assert_eq!(status["profileVerified"], json!(true));
    assert_eq!(status["lastError"], Value::Null);
    assert_eq!(
        svc.rpc("tabs", &json!({}), "cli:task"),
        json!({ "result": [{ "tabId": "7", "title": "Example", "url": "https://example.com/" }] })
    );
}

#[test]
fn a_second_service_on_the_same_runtime_exits_and_the_first_keeps_running() {
    let rt = Runtime::new();
    let svc = rt.serve();
    let second = rt.command(&["serve"]).output().unwrap();
    assert!(second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("phantab service already running"));
    assert_eq!(rt.wait_endpoint().port, svc.endpoint.port);
}

#[test]
fn shutdown_removes_the_endpoint_and_exits() {
    let rt = Runtime::new();
    let mut svc = rt.serve();
    assert!(rt.path().join("service.lock").exists());
    assert_eq!(svc.rpc("shutdown", &json!({}), "test"), json!({ "result": { "stopping": true } }));
    let status = svc.wait_exit(Duration::from_secs(10)).expect("the service exits");
    assert!(status.success());
    assert!(!rt.path().join("endpoint.json").exists());
    // SR-12: the lock file stays, as after a kill; only the OS lock goes, and the next start takes it.
    assert!(rt.path().join("service.lock").exists());
    let next = rt.serve();
    assert_ne!(next.endpoint.token, svc.endpoint.token);
}

#[test]
fn a_missing_config_stops_the_service_with_nodes_wording() {
    let rt = Runtime::new();
    std::fs::remove_file(rt.path().join("config.json")).unwrap();
    let out = rt.command(&["serve"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ENOENT: no such file or directory, open '"));
    assert!(!rt.path().join("endpoint.json").exists());
}

#[cfg(unix)]
#[test]
fn the_endpoint_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let rt = Runtime::new();
    let _svc = rt.serve();
    let mode = std::fs::metadata(rt.path().join("endpoint.json")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// SR-10, SR-11: the service makes its runtime dir owner-only at start (protected DACL on Windows,
/// 0700 on macOS), and the endpoint file inside is owner-only too.
#[test]
fn the_runtime_dir_and_endpoint_are_owner_only() {
    use phantab_window::secure_dir::inspect;
    let rt = Runtime::new();
    let _svc = rt.serve();
    let dir = inspect(rt.path()).unwrap();
    assert!(dir.owned_by_me && dir.owner_only && dir.protected, "{dir:?}");
    let endpoint = inspect(&rt.path().join("endpoint.json")).unwrap();
    assert!(endpoint.owner_only, "{endpoint:?}");
}

/// SR-48, L1: an installed binary (`<runtime>/bin`, `config.json` beside it) whose folder was opened to
/// everyone has it made owner-only again when the service starts from it.
#[test]
fn the_installed_binary_folder_is_made_owner_only_at_start() {
    use phantab_window::secure_dir::inspect;
    let rt = Runtime::new();
    let bin = rt.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let exe = bin.join(format!("phantab{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(common::BIN, &exe).unwrap();
    #[cfg(windows)]
    {
        let icacls = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("icacls.exe");
        let out =
            std::process::Command::new(icacls).arg(&bin).args(["/grant", "*S-1-1-0:(OI)(CI)RX"]).output();
        assert!(out.unwrap().status.success());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(!inspect(&bin).unwrap().owner_only);
    let home = rt.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut child = std::process::Command::new(&exe)
        .arg("serve")
        .env("PHANTAB_RUNTIME", rt.path())
        .env("LOCALAPPDATA", rt.path().join("localappdata"))
        .env("HOME", &home)
        .env_remove("RUST_LOG")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let _endpoint = rt.wait_endpoint();
    let after = inspect(&bin).unwrap();
    // The service this test started, and only it.
    let _ = child.kill();
    let _ = child.wait();
    assert!(after.owned_by_me && after.owner_only && after.protected, "{after:?}");
}

/// SR-10: a runtime that is a junction (Windows) or symlink (macOS) stops the service with a named
/// error before it writes anything.
#[test]
fn a_linked_runtime_dir_refuses_to_start() {
    let rt = Runtime::new();
    let target = rt.path().join("real");
    std::fs::create_dir_all(&target).unwrap();
    let link = rt.path().join("linked");
    #[cfg(windows)]
    {
        let cmd = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let made =
            std::process::Command::new(cmd).args(["/C", "mklink", "/J"]).arg(&link).arg(&target).output();
        assert!(made.unwrap().status.success());
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let out = rt.command(&["serve"]).env("PHANTAB_RUNTIME", &link).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("is a link"), "{stderr}");
    assert!(!target.join("endpoint.json").exists() && !target.join("service.lock").exists());
    if std::fs::remove_dir(&link).is_err() {
        std::fs::remove_file(&link).unwrap();
    }
}

/// SR-12: starts racing on one runtime give one listener; the losers exit saying so. After the winner is
/// killed outright (no clean stop, the lock file left behind), the next start succeeds.
#[test]
fn racing_starts_give_one_listener_and_a_killed_service_is_replaced() {
    let rt = Runtime::new();
    let mut children: Vec<std::process::Child> = (0..4)
        .map(|_| {
            rt.command(&["serve"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    let first = rt.wait_endpoint();
    assert!(wait_until(Duration::from_secs(15), || {
        children.iter_mut().map(|c| c.try_wait().unwrap()).filter(Option::is_none).count() == 1
    }));
    let mut winner =
        children.into_iter().find_map(|mut c| c.try_wait().unwrap().is_none().then_some(c)).unwrap();
    assert_eq!(winner.id(), first.pid);
    winner.kill().unwrap();
    winner.wait().unwrap();
    assert!(rt.path().join("service.lock").exists(), "a kill leaves the lock file; only the OS lock goes");
    let next = rt.serve();
    assert_ne!(next.endpoint.pid, first.pid);
    assert_ne!(next.endpoint.token, first.token);
}

/// SR-5, L3: the token never reaches an output. The service runs at `RUST_LOG=trace` with its own
/// output captured, gets good and bad calls, the CLI reports on it at `RUST_LOG=trace`, and it stops;
/// no byte of any of that holds the token.
#[test]
fn the_token_never_reaches_an_output() {
    use std::process::Stdio;
    let rt = Runtime::new();
    let child = rt
        .command(&["serve"])
        .env("RUST_LOG", "trace")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let ep = rt.wait_endpoint();
    let (port, token) = (ep.port, ep.token.clone());
    let auth = format!("Bearer {token}");
    let mut replies = Vec::new();
    for (method, path, headers, body) in [
        ("GET", "/health", vec![], &b""[..]),
        ("GET", &*format!("/hello?nonce={}", "cd".repeat(32)), vec![], b""),
        ("POST", "/rpc", vec![("Authorization", auth.as_str())], br#"{"method":"status","client":"t"}"#),
        ("POST", "/rpc", vec![("Authorization", auth.as_str())], br#"{"method":"nope","client":"t"}"#),
        (
            "POST",
            "/rpc",
            vec![("Authorization", auth.as_str())],
            br#"{"method":"open","client":"t","args":{"url":"file:///x"}}"#,
        ),
        ("POST", "/rpc", vec![("Authorization", auth.as_str())], b"{"),
        ("POST", "/rpc", vec![("Authorization", "Bearer 00")], b"{}"),
        ("GET", "/bridge", vec![("Authorization", auth.as_str())], b""),
        ("GET", "/view", vec![], b""),
    ] {
        let r = request(port, method, path, &headers, body).unwrap();
        replies.push(String::from_utf8_lossy(&r.body).into_owned());
    }
    let mut cli = String::new();
    for args in [&["doctor"][..], &["status"], &["tabs"], &["pages"]] {
        let out = rt
            .command(args)
            .env("RUST_LOG", "trace")
            .env("PHANTAB_CLIENT", "t")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        cli.push_str(&String::from_utf8_lossy(&out.stdout));
        cli.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    assert!(cli.contains("phantab") || cli.contains("connected"), "the CLI said nothing: {cli}");
    // An MCP session at TRACE: its calls and kept connection, stdout and stderr both.
    let mcp = mcp_session_output(&rt);
    assert!(mcp.contains("connected"), "the MCP session said nothing: {mcp}");
    let _ =
        request(port, "POST", "/rpc", &[("Authorization", &auth)], br#"{"method":"shutdown","client":"t"}"#);
    let out = child.wait_with_output().unwrap();
    let service = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    for (what, text) in [("service output", &service), ("CLI output", &cli), ("MCP output", &mcp)] {
        assert!(!text.contains(&token), "the token is in the {what}");
    }
    for (i, reply) in replies.iter().enumerate() {
        assert!(!reply.contains(&token), "the token is in reply {i}");
    }
}

/// `phantab mcp` at `RUST_LOG=trace` through a few calls on its kept connection, then closed: all it
/// wrote to stdout and stderr.
fn mcp_session_output(rt: &Runtime) -> String {
    use std::io::{BufRead as _, BufReader};
    use std::process::Stdio;
    let mut child = rt
        .command(&["mcp"])
        .env("RUST_LOG", "trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let mut out = String::new();
    let mut ask = |message: Value, answered: bool| {
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
        if answered {
            stdout.read_line(&mut out).unwrap();
        }
    };
    ask(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } } }),
        true,
    );
    ask(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }), false);
    for (id, name) in
        [(2, "browser_status"), (3, "browser_pages"), (4, "browser_status"), (5, "browser_tabs")]
    {
        ask(
            json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": {} } }),
            true,
        );
    }
    drop(ask);
    drop(stdin);
    let _ = child.wait();
    let _ = stdout.read_to_string(&mut out);
    out.push_str(&errors.join().unwrap());
    out
}
