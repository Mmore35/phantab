//! The CLI and native-host modes of the real binary. Each starts the service itself, detached, as
//! it does for the owner; the runtime's drop stops it.
// Test helpers fail by panicking, like the tests themselves (clippy.toml allows it only inside #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read as _, Write as _};
use std::process::Stdio;
use std::time::Duration;

use common::{Runtime, frame, read_frame, wait_until};
use serde_json::{Value, json};

/// Runs one CLI call to its exit and returns what it wrote.
///
/// Output goes to pipes, which reach their end when the call exits: the service the call starts holds
/// none of its std handles (on Windows, `phantab_window::disable_std_handle_inheritance` at the top of
/// main sees to that).
fn run(rt: &Runtime, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = rt.command(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap();
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    let (code, out, err) = (out.status.code().unwrap_or(-1), text(out.stdout), text(out.stderr));
    if format!("{out}{err}").contains("failed to start") {
        diagnose_serve(rt);
    }
    (code, out, err)
}

/// The detached service writes nowhere, so when a client says it did not start, run `serve` in the
/// foreground with the environment a client gives it and print what it said (shown with the failure).
fn diagnose_serve(rt: &Runtime) {
    let mut cmd = rt.command(&["serve"]);
    let set: Vec<(std::ffi::OsString, Option<std::ffi::OsString>)> =
        cmd.get_envs().map(|(k, v)| (k.to_owned(), v.map(ToOwned::to_owned))).collect();
    let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
        std::env::vars_os().collect();
    for (k, v) in set {
        match v {
            Some(v) => env.insert(k, v),
            None => env.remove(&k),
        };
    }
    cmd.env_clear();
    for (k, v) in env {
        if phantab::runtime::service_env_allowed(&k.to_string_lossy()) {
            cmd.env(k, v);
        }
    }
    let started = std::time::Instant::now();
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    while started.elapsed() < Duration::from_secs(15) {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if rt.endpoint().is_some() {
            eprintln!("diagnose: serve wrote its endpoint after {} ms", started.elapsed().as_millis());
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if child.try_wait().unwrap().is_none() {
        let _ = child.kill();
    }
    let out = child.wait_with_output().unwrap();
    eprintln!(
        "diagnose: serve {} after {} ms; stdout {:?}; stderr {:?}",
        out.status,
        started.elapsed().as_millis(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_calls_start_the_service_and_need_a_client_for_page_work() {
    let rt = Runtime::new();
    let (code, out, _) = run(&rt, &["doctor"], &[]);
    assert_eq!(code, 0);
    let state: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(state["connected"], json!(false));
    assert!(out.starts_with("{\n  \"connected\": false,"), "pretty, in its documented key order: {out}");
    assert!(rt.endpoint().is_some());

    let (code, _, err) = run(&rt, &["open", r#"{"url":"https://example.com"}"#], &[]);
    assert_eq!(code, 1);
    assert!(err.contains("Set PHANTAB_CLIENT to a unique stable task ID"), "{err}");

    let (code, out, _) = run(&rt, &["pages"], &[("PHANTAB_CLIENT", "task-1")]);
    assert_eq!((code, out.trim()), (0, "[]"));
    // An agent session's own id works too.
    let (code, _, err) =
        run(&rt, &["open", r#"{"url":"file:///etc/passwd"}"#], &[("CODEX_THREAD_ID", "task-1")]);
    assert_eq!((code, err.trim()), (1, "Only HTTP(S) website URLs are accepted."));

    let (code, _, err) = run(&rt, &["pages", "{nope"], &[("PHANTAB_CLIENT", "task-1")]);
    assert_eq!(code, 1);
    assert!(err.contains("Invalid JSON"), "{err}");
    let (code, _, err) = run(&rt, &["toString"], &[("PHANTAB_CLIENT", "task-1")]);
    assert_eq!((code, err.trim()), (1, "Invalid method or client"));
}

/// THREAT-MODEL SR-13, L3: a stale endpoint whose port another process now holds. The client asks
/// that listener to prove the token, it cannot, and the client starts a fresh service instead. The
/// listener never sees an `Authorization` header (nor the token anywhere).
#[test]
fn a_listener_that_cannot_prove_the_token_never_receives_it() {
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    let rt = Runtime::new();
    let fake = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = fake.local_addr().unwrap().port();
    fake.set_nonblocking(true).unwrap();
    let token = "5e".repeat(32);
    std::fs::write(
        rt.path().join("endpoint.json"),
        json!({ "port": port, "token": token, "pid": 1, "protocol": 1, "source": "stale" }).to_string(),
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let listener = std::thread::spawn({
        let (seen, stop) = (Arc::clone(&seen), Arc::clone(&stop));
        move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok((mut conn, _)) = fake.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                conn.set_nonblocking(false).unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut buf = vec![0u8; 16 * 1024];
                let n = conn.read(&mut buf).unwrap_or(0);
                seen.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned());
                // Answers everything as a service would, with a proof for some other token.
                let body = format!(r#"{{"service":"phantab","protocol":1,"proof":"{}"}}"#, "00".repeat(32));
                let _ = write!(
                    conn,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        }
    });
    let (code, out, err) = run(&rt, &["doctor"], &[]);
    stop.store(true, Ordering::SeqCst);
    listener.join().unwrap();
    assert_eq!(code, 0, "{out}{err}");
    let fresh = rt.endpoint().unwrap();
    assert_ne!(fresh["port"], json!(port), "a fresh service took over");
    let seen = seen.lock().unwrap();
    assert!(
        seen.iter().any(|r| r.starts_with("GET /hello?nonce=")),
        "the client asked for the hello: {seen:?}"
    );
    for r in seen.iter() {
        assert!(!r.to_ascii_lowercase().contains("authorization"), "{r}");
        assert!(!r.contains(&token), "{r}");
    }
}

/// sec-local-2 for the native host, THREAT-MODEL SR-13: a listener that proves the token on one
/// connection and then closes it. The host's `/bridge` join goes only on the proven connection, so with
/// that gone the host refuses; it never opens another connection to send the token on.
#[test]
fn the_host_sends_the_token_only_on_the_connection_that_proved_it() {
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    let rt = Runtime::new();
    let fake = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = fake.local_addr().unwrap().port();
    fake.set_nonblocking(true).unwrap();
    let token = "6f".repeat(32);
    std::fs::write(
        rt.path().join("endpoint.json"),
        json!({ "port": port, "token": token, "pid": 1, "protocol": 1, "source": "fake" }).to_string(),
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let listener = std::thread::spawn({
        let (seen, stop, token) = (Arc::clone(&seen), Arc::clone(&stop), token.clone());
        move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok((mut conn, _)) = fake.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                conn.set_nonblocking(false).unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut buf = vec![0u8; 16 * 1024];
                let n = conn.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                // The right proof, then the connection closes.
                let target = request.split(' ').nth(1).unwrap_or_default();
                let proof = phantab::hello::nonce_of(target)
                    .and_then(|nonce| phantab::hello::proof(&token, &nonce))
                    .unwrap_or_default();
                seen.lock().unwrap().push(request);
                let body = format!(r#"{{"proof":"{proof}","keep":120}}"#);
                let _ = write!(
                    conn,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        }
    });
    let origin = format!("chrome-extension://{}/", *phantab::bridge::EXTENSION_ID);
    let mut host = rt.command(&[&origin]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let _to_host = host.stdin.take().unwrap();
    let refused = read_frame(&mut host.stdout.take().unwrap()).unwrap();
    let code = host.wait().unwrap().code();
    stop.store(true, Ordering::SeqCst);
    listener.join().unwrap();
    let endpoint = rt.endpoint().unwrap();
    // The fake's endpoint names no service of ours: the runtime's drop must not stop its pid.
    if endpoint["port"] == json!(port) {
        std::fs::remove_file(rt.path().join("endpoint.json")).unwrap();
    }
    let text = refused["refused"].as_str().unwrap_or_default();
    assert!(text.starts_with("Browser service unreachable:"), "{refused}");
    assert_eq!(code, Some(1));
    assert_eq!(endpoint["port"], json!(port), "no fresh service: the proof held");
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "the host asked for the hello");
    for r in seen.iter() {
        assert!(r.starts_with("GET /hello?nonce="), "{r}");
        assert!(!r.to_ascii_lowercase().contains("authorization"), "{r}");
        assert!(!r.contains(&token), "{r}");
    }
}

/// What the owner types back at sign-in-clear's prompt, in a test build at a terminal (stdin is null here,
/// as in an agent's shell).
fn typed(target: &str) -> [(&'static str, String); 2] {
    [("PHANTAB_TEST_TERMINAL", "1".to_owned()), ("PHANTAB_TEST_TYPED", target.to_owned())]
}

fn clear(rt: &Runtime, target: &str, env: &[(&str, String)]) -> (i32, String, String) {
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    run(rt, &["sign-in-clear", target], &env)
}

/// The last line sign-in-clear wrote to stderr (the prompt comes first).
fn last_line(err: &str) -> &str {
    err.trim().lines().last().unwrap_or_default().trim()
}

const STOPPED: &str = r#"{"version":1,"accounts":{"a":{"hosts":["example.com"],"submits":[],"stopped":{"reason":"x","at":"t"}}}}"#;

#[test]
fn sign_in_clear_works_without_a_service() {
    let rt = Runtime::new();
    let guard = rt.path().join("sign-in-guard.json");
    std::fs::write(&guard, STOPPED).unwrap();
    let (code, _, err) = run(&rt, &["sign-in-clear"], &[]);
    assert_eq!((code, err.trim()), (1, "Name a host, or all."));
    let (code, out, err) = clear(&rt, "example.com", &typed("example.com"));
    assert_eq!((code, out.trim()), (0, r#"{"cleared":1}"#));
    assert!(err.contains("type example.com and press Enter"), "{err}");
    std::fs::write(&guard, "{broken").unwrap();
    let (code, _, err) = clear(&rt, "example.com", &typed("example.com"));
    assert_eq!((code, last_line(&err)), (1, "The guard file is damaged: run sign-in-clear all."));
    assert_eq!(clear(&rt, "all", &typed(" all ")).1.trim(), r#"{"cleared":"all"}"#);
    assert!(!guard.exists());
    assert!(rt.endpoint().is_none(), "sign-in-clear started a service");
}

/// The wake command: `check-wait` refuses a malformed token, and otherwise exits 0 on every end, a
/// service that is down or a token no hand-off holds included, since its exit is what wakes the agent.
/// It starts no service of its own.
#[test]
fn check_wait_ends_on_every_end_and_starts_no_service() {
    let rt = Runtime::new();
    let token = "ab".repeat(24);
    let (code, _, err) = run(&rt, &["check-wait", "abc"], &[]);
    assert_eq!((code, err.trim()), (1, "check-wait takes the token from a verification's wake command."));
    let (code, out, _) = run(&rt, &["check-wait", &token], &[]);
    assert_eq!((code, out.trim()), (0, "verification gone: the browser service is not running"));
    assert!(rt.endpoint().is_none(), "check-wait started a service");

    assert_eq!(run(&rt, &["doctor"], &[]).0, 0);
    assert!(rt.endpoint().is_some());
    let (code, out, _) = run(&rt, &["check-wait", &token], &[]);
    assert_eq!((code, out.trim()), (0, "verification gone"));
}

/// sec-agent-5: a plain non-interactive shell, an agent's included, has no terminal, so sign-in-clear
/// refuses it. A determined same-user process could still drive one (THREAT-MODEL R20).
#[test]
fn sign_in_clear_needs_a_terminal() {
    let rt = Runtime::new();
    let guard = rt.path().join("sign-in-guard.json");
    std::fs::write(&guard, STOPPED).unwrap();
    for target in ["example.com", "all"] {
        let (code, out, err) = clear(&rt, target, &[("PHANTAB_TEST_TERMINAL", "0".to_owned())]);
        assert_eq!(
            (code, out.as_str(), err.trim()),
            (
                1,
                "",
                "sign-in-clear lifts a sign-in stop, which is yours to do: run it yourself in a terminal window."
            )
        );
        assert_eq!(std::fs::read_to_string(&guard).unwrap(), STOPPED, "the stop stands");
    }
    assert!(rt.endpoint().is_none(), "sign-in-clear started a service");
}

/// At a terminal, the owner must type back exactly what is cleared. Nothing typed (here a null stdin
/// the hidden read refuses) or anything else clears nothing.
#[test]
fn sign_in_clear_needs_the_target_typed_back() {
    let rt = Runtime::new();
    let guard = rt.path().join("sign-in-guard.json");
    std::fs::write(&guard, STOPPED).unwrap();
    for (target, said) in
        [("example.com", "all"), ("all", "example.com"), ("example.com", ""), ("all", "ALL")]
    {
        let (code, out, err) = clear(&rt, target, &typed(said));
        assert_eq!(
            (code, out.as_str(), last_line(&err)),
            (1, "", format!("That was not {target}: nothing was cleared.").as_str())
        );
        assert_eq!(std::fs::read_to_string(&guard).unwrap(), STOPPED, "the stop stands");
    }
    for target in ["example.com", "all"] {
        let (code, out, err) = clear(&rt, target, &[("PHANTAB_TEST_TERMINAL", "1".to_owned())]);
        assert_eq!((code, out.as_str()), (1, ""), "{err}");
        assert!(last_line(&err).starts_with("Could not read what you typed ("), "{err}");
        assert!(last_line(&err).ends_with("): nothing was cleared."), "{err}");
        assert_eq!(std::fs::read_to_string(&guard).unwrap(), STOPPED, "the stop stands");
    }
    assert!(rt.endpoint().is_none(), "sign-in-clear started a service");
}

/// THREAT-MODEL SR-49: closing the owner's Chrome is the owner's. `chrome restart-quiet` needs a terminal
/// and a typed y, and the service's `restart_quiet` is never called by name. With quiet debugging off,
/// the service refuses and touches no Chrome.
#[test]
fn chrome_restart_quiet_is_the_owners_at_a_terminal() {
    let rt = Runtime::new();
    let restart = |env: &[(&str, &str)]| run(&rt, &["chrome", "restart-quiet"], env);
    let (code, _, err) = run(&rt, &["chrome"], &[]);
    assert_eq!((code, err.trim()), (1, "Usage: phantab chrome restart-quiet"));
    let (code, _, err) = run(&rt, &["chrome", "restart-quiet", "--yes"], &[]);
    assert_eq!((code, err.trim()), (1, "Usage: phantab chrome restart-quiet"));
    let (code, out, err) = restart(&[("PHANTAB_TEST_TERMINAL", "0")]);
    assert_eq!(
        (code, out.as_str(), err.trim()),
        (
            1,
            "",
            "chrome restart-quiet closes your Chrome, which is yours to do: run it yourself in a terminal window."
        )
    );
    for said in ["", "n", "no", "maybe"] {
        let (code, out, err) = restart(&[("PHANTAB_TEST_TERMINAL", "1"), ("PHANTAB_TEST_TYPED", said)]);
        // The prompt and the answer share a line here: nothing typed echoes the Enter.
        assert_eq!((code, out.as_str()), (1, ""), "{said:?}");
        assert!(
            err.contains("Restart Chrome now? [y/N] ") && err.trim().ends_with("Nothing was restarted."),
            "{err}"
        );
    }
    let (code, _, err) = run(&rt, &["restart_quiet"], &[]);
    assert_eq!((code, err.trim()), (1, "Run phantab chrome restart-quiet."));
    assert!(rt.endpoint().is_none(), "nothing reached a service");

    let (code, out, err) = restart(&[("PHANTAB_TEST_TERMINAL", "1"), ("PHANTAB_TEST_TYPED", "y")]);
    assert_eq!((code, out.as_str()), (1, ""), "{err}");
    assert!(err.contains("[y/N] Quiet debugging is off, so a restart would not hide the bar."), "{err}");
}

#[test]
fn the_native_host_serves_only_our_extension() {
    let rt = Runtime::new();
    let mut child = rt
        .command(&["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let refused = read_frame(&mut stdout).unwrap();
    assert_eq!(refused, json!({ "refused": "This native host serves only the phantab bridge extension." }));
    assert_eq!(child.wait().unwrap().code(), Some(1));
    assert!(rt.endpoint().is_none());
}

#[test]
fn chrome_starts_the_service_through_its_native_host_and_the_service_outlives_it() {
    let rt = Runtime::new();
    rt.install_extension_in_profile();
    let origin = format!("chrome-extension://{}/", *phantab::bridge::EXTENSION_ID);
    // Chrome on Windows adds the parent window; the host ignores it.
    let mut host = rt
        .command(&[&origin, "--parent-window=0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut to_host = host.stdin.take().unwrap();
    let mut from_host = host.stdout.take().unwrap();
    to_host
        .write_all(&frame(&json!({ "hello": { "version": "1.0.0", "protocol": 1, "instance": "one" } })))
        .unwrap();
    to_host.flush().unwrap();
    // Every frame comes through a reader thread with a timeout, so a host that stops sending cannot hang
    // the test.
    let frames = {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            while let Some(m) = read_frame(&mut from_host) {
                if tx.send(m).is_err() {
                    break;
                }
            }
        });
        rx
    };
    assert_eq!(
        frames.recv_timeout(Duration::from_secs(30)).ok(),
        Some(json!({ "welcome": true, "events": phantab_cdp::EVENTS }))
    );

    let ep = rt.wait_endpoint();
    assert_ne!(ep.pid, host.id(), "the host started a separate service");
    assert!(wait_until(Duration::from_secs(5), || common::rpc(
        ep.port,
        &ep.token,
        "status",
        &json!({}),
        "test"
    )["result"]["connected"]
        == json!(true)));

    // An op crosses the host both ways unchanged. Its answer comes through a channel too, so an RPC that
    // never returns fails the test in 30 s instead of hanging it (review r7 R7-9).
    let answer = {
        let ep = ep.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(common::rpc(ep.port, &ep.token, "tabs", &json!({}), "cli:t"));
        });
        rx
    };
    // Bounded: a service that refuses the bridge still pings, and answering forever once hung a macOS run for 30 min.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let op = loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let m = frames.recv_timeout(left);
        assert!(m.is_ok() && !left.is_zero(), "no op reached the host in 30 s ({m:?})");
        let m = m.unwrap();
        if m["op"] == "ping" {
            to_host.write_all(&frame(&json!({ "id": m["id"], "result": {} }))).unwrap();
            continue;
        }
        break m;
    };
    assert_eq!(op["op"], json!("tabs"));
    let tabs = json!([{ "tabId": 3, "title": "Ünïcode", "url": "https://example.com/" }]);
    to_host.write_all(&frame(&json!({ "id": op["id"], "result": tabs }))).unwrap();
    to_host.flush().unwrap();
    assert_eq!(
        answer.recv_timeout(Duration::from_secs(30)).ok(),
        Some(json!({ "result": [{ "tabId": "3", "title": "Ünïcode", "url": "https://example.com/" }] }))
    );

    // Chrome closing the port ends the host; the service records why and keeps running.
    drop(to_host);
    assert!(
        wait_until(Duration::from_secs(10), || host.try_wait().ok().flatten().is_some()),
        "the host exits with Chrome"
    );
    let status = || common::rpc(ep.port, &ep.token, "status", &json!({}), "test")["result"].clone();
    assert!(wait_until(Duration::from_secs(5), || status()["lastDisconnect"].is_object()));
    let state = status();
    assert_eq!(state["connected"], json!(false));
    assert!(state["lastDisconnect"]["reason"].as_str().unwrap().contains("closed the connection"), "{state}");
    assert!(common::alive(ep.pid));
}

/// SR-14, L3: the service a client starts runs in the runtime dir, not the folder the client was started
/// from, which it would otherwise hold open; a relative runtime override still names the same dir.
#[test]
fn a_started_service_runs_in_the_runtime_dir() {
    let rt = Runtime::new();
    let runtime = rt.path().canonicalize().unwrap();
    let parent = runtime.parent().unwrap();
    let relative = runtime.file_name().unwrap().to_string_lossy().into_owned();
    // The client starts in `parent` with the runtime named relative to it.
    let out = rt
        .command(&["doctor"])
        .env("PHANTAB_RUNTIME", &relative)
        .current_dir(parent)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let pid = u32::try_from(rt.endpoint().unwrap()["pid"].as_u64().unwrap()).unwrap();
    let mut sys = sysinfo::System::new().unwrap();
    let spid = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[spid]),
        true,
        sysinfo::ProcessRefreshKind::nothing().with_cwd(sysinfo::UpdateKind::Always),
    );
    let cwd = sys.process(spid).unwrap().cwd().unwrap().canonicalize().unwrap();
    assert_eq!(cwd, runtime);
    // A client from another folder, with the runtime named in full, finds the same service.
    let (code, out, err) = run(&rt, &["doctor"], &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(u32::try_from(rt.endpoint().unwrap()["pid"].as_u64().unwrap()).unwrap(), pid);
}

/// SR-14, L3: the service a client starts gets a rebuilt environment. The client's `RUST_LOG` and an
/// unrelated `FOO` stay with the client; the runtime override, `LANG`, the proxy variables (for `bw`,
/// both cases where the names differ by case) and, in this test build, `PHANTAB_TEST_*` pass. Read from
/// the running service's own environment block.
#[test]
fn a_clients_environment_stays_with_the_client() {
    let rt = Runtime::new();
    let mut env = vec![
        ("RUST_LOG", "trace"),
        ("FOO", "1"),
        ("PHANTAB_TEST_MARK", "1"),
        ("LANG", "C"),
        ("HTTPS_PROXY", "http://127.0.0.1:9"),
    ];
    // On Windows the two cases are one variable.
    if !cfg!(windows) {
        env.push(("https_proxy", "http://127.0.0.1:9"));
    }
    let (code, out, err) = run(&rt, &["doctor"], &env);
    assert_eq!(code, 0, "{out}{err}");
    let pid = u32::try_from(rt.endpoint().unwrap()["pid"].as_u64().unwrap()).unwrap();
    let mut sys = sysinfo::System::new().unwrap();
    let spid = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[spid]),
        true,
        sysinfo::ProcessRefreshKind::nothing().with_environ(sysinfo::UpdateKind::Always),
    );
    let names: Vec<String> = sys
        .process(spid)
        .unwrap()
        .environ()
        .iter()
        .filter_map(|kv| kv.to_string_lossy().split_once('=').map(|(k, _)| k.to_owned()))
        .filter(|k| !k.is_empty())
        // macOS: sysinfo reads the kernel's argument area, where the environment is followed by the
        // `apple[]` strings (`ptr_munge=`, `executable_path=`, `main_stack=`, …). Those are not environment
        // variables, and their keys are lowercase. The only lowercase names on the allow-list are the proxy
        // variables, so a lowercase key is dropped unless the allow-list takes it.
        .filter(|k| {
            !(cfg!(target_os = "macos")
                && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
                && !phantab::runtime::service_env_allowed(k))
        })
        .collect();
    assert!(names.iter().any(|k| k == "PHANTAB_RUNTIME"), "{names:?}");
    assert!(names.iter().any(|k| k == "PHANTAB_TEST_MARK"), "{names:?}");
    assert!(names.iter().any(|k| k == "LANG"), "{names:?}");
    assert!(names.iter().any(|k| k.eq_ignore_ascii_case("HTTPS_PROXY")), "{names:?}");
    if !cfg!(windows) {
        assert!(
            names.iter().any(|k| k == "HTTPS_PROXY") && names.iter().any(|k| k == "https_proxy"),
            "{names:?}"
        );
    }
    for name in &names {
        assert!(phantab::runtime::service_env_allowed(name), "the service inherited {name}");
    }
    assert!(!names.iter().any(|k| k.eq_ignore_ascii_case("RUST_LOG") || k == "FOO"), "{names:?}");
}

/// SR-59, L1: the panic hook prints the location and never the payload, and release builds abort
/// with overflow checks left off.
#[test]
fn a_panic_prints_its_location_never_its_message() {
    let rt = Runtime::new();
    let sentinel = "SENTINEL-payload-7f3a";
    let (code, out, err) = run(&rt, &["status"], &[("PHANTAB_TEST_PANIC", sentinel)]);
    assert_ne!(code, 0);
    assert!(err.contains("phantab: internal error at ") && err.contains("panic_hook.rs:"), "{err}");
    assert!(!err.contains(sentinel) && !out.contains(sentinel), "{out}{err}");

    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml")).unwrap();
    let release = manifest.split("[profile.release]").nth(1).unwrap_or_default();
    let release = release.split("\n[").next().unwrap_or_default();
    assert!(release.lines().any(|l| l.trim() == "panic = \"abort\""), "{release}");
    // With the abort, an overflow a page can reach would end the service. Read the comment in
    // Cargo.toml's [profile.release] before turning the checks on. The whole manifest: a
    // `[profile.release.package.*]` override or a dotted or quoted key sets them as well.
    let set: Vec<&str> = manifest
        .lines()
        .filter(|l| l.split('#').next().unwrap_or_default().contains("overflow-checks"))
        .collect();
    assert!(
        set.is_empty(),
        "remove overflow-checks from Cargo.toml (even `= false`); read the comment in [profile.release] for \
         the audit it needs first: {set:?}"
    );
}

/// SR-26, L3: the client id is 1 to 150 characters on the client side too. Too long fails before any
/// call (no service is started); exactly 150 with the `cli:` prefix works.
#[test]
fn a_client_id_over_150_characters_is_refused_before_any_call() {
    let rt = Runtime::new();
    let long = "a".repeat(147);
    let (code, _, err) = run(&rt, &["pages"], &[("PHANTAB_CLIENT", &long)]);
    assert_eq!(code, 1);
    assert!(err.contains("at most 150 characters"), "{err}");
    assert!(rt.endpoint().is_none(), "a refused id must not start the service");

    let (code, _, err) = run(&rt, &["mcp"], &[("PHANTAB_CLIENT", &"a".repeat(151))]);
    assert_eq!(code, 1);
    assert!(err.contains("PHANTAB_CLIENT must be at most 150 characters"), "{err}");

    let (code, out, err) = run(&rt, &["pages"], &[("PHANTAB_CLIENT", &"a".repeat(146))]);
    assert_eq!((code, out.trim()), (0, "[]"), "{err}");
}
