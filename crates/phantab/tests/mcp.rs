//! `phantab mcp` over real stdio: the tool list byte for byte against its golden file, the server
//! name, and tool calls answered by the engine through a service the MCP server starts itself.
// Test helpers fail by panicking, like the tests themselves (clippy.toml allows it only inside #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use common::Runtime;
use serde_json::{Value, json};

/// `tools/list`'s `result`, as phantab sends it (ARCHITECTURE § Names and constants). A deliberate
/// change to a tool rewrites it: run this test with `PHANTAB_UPDATE_GOLDEN=1`, then review the diff.
const TOOLS_GOLDEN: &str = include_str!("fixtures/tools-list.json");
const TOOLS_GOLDEN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tools-list.json");
/// `tools/list`'s `result` with `"devTools": true` in config.json (THREAT-MODEL SR-90): the list above
/// and the five developer tools after it. Rewritten the same way.
const DEVTOOLS_GOLDEN: &str = include_str!("fixtures/tools-list-devtools.json");
const DEVTOOLS_GOLDEN_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tools-list-devtools.json");
/// `tools/list`'s `result` with `"work": true` in config.json (THREAT-MODEL SR-92): the first list without
/// `browser_sign_in` and `browser_sign_up`. Rewritten the same way.
const WORK_GOLDEN: &str = include_str!("fixtures/tools-list-work.json");
const WORK_GOLDEN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tools-list-work.json");

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
}

impl Mcp {
    fn start(rt: &Runtime, args: &[&str]) -> Self {
        let mut all = vec!["mcp"];
        all.extend_from_slice(args);
        let mut child = rt
            .command(&all)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, stdin, lines }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// The next line, as sent.
    fn line(&self, within: Duration) -> String {
        self.lines.recv_timeout(within).expect("an MCP answer")
    }

    fn initialize(&mut self) -> String {
        self.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "fixture", "version": "1" } } }));
        let init = self.line(Duration::from_secs(10));
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        init
    }

    fn call(&mut self, id: u64, name: &str, arguments: &Value) -> Value {
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": arguments } }));
        let answer: Value = serde_json::from_str(&self.line(Duration::from_secs(60))).unwrap();
        assert_eq!(answer["id"], json!(id));
        answer["result"].clone()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn tools_list_matches_the_golden_file_byte_for_byte() {
    let rt = Runtime::new();
    let mut mcp = Mcp::start(&rt, &[]);
    let init: Value = serde_json::from_str(&mcp.initialize()).unwrap();
    assert_eq!(init["result"]["protocolVersion"], json!("2025-06-18"));
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert_eq!(init["result"]["serverInfo"]["name"], json!("phantab"));
    assert_eq!(init["result"]["serverInfo"]["version"], json!(env!("CARGO_PKG_VERSION")));

    mcp.send(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }));
    let line = mcp.line(Duration::from_secs(10));
    let ours: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ours["id"], json!(2));
    let listed = serde_json::to_string(&ours["result"]).unwrap();
    if std::env::var_os("PHANTAB_UPDATE_GOLDEN").is_some() {
        std::fs::write(
            TOOLS_GOLDEN_PATH,
            format!(
                "{listed}
"
            ),
        )
        .unwrap();
    } else {
        assert_eq!(listed, TOOLS_GOLDEN.trim_end(), "tools/list changed; see TOOLS_GOLDEN");
    }
    // Listing tools starts no service.
    assert!(rt.endpoint().is_none());
}

/// The tool list `phantab mcp` sends for a given config.json.
fn listed_with(config: &Value) -> String {
    let rt = Runtime::new();
    rt.write_config(config);
    let mut mcp = Mcp::start(&rt, &[]);
    mcp.initialize();
    mcp.send(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }));
    let ours: Value = serde_json::from_str(&mcp.line(Duration::from_secs(10))).unwrap();
    serde_json::to_string(&ours["result"]).unwrap()
}

/// SR-90: only the JSON `true` lists the developer tools; anything else lists the golden above.
#[test]
fn developer_tools_are_listed_only_with_dev_tools_true() {
    let base = json!({ "profileDirectory": "test" });
    let listed = listed_with(&json!({ "profileDirectory": "test", "devTools": true }));
    if std::env::var_os("PHANTAB_UPDATE_GOLDEN").is_some() {
        std::fs::write(
            DEVTOOLS_GOLDEN_PATH,
            format!(
                "{listed}
"
            ),
        )
        .unwrap();
    } else {
        assert_eq!(
            listed,
            DEVTOOLS_GOLDEN.trim_end(),
            "tools/list with devTools changed; see DEVTOOLS_GOLDEN"
        );
    }
    for off in [json!(false), json!("true"), json!(1), json!(null)] {
        let mut config = base.clone();
        config["devTools"] = off.clone();
        assert_eq!(listed_with(&config), TOOLS_GOLDEN.trim_end(), "devTools {off}");
    }
}

/// The tool names in a `tools/list` result.
fn names(listed: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(listed).unwrap();
    v["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_owned()).collect()
}

/// SR-92: `work` on lists no sign-in tool; absent and `false` list the golden above. Any other value
/// counts as on. With `devTools` too (what `phantab install --work` writes), the developer tools stay.
#[test]
fn sign_in_tools_are_not_listed_with_work_on() {
    let listed = listed_with(&json!({ "profileDirectory": "test", "work": true }));
    if std::env::var_os("PHANTAB_UPDATE_GOLDEN").is_some() {
        std::fs::write(WORK_GOLDEN_PATH, format!("{listed}\n")).unwrap();
    } else {
        assert_eq!(listed, WORK_GOLDEN.trim_end(), "tools/list with work changed; see WORK_GOLDEN");
    }
    let sign_in = ["browser_sign_in", "browser_sign_up"];
    let mut expected = names(TOOLS_GOLDEN);
    expected.retain(|n| !sign_in.contains(&n.as_str()));
    assert_eq!(names(&listed), expected);
    for on in [json!("yes"), json!(null), json!(0)] {
        let config = json!({ "profileDirectory": "test", "work": on });
        assert_eq!(listed_with(&config), WORK_GOLDEN.trim_end(), "work {on}");
    }
    assert_eq!(listed_with(&json!({ "profileDirectory": "test", "work": false })), TOOLS_GOLDEN.trim_end());
    let both = names(&listed_with(&json!({ "profileDirectory": "test", "work": true, "devTools": true })));
    let mut expected = names(DEVTOOLS_GOLDEN);
    expected.retain(|n| !sign_in.contains(&n.as_str()));
    assert_eq!(both, expected);
}

#[test]
fn the_server_name_can_be_another() {
    let rt = Runtime::new();
    let mut mcp = Mcp::start(&rt, &["--server-name", "my-browser"]);
    let init: Value = serde_json::from_str(&mcp.initialize()).unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], json!("my-browser"));
}

#[test]
fn tool_calls_start_the_service_and_answer_from_the_engine() {
    let rt = Runtime::new();
    let mut mcp = Mcp::start(&rt, &[]);
    mcp.initialize();

    let status = mcp.call(3, "browser_status", &json!({}));
    // A success carries no isError at all.
    assert_eq!(status["isError"], Value::Null);
    assert_eq!(status["content"][0]["type"], json!("text"));
    let state: Value = serde_json::from_str(status["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(state["connected"], json!(false));
    let endpoint = rt.endpoint().expect("the MCP server started the service");
    assert_eq!(state["pid"], endpoint["pid"]);

    assert_eq!(mcp.call(4, "browser_pages", &json!({}))["content"][0]["text"], json!("[]"));
    // The engine checks the URL before it needs a browser.
    let open = mcp.call(5, "browser_open", &json!({ "url": "file:///etc/passwd" }));
    let refused = "Only HTTP(S) website URLs are accepted.";
    assert_eq!(open, json!({ "content": [{ "type": "text", "text": refused }], "isError": true }));
    let unknown = mcp.call(6, "browser_nothing", &json!({}));
    assert_eq!(unknown, json!({ "content": [{ "type": "text", "text": "Unknown tool" }], "isError": true }));

    // Closing stdin ends the server; the service it started lives on.
    drop(mcp.stdin.take());
    let ended = common::wait_until(Duration::from_secs(10), || mcp.child.try_wait().ok().flatten().is_some());
    assert!(ended, "the MCP server exits when its client goes away");
    // The service holds none of the server's pipes, so stdout reaches its end. On Windows that needs
    // `phantab_window::disable_std_handle_inheritance` at the top of main: std spawns with handle
    // inheritance on, so the service would otherwise hold the server's std handles.
    assert!(matches!(
        mcp.lines.recv_timeout(Duration::from_secs(5)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
    let pid = u32::try_from(endpoint["pid"].as_u64().unwrap()).unwrap();
    assert!(common::alive(pid), "the service outlives the MCP server");
}

/// The service pid a `browser_status` answer names.
fn status_pid(status: &Value) -> u64 {
    assert_eq!(status["isError"], Value::Null, "{status}");
    let state: Value = serde_json::from_str(status["content"][0]["text"].as_str().unwrap()).unwrap();
    state["pid"].as_u64().unwrap()
}

/// The MCP server keeps one proven connection to the service. A service that is killed, or shut down,
/// under it is replaced on the next call as before: the session never sees the restart.
#[test]
fn a_service_restart_is_transparent_to_an_mcp_session() {
    let rt = Runtime::new();
    let mut mcp = Mcp::start(&rt, &[]);
    mcp.initialize();
    let first = status_pid(&mcp.call(2, "browser_status", &json!({})));
    assert_eq!(status_pid(&mcp.call(3, "browser_status", &json!({}))), first, "the same service");

    let pid = u32::try_from(first).unwrap();
    common::kill(pid);
    assert!(common::wait_until(Duration::from_secs(10), || !common::alive(pid)));
    let second = status_pid(&mcp.call(4, "browser_status", &json!({})));
    assert_ne!(second, first, "a fresh service took over");
    assert_eq!(rt.endpoint().unwrap()["pid"], json!(second));

    let out = rt.command(&["shutdown"]).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let pid = u32::try_from(second).unwrap();
    assert!(common::wait_until(Duration::from_secs(10), || !common::alive(pid)));
    let third = status_pid(&mcp.call(5, "browser_status", &json!({})));
    assert!(third != first && third != second, "a fresh service after the shutdown");
}

/// Calls of different kinds sent together, without waiting, each get an answer of their own kind from
/// the real service. Same-kind answers here are alike; `calls_of_one_kind_never_swap_answers` tells
/// them apart.
#[test]
fn concurrent_tool_calls_each_get_their_own_answer() {
    let rt = Runtime::new();
    let mut mcp = Mcp::start(&rt, &[]);
    mcp.initialize();
    let pid = status_pid(&mcp.call(2, "browser_status", &json!({})));
    let refused = json!({ "content": [{ "type": "text", "text": "Only HTTP(S) website URLs are accepted." }], "isError": true });
    let calls = [
        ("browser_status", json!({})),
        ("browser_pages", json!({})),
        ("browser_open", json!({ "url": "file:///etc/passwd" })),
        ("browser_tabs", json!({ "nope": 1 })),
    ];
    let count = 24u64;
    for id in 0..count {
        let (name, arguments) = &calls[usize::try_from(id).unwrap() % calls.len()];
        mcp.send(&json!({ "jsonrpc": "2.0", "id": 100 + id, "method": "tools/call", "params": { "name": name, "arguments": arguments } }));
    }
    let mut answered = std::collections::BTreeMap::new();
    for _ in 0..count {
        let answer: Value = serde_json::from_str(&mcp.line(Duration::from_secs(60))).unwrap();
        answered.insert(answer["id"].as_u64().unwrap() - 100, answer["result"].clone());
    }
    assert_eq!(answered.len(), usize::try_from(count).unwrap());
    for (id, result) in answered {
        match id % 4 {
            0 => assert_eq!(status_pid(&result), pid, "{id}"),
            1 => assert_eq!(result["content"][0]["text"], json!("[]"), "{id}"),
            2 => assert_eq!(result, refused, "{id}"),
            _ => assert_eq!(
                result["content"][0]["text"],
                json!("Unknown argument \"nope\" for browser_tabs."),
                "{id}"
            ),
        }
    }
    assert_eq!(status_pid(&mcp.call(200, "browser_status", &json!({}))), pid);
}

/// A stand-in service on 127.0.0.1 that keeps its connections, as this version's does: `/hello`
/// proves `token` and says `keep`, and `/rpc` answers `{"method", "args"}` of the call it got, with
/// [`OPENED`] as `pageId` for an `open`. A call
/// whose url ends `?n=<i>` is answered after `(16 - i) * 20` ms, so answers come back in reverse.
/// Every request is recorded as (connection, request line, whether it carried the token).
struct KeepingService {
    port: u16,
    seen: std::sync::Arc<std::sync::Mutex<Vec<(usize, String, bool)>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl KeepingService {
    fn start(token: &str) -> Self {
        use std::sync::atomic::Ordering;

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let seen = std::sync::Arc::default();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen2, stop2, token) =
            (std::sync::Arc::clone(&seen), std::sync::Arc::clone(&stop), token.to_owned());
        std::thread::spawn(move || {
            let mut n = 0;
            while !stop2.load(Ordering::SeqCst) {
                let Ok((conn, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                let (seen, token) = (std::sync::Arc::clone(&seen2), token.clone());
                std::thread::spawn(move || Self::serve(conn, n, &token, &seen));
                n += 1;
            }
        });
        Self { port, seen, stop }
    }

    /// Answers requests on one connection until the client closes it.
    fn serve(
        conn: std::net::TcpStream,
        n: usize,
        token: &str,
        seen: &std::sync::Mutex<Vec<(usize, String, bool)>>,
    ) {
        use std::io::Read as _;

        conn.set_nonblocking(false).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut out = conn.try_clone().unwrap();
        let mut reader = BufReader::new(conn);
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let request = line.trim_end().to_owned();
            let (mut length, mut authed) = (0, false);
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let header = line.trim_end().to_ascii_lowercase();
                if header.is_empty() {
                    break;
                }
                if let Some(v) = header.strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
                authed |= header == format!("authorization: bearer {token}");
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).unwrap();
            seen.lock().unwrap().push((n, request.clone(), authed));
            let target = request.split(' ').nth(1).unwrap_or_default();
            let answer = if let Some(nonce) = phantab::hello::nonce_of(target) {
                json!({ "proof": phantab::hello::proof(token, &nonce).unwrap(), "keep": 120 })
            } else {
                let call: Value = serde_json::from_slice(&body).unwrap();
                let i = call["args"]["url"].as_str().and_then(|u| u.split_once("?n=")).map(|(_, i)| i);
                if let Some(i) = i.and_then(|i| i.parse::<u64>().ok()) {
                    std::thread::sleep(Duration::from_millis(16u64.saturating_sub(i) * 20));
                }
                let mut result = json!({ "method": call["method"], "args": call["args"] });
                if call["method"] == "open" {
                    result["pageId"] = json!(OPENED);
                }
                json!({ "result": result })
            };
            let answer = answer.to_string();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                answer.len()
            );
            if out.write_all(format!("{head}{answer}").as_bytes()).is_err() {
                return;
            }
        }
    }

    fn seen(&self) -> Vec<(usize, String, bool)> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for KeepingService {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The page id the stand-in service gives every page it opens.
const OPENED: &str = "f00dfeed-0000-4000-8000-000000000001";

/// Removes the endpoint a test wrote for a stand-in service before the runtime's drop reads it: that
/// drop stops the service an endpoint names, and this one names none of ours.
struct Unadvertise(std::path::PathBuf);

impl Drop for Unadvertise {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Calls of one kind sent together, without waiting, each get their own answer even when the answers
/// would come back in reverse: no answer goes to another call. Every connection the MCP server opens proves
/// the service first and only then carries the token.
#[test]
fn calls_of_one_kind_never_swap_answers() {
    let rt = Runtime::new();
    let token = "7a".repeat(32);
    let service = KeepingService::start(&token);
    let endpoint = rt.path().join("endpoint.json");
    let endpoint_json = json!({
        "port": service.port, "token": token, "pid": 1,
        "protocol": phantab::paths::SERVICE_PROTOCOL, "source": "fake"
    });
    std::fs::write(&endpoint, endpoint_json.to_string()).unwrap();
    let _unadvertise = Unadvertise(endpoint);
    let mut mcp = Mcp::start(&rt, &[]);
    mcp.initialize();
    let count = 16u64;
    for i in 0..count {
        let arguments = json!({ "url": format!("https://example.com/?n={i}") });
        mcp.send(&json!({ "jsonrpc": "2.0", "id": 100 + i, "method": "tools/call", "params": { "name": "browser_open", "arguments": arguments } }));
    }
    for _ in 0..count {
        let answer: Value = serde_json::from_str(&mcp.line(Duration::from_secs(60))).unwrap();
        let i = answer["id"].as_u64().unwrap() - 100;
        let text = answer["result"]["content"][0]["text"].as_str().unwrap_or_default().to_owned();
        let got: Value = serde_json::from_str(&text).unwrap_or_default();
        assert_eq!(got["method"], json!("open"), "{i}: {answer}");
        assert_eq!(got["args"]["url"], json!(format!("https://example.com/?n={i}")), "{i}: {answer}");
    }
    drop(mcp);
    let seen = service.seen();
    assert_eq!(seen.iter().filter(|r| r.1 == "POST /rpc HTTP/1.1").count(), 16, "{seen:?}");
    let connections: std::collections::BTreeSet<usize> = seen.iter().map(|r| r.0).collect();
    for n in connections {
        let on: Vec<_> = seen.iter().filter(|r| r.0 == n).collect();
        let (first, rest) = on.split_first().unwrap();
        assert!(first.1.starts_with("GET /hello?nonce=") && !first.2, "{on:?}");
        assert!(rest.iter().all(|r| r.1 == "POST /rpc HTTP/1.1" && r.2), "{on:?}");
    }
}

/// `browser_sign_in` with `url` opens the page, as `browser_open` does with its defaults, and signs in
/// on it in the same call; the answer starts with the open's line, so the agent knows the page. Without
/// a page, or with both, it refuses before anything reaches the service.
#[test]
fn a_sign_in_with_a_url_opens_the_page_and_signs_in_there() {
    let rt = Runtime::new();
    let token = "7b".repeat(32);
    let service = KeepingService::start(&token);
    let endpoint = rt.path().join("endpoint.json");
    let endpoint_json = json!({
        "port": service.port, "token": token, "pid": 1,
        "protocol": phantab::paths::SERVICE_PROTOCOL, "source": "fake"
    });
    std::fs::write(&endpoint, endpoint_json.to_string()).unwrap();
    let _unadvertise = Unadvertise(endpoint);
    let mut mcp = Mcp::start(&rt, &[]);
    mcp.initialize();
    let posts =
        |service: &KeepingService| service.seen().iter().filter(|r| r.1 == "POST /rpc HTTP/1.1").count();
    for (id, arguments, said) in [
        (2, json!({}), "browser_sign_in needs pageId, or url to open the page."),
        (
            3,
            json!({ "url": "https://a.test/", "pageId": "p" }),
            "browser_sign_in takes pageId or url, not both.",
        ),
        (4, json!({ "url": 7 }), "url must be a string."),
    ] {
        let refused = mcp.call(id, "browser_sign_in", &arguments);
        assert_eq!(refused["isError"], json!(true), "{refused}");
        assert_eq!(refused["content"][0]["text"], json!(said));
    }
    assert_eq!(posts(&service), 0, "a refused call reaches no service");
    let answer = mcp.call(5, "browser_sign_in", &json!({ "url": "https://a.test/login", "account": "me" }));
    let text = answer["content"][0]["text"].as_str().unwrap().to_owned();
    let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert_eq!(lines[0]["method"], json!("open"));
    assert_eq!(lines[0]["args"], json!({ "url": "https://a.test/login" }), "opened with the defaults");
    assert_eq!(lines[0]["pageId"], json!(&OPENED[..8]), "the agent's short id for the page");
    assert_eq!(lines[1]["method"], json!("sign_in"));
    // The service echoes the arguments it got; the answer shows the page id short, as every answer does.
    assert_eq!(lines[1]["args"], json!({ "pageId": &OPENED[..8], "account": "me" }));
    assert_eq!(posts(&service), 2);
}
