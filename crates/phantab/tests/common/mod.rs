//! Helpers for the process tests: a throwaway runtime, the real binary with a clean environment,
//! blocking HTTP and a fake bridge extension. Nothing here reads the owner's runtime or Chrome.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const BIN: &str = env!("CARGO_BIN_EXE_phantab");

/// Environment that would point the binary at a real session or runtime.
const SCRUB: &[&str] = &[
    "PHANTAB_CLIENT",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
    "CLAUDE_SESSION_ID",
    "CLAUDE_CODE_SESSION_ID",
    "PHANTAB_RUNTIME",
    "RUST_LOG",
];

/// A temp runtime with a config naming a temp Chrome user-data dir (profile `test`).
#[derive(Debug)]
pub struct Runtime {
    pub dir: tempfile::TempDir,
}

impl Runtime {
    pub fn new() -> Self {
        let dir = tempfile::Builder::new().prefix("phantab-test-").tempdir().unwrap();
        let rt = Self { dir };
        std::fs::create_dir_all(rt.user_data_dir().join("test")).unwrap();
        rt.write_config(&json!({ "profileDirectory": "test", "userDataDir": rt.user_data_dir() }));
        rt
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn user_data_dir(&self) -> PathBuf {
        self.path().join("chrome")
    }

    pub fn write_config(&self, config: &Value) {
        std::fs::write(self.path().join("config.json"), config.to_string()).unwrap();
    }

    /// Lists the bridge extension in the configured profile, unpacked from `<runtime>/extension` (the
    /// service's `paths::extension_dir()`, SR-19), so the profile check passes.
    pub fn install_extension_in_profile(&self) {
        let ext = self.path().join("extension");
        std::fs::create_dir_all(&ext).unwrap();
        let entry = json!({ "path": ext, "location": 4 });
        let prefs =
            json!({ "extensions": { "settings": { (phantab::bridge::EXTENSION_ID.as_str()): entry } } });
        std::fs::write(self.user_data_dir().join("test").join("Secure Preferences"), prefs.to_string())
            .unwrap();
    }

    /// The binary with only this runtime in its environment. LOCALAPPDATA and HOME move too, so a
    /// fallback can never reach the owner's folders.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args);
        for k in SCRUB {
            cmd.env_remove(k);
        }
        let home = self.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        cmd.env("PHANTAB_RUNTIME", self.path())
            .env("LOCALAPPDATA", self.path().join("localappdata"))
            .env("HOME", &home)
            .env("XDG_STATE_HOME", self.path().join("state"));
        cmd
    }

    pub fn endpoint(&self) -> Option<Value> {
        let text = std::fs::read(self.path().join("endpoint.json")).ok()?;
        serde_json::from_slice(&text).ok()
    }

    /// Waits for the endpoint of a healthy service.
    pub fn wait_endpoint(&self) -> Endpoint {
        let end = Instant::now() + Duration::from_secs(15);
        while Instant::now() < end {
            if let Some(ep) = self.endpoint() {
                let ep = Endpoint {
                    port: u16::try_from(ep["port"].as_u64().unwrap()).unwrap(),
                    token: ep["token"].as_str().unwrap().to_owned(),
                    pid: u32::try_from(ep["pid"].as_u64().unwrap()).unwrap(),
                };
                if get(ep.port, "/health").0 == 200 {
                    return ep;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no service endpoint in {}", self.path().display());
    }

    /// Starts `phantab serve` as a child this test owns.
    pub fn serve(&self) -> Service {
        let child = self
            .command(&["serve"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let endpoint = self.wait_endpoint();
        Service { child: Some(child), endpoint }
    }
}

impl Drop for Runtime {
    // A service a client started detached is no child of the test: stop it by its endpoint.
    fn drop(&mut self) {
        let Some(ep) = self.endpoint() else { return };
        if let (Some(port), Some(token)) =
            (ep["port"].as_u64().and_then(|p| u16::try_from(p).ok()), ep["token"].as_str())
        {
            let _ = try_rpc(port, token, "shutdown", &json!({}), "test");
        }
        if let Some(pid) = ep["pid"].as_u64().and_then(|p| u32::try_from(p).ok()) {
            wait_until(Duration::from_secs(5), || !alive(pid));
            kill(pid);
        }
    }
}

pub fn alive(pid: u32) -> bool {
    let mut sys = sysinfo::System::new().unwrap();
    let pid = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).is_some()
}

pub fn kill(pid: u32) {
    let mut sys = sysinfo::System::new().unwrap();
    let pid = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    if let Some(p) = sys.process(pid) {
        p.kill();
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
    pub pid: u32,
}

#[derive(Debug)]
pub struct Service {
    pub child: Option<Child>,
    pub endpoint: Endpoint,
}

impl Service {
    pub fn rpc(&self, method: &str, args: &Value, client: &str) -> Value {
        rpc(self.endpoint.port, &self.endpoint.token, method, args, client)
    }

    /// Waits for the child to exit by itself.
    pub fn wait_exit(&mut self, within: Duration) -> Option<std::process::ExitStatus> {
        let child = self.child.as_mut()?;
        let end = Instant::now() + within;
        while Instant::now() < end {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = try_rpc(self.endpoint.port, &self.endpoint.token, "shutdown", &json!({}), "test");
            wait_until(Duration::from_secs(5), || child.try_wait().ok().flatten().is_some());
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A response: status, raw head, body.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&self.body)))
    }

    /// A header's value, by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    }
}

/// One HTTP/1.1 request with `Connection: close`. `Host` is the service's unless `headers` sets one.
pub fn request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<Reply> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        let _ = write!(head, "Host: 127.0.0.1:{port}\r\n");
    }
    for (k, v) in headers {
        let _ = write!(head, "{k}: {v}\r\n");
    }
    let _ = write!(head, "Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    Ok(parse(&raw))
}

fn parse(raw: &[u8]) -> Reply {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = raw.get(split + 4..).unwrap_or_default().to_vec();
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    Reply { status, head, body }
}

pub fn get(port: u16, path: &str) -> (u16, Vec<u8>) {
    request(port, "GET", path, &[], b"").map_or((0, Vec::new()), |r| (r.status, r.body))
}

pub fn try_rpc(port: u16, token: &str, method: &str, args: &Value, client: &str) -> std::io::Result<Reply> {
    let body = json!({ "method": method, "args": args, "client": client }).to_string();
    let auth = format!("Bearer {token}");
    request(
        port,
        "POST",
        "/rpc",
        &[("Authorization", &auth), ("Content-Type", "application/json")],
        body.as_bytes(),
    )
}

/// The parsed body of an rpc: `{result}` or `{error}`.
pub fn rpc(port: u16, token: &str, method: &str, args: &Value, client: &str) -> Value {
    try_rpc(port, token, method, args, client).unwrap().json()
}

/// Sends an upgrade request; returns the status, and the socket if it switched.
pub fn upgrade(port: u16, headers: &[(&str, &str)], path: &str) -> (u16, Option<TcpStream>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: Upgrade\r\n");
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("upgrade")) {
        head.push_str("Upgrade: phantab-bridge\r\n");
    }
    for (k, v) in headers {
        let _ = write!(head, "{k}: {v}\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    // Byte by byte, so nothing after the head is consumed.
    while !raw.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => raw.push(byte[0]),
        }
    }
    let status = parse(&raw).status;
    (status, (status == 101).then_some(stream))
}

/// The native-messaging framing: 4-byte little-endian length, then JSON.
pub fn frame(value: &Value) -> Vec<u8> {
    let body = value.to_string().into_bytes();
    let mut out = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    out.extend(body);
    out
}

/// Reads one frame; `None` at the end of the stream.
pub fn read_frame(stream: &mut impl std::io::Read) -> Option<Value> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).ok()?;
    let mut body = vec![0u8; usize::try_from(u32::from_le_bytes(len)).unwrap()];
    stream.read_exact(&mut body).ok()?;
    Some(serde_json::from_slice(&body).unwrap())
}

/// Says hello as the bridge extension on `io` and checks the welcome (test/fake-extension.mjs).
pub fn hello(io: &mut (impl std::io::Read + std::io::Write), instance: &str) {
    io.write_all(&frame(&json!({ "hello": { "version": "1.0.0", "protocol": 1, "instance": instance } })))
        .unwrap();
    io.flush().unwrap();
    assert_eq!(read_frame(io), Some(json!({ "welcome": true, "events": phantab_cdp::EVENTS })));
}

/// A fake bridge extension on an upgraded socket: hello, then a thread that answers `ping` and hands
/// every other op to `answer`.
pub fn fake_extension(
    mut stream: TcpStream,
    instance: &str,
    answer: impl Fn(&Value) -> Value + Send + 'static,
) -> std::thread::JoinHandle<()> {
    stream.set_read_timeout(None).unwrap();
    hello(&mut stream, instance);
    std::thread::spawn(move || {
        while let Some(m) = read_frame(&mut stream) {
            let reply = if m["op"] == "ping" { json!({ "id": m["id"], "result": {} }) } else { answer(&m) };
            if stream.write_all(&frame(&reply)).is_err() {
                break;
            }
        }
    })
}

pub fn wait_until(within: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + within;
    while Instant::now() < end {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}
