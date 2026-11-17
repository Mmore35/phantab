//! What every client of the service shares (runtime.mjs): the config, the endpoint, starting the
//! service when it is down, and the `/rpc` call on a kept, proven connection.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::net::TcpStream;

use crate::paths::{self, SERVICE_PROTOCOL};
use crate::util::{json_error, node_fs_error};

/// `config.json`, written by the installer. Unknown keys are kept so a newer installer's settings
/// survive a read by an older service.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_directory: Option<String>,
    /// Chrome profile folders besides `profileDirectory` that agents may reach when they name one,
    /// each through its own copy of the bridge (`paths::profile_extension_dir`). Written by
    /// `phantab install`: by default every profile folder but the usual one and `excludeProfiles`, or under
    /// `allProfiles: false` those named with `--add-profile`. Absent means the usual profile only. The
    /// service reads only this list, once at its start (SR-76).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_profiles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chrome_executable: Option<PathBuf>,
    /// Where the installed code lives. The service is never started from it (THREAT-MODEL SR-14): a
    /// writable config must not choose the binary. Kept for the providers that check their parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_source: Option<PathBuf>,
    /// `{command: [program, ...args]}` of the sign-in provider, if the owner set one up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_provider: Option<Value>,
    /// Several sign-in sources in order (docs/VAULTS.md): `[{name, source?, command?, caps?, pin?,
    /// sites?, bitwarden?}]`. Set with `phantab install --add-sign-in-provider`; never together with
    /// `signInProvider` (every sign-in then answers `provider-failed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_providers: Option<Value>,
    /// The `signInProviders` name a sign-up's new login is saved to, when no site pin or `vault` says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_save_to: Option<Value>,
    /// `true` once install recorded the extension's files beside the folder and checked the folder
    /// against the record; install writes it last (THREAT-MODEL SR-74). With it set, a missing record
    /// refuses the bridge like a changed file; without it (an install from before SR-74) a missing record
    /// is accepted. The key is [`crate::extension_files::MARKER`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_files_recorded: Option<bool>,
    /// The owner's own route to a verification check from another device. Absent: no second
    /// listener, and a check is only shown on this computer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_viewer: Option<RemoteViewer>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl Config {
    /// `otherProfiles` as the service uses it: valid profile folders ([`paths::valid_profile_dir`]), once
    /// each, never the usual `profileDirectory`. The installer writes no other kind; a hand-edited entry
    /// that is one is ignored, so its copy of the bridge is refused like any unknown one.
    #[must_use]
    pub fn allowed_other_profiles(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for dir in self.other_profiles.iter().flatten() {
            if paths::valid_profile_dir(dir)
                && self.profile_directory.as_deref() != Some(dir.as_str())
                && !out.contains(dir)
            {
                out.push(dir.clone());
            }
        }
        out
    }

    /// `devTools` (THREAT-MODEL SR-90): the developer tools `browser_evaluate`, `browser_console` and
    /// `browser_network`, on only when the value is the JSON boolean `true`. A string, a number or
    /// anything else is off, so a mistyped setting never turns them on.
    #[must_use]
    pub fn dev_tools(&self) -> bool {
        self.other.get("devTools") == Some(&Value::Bool(true))
    }
}

/// `remoteViewer` in `config.json`: a second listener, on loopback, that serves only the live view. The
/// owner puts his own private route in front of it (for example Tailscale Serve); Phantab
/// never listens beyond loopback itself (THREAT-MODEL SR-70).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteViewer {
    /// `127.0.0.1:PORT` or `[::1]:PORT`.
    pub listen: String,
    /// The address the owner's other device opens, such as `http://mypc:8490`. Its host is the only
    /// `Host` the listener answers.
    pub public_base_url: String,
    /// A header the route in front adds and the owner's device cannot forge, and the one value it must
    /// carry (Tailscale Serve's `Tailscale-User-Login`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_identity: Option<TrustedIdentity>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustedIdentity {
    pub header: String,
    pub equals: String,
}

/// A [`RemoteViewer`] that passed its checks: what the listener binds and compares.
#[derive(Debug, Clone)]
pub struct RemoteListen {
    pub addr: std::net::SocketAddr,
    /// `publicBaseUrl` without a trailing slash; links are `{base}/view#token`.
    pub base: String,
    /// The exact `Host` a request must carry.
    pub host: String,
    /// The exact `Origin` a request may carry.
    pub origin: String,
    /// `(lower-case header name, value)`.
    pub identity: Option<(String, String)>,
}

impl RemoteViewer {
    /// Checks the setting. A bad one leaves the remote view off; the rest of Phantab still starts.
    ///
    /// # Errors
    /// `listen` is not a loopback address with a port, or `publicBaseUrl` is not a bare http(s) origin.
    pub fn checked(&self) -> Result<RemoteListen, String> {
        let addr: std::net::SocketAddr = self
            .listen
            .parse()
            .map_err(|_| format!("remoteViewer.listen must be 127.0.0.1:PORT, not {:?}", self.listen))?;
        if !addr.ip().is_loopback() || addr.port() == 0 {
            return Err(format!(
                "remoteViewer.listen must be a loopback address with a port, not {:?}: Phantab never listens beyond this computer.",
                self.listen
            ));
        }
        let trimmed = self.public_base_url.trim_end_matches('/');
        let url = url::Url::parse(trimmed).map_err(|e| format!("remoteViewer.publicBaseUrl: {e}"))?;
        let bare = matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none();
        let Some(name) = url.host_str().filter(|_| bare) else {
            return Err(format!(
                "remoteViewer.publicBaseUrl must be an http(s) address with no path, such as http://mypc:8490, not {:?}",
                self.public_base_url
            ));
        };
        let host = url.port().map_or_else(|| name.to_owned(), |p| format!("{name}:{p}"));
        let identity = match &self.trusted_identity {
            None => None,
            Some(t) => {
                let ok = hyper::header::HeaderName::from_bytes(t.header.as_bytes()).is_ok()
                    && !t.equals.is_empty();
                if !ok {
                    return Err(
                        "remoteViewer.trustedIdentity needs a header name and the value it must equal."
                            .to_owned(),
                    );
                }
                Some((t.header.to_ascii_lowercase(), t.equals.clone()))
            }
        };
        Ok(RemoteListen {
            addr,
            base: format!("{}://{host}", url.scheme()),
            host,
            origin: url.origin().ascii_serialization(),
            identity,
        })
    }
}

/// Reads `config.json`. Its absence is an error: the installer writes it, and a service without it
/// would not know which Chrome profile is the owner's.
///
/// # Errors
/// The file is missing, unreadable or not JSON (worded like Node's file errors, which callers match).
pub fn read_config() -> anyhow::Result<Config> {
    let path = paths::config_path();
    let text = std::fs::read(&path).map_err(|e| anyhow!(node_fs_error(&e, "open", &path)))?;
    serde_json::from_slice(&text).map_err(|e| anyhow!(json_error(&text, &e)))
}

/// `endpoint.json`: where the running service listens and the token it accepts.
#[derive(Clone, Deserialize, Serialize)]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
    pub pid: u32,
    /// Compared as JSON: a service written by another version may put anything here.
    pub protocol: Value,
    pub source: String,
}

impl std::fmt::Debug for Endpoint {
    // The token never reaches a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("port", &self.port)
            .field("pid", &self.pid)
            .field("protocol", &self.protocol)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// # Errors
/// No endpoint file, or not one this version can read.
pub fn read_endpoint() -> anyhow::Result<Endpoint> {
    read_endpoint_at(&paths::endpoint_path())
}

fn read_endpoint_at(path: &Path) -> anyhow::Result<Endpoint> {
    let text = std::fs::read(path).map_err(|e| anyhow!(node_fs_error(&e, "open", path)))?;
    serde_json::from_slice(&text).map_err(|e| anyhow!(json_error(&text, &e)))
}

/// A finished HTTP exchange with the service.
#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub body: Bytes,
}

/// Why an exchange did not finish, worded as Node's `fetch` words it (callers show it).
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("The operation was aborted due to timeout")]
    Timeout,
    #[error("fetch failed")]
    Failed(#[source] anyhow::Error),
}

/// One HTTP/1.1 request to the service on 127.0.0.1, with `Host` set as the service requires.
///
/// # Errors
/// No connection, a broken exchange, or no answer within `timeout`.
pub async fn http(
    port: u16,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<Reply, HttpError> {
    let exchange = async {
        let stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(conn);
        let mut req = Request::builder().method(method).uri(path).header("Host", format!("127.0.0.1:{port}"));
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req.body(Full::new(Bytes::from(body.unwrap_or_default())))?;
        let res = sender.send_request(req).await?;
        let status = res.status();
        let body = res.into_body().collect().await?.to_bytes();
        anyhow::Ok(Reply { status, body })
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(e)) => Err(HttpError::Failed(e)),
        Err(_) => Err(HttpError::Timeout),
    }
}

/// `GET /health` answered 2xx within `timeout`.
pub async fn healthy(port: u16, timeout: Duration) -> bool {
    http(port, Method::GET, "/health", &[], None, timeout).await.is_ok_and(|r| r.status.is_success())
}

/// A connection to the service whose listener proved, on this very connection, that it holds the
/// endpoint's token (THREAT-MODEL SR-13). The token is only ever sent on such a connection: a socket
/// that is still open cannot change owner, so nothing that took the port between the proof and the
/// request can be handed the token (sec-local-2).
pub struct Proven {
    pub endpoint: Endpoint,
    sender: SendRequest<Full<Bytes>>,
    /// How long the connection may sit idle and still carry the next call: half what the service said
    /// in its hello that it holds a connection (`keep`), at most [`REUSE_WITHIN`]. Zero for a service
    /// that did not say (one from before kept connections): its connections carry one call, as then.
    reuse_within: Duration,
    /// A second handle on the same socket, so a kept connection's state can be read from the OS
    /// before it carries a call ([`peer_still_there`]). `None` when the OS gave no second handle, or
    /// for a test's in-memory stream.
    watch: Option<std::net::TcpStream>,
}

/// A handle of our own on `stream`'s socket. Closing it does not close the socket while hyper's
/// handle is open, and the reverse holds too: a connection hyper closed itself (the service's idle
/// close, a restart) stays half open until its `Proven` is dropped, at the next call's pool sweep or
/// when the process exits; at most [`MAX_KEPT`] of them. std makes it uninheritable
/// (`F_DUPFD_CLOEXEC`, `WSA_FLAG_NO_HANDLE_INHERIT`), so a service this process starts never holds it.
fn watch_handle(stream: &TcpStream) -> Option<std::net::TcpStream> {
    #[cfg(unix)]
    let owned = std::os::fd::AsFd::as_fd(stream).try_clone_to_owned().ok()?;
    #[cfg(windows)]
    let owned = std::os::windows::io::AsSocket::as_socket(stream).try_clone_to_owned().ok()?;
    let watch = std::net::TcpStream::from(owned);
    // On Unix the flag belongs to the shared file description, which tokio already made non-blocking:
    // never clear it here, or hyper's own reads would block the runtime.
    watch.set_nonblocking(true).ok()?;
    Some(watch)
}

/// Whether the service is still at the other end of a kept connection, asked of the OS itself.
///
/// hyper learns of a close only when the runtime next polls the socket, so a call made just after
/// the service died could go out on the dead connection first. An action sent so fails and is never
/// sent again (SR-35), though the service never saw it; a read runs once more ([`RESENT_ONCE`]). A peek finds the close, or a reset, already in
/// the socket's queue: nothing has been written, so the call goes on a fresh proven connection
/// instead. Anything but "nothing to read yet" (an end, an error, bytes nobody asked for) means the
/// connection is not reused.
fn peer_still_there(watch: Option<&std::net::TcpStream>) -> bool {
    let Some(watch) = watch else { return true };
    matches!(watch.peek(&mut [0u8; 1]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
}

impl std::fmt::Debug for Proven {
    // The endpoint's own Debug hides the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proven").field("endpoint", &self.endpoint).finish_non_exhaustive()
    }
}

impl Proven {
    /// Sends `req` on the proven connection. `Host` is set here, as the service requires.
    ///
    /// # Errors
    /// The connection closed or the exchange broke (hyper's error).
    pub async fn send(
        &mut self,
        req: hyper::http::request::Builder,
        body: Bytes,
    ) -> anyhow::Result<Response<Incoming>> {
        let req = req.header("Host", format!("127.0.0.1:{}", self.endpoint.port)).body(Full::new(body))?;
        Ok(self.sender.send_request(req).await?)
    }
}

/// Opens a connection to `e.port` and has the listener prove it holds `e.token` on it: it answers a
/// fresh nonce with `HMAC-SHA256(token, "phantab-hello" || nonce)`, checked in constant time. `None`
/// for anything else (no listener, a wrong proof, no answer within `timeout`); that connection is
/// dropped without the token ever being written to it.
pub async fn prove(e: Endpoint, timeout: Duration) -> Option<Proven> {
    let nonce = crate::hello::nonce().ok()?;
    let target = format!("/hello?nonce={}", crate::util::hex(&nonce));
    let exchange = async {
        let stream = TcpStream::connect(("127.0.0.1", e.port)).await.ok()?;
        // Without a second handle (the OS refused one) the connection still works; it is just not checked.
        let watch = watch_handle(&stream);
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.ok()?;
        // With upgrades: the native host joins `/bridge` on this same connection.
        tokio::spawn(conn.with_upgrades());
        let mut proven = Proven { endpoint: e, sender, reuse_within: Duration::ZERO, watch };
        let res = proven.send(Request::get(&target), Bytes::new()).await.ok()?;
        let ok = res.status().is_success();
        let body = res.into_body().collect().await.ok()?.to_bytes();
        let answer: Value = serde_json::from_slice(&body).ok()?;
        let proof = answer.get("proof").and_then(Value::as_str)?;
        if !(ok && crate::hello::verify(&proven.endpoint.token, &nonce, proof)) {
            return None;
        }
        // Half the service's hold, so a reused connection is never the one the service is closing.
        let keep = answer.get(crate::hello::KEEP).and_then(Value::as_u64).unwrap_or(0);
        proven.reuse_within = REUSE_WITHIN.min(Duration::from_secs(keep) / 2);
        Some(proven)
    };
    tokio::time::timeout(timeout, exchange).await.ok().flatten()
}

/// A proven connection to the running service, starting the service first when allowed. An endpoint
/// whose listener does not prove itself (SR-13) is stale: a fresh service is started, as for a dead one.
///
/// # Errors
/// The service is down and `start` is false, it did not come up, or it speaks another protocol.
pub async fn ensure_service(start: bool) -> anyhow::Result<Proven> {
    ensure_service_at(&paths::endpoint_path(), start).await
}

async fn ensure_service_at(endpoint_path: &Path, start: bool) -> anyhow::Result<Proven> {
    let mut found = None;
    if let Ok(e) = read_endpoint_at(endpoint_path) {
        // An older or newer service may not know the hello; its own endpoint says so, and it must
        // drain rather than be raced by a second start.
        if e.protocol != json!(SERVICE_PROTOCOL) && healthy(e.port, Duration::from_secs(1)).await {
            return Err(upgrade_pending());
        }
        found = prove(e, Duration::from_secs(1)).await;
    }
    if found.is_none() {
        if !start {
            return Err(anyhow!("Browser service is not running."));
        }
        // R15: owner-only from the create call; the service's own lock_down checks it at start.
        phantab_window::secure_dir::create_owner_only(&paths::runtime_dir())
            .map_err(|e| anyhow!(node_fs_error(&e, "mkdir", &paths::runtime_dir())))?;
        read_config()?;
        spawn_service()?;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(next) = read_endpoint_at(endpoint_path)
                && let Some(proven) = prove(next, Duration::from_millis(400)).await
            {
                found = Some(proven);
                break;
            }
        }
    }
    let Some(proven) = found else {
        return Err(anyhow!("Browser service failed to start; run doctor."));
    };
    if proven.endpoint.protocol != json!(SERVICE_PROTOCOL) {
        return Err(upgrade_pending());
    }
    Ok(proven)
}

fn upgrade_pending() -> anyhow::Error {
    anyhow!(
        "Browser service upgrade is pending. Drain existing pages, then restart only the phantab service; never close Chrome."
    )
}

/// The environment the service is started with (THREAT-MODEL SR-14): only what a Windows or macOS
/// process needs, the runtime overrides, and `LANG` and the proxy variables, which the service passes
/// on to `bw` (`signin::bitwarden::cli::BW_ENV_ALLOWED`); without them every `bw` run from the service
/// lost a proxy that `phantab bitwarden connect`, run in the owner's terminal, had. Names match in any
/// case, so `HTTPS_PROXY` passes too. Chrome gets `LANG` but never the proxy variables (phantab-cdp's
/// `chrome_command`), and a `proxy` in the Bitwarden config replaces them for `bw`. The first client's
/// `RUST_LOG`, loaders and secrets stay with that client.
const SERVICE_ENV: &[&str] = &[
    "SystemRoot",
    "windir",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "APPDATA",
    "ProgramData",
    "ComSpec",
    "HOME",
    "TMPDIR",
    "LANG",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
    paths::RUNTIME_ENV,
];

/// SR-48: the installed binary's folder (`<runtime>/bin`) is owner-only, like the runtime, checked at
/// every service start; a link or a foreign owner refuses to start. A binary outside an install (a
/// development build under `target/`) is not checked.
///
/// # Errors
/// The folder is a link, someone else's, or cannot be restricted.
pub fn lock_binary_folder() -> Result<(), phantab_window::secure_dir::SecureDirError> {
    let Ok(exe) = std::env::current_exe() else { return Ok(()) };
    match (paths::installed_runtime(&exe), exe.parent()) {
        (Some(_), Some(bin)) => phantab_window::secure_dir::lock_down(bin),
        _ => Ok(()),
    }
}

/// Whether the service inherits the variable `name` (SR-14): the list above, case-insensitively, and in
/// test builds (`test-seams`, which a release build cannot turn on) `PHANTAB_TEST_*`.
#[must_use]
pub fn service_env_allowed(name: &str) -> bool {
    if cfg!(feature = "test-seams") && name.starts_with("PHANTAB_TEST_") {
        return true;
    }
    SERVICE_ENV.iter().any(|allowed| name.eq_ignore_ascii_case(allowed))
}

/// Starts `phantab serve` from this binary, detached and windowless, so it outlives the client that
/// started it (the native host lives only as long as Chrome's port; the MCP server as long as its
/// session). This binary, not `installedSource`: the config is writable, the running image is not
/// chosen by it. It runs in the runtime dir (owner-only, made before the start), not in whatever folder
/// the client was started from (a project, Chrome's folder), which it would otherwise keep open, and
/// where a relative lookup would find files another account may have put.
fn spawn_service() -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("Browser service failed to start; run doctor.")?;
    let runtime = std::path::absolute(paths::runtime_dir())
        .map_err(|e| anyhow!("Browser service failed to start: {e}"))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("serve")
        .current_dir(&runtime)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env_clear();
    for (k, v) in std::env::vars_os() {
        if service_env_allowed(&k.to_string_lossy()) {
            cmd.env(&k, v);
        }
    }
    if std::env::var_os(paths::RUNTIME_ENV).is_some_and(|v| !v.is_empty()) {
        // A relative override names the folder from the client's folder; from the runtime it would not.
        cmd.env(paths::RUNTIME_ENV, &runtime);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        // Node's `detached` adds the new process group: Ctrl-C in the client's console must not reach it.
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    cmd.spawn().map(drop).map_err(|e| anyhow!("Browser service failed to start: {e}"))
}

/// A proven connection that an `/rpc` call finished on, kept for this process's next call: the connect,
/// the handshake and the SR-13 hello are paid once per connection rather than per call (perf-idle-1,
/// perf-ops-7). The token still goes only where it was proven, on the same socket.
#[derive(Debug)]
struct Kept {
    endpoint_path: PathBuf,
    proven: Proven,
    idle_since: Instant,
}

/// Idle connections kept per process. An MCP session's calls and heartbeat reuse one; concurrent calls
/// each take a connection of their own, as before, and up to this many come back.
const MAX_KEPT: usize = 4;
/// A kept connection idle longer than this is closed rather than reused: longer than the MCP heartbeat,
/// so an idle session keeps its one connection, and at most half the service's hold on it
/// ([`crate::service::KEPT_IDLE`], which the hello advertises), so a call never races the service
/// closing it.
const REUSE_WITHIN: Duration = Duration::from_secs(60);
const _: () = assert!(REUSE_WITHIN.as_secs() * 2 <= crate::service::KEPT_IDLE.as_secs());
// The idle saving needs the heartbeat to find its connection still kept.
const _: () = assert!(REUSE_WITHIN.as_secs() > crate::mcp::HEARTBEAT_EVERY.as_secs());
/// An `/rpc` exchange's budget, as Node's 90000 ms abort: on a kept connection it also covers the
/// readiness probe, on a fresh one it starts once the service is proven.
pub(crate) const RPC_TIMEOUT: Duration = Duration::from_secs(90);
/// The longest wait for a kept connection to be ready, within [`RPC_TIMEOUT`].
const READY_WITHIN: Duration = Duration::from_secs(1);

static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

/// Calls retried on another connection because a kept one closed before the call was written: the
/// retry test checks that branch ran.
#[cfg(test)]
static RETRIED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The most recent kept connection for `endpoint_path` that is still open and ready by `deadline`,
/// with its service still at the other end.
async fn take_kept(endpoint_path: &Path, deadline: tokio::time::Instant) -> Option<Proven> {
    loop {
        let mut proven = {
            let mut pool = crate::util::lock(&KEPT);
            pool.retain(|k| !k.proven.sender.is_closed() && k.idle_since.elapsed() < k.proven.reuse_within);
            let at = pool.iter().rposition(|k| k.endpoint_path == endpoint_path)?;
            pool.remove(at).proven
        };
        // Ready at once unless hyper is still finishing the last exchange; an error means it closed.
        let by = deadline.min(tokio::time::Instant::now() + READY_WITHIN);
        if let Ok(Ok(())) = tokio::time::timeout_at(by, proven.sender.ready()).await
            && peer_still_there(proven.watch.as_ref())
        {
            return Some(proven);
        }
    }
}

/// Keeps `proven` for the next call, unless its service did not say it holds connections.
fn keep(endpoint_path: &Path, proven: Proven) {
    let mut pool = crate::util::lock(&KEPT);
    let here = pool.iter().filter(|k| k.endpoint_path == endpoint_path).count();
    if here < MAX_KEPT && !proven.reuse_within.is_zero() && !proven.sender.is_closed() {
        pool.push(Kept { endpoint_path: endpoint_path.to_path_buf(), proven, idle_since: Instant::now() });
    }
}

/// How one `/rpc` exchange on a proven connection ended.
enum Sent {
    Done(Reply),
    /// The connection closed before any of the request was written (hyper hands the request back), so
    /// the service never saw it and another proven connection may carry it.
    Unsent(HttpError),
    /// The call may have been written, then the connection ended or broke before any answer began:
    /// a reset, a close, a failed write, an answer head that did not parse. The service may have run
    /// it, so only [`RESENT_ONCE`] is sent again.
    Lost(HttpError),
    /// Anything else: an answer cut short, or the budget spent. Never sent again (SR-35).
    Failed(HttpError),
}

/// The methods that only read, or say the client is still there (`heartbeat`), so a call lost on a
/// kept connection runs once more, on a freshly proven one, as a read interrupted by a detach does
/// (SR-35). A service killed a moment before the call can still look alive to the socket: the kernel
/// resets the connection only after the process is gone (macOS, about 2 ms after the process reads
/// as dead), so the call is written and then reset. An action is never in this list: it may have
/// landed, and fails as it did. The service's method test holds each name to an effect-free method.
pub(crate) const RESENT_ONCE: &[&str] = &["status", "heartbeat", "pages", "tabs"];

async fn send_rpc(proven: &mut Proven, body: &Bytes, deadline: tokio::time::Instant) -> Sent {
    let req = Request::post("/rpc")
        .header("Host", format!("127.0.0.1:{}", proven.endpoint.port))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", proven.endpoint.token))
        .body(Full::new(body.clone()));
    let req = match req {
        Ok(r) => r,
        Err(e) => return Sent::Failed(HttpError::Failed(e.into())),
    };
    let exchange = async {
        let res = proven.sender.try_send_request(req).await.map_err(|mut e| {
            let sent: fn(HttpError) -> Sent =
                if e.take_message().is_some() { Sent::Unsent } else { Sent::Lost };
            (sent, anyhow::Error::from(e.into_error()))
        })?;
        let status = res.status();
        let cut_short: fn(HttpError) -> Sent = Sent::Failed;
        let body =
            res.into_body().collect().await.map_err(|e| (cut_short, anyhow::Error::from(e)))?.to_bytes();
        Ok::<_, (fn(HttpError) -> Sent, anyhow::Error)>(Reply { status, body })
    };
    match tokio::time::timeout_at(deadline, exchange).await {
        Ok(Ok(reply)) => Sent::Done(reply),
        Ok(Err((sent, e))) => sent(HttpError::Failed(e)),
        Err(_) => Sent::Failed(HttpError::Timeout),
    }
}

/// `POST /rpc` with `body`: on a kept connection when one is open, else on a freshly proven one. A
/// `read` ([`RESENT_ONCE`]) lost on a kept connection goes once more, on a freshly proven one, within
/// the same [`RPC_TIMEOUT`].
async fn post_rpc(endpoint_path: &Path, start: bool, body: &Bytes, read: bool) -> anyhow::Result<Reply> {
    let deadline = tokio::time::Instant::now() + RPC_TIMEOUT;
    let mut resend = false;
    while let Some(mut proven) = take_kept(endpoint_path, deadline).await {
        match send_rpc(&mut proven, body, deadline).await {
            Sent::Done(reply) => {
                keep(endpoint_path, proven);
                return Ok(reply);
            }
            // Closed under us (the service restarted, most likely): the next one, or a fresh proof.
            Sent::Unsent(_) => {
                #[cfg(test)]
                RETRIED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            // Once more and no further: straight to a fresh proof, not another kept connection.
            Sent::Lost(_) if read => {
                resend = true;
                break;
            }
            Sent::Lost(e) | Sent::Failed(e) => return Err(e.into()),
        }
    }
    let mut proven = ensure_service_at(endpoint_path, start).await?;
    let by = if resend { deadline } else { tokio::time::Instant::now() + RPC_TIMEOUT };
    match send_rpc(&mut proven, body, by).await {
        Sent::Done(reply) => {
            keep(endpoint_path, proven);
            Ok(reply)
        }
        // The token never goes to a connection that was not proven, so a fresh connection that closed
        // before the call went out ends the call, as a refused connect did.
        Sent::Unsent(e) | Sent::Lost(e) | Sent::Failed(e) => Err(e.into()),
    }
}

/// Calls a service method, starting the service when `start` allows.
///
/// # Errors
/// The service is unreachable, or the method failed (its message, as the service gave it).
pub async fn rpc(method: &str, args: Value, client: &str, start: bool) -> anyhow::Result<Value> {
    rpc_at(&paths::endpoint_path(), method, args, client, start).await
}

async fn rpc_at(
    endpoint_path: &Path,
    method: &str,
    args: Value,
    client: &str,
    start: bool,
) -> anyhow::Result<Value> {
    let body = Bytes::from(serde_json::to_vec(&json!({ "method": method, "args": args, "client": client }))?);
    let reply = post_rpc(endpoint_path, start, &body, RESENT_ONCE.contains(&method)).await?;
    let value: Value =
        serde_json::from_slice(&reply.body).map_err(|err| anyhow!(json_error(&reply.body, &err)))?;
    if let Some(error) = value.get("error").filter(|v| crate::util::truthy(v)) {
        return Err(anyhow!(crate::util::js_string(Some(error))));
    }
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// How a [`Fake`] answers the hello.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Behaviour {
        /// As this version's service: the proof and `keep`.
        Keeps,
        /// As a service from before kept connections: the proof alone.
        Old,
        /// Proves itself, then closes the connection.
        ClosesAfterHello,
    }

    /// A stand-in service on 127.0.0.1 for the client: `/hello` proves `token`, `/rpc` answers
    /// `{"result": <its method>}` after `args.delay` ms. Every request is recorded as (connection,
    /// request line, whether it carried `Authorization`).
    struct Fake {
        port: u16,
        token: String,
        seen: Arc<Mutex<Vec<(usize, String, bool)>>>,
        connections: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Fake {
        async fn start(token: &str, behaviour: Behaviour) -> Self {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let seen: Arc<Mutex<Vec<(usize, String, bool)>>> = Arc::default();
            let connections = Arc::new(AtomicUsize::new(0));
            let (seen2, connections2, token2) =
                (Arc::clone(&seen), Arc::clone(&connections), token.to_owned());
            let task = tokio::spawn(async move {
                // Aborting this task drops the set, which closes every connection: a service exiting.
                let mut open = tokio::task::JoinSet::new();
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let n = connections2.fetch_add(1, Ordering::SeqCst);
                    let (seen, token) = (Arc::clone(&seen2), token2.clone());
                    let handler = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let (seen, token) = (Arc::clone(&seen), token.clone());
                        async move {
                            let target = req.uri().to_string();
                            let auth = req.headers().contains_key("authorization");
                            crate::util::lock(&seen).push((n, format!("{} {target}", req.method()), auth));
                            let mut res = if let Some(nonce) = crate::hello::nonce_of(&target) {
                                let proof = crate::hello::proof(&token, &nonce).unwrap();
                                let mut answer = json!({ "proof": proof });
                                if behaviour != Behaviour::Old {
                                    answer[crate::hello::KEEP] = json!(120);
                                }
                                Response::new(Full::new(Bytes::from(answer.to_string())))
                            } else {
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let call: Value = serde_json::from_slice(&body).unwrap();
                                if let Some(ms) = call["args"]["delay"].as_u64() {
                                    tokio::time::sleep(Duration::from_millis(ms)).await;
                                }
                                let answer = json!({ "result": call["method"] }).to_string();
                                Response::new(Full::new(Bytes::from(answer)))
                            };
                            if behaviour == Behaviour::ClosesAfterHello && target.starts_with("/hello") {
                                res.headers_mut().insert("connection", "close".parse().unwrap());
                            }
                            Ok::<_, std::convert::Infallible>(res)
                        }
                    });
                    open.spawn(
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), handler),
                    );
                }
            });
            Self { port, token: token.to_owned(), seen, connections, task }
        }

        /// Points `dir`'s endpoint at this service.
        fn advertise(&self, dir: &Path) -> PathBuf {
            let path = dir.join("endpoint.json");
            let endpoint = json!({
                "port": self.port, "token": self.token, "pid": 1, "protocol": SERVICE_PROTOCOL, "source": "fake"
            });
            std::fs::write(&path, endpoint.to_string()).unwrap();
            path
        }

        fn connections(&self) -> usize {
            self.connections.load(Ordering::SeqCst)
        }

        fn seen(&self) -> Vec<(usize, String, bool)> {
            crate::util::lock(&self.seen).clone()
        }

        fn calls(&self) -> usize {
            self.seen().iter().filter(|(_, line, _)| line == "POST /rpc").count()
        }

        /// The hello first on every connection, without the token; every call after it, with it.
        fn assert_proven_first(&self) {
            let seen = self.seen();
            for n in 0..self.connections() {
                let on: Vec<_> = seen.iter().filter(|r| r.0 == n).collect();
                if let Some((first, rest)) = on.split_first() {
                    assert!(first.1.starts_with("GET /hello?nonce=") && !first.2, "{on:?}");
                    assert!(rest.iter().all(|r| r.1 == "POST /rpc" && r.2), "{on:?}");
                }
            }
        }

        async fn stop(self) {
            self.task.abort();
            let _ = self.task.await;
        }
    }

    /// perf-idle-1, perf-ops-7: one connection, one hello, then every call on it.
    #[tokio::test]
    async fn calls_reuse_the_connection_they_proved() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&"ab".repeat(32), Behaviour::Keeps).await;
        let path = fake.advertise(dir.path());
        for method in ["status", "pages", "heartbeat", "tabs", "status"] {
            assert_eq!(rpc_at(&path, method, json!({}), "t", false).await.unwrap(), json!(method));
        }
        assert_eq!(fake.connections(), 1);
        assert_eq!(fake.seen().len(), 6, "one hello, five calls: {:?}", fake.seen());
        fake.assert_proven_first();
        fake.stop().await;
    }

    /// Concurrent calls each take a proven connection of their own and get their own answer, whatever
    /// order the answers come back in; afterwards calls reuse those connections.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_calls_get_their_own_answers() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&"cd".repeat(32), Behaviour::Keeps).await;
        let path = fake.advertise(dir.path());
        let mut calls = tokio::task::JoinSet::new();
        for i in 0..8u64 {
            let path = path.clone();
            // The first call answers last.
            calls.spawn(async move {
                let got = rpc_at(&path, &format!("m{i}"), json!({ "delay": (8 - i) * 25 }), "t", false).await;
                (i, got.unwrap())
            });
        }
        let mut order = Vec::new();
        while let Some(done) = calls.join_next().await {
            let (i, got) = done.unwrap();
            assert_eq!(got, json!(format!("m{i}")));
            order.push(i);
        }
        assert_ne!(order, (0..8).collect::<Vec<_>>(), "the answers overlapped");
        let opened = fake.connections();
        assert!((1..=8).contains(&opened), "{opened}");
        for i in 0..6 {
            assert_eq!(rpc_at(&path, "next", json!({ "n": i }), "t", false).await.unwrap(), json!("next"));
        }
        assert_eq!(fake.connections(), opened, "sequential calls reuse a kept connection");
        assert_eq!(fake.calls(), 14);
        fake.assert_proven_first();
        fake.stop().await;
    }

    /// sec-local-2: a listener that proves the token and then closes never gets the token on another
    /// connection. The call fails as a refused connect does.
    #[tokio::test]
    async fn the_token_goes_only_on_the_connection_that_proved_it() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&"ef".repeat(32), Behaviour::ClosesAfterHello).await;
        let path = fake.advertise(dir.path());
        let err = rpc_at(&path, "status", json!({}), "t", false).await.unwrap_err();
        assert_eq!(err.to_string(), "fetch failed");
        let seen = fake.seen();
        assert!(seen.iter().all(|(_, _, auth)| !auth), "{seen:?}");
        assert_eq!(fake.connections(), 1, "{seen:?}");
        fake.stop().await;
    }

    /// A service restart: the kept connection closes with the old service, and the next call reads the
    /// new endpoint and proves the new service, as a first call does.
    #[tokio::test]
    async fn a_restarted_service_is_proven_again() {
        let dir = tempfile::tempdir().unwrap();
        let old = Fake::start(&"01".repeat(32), Behaviour::Keeps).await;
        let path = old.advertise(dir.path());
        assert_eq!(rpc_at(&path, "status", json!({}), "t", false).await.unwrap(), json!("status"));
        old.stop().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let new = Fake::start(&"02".repeat(32), Behaviour::Keeps).await;
        new.advertise(dir.path());
        assert_eq!(rpc_at(&path, "status", json!({}), "t", false).await.unwrap(), json!("status"));
        assert_eq!((new.connections(), new.calls()), (1, 1));
        new.assert_proven_first();
        // Down for good: the stale endpoint proves nothing and, without `start`, nothing starts.
        new.stop().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let err = rpc_at(&path, "status", json!({}), "t", false).await.unwrap_err();
        assert_eq!(err.to_string(), "Browser service is not running.");
    }

    /// SR-35: an action in flight when the service exits fails and is never sent again, not even to
    /// a service that is already up.
    #[tokio::test]
    async fn an_in_flight_call_is_not_replayed() {
        let dir = tempfile::tempdir().unwrap();
        let old = Fake::start(&"03".repeat(32), Behaviour::Keeps).await;
        let path = old.advertise(dir.path());
        let call = tokio::spawn({
            let path = path.clone();
            // Answered only long after the old service stops, so the call is still in flight then.
            async move { rpc_at(&path, "act", json!({ "delay": 60_000 }), "t", false).await }
        });
        // In flight means the old service has the call. A fixed sleep raced a loaded machine: a call not
        // yet connected when the old service stopped was refused ("not running"), not cut off.
        tokio::time::timeout(Duration::from_secs(30), async {
            while old.calls() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the call reaches the old service");
        let new = Fake::start(&"04".repeat(32), Behaviour::Keeps).await;
        new.advertise(dir.path());
        old.stop().await;
        let err = call.await.unwrap().unwrap_err();
        assert_eq!(err.to_string(), "fetch failed");
        assert_eq!(new.calls(), 0, "{:?}", new.seen());
        new.stop().await;
    }

    /// A service from before kept connections does not say `keep` in its hello, and holds an idle
    /// connection only for its 30 s header wait: each call gets a connection of its own, as before, so
    /// none races that close.
    #[tokio::test]
    async fn an_older_service_gets_a_connection_per_call() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&"05".repeat(32), Behaviour::Old).await;
        let path = fake.advertise(dir.path());
        for method in ["status", "heartbeat", "pages"] {
            assert_eq!(rpc_at(&path, method, json!({}), "t", false).await.unwrap(), json!(method));
        }
        assert_eq!(fake.connections(), 3, "{:?}", fake.seen());
        assert_eq!(fake.seen().len(), 6, "a hello and one call on each: {:?}", fake.seen());
        fake.assert_proven_first();
        assert!(!crate::util::lock(&KEPT).iter().any(|k| k.endpoint_path == path));
        fake.stop().await;
    }

    /// SR-35's retry: a kept connection that closed before the call was written (here, before its
    /// connection task even saw the close) is put aside, and the call goes on a newly proven connection,
    /// never an unproven one.
    #[tokio::test]
    async fn a_call_unsent_on_a_closed_connection_is_retried_on_a_proven_one() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&"06".repeat(32), Behaviour::Keeps).await;
        let path = fake.advertise(dir.path());
        // A kept connection whose service has gone. On this one-thread runtime its connection task
        // does not run until the call below waits, so the pool still takes it as open and ready.
        let (client, server) = tokio::io::duplex(1 << 16);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(conn);
        sender.ready().await.unwrap();
        drop(server);
        assert!(!sender.is_closed());
        let endpoint = read_endpoint_at(&path).unwrap();
        let proven = Proven { endpoint, sender, reuse_within: REUSE_WITHIN, watch: None };
        crate::util::lock(&KEPT).push(Kept {
            endpoint_path: path.clone(),
            proven,
            idle_since: Instant::now(),
        });
        let before = RETRIED.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(rpc_at(&path, "status", json!({}), "t", false).await.unwrap(), json!("status"));
        assert!(
            RETRIED.load(std::sync::atomic::Ordering::SeqCst) > before,
            "the kept connection was not tried"
        );
        assert_eq!((fake.connections(), fake.calls()), (1, 1), "{:?}", fake.seen());
        fake.assert_proven_first();
        fake.stop().await;
    }

    /// A service killed just before a call: the close has reached the kept socket, but on this
    /// one-thread runtime hyper has not polled it yet, so the connection still looks open and ready.
    /// The OS check finds the close before anything is written, and the call goes on a fresh proven
    /// connection. Without it the call went out on the dead socket and failed (macOS, mcp.rs's restart
    /// test); the dead socket's end shows nothing was sent to it.
    #[tokio::test]
    async fn a_kept_connection_closed_before_hyper_saw_it_is_not_used() {
        use std::io::Read as _;
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&"07".repeat(32), Behaviour::Keeps).await;
        let path = fake.advertise(dir.path());
        let gone = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let stream = TcpStream::connect(gone.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = gone.accept().unwrap();
        // Set while the connection is up: macOS answers EINVAL to setsockopt once it has closed.
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let watch = watch_handle(&stream);
        assert!(watch.is_some());
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(conn);
        sender.ready().await.unwrap();
        // The service's end closes; nothing here polls the runtime, so hyper does not see it.
        server.shutdown(std::net::Shutdown::Write).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!sender.is_closed() && sender.is_ready());
        assert!(!peer_still_there(watch.as_ref()));
        let endpoint = read_endpoint_at(&path).unwrap();
        crate::util::lock(&KEPT).push(Kept {
            endpoint_path: path.clone(),
            proven: Proven { endpoint, sender, reuse_within: REUSE_WITHIN, watch },
            idle_since: Instant::now(),
        });
        assert_eq!(rpc_at(&path, "status", json!({}), "t", false).await.unwrap(), json!("status"));
        assert_eq!((fake.connections(), fake.calls()), (1, 1), "{:?}", fake.seen());
        fake.assert_proven_first();
        // The dead connection was dropped unused: its far end reads an end, not a request. Its
        // connection task closes its handle when it next runs.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut got = Vec::new();
        server.read_to_end(&mut got).unwrap();
        assert!(got.is_empty(), "{}", String::from_utf8_lossy(&got));
        fake.stop().await;
    }

    /// Keeps, for `path`'s endpoint, a connection to a service that reads the next call whole and then
    /// goes without answering: a service killed as the call reached it, whose socket still looked open.
    /// The thread returns what it read.
    async fn keep_one_that_reads_and_goes(path: &Path) -> std::thread::JoinHandle<Vec<u8>> {
        use std::io::Read as _;
        let gone = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let stream = TcpStream::connect(gone.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = gone.accept().unwrap();
        // Set while the connection is up: macOS answers EINVAL to setsockopt once it has closed.
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let watch = watch_handle(&stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(conn);
        sender.ready().await.unwrap();
        let endpoint = read_endpoint_at(path).unwrap();
        crate::util::lock(&KEPT).push(Kept {
            endpoint_path: path.to_path_buf(),
            proven: Proven { endpoint, sender, reuse_within: REUSE_WITHIN, watch },
            idle_since: Instant::now(),
        });
        std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            // The call's JSON body ends the request.
            while !got.ends_with(b"}") {
                let n = server.read(&mut buf).unwrap();
                assert!(n > 0, "{}", String::from_utf8_lossy(&got));
                got.extend_from_slice(&buf[..n]);
            }
            got
        })
    }

    /// SR-35 for a restart: a read written to a kept connection whose service then went before
    /// answering runs once more, on a freshly proven connection (mcp.rs's restart test on macOS, where
    /// the kernel resets the socket a moment after the killed service reads as dead).
    #[tokio::test]
    async fn a_read_lost_on_a_kept_connection_runs_once_more_on_a_proven_one() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&"08".repeat(32), Behaviour::Keeps).await;
        let path = fake.advertise(dir.path());
        for method in RESENT_ONCE {
            let gone = keep_one_that_reads_and_goes(&path).await;
            assert_eq!(rpc_at(&path, method, json!({}), "t", false).await.unwrap(), json!(method));
            let got = String::from_utf8(gone.join().unwrap()).unwrap();
            assert!(got.starts_with("POST /rpc ") && got.contains(&format!("\"{method}\"")), "{got}");
        }
        // Each resend proves a connection of its own, rather than trying another kept one.
        let n = RESENT_ONCE.len();
        assert_eq!((fake.connections(), fake.calls()), (n, n), "{:?}", fake.seen());
        fake.assert_proven_first();
        fake.stop().await;
    }

    /// Every other method lost so is never sent again (SR-35): an action may have landed before the
    /// service went, and the client resends no read beyond the four.
    #[tokio::test]
    async fn every_other_method_lost_on_a_kept_connection_is_not_sent_again() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&"09".repeat(32), Behaviour::Keeps).await;
        let path = fake.advertise(dir.path());
        let service =
            ["status", "release", "disconnect", "heartbeat", "shutdown", "check_wait", "restart_quiet"];
        let all = service
            .into_iter()
            .chain(crate::engine_api::EngineMethod::ALL.map(crate::engine_api::EngineMethod::name));
        for method in all.filter(|m| !RESENT_ONCE.contains(m)) {
            let gone = keep_one_that_reads_and_goes(&path).await;
            let err = rpc_at(&path, method, json!({}), "t", false).await.unwrap_err();
            assert_eq!(err.to_string(), "fetch failed");
            assert!(String::from_utf8(gone.join().unwrap()).unwrap().starts_with("POST /rpc "));
        }
        assert_eq!(fake.calls(), 0, "{:?}", fake.seen());
        fake.stop().await;
    }

    /// A kept connection whose service is there reads as there, so it carries the next call.
    #[tokio::test]
    async fn a_live_kept_connection_reads_as_there() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().unwrap();
        let watch = watch_handle(&stream).unwrap();
        assert!(peer_still_there(Some(&watch)));
        // Only the second handle is closed: the connection itself stays up, as its far end sees.
        drop(watch);
        assert!(peer_still_there(Some(&watch_handle(&stream).unwrap())));
        server.set_nonblocking(true).unwrap();
        let far = server.peek(&mut [0u8; 1]);
        assert!(matches!(&far, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "{far:?}");
        assert!(peer_still_there(None));
    }

    #[tokio::test]
    async fn a_kept_connection_does_not_print_the_token() {
        let token = "secret-token";
        let e = Endpoint { port: 1, token: token.into(), pid: 2, protocol: json!(1), source: String::new() };
        let (client, _server) = tokio::io::duplex(64);
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(conn);
        let kept = Kept {
            endpoint_path: PathBuf::new(),
            proven: Proven { endpoint: e, sender, reuse_within: REUSE_WITHIN, watch: None },
            idle_since: Instant::now(),
        };
        let shown = format!("{kept:?} {kept:#?}");
        assert!(shown.contains("port") && !shown.contains(token), "{shown}");
    }

    fn remote(listen: &str, url: &str) -> Result<RemoteListen, String> {
        RemoteViewer { listen: listen.into(), public_base_url: url.into(), trusted_identity: None }.checked()
    }

    /// SR-70: the remote view listens on loopback only, and answers one exact Host.
    #[test]
    fn a_remote_viewer_listens_on_loopback_for_one_address() {
        let r = remote("127.0.0.1:8491", "http://mypc:8490/").unwrap();
        assert_eq!(
            (r.base.as_str(), r.host.as_str(), r.origin.as_str()),
            ("http://mypc:8490", "mypc:8490", "http://mypc:8490")
        );
        let r = remote("[::1]:8491", "https://mypc.tail0000.ts.net").unwrap();
        assert_eq!(
            (r.base.as_str(), r.host.as_str()),
            ("https://mypc.tail0000.ts.net", "mypc.tail0000.ts.net")
        );
        for listen in ["0.0.0.0:8491", "100.64.0.1:8491", "127.0.0.1:0", "localhost:8491", "8491"] {
            assert!(remote(listen, "http://mypc:8490").is_err(), "{listen}");
        }
        for url in [
            "mypc:8490",
            "ftp://mypc",
            "http://mypc:8490/view",
            "http://u:p@mypc",
            "http://mypc/?a=1",
            "file:///c:/x",
        ] {
            assert!(remote("127.0.0.1:8491", url).is_err(), "{url}");
        }
        let with = |header: &str, equals: &str| {
            RemoteViewer {
                listen: "127.0.0.1:8491".into(),
                public_base_url: "http://mypc:8490".into(),
                trusted_identity: Some(TrustedIdentity { header: header.into(), equals: equals.into() }),
            }
            .checked()
        };
        assert_eq!(
            with("Tailscale-User-Login", "owner@example.test").unwrap().identity,
            Some(("tailscale-user-login".into(), "owner@example.test".into()))
        );
        assert!(with("not a header", "x").is_err());
        assert!(with("Tailscale-User-Login", "").is_err());
    }

    /// SR-76: only real profile folders other than the usual one, each once, in the owner's order.
    #[test]
    fn allowed_other_profiles_drops_the_usual_one_bad_names_and_repeats() {
        let config: Config = serde_json::from_value(json!({
            "profileDirectory": "Profile 4",
            "otherProfiles": ["Profile 1", "Profile 4", "../Default", "Profile 1", "Default", "--x"],
        }))
        .unwrap();
        assert_eq!(config.allowed_other_profiles(), ["Profile 1", "Default"]);
        assert_eq!(Config::default().allowed_other_profiles(), Vec::<String>::new());
        let back = serde_json::to_value(&config).unwrap();
        assert_eq!(back["otherProfiles"][0], "Profile 1", "kept as written for an older service");
    }

    #[test]
    fn endpoint_debug_hides_the_token() {
        let e = Endpoint {
            port: 1,
            token: "secret-token".into(),
            pid: 2,
            protocol: json!(1),
            source: String::new(),
        };
        assert!(!format!("{e:?}").contains("secret-token"));
    }

    #[test]
    fn the_service_environment_is_an_allow_list() {
        for name in ["PATH", "Path", "SystemRoot", "PHANTAB_RUNTIME", "TMPDIR"] {
            assert!(service_env_allowed(name), "{name}");
        }
        // Every variable `bw` is given from the service's environment reaches the service first.
        for name in crate::signin::bitwarden::cli::BW_ENV_ALLOWED {
            assert!(service_env_allowed(name), "{name} is passed to bw but never reaches the service");
        }
        // Nor does any variable that loads code into a process or changes which certificates it trusts.
        for name in [
            "RUST_LOG",
            "RUST_BACKTRACE",
            "FOO",
            "NODE_OPTIONS",
            "NODE_EXTRA_CA_CERTS",
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "NODE_USE_SYSTEM_CA",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "SSLKEYLOGFILE",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
        ] {
            assert!(!service_env_allowed(name), "{name}");
        }
        // A unit-test build is not a `test-seams` build unless the feature is on.
        assert_eq!(service_env_allowed("PHANTAB_TEST_X"), cfg!(feature = "test-seams"));
    }

    #[test]
    fn config_keeps_unknown_keys() {
        let c: Config = serde_json::from_str(r#"{"profileDirectory":"P","future":1}"#).unwrap();
        assert_eq!(c.profile_directory.as_deref(), Some("P"));
        assert_eq!(serde_json::to_string(&c).unwrap(), r#"{"profileDirectory":"P","future":1}"#);
    }
}
