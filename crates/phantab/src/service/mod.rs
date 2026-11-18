//! `phantab serve`: the one long-lived process per runtime. It holds the bridge link and
//! the engine, and answers clients on 127.0.0.1 with the endpoint token.
//!
//! Built on hyper directly rather than axum: the bridge join is an HTTP upgrade with a custom token
//! that Node's server routed to its own handler for any request carrying `Connection: upgrade`, and a
//! refused join is a bare 403 that closes the socket. Both are a few lines on hyper and would be fought
//! through axum's routing and extractors.

mod http;

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::bridge::Bridge;
use crate::engine_api::{
    self, EngineError, EngineMethod, EngineResult, EngineSetup, PageService, Serializer, Turn,
};
use crate::paths::{self, SERVICE_PROTOCOL};
use crate::util::{lock, random_hex, same_secret};

/// An MCP client silent this long has its pages released. A reloading or resuming client gets this
/// grace; `cli:` clients are stable task ids and keep their work until they close it.
pub const CLIENT_GRACE: Duration = Duration::from_secs(600);
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// How long a connection's next request headers may take to arrive (THREAT-MODEL R14), counted from
/// when the connection opened or answered its last request. It is hyper's default, set on both
/// listeners so neither depends on it and [`ConnTimer`]'s arithmetic matches it.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The same wait on a connection that has carried a valid token (an `/rpc` call): a client keeps that
/// connection for its next call and heartbeat (`runtime.rs`, perf-idle-1), and the 30 s heartbeat must
/// not race a 30 s close. Only a token holder gets it; every other connection keeps 30 s.
pub const KEPT_IDLE: Duration = Duration::from_secs(120);

/// hyper's timer for one connection. hyper's HTTP/1 server uses its timer for one thing, the
/// header-read timeout (checked against hyper 1.12; `a_kept_connection_waits_longer_only_once_authed`
/// holds it to that), so stretching the deadlines it asks for stretches exactly that wait, by `extra`,
/// once `authed` is set.
#[derive(Clone, Debug)]
struct ConnTimer {
    inner: TokioTimer,
    authed: Arc<AtomicBool>,
    extra: Duration,
}

impl ConnTimer {
    /// The service's: [`HEADER_READ_TIMEOUT`], or [`KEPT_IDLE`] once authed.
    fn new() -> Self {
        Self::with_extra(KEPT_IDLE.saturating_sub(HEADER_READ_TIMEOUT))
    }

    fn with_extra(extra: Duration) -> Self {
        Self { inner: TokioTimer::new(), authed: Arc::default(), extra }
    }

    fn deadline(&self, asked: Instant) -> Instant {
        if self.authed.load(Ordering::Relaxed) { asked + self.extra } else { asked }
    }
}

impl hyper::rt::Timer for ConnTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        self.inner.sleep_until(self.deadline(self.inner.now() + duration))
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        self.inner.sleep_until(self.deadline(deadline))
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn hyper::rt::Sleep>>, new_deadline: Instant) {
        self.inner.reset(sleep, self.deadline(new_deadline));
    }
}

/// Runs the service until it is stopped. The exit code is the process's.
pub async fn run() -> i32 {
    match serve().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

async fn serve() -> anyhow::Result<()> {
    let runtime = paths::runtime_dir();
    // SR-10: owner-only, checked at every start; a link or a foreign owner refuses to start.
    phantab_window::secure_dir::lock_down(&runtime)?;
    crate::runtime::lock_binary_folder()?; // SR-48: the installed binary's folder too.
    // SR-59: no core file holding the token (macOS).
    let _ = phantab_window::process::disable_core_dumps();
    let lock_path = paths::lock_path();
    let Some(service_lock) = ServiceLock::acquire(&lock_path)? else {
        // Another service holds this runtime; the client that started us will find it.
        eprintln!("phantab service already running");
        return Ok(());
    };
    let config = crate::runtime::read_config()?;
    let token = random_hex(32)?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    // A remote view that cannot start leaves the rest of Phantab running; status says why.
    let (remote, remote_listener) =
        match config.remote_viewer.as_ref().map(crate::runtime::RemoteViewer::checked) {
            None => (RemoteState::Off, None),
            Some(Err(e)) => (RemoteState::Failed(e), None),
            Some(Ok(r)) => match TcpListener::bind(r.addr).await {
                Ok(l) => (RemoteState::Listening(r), Some(l)),
                Err(e) => (RemoteState::Failed(format!("remoteViewer.listen {}: {e}", r.addr)), None),
            },
        };
    if let RemoteState::Failed(e) = &remote {
        tracing::warn!(error = %e, "remote viewer off");
    }
    let remote_base = match &remote {
        RemoteState::Listening(r) => Some(r.base.clone()),
        _ => None,
    };
    // Only the usual profile and otherProfiles may link (SR-76); the developer tools only with `devTools`
    // (SR-90).
    let bridge =
        Arc::new(Bridge::with_profiles(config.allowed_other_profiles()).with_dev_tools(config.dev_tools()));
    let serializer = Serializer::default();
    let engine = engine_api::build_engine(EngineSetup {
        config,
        runtime: runtime.clone(),
        extension_path: paths::extension_dir(),
        quiet_marker: paths::quiet_marker_path(),
        sign_in_guard: paths::sign_in_guard_path(),
        bridge: Arc::clone(&bridge),
        port,
        serializer: serializer.clone(),
        remote_base,
        start_profile: engine_api::StartProfile::default(),
    })?;
    let source = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
        .unwrap_or_default()
        .display()
        .to_string();
    let endpoint_path = paths::endpoint_path();
    let svc = Arc::new(Service {
        host: format!("127.0.0.1:{port}"),
        token,
        engine,
        bridge,
        serializer,
        clients: Mutex::default(),
        stopping: AtomicBool::new(false),
        source,
        lock: Mutex::new(Some(service_lock)),
        endpoint_path,
        remote,
    });
    svc.write_endpoint(port)?;
    tokio::spawn(sweep(Arc::clone(&svc)));
    tokio::spawn(on_signals(Arc::clone(&svc)));
    if let Some(l) = remote_listener {
        tokio::spawn(serve_remote(Arc::clone(&svc), l));
    }
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            // Out of handles, most likely; give the machine a moment rather than spin.
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        tokio::spawn(serve_conn(Arc::clone(&svc), stream));
    }
}

/// Serves one accepted connection until it closes.
async fn serve_conn<I>(svc: Arc<Service>, io: I)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let timer = ConnTimer::new();
    let authed = Arc::clone(&timer.authed);
    let handler = service_fn(move |req| {
        let (svc, authed) = (Arc::clone(&svc), Arc::clone(&authed));
        async move { Ok::<_, Infallible>(http::handle(svc, req, &authed).await) }
    });
    // The timer turns on hyper's header-read timeout: a client that never finishes its headers is
    // dropped (THREAT-MODEL R14). [`ConnTimer`] gives a connection that carried the token longer.
    let _ = http1::Builder::new()
        .timer(timer)
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(io), handler)
        .with_upgrades()
        .await;
}

/// The remote view's listener: the live view and nothing else (`http::handle_remote`). No upgrades, so
/// the bridge cannot join here.
async fn serve_remote(svc: Arc<Service>, listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let svc = Arc::clone(&svc);
        tokio::spawn(async move {
            let handler = service_fn(move |req| {
                let svc = Arc::clone(&svc);
                async move { Ok::<_, Infallible>(http::handle_remote(svc, req).await) }
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .title_case_headers(true)
                .serve_connection(TokioIo::new(stream), handler)
                .await;
        });
    }
}

/// Whether the remote view is on, as `status` reports it.
#[derive(Debug)]
enum RemoteState {
    Off,
    Failed(String),
    Listening(crate::runtime::RemoteListen),
}

/// One service per runtime, by an OS lock held for the service's life (THREAT-MODEL SR-12): a killed
/// service leaves no stale claim, and two starts racing get one winner without reading a PID.
#[derive(Debug)]
struct ServiceLock {
    _file: File,
}

impl ServiceLock {
    fn acquire(path: &Path) -> anyhow::Result<Option<Self>> {
        // A link at `path` is refused, not followed: the set_len below would truncate its target.
        let mut file = phantab_window::secure_dir::open_lock_file(path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        // For a person looking at the folder; nothing reads it.
        file.set_len(0)?;
        file.write_all(std::process::id().to_string().as_bytes())?;
        Ok(Some(Self { _file: file }))
    }
}

/// What the service method table names, beside the engine's own methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Status,
    Release,
    Disconnect,
    Heartbeat,
    Shutdown,
    /// `check_wait {watch}`: the wake command's wait for a verification hand-off to end.
    CheckWait,
    /// `restart_quiet`: the owner's Chrome restarts with the quiet-debugging flag (`phantab chrome
    /// restart-quiet`).
    RestartQuiet,
    Engine(EngineMethod),
}

impl Method {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "status" => Self::Status,
            "release" => Self::Release,
            "disconnect" => Self::Disconnect,
            "heartbeat" => Self::Heartbeat,
            "shutdown" => Self::Shutdown,
            "check_wait" => Self::CheckWait,
            "restart_quiet" => Self::RestartQuiet,
            other => Self::Engine(EngineMethod::from_name(other)?),
        })
    }

    /// Where `client`'s call waits in the queue; `None` runs at once. A wait takes no action on its page;
    /// in the queue it held every other agent's calls for up to 15 s. A sign-in queues only its fill and
    /// click, as asking a provider takes seconds. `disconnect` changes nothing, so it waits only for the
    /// client's own calls, not another agent's long navigate. A wake's `check_wait` only watches a
    /// check's state, for up to a minute. The engine's methods: [`EngineMethod::turn`].
    fn turn(self, args: &Value, client: &str) -> Option<Turn> {
        match self {
            Self::Status | Self::Heartbeat | Self::CheckWait => None,
            Self::Disconnect => Some(Turn::shared(client)),
            // A restart ends the browser every page runs in: nothing else may run meanwhile.
            Self::Release | Self::Shutdown | Self::RestartQuiet => Some(Turn::Exclusive),
            Self::Engine(m) => m.turn(args, client),
        }
    }
}

struct Service {
    host: String,
    token: String,
    engine: Arc<dyn PageService>,
    bridge: Arc<Bridge>,
    serializer: Serializer,
    clients: Mutex<HashMap<String, Instant>>,
    stopping: AtomicBool,
    source: String,
    lock: Mutex<Option<ServiceLock>>,
    endpoint_path: PathBuf,
    remote: RemoteState,
}

impl std::fmt::Debug for Service {
    // The token never reaches a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service").field("host", &self.host).finish_non_exhaustive()
    }
}

impl Service {
    /// `{port, token, pid, protocol, source}`, written owner-only through a temp file and a rename, so a
    /// client never reads half of it (THREAT-MODEL SR-11).
    fn write_endpoint(&self, port: u16) -> std::io::Result<()> {
        let body = serde_json::to_vec(&json!({
            "port": port,
            "token": self.token,
            "pid": std::process::id(),
            "protocol": SERVICE_PROTOCOL,
            "source": self.source,
        }))?;
        let tmp = self.endpoint_path.with_extension(format!("json.{}.tmp", std::process::id()));
        // SR-11: a fresh file (O_CREAT|O_EXCL, which also refuses a planted symlink), mode 0600 on unix,
        // the runtime dir's owner-only DACL on Windows.
        let _ = std::fs::remove_file(&tmp);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &self.endpoint_path)
    }

    fn status(&self) -> Value {
        let mut m = self.engine.status();
        m.insert("protocol".into(), json!(SERVICE_PROTOCOL));
        m.insert("source".into(), json!(self.source));
        m.insert("pid".into(), json!(std::process::id()));
        // Absent when it is not set up, so a status without it reads as before.
        match &self.remote {
            RemoteState::Off => {}
            RemoteState::Failed(e) => {
                m.insert("remoteViewer".into(), json!({ "listening": false, "error": e }));
            }
            RemoteState::Listening(r) => {
                m.insert(
                    "remoteViewer".into(),
                    json!({ "listening": true, "url": r.base, "identityChecked": r.identity.is_some() }),
                );
            }
        }
        Value::Object(m)
    }

    /// Runs a validated method for a client. Engine work is spawned, so a client that hangs up does not
    /// cancel it halfway: as in Node, a call once started finishes.
    /// The place in the queue is taken here, before the spawn, so calls keep the order they came in
    /// (a `ready_first` call's after its browser wait, `engine_api::spawn_call`).
    async fn dispatch(self: &Arc<Self>, method: Method, args: Value, client: String) -> EngineResult {
        let task = if let Method::Engine(m) = method {
            engine_api::spawn_call(Arc::clone(&self.engine), &self.serializer, m, args, client)
        } else {
            let turn = method.turn(&args, &client);
            let svc = Arc::clone(self);
            let work = async move {
                match method {
                    Method::Status => Ok(svc.status()),
                    Method::Heartbeat => Ok(json!({ "ok": true })),
                    Method::Disconnect => Ok(json!({ "retainedForResume": true })),
                    Method::Release => svc.engine.release(&client).await,
                    Method::Shutdown => svc.shutdown(),
                    Method::RestartQuiet => svc.engine.restart_quiet().await,
                    Method::CheckWait => {
                        let watch = args.get("watch").and_then(Value::as_str).unwrap_or("");
                        Ok(svc.engine.check_wait(watch).await)
                    }
                    // Taken by `spawn_call` above.
                    Method::Engine(m) => svc.engine.call(m, args, &client).await,
                }
            };
            match turn {
                Some(turn) => {
                    let ticket = self.serializer.enter(turn);
                    tokio::spawn(ticket.run(work))
                }
                None => tokio::spawn(work),
            }
        };
        task.await.unwrap_or_else(|e| Err(EngineError(format!("Browser service call failed: {e}"))))
    }

    fn shutdown(self: &Arc<Self>) -> EngineResult {
        if self.engine.active_pages() > 0 {
            return Err(
                "Active pages remain. Close agent work and finish owner handoffs before maintenance.".into(),
            );
        }
        self.stopping.store(true, Ordering::SeqCst);
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if svc.stop().await.is_err() {
                svc.stopping.store(false, Ordering::SeqCst);
            }
        });
        Ok(json!({ "stopping": true }))
    }

    /// Disposes the engine, closes the bridge, removes the endpoint if it is still this service's,
    /// unlocks and exits. Returns only if the engine refused (an owner takeover is active).
    async fn stop(&self) -> Result<Infallible, EngineError> {
        self.engine.dispose().await?;
        self.bridge.close();
        // Before the unlock, so no service started after this one can have written it yet; the check
        // leaves any file that is not this service's alone.
        remove_endpoint_if_ours(&self.endpoint_path, &self.token, std::process::id());
        // The lock file stays (SR-12), as after a kill. Removed after the unlock, it could be the file a
        // service starting this moment has just locked, and the next start would lock a new one beside it:
        // two services on one runtime.
        drop(lock(&self.lock).take());
        std::process::exit(0)
    }

    fn touch(&self, client: &str) {
        lock(&self.clients).insert(client.to_owned(), Instant::now());
    }
}

/// Removes the endpoint file at `path` only when it names this service: `token` (compared in constant
/// time) and `pid`. Whether it was removed.
fn remove_endpoint_if_ours(path: &Path, token: &str, pid: u32) -> bool {
    let Ok(bytes) = std::fs::read(path) else { return false };
    let Ok(found) = serde_json::from_slice::<Value>(&bytes) else { return false };
    let ours = found["pid"].as_u64() == Some(u64::from(pid))
        && found["token"].as_str().is_some_and(|t| same_secret(t.as_bytes(), token.as_bytes()));
    ours && std::fs::remove_file(path).is_ok()
}

/// Takes every client unseen for longer than the grace out of the table, and returns the ones to
/// release: all but `cli:` clients, which keep their pages until closed. A `cli:` entry leaves the
/// table too, so one-off CLI task ids do not pile up for the service's life (perf-idle-9); the
/// table only times the grace, so its next call just puts it back.
fn expire(clients: &mut HashMap<String, Instant>, now: Instant) -> Vec<String> {
    let mut gone = Vec::new();
    clients.retain(|client, seen| {
        if now.saturating_duration_since(*seen) <= CLIENT_GRACE {
            return true;
        }
        if !client.starts_with("cli:") {
            gone.push(client.clone());
        }
        false
    });
    gone
}

// Live MCP clients heartbeat. Stable CLI tasks retain work until explicitly closed.
// A disconnected MCP has a ten-minute grace period for a client reload/resume.
async fn sweep(svc: Arc<Service>) {
    let mut every = tokio::time::interval_at(tokio::time::Instant::now() + SWEEP_EVERY, SWEEP_EVERY);
    loop {
        every.tick().await;
        let gone = expire(&mut lock(&svc.clients), Instant::now());
        for client in gone {
            let (engine, serializer) = (Arc::clone(&svc.engine), svc.serializer.clone());
            tokio::spawn(async move {
                let _ = serializer.run(engine.release(&client)).await;
            });
        }
    }
}

async fn on_signals(svc: Arc<Service>) {
    loop {
        wait_for_stop_signal().await;
        // Returns only when the engine refused (an owner takeover is active); the service keeps running.
        let Err(e) = svc.stop().await;
        eprintln!("{e}");
    }
}

#[cfg(unix)]
async fn wait_for_stop_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_stop_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        // No console to listen on (a detached service): only `shutdown` stops it.
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_releases_only_silent_mcp_clients() {
        let now = Instant::now();
        let old = now.checked_sub(CLIENT_GRACE + Duration::from_secs(1)).unwrap();
        let recent = now.checked_sub(Duration::from_secs(5)).unwrap();
        let mut clients = HashMap::from([
            ("session:a".to_owned(), old),
            ("cli:task".to_owned(), old),
            ("session:b".to_owned(), recent),
        ]);
        assert_eq!(expire(&mut clients, now), vec!["session:a".to_owned()]);
        // perf-idle-9: the silent `cli:` id leaves the table without a release; a recent one stays.
        assert_eq!(clients.keys().collect::<Vec<_>>(), vec!["session:b"]);
        clients.insert("cli:fresh".to_owned(), recent);
        assert_eq!(expire(&mut clients, now), Vec::<String>::new());
        assert_eq!(clients.len(), 2);
    }

    /// SR-11, SR-12: a stop removes the endpoint only when it is this service's.
    #[test]
    fn a_stop_removes_only_its_own_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoint.json");
        let write = |token: &str, pid: u32| {
            std::fs::write(&path, json!({ "port": 1, "token": token, "pid": pid }).to_string()).unwrap();
        };
        for (token, pid) in [("theirs", 7), ("mine", 8)] {
            write(token, pid);
            assert!(!remove_endpoint_if_ours(&path, "mine", 7), "{token} {pid}");
            assert!(path.exists());
        }
        std::fs::write(&path, b"{").unwrap();
        assert!(!remove_endpoint_if_ours(&path, "mine", 7));
        write("mine", 7);
        assert!(remove_endpoint_if_ours(&path, "mine", 7));
        assert!(!path.exists());
        assert!(!remove_endpoint_if_ours(&path, "mine", 7), "nothing left to remove");
    }

    #[test]
    fn method_table_and_queue() {
        assert_eq!(Method::from_name("sign_in"), Some(Method::Engine(EngineMethod::SignIn)));
        assert_eq!(Method::from_name("toString"), None);
        let page = json!({ "pageId": "p1" });
        let turn = |m: &str| Method::from_name(m).unwrap().turn(&page, "mcp:a");
        let on = |page: &str| Some(Turn::Page { client: "mcp:a".into(), page: page.into() });
        assert_eq!(Method::from_name("check_wait"), Some(Method::CheckWait));
        assert_eq!(Method::from_name("sign_up"), Some(Method::Engine(EngineMethod::SignUp)));
        for m in ["status", "heartbeat", "wait", "sign_in", "sign_up", "check_wait"] {
            assert_eq!(turn(m), None, "{m}");
        }
        for m in ["snapshot", "screenshot", "act"] {
            assert_eq!(turn(m), on("p1"), "{m}");
        }
        for m in ["pages", "connect", "tabs", "disconnect"] {
            assert_eq!(turn(m), Some(Turn::Shared { client: "mcp:a".into() }), "{m}");
        }
        for m in ["open", "attach", "show", "resume", "close", "release", "shutdown", "restart_quiet"] {
            assert_eq!(turn(m), Some(Turn::Exclusive), "{m}");
        }
        // The engine's `String(args.pageId)`: an absent id is one page, "undefined", that no record has.
        assert_eq!(Method::from_name("act").unwrap().turn(&json!({}), "mcp:a"), on("undefined"));
        assert_eq!(Method::from_name("act").unwrap().turn(&json!({ "pageId": 7 }), "mcp:a"), on("7"));
        // A call with no client to tell its calls apart waits for every other call.
        for m in ["snapshot", "pages", "disconnect"] {
            assert_eq!(Method::from_name(m).unwrap().turn(&page, ""), Some(Turn::Exclusive), "{m}");
        }
    }

    /// The client resends these once after a lost connection (SR-35), so each must stay a
    /// method that only reads or says the client is still there.
    #[test]
    fn the_methods_a_client_resends_only_read() {
        for name in crate::runtime::RESENT_ONCE {
            assert!(
                matches!(
                    Method::from_name(name),
                    Some(
                        Method::Status
                            | Method::Heartbeat
                            | Method::Engine(EngineMethod::Pages | EngineMethod::Tabs)
                    )
                ),
                "{name}"
            );
        }
    }

    /// THREAT-MODEL R14 with kept connections: hyper's header-read timer is the only one [`ConnTimer`]
    /// stretches, an idle connection without the token still closes at the header timeout, and one that
    /// carried it waits `extra` longer. Scaled down from 30 s and 120 s.
    #[tokio::test]
    async fn a_kept_connection_waits_longer_only_once_authed() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        async fn idle_close_after(auth: bool) -> Duration {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let timer = ConnTimer::with_extra(Duration::from_millis(1200));
                let authed = Arc::clone(&timer.authed);
                let handler = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    if req.headers().contains_key("x-token") {
                        authed.store(true, Ordering::Relaxed);
                    }
                    async {
                        Ok::<_, Infallible>(
                            hyper::Response::new(http_body_util::Empty::<bytes::Bytes>::new()),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .timer(timer)
                    .header_read_timeout(Duration::from_millis(300))
                    .serve_connection(TokioIo::new(stream), handler)
                    .await;
            });
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let token = if auth { "X-Token: 1\r\n" } else { "" };
            client.write_all(format!("GET / HTTP/1.1\r\nHost: a\r\n{token}\r\n").as_bytes()).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = client.read(&mut buf).await.unwrap();
            assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&buf[..n]));
            let answered = Instant::now();
            let closed = async { while client.read(&mut buf).await.unwrap_or(0) > 0 {} };
            tokio::time::timeout(Duration::from_secs(10), closed).await.expect("the idle connection closes");
            answered.elapsed()
        }

        let plain = idle_close_after(false).await;
        assert!(plain >= Duration::from_millis(250) && plain < Duration::from_millis(1000), "{plain:?}");
        let kept = idle_close_after(true).await;
        assert!(kept >= Duration::from_millis(1400) && kept < Duration::from_millis(3000), "{kept:?}");
    }

    // The service's two waits, as [`ConnTimer::new`] and `serve_conn` set them.
    const _: () = assert!(KEPT_IDLE.as_secs() > HEADER_READ_TIMEOUT.as_secs());

    #[test]
    fn the_service_timer_adds_up_to_the_kept_wait() {
        assert_eq!(ConnTimer::new().extra + HEADER_READ_TIMEOUT, KEPT_IDLE);
    }

    /// An engine with no pages; the routes below never need one.
    #[derive(Debug)]
    struct Idle;

    #[async_trait::async_trait]
    impl PageService for Idle {
        async fn call(&self, _: EngineMethod, _: Value, _: &str) -> EngineResult {
            Ok(Value::Null)
        }
        async fn viewer(&self, _: &str, _: Option<&str>, _: Value, _: bool) -> EngineResult {
            Ok(Value::Null)
        }
        /// One local hand-off, viewed with the key `k`.
        fn viewer_known(&self, key: &str, remote: bool) -> bool {
            key == "k" && !remote
        }
        async fn release(&self, _: &str) -> EngineResult {
            Ok(Value::Null)
        }
        async fn dispose(&self) -> EngineResult<()> {
            Ok(())
        }
        fn status(&self) -> serde_json::Map<String, Value> {
            serde_json::Map::new()
        }
        fn active_pages(&self) -> usize {
            0
        }
    }

    const HOST: &str = "127.0.0.1:1";

    /// A service with no pages that answers on `HOST` and takes `token`.
    fn idle_service(token: &str) -> Arc<Service> {
        Arc::new(Service {
            host: HOST.to_owned(),
            token: token.to_owned(),
            engine: Arc::new(Idle),
            bridge: Arc::new(Bridge::new()),
            serializer: Serializer::default(),
            clients: Mutex::default(),
            stopping: AtomicBool::new(false),
            source: String::new(),
            lock: Mutex::new(None),
            endpoint_path: PathBuf::new(),
            remote: RemoteState::Off,
        })
    }

    /// A POST with `auth` (a whole header line, or nothing) and a JSON `body`.
    fn post(auth: &str, path: &str, body: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {HOST}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// The next answer on `client`: its head and its body.
    async fn read_answer(client: &mut tokio::io::DuplexStream) -> (String, String) {
        use tokio::io::AsyncReadExt as _;
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "closed before answering: {:?}", String::from_utf8_lossy(&seen));
            seen.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&seen).into_owned();
            let Some((head, body)) = text.split_once("\r\n\r\n") else { continue };
            let length = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(str::to_owned))
                .map_or(0, |v| v.trim().parse::<usize>().unwrap());
            if body.len() >= length {
                return (head.to_owned(), body.to_owned());
            }
        }
    }

    /// THREAT-MODEL R14 on the real server: `serve_conn` and `route` as the service runs them, in paused
    /// time so the full 30 s and 120 s are measured. Only a valid token on `/rpc` earns the longer wait:
    /// no token, a wrong one, the hello, `/health`, the viewer and an ended viewer all keep 30 s.
    #[tokio::test(start_paused = true)]
    async fn only_a_valid_token_earns_the_kept_wait() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        /// The answer's status line and body, and how long the idle connection then stayed open.
        async fn idle_close_after(token: &str, request: &str) -> (String, String, Duration) {
            let (mut client, server) = tokio::io::duplex(1 << 16);
            tokio::spawn(serve_conn(idle_service(token), server));
            client.write_all(request.as_bytes()).await.unwrap();
            let (head, body) = read_answer(&mut client).await;
            let answered = tokio::time::Instant::now();
            let mut buf = [0u8; 4096];
            let closed = async { while client.read(&mut buf).await.unwrap_or(0) > 0 {} };
            tokio::time::timeout(Duration::from_secs(600), closed).await.expect("the idle connection closes");
            let status = head.lines().next().unwrap_or_default().to_owned();
            (status, body, answered.elapsed())
        }

        let token = "ab".repeat(32);
        let heartbeat = r#"{"method":"heartbeat","args":{},"client":"t"}"#;
        let nonce = "0f".repeat(crate::hello::NONCE_LEN);
        let cases = [
            ("no token", post("", "/rpc", heartbeat), "403"),
            (
                "a wrong token",
                post(&format!("Authorization: Bearer {}\r\n", "cd".repeat(32)), "/rpc", heartbeat),
                "403",
            ),
            ("the hello", format!("GET /hello?nonce={nonce} HTTP/1.1\r\nHost: {HOST}\r\n\r\n"), "200"),
            ("/health", format!("GET /health HTTP/1.1\r\nHost: {HOST}\r\n\r\n"), "200"),
            ("the viewer", post("Authorization: Bearer k\r\n", "/viewer", r#"{"action":"x"}"#), "200"),
            (
                "an ended viewer",
                post("Authorization: Bearer gone\r\n", "/viewer", r#"{"action":"x"}"#),
                "400",
            ),
        ];
        let header_wait = HEADER_READ_TIMEOUT.as_secs_f64();
        for (what, request, status) in cases {
            let (line, body, idle) = idle_close_after(&token, &request).await;
            assert!(line.contains(status), "{what}: {line} {body}");
            assert!((idle.as_secs_f64() - header_wait).abs() < 1.0, "{what} waited {idle:?}");
            if what == "the hello" {
                let answer: Value = serde_json::from_str(&body).unwrap();
                assert_eq!(answer[crate::hello::KEEP], json!(KEPT_IDLE.as_secs()), "{body}");
            }
        }
        let valid = post(&format!("Authorization: Bearer {token}\r\n"), "/rpc", heartbeat);
        let (line, body, idle) = idle_close_after(&token, &valid).await;
        assert!(line.contains("200") && body.contains(r#""ok":true"#), "{line} {body}");
        assert!((idle.as_secs_f64() - KEPT_IDLE.as_secs_f64()).abs() < 1.0, "a token holder waited {idle:?}");
    }

    /// THREAT-MODEL R14 on one kept connection: the token earns a longer wait between requests and
    /// nothing else. After a valid `/rpc`, a request with no token or a wrong one is still refused, and a
    /// body that stalls is cut at the body limit (`http::BODY_TIMEOUT`), not at the kept wait.
    #[tokio::test(start_paused = true)]
    async fn a_kept_connection_still_checks_every_request() {
        use tokio::io::AsyncWriteExt as _;

        let token = "ab".repeat(32);
        let heartbeat = r#"{"method":"heartbeat","args":{},"client":"t"}"#;
        let valid = format!("Authorization: Bearer {token}\r\n");
        let wrong = format!("Authorization: Bearer {}\r\n", "cd".repeat(32));
        let (mut client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(serve_conn(idle_service(&token), server));

        let steps = [
            ("a valid token", post(&valid, "/rpc", heartbeat), "200"),
            ("no token", post("", "/rpc", heartbeat), "403"),
            ("a wrong token", post(&wrong, "/rpc", heartbeat), "403"),
            ("a valid token again", post(&valid, "/rpc", heartbeat), "200"),
        ];
        for (what, request, status) in steps {
            client.write_all(request.as_bytes()).await.unwrap();
            let (head, body) = read_answer(&mut client).await;
            assert!(head.lines().next().unwrap_or_default().contains(status), "{what}: {head} {body}");
            if status == "200" {
                assert!(body.contains(r#""ok":true"#), "{what}: {body}");
            } else {
                assert!(!body.contains(r#""ok":true"#), "{what} reached the engine: {body}");
            }
        }

        // A valid request whose body never finishes, on the connection that now waits 120 s.
        let stalled = format!(
            "POST /rpc HTTP/1.1\r\nHost: {HOST}\r\n{valid}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            heartbeat.len(),
            &heartbeat[..10]
        );
        client.write_all(stalled.as_bytes()).await.unwrap();
        let sent = tokio::time::Instant::now();
        let (head, body) = read_answer(&mut client).await;
        assert!(head.lines().next().unwrap_or_default().contains("400"), "{head} {body}");
        assert!(body.contains("Request body timed out"), "{body}");
        let waited = sent.elapsed().as_secs_f64();
        assert!(
            (waited - http::BODY_TIMEOUT.as_secs_f64()).abs() < 1.0,
            "a stalled body was held {waited} s"
        );
    }
}
