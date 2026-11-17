//! The seam between the service shell and the page engine.
//!
//! The service (`service/`) owns HTTP, the token, the client table and the queue. Everything about
//! pages belongs to a [`PageService`]. [`build_engine`] is the one place that chooses the
//! implementation: today [`StubEngine`], later the real engine, with nothing else changing.
//!
//! # What an engine must do
//! - **Build** from an [`EngineSetup`]: the config, the runtime paths, the shared [`Bridge`], the bound
//!   port (for `/view` URLs) and the service's [`Serializer`]. Subscribe to `bridge.subscribe()` before
//!   `build_engine` returns, or the first `Connect` can be missed.
//! - **Track the bridge** from its events: verify the profile on `Connect` and keep
//!   `lastError`; on `Refused` set `lastError`; on `Disconnect` set `lastDisconnect` and end every shared
//!   page; on `TabEnded` end or detach the matching records. The CDP relay is `bridge.op_raw("send", ..)`
//!   plus the `Cdp` events.
//! - **Answer [`PageService::call`]** for every [`EngineMethod`], with the args exactly as the client sent
//!   them (`{}` when absent) and the client id as given. Ownership checks are the engine's.
//! - **Queueing.** The service runs `wait` and `sign_in` outside the queue and every other method inside
//!   it, where it waits per [`EngineMethod::turn`]: a page call only for
//!   exclusive calls and the earlier calls on its page or from its client, everything that changes
//!   windows or records alone.
//!   Inside the queue, never call [`Serializer::run`]: it waits for itself, as the promise chain did.
//!   `sign_in` queues only its fill and click through `serializer`, alone. [`PageService::ready`] runs
//!   before a [`EngineMethod::ready_first`] method takes its place, so waiting for the browser holds
//!   no one else.
//! - **`status()`** is synchronous, never waits, and returns these keys in this order:
//!   `connected, profile, profileVerified, agentPages, lastError, lastDisconnect, connectionPolicy` and
//!   `quietDebugging` when on. The service appends `protocol, source, pid`.
//! - **`active_pages()`** is `records.size`; `shutdown` refuses while it is above 0.
//! - **`release(client)`** closes or orphans that client's pages and answers `{released:true}`. The service
//!   calls it, queued alone, for an MCP client silent for ten minutes, and for the `release` method.
//! - **`viewer(token, action, args)`** checks the viewer token itself (constant time, THREAT-MODEL SR-8)
//!   and answers `This handoff has ended.` for an unknown one. Queued, alone.
//! - **`check_wait(watch)`** waits, outside the queue, for the verification hand-off holding that wake
//!   token to end (at most a minute) and answers its state and page id; `gone` for an unknown token.
//!   The token is compared in constant time and opens nothing else (SR-72).
//! - **`dispose()`** refuses while an owner takeover is active, else closes what the agents opened. The
//!   service closes the bridge and removes its files after it.
//! - A call's future may outlive the HTTP request that asked for it (the service spawns each call), so
//!   nothing needs to be cancel-safe; work started is finished, as in Node.
//! - Error text reaches agents verbatim: never put the endpoint token, a credential or a runtime path in it.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Map, Value, json};
use tokio::sync::broadcast::error::RecvError;

use crate::bridge::{self, Bridge, BridgeError, BridgeEvent, ProfileCheck};
use crate::runtime::Config;
use crate::util::{iso_now, lock, node_fs_error};

/// The methods the engine answers. `status`, `release`, `disconnect`, `heartbeat` and `shutdown` are the
/// service's own (it asks the engine for status and release through their own trait methods).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineMethod {
    Pages,
    Connect,
    Open,
    Tabs,
    Attach,
    Snapshot,
    Act,
    Show,
    Resume,
    Close,
    Screenshot,
    Wait,
    SignIn,
    SignUp,
    /// Developer tools (THREAT-MODEL SR-90), refused unless `devTools` is on.
    Evaluate,
    Console,
    Network,
}

impl EngineMethod {
    pub const ALL: [Self; 17] = [
        Self::Pages,
        Self::Connect,
        Self::Open,
        Self::Tabs,
        Self::Attach,
        Self::Snapshot,
        Self::Act,
        Self::Show,
        Self::Resume,
        Self::Close,
        Self::Screenshot,
        Self::Wait,
        Self::SignIn,
        Self::SignUp,
        Self::Evaluate,
        Self::Console,
        Self::Network,
    ];

    /// The method's name on the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pages => "pages",
            Self::Connect => "connect",
            Self::Open => "open",
            Self::Tabs => "tabs",
            Self::Attach => "attach",
            Self::Snapshot => "snapshot",
            Self::Act => "act",
            Self::Show => "show",
            Self::Resume => "resume",
            Self::Close => "close",
            Self::Screenshot => "screenshot",
            Self::Wait => "wait",
            Self::SignIn => "sign_in",
            Self::SignUp => "sign_up",
            Self::Evaluate => "evaluate",
            Self::Console => "console",
            Self::Network => "network",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == name)
    }

    /// Where `client`'s call waits in the service's queue; `None` runs at once.
    /// When in doubt a method is exclusive. A client's own calls never overlap, whatever their pages.
    ///
    /// - `wait` and `sign_in` run at once; `sign_in` queues its fill and click,
    ///   exclusive, through [`Serializer::run`]. `sign_up` runs as `sign_in` does: its fill is queued.
    /// - `snapshot`, `screenshot` and `act` touch one page: its CDP session, its keyboard and mouse
    ///   state, its emulation, its site lease (an atomic check-and-take under the engine's state lock).
    ///   They wait for an exclusive call, that page's earlier calls and the client's earlier calls.
    ///   `evaluate`, `console` and `network` touch one page the same way: a script, its recording.
    /// - `pages`, `connect` and `tabs` read records, the bridge and the profile check's status fields.
    /// - `open` arms the OS hook that hides the first Chrome window to appear at the workspace's
    ///   position, which a click on another page could open; `attach` checks a tab is unassigned, then
    ///   records it; `show` and `resume` change the owner's windows and foreground; `close` ends a
    ///   page. All exclusive.
    #[must_use]
    pub fn turn(self, args: &Value, client: &str) -> Option<Turn> {
        match self {
            Self::Wait | Self::SignIn | Self::SignUp => None,
            Self::Snapshot
            | Self::Screenshot
            | Self::Act
            | Self::Evaluate
            | Self::Console
            | Self::Network => Some(Turn::page(client, page_id(args))),
            Self::Pages | Self::Connect | Self::Tabs => Some(Turn::shared(client)),
            Self::Open | Self::Attach | Self::Show | Self::Resume | Self::Close => Some(Turn::Exclusive),
        }
    }

    /// Whether [`PageService::ready`] runs before the call takes its place: a call that first waits for
    /// the browser to connect (up to 10 s, then up to 15 s for the profile) then waits outside the line.
    #[must_use]
    pub const fn ready_first(self) -> bool {
        matches!(self, Self::Connect | Self::Open | Self::Tabs | Self::Attach)
    }
}

/// The `pageId` a page call names, as the engine reads it (`String(args.pageId)`).
#[must_use]
pub fn page_id(args: &Value) -> String {
    crate::util::js_string(args.get("pageId").filter(|v| !v.is_null()))
}

/// Runs one engine method as the service does: spawned, so a client that hangs up does not cancel it
/// halfway, and in the queue per [`EngineMethod::turn`]. The place in line is taken before this returns
/// (after [`PageService::ready`] for a [`EngineMethod::ready_first`] method).
pub fn spawn_call(
    engine: Arc<dyn PageService>,
    serializer: &Serializer,
    method: EngineMethod,
    args: Value,
    client: String,
) -> tokio::task::JoinHandle<EngineResult> {
    let Some(turn) = method.turn(&args, &client) else {
        return tokio::spawn(async move { engine.call(method, args, &client).await });
    };
    if method.ready_first() {
        let serializer = serializer.clone();
        return tokio::spawn(async move {
            engine.ready(method, &args).await?;
            serializer.enter(turn).run(engine.call(method, args, &client)).await
        });
    }
    let ticket = serializer.enter(turn);
    tokio::spawn(async move { ticket.run(engine.call(method, args, &client)).await })
}

/// An engine failure. Its text is what the agent reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError(pub String);

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EngineError {}

impl From<BridgeError> for EngineError {
    fn from(e: BridgeError) -> Self {
        Self(e.to_string())
    }
}

impl From<String> for EngineError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for EngineError {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<anyhow::Error> for EngineError {
    fn from(e: anyhow::Error) -> Self {
        Self(e.to_string())
    }
}

pub type EngineResult<T = Value> = Result<T, EngineError>;

/// What a queued call has to wait for. [`EngineMethod::turn`] gives each method's.
/// Every turn but [`Turn::Exclusive`] names its client, and one client's calls always conflict: one
/// agent's own calls run one at a time in the order it sent them, as before, even on two pages (an
/// MCP server answers each request in its own task, so an agent can have several in flight). Only
/// different clients' calls run side by side. A [`EngineMethod::ready_first`] call takes its place after
/// its browser wait, so a later call, even of the same client, can run before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Turn {
    /// Alone: it waits for every call before it, and every call after it waits for it. Windows, the
    /// owner's view, records coming and going, the sign-in fill, and any call with no client.
    Exclusive,
    /// A client's call that reads only what page calls never change: it waits for an exclusive call
    /// and the client's earlier calls.
    Shared { client: String },
    /// A client's call on one page, by `pageId`: it waits for an exclusive call, this page's earlier
    /// calls and the client's earlier calls, never for another client's other page.
    Page { client: String, page: String },
}

impl Turn {
    /// A client's page call; with no client to tell its calls apart, exclusive.
    #[must_use]
    pub fn page(client: &str, page: String) -> Self {
        if client.is_empty() { Self::Exclusive } else { Self::Page { client: client.to_owned(), page } }
    }

    /// A client's shared call; with no client to tell its calls apart, exclusive.
    #[must_use]
    pub fn shared(client: &str) -> Self {
        if client.is_empty() { Self::Exclusive } else { Self::Shared { client: client.to_owned() } }
    }

    fn client(&self) -> Option<&str> {
        match self {
            Self::Exclusive => None,
            Self::Shared { client } | Self::Page { client, .. } => Some(client),
        }
    }

    fn conflicts(&self, other: &Self) -> bool {
        let (Some(a), Some(b)) = (self.client(), other.client()) else { return true };
        let same_page =
            matches!((self, other), (Self::Page { page: p, .. }, Self::Page { page: q, .. }) if p == q);
        a == b || same_page
    }
}

/// The service's queue: a call starts once every call
/// before it that it conflicts with ([`Turn`]) has settled, success or failure. So an exclusive call
/// runs alone, in arrival order, one client's calls run one
/// at a time in its order, and two clients' calls on their own pages run side by side.
///
/// - **Order.** A call takes its place in line when [`Serializer::enter`] is called, not when its task
///   first runs: the service enters at dispatch, so a page's or a client's calls keep the order they
///   came in (a [`EngineMethod::ready_first`] call enters after its browser wait). A global `RwLock`
///   plus a mutex per page does not: readers woken together when a writer leaves can
///   be polled in either order on the multi-thread runtime and reach the page mutex swapped.
/// - **No starvation.** A waiting exclusive call holds back every call that came after it, so a stream
///   of page calls cannot keep it waiting.
/// - **No deadlock.** This is the only lock a call takes for its turn, taken once, with nothing held
///   while it waits; the line's own mutex is a std mutex never held across an await. Lock order is
///   this queue, then the engine's `State`, then a `Rec` (both std mutexes, never held across an
///   await). The one way to deadlock is a call that enters again from inside its own turn: never call
///   [`Serializer::run`] inside a queued call, since it waits for that call, as the promise chain did.
///   The verification watcher and the sign-in fill run from their own tasks.
#[derive(Debug, Clone, Default)]
pub struct Serializer(Arc<Mutex<Line>>);

#[derive(Debug, Default)]
struct Line {
    next: u64,
    /// Every call not yet settled, in arrival order. `go` is taken when the call starts.
    places: Vec<Place>,
}

#[derive(Debug)]
struct Place {
    id: u64,
    turn: Turn,
    go: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Line {
    /// Starts every waiting call that no earlier unsettled call conflicts with.
    fn admit(&mut self) {
        for i in 0..self.places.len() {
            let (before, rest) = self.places.split_at_mut(i);
            let place = &mut rest[0];
            if place.go.is_none() || before.iter().any(|p| p.turn.conflicts(&place.turn)) {
                continue;
            }
            if let Some(go) = place.go.take() {
                let _ = go.send(());
            }
        }
    }
}

/// A call's place in the [`Serializer`]'s line, from [`Serializer::enter`]. Dropping it, run or not,
/// gives the place up.
#[derive(Debug)]
pub struct Ticket {
    line: Arc<Mutex<Line>>,
    id: u64,
    ready: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl Ticket {
    /// Waits for the turn, runs `f`, then lets the calls behind it go.
    pub async fn run<F: Future>(mut self, f: F) -> F::Output {
        if let Some(ready) = self.ready.take() {
            // The sender goes only with this ticket's place, which only this ticket removes.
            let _ = ready.await;
        }
        f.await
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut line = lock(&self.line);
        line.places.retain(|p| p.id != self.id);
        line.admit();
    }
}

impl Serializer {
    /// Takes a place in line now. The call starts when [`Ticket::run`] finds its turn.
    #[must_use]
    pub fn enter(&self, turn: Turn) -> Ticket {
        let (go, ready) = tokio::sync::oneshot::channel();
        let mut line = lock(&self.0);
        line.next += 1;
        let id = line.next;
        line.places.push(Place { id, turn, go: Some(go) });
        line.admit();
        Ticket { line: Arc::clone(&self.0), id, ready: Some(ready) }
    }

    /// Runs `f` alone ([`Turn::Exclusive`]), in line from its first poll.
    pub async fn run<F: Future>(&self, f: F) -> F::Output {
        self.enter(Turn::Exclusive).run(f).await
    }

    /// How many calls hold or wait for a place, so a test can wait for one to take its place.
    #[cfg(test)]
    pub(crate) fn places(&self) -> usize {
        lock(&self.0).places.len()
    }
}

/// Everything an engine is built from.
#[derive(Debug, Clone)]
pub struct EngineSetup {
    pub config: Config,
    pub runtime: PathBuf,
    /// The unpacked extension folder named in the not-connected error.
    pub extension_path: PathBuf,
    /// Present while quiet debugging is on.
    pub quiet_marker: PathBuf,
    pub sign_in_guard: PathBuf,
    pub bridge: Arc<Bridge>,
    /// The service's port on 127.0.0.1, for `/view` URLs.
    pub port: u16,
    /// `remoteViewer.publicBaseUrl` without its trailing `/`, when the remote listener runs: the start of
    /// every verification link.
    pub remote_base: Option<String>,
    pub serializer: Serializer,
    /// Starts a closed allowed Chrome profile without a window (SR-76).
    pub start_profile: StartProfile,
}

/// How the engine starts Chrome: `(chromeExecutable, args)`. The service's is
/// [`crate::engine::start_chrome`]; a test's records the call instead.
#[derive(Clone)]
pub struct StartProfile(pub Arc<StartFn>);

/// [`StartProfile`]'s function.
pub type StartFn = dyn Fn(&std::path::Path, &[std::ffi::OsString]) -> std::io::Result<()> + Send + Sync;

impl Default for StartProfile {
    fn default() -> Self {
        Self(Arc::new(crate::engine::start_chrome))
    }
}

impl std::fmt::Debug for StartProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StartProfile")
    }
}

/// The page engine as the service sees it. See the module docs for its obligations.
#[async_trait]
pub trait PageService: Send + Sync + std::fmt::Debug {
    async fn call(&self, method: EngineMethod, args: Value, client: &str) -> EngineResult;
    /// Before a [`EngineMethod::ready_first`] method takes its place in the queue: waits that change
    /// nothing a queued call reads (the browser connecting). An error is the call's answer, and the call
    /// then never runs, so it must be the error [`Self::call`] would have given first.
    async fn ready(&self, _method: EngineMethod, _args: &Value) -> EngineResult<()> {
        Ok(())
    }
    /// A live-view call. `remote` says which listener it came in on; each takes only its own tokens.
    async fn viewer(&self, token: &str, action: Option<&str>, args: Value, remote: bool) -> EngineResult;
    /// Whether `token` is a live hand-off's viewer key on the listener `remote` names, compared in
    /// constant time (SR-8). The service asks before it reads a `/viewer` body, so an unknown caller gets
    /// no body read; [`Self::viewer`] still decides the call.
    fn viewer_known(&self, token: &str, remote: bool) -> bool;
    /// `check_wait {watch}`: until the verification hand-off with this wake token ends, or a minute.
    /// Answers `{state, pageId}`, or `{state: "gone"}` for a token it does not know. Clientless and
    /// unqueued; the token reads the check's state and nothing else (SR-72).
    async fn check_wait(&self, _watch: &str) -> Value {
        serde_json::json!({ "state": "gone" })
    }
    /// `restart_quiet`: the owner's Chrome restarts with the quiet-debugging flag, saving and restoring its
    /// session (`phantab chrome restart-quiet`). Exclusive in the queue. An engine without windows refuses.
    async fn restart_quiet(&self) -> EngineResult {
        Err(EngineError("This service cannot restart Chrome.".to_owned()))
    }
    async fn release(&self, client: &str) -> EngineResult;
    async fn dispose(&self) -> EngineResult<()>;
    fn status(&self) -> Map<String, Value>;
    fn active_pages(&self) -> usize;
}

/// The engine the service runs: [`crate::engine::Engine`]. [`StubEngine`] stays for the service's own
/// tests.
///
/// # Errors
/// The engine could not start.
pub fn build_engine(setup: EngineSetup) -> anyhow::Result<Arc<dyn PageService>> {
    Ok(crate::engine::from_setup(setup))
}

// ---- Stub ----------------------------------------------------------------------------------------

/// The not-connected error's start; the extension path and the rest follow.
pub const NOT_CONNECTED: &str = "The phantab bridge extension has not connected. In the usual Chrome profile open chrome://extensions, turn on Developer mode and Load unpacked ";
pub const CONNECTION_POLICY: &str = "phantab bridge extension; reconnects automatically; never prompts";
pub const NOT_BUILT: &str = "engine not built";

#[derive(Debug, Default)]
struct Track {
    verified: bool,
    last_error: Option<String>,
    last_disconnect: Option<Value>,
}

/// Holds the service up without pages: the engine's connection half (status, connect, tabs,
/// profile check, the bridge's events) and "engine not built" for everything that needs a page.
#[derive(Debug)]
pub struct StubEngine {
    setup: EngineSetup,
    track: Arc<Mutex<Track>>,
}

impl StubEngine {
    #[must_use]
    pub fn new(setup: EngineSetup) -> Arc<Self> {
        let engine = Arc::new(Self { setup, track: Arc::default() });
        let mut events = engine.setup.bridge.subscribe();
        let weak = Arc::downgrade(&engine);
        tokio::spawn(async move {
            loop {
                let event = match events.recv().await {
                    Ok(e) => e,
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                };
                let Some(engine) = weak.upgrade() else { break };
                engine.on_event(&event);
            }
        });
        engine
    }

    /// The stub knows only the usual profile; another profile's events pass it by.
    fn on_event(&self, event: &BridgeEvent) {
        match event {
            BridgeEvent::Connect { profile, .. } if **profile == *bridge::USUAL => {
                self.verify();
            }
            BridgeEvent::Refused { reason, .. } => lock(&self.track).last_error = Some(reason.clone()),
            BridgeEvent::Disconnect { profile, reason } if **profile == *bridge::USUAL => {
                let mut t = lock(&self.track);
                t.verified = false;
                t.last_disconnect = Some(json!({ "at": iso_now(), "reason": reason }));
            }
            BridgeEvent::TabEnded { profile, tab_id, reason, .. }
                if **profile == *bridge::USUAL && reason.as_deref() == Some("canceled_by_user") =>
            {
                lock(&self.track).last_disconnect = Some(json!({
                    "at": iso_now(),
                    "reason": format!("The owner canceled debugging from Chrome's bar or the bridge's badge (tab {tab_id}); its agent page was released and is not re-attached without asking."),
                }));
            }
            BridgeEvent::Connect { .. }
            | BridgeEvent::Disconnect { .. }
            | BridgeEvent::TabEnded { .. }
            | BridgeEvent::Cdp(_) => {}
        }
    }

    /// The profile and extension-file check (SR-19, SR-74), as a call that owns its inputs, so it can run
    /// off the runtime's workers.
    fn profile_check(&self) -> impl FnOnce() -> ProfileCheck + Send + 'static {
        let dir = self.setup.config.user_data_dir.clone();
        let profile = self.setup.config.profile_directory.clone().unwrap_or_default();
        let recorded = self.setup.config.extension_files_recorded == Some(true);
        move || match &dir {
            Some(dir) => bridge::profile_check(dir, &profile, &bridge::EXTENSION_ID, recorded)
                .unwrap_or_else(|e| ProfileCheck::Failed {
                    final_: true,
                    error: format!("Chrome profile check failed: {}", node_fs_error(&e, "scandir", dir)),
                }),
            None => ProfileCheck::Failed {
                final_: true,
                error: "Chrome profile check failed: config.json names no userDataDir".to_owned(),
            },
        }
    }

    fn verify(&self) -> ProfileCheck {
        let check = self.profile_check()();
        self.record_check(check)
    }

    /// `require_browser`'s check, on tokio's blocking pool. It reads every file of the installed extension
    /// (up to 64 MiB), and a virus scanner can hold each one open; on one of `serve`'s two workers
    /// (`mode::SERVICE_WORKERS`) that would stall the bridge and every other client's call.
    async fn verify_off_workers(&self) -> ProfileCheck {
        let check = tokio::task::spawn_blocking(self.profile_check()).await.unwrap_or_else(|e| {
            ProfileCheck::Failed { final_: true, error: format!("Chrome profile check failed: {e}") }
        });
        self.record_check(check)
    }

    fn record_check(&self, check: ProfileCheck) -> ProfileCheck {
        let mut t = lock(&self.track);
        t.verified = check == ProfileCheck::Ok;
        t.last_error = match &check {
            ProfileCheck::Ok => None,
            ProfileCheck::Failed { error, .. } => Some(error.clone()),
        };
        check
    }

    /// The bridge connects by itself; a cold service gives Chrome a moment to relaunch the host.
    async fn require_browser(&self) -> EngineResult<()> {
        let result = async {
            if !self.setup.bridge.wait_connected(Duration::from_secs(10)).await {
                return Err(EngineError(format!(
                    "{NOT_CONNECTED}{} (once). Headless tools do not inherit this login.",
                    self.setup.extension_path.display()
                )));
            }
            let mut check = self.verify_off_workers().await;
            // Chrome records a just-loaded extension in Preferences on a timer.
            let end = tokio::time::Instant::now() + Duration::from_secs(15);
            while let ProfileCheck::Failed { final_: false, .. } = check {
                if tokio::time::Instant::now() >= end {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                check = self.verify_off_workers().await;
            }
            match check {
                ProfileCheck::Ok => Ok(()),
                ProfileCheck::Failed { error, .. } => Err(EngineError(error)),
            }
        }
        .await;
        if let Err(e) = &result {
            lock(&self.track).last_error = Some(e.0.clone());
        }
        result
    }

    async fn tabs(&self) -> EngineResult {
        self.require_browser().await?;
        let tabs = self.setup.bridge.op("tabs", json!({})).await?;
        let list = tabs.as_array().map(Vec::as_slice).unwrap_or_default();
        let out: Vec<Value> = list
            .iter()
            .filter(|t| {
                let url = t.get("url").and_then(Value::as_str).unwrap_or("");
                (url.starts_with("http:") || url.starts_with("https:")) && !self.is_viewer(url)
            })
            .map(|t| {
                json!({
                    "tabId": crate::util::js_string(t.get("tabId")),
                    "title": t.get("title"),
                    "url": t.get("url"),
                })
            })
            .collect();
        Ok(Value::Array(out))
    }

    fn is_viewer(&self, url: &str) -> bool {
        url.starts_with(&format!("http://127.0.0.1:{}/view", self.setup.port))
    }
}

#[async_trait]
impl PageService for StubEngine {
    async fn call(&self, method: EngineMethod, _args: Value, _client: &str) -> EngineResult {
        match method {
            EngineMethod::Pages => Ok(json!([])),
            EngineMethod::Connect => {
                self.require_browser().await?;
                Ok(Value::Object(self.status()))
            }
            EngineMethod::Tabs => self.tabs().await,
            _ => Err(NOT_BUILT.into()),
        }
    }

    async fn viewer(&self, _token: &str, _action: Option<&str>, _args: Value, _remote: bool) -> EngineResult {
        Err("This handoff has ended.".into())
    }

    fn viewer_known(&self, _token: &str, _remote: bool) -> bool {
        false
    }

    async fn release(&self, _client: &str) -> EngineResult {
        Ok(json!({ "released": true }))
    }

    async fn dispose(&self) -> EngineResult<()> {
        Ok(())
    }

    fn status(&self) -> Map<String, Value> {
        let t = lock(&self.track);
        let mut m = Map::new();
        m.insert("connected".into(), Value::Bool(self.setup.bridge.connected()));
        // Absent in the config means absent here, as JSON.stringify drops undefined.
        if let Some(p) = &self.setup.config.profile_directory {
            m.insert("profile".into(), Value::String(p.clone()));
        }
        m.insert("profileVerified".into(), Value::Bool(t.verified));
        m.insert("agentPages".into(), json!(0));
        m.insert("lastError".into(), t.last_error.clone().map_or(Value::Null, Value::String));
        m.insert("lastDisconnect".into(), t.last_disconnect.clone().unwrap_or(Value::Null));
        m.insert("connectionPolicy".into(), Value::String(CONNECTION_POLICY.to_owned()));
        m
    }

    fn active_pages(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names_round_trip() {
        for m in EngineMethod::ALL {
            assert_eq!(EngineMethod::from_name(m.name()), Some(m));
        }
        assert_eq!(EngineMethod::from_name("status"), None);
    }

    #[tokio::test]
    async fn serializer_runs_one_at_a_time_in_order() {
        let s = Serializer::default();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for i in 0..5u64 {
            let (s, log) = (s.clone(), Arc::clone(&log));
            tasks.push(tokio::spawn(async move {
                s.run(async {
                    lock(&log).push(format!("start {i}"));
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    lock(&log).push(format!("end {i}"));
                })
                .await;
            }));
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        for t in tasks {
            t.await.unwrap();
        }
        let log = lock(&log).clone();
        let expected: Vec<String> = (0..5).flat_map(|i| [format!("start {i}"), format!("end {i}")]).collect();
        assert_eq!(log, expected);
    }

    type Log = Arc<Mutex<Vec<String>>>;

    /// A call that takes its place now and, in its turn, logs `start name`, holds until `until` is done,
    /// then logs `end name`.
    fn job(
        s: &Serializer,
        turn: Turn,
        log: &Log,
        name: &str,
        until: impl Future<Output = ()> + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let (log, name) = (Arc::clone(log), name.to_owned());
        let ticket = s.enter(turn);
        tokio::spawn(ticket.run(async move {
            lock(&log).push(format!("start {name}"));
            until.await;
            lock(&log).push(format!("end {name}"));
        }))
    }

    /// A page call from a client of its own, so two pages here are two agents'.
    fn page(id: &str) -> Turn {
        on(&format!("agent {id}"), id)
    }

    fn on(client: &str, page: &str) -> Turn {
        Turn::page(client, page.to_owned())
    }

    fn gate() -> (tokio::sync::oneshot::Sender<()>, impl Future<Output = ()> + Send + 'static) {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        (tx, async move {
            let _ = rx.await;
        })
    }

    fn logged(log: &Log) -> Vec<String> {
        lock(log).clone()
    }

    /// Waits until `log` has `n` entries, so a check never depends on how soon a task was polled.
    async fn until_logged(log: &Log, n: usize) -> Vec<String> {
        let wait = async {
            while lock(log).len() < n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait).await.unwrap_or_else(|_| {
            panic!("{n} entries never came: {:?}", logged(log));
        });
        logged(log)
    }

    /// Gives a call that should wait a moment to start wrongly. Only for checking that something has
    /// not happened, which a slow machine cannot make fail.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // Each later call is shorter, so on a multi-thread runtime any overlap or reordering shows.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_pages_calls_run_one_at_a_time_in_arrival_order_beside_another_page() {
        let s = Serializer::default();
        let (log, other): (Log, Log) = (Arc::default(), Arc::default());
        let mut tasks = Vec::new();
        for i in 0..20u64 {
            let hold = Duration::from_millis(20 - i);
            tasks.push(job(&s, page("p"), &log, &i.to_string(), tokio::time::sleep(hold)));
            tasks.push(job(&s, page("q"), &other, &i.to_string(), tokio::time::sleep(hold)));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let expected: Vec<String> =
            (0..20).flat_map(|i| [format!("start {i}"), format!("end {i}")]).collect();
        assert_eq!(logged(&log), expected);
        assert_eq!(logged(&other), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn other_pages_and_shared_calls_run_while_a_page_call_holds_its_page() {
        let s = Serializer::default();
        let log: Log = Arc::default();
        let (release, held) = gate();
        let a = job(&s, page("a"), &log, "a", held);
        let b = job(&s, page("b"), &log, "b", async {});
        let shared = job(&s, Turn::shared("reader"), &log, "shared", async {});
        let again = job(&s, page("a"), &log, "a again", async {});
        tokio::time::timeout(Duration::from_secs(5), async {
            b.await.unwrap();
            shared.await.unwrap();
        })
        .await
        .expect("page b and the shared call ran beside page a");
        settle().await;
        assert!(!logged(&log).contains(&"start a again".to_owned()), "page a's next call waits");
        release.send(()).unwrap();
        a.await.unwrap();
        again.await.unwrap();
        let log = logged(&log);
        let at = |e: &str| log.iter().position(|x| x == e).unwrap();
        assert!(at("end a") < at("start a again"));
    }

    // An MCP server answers each request in its own task, so one agent can have a fill on one page and
    // a click on another in flight at once; they still run one at a time, in the order sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_clients_calls_never_overlap_even_on_two_pages() {
        let s = Serializer::default();
        let log: Log = Arc::default();
        let (release, held) = gate();
        let fill = job(&s, on("agent a", "p1"), &log, "fill p1", held);
        let click = job(&s, on("agent a", "p2"), &log, "click p2", async {});
        let pages = job(&s, Turn::shared("agent a"), &log, "pages", async {});
        let other = job(&s, on("agent b", "p3"), &log, "agent b", async {});
        tokio::time::timeout(Duration::from_secs(5), other).await.expect("another agent runs").unwrap();
        settle().await;
        let mut log_now = logged(&log);
        log_now.sort();
        assert_eq!(log_now, ["end agent b", "start agent b", "start fill p1"], "agent a's next calls wait");
        release.send(()).unwrap();
        for t in [fill, click, pages] {
            t.await.unwrap();
        }
        let log = logged(&log);
        assert_eq!(log[3..], ["end fill p1", "start click p2", "end click p2", "start pages", "end pages"]);
    }

    // The sign-in fill, the verification watcher and the sweep take this turn through `run`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_exclusive_call_waits_for_running_calls_and_holds_back_every_later_one() {
        let s = Serializer::default();
        let log: Log = Arc::default();
        let (release_a, held_a) = gate();
        let a = job(&s, page("a"), &log, "a", held_a);
        until_logged(&log, 1).await;
        let shared_before = job(&s, Turn::shared("reader"), &log, "shared before", async {});
        until_logged(&log, 3).await;
        let (release_x, held_x) = gate();
        let x = job(&s, Turn::Exclusive, &log, "x", held_x);
        let b = job(&s, page("b"), &log, "b", async {});
        let shared_after = job(&s, Turn::shared("reader"), &log, "shared after", async {});
        settle().await;
        assert_eq!(logged(&log), ["start a", "start shared before", "end shared before"]);
        release_a.send(()).unwrap();
        a.await.unwrap();
        assert_eq!(until_logged(&log, 5).await[3..], ["end a", "start x"]);
        settle().await;
        assert_eq!(logged(&log).len(), 5, "b and the shared call still wait for x");
        release_x.send(()).unwrap();
        for t in [x, b, shared_before, shared_after] {
            t.await.unwrap();
        }
        let log = logged(&log);
        assert_eq!(log[5], "end x");
        assert_eq!(log.len(), 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_place_given_up_unrun_cancelled_or_by_a_panic_lets_the_line_move() {
        let s = Serializer::default();
        let log: Log = Arc::default();
        let (release, held) = gate();
        let first = job(&s, Turn::Exclusive, &log, "first", held);
        drop(s.enter(Turn::Exclusive));
        let waiting = s.enter(Turn::Exclusive).run(async {});
        assert!(tokio::time::timeout(Duration::from_millis(30), waiting).await.is_err());
        let panics = s.enter(page("a"));
        let panicked = tokio::spawn(panics.run(async { panic!("a call that panics") }));
        let next = job(&s, page("a"), &log, "next", async {});
        release.send(()).unwrap();
        first.await.unwrap();
        let panicked = tokio::time::timeout(Duration::from_secs(2), panicked).await;
        assert!(panicked.expect("the call after the given-up places ran").is_err());
        tokio::time::timeout(Duration::from_secs(2), next).await.expect("the line moved").unwrap();
        assert!(lock(&s.0).places.is_empty());
    }

    #[test]
    fn a_turn_with_no_client_is_exclusive_and_one_clients_turns_conflict() {
        assert_eq!(Turn::page("", "p".into()), Turn::Exclusive);
        assert_eq!(Turn::shared(""), Turn::Exclusive);
        assert!(on("a", "p").conflicts(&Turn::shared("a")) && on("a", "p").conflicts(&on("a", "q")));
        assert!(!on("a", "p").conflicts(&Turn::shared("b")) && !on("a", "p").conflicts(&on("b", "q")));
        assert!(on("a", "p").conflicts(&on("b", "p")), "one page, whoever names it");
        assert!(!Turn::shared("a").conflicts(&Turn::shared("b")));
    }
}
