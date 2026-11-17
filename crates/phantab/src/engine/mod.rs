//! The page engine.
//!
//! Every agent page is a record. A shared page (`shared-hidden`, `visible`, `existing-tab`) is a
//! [`phantab_cdp::Page`] over the bridge's CDP relay ([`relay`]); `isolated-headless` launches its own
//! headless Chrome. Records keep their owner (the client id), the site leases (`lock`), the handoff
//! state (`paused`, `handback`, the viewer token) and the detach state that [`recover`] re-attaches
//! from. Window work goes through [`phantab_window::WindowControl`]; how it differs per platform is in
//! [`window`]. Sign-in runs in `crate::signin`, which reaches the engine through its `Host` and `SignInRecord`
//! traits ([`signin_host`]).
//!
//! Error texts are part of the interface agents read: change them only on purpose.

mod echo;
mod files;
mod guardrails;
mod ops;
mod profiles;
mod quiet;
mod read;
mod record;
mod recover;
mod relay;
mod signin_host;
mod verify;
mod window;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use phantab_cdp::CdpError;
use phantab_window::{HideStrategy, WindowControl, WindowError};
use serde_json::{Map, Value, json};
use tokio::sync::broadcast::error::RecvError;

use crate::bridge::{self, Bridge, BridgeEvent, ForeignPage, Profile, ProfileCheck, TabId, USUAL};
use crate::engine_api::{
    CONNECTION_POLICY, EngineError, EngineMethod, EngineResult, EngineSetup, PageService,
};
use crate::util::{iso_now, lock};

pub(crate) use profiles::start_chrome;
pub use read::{READ_TIMEOUT_FRAME, until};

use record::Rec;
use relay::Route;

pub(crate) const RELOAD: &str =
    "Reload the phantab bridge at chrome://extensions so it reports why Chrome detached it.";
/// SR-32: page-controlled text in an error is cut to this many characters.
pub(crate) const PAGE_TEXT_LIMIT: usize = 300;

/// A page being created, so a detach during creation can end it (`this.creating`).
#[derive(Debug, Default)]
struct Creating {
    detached: Option<String>,
    /// The relay route of its page once attached (`c.transport`).
    route: Option<u64>,
}

/// A profile's last check (`profileVerified`, `lastError` in status).
#[derive(Debug, Default)]
pub(crate) struct Check {
    verified: bool,
    last_error: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct State {
    /// In creation order.
    records: Vec<Arc<Rec>>,
    creating: HashMap<(Profile, TabId), Creating>,
    /// Site leases: (profile, origin) → the records holding it, in the order they took it.
    origins: Vec<((Profile, String), Vec<String>)>,
    /// Live view tokens.
    viewers: Vec<Viewer>,
    /// Wake tokens of verification hand-offs (`check_wait`), kept a while past their check's end so a
    /// waiter that looks just after it still learns how it ended.
    watches: Vec<Watch>,
    /// Verification pop-ups per site in the last hour (`verify`'s rate limit).
    verify_sites: Vec<(String, std::collections::VecDeque<tokio::time::Instant>)>,
    /// Per profile; a refused link's reason goes to the usual profile's.
    checks: HashMap<Profile, Check>,
    last_disconnect: Option<Value>,
    quiet: Option<Value>,
    /// A closed page's hidden window, kept for its client's next open (`window::Spare`).
    spare: Option<window::Spare>,
    /// What sign-ins saw sites show back, redacted from everything the agent receives ([`echo`]).
    echoes: Vec<Arc<crate::signin::Echo>>,
    /// The tabs whose screenshots are refused for it.
    echo_marks: Vec<echo::EchoMark>,
}

/// A live view token and the page it shows. A local token opens the viewer on this machine and never
/// leaves the service; a remote one is the verification link the agent posts, accepted only by the
/// remote listener (THREAT-MODEL SR-8). Neither listener takes the other's.
#[derive(Debug)]
pub(crate) struct Viewer {
    pub token: String,
    pub page: String,
    pub remote: bool,
}

/// A verification hand-off's wake token: read-only, it tells `check_wait` the check's state and page id
/// and opens nothing (THREAT-MODEL SR-72).
#[derive(Debug)]
pub(crate) struct Watch {
    pub token: String,
    pub page: String,
    pub made: tokio::time::Instant,
    pub state: tokio::sync::watch::Receiver<record::CheckState>,
}

/// The page engine. Built by [`Engine::new`]; the service holds it as a [`PageService`].
pub struct Engine {
    me: Weak<Engine>,
    setup: EngineSetup,
    windows: Arc<dyn WindowControl>,
    /// The sign-in call's options.
    options: crate::signin::Options,
    state: Mutex<State>,
    /// Relay pages by profile and tab: where the dispatcher sends each tab's CDP events. Tab IDs are a
    /// Chrome profile's own, so two profiles can both have tab 7.
    routes: Mutex<HashMap<(Profile, TabId), Route>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("strategy", &self.windows.strategy())
            .field("pages", &self.active_pages())
            .finish_non_exhaustive()
    }
}

impl From<CdpError> for EngineError {
    /// The error's text, with a page's own words (a thrown error) cut to [`PAGE_TEXT_LIMIT`] (SR-32).
    fn from(e: CdpError) -> Self {
        match e {
            CdpError::Evaluation { message, .. } => EngineError(cut(&message, PAGE_TEXT_LIMIT)),
            other => EngineError(other.to_string()),
        }
    }
}

impl From<WindowError> for EngineError {
    fn from(e: WindowError) -> Self {
        EngineError(e.to_string())
    }
}

/// A `lastDisconnect` `d`, naming `profile` when it is not the usual one (SR-76).
fn in_profile(mut d: Value, profile: &Profile) -> Value {
    if **profile != *USUAL {
        d["profile"] = Value::String(profile.to_string());
    }
    d
}

/// The first `n` characters of `s`.
pub(crate) fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// What a message calls an extension it cannot name.
pub(crate) const OTHER_EXTENSION: &str = "The other extension";

/// Whether `id` has the form of a Chrome extension ID: 32 letters, each `a` to `p`.
pub(crate) fn is_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// SR-34: the most of a page's URL phantab reports, in UTF-16 units, as a snapshot cuts an href.
pub(crate) const URL_LIMIT: usize = 2048;

/// A page's URL as phantab reports it: cut to [`URL_LIMIT`], with `…` after a cut one. A page sets its
/// own URL (a same-document navigation can grow the hash to megabytes), and it goes into every result.
pub(crate) fn report_url(url: &str) -> String {
    let mut out = read::utf16_prefix(url, URL_LIMIT);
    if out.len() < url.len() {
        out.push('…');
    }
    out
}

impl Engine {
    /// Builds the engine and starts its one bridge-event dispatcher, subscribed before this returns.
    #[must_use]
    pub fn new(
        setup: EngineSetup,
        windows: Arc<dyn WindowControl>,
        options: crate::signin::Options,
    ) -> Arc<Self> {
        let mut events = setup.bridge.subscribe();
        let engine = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            setup,
            windows,
            options,
            state: Mutex::default(),
            routes: Mutex::default(),
        });
        let weak = Arc::downgrade(&engine);
        tokio::spawn(async move {
            loop {
                let event = match events.recv().await {
                    Ok(e) => e,
                    Err(RecvError::Lagged(n)) => {
                        // 16384 events behind: a page's frame tree may now be stale; its next detach or
                        // re-attach rebuilds it.
                        tracing::warn!(lost = n, "engine fell behind the bridge's events");
                        continue;
                    }
                    Err(RecvError::Closed) => break,
                };
                let Some(engine) = weak.upgrade() else { break };
                engine.on_event(event);
            }
        });
        engine
    }

    /// The engine as an Arc, for work that outlives the call (`None` only while it is being dropped).
    pub(crate) fn arc(&self) -> Option<Arc<Engine>> {
        self.me.upgrade()
    }

    pub(crate) fn bridge(&self) -> &Arc<Bridge> {
        &self.setup.bridge
    }

    pub(crate) fn strategy(&self) -> HideStrategy {
        self.windows.strategy()
    }

    pub(crate) fn st(&self) -> std::sync::MutexGuard<'_, State> {
        lock(&self.state)
    }

    fn on_event(&self, event: BridgeEvent) {
        match event {
            BridgeEvent::Connect { profile, .. } => {
                self.verify(&profile);
                if *profile == *USUAL {
                    self.apply_quiet();
                }
            }
            // Filed under the profile the refused copy claimed; one that named none, or none allowed, under
            // the usual profile.
            BridgeEvent::Refused { profile, reason } => {
                let profile = profile.unwrap_or_else(|| Arc::from(USUAL));
                Engine::check_mut(&mut self.st(), &profile).last_error = Some(reason);
            }
            // Shared page IDs die with the link; the extension detaches its tabs and closes hidden agent
            // windows. Only that profile's: another profile's link and pages go on.
            BridgeEvent::Disconnect { profile, reason } => {
                let shared: Vec<Arc<Rec>> = {
                    let mut st = self.st();
                    Engine::check_mut(&mut st, &profile).verified = false;
                    st.last_disconnect =
                        Some(in_profile(json!({ "at": iso_now(), "reason": reason }), &profile));
                    st.records.clone()
                };
                self.spare_gone(&profile, None);
                for r in shared {
                    if !r.is_isolated() && r.profile == profile {
                        self.ended(&r, false);
                    }
                }
            }
            BridgeEvent::TabEnded { profile, tab_id, reason, tab_open, foreign } => {
                self.tab_ended(&profile, tab_id, reason.as_deref(), tab_open, foreign.as_ref());
            }
            BridgeEvent::Cdp(event) => self.route_event(&event),
        }
    }

    // Chrome also detaches (target_closed, tab open) when another extension's page appears in the tab;
    // that record is kept, detached, and re-attached on its next call.
    fn tab_ended(
        &self,
        profile: &Profile,
        tab: TabId,
        reason: Option<&str>,
        tab_open: Option<bool>,
        foreign: Option<&ForeignPage>,
    ) {
        if reason == Some("removed") {
            self.echo_tab_closed(profile, tab);
        }
        let target_closed = reason == Some("target_closed");
        let kept = target_closed && tab_open == Some(true);
        let message = (target_closed && tab_open != Some(false))
            .then(|| self.detach_message(profile, tab, foreign, tab_open));
        let records = {
            let mut st = self.st();
            let route = match (st.creating.get_mut(&(profile.clone(), tab)), &message) {
                (Some(c), Some(m)) => {
                    c.detached = Some(m.clone());
                    c.route
                }
                _ => None,
            };
            drop(st);
            if let Some(route) = route {
                self.close_route(profile, tab, route, false);
            }
            self.st().records.clone()
        };
        self.spare_gone(profile, Some(tab));
        for r in records.into_iter().filter(|r| r.profile == *profile) {
            let mine = {
                let mut s = r.lock();
                if s.viewer_tab == Some(tab) {
                    s.viewer_tab = None;
                }
                s.tab_id == Some(tab)
            };
            if !mine {
                continue;
            }
            if let Some(m) = &message {
                let d = json!({ "at": iso_now(), "tabId": tab.to_string(), "reason": m });
                self.st().last_disconnect = Some(in_profile(d, profile));
            }
            match (&message, kept) {
                (Some(m), true) => self.detach(&r, m, foreign),
                _ => self.ended(&r, reason != Some("removed")),
            }
        }
        if reason == Some("canceled_by_user") {
            let d = json!({
                "at": iso_now(),
                "reason": format!("The owner canceled debugging from Chrome's bar or the bridge's badge (tab {tab}); its agent page was released and is not re-attached without asking."),
            });
            self.st().last_disconnect = Some(in_profile(d, profile));
        }
    }

    fn detach_message(
        &self,
        profile: &str,
        tab: TabId,
        foreign: Option<&ForeignPage>,
        tab_open: Option<bool>,
    ) -> String {
        if tab_open.is_none() {
            return format!("Chrome detached the agent from tab {tab} and the page was released. {RELOAD}");
        }
        let Some(foreign) = foreign else {
            return format!(
                "Chrome detached the agent from tab {tab} (target_closed); the tab stayed open and no other extension's frame was seen."
            );
        };
        format!(
            "{}'s page {} appeared in tab {tab}; Chrome does not let one extension debug a tab that shows another extension's page, so it detached the agent.",
            self.extension_name(profile, &foreign.id),
            cut(&foreign.url, PAGE_TEXT_LIMIT)
        )
    }

    /// The name of extension `id` as Chrome profile `profile` has it installed, for a message an agent
    /// reads. `id` is the host of a frame's URL, and the page in the tab chooses the address it frames
    /// (SR-32): a host that is not an extension ID is not looked up and not repeated, and a name is cut
    /// like any page text.
    pub(crate) fn extension_name(&self, profile: &str, id: &str) -> String {
        if !is_extension_id(id) {
            return OTHER_EXTENSION.to_owned();
        }
        let name = match &self.setup.config.user_data_dir {
            Some(dir) => bridge::extension_name(dir, self.folder(profile), id),
            None => id.to_owned(),
        };
        cut(&name, PAGE_TEXT_LIMIT)
    }

    /// The `status()` map, keys in their documented order.
    fn status_map(&self) -> Map<String, Value> {
        let st = self.st();
        let mut m = Map::new();
        let usual = st.checks.get(USUAL);
        m.insert("connected".into(), Value::Bool(self.setup.bridge.connected_in(USUAL)));
        // Absent in the config means absent here, as JSON.stringify drops undefined.
        if let Some(p) = &self.setup.config.profile_directory {
            m.insert("profile".into(), Value::String(p.clone()));
        }
        m.insert("profileVerified".into(), Value::Bool(usual.is_some_and(|c| c.verified)));
        m.insert("agentPages".into(), json!(st.records.len()));
        m.insert(
            "lastError".into(),
            usual.and_then(|c| c.last_error.clone()).map_or(Value::Null, Value::String),
        );
        m.insert("lastDisconnect".into(), st.last_disconnect.clone().unwrap_or(Value::Null));
        // Keyed by folder: Chrome's names need not be unique.
        let others = self.setup.config.allowed_other_profiles();
        if !others.is_empty() {
            let names =
                self.setup.config.user_data_dir.as_deref().map(bridge::profile_names).unwrap_or_default();
            let mut o = Map::new();
            for folder in others {
                let check = st.checks.get(folder.as_str());
                let name = names.iter().find(|(f, _)| *f == folder).map(|(_, n)| n.clone());
                o.insert(
                    folder.clone(),
                    json!({
                        "name": name,
                        "connected": self.setup.bridge.connected_in(&folder),
                        "profileVerified": check.is_some_and(|c| c.verified),
                        "lastError": check.and_then(|c| c.last_error.clone()),
                    }),
                );
            }
            m.insert("otherProfiles".into(), Value::Object(o));
        }
        m.insert("connectionPolicy".into(), Value::String(CONNECTION_POLICY.to_owned()));
        if let Some(Value::Object(q)) = &st.quiet {
            m.insert("quietDebugging".into(), Value::Object(Engine::quiet_status(q)));
        }
        m
    }

    fn verify(&self, profile: &Profile) -> ProfileCheck {
        let check = self.profile_check(profile)();
        self.record_check(profile, check)
    }

    /// `require_browser`'s check, on tokio's blocking pool. It reads every file of the installed extension
    /// (up to 64 MiB), and a virus scanner can hold each one open; on one of `serve`'s two workers
    /// (`mode::SERVICE_WORKERS`) that would stall the bridge and every other client's call.
    async fn verify_off_workers(&self, profile: &Profile) -> ProfileCheck {
        let check = tokio::task::spawn_blocking(self.profile_check(profile)).await.unwrap_or_else(|e| {
            ProfileCheck::Failed { final_: true, error: format!("Chrome profile check failed: {e}") }
        });
        self.record_check(profile, check)
    }

    fn record_check(&self, profile: &Profile, check: ProfileCheck) -> ProfileCheck {
        let mut st = self.st();
        let c = Engine::check_mut(&mut st, profile);
        c.verified = check == ProfileCheck::Ok;
        c.last_error = match &check {
            ProfileCheck::Ok => None,
            ProfileCheck::Failed { error, .. } => Some(error.clone()),
        };
        check
    }

    /// The bridge connects by itself; a cold service gives Chrome a moment to relaunch the host. Another
    /// allowed profile that is closed is started ([`Engine::link_up`]).
    pub(crate) async fn require_browser(&self, profile: &Profile) -> EngineResult<()> {
        let result = async {
            self.link_up(profile).await?;
            let timed = || async {
                let at = std::time::Instant::now();
                let check = self.verify_off_workers(profile).await;
                (check, at.elapsed())
            };
            let (mut check, mut took) = timed().await;
            // Chrome records a just-loaded extension in Preferences on a timer (about 10 s).
            let end = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
            while let ProfileCheck::Failed { final_: false, .. } = check {
                if tokio::time::Instant::now() >= end {
                    break;
                }
                tokio::time::sleep(recheck_gap(took)).await;
                (check, took) = timed().await;
            }
            match check {
                ProfileCheck::Ok => Ok(()),
                ProfileCheck::Failed { error, .. } => Err(EngineError(error)),
            }
        }
        .await;
        if let Err(e) = &result {
            Engine::check_mut(&mut self.st(), profile).last_error = Some(e.0.clone());
        }
        result
    }

    pub(crate) fn chrome_executable(&self) -> Option<PathBuf> {
        self.setup.config.chrome_executable.clone()
    }

    /// [`PageService::ready`]: the browser wait a call starts with, run before it queues, for the profile
    /// it names. `connect`, `tabs` and `attach` start with it; `open` after its url, mode and profile
    /// checks, and not for an isolated-headless page, which needs no bridge. The call runs it once more in
    /// its turn: no wait unless the link dropped in between, but the profile check reads and hashes the
    /// files again. A bad `profile` is left for the call to report.
    pub(crate) async fn ready_for(&self, method: EngineMethod, args: &Value) -> EngineResult<()> {
        let target = match method {
            EngineMethod::Connect | EngineMethod::Tabs | EngineMethod::Attach => self.target(args).ok(),
            EngineMethod::Open => Self::open_args(args)
                .ok()
                .filter(|(_, mode)| mode != "isolated-headless")
                .and_then(|(_, mode)| self.open_target(args, &mode).ok()),
            _ => None,
        };
        match target {
            Some(t) => self.require_browser(&t.profile).await,
            None => Ok(()),
        }
    }
}

/// The wait before the next profile re-check, after one that took `took`. A re-check of unchanged files
/// reuses their parse (`bridge::settings`), so it comes every 250 ms and the connect ends soon after
/// Chrome's commit. One that took longer than 15 ms (a CPU without SHA instructions hashes about as
/// slowly as it parses, or very large Preferences) waits the 1 s it did before. The threshold is absolute,
/// so the bound is too: at most 15 ms of every 265 ms, under 6% of one core and under 1 s of CPU, and only
/// while a connect waits for Chrome's commit. Relative to main it can be 4 to 6x: a CPU without SHA
/// instructions and small Preferences (a check of 8 to 12 ms, against main's 6 to 10 ms once a second)
/// takes the 250 ms gap too (perf-ops-11).
pub(crate) fn recheck_gap(took: std::time::Duration) -> std::time::Duration {
    std::time::Duration::from_millis(if took <= std::time::Duration::from_millis(15) { 250 } else { 1000 })
}

/// The engine the service runs: the platform's window control (or none, in a test build that asks for
/// it with `PHANTAB_TEST_WINDOWS=none`).
#[must_use]
pub fn from_setup(setup: EngineSetup) -> Arc<Engine> {
    #[allow(unused_mut, reason = "only test builds change the defaults")]
    let mut windows = phantab_window::platform();
    #[allow(unused_mut, reason = "only test builds change the defaults")]
    let mut options = crate::signin::Options::default();
    #[cfg(feature = "test-seams")]
    {
        if std::env::var("PHANTAB_TEST_WINDOWS").as_deref() == Ok("none") {
            windows = Arc::new(phantab_window::Noop);
        }
        if std::env::var("PHANTAB_TEST_ALLOW_LOOPBACK").as_deref() == Ok("1") {
            options = options.with_loopback(true);
        }
    }
    Engine::new(setup, windows, options)
}

#[async_trait]
impl PageService for Engine {
    /// Every answer passes [`Engine::redacted`].
    async fn call(&self, method: EngineMethod, args: Value, client: &str) -> EngineResult {
        let result = self.call_raw(method, args, client).await;
        self.redacted(result, method == EngineMethod::Screenshot)
    }

    async fn ready(&self, method: EngineMethod, args: &Value) -> EngineResult<()> {
        let result = self.ready_for(method, args).await;
        self.redacted(result.map(|()| Value::Null), false).map(|_| ())
    }

    async fn viewer(&self, token: &str, action: Option<&str>, args: Value, remote: bool) -> EngineResult {
        self.viewer_call(token, action, &args, remote).await
    }

    fn viewer_known(&self, token: &str, remote: bool) -> bool {
        self.viewer_page(token, remote).is_some()
    }

    async fn check_wait(&self, watch: &str) -> Value {
        let result = self.wait_watch(watch).await;
        self.redacted(result, false)
    }

    async fn restart_quiet(&self) -> EngineResult {
        let result = Engine::restart_quiet(self).await;
        self.redacted(result, false)
    }

    async fn release(&self, client: &str) -> EngineResult {
        let result = self.release_all(client).await;
        self.redacted(result, false)
    }

    async fn dispose(&self) -> EngineResult<()> {
        self.dispose_all().await
    }

    fn status(&self) -> Map<String, Value> {
        self.redacted(self.status_map(), false)
    }

    fn active_pages(&self) -> usize {
        self.st().records.len()
    }
}

impl Engine {
    /// [`PageService::call`] before its redaction.
    async fn call_raw(&self, method: EngineMethod, args: Value, client: &str) -> EngineResult {
        match method {
            EngineMethod::Pages => Ok(self.pages(client)),
            EngineMethod::Connect => {
                let profile = self.target(&args)?.profile;
                self.require_browser(&profile).await?;
                Ok(Value::Object(self.status_map()))
            }
            EngineMethod::Open => self.open(client, &args).await,
            EngineMethod::Tabs => self.tabs(&args).await,
            EngineMethod::Attach => self.attach(client, &args).await,
            EngineMethod::Snapshot => self.snapshot(client, &args).await,
            EngineMethod::Act => self.act(client, &args).await,
            EngineMethod::Show => self.show(client, &args).await,
            EngineMethod::Resume => self.resume(client, &args).await,
            EngineMethod::Close => self.close(client, &args).await,
            EngineMethod::Screenshot => self.screenshot(client, &args).await,
            EngineMethod::Wait => self.wait(client, &args).await,
            EngineMethod::SignIn => crate::signin::sign_in(self, client, &args).await,
            EngineMethod::SignUp => crate::signin::sign_up(self, client, &args).await,
        }
    }
}
