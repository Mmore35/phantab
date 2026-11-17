//! A record's life: `record`, `watch`, `forget`, `ended`, `detach`, `recover` and the `cdp` wrapper.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use phantab_cdp::{CdpError, Page};
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::time::Instant;

use super::read::Abort;
use super::record::{Detached, Fields, Rec};
use super::relay::{Linked, fire};
use super::{Engine, OTHER_EXTENSION, PAGE_TEXT_LIMIT, RELOAD, cut};
use crate::bridge::ForeignPage;
use crate::engine_api::{EngineError, EngineResult};
use crate::util::{js_string, truthy, uuid_v4};

/// A password manager adds up to two frames per page load.
pub(crate) const RECOVERIES_PER_MINUTE: usize = 6;
const MINUTE: Duration = Duration::from_secs(60);

/// How long a failed call waits for Chrome to report a detach that may have caused it.
const DETACH_REPORT: Duration = Duration::from_millis(500);

async fn sleep_ms(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// How a call passed to [`Engine::cdp`] failed.
#[derive(Debug)]
pub(crate) enum Failed {
    /// No detach can have caused it: an argument the call refused before or without sending anything, or
    /// the page's own answer (a reply carries it, so the page was attached when it gave it).
    Settled(EngineError),
    /// Anything else, which a detach Chrome has yet to report may have caused.
    Unsure(EngineError),
}

impl From<EngineError> for Failed {
    fn from(e: EngineError) -> Self {
        Failed::Unsure(e)
    }
}

/// A page function that threw answered over an attached session; every other CDP failure may be a detach.
impl From<CdpError> for Failed {
    fn from(e: CdpError) -> Self {
        if matches!(e, CdpError::Evaluation { .. }) {
            Failed::Settled(e.into())
        } else {
            Failed::Unsure(e.into())
        }
    }
}

impl From<Failed> for EngineError {
    fn from(f: Failed) -> Self {
        match f {
            Failed::Settled(e) | Failed::Unsure(e) => e,
        }
    }
}

impl Engine {
    pub(crate) fn alive(&self, r: &Arc<Rec>) -> bool {
        self.st().records.iter().any(|x| Arc::ptr_eq(x, r))
    }

    pub(crate) fn find(&self, id: &str) -> Option<Arc<Rec>> {
        self.st().records.iter().find(|r| r.id == id).cloned()
    }

    /// `record(page, owner, fields)`.
    pub(crate) fn record(&self, page: Page, owner: &str, fields: Fields) -> EngineResult<Arc<Rec>> {
        let id = uuid_v4().map_err(|e| EngineError(e.to_string()))?;
        let watched = page.clone();
        let r = Arc::new(Rec::new(id, self.me.clone(), page, owner.to_owned(), fields));
        self.st().records.push(Arc::clone(&r));
        self.watch(&r, &watched, 0);
        Ok(r)
    }

    /// Only the record's current, attached page ends it; a page replaced by a re-attach does not.
    pub(crate) fn watch(&self, r: &Arc<Rec>, page: &Page, generation: u64) {
        let mut closed = page.closed();
        let engine = self.me.clone();
        let r = Arc::clone(r);
        tokio::spawn(async move {
            let _ = closed.wait_for(Option::is_some).await;
            let Some(engine) = engine.upgrade() else { return };
            let current = {
                let s = r.lock();
                s.generation == generation && s.detached.is_none()
            };
            if current && engine.alive(&r) {
                engine.forget(&r.id);
            }
        });
    }

    /// `forget(id)`: drops the record, its leases and viewer token, and ends its page and calls.
    pub(crate) fn forget(&self, id: &str) {
        let r = {
            let mut st = self.st();
            let Some(i) = st.records.iter().position(|r| r.id == id) else { return };
            let r = st.records.remove(i);
            for (_, ids) in &mut st.origins {
                ids.retain(|x| x != id);
            }
            st.origins.retain(|(_, ids)| !ids.is_empty());
            st.viewers.retain(|v| v.page != id);
            r
        };
        if r.is_isolated() {
            self.echo_page_gone(id);
            self.marks_page_gone(id);
        }
        let (link, calls) = {
            let mut s = r.lock();
            (s.link.take(), std::mem::take(&mut s.calls))
        };
        if let Some(link) = link {
            self.close_link(&link);
        }
        for (_, call) in calls {
            let _ = call.send(true);
        }
    }

    /// `ended(r, closeHidden)`: a hidden agent window nobody can see is closed with its page (else it
    /// lingers as an unassigned tab).
    pub(crate) fn ended(&self, r: &Arc<Rec>, close_hidden: bool) {
        let (route, tab) = {
            let mut s = r.lock();
            s.closed = true;
            (s.link.clone(), s.tab_id)
        };
        if let Some(link) = route {
            self.close_route(&link.profile, link.tab, link.route, false);
        }
        if close_hidden
            && r.hidden_workspace()
            && let Some(tab) = tab
        {
            let bridge = Arc::clone(self.bridge());
            let profile = r.profile.clone();
            fire(async move {
                let _ = bridge.op_in(&profile, "closeTab", json!({ "tabId": tab })).await;
            });
        }
        self.forget(&r.id);
    }

    /// `detach(r, message, foreign)`: keeps the record, detached, for its next call to re-attach. Fails
    /// waits and navigations in flight now instead of after their timeouts.
    pub(crate) fn detach(&self, r: &Arc<Rec>, message: &str, foreign: Option<&ForeignPage>) {
        let name =
            foreign.map_or_else(|| OTHER_EXTENSION.to_owned(), |f| self.extension_name(&r.profile, &f.id));
        let menu = if foreign.is_some_and(|f| f.url.ends_with("/overlay/menu.html")) {
            "autofill menu"
        } else {
            "frame"
        };
        let (link, calls) = {
            let mut s = r.lock();
            s.detached = Some(Detached { message: message.to_owned(), at: Instant::now(), name, menu });
            s.detaches += 1;
            (s.link.take(), std::mem::take(&mut s.calls))
        };
        if let Some(link) = link {
            self.close_link(&link);
        }
        for (_, call) in calls {
            let _ = call.send(true);
        }
        // Last, so a woken call finds the old route closed and the calls in flight failed. The bridge's
        // `detach` op for that route is only fired (`close_route`), and an `attach` sent before it would
        // be detached by it. This relies on `recover_once` awaiting before it attaches (a 1 s sleep for a
        // tab the owner sees, the `clearForeignFrames` round trip for a hidden one): keep an await there.
        r.detached_event.notify_waiters();
    }

    /// Waits up to [`DETACH_REPORT`] for a detach after `seen`, waking on the detach itself.
    async fn await_detach(r: &Arc<Rec>, seen: u64) {
        let end = Instant::now() + DETACH_REPORT;
        loop {
            let event = r.detached_event.notified();
            tokio::pin!(event);
            // Registered before the check, so a detach between the two still wakes it.
            event.as_mut().enable();
            if r.lock().detaches != seen || tokio::time::timeout_at(end, event).await.is_err() {
                return;
            }
        }
    }

    /// Viewport and focus emulation every agent workspace page needs, on open, after a re-attach and at
    /// handback.
    pub(crate) async fn prepare(page: &Page) -> EngineResult<()> {
        // Sent together: neither depends on the other, and Chrome runs a session's commands in the
        // order sent. The viewport's error is still the one reported when both fail.
        let (viewport, focus) =
            futures_util::future::join(page.set_viewport(Some((1280, 900))), page.emulate_focus(true)).await;
        viewport?;
        focus?;
        Ok(())
    }

    /// Waits for a re-attach in progress, ignoring how it ended.
    pub(crate) async fn settle_recovery(r: &Arc<Rec>) {
        let running = r.lock().recovering.clone();
        if let Some(running) = running {
            let _ = running.await;
        }
    }

    /// `recover(r)`: re-attaches a detached record, decided at call time; one re-attach at a time.
    pub(crate) async fn recover(&self, r: &Arc<Rec>) -> EngineResult<()> {
        let running = {
            let mut s = r.lock();
            if s.detached.is_none() {
                return Ok(());
            }
            if let Some(running) = &s.recovering {
                running.clone()
            } else {
                let Some(engine) = self.arc() else {
                    return Err(EngineError("The page has since ended.".into()));
                };
                let rec = Arc::clone(r);
                let fut = async move {
                    let out = engine.recover_once(&rec).await;
                    rec.lock().recovering = None;
                    out
                }
                .boxed()
                .shared();
                s.recovering = Some(fut.clone());
                fut
            }
        };
        running.await.map_err(EngineError)
    }

    // Hidden agent windows lose the other extension's frames first; a tab the owner can see is never
    // changed.
    async fn recover_once(&self, r: &Arc<Rec>) -> Result<(), String> {
        let Some(Detached { message, at, name, menu }) = r.lock().detached.clone() else { return Ok(()) };
        let hidden = r.hidden_workspace();
        let tab = r.lock().tab_id;
        // An attach right after the detach gets in before the other extension's page has loaded and
        // leaves a half-attached page; a second later Chrome refuses it while the page is there. This
        // await, and the hidden page's `clearForeignFrames` below, also let `detach()`'s fired `detach`
        // op go first.
        if !hidden {
            tokio::time::sleep_until(at + Duration::from_secs(1)).await;
        }
        let stuck = |fix: &str| format!("{message} The page is still detached: {fix}");
        if hidden {
            let now = Instant::now();
            let mut s = r.lock();
            s.recoveries.retain(|t| now.duration_since(*t) < MINUTE);
            if s.recoveries.len() >= RECOVERIES_PER_MINUTE {
                return Err(stuck(&format!(
                    "{name}'s {menu} keeps coming back ({RECOVERIES_PER_MINUTE} re-attaches this minute). Retry in a minute, or close the page."
                )));
            }
            s.recoveries.push(now);
        }
        let Some(tab) = tab else {
            return Err(stuck("re-attaching failed (no tab). Retry, or close the page."));
        };
        // A hidden page's focus comes back with prepare, and a menu added then detaches once more before
        // the guard has emptied it; the next pass finds it gone.
        let mut p: Option<Linked> = None;
        let mut error: Option<String> = None;
        let mut scan: Option<String> = None;
        for i in 0..(if hidden { 3 } else { 1 }) {
            if p.is_some() {
                break;
            }
            if i > 0 {
                sleep_ms(300).await;
            }
            if !self.alive(r) {
                break;
            }
            if hidden {
                match self.bridge().op_in(&r.profile, "clearForeignFrames", json!({ "tabId": tab })).await {
                    Ok(v) => {
                        scan = v
                            .get("errors")
                            .and_then(|e| e.get(0))
                            .filter(|e| truthy(e))
                            // The extension's words for a failure inside the page (SR-32).
                            .map(|e| cut(&js_string(Some(e)), PAGE_TEXT_LIMIT));
                    }
                    Err(e) => {
                        let e = e.to_string();
                        return Err(stuck(&if e.contains("Unknown bridge operation") {
                            RELOAD.to_owned()
                        } else {
                            format!("removing {name}'s {menu} failed: {e}")
                        }));
                    }
                }
            }
            match self.page_for(&r.profile, tab, r.workspace()).await {
                Ok(linked) => p = Some(linked),
                Err(e) => error = Some(e.0),
            }
            if let Some(linked) = &p
                && hidden
            {
                // A detach ends the screencast that keeps a hidden window rendering.
                let _ = self.bridge().op_in(&r.profile, "keepRendering", json!({ "tabId": tab })).await;
                if let Err(e) = Self::prepare(&linked.page).await {
                    error = Some(e.0);
                    self.close_link(&linked.link);
                    p = None;
                }
            }
        }
        if !self.alive(r) {
            if let Some(linked) = p {
                self.close_link(&linked.link);
            }
            return Err(format!("{message} The page has since ended."));
        }
        let Some(linked) = p else {
            return Err(stuck(&if hidden {
                let scan =
                    scan.map(|s| format!("; looking for {name}'s {menu} failed in {s}")).unwrap_or_default();
                format!(
                    "re-attaching failed ({}){scan}. Retry, or close the page.",
                    error.as_deref().unwrap_or("undefined")
                )
            } else {
                format!(
                    "click elsewhere in that tab to close {name}'s {menu} (or turn it off for this site), then retry."
                )
            }));
        };
        let generation = {
            let mut s = r.lock();
            s.page = linked.page.clone();
            s.link = Some(linked.link);
            s.detached = None;
            s.generation += 1;
            s.generation
        };
        self.watch(r, &linked.page, generation);
        Ok(())
    }

    /// `cdp(r, fn, action)`: runs `f` on the record's current page, re-attaching first when detached. A
    /// detach during `f` re-attaches. A read (`action` `None`) then runs once more, so a password manager's
    /// menu costs an agent nothing; an action fails with what happened and is never replayed, since it may
    /// have landed (SR-35). Chrome fails a command a moment before it reports the detach, so an
    /// [`Failed::Unsure`] failure waits up to 500 ms for that report; a [`Failed::Settled`] one acts only
    /// on a detach already reported.
    pub(crate) async fn cdp<T, E, F, Fut>(&self, r: &Arc<Rec>, action: Option<&str>, f: F) -> EngineResult<T>
    where
        F: Fn(Page, Abort) -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: Into<Failed>,
    {
        Self::settle_recovery(r).await;
        self.recover(r).await?;
        let mut again = action.is_none();
        loop {
            let (tx, rx) = watch::channel(false);
            let (seen, key, page) = {
                let mut s = r.lock();
                s.next_call += 1;
                let key = s.next_call;
                s.calls.insert(key, tx);
                (s.detaches, key, s.page.clone())
            };
            let result = f(page, rx).await;
            r.lock().calls.remove(&key);
            let e = match result.map_err(Into::into) {
                Ok(v) => return Ok(v),
                Err(Failed::Settled(e)) => e,
                Err(Failed::Unsure(e)) => {
                    Self::await_detach(r, seen).await;
                    e
                }
            };
            let still = r.lock().detaches == seen;
            if still || !self.alive(r) {
                return Err(e);
            }
            let detached = r.lock().detached.as_ref().map(|d| d.message.clone());
            let message = detached.unwrap_or_else(|| {
                js_string(self.st().last_disconnect.as_ref().and_then(|d| d.get("reason")))
            });
            let (attached, outcome) = match self.recover(r).await {
                Ok(()) => (true, format!("{message} The page was re-attached as the same pageId.")),
                Err(f) => (false, f.0),
            };
            if again && attached {
                again = false;
                continue;
            }
            let suffix = action
                .map(|a| format!(" The {a} may or may not have taken effect: snapshot before repeating it."))
                .unwrap_or_default();
            return Err(EngineError(outcome + &suffix));
        }
    }

    /// `closeTab(r)`.
    pub(crate) async fn close_tab(&self, r: &Arc<Rec>) -> EngineResult<()> {
        let (closed, tab, page) = {
            let s = r.lock();
            (s.closed, s.tab_id, s.page.clone())
        };
        if closed {
            return Ok(());
        }
        match tab {
            None => Ok(page.close().await?),
            Some(tab) => {
                let _ = self.bridge().op_in(&r.profile, "closeTab", json!({ "tabId": tab })).await;
                Ok(())
            }
        }
    }

    /// `describe(r)`.
    pub(crate) fn describe(r: &Rec) -> serde_json::Map<String, Value> {
        let s = r.lock();
        let mut m = serde_json::Map::new();
        m.insert("pageId".into(), Value::String(r.id.clone()));
        m.insert("url".into(), Value::String(super::report_url(&s.page.url())));
        m.insert("mode".into(), Value::String(s.mode.clone()));
        m.insert("paused".into(), Value::Bool(s.paused));
        m.insert("ownsTab".into(), Value::Bool(s.owned));
        // The folder: unique, the key of `status`'s `otherProfiles`, and accepted back as `profile`. Chrome's
        // name for it, which two profiles may share, comes beside it when Chrome gives one.
        if let Some(name) = &r.profile_name {
            m.insert("profile".into(), Value::String(r.profile.to_string()));
            if **name != *r.profile {
                m.insert("profileName".into(), Value::String(name.clone()));
            }
        }
        if let Some(d) = &s.detached {
            m.insert("detached".into(), Value::String(d.message.clone()));
        }
        m
    }

    /// [`Self::describe`] plus the dialogs the page opened since the last report, when there are any. A
    /// hidden page's dialog is answered at once (the extension, or `answer_dialogs` when headless), so the agent
    /// learns of it here. An accepted "Leave site?" is left out: it is the navigation the agent asked for.
    pub(crate) fn describe_reporting(r: &Rec) -> serde_json::Map<String, Value> {
        let mut m = Self::describe(r);
        let dialogs: Vec<Value> = r
            .lock()
            .page
            .take_dialogs()
            .into_iter()
            .filter(|d| !(d.kind == "beforeunload" && d.accepted == Some(true)))
            .map(|d| {
                let answer = match d.accepted {
                    Some(true) => "accepted",
                    Some(false) => "dismissed",
                    None => "open",
                };
                json!({ "type": d.kind, "message": d.message, "answer": answer })
            })
            .collect();
        if !dialogs.is_empty() {
            m.insert("dialogs".into(), Value::Array(dialogs));
        }
        m
    }
}
