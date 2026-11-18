//! The owner-solved verification hand-off.
//!
//! When a site puts a "are you human" check in front of a page, Phantab stops writing to it, gives the
//! check a few seconds to clear by itself, and then shows the page to the owner, here and (with
//! `remoteViewer`) through a link the agent posts in its chat. Once the check clears, a hand-off Phantab
//! started hands itself back: the window hides again and the agent carries on.
//!
//! A site asking for the owner's passkey takes the same hand-off, of kind `passkey`: only he
//! can give one, in Bitwarden's pop-up or the OS's, and it ends once the page has its answer or moves on.
//!
//! **Phantab never solves the check** (THREAT-MODEL SR-68). Everything here only reads: the CDP frame
//! tree, the challenge frame's box as its parent frame lays it out, and [`VERIFY_STATE`] in the main
//! frame. No input event, focus or script goes to a challenge frame. Every input the page gets during a
//! check is the owner's, through the viewer or his own window.

use std::sync::Arc;
use std::time::Duration;

use phantab_cdp::{BoundingBox, Page};
use serde_json::{Map, Value, json};
use tokio::sync::watch;
use tokio::time::Instant;

use super::Engine;
use super::record::{CheckKind, CheckState, PasskeyFrom, Rec, Verification};
use crate::engine_api::{EngineError, EngineResult};
use crate::page_js::VERIFY_STATE;
use crate::signin::{challenge_frame, challenge_shows, passkey};
use crate::util::{iso_now, random_hex, same_secret};

/// How long a check gets to clear by itself before the owner sees it. Turnstile on the owner's real,
/// signed-in browser cleared with no input in under 2 s in the plan's proofs of concept (POC 6–7), so
/// 8 s leaves room for a slow page without keeping the owner waiting long.
pub(crate) const GRACE: Duration = Duration::from_secs(8);
/// How often the watcher looks. One read of the frame tree and one small evaluate each time.
const POLL: Duration = Duration::from_millis(500);
/// A check counts as cleared once it has stayed gone this long: a wall reloads itself between steps, and
/// a single clear reading in the middle would hand the page back too early (POC 7).
const STEADY: Duration = Duration::from_millis(1500);
/// A hand-off nobody finishes ends by itself, and its link stops working.
pub(crate) const EXPIRY: Duration = Duration::from_mins(15);
/// What the detector may add to a call's time. Past it the call reports nothing; its next call looks again.
const CALL_BUDGET: Duration = Duration::from_millis(300);
/// The watcher can wait longer: no call is held up by it.
const WATCH_BUDGET: Duration = Duration::from_secs(2);
/// Rate limits against a hostile page faking checks to make the owner's window pop up: one pop-up per
/// page per 10 minutes and three per site per hour. Checks that cleared by themselves cost the owner
/// nothing, so they do not count.
const PAGE_WINDOW: Duration = Duration::from_secs(600);
const PAGE_LIMIT: usize = 1;
const SITE_WINDOW: Duration = Duration::from_secs(3600);
const SITE_LIMIT: usize = 3;
/// `browser_wait {verification:true}` returns after at most this long, so an agent's call never hangs.
pub(crate) const WAIT_LIMIT: Duration = Duration::from_secs(60);
/// How long a wake token answers after its pop-up: past [`EXPIRY`], so a waiter that looks just after
/// the check ended still learns how it ended, and the CLI's own cap (`cli::WAKE_LIMIT`) fits inside.
const WATCH_KEEP: Duration = Duration::from_mins(17);

/// What one look at a page found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seen {
    Nothing,
    Check(CheckKind),
    /// The page did not answer (navigating, busy). Neither a check nor its absence.
    Unknown,
}

/// The rules over what the page reported (unit-tested apart from the browser).
fn classify(state: &Value, visible_frame: bool) -> Seen {
    let n = |k: &str| state.pointer(k).and_then(Value::as_u64).unwrap_or(0);
    let (total, empty, usable) = (n("/fields/total"), n("/fields/empty"), n("/usable"));
    let wall_title = state.get("wallTitle").and_then(Value::as_bool).unwrap_or(false);
    // Every response field filled: the check is solved, whatever the page still looks like.
    if total > 0 && empty == 0 {
        return Seen::Nothing;
    }
    if wall_title {
        return Seen::Check(CheckKind::Wall);
    }
    if visible_frame {
        // A widget with nothing else on the page to use is in front of the whole page (POC 7).
        return Seen::Check(if usable == 0 { CheckKind::Wall } else { CheckKind::Widget });
    }
    Seen::Nothing
}

/// Reads the page: the challenge frames in the CDP frame tree (Turnstile's iframe is not in the DOM a
/// page script sees, POC 6), whether any is laid out with an area, and [`VERIFY_STATE`].
pub(crate) async fn detect(page: &Page) -> Seen {
    let Ok(main) = page.main_frame() else { return Seen::Unknown };
    let mut visible = false;
    for f in page.frames() {
        if f.id == main || !challenge_frame(&f.url) {
            continue;
        }
        // The box comes from the `<iframe>` element in its parent; nothing runs inside the frame.
        // An area is not enough: a check parked offscreen or hidden asks nothing of the owner.
        if let Ok(Some(b)) = page.frame_element_box(&f.id).await
            && b.width * b.height > 0.0
            && challenge_shows(page, &f.id).await
        {
            visible = true;
            break;
        }
    }
    match page.evaluate(&main, VERIFY_STATE, Vec::new()).await {
        Ok(state) => classify(&state, visible),
        Err(_) => Seen::Unknown,
    }
}

async fn detect_within(page: &Page, budget: Duration) -> Seen {
    tokio::time::timeout(budget, detect(page)).await.unwrap_or(Seen::Unknown)
}

/// The page's address without its fragment: a hash change is not the page moving on.
fn without_fragment(url: &str) -> String {
    url.split_once('#').map_or(url, |(u, _)| u).to_owned()
}

/// The rules for a passkey hand-off (unit-tested apart from the browser): it is over once the page
/// has moved on, a request was answered, or the counts started again (a new document at the same
/// address). Otherwise the passkey is still the owner's to give, pending or not: he may cancel the
/// pop-up and ask again from the page.
fn passkey_rule(from: &PasskeyFrom, url: &str, now: Option<phantab_cdp::PasskeyAsks>) -> Seen {
    if without_fragment(url) != from.url {
        return Seen::Nothing;
    }
    match now {
        None => Seen::Unknown,
        Some(a) if a.answered > from.asks.answered || a.asked < from.asks.asked => Seen::Nothing,
        Some(_) => Seen::Check(CheckKind::Passkey),
    }
}

async fn passkey_seen(page: &Page, from: &PasskeyFrom, budget: Duration) -> Seen {
    match tokio::time::timeout(budget, passkey::read(page)).await {
        Ok(now) => passkey_rule(from, &page.url(), now),
        Err(_) => Seen::Unknown,
    }
}

/// What the watcher sees on a hand-off's page: its own detector for a passkey, else the check's.
async fn seen_for(page: &Page, from: Option<&PasskeyFrom>, budget: Duration) -> Seen {
    match from {
        Some(from) => passkey_seen(page, from, budget).await,
        None => detect_within(page, budget).await,
    }
}

/// The visible challenge frame's box, for the viewer's zoom.
pub(crate) async fn challenge_box(page: &Page) -> Option<BoundingBox> {
    let main = page.main_frame().ok()?;
    for f in page.frames() {
        if f.id == main || !challenge_frame(&f.url) {
            continue;
        }
        // An area is not enough: a check parked offscreen or hidden asks nothing of the owner.
        if let Ok(Some(b)) = page.frame_element_box(&f.id).await
            && b.width * b.height > 0.0
            && challenge_shows(page, &f.id).await
        {
            return Some(b);
        }
    }
    None
}

fn site(origin: &str) -> String {
    url::Url::parse(origin).ok().and_then(|u| u.host_str().map(str::to_owned)).unwrap_or_default()
}

fn prune(times: &mut std::collections::VecDeque<Instant>, window: Duration) {
    let now = Instant::now();
    while times.front().is_some_and(|t| now.duration_since(*t) >= window) {
        times.pop_front();
    }
}

impl Engine {
    fn remote_link(&self, token: &str) -> Option<String> {
        self.setup.remote_base.as_ref().map(|base| format!("{base}/view#{token}"))
    }

    /// The `verification` field of a result: a live hand-off, or one that ended since the last report
    /// (reported once, then dropped).
    pub(crate) fn verification_field(&self, r: &Rec) -> Option<Value> {
        self.verification_report(r, true)
    }

    /// [`Self::verification_field`]; `consume` false leaves an ended hand-off for the next result.
    fn verification_report(&self, r: &Rec, consume: bool) -> Option<Value> {
        let mut s = r.lock();
        let v = s.verification.as_ref()?;
        let state = v.current();
        let mut m = Map::new();
        m.insert("state".into(), Value::String(state.name().to_owned()));
        m.insert("kind".into(), Value::String(kind_name(v.kind).to_owned()));
        m.insert("since".into(), Value::String(v.since.clone()));
        if state.live()
            && let Some(link) = v.link_token.as_deref().and_then(|t| self.remote_link(t))
        {
            m.insert("link".into(), Value::String(link));
            if let Some(watch) = v.watch_token.as_deref()
                && let Some(wake) = wake_command(watch)
            {
                m.insert("wake".into(), Value::String(wake));
            }
        }
        m.insert("next".into(), Value::String(next_line(v.kind, state, v.link_token.is_some()).to_owned()));
        if consume && !state.live() {
            s.verification = None;
        }
        Some(Value::Object(m))
    }

    /// Adds [`Self::verification_field`] to a result.
    pub(crate) fn with_verification(&self, r: &Rec, mut out: Map<String, Value>) -> Map<String, Value> {
        if let Some(v) = self.verification_field(r) {
            out.insert("verification".into(), v);
        }
        out
    }

    /// The refusal a write gets while a check holds the page or its site; `None` when none does.
    pub(crate) fn verification_refusal(&self, r: &Rec) -> Option<EngineError> {
        let s = r.lock();
        let v = s.verification.as_ref().filter(|v| v.current().live() && !v.prior_paused)?;
        let host = site(&v.origin);
        let wait = |until: &str| {
            format!(
                "Carry on with other sites; browser_wait {{pageId: \"{}\", verification: true}} returns as soon as {until}.",
                r.id
            )
        };
        let link = v.link_token.as_deref().and_then(|t| self.remote_link(t));
        if v.kind == CheckKind::Passkey {
            let text = match link {
                Some(link) => format!(
                    "{host} is waiting for the owner's passkey, which only they can give. Tell them once, as in the sign-in's verification.next; this link lets them pick another way from anywhere: {link} {}",
                    wait("they have given it")
                ),
                None => format!(
                    "{host} is waiting for the owner's passkey, which only they can give. {}",
                    wait("they have given it")
                ),
            };
            return Some(EngineError(text));
        }
        let text = match (v.current(), link) {
            (CheckState::Checking, _) => format!(
                "A verification check on {host} is giving itself a few seconds to clear before Phantab shows it to the owner. {}",
                wait("it clears or the owner has it")
            ),
            (_, Some(link)) => format!(
                "A verification check on {host} is with the owner. Post this link in your chat once so they can solve it from anywhere: {link} {}",
                wait("it clears")
            ),
            (_, None) => format!("A verification check on {host} is with the owner. {}", wait("it clears")),
        };
        Some(EngineError(text))
    }

    /// After a call: looks for a check, and starts the hand-off for a wall. A widget is only reported:
    /// the agent asks for it with `browser_show {verification:true}` once its own form work is done.
    pub(crate) async fn look(&self, r: &Arc<Rec>) -> Option<Value> {
        self.look_reporting(r, true).await
    }

    /// [`Self::look`]; `consume` as in [`Self::verification_report`].
    async fn look_reporting(&self, r: &Arc<Rec>, consume: bool) -> Option<Value> {
        let (page, live, closed) = {
            let s = r.lock();
            (s.page.clone(), s.verification.as_ref().is_some_and(|v| v.current().live()), s.closed)
        };
        if !live && !closed && is_website(&page.url()) {
            match detect_within(&page, CALL_BUDGET).await {
                Seen::Check(CheckKind::Wall) => self.begin(r, CheckKind::Wall, false),
                Seen::Check(CheckKind::Widget) => {
                    return Some(json!({
                        "state": "widget",
                        "kind": "widget",
                        "next": "This page's form has a verification check. Finish your own form work, then call browser_show {pageId, verification: true} so the owner can solve it; the page comes back to you by itself once it clears.",
                    }));
                }
                Seen::Check(CheckKind::Passkey) | Seen::Nothing | Seen::Unknown => {}
            }
        }
        self.verification_report(r, consume)
    }

    /// [`Self::look`] into a result.
    pub(crate) async fn looked(&self, r: &Arc<Rec>, mut out: Map<String, Value>) -> Map<String, Value> {
        if let Some(v) = self.look(r).await {
            out.insert("verification".into(), v);
        }
        out
    }

    /// When a call failed: if the page now shows a check, the failure is the check's refusal, since a
    /// selector that never appears behind a wall says nothing useful.
    pub(crate) async fn explain(&self, r: &Arc<Rec>, e: EngineError) -> EngineError {
        // An error carries no `verification`, so an ended check stays for the next result to report.
        let _ = self.look_reporting(r, false).await;
        self.verification_refusal(r).unwrap_or(e)
    }

    /// Starts a hand-off. `asked` is the agent's `browser_show {verification:true}`: the owner sees it at
    /// once and the rate limits do not apply, since the agent, not the page, chose to ask.
    pub(crate) fn begin(&self, r: &Arc<Rec>, kind: CheckKind, asked: bool) {
        self.begin_with(r, kind, asked, None);
    }

    /// [`Self::begin`], with where a passkey hand-off started.
    fn begin_with(&self, r: &Arc<Rec>, kind: CheckKind, asked: bool, passkey: Option<PasskeyFrom>) {
        let Ok(origin) = url::Url::parse(&r.page().url()).map(|u| u.origin().ascii_serialization()) else {
            return;
        };
        let id = {
            let mut s = r.lock();
            if s.verification.as_ref().is_some_and(|v| v.current().live()) {
                return;
            }
            let prior_paused = s.paused;
            s.paused = true;
            if !prior_paused {
                s.handback = false;
            }
            // The calls counter is unique per record, which is all a hand-off id needs.
            s.next_call += 1;
            let id = s.next_call;
            let (state, _) = watch::channel(CheckState::Checking);
            s.verification = Some(Verification {
                id,
                kind,
                started: Instant::now(),
                since: iso_now(),
                state,
                prior_paused,
                shown: prior_paused,
                origin,
                link_token: None,
                watch_token: None,
                owner_done: false,
                declined: false,
                passkey,
            });
            id
        };
        tracing::info!(page = %r.id, ?kind, asked, "verification check found");
        let (Some(me), r) = (self.arc(), Arc::clone(r)) else { return };
        tokio::spawn(async move { me.watch_check(r, id, asked).await });
    }

    /// The hand-off's own task, outside the service queue so the agent's other pages carry on. Window
    /// work (the pop-up, the hand-back) still goes through the queue, as every other window change does.
    async fn watch_check(self: Arc<Self>, r: Arc<Rec>, id: u64, asked: bool) {
        let mut clear_since: Option<Instant> = None;
        loop {
            let (started, state, owner_done, declined, page, from) = {
                let s = r.lock();
                let Some(v) = s.verification.as_ref().filter(|v| v.id == id && v.current().live()) else {
                    return;
                };
                (v.started, v.current(), v.owner_done, v.declined, s.page.clone(), v.passkey.clone())
            };
            if !self.alive(&r) {
                return;
            }
            if declined {
                self.end_check(&r, id, CheckState::Declined).await;
                return;
            }
            if owner_done {
                self.end_check(&r, id, CheckState::Cleared).await;
                return;
            }
            if started.elapsed() >= EXPIRY {
                self.end_check(&r, id, CheckState::Expired).await;
                return;
            }
            match seen_for(&page, from.as_ref(), WATCH_BUDGET).await {
                Seen::Nothing => {
                    let since = *clear_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= STEADY {
                        self.end_check(&r, id, CheckState::Cleared).await;
                        return;
                    }
                }
                Seen::Check(_) | Seen::Unknown => clear_since = None,
            }
            if state == CheckState::Checking && clear_since.is_none() && (asked || started.elapsed() >= GRACE)
            {
                if !asked && !self.within_limits(&r) {
                    self.end_check(&r, id, CheckState::Suspected).await;
                    return;
                }
                self.pop_up(&r, id).await;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Takes a pop-up from the rate limits, or says it is over them. The record and engine locks are
    /// taken one at a time: `lock_site` takes them the other way round. Only this page's own watcher
    /// spends from its history, so the gap between them races nothing.
    pub(super) fn within_limits(&self, r: &Rec) -> bool {
        let origin = {
            let mut s = r.lock();
            let Some(origin) = s.verification.as_ref().map(|v| v.origin.clone()) else { return false };
            prune(&mut s.verify_history, PAGE_WINDOW);
            if s.verify_history.len() >= PAGE_LIMIT {
                return false;
            }
            origin
        };
        let now = Instant::now();
        {
            let mut st = self.st();
            if !st.verify_sites.iter().any(|(o, _)| *o == origin) {
                st.verify_sites.push((origin.clone(), std::collections::VecDeque::new()));
            }
            let Some((_, times)) = st.verify_sites.iter_mut().find(|(o, _)| *o == origin) else {
                return false;
            };
            prune(times, SITE_WINDOW);
            if times.len() >= SITE_LIMIT {
                return false;
            }
            times.push_back(now);
        }
        r.lock().verify_history.push_back(now);
        true
    }

    /// The show step: the same window path as `browser_show`, and the remote link's token.
    pub(super) async fn pop_up(&self, r: &Arc<Rec>, id: u64) {
        let link_token = if self.setup.remote_base.is_some() { random_hex(24).ok() } else { None };
        // The wake token comes with the link: an agent that posts a link ends its turn, so it needs a wake.
        let watch_token = link_token.as_ref().and_then(|_| random_hex(24).ok());
        // The link works before anyone hears of it: a `browser_wait` wakes on `WithOwner` and posts it.
        self.add_remote_viewer(r, link_token.clone());
        let (watch, workspace) = {
            let mut s = r.lock();
            let Some(v) = s.verification.as_mut().filter(|v| v.id == id) else {
                drop(s);
                if let Some(t) = link_token {
                    self.st().viewers.retain(|v| v.token != t);
                }
                return;
            };
            v.link_token.clone_from(&link_token);
            let watch = watch_token.map(|token| super::Watch {
                token,
                page: r.id.clone(),
                made: Instant::now(),
                state: v.state.subscribe(),
            });
            v.watch_token = watch.as_ref().map(|w| w.token.clone());
            let held = v.shown;
            v.shown = true;
            v.state.send_replace(CheckState::WithOwner);
            // The owner already holding the page, only the link is new.
            (watch, (!held).then_some(s.workspace))
        };
        // The engine lock after the record's, never inside it (see `within_limits`).
        if let Some(w) = watch {
            let mut st = self.st();
            st.watches.retain(|w| w.made.elapsed() < WATCH_KEEP);
            st.watches.push(w);
        }
        let Some(workspace) = workspace else { return };
        let shown = self.setup.serializer.run(self.show_inner(r, workspace)).await;
        if let Err(e) = shown {
            // The link still works; the agent posts it. The window may show at the owner's next look.
            tracing::warn!(page = %r.id, error = %e.0, "verification pop-up failed");
        }
    }

    fn add_remote_viewer(&self, r: &Rec, token: Option<String>) {
        if let Some(t) = token {
            self.st().viewers.push(super::Viewer { token: t, page: r.id.clone(), remote: true });
        }
    }

    /// Ends a hand-off. A hand-off Phantab started gives the page back to the agent; one the owner already
    /// held stays with him (SR-69). Either way the link stops working.
    async fn end_check(&self, r: &Arc<Rec>, id: u64, outcome: CheckState) {
        let (prior_paused, shown, token) = {
            let mut s = r.lock();
            let Some(v) = s.verification.as_mut().filter(|v| v.id == id) else { return };
            (v.prior_paused, v.shown, v.link_token.take())
        };
        if let Some(t) = token {
            self.st().viewers.retain(|v| v.token != t);
        }
        Self::release_held(r);
        if !prior_paused {
            let back = if shown {
                self.setup
                    .serializer
                    .run(async {
                        let back = self.hand_back(r, true).await;
                        if back.is_err() {
                            // Unpaused anyway: the check is over, and a window left showing is the owner's
                            // to close. Still in the slot, so a `show` queued behind the hand-back sees the
                            // page given back and takes the usual path, never a paused page it would show
                            // and then lose to this unpause (review r5 N1).
                            self.unpause(r);
                        }
                        back
                    })
                    .await
            } else {
                self.unpause(r);
                Ok(())
            };
            if let Err(e) = back {
                tracing::warn!(page = %r.id, error = %e.0, "verification hand-back failed");
            }
        }
        if let Some(v) = r.lock().verification.as_mut().filter(|v| v.id == id) {
            v.state.send_replace(outcome);
        }
        tracing::info!(page = %r.id, state = outcome.name(), "verification check ended");
    }

    fn unpause(&self, r: &Rec) {
        let token = {
            let mut s = r.lock();
            s.paused = false;
            s.handback = false;
            s.viewer_token.take()
        };
        if let Some(t) = token {
            self.st().viewers.retain(|v| v.token != t);
        }
    }

    /// Ends a live hand-off at once, with no window work: the page is closing or released.
    pub(crate) fn drop_check(&self, r: &Rec) {
        let token = {
            let mut s = r.lock();
            let Some(v) = s.verification.take() else { return };
            if !v.prior_paused && v.current().live() {
                s.paused = false;
                s.handback = false;
            }
            v.state.send_replace(CheckState::Declined);
            v.link_token
        };
        if let Some(t) = token {
            self.st().viewers.retain(|v| v.token != t);
        }
        Self::release_held(r);
    }

    /// The release of a press the owner's device left down (its tab locked or closed mid-hold, or the
    /// check ended first), sent once the check is over: else every later click on the page refuses
    /// ("'left' is already pressed."). It is the owner's own press ending, never input of Phantab's own.
    fn release_held(r: &Rec) {
        let Some((x, y)) = r.lock().pointer_held.take() else { return };
        let page = r.page();
        super::relay::fire(async move {
            let _ = page.mouse_up(x, y).await;
        });
    }

    /// `browser_show {verification:true}`: Phantab checks for itself that a check is there before it
    /// asks the owner, so an agent cannot use it to pop any page up.
    pub(crate) async fn show_check(&self, r: &Arc<Rec>) -> EngineResult {
        if r.lock().verification.as_ref().is_some_and(|v| v.current().live()) {
            return Ok(Value::Object(self.with_verification(r, Self::describe(r))));
        }
        let page = r.page();
        // A passkey request waiting (the agent clicked the site's passkey button): only the owner can
        // answer it, so it is handed to him the same way, whatever else the page shows.
        if passkey::waiting(&page).await {
            self.lock_site(r, None)?;
            self.start_passkey(r).await;
            return Ok(Value::Object(self.with_verification(r, Self::describe(r))));
        }
        let kind = match detect_within(&page, WATCH_BUDGET).await {
            Seen::Check(kind) => kind,
            Seen::Nothing => return Err(EngineError("No verification check is on this page.".to_owned())),
            Seen::Unknown => {
                return Err(EngineError(
                    "The page did not answer, so Phantab could not see a check. Retry in a few seconds."
                        .to_owned(),
                ));
            }
        };
        self.lock_site(r, None)?;
        self.begin(r, kind, true);
        Self::shown_soon(r).await;
        Ok(Value::Object(self.with_verification(r, Self::describe(r))))
    }

    /// The pop-up runs in the hand-off's task; gives it a moment so the result can carry the link.
    async fn shown_soon(r: &Rec) {
        let mut state = r.lock().verification.as_ref().map(|v| v.state.subscribe());
        if let Some(rx) = state.as_mut() {
            let _ = tokio::time::timeout(Duration::from_secs(2), rx.wait_for(|s| *s != CheckState::Checking))
                .await;
        }
    }

    /// A sign-in's `wall` / `passkey`: the tab goes to the owner at once, as a hand-off of
    /// kind `passkey`, and the result's `verification` says what to tell him. `None` when nothing was
    /// handed over (the page closed, or is not a website).
    pub(crate) async fn hand_off_passkey(&self, r: &Arc<Rec>) -> Option<Value> {
        if !self.start_passkey(r).await {
            return None;
        }
        self.verification_field(r)
    }

    /// Starts a passkey hand-off, asked: the agent's own call met the request, so the owner sees it at
    /// once and the rate limits do not apply, as for `browser_show {verification:true}`. A page that
    /// forges a request only gets its tab shown (THREAT-MODEL SR-75). Whether a hand-off is live now.
    async fn start_passkey(&self, r: &Arc<Rec>) -> bool {
        let page = r.page();
        let url = page.url();
        if r.lock().closed || !is_website(&url) {
            return false;
        }
        let from = PasskeyFrom { url: without_fragment(&url), asks: passkey::asks(&page).await };
        self.begin_with(r, CheckKind::Passkey, true, Some(from));
        Self::shown_soon(r).await;
        r.lock().verification.as_ref().is_some()
    }

    /// `browser_wait {verification:true}`: until the check on the page reaches the owner (from `checking`)
    /// or ends, or [`WAIT_LIMIT`].
    pub(crate) async fn wait_check(&self, r: &Arc<Rec>, within: Duration) -> Value {
        // A wall found now starts its hand-off, which this then waits for. A widget only waits for the agent.
        // A check that ended before this call is reported by `look`, once; it is the result's fallback.
        let looked = self.look(r).await;
        let rx = r.lock().verification.as_ref().filter(|v| v.current().live()).map(|v| v.state.subscribe());
        if let Some(mut rx) = rx {
            // Woken as the owner gets it, the agent can post the link at once.
            let from_checking = *rx.borrow() == CheckState::Checking;
            let done = move |s: &CheckState| !s.live() || (from_checking && *s != CheckState::Checking);
            let _ = tokio::time::timeout(within.min(WAIT_LIMIT), rx.wait_for(done)).await;
        }
        let mut out = self.with_verification(r, Self::describe(r));
        if let Some(v) =
            looked.filter(|v| v.get("state").and_then(Value::as_str).is_some_and(|s| !is_live_name(s)))
        {
            out.entry("verification").or_insert(v);
        }
        Value::Object(out)
    }

    /// `check_wait {watch}` (the `wake` command's call): until the hand-off holding this wake token
    /// ends, or [`WAIT_LIMIT`]. Every token is compared, in constant time (SR-72), and only the state
    /// and page id come back.
    pub(crate) async fn wait_watch(&self, watch: &str) -> Value {
        let found = {
            let mut st = self.st();
            st.watches.retain(|w| w.made.elapsed() < WATCH_KEEP);
            let mut found = None;
            for w in &st.watches {
                if same_secret(w.token.as_bytes(), watch.as_bytes()) {
                    found = Some((w.page.clone(), w.state.clone()));
                }
            }
            found
        };
        let Some((page, mut rx)) = found else { return json!({ "state": "gone" }) };
        let ended = tokio::time::timeout(WAIT_LIMIT, rx.wait_for(|s| !s.live())).await.map(|r| r.map(|s| *s));
        let state = match ended {
            Ok(Ok(s)) => s.name(),
            // The hand-off went without an end state; nothing is left to wait for.
            Ok(Err(_)) => "gone",
            Err(_) => rx.borrow().name(),
        };
        json!({ "state": state, "pageId": page })
    }

    /// The viewer's Done: Phantab looks for itself, since the owner may press it before the page has
    /// moved on.
    pub(crate) async fn owner_done(&self, r: &Arc<Rec>) -> EngineResult {
        let live = r.lock().verification.as_ref().is_some_and(|v| v.current().live());
        if !live {
            r.lock().handback = true;
            return Ok(json!({ "ready": true }));
        }
        let from = r.lock().verification.as_ref().and_then(|v| v.passkey.clone());
        if from.is_some() {
            // A passkey is the owner's own call: Done is his word that he gave it, or chose not to,
            // unless the site is plainly still waiting for it.
            if passkey::waiting(&r.page()).await {
                return Err(EngineError(
                    "The site is still waiting for your passkey. Give it in the pop-up, or close the pop-up, then press Done again."
                        .to_owned(),
                ));
            }
        } else if detect_within(&r.page(), WATCH_BUDGET).await != Seen::Nothing {
            return Err(EngineError(
                "The site still shows a check. Finish it, then press Done again.".to_owned(),
            ));
        }
        if let Some(v) = r.lock().verification.as_mut() {
            v.owner_done = true;
        }
        Ok(json!({ "ready": true }))
    }

    /// The viewer's Not now.
    pub(crate) fn owner_declined(r: &Rec) -> Value {
        if let Some(v) = r.lock().verification.as_mut() {
            v.declined = true;
        }
        json!({ "ready": true })
    }
}

fn is_website(url: &str) -> bool {
    url.starts_with("http:") || url.starts_with("https:")
}

/// A reported state that is still live (a widget is reported but not yet a hand-off): the result's own
/// field is current for it, so `look`'s copy is not kept.
fn is_live_name(state: &str) -> bool {
    matches!(state, "checking" | "with-owner")
}

/// The `wake` command for a wake token: this binary, quoted, then `check-wait <token>`. Forward slashes,
/// so the line runs as given in a POSIX shell on Windows too. `None` if the binary's path is unknown.
fn wake_command(watch: &str) -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let exe = exe.to_str()?;
    let exe = if cfg!(windows) { exe.replace('\\', "/") } else { exe.to_owned() };
    Some(format!("\"{exe}\" check-wait {watch}"))
}

fn kind_name(kind: CheckKind) -> &'static str {
    match kind {
        CheckKind::Wall => "wall",
        CheckKind::Widget => "widget",
        CheckKind::Passkey => "passkey",
    }
}

/// What the agent should do next, per kind and state. The link is posted once, as a plain line.
fn next_line(kind: CheckKind, state: CheckState, link: bool) -> &'static str {
    if kind == CheckKind::Passkey {
        return passkey_line(state, link);
    }
    match (state, link) {
        (CheckState::Checking, _) => {
            "A site is checking that a human is here. Leave this page alone for a moment and carry on with other sites; browser_wait {pageId, verification: true} returns once it clears or the owner has it."
        }
        (CheckState::WithOwner, true) => {
            "The owner has the check. Post the link once in your chat, as a plain line: \"A site needs you to confirm you're human: <link>\". Don't repeat it. Before you end your turn, start the wake command as a background command (in PowerShell, put & before it): it exits the moment the check ends, and your harness wakes you then. On waking, carry on with this page at once, since a solved check expires in about two minutes. While your turn lasts, browser_wait {pageId, verification: true} also returns once it clears."
        }
        (CheckState::WithOwner, false) => {
            "The check is open in the owner's Chrome. browser_wait {pageId, verification: true} returns once it clears; carry on with other sites meanwhile."
        }
        (CheckState::Cleared, _) => {
            "The check cleared and the page is yours again. Snapshot it and carry on."
        }
        (CheckState::Declined, _) => {
            "The owner chose not to solve this check now. Leave this site for now and tell the owner what is waiting on it."
        }
        (CheckState::Expired, _) => {
            "Nobody solved the check in 15 minutes and the link has stopped working. The page is yours again; tell the owner what is waiting on it."
        }
        (CheckState::Suspected, _) => {
            "This site keeps showing checks, more than a real site would, so nothing popped up. If the owner wants to solve it, call browser_show {pageId, verification: true}."
        }
    }
}

/// [`next_line`] for a passkey hand-off: one line to the owner, in the agent's words, then wait.
fn passkey_line(state: CheckState, link: bool) -> &'static str {
    match (state, link) {
        (CheckState::Checking, _) => {
            "The site asked for the owner's passkey and Phantab is showing them the page. Leave this page alone; browser_wait {pageId, verification: true} returns once they have it."
        }
        (CheckState::WithOwner, true) => {
            "The site wants the owner's passkey, which only they can give, at their computer. Tell them once, as a plain line: \"<site> wants your passkey: confirm it in the pop-up on your computer (Bitwarden, Windows Hello or Touch ID) and I'll take it from there. Away from it? Open <link> to pick another way.\" Don't repeat it. Before you end your turn, start the wake command as a background command (in PowerShell, put & before it): it exits the moment they are done, and your harness wakes you then. While your turn lasts, browser_wait {pageId, verification: true} also returns then."
        }
        (CheckState::WithOwner, false) => {
            "The site wants the owner's passkey, which only they can give. Tell them once, as a plain line: \"<site> wants your passkey: confirm it in the pop-up on your computer (Bitwarden, Windows Hello or Touch ID) and I'll take it from there.\" browser_wait {pageId, verification: true} returns once they are done; carry on with other sites meanwhile."
        }
        (CheckState::Cleared, _) => {
            "The owner is done with the passkey and the page is yours again. Snapshot it to see whether the sign-in finished, and carry on."
        }
        (CheckState::Declined, _) => {
            "The owner chose not to give the passkey now. Leave this site for now and tell the owner what is waiting on it."
        }
        (CheckState::Expired, _) => {
            "Nobody gave the passkey in 15 minutes and the link has stopped working. The page is yours again; tell the owner what is waiting on it."
        }
        (CheckState::Suspected, _) => {
            "The site asked for a passkey, but nothing popped up. If the owner wants to give it, call browser_show {pageId, verification: true}."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(wall_title: bool, total: u64, empty: u64, usable: u64) -> Value {
        json!({ "wallTitle": wall_title, "fields": { "total": total, "empty": empty }, "usable": usable })
    }

    #[test]
    fn the_detector_rules() {
        // A wall by its title, with or without a frame.
        assert_eq!(classify(&state(true, 0, 0, 5), false), Seen::Check(CheckKind::Wall));
        // POC 7: a widget that is the page's only usable content is a wall.
        assert_eq!(classify(&state(false, 1, 1, 0), true), Seen::Check(CheckKind::Wall));
        assert_eq!(classify(&state(false, 0, 0, 0), true), Seen::Check(CheckKind::Wall));
        // A widget inside a form.
        assert_eq!(classify(&state(false, 1, 1, 4), true), Seen::Check(CheckKind::Widget));
        // Solved: every response field filled, even under a wall title.
        assert_eq!(classify(&state(true, 1, 0, 0), true), Seen::Nothing);
        assert_eq!(classify(&state(false, 2, 0, 4), true), Seen::Nothing);
        // A response field with no visible frame (an invisible reCAPTCHA) is not a check for the owner.
        assert_eq!(classify(&state(false, 1, 1, 4), false), Seen::Nothing);
        // An ordinary page.
        assert_eq!(classify(&state(false, 0, 0, 12), false), Seen::Nothing);
        // A page that did not answer the evaluate in shape counts as nothing, not a check.
        assert_eq!(classify(&json!(null), false), Seen::Nothing);
    }

    #[test]
    fn every_state_names_itself_and_says_what_next() {
        for s in [
            CheckState::Checking,
            CheckState::WithOwner,
            CheckState::Cleared,
            CheckState::Declined,
            CheckState::Expired,
            CheckState::Suspected,
        ] {
            assert_ne!(s.name(), "");
            for kind in [CheckKind::Wall, CheckKind::Widget, CheckKind::Passkey] {
                assert_ne!(next_line(kind, s, true), "");
                assert_ne!(next_line(kind, s, false), "");
            }
            assert_ne!(next_line(CheckKind::Passkey, s, true), next_line(CheckKind::Wall, s, true));
            assert_eq!(s.live(), matches!(s, CheckState::Checking | CheckState::WithOwner));
        }
        // The owner is told of the passkey and the pop-up; the link is only for another way.
        for link in [true, false] {
            let line = next_line(CheckKind::Passkey, CheckState::WithOwner, link);
            assert!(line.contains("wants your passkey") && line.contains("Bitwarden"), "{line}");
            assert_eq!(line.contains("<link>"), link, "{line}");
        }
    }

    #[test]
    fn a_passkey_hand_off_ends_when_the_page_has_its_answer_or_moves_on() {
        use phantab_cdp::PasskeyAsks;
        let asks = |asked, pending, answered| Some(PasskeyAsks { asked, pending, answered });
        let from = PasskeyFrom {
            url: "https://a.example/login".into(),
            asks: PasskeyAsks { asked: 1, pending: 1, answered: 0 },
        };
        let here = "https://a.example/login";
        // Waiting, or the pop-up closed with no answer: still the owner's.
        assert_eq!(passkey_rule(&from, here, asks(1, 1, 0)), Seen::Check(CheckKind::Passkey));
        assert_eq!(passkey_rule(&from, here, asks(1, 0, 0)), Seen::Check(CheckKind::Passkey));
        assert_eq!(
            passkey_rule(&from, "https://a.example/login#again", asks(2, 1, 0)),
            Seen::Check(CheckKind::Passkey)
        );
        // Answered, a new document at the same address, or another address.
        assert_eq!(passkey_rule(&from, here, asks(1, 0, 1)), Seen::Nothing);
        assert_eq!(passkey_rule(&from, here, asks(0, 0, 0)), Seen::Nothing);
        assert_eq!(passkey_rule(&from, "https://a.example/home", None), Seen::Nothing);
        // No frame answered: neither.
        assert_eq!(passkey_rule(&from, here, None), Seen::Unknown);
        assert_eq!(without_fragment("https://a.example/x?q=1#f"), "https://a.example/x?q=1");
    }
}
