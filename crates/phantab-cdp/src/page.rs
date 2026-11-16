//! One page: its frame tree, OOPIF sessions, execution contexts, navigation, input and emulation.
//!
//! The bookkeeping follows puppeteer-core 25.11's `FrameManager`, `IsolatedWorld`, `LifecycleWatcher`
//! and `TargetManager`; where it differs, the comment at that spot says so.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures_util::future::join_all;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};

use crate::handle::{Arg, JsHandle, call_function, value_from_remote};
use crate::input::{Keyboard, Mouse, MouseButton, Txn, char_is_key};
use crate::{CdpError, SessionId, Transport, TransportEvent};

/// How many recently removed frames are remembered, so a late call on one says "detached" rather than
/// "unknown".
const DETACHED_MEMORY: usize = 256;

/// A frame id (CDP `Page.FrameId`; for the main frame this is also the target id).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct FrameId(pub String);

impl FrameId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FrameId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for FrameId {
    fn from(s: &str) -> Self {
        FrameId(s.to_owned())
    }
}

/// A snapshot of one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameInfo {
    pub id: FrameId,
    pub url: String,
    pub parent: Option<FrameId>,
    /// Only [`Page::frame_info`] reports `true`; [`Page::frames`] lists attached frames, like puppeteer.
    pub detached: bool,
}

/// A rectangle in CSS pixels.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BoundingBox {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Page tuning.
#[derive(Debug, Clone)]
pub struct PageOptions {
    /// Per-command limit (puppeteer's `protocolTimeout`; the engine uses 15 s).
    pub protocol_timeout: Duration,
    /// How long to wait for a frame's execution context (puppeteer's default timeout, 30 s).
    pub default_timeout: Duration,
    /// Total time for [`Page::click_selector`] and [`Page::fill`], retries included (the engine's
    /// `locator.setTimeout(10000)`). Zero means no limit.
    pub locator_timeout: Duration,
    /// The page's target id when it lives on a browser-level connection: [`Page::close`] then uses
    /// `Target.closeTarget` on the browser session. Without it, `Page.close` goes to the root session.
    pub target_id: Option<String>,
    /// Answer JavaScript dialogs the moment they open: `beforeunload` and `alert` accepted, `confirm` and
    /// `prompt` dismissed. For a page nobody can see (headless), where an open dialog would block the page,
    /// a close and a navigation until someone answered. Shared pages leave this off: their extension answers
    /// first, before Chrome draws the dialog (`extension/src/background.ts`, `answerHiddenDialog`).
    pub answer_dialogs: bool,
    /// Open a page's popups as tabs of its own window ([`POPUPS_AS_TABS`]), in every frame, before the
    /// frame's own scripts run. For a page in a hidden window: a popup is a new top-level window that
    /// nothing hides, so Chrome draws it on the owner's screen.
    pub popups_as_tabs: bool,
    /// Count the page's passkey requests ([`PASSKEY_WATCH`]), in every frame, before the frame's own
    /// scripts run, for [`Page::passkey_asks`]. For a page the agent drives: a passkey request there
    /// raises a pop-up only the owner can answer, so a sign-in has to hand the tab to him.
    pub watch_passkeys: bool,
}

/// `window.open` with a features string asks for a popup window; `popup=0` last overrides any earlier
/// `popup` or size keys (HTML's "check if a popup window is requested"), so it opens a tab instead,
/// keeping `opener`, the name and `noopener`. A Proxy keeps `typeof`, `name` and `length`.
///
/// `document.open(url, name, features)`, the three-argument form, is wrapped the same way: Blink sends
/// it to the native `open`, past whatever `window.open` now holds. All three arguments are required
/// there, so `undefined` features read as the string `undefined`, which asks for a popup too; a template
/// literal converts them as Blink does. The two-argument `document.open` (rewrite this document) is left
/// as it is.
///
/// It runs in the main world on purpose, as fill's writes do (`dom.rs`): it must replace the `open` the
/// page's own code calls, and an isolated world has its own `window`. A page can tell it is there
/// (`Function.prototype.toString` of a Proxy reads `function () { [native code] }`, without the name),
/// and phantab does not try to hide that it drives a page (THREAT-MODEL SR-61). Chrome runs the script
/// in every new document of the session's frames, the initial `about:blank` of a new iframe included
/// (`InspectorPageAgent::DidCreateMainWorldContext` injects on every main-world context it creates), so
/// an `open` taken from a fresh same-origin iframe is wrapped too.
pub const POPUPS_AS_TABS: &str = "(() => { const open = window.open; \
    window.open = new Proxy(open, { apply(target, self, args) { \
    const features = args.length > 2 && args[2] !== undefined ? String(args[2]) : ''; \
    if (features !== '') args = [args[0], args[1], features + ',popup=0', ...args.slice(3)]; \
    return Reflect.apply(target, self, args); } }); \
    Document.prototype.open = new Proxy(Document.prototype.open, { apply(target, self, args) { \
    if (args.length > 2) args = [args[0], args[1], `${args[2]},popup=0`, ...args.slice(3)]; \
    return Reflect.apply(target, self, args); } }); })();";

/// Counts the frame's passkey requests: `navigator.credentials.get` or `.create` called with a
/// `publicKey` option, other than `mediation: "conditional"` (autofill, which shows nothing until the
/// owner picks a passkey from the field's menu). `asked` counts calls, `pending` the ones not settled
/// yet, `answered` the ones that settled with a credential. It keeps no option, credential or other
/// data, only the three numbers, read with [`PASSKEY_READ`].
///
/// Both the prototype's methods and the instance are covered, in either order with a password
/// manager's main-world override (Bitwarden's `fido2-page-script.js` binds whatever
/// `navigator.credentials.get` is, then plain-assigns its own): an own accessor on the instance wraps
/// any function assigned to it and otherwise returns the prototype's, itself wrapped. A request that
/// goes through both is counted twice, which does no harm: the engine compares counts with an earlier
/// read of the same frame. The wrapper calls through first and counts after, inside `try`, so it never
/// changes what the page gets, and it never calls `WebAuthn` itself.
///
/// It runs in the main world, as [`POPUPS_AS_TABS`] does and for the same reason, so the page can
/// forge the numbers. That only makes the engine hand the tab to the owner, which `browser_show` can
/// do anyway (THREAT-MODEL SR-75).
pub const PASSKEY_WATCH: &str = "(() => { try { \
    const C = window.CredentialsContainer, creds = window.navigator && navigator.credentials; \
    if (!C || !creds || Object.prototype.hasOwnProperty.call(window, '__phantabPasskeys')) return; \
    const apply = Reflect.apply, then = Promise.prototype.then, own = Object.prototype.hasOwnProperty; \
    let asked = 0, pending = 0, answered = 0; \
    const counted = (args) => { try { const o = args[0]; \
    return !!o && typeof o === 'object' && 'publicKey' in o && o.mediation !== 'conditional'; } \
    catch (e) { return false; } }; \
    const watch = (fn) => typeof fn !== 'function' ? fn : new Proxy(fn, { apply(target, self, args) { \
    const result = apply(target, self, args); \
    try { if (counted(args)) { asked++; pending++; let done = false; \
    const settle = (v) => { if (!done) { done = true; pending--; if (v) answered++; } }; \
    try { apply(then, result, [settle, () => settle(null)]); } catch (e) { settle(null); } } } catch (e) {} \
    return result; } }); \
    for (const name of ['get', 'create']) { \
    const d = Object.getOwnPropertyDescriptor(C.prototype, name); \
    if (!d || typeof d.value !== 'function') continue; \
    Object.defineProperty(C.prototype, name, { value: watch(d.value), writable: d.writable, \
    enumerable: d.enumerable, configurable: d.configurable }); \
    let assigned = own.call(creds, name) ? watch(creds[name]) : undefined; \
    Object.defineProperty(creds, name, { configurable: true, enumerable: false, \
    get() { return assigned !== undefined ? assigned : C.prototype[name]; }, \
    set(v) { assigned = watch(v); } }); } \
    Object.defineProperty(window, '__phantabPasskeys', \
    { value: Object.freeze({ read: () => ({ asked, pending, answered }) }) }); \
    } catch (e) {} })();";

/// Reads [`PASSKEY_WATCH`]'s numbers in the frame's main world: `{asked, pending, answered}`, or
/// `null` where the script is not running.
pub const PASSKEY_READ: &str = "() => { const w = window.__phantabPasskeys; return w && typeof w.read === 'function' ? w.read() : null; }";

/// The frame's passkey requests so far, as [`PASSKEY_WATCH`] counts them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PasskeyAsks {
    /// Requests made.
    pub asked: u64,
    /// Requests not settled yet: a pop-up may be open.
    pub pending: u64,
    /// Requests that settled with a credential.
    pub answered: u64,
}

/// The isolated world phantab's page functions run in (THREAT-MODEL SR-34). It shares the frame's DOM but
/// none of the page's JavaScript: a page that replaces `document.querySelector`, a prototype method or
/// the `value` setter cannot change what a read returns, steer where a click lands, or see a value a
/// sign-in writes, and page script cannot reach the world. Made per frame and document with
/// `Page.createIsolatedWorld`, never with `grantUniveralAccess` (Chrome's spelling), which would let it
/// read other origins.
pub const ISOLATED_WORLD: &str = "phantab";

impl Default for PageOptions {
    fn default() -> Self {
        PageOptions {
            protocol_timeout: Duration::from_secs(15),
            default_timeout: Duration::from_secs(30),
            locator_timeout: Duration::from_secs(10),
            target_id: None,
            answer_dialogs: false,
            popups_as_tabs: false,
            watch_passkeys: false,
        }
    }
}

/// A JavaScript dialog the page opened, as `Page.javascriptDialogOpening` and `...Closed` reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog {
    /// `alert`, `confirm`, `prompt` or `beforeunload`.
    pub kind: String,
    /// The page's own text: untrusted, and cut to [`DIALOG_MESSAGE_LIMIT`] characters.
    pub message: String,
    /// `Some(true)` accepted, `Some(false)` dismissed, `None` still open.
    pub accepted: Option<bool>,
}

/// A tab's history, as [`Page::history`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    /// The index of the current entry in `entries`.
    pub current: usize,
    pub entries: Vec<HistoryEntry>,
}

/// One entry of a [`History`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// What [`Page::go_to_history_entry`] takes.
    pub id: i64,
    pub url: String,
    /// Chrome's `transitionType`: `form_submit` for a page a form sent, which loading again may send again.
    pub transition: String,
}

/// Dialogs kept until [`Page::take_dialogs`]; a page that opens more loses the oldest.
const DIALOG_MEMORY: usize = 10;

/// [`Page::visual_viewport`]'s fallback: the viewport as the page sees it, in CSS pixels.
/// The document's scroll size, for [`Page::full_page`] when `Page.getLayoutMetrics` is refused.
const DOCUMENT_SIZE: &str = "()=>{const d=document.documentElement,b=document.body;return{width:Math.max(d.scrollWidth,b?b.scrollWidth:0),height:Math.max(d.scrollHeight,b?b.scrollHeight:0)};}";
const VISUAL_VIEWPORT: &str = "()=>{const v=window.visualViewport;return v?{x:v.pageLeft,y:v.pageTop,width:v.width,height:v.height}:{x:scrollX,y:scrollY,width:document.documentElement.clientWidth,height:document.documentElement.clientHeight};}";

/// `Page.captureScreenshot`'s base64, moved out of the reply rather than copied (a few hundred kilobytes).
fn screenshot_data(reply: Value) -> Result<String, CdpError> {
    if let Value::Object(mut m) = reply
        && let Some(Value::String(data)) = m.remove("data")
    {
        return Ok(data);
    }
    Err(CdpError::Other("Page.captureScreenshot returned no data".into()))
}

pub const DIALOG_MESSAGE_LIMIT: usize = 500;

/// Where an execution context lives: a frame's main world or its isolated world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextRef {
    pub session: Option<SessionId>,
    pub id: i64,
    pub frame: FrameId,
    /// The context's `uniqueId` from `Runtime.executionContextCreated`, when Chrome sent one. Calls go
    /// by it: a number can name another context once its own is gone (ids are per renderer, so an OOPIF
    /// swap can reuse one in the same session), a unique id names this context or none.
    pub unique: Option<String>,
}

#[derive(Debug, Clone)]
struct Frame {
    parent: Option<FrameId>,
    url: String,
    loader_id: String,
    lifecycle: HashSet<String>,
    started_loading: bool,
    /// The session whose events own this frame: the root, or the OOPIF session it moved to.
    session: Option<SessionId>,
    /// The main world's context (`isDefault`).
    context: Option<i64>,
    /// Its `uniqueId`; set with every `context = Some(..)`, read only while `context` is.
    context_unique: Option<String>,
    /// The [`ISOLATED_WORLD`] context of the current document, once a call asked for it.
    world: Option<i64>,
    /// Its `uniqueId`, as the world's `executionContextCreated` gave it.
    world_unique: Option<String>,
    /// Bumped each time `world` is forgotten, so the answer to a `Page.createIsolatedWorld` sent before
    /// is not kept for a document it does not belong to.
    world_epoch: u64,
    same_document_navigations: u64,
    swaps: u64,
    /// When it was added: siblings list in this order, as puppeteer's `page.frames()` does.
    order: u64,
}

impl Frame {
    fn new(parent: Option<FrameId>, session: Option<SessionId>) -> Self {
        Frame {
            parent,
            url: String::new(),
            loader_id: String::new(),
            lifecycle: HashSet::new(),
            started_loading: false,
            session,
            context: None,
            context_unique: None,
            world: None,
            world_unique: None,
            world_epoch: 0,
            same_document_navigations: 0,
            swaps: 0,
            order: 0,
        }
    }

    /// The document changed or its contexts went away, and the isolated world with them.
    fn forget_world(&mut self) {
        self.world = None;
        self.world_unique = None;
        self.world_epoch = self.world_epoch.wrapping_add(1);
    }
}

#[derive(Debug, Clone)]
struct ChildSession {
    parent: Option<SessionId>,
    target_id: String,
}

/// A main-world context reported before its frame was known. Events and command answers reach the page
/// on different tasks, so `executionContextCreated` can overtake the frame tree that introduces its
/// frame; puppeteer never sees that because Node dispatches both in wire order.
#[derive(Debug, Clone)]
struct EarlyContext {
    frame: FrameId,
    session: Option<SessionId>,
    id: i64,
    unique: Option<String>,
}

const EARLY_CONTEXT_MEMORY: usize = 64;

/// An [`ISOLATED_WORLD`] context Chrome reported. `Page.createIsolatedWorld` answers with a bare number,
/// and the answer can reach the page before the events Chrome sent ahead of it; the world is kept only
/// once its own event is here, so the frame and the unique id it is called by are Chrome's word for
/// that context.
#[derive(Debug, Clone)]
struct IsolatedContext {
    frame: FrameId,
    session: Option<SessionId>,
    id: i64,
    unique: Option<String>,
}

/// Follow-up work an event asks for; run outside the state lock.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Action {
    InitFrameSession(SessionId),
    Resume(SessionId),
    /// A dialog opened on this session; with `answer_dialogs`, answer it (accept or dismiss, and a
    /// prompt's text when one was set).
    Dialog(Option<SessionId>, bool, Option<String>),
}

#[derive(Debug, Default)]
pub(crate) struct State {
    main: Option<FrameId>,
    frames: HashMap<FrameId, Frame>,
    detached: VecDeque<(FrameId, String)>,
    sessions: HashMap<SessionId, ChildSession>,
    /// Frames navigated while some session's frame tree was in flight; their tree entry is stale.
    navigated_during_init: HashSet<FrameId>,
    inits_in_flight: usize,
    early_contexts: VecDeque<EarlyContext>,
    /// The latest [`ISOLATED_WORLD`] contexts reported, until destroyed; at most
    /// [`EARLY_CONTEXT_MEMORY`].
    isolated: VecDeque<IsolatedContext>,
    /// Frames added so far, for `Frame::order`.
    added: u64,
    dialogs: VecDeque<Dialog>,
    /// The answer [`Page::answer_next_dialog`] set for the next dialog: accept, and a prompt's text.
    next_dialog: Option<(bool, Option<String>)>,
    /// Frames whose isolated world a call is creating; other calls wait for it instead of sending their
    /// own.
    worlds_creating: HashSet<FrameId>,
}

impl State {
    fn children(&self, id: &FrameId) -> Vec<FrameId> {
        self.frames.iter().filter(|(_, f)| f.parent.as_ref() == Some(id)).map(|(k, _)| k.clone()).collect()
    }

    fn remove_recursively(&mut self, id: &FrameId) {
        for child in self.children(id) {
            self.remove_recursively(&child);
        }
        if let Some(f) = self.frames.remove(id) {
            if self.detached.len() == DETACHED_MEMORY {
                self.detached.pop_front();
            }
            self.detached.push_back((id.clone(), f.url));
        }
        if self.main.as_ref() == Some(id) {
            self.main = None;
        }
    }

    /// Adds a frame. If an OOPIF session for it already attached (the tree can arrive after the target
    /// does), the frame belongs to that session; a context that arrived early is picked up.
    fn create_frame(&mut self, id: FrameId, parent: Option<FrameId>, session: Option<SessionId>) {
        let session =
            self.sessions.iter().find(|(_, c)| c.target_id == id.0).map_or(session, |(k, _)| Some(k.clone()));
        let mut frame = Frame::new(parent, session);
        self.added += 1;
        frame.order = self.added;
        if let Some(i) = self.early_contexts.iter().rposition(|c| c.frame == id && c.session == frame.session)
            && let Some(c) = self.early_contexts.remove(i)
        {
            frame.context = Some(c.id);
            frame.context_unique = c.unique;
        }
        self.frames.insert(id, frame);
    }

    fn on_frame_attached(&mut self, session: Option<&SessionId>, id: FrameId, parent: FrameId) {
        if let Some(frame) = self.frames.get(&id) {
            let parent_session = self.frames.get(&parent).map(|p| p.session.clone());
            // An OOPIF coming back in-process is attached to its parent before its own target goes away.
            // Puppeteer moves the frame to whichever session reported it; moving it only to the parent's
            // session keeps an OOPIF's own frame tree (which also lists it) from resetting its context.
            if let Some(ps) = parent_session
                && frame.session != ps
                && session == ps.as_ref()
                && let Some(frame) = self.frames.get_mut(&id)
            {
                frame.session = ps;
                frame.context = None;
                frame.forget_world();
            }
            return;
        }
        self.create_frame(id, Some(parent), session.cloned());
    }

    fn on_frame_navigated(
        &mut self,
        root: Option<&SessionId>,
        payload: &Value,
        navigation_type: &str,
        from_tree: bool,
    ) {
        let Some(id) = payload.get("id").and_then(Value::as_str).map(FrameId::from) else { return };
        if self.inits_in_flight > 0 && !from_tree {
            self.navigated_during_init.insert(id.clone());
        }
        let is_main = payload.get("parentId").and_then(Value::as_str).is_none();
        // A tree snapshot may be older than frame events already applied (see `EarlyContext`), so it never
        // drops children; a real navigation does.
        if !from_tree && self.frames.contains_key(&id) {
            for child in self.children(&id) {
                self.remove_recursively(&child);
            }
        }
        if is_main {
            if !self.frames.contains_key(&id) {
                // Initial navigation, or (rarely) a new main frame id. Puppeteer creates a fresh frame
                // here too; the old main frame is dropped rather than left orphaned in the tree.
                if let Some(old) = self.main.clone() {
                    self.remove_recursively(&old);
                }
                self.create_frame(id.clone(), None, root.cloned());
            }
            self.main = Some(id.clone());
        }
        let Some(frame) = self.frames.get_mut(&id) else { return };
        if !from_tree {
            // A new document: same-document navigations come as `navigatedWithinDocument`.
            frame.forget_world();
        }
        let url = payload.get("url").and_then(Value::as_str).unwrap_or("");
        let fragment = payload.get("urlFragment").and_then(Value::as_str).unwrap_or("");
        frame.url = format!("{url}{fragment}");
        if navigation_type == "BackForwardCacheRestore" {
            frame.swaps += 1;
        }
    }

    fn apply_frame_tree(&mut self, session: Option<&SessionId>, root: Option<&SessionId>, tree: &Value) {
        let Some(frame) = tree.get("frame") else { return };
        let Some(id) = frame.get("id").and_then(Value::as_str).map(FrameId::from) else { return };
        if let Some(parent) = frame.get("parentId").and_then(Value::as_str) {
            self.on_frame_attached(session, id.clone(), FrameId::from(parent));
        }
        if !self.navigated_during_init.remove(&id) {
            self.on_frame_navigated(root, frame, "Navigation", true);
        }
        if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
            for child in children {
                self.apply_frame_tree(session, root, child);
            }
        }
    }

    fn frame_by_param(&mut self, params: &Value) -> Option<&mut Frame> {
        let id = params.get("frameId").and_then(Value::as_str)?;
        self.frames.get_mut(&FrameId::from(id))
    }

    /// Forgets the session's contexts, or only the one with id `only`. A frame whose main context goes
    /// loses its isolated world too: both belong to the document.
    fn clear_contexts(&mut self, session: Option<&SessionId>, only: Option<i64>) {
        for f in self.frames.values_mut() {
            if f.session.as_ref() != session {
                continue;
            }
            if only.is_none() || f.context == only {
                f.context = None;
                f.forget_world();
            } else if f.world == only {
                f.forget_world();
            }
        }
        self.early_contexts
            .retain(|c| c.session.as_ref() != session || (only.is_some() && Some(c.id) != only));
        let gone =
            |c: &IsolatedContext| c.session.as_ref() == session && (only.is_none() || Some(c.id) == only);
        for c in self.isolated.iter().filter(|c| gone(c)) {
            // A world that goes before its answer was applied: the call waiting on it makes another.
            if let Some(f) = self.frames.get_mut(&c.frame)
                && f.session.as_ref() == session
                && f.world.is_none()
            {
                f.forget_world();
            }
        }
        self.isolated.retain(|c| !gone(c));
    }

    fn remove_session(&mut self, sid: &SessionId) {
        if self.sessions.remove(sid).is_none() {
            return;
        }
        self.clear_contexts(Some(sid), None);
        let orphans: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, c)| c.parent.as_ref() == Some(sid))
            .map(|(k, _)| k.clone())
            .collect();
        for o in orphans {
            self.remove_session(&o);
        }
    }

    fn on_dialog(&mut self, session: Option<&SessionId>, method: &str, params: &Value) -> Option<Action> {
        if method == "Page.javascriptDialogClosed" {
            // Closed carries no id; dialogs on one page are answered one at a time, oldest first.
            let result = params.get("result").and_then(Value::as_bool).unwrap_or(false);
            if let Some(d) = self.dialogs.iter_mut().find(|d| d.accepted.is_none()) {
                d.accepted = Some(result);
            }
            return None;
        }
        let kind = params.get("type").and_then(Value::as_str).unwrap_or("").to_owned();
        let message = params.get("message").and_then(Value::as_str).unwrap_or("");
        if self.dialogs.len() == DIALOG_MEMORY {
            self.dialogs.pop_front();
        }
        let (accept, text) =
            self.next_dialog.take().unwrap_or((matches!(kind.as_str(), "beforeunload" | "alert"), None));
        self.dialogs.push_back(Dialog {
            kind,
            message: message.chars().take(DIALOG_MESSAGE_LIMIT).collect(),
            accepted: None,
        });
        Some(Action::Dialog(session.cloned(), accept, text))
    }

    /// A frame's new main-world context, or an [`ISOLATED_WORLD`] one, noted for the call that made it.
    /// Other isolated worlds (an extension's content scripts) are not ours to use.
    fn on_context_created(&mut self, session: Option<&SessionId>, params: &Value) -> Option<()> {
        let ctx = params.get("context")?;
        let id = ctx.get("id").and_then(Value::as_i64)?;
        let unique = ctx.get("uniqueId").and_then(Value::as_str).map(str::to_owned);
        let aux = ctx.get("auxData")?;
        let frame_id = FrameId::from(aux.get("frameId").and_then(Value::as_str)?);
        if aux.get("isDefault").and_then(Value::as_bool) != Some(true) {
            if ctx.get("name").and_then(Value::as_str) == Some(ISOLATED_WORLD) {
                if self.isolated.len() == EARLY_CONTEXT_MEMORY {
                    self.isolated.pop_front();
                }
                self.isolated.push_back(IsolatedContext {
                    frame: frame_id,
                    session: session.cloned(),
                    id,
                    unique,
                });
                return Some(());
            }
            return None;
        }
        let Some(f) = self.frames.get_mut(&frame_id) else {
            if self.early_contexts.len() == EARLY_CONTEXT_MEMORY {
                self.early_contexts.pop_front();
            }
            self.early_contexts.push_back(EarlyContext {
                frame: frame_id,
                session: session.cloned(),
                id,
                unique,
            });
            return None;
        };
        // A context reported by a session that no longer owns the frame is stale (swap race).
        if f.session.as_ref() == session {
            if f.context != Some(id) {
                f.forget_world();
            }
            f.context = Some(id);
            f.context_unique = unique;
        }
        Some(())
    }

    /// Applies one event that arrived on `session` (the root or a known child). Returns follow-up work.
    pub(crate) fn on_session_event(
        &mut self,
        root: Option<&SessionId>,
        session: Option<&SessionId>,
        method: &str,
        params: &Value,
    ) -> Option<Action> {
        match method {
            "Page.javascriptDialogOpening" | "Page.javascriptDialogClosed" => {
                return self.on_dialog(session, method, params);
            }
            "Page.frameAttached" => {
                let id = params.get("frameId").and_then(Value::as_str)?;
                let parent = params.get("parentFrameId").and_then(Value::as_str)?;
                self.on_frame_attached(session, FrameId::from(id), FrameId::from(parent));
            }
            "Page.frameNavigated" => {
                let kind = params.get("type").and_then(Value::as_str).unwrap_or("Navigation");
                if let Some(frame) = params.get("frame") {
                    self.on_frame_navigated(root, frame, kind, false);
                }
            }
            "Page.navigatedWithinDocument" => {
                let url = params.get("url").and_then(Value::as_str).unwrap_or("").to_owned();
                let f = self.frame_by_param(params)?;
                f.url = url;
                f.same_document_navigations += 1;
            }
            "Page.frameDetached" => {
                let id = FrameId::from(params.get("frameId").and_then(Value::as_str)?);
                match params.get("reason").and_then(Value::as_str) {
                    // The frame moves to an OOPIF target; it keeps its identity and waits for that session.
                    Some("swap") => {
                        if let Some(f) = self.frames.get_mut(&id) {
                            f.swaps += 1;
                        }
                    }
                    _ => self.remove_recursively(&id),
                }
            }
            "Page.frameStartedLoading" => self.frame_by_param(params)?.started_loading = true,
            "Page.frameStoppedLoading" => {
                let f = self.frame_by_param(params)?;
                f.lifecycle.insert("DOMContentLoaded".into());
                f.lifecycle.insert("load".into());
            }
            "Page.lifecycleEvent" => {
                let name = params.get("name").and_then(Value::as_str)?.to_owned();
                let loader = params.get("loaderId").and_then(Value::as_str).unwrap_or("").to_owned();
                let f = self.frame_by_param(params)?;
                if name == "init" {
                    f.loader_id = loader;
                    f.lifecycle.clear();
                }
                f.lifecycle.insert(name);
            }
            "Runtime.executionContextCreated" => self.on_context_created(session, params)?,
            "Runtime.executionContextDestroyed" => {
                let id = params.get("executionContextId").and_then(Value::as_i64)?;
                self.clear_contexts(session, Some(id));
            }
            "Runtime.executionContextsCleared" => self.clear_contexts(session, None),
            "Target.attachedToTarget" => {
                let sid = SessionId::from(params.get("sessionId").and_then(Value::as_str)?);
                let info = params.get("targetInfo")?;
                if info.get("type").and_then(Value::as_str) != Some("iframe") {
                    // Workers and the like: let them run, and ignore their events.
                    return Some(Action::Resume(sid));
                }
                let tid = info.get("targetId").and_then(Value::as_str).unwrap_or("").to_owned();
                if let Some(f) = self.frames.get_mut(&FrameId::from(tid.as_str())) {
                    f.session = Some(sid.clone());
                    f.context = None;
                    f.forget_world();
                }
                self.sessions.insert(sid.clone(), ChildSession { parent: session.cloned(), target_id: tid });
                return Some(Action::InitFrameSession(sid));
            }
            "Target.detachedFromTarget" => {
                let sid = SessionId::from(params.get("sessionId").and_then(Value::as_str)?);
                self.remove_session(&sid);
            }
            _ => {}
        }
        None
    }

    fn lifecycle_complete(&self, id: &FrameId) -> bool {
        let Some(f) = self.frames.get(id) else { return false };
        f.lifecycle.contains("DOMContentLoaded")
            && self.children(id).iter().all(|c| {
                self.frames.get(c).is_none_or(|cf| !cf.started_loading) || self.lifecycle_complete(c)
            })
    }

    fn info(&self, id: &FrameId) -> Option<FrameInfo> {
        self.frames.get(id).map(|f| FrameInfo {
            id: id.clone(),
            url: f.url.clone(),
            parent: f.parent.clone(),
            detached: false,
        })
    }
}

pub(crate) struct Inner {
    transport: Arc<dyn Transport>,
    root: Option<SessionId>,
    opts: PageOptions,
    state: Mutex<State>,
    changed: watch::Sender<u64>,
    closed: watch::Sender<Option<String>>,
    keyboard: Mutex<Keyboard>,
    mouse: Mutex<Mouse>,
    /// The emulated viewport [`Page::set_viewport`] last set, `None` while none is.
    viewport: Mutex<Option<(u32, u32)>>,
    /// Test builds only: how many click checks fell back to the box rule, by reason
    /// (`Page::strict_fallbacks`).
    #[cfg(feature = "test-seams")]
    pub(crate) strict_fallbacks: [std::sync::atomic::AtomicUsize; crate::dom::Unsettled::ALL.len()],
}

impl Inner {
    fn bump(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    fn closed_reason(&self) -> Option<String> {
        self.closed.borrow().clone()
    }

    pub(crate) fn mark_closed(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.closed.send_if_modified(|c| {
            if c.is_some() {
                return false;
            }
            *c = Some(reason);
            true
        });
        self.bump();
    }

    /// Sends one command with the page's timeout, failing fast once the page closes.
    pub(crate) async fn send(
        &self,
        session: Option<&SessionId>,
        method: &str,
        params: Value,
    ) -> Result<Value, CdpError> {
        let mut closed = self.closed.subscribe();
        if let Some(r) = closed.borrow_and_update().clone() {
            return Err(CdpError::Closed(r));
        }
        let call = self.transport.send(session, method, params);
        tokio::select! {
            // Biased so the transport is polled first and queues the request in call order.
            biased;
            r = call => r,
            r = closed.wait_for(Option::is_some) => {
                Err(CdpError::Closed(r.ok().and_then(|v| v.clone()).unwrap_or_else(|| "Target closed".into())))
            }
            () = tokio::time::sleep(self.opts.protocol_timeout) => Err(CdpError::Timeout { method: method.to_owned() }),
        }
    }

    fn on_event(self: &Arc<Self>, session: Option<&SessionId>, method: &str, params: &Value) {
        let root = self.root.as_ref();
        let action = {
            let mut st = self.state.lock();
            if session == root {
                if method == "Inspector.detached" {
                    let reason = params.get("reason").and_then(Value::as_str).unwrap_or("Target closed");
                    drop(st);
                    self.mark_closed(reason.to_owned());
                    return;
                }
                st.on_session_event(root, root, method, params)
            } else if let Some(sid) = session.filter(|s| st.sessions.contains_key(*s)) {
                st.on_session_event(root, Some(sid), method, params)
            } else if session.is_none() {
                // Browser-level event on a shared browser connection: only our own target's end matters.
                let ours = match method {
                    "Target.detachedFromTarget" => {
                        params.get("sessionId").and_then(Value::as_str) == root.map(SessionId::as_str)
                    }
                    "Target.targetDestroyed" => {
                        params.get("targetId").and_then(Value::as_str) == self.opts.target_id.as_deref()
                    }
                    _ => false,
                };
                if ours {
                    drop(st);
                    self.mark_closed("Target closed");
                }
                return;
            } else {
                return;
            }
        };
        self.bump();
        match action {
            Some(Action::InitFrameSession(sid)) => {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.init_session(Some(sid.clone())).await {
                        tracing::debug!(session = %sid, error = %e, "OOPIF session init failed");
                    }
                });
            }
            Some(Action::Resume(sid)) => {
                let me = self.clone();
                tokio::spawn(async move {
                    let _ = me.send(Some(&sid), "Runtime.runIfWaitingForDebugger", json!({})).await;
                });
            }
            Some(Action::Dialog(sid, accept, text)) if self.opts.answer_dialogs => {
                let me = self.clone();
                let mut answer = json!({ "accept": accept });
                if let Some(text) = text {
                    answer["promptText"] = json!(text);
                }
                tokio::spawn(async move {
                    let _ = me.send(sid.as_ref(), "Page.handleJavaScriptDialog", answer).await;
                });
            }
            Some(Action::Dialog(..)) | None => {}
        }
    }

    /// Puppeteer's `FrameManager.initialize` plus `TargetManager`'s auto-attach for one session. All
    /// commands are queued together, in this order, so the target is resumed only after its domains are
    /// enabled. Network and Audits are never enabled: the relay must not see request traffic, and the
    /// engine runs with `networkEnabled: false, issuesEnabled: false`.
    async fn init_session(&self, session: Option<SessionId>) -> Result<(), CdpError> {
        let s = session.as_ref();
        self.state.lock().inits_in_flight += 1;
        let auto_attach = json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true});
        // The tree is applied the moment it arrives, before the contexts `Runtime.enable` reports.
        let tree = async {
            let tree = self.send(s, "Page.getFrameTree", json!({})).await?;
            if let Some(t) = tree.get("frameTree") {
                self.state.lock().apply_frame_tree(s, self.root.as_ref(), t);
                self.bump();
            }
            Ok(())
        };
        // Before the resume, so a new frame's own scripts find it in place. A page that refuses it still
        // works, so the attach goes on.
        let popups = async {
            if !self.opts.popups_as_tabs {
                return;
            }
            let script = json!({"source": POPUPS_AS_TABS, "runImmediately": true});
            if let Err(e) = self.send(s, "Page.addScriptToEvaluateOnNewDocument", script).await {
                tracing::debug!(error = %e, "popups-as-tabs script refused");
            }
        };
        let passkeys = async {
            if !self.opts.watch_passkeys {
                return;
            }
            let script = json!({"source": PASSKEY_WATCH, "runImmediately": true});
            if let Err(e) = self.send(s, "Page.addScriptToEvaluateOnNewDocument", script).await {
                tracing::debug!(error = %e, "passkey watch script refused");
            }
        };
        let (enabled, ((), ()), resumed) = futures_util::future::join3(
            futures_util::future::try_join5(
                self.send(s, "Page.enable", json!({})),
                tree,
                self.send(s, "Page.setLifecycleEventsEnabled", json!({"enabled": true})),
                self.send(s, "Runtime.enable", json!({})),
                self.send(s, "Target.setAutoAttach", auto_attach),
            ),
            futures_util::future::join(popups, passkeys),
            self.send(s, "Runtime.runIfWaitingForDebugger", json!({})),
        )
        .await;
        {
            let mut st = self.state.lock();
            st.inits_in_flight -= 1;
            if st.inits_in_flight == 0 {
                st.navigated_during_init.clear();
            }
        }
        enabled?;
        // The root target is normally not paused; a failed resume there is not worth failing attach for.
        if session != self.root {
            resumed?;
        }
        Ok(())
    }

    /// Waits for the frame's main-world context, as puppeteer's `IsolatedWorld` does.
    pub(crate) async fn context_for(&self, frame: &FrameId) -> Result<ContextRef, CdpError> {
        let mut changed = self.changed.subscribe();
        let ms = millis(self.opts.default_timeout);
        let wait = async {
            let mut first = true;
            loop {
                changed.borrow_and_update();
                if let Some(r) = self.closed_reason() {
                    return Err(CdpError::Closed(r));
                }
                {
                    let st = self.state.lock();
                    match st.frames.get(frame) {
                        Some(f) => {
                            if let Some(id) = f.context {
                                return Ok(ContextRef {
                                    session: f.session.clone(),
                                    id,
                                    frame: frame.clone(),
                                    unique: f.context_unique.clone(),
                                });
                            }
                        }
                        None if first => {
                            return Err(CdpError::DetachedFrame(format!(
                                "Attempted to use detached Frame '{frame}'."
                            )));
                        }
                        // Puppeteer: the world was disposed while waiting.
                        None => return Err(CdpError::ContextDestroyed),
                    }
                }
                first = false;
                if changed.changed().await.is_err() {
                    return Err(CdpError::Closed("Target closed".into()));
                }
            }
        };
        match tokio::time::timeout(self.opts.default_timeout, wait).await {
            Ok(r) => r,
            Err(_) => Err(CdpError::WaitTimeout { ms, last: Some("execution context".into()) }),
        }
    }

    /// The frame's [`ISOLATED_WORLD`] context, made on first use for each document and kept until the
    /// document or its contexts go: about one `Page.createIsolatedWorld` per frame per document. Waits
    /// for the main world first, so the world is made in the document that is there, not one on its way
    /// out. Never falls back to the main world.
    pub(crate) async fn world_for(&self, frame: &FrameId) -> Result<ContextRef, CdpError> {
        let mut changed = self.changed.subscribe();
        let ms = millis(self.opts.default_timeout);
        let work = async {
            loop {
                changed.borrow_and_update();
                let main = self.context_for(frame).await?;
                let epoch = {
                    let mut st = self.state.lock();
                    let Some(f) = st.frames.get(frame) else { return Err(CdpError::ContextDestroyed) };
                    if f.context != Some(main.id) || f.session != main.session {
                        // The document changed since `context_for` looked; look again.
                        continue;
                    }
                    if let Some(id) = f.world {
                        return Ok(ContextRef { id, unique: f.world_unique.clone(), ..main });
                    }
                    let epoch = f.world_epoch;
                    st.worlds_creating.insert(frame.clone()).then_some(epoch)
                };
                let Some(epoch) = epoch else {
                    // Another call is making it; its guard wakes this one however that call ends.
                    if changed.changed().await.is_err() {
                        return Err(CdpError::Closed("Target closed".into()));
                    }
                    continue;
                };
                let _creating = CreatingWorld { inner: self, frame };
                let params = json!({"frameId": frame, "worldName": ISOLATED_WORLD});
                let made = self.send(main.session.as_ref(), "Page.createIsolatedWorld", params).await?;
                let id = made.get("executionContextId").and_then(Value::as_i64).ok_or_else(|| {
                    CdpError::Other("Page.createIsolatedWorld returned no execution context".into())
                })?;
                // Events and answers arrive on different tasks, so the answer can come before the world's
                // own `executionContextCreated`, and before a navigation Chrome reported ahead of both.
                // The world is kept once its event is here and nothing has replaced the document since
                // the request; else the next turn makes another.
                let Some(unique) = self.keep_world(frame, &main, epoch, id, &mut changed).await? else {
                    continue;
                };
                return Ok(ContextRef { id, unique, ..main });
            }
        };
        match tokio::time::timeout(self.opts.default_timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(CdpError::WaitTimeout { ms, last: Some("isolated world".into()) }),
        }
    }

    /// Waits for the `executionContextCreated` of world `id`, made in `main`'s document at `epoch`, and
    /// keeps the world as the frame's: `Some(unique id)` once the event is here for this frame while the
    /// document is still that one; `None` if the document changed first, or the event names another
    /// frame. The check and the write share one lock, so no navigation applied between them can leave
    /// the old document's world cached (review R2).
    async fn keep_world(
        &self,
        frame: &FrameId,
        main: &ContextRef,
        epoch: u64,
        id: i64,
        changed: &mut watch::Receiver<u64>,
    ) -> Result<Option<Option<String>>, CdpError> {
        loop {
            changed.borrow_and_update();
            if let Some(r) = self.closed_reason() {
                return Err(CdpError::Closed(r));
            }
            {
                let mut st = self.state.lock();
                let st = &mut *st;
                let Some(f) = st.frames.get_mut(frame) else { return Err(CdpError::ContextDestroyed) };
                if f.world_epoch != epoch || f.context != Some(main.id) || f.session != main.session {
                    return Ok(None);
                }
                if let Some(c) = st.isolated.iter().rev().find(|c| c.session == main.session && c.id == id) {
                    if c.frame != *frame {
                        return Ok(None);
                    }
                    f.world = Some(id);
                    f.world_unique.clone_from(&c.unique);
                    return Ok(Some(c.unique.clone()));
                }
            }
            if changed.changed().await.is_err() {
                return Err(CdpError::Closed("Target closed".into()));
            }
        }
    }

    /// A call found `ctx` gone: if it was a frame's isolated world, the next call makes a new one rather
    /// than wait for an event that may already have been applied.
    pub(crate) fn forget_context(&self, ctx: &ContextRef) {
        let mut st = self.state.lock();
        if let Some(f) = st.frames.get_mut(&ctx.frame)
            && f.session == ctx.session
            && f.world == Some(ctx.id)
        {
            f.forget_world();
        }
    }

    fn main_frame(&self) -> Result<FrameId, CdpError> {
        if let Some(r) = self.closed_reason() {
            return Err(CdpError::Closed(r));
        }
        self.state.lock().main.clone().ok_or_else(|| CdpError::Other("Page has no main frame".into()))
    }

    pub(crate) fn session_of(&self, frame: &FrameId) -> Result<Option<SessionId>, CdpError> {
        self.state
            .lock()
            .frames
            .get(frame)
            .map(|f| f.session.clone())
            .ok_or_else(|| CdpError::DetachedFrame(format!("Attempted to use detached Frame '{frame}'.")))
    }

    fn parent_of(&self, frame: &FrameId) -> Option<FrameId> {
        self.state.lock().frames.get(frame).and_then(|f| f.parent.clone())
    }

    pub(crate) fn children_of(&self, frame: &FrameId) -> Vec<FrameId> {
        self.state.lock().children(frame)
    }
}

/// Held by the one call making a frame's isolated world. Dropping it, on success, failure or
/// cancellation, lets the calls waiting on that frame look again.
struct CreatingWorld<'a> {
    inner: &'a Inner,
    frame: &'a FrameId,
}

impl Drop for CreatingWorld<'_> {
    fn drop(&mut self) {
        self.inner.state.lock().worlds_creating.remove(self.frame);
        self.inner.bump();
    }
}

async fn run_events(weak: Weak<Inner>, mut events: mpsc::UnboundedReceiver<TransportEvent>) {
    while let Some(ev) = events.recv().await {
        let Some(inner) = weak.upgrade() else { return };
        match ev {
            TransportEvent::Event { session, method, params } => {
                inner.on_event(session.as_ref(), &method, &params);
            }
            TransportEvent::Closed(reason) => {
                inner.mark_closed(reason);
                return;
            }
        }
    }
    if let Some(inner) = weak.upgrade() {
        inner.mark_closed("Transport closed");
    }
}

pub(crate) fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// One page over any [`Transport`]. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Page {
    pub(crate) inner: Arc<Inner>,
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page")
            .field("root", &self.inner.root)
            .field("target_id", &self.inner.opts.target_id)
            .field("closed", &self.inner.closed_reason())
            .finish_non_exhaustive()
    }
}

impl Page {
    /// Attaches to the page reachable at `root` over `transport`. `events` must carry every event of the
    /// root session and its child sessions (and, on a shared browser connection, browser-level `Target`
    /// events).
    pub async fn attach(
        transport: Arc<dyn Transport>,
        root: Option<SessionId>,
        events: mpsc::UnboundedReceiver<TransportEvent>,
        options: PageOptions,
    ) -> Result<Page, CdpError> {
        let inner = Arc::new(Inner {
            transport,
            root: root.clone(),
            opts: options,
            state: Mutex::new(State::default()),
            changed: watch::Sender::new(0),
            closed: watch::Sender::new(None),
            keyboard: Mutex::new(Keyboard::default()),
            mouse: Mutex::new(Mouse::default()),
            viewport: Mutex::new(None),
            #[cfg(feature = "test-seams")]
            strict_fallbacks: Default::default(),
        });
        tokio::spawn(run_events(Arc::downgrade(&inner), events));
        inner.init_session(root).await?;
        Ok(Page { inner })
    }

    /// The root session (`None` for the relay's tab).
    pub fn session(&self) -> Option<&SessionId> {
        self.inner.root.as_ref()
    }

    pub fn target_id(&self) -> Option<&str> {
        self.inner.opts.target_id.as_deref()
    }

    pub fn options(&self) -> &PageOptions {
        &self.inner.opts
    }

    /// Sets the answer for the next dialog the page opens, once: accept or dismiss, and the text a
    /// `prompt()` gets when accepted. The dialogs after it get the usual answers again (`answer_dialogs`),
    /// and so does that one on a page that does not answer its own dialogs.
    pub fn answer_next_dialog(&self, accept: bool, prompt_text: Option<String>) {
        self.inner.state.lock().next_dialog = Some((accept, prompt_text));
    }

    /// The dialogs opened since the last call, oldest first, and forgets the answered ones. One still open
    /// stays, so the next call reports its answer.
    pub fn take_dialogs(&self) -> Vec<Dialog> {
        let mut st = self.inner.state.lock();
        let all: Vec<Dialog> = st.dialogs.iter().cloned().collect();
        st.dialogs.retain(|d| d.accepted.is_none());
        all
    }

    /// The main frame's URL (empty before the first navigation is known).
    pub fn url(&self) -> String {
        let st = self.inner.state.lock();
        st.main.as_ref().and_then(|m| st.frames.get(m)).map(|f| f.url.clone()).unwrap_or_default()
    }

    pub fn main_frame(&self) -> Result<FrameId, CdpError> {
        self.inner.main_frame()
    }

    /// Attached frames in the main frame's tree: the main frame first, then the rest in the order they
    /// were added, as puppeteer's `page.frames()` lists them (frame ids are random, so never by id). The
    /// snapshot reads the first 20 website frames of this list.
    pub fn frames(&self) -> Vec<FrameInfo> {
        let st = self.inner.state.lock();
        let mut tree = Vec::with_capacity(st.frames.len());
        let mut queue: VecDeque<FrameId> = st.main.iter().cloned().collect();
        while let Some(id) = queue.pop_front() {
            queue.extend(st.children(&id));
            tree.push(id);
        }
        if let Some(rest) = tree.get_mut(1..) {
            rest.sort_by_key(|id| st.frames.get(id).map_or(u64::MAX, |f| f.order));
        }
        tree.iter().filter_map(|id| st.info(id)).collect()
    }

    /// One frame, including a recently detached one (`detached: true`).
    pub fn frame_info(&self, id: &FrameId) -> Option<FrameInfo> {
        let st = self.inner.state.lock();
        st.info(id).or_else(|| {
            st.detached.iter().rev().find(|(d, _)| d == id).map(|(d, url)| FrameInfo {
                id: d.clone(),
                url: url.clone(),
                parent: None,
                detached: true,
            })
        })
    }

    /// Runs `js` (a function source) in the frame's isolated world ([`ISOLATED_WORLD`]) and returns its
    /// result by value. The world sees the page's DOM but none of its scripts' globals or prototype
    /// changes, so a page cannot change what this reads or does (SR-34). Waits for the frame's context if
    /// a navigation is between documents.
    pub async fn evaluate(&self, frame: &FrameId, js: &str, args: Vec<Arg<'_>>) -> Result<Value, CdpError> {
        let ctx = self.inner.world_for(frame).await?;
        let remote = call_function(&self.inner, &ctx, js, &args, true).await?;
        Ok(value_from_remote(&remote))
    }

    /// Like [`Page::evaluate`], but returns a handle to the result (in the isolated world).
    pub async fn evaluate_handle(
        &self,
        frame: &FrameId,
        js: &str,
        args: Vec<Arg<'_>>,
    ) -> Result<JsHandle, CdpError> {
        let ctx = self.inner.world_for(frame).await?;
        let remote = call_function(&self.inner, &ctx, js, &args, false).await?;
        Ok(JsHandle::new(self.inner.clone(), ctx, remote))
    }

    /// Like [`Page::evaluate`], but in the frame's main world, where the page's own scripts run and can
    /// change every global and prototype the function uses. Only for a documented exception (reading a
    /// page's own state in a test, or a write the page's framework must see); never for a read the
    /// engine trusts.
    pub async fn evaluate_main(
        &self,
        frame: &FrameId,
        js: &str,
        args: Vec<Arg<'_>>,
    ) -> Result<Value, CdpError> {
        let ctx = self.inner.context_for(frame).await?;
        let remote = call_function(&self.inner, &ctx, js, &args, true).await?;
        Ok(value_from_remote(&remote))
    }

    /// The frame's passkey requests so far ([`PASSKEY_WATCH`]), or `None` where the script is not
    /// running: an owner's tab, a page opened without [`PageOptions::watch_passkeys`], or a frame with
    /// no `navigator.credentials`. Read in the main world, a documented exception: a page that forges
    /// the numbers only gets its tab shown to the owner (THREAT-MODEL SR-75).
    pub async fn passkey_asks(&self, frame: &FrameId) -> Result<Option<PasskeyAsks>, CdpError> {
        let v = self.evaluate_main(frame, PASSKEY_READ, vec![]).await?;
        let n = |k: &str| v.get(k).and_then(Value::as_u64);
        Ok(match (n("asked"), n("pending"), n("answered")) {
            (Some(asked), Some(pending), Some(answered)) => Some(PasskeyAsks { asked, pending, answered }),
            _ => None,
        })
    }

    /// The same DOM node as `handle`, as a handle in its frame's main world: for a write the page's own
    /// framework has to see (React's value tracker lives on the main world's element wrapper). Costs
    /// `DOM.describeNode` and `DOM.resolveNode`. The caller disposes the result.
    pub async fn main_world_handle(&self, handle: &JsHandle) -> Result<JsHandle, CdpError> {
        let Some(object) = handle.object_id() else {
            return Err(CdpError::Other("main_world_handle needs a node handle".into()));
        };
        let from = handle.context();
        let node =
            self.inner.send(from.session.as_ref(), "DOM.describeNode", json!({"objectId": object})).await?;
        let backend = node
            .pointer("/node/backendNodeId")
            .cloned()
            .ok_or_else(|| CdpError::Other("DOM.describeNode returned no node".into()))?;
        let ctx = self.inner.context_for(&from.frame).await?;
        if ctx.session != from.session {
            // The frame moved to another process since the handle was made; its node ids are gone.
            return Err(CdpError::ContextDestroyed);
        }
        let resolved = self
            .inner
            .send(
                ctx.session.as_ref(),
                "DOM.resolveNode",
                json!({"backendNodeId": backend, "executionContextId": ctx.id}),
            )
            .await?;
        let object = resolved
            .get("object")
            .cloned()
            .ok_or_else(|| CdpError::Other("DOM.resolveNode returned no object".into()))?;
        Ok(JsHandle::new(self.inner.clone(), ctx, object))
    }

    /// Sends a raw command on the root session, with the page's timeout and close handling.
    pub async fn send(&self, method: &str, params: Value) -> Result<Value, CdpError> {
        self.inner.send(self.inner.root.as_ref(), method, params).await
    }

    /// A JPEG of the viewport, base64-encoded.
    pub async fn screenshot_jpeg(&self, quality: u8) -> Result<String, CdpError> {
        if quality > 100 {
            return Err(CdpError::Other(format!(
                "Expected 'quality' ({quality}) to be between 0 and 100, inclusive."
            )));
        }
        let res = self
            .send(
                "Page.captureScreenshot",
                json!({"format": "jpeg", "quality": quality, "optimizeForSpeed": false,
                       "fromSurface": true, "captureBeyondViewport": false}),
            )
            .await?;
        screenshot_data(res)
    }

    /// The visual viewport in CSS pixels: `x`/`y` its scroll offset in the document, then its size.
    /// `Page.getLayoutMetrics` first; when that fails, the page's own `visualViewport`, which gives the
    /// same numbers. An extension older than the one that allows the method refuses it, and the owner
    /// reloads the extension only at the PC: without the fallback, every frame of a phone's live view of
    /// a check failed until then (2026-11-06, the owner away from the PC with a check waiting).
    pub async fn visual_viewport(&self) -> Result<BoundingBox, CdpError> {
        let m = match self.send("Page.getLayoutMetrics", json!({})).await {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(error = %e, "Page.getLayoutMetrics failed; reading visualViewport instead");
                return self.page_visual_viewport().await;
            }
        };
        let v = m.get("cssVisualViewport").ok_or_else(|| CdpError::Other("no cssVisualViewport".into()))?;
        let n = |k: &str| v.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        Ok(BoundingBox { x: n("pageX"), y: n("pageY"), width: n("clientWidth"), height: n("clientHeight") })
    }

    /// [`Page::visual_viewport`] as the page's own `visualViewport` reports it: its fallback, public so a
    /// test can hold the two to the same numbers.
    pub async fn page_visual_viewport(&self) -> Result<BoundingBox, CdpError> {
        let v = self.evaluate(&self.main_frame()?, VISUAL_VIEWPORT, vec![]).await?;
        let n = |k: &str| v.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        Ok(BoundingBox { x: n("x"), y: n("y"), width: n("width"), height: n("height") })
    }

    /// A JPEG of the `clip` rectangle, scaled by `scale`, base64-encoded. `clip` is in viewport
    /// coordinates, as [`Page::frame_element_box`] and mouse events are; CDP's clip is in document
    /// coordinates, so the scroll offset is added here (as puppeteer's element screenshot does). The live
    /// viewer zooms a phone's view onto a verification check this way.
    pub async fn screenshot_jpeg_clip(
        &self,
        quality: u8,
        clip: BoundingBox,
        scale: f64,
    ) -> Result<String, CdpError> {
        if quality > 100 {
            return Err(CdpError::Other(format!(
                "Expected 'quality' ({quality}) to be between 0 and 100, inclusive."
            )));
        }
        let at = self.visual_viewport().await?;
        let res = self
            .send(
                "Page.captureScreenshot",
                json!({"format": "jpeg", "quality": quality, "optimizeForSpeed": false,
                       "fromSurface": true, "captureBeyondViewport": false,
                       "clip": {"x": clip.x + at.x, "y": clip.y + at.y, "width": clip.width,
                                "height": clip.height, "scale": scale}}),
            )
            .await?;
        screenshot_data(res)
    }

    /// The viewport [`Page::set_viewport`] emulates now, `None` while the page has its window's own.
    #[must_use]
    pub fn viewport(&self) -> Option<(u32, u32)> {
        *self.inner.viewport.lock()
    }

    /// A picture of the page, base64-encoded: PNG with `png`, else JPEG at `quality`. `clip`, in document
    /// coordinates, takes only that rectangle, painted beyond the viewport when it reaches past it (a
    /// full page, or an element taller than the view); without it, the viewport.
    pub async fn capture(
        &self,
        png: bool,
        quality: u8,
        clip: Option<BoundingBox>,
    ) -> Result<String, CdpError> {
        if quality > 100 {
            return Err(CdpError::Other(format!(
                "Expected 'quality' ({quality}) to be between 0 and 100, inclusive."
            )));
        }
        let mut params = json!({"format": if png { "png" } else { "jpeg" }, "optimizeForSpeed": false,
                                "fromSurface": true, "captureBeyondViewport": clip.is_some()});
        if !png {
            params["quality"] = json!(quality);
        }
        if let Some(c) = clip {
            params["clip"] = json!({"x": c.x, "y": c.y, "width": c.width, "height": c.height, "scale": 1});
        }
        screenshot_data(self.send("Page.captureScreenshot", params).await?)
    }

    /// The whole document's size in CSS pixels, as a clip from its top left for [`Page::capture`].
    /// `Page.getLayoutMetrics` first, else the document's own scroll size (an extension older than the
    /// one that allows the method).
    pub async fn full_page(&self) -> Result<BoundingBox, CdpError> {
        let size = match self.send("Page.getLayoutMetrics", json!({})).await {
            Ok(m) => m.get("cssContentSize").map(|c| {
                let n = |k: &str| c.get(k).and_then(Value::as_f64).unwrap_or(0.0);
                (n("width"), n("height"))
            }),
            Err(e) => {
                tracing::debug!(error = %e, "Page.getLayoutMetrics failed; reading the scroll size instead");
                None
            }
        };
        let (width, height) = if let Some(s) = size {
            s
        } else {
            let v = self.evaluate(&self.main_frame()?, DOCUMENT_SIZE, vec![]).await?;
            let n = |k: &str| v.get(k).and_then(Value::as_f64).unwrap_or(0.0);
            (n("width"), n("height"))
        };
        Ok(BoundingBox { x: 0.0, y: 0.0, width: width.ceil(), height: height.ceil() })
    }

    /// Emulates a `width x height` viewport (scale 1, not mobile, no touch), or clears the emulation.
    pub async fn set_viewport(&self, size: Option<(u32, u32)>) -> Result<(), CdpError> {
        let root = self.inner.root.as_ref();
        let touch_off = json!({"enabled": false});
        match size {
            None => {
                if self.inner.viewport.lock().take().is_none() {
                    return Ok(());
                }
                // Puppeteer only logs failures to clear.
                let (a, b) = futures_util::future::join(
                    self.inner.send(root, "Emulation.clearDeviceMetricsOverride", json!({})),
                    self.inner.send(root, "Emulation.setTouchEmulationEnabled", touch_off),
                )
                .await;
                for e in [a.err(), b.err()].into_iter().flatten() {
                    tracing::debug!(error = %e, "clearing viewport emulation failed");
                }
                Ok(())
            }
            Some((width, height)) => {
                *self.inner.viewport.lock() = Some((width, height));
                let metrics = json!({"mobile": false, "width": width, "height": height, "deviceScaleFactor": 1,
                                     "screenOrientation": {"angle": 0, "type": "portraitPrimary"}});
                let (a, b) = futures_util::future::join(
                    self.inner.send(root, "Emulation.setDeviceMetricsOverride", metrics),
                    self.inner.send(root, "Emulation.setTouchEmulationEnabled", touch_off),
                )
                .await;
                match a {
                    Err(CdpError::Protocol { message, .. })
                        if message.contains("Target does not support metrics override") => {}
                    other => {
                        other?;
                    }
                }
                b.map(drop)
            }
        }
    }

    /// Makes the page behave as focused even when its window is not (puppeteer's `emulateFocusedPage`).
    pub async fn emulate_focus(&self, enabled: bool) -> Result<(), CdpError> {
        self.send("Emulation.setFocusEmulationEnabled", json!({"enabled": enabled})).await.map(drop)
    }

    /// Navigates the main frame and waits for `DOMContentLoaded` of the new document, or for the
    /// same-document navigation. A zero `timeout` waits forever.
    pub async fn goto(&self, url: &str, timeout: Duration) -> Result<(), CdpError> {
        let inner = &self.inner;
        let mut changed = inner.changed.subscribe();
        let frame = inner.main_frame()?;
        let (session, initial_same_doc, initial_swaps) = {
            let st = inner.state.lock();
            let f = st.frames.get(&frame).ok_or_else(|| CdpError::Other("Page has no main frame".into()))?;
            (f.session.clone(), f.same_document_navigations, f.swaps)
        };
        let work = async {
            let res =
                inner.send(session.as_ref(), "Page.navigate", json!({"url": url, "frameId": frame})).await?;
            let error_text = res.get("errorText").and_then(Value::as_str).unwrap_or("");
            // Puppeteer: an HTTP error status is a loaded page, not a failed navigation.
            if error_text == "net::ERR_HTTP_RESPONSE_CODE_FAILURE" {
                return Ok(());
            }
            // Wait for this navigation's own loader: "the loader changed" also matches a late commit
            // left by an earlier navigation, such as the error page of one that timed out.
            let new_loader = res.get("loaderId").and_then(Value::as_str).map(str::to_owned);
            if !error_text.is_empty() {
                return Err(CdpError::Navigation(format!("{error_text} at {url}")));
            }
            loop {
                changed.borrow_and_update();
                if let Some(r) = inner.closed_reason() {
                    return Err(CdpError::Closed(r));
                }
                {
                    let st = inner.state.lock();
                    let Some(f) = st.frames.get(&frame) else {
                        return Err(CdpError::Navigation("Navigating frame was detached".into()));
                    };
                    if st.lifecycle_complete(&frame) {
                        if let Some(loader) = &new_loader {
                            if f.swaps != initial_swaps || f.loader_id == *loader {
                                return Ok(());
                            }
                        } else if f.same_document_navigations != initial_same_doc {
                            return Ok(());
                        }
                    }
                }
                if changed.changed().await.is_err() {
                    return Err(CdpError::Closed("Target closed".into()));
                }
            }
        };
        if timeout.is_zero() {
            return work.await;
        }
        match tokio::time::timeout(timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(CdpError::NavigationTimeout(millis(timeout))),
        }
    }

    /// The tab's history (`Page.getNavigationHistory`): its entries, oldest first, and which is current.
    pub async fn history(&self) -> Result<History, CdpError> {
        let h = self.send("Page.getNavigationHistory", json!({})).await?;
        let current = h.get("currentIndex").and_then(Value::as_u64).and_then(|i| usize::try_from(i).ok());
        let entries = h
            .get("entries")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some(HistoryEntry {
                            id: e.get("id")?.as_i64()?,
                            url: e.get("url").and_then(Value::as_str).unwrap_or("").to_owned(),
                            transition: e
                                .get("transitionType")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(History { current: current.unwrap_or(0), entries })
    }

    /// Goes to history entry `id` ([`Page::history`]), as Back and Forward do, and waits as
    /// [`Page::goto`] does: for the document it loads, a page kept in the back-forward cache coming back,
    /// or a move within the document.
    pub async fn go_to_history_entry(&self, id: i64, timeout: Duration) -> Result<(), CdpError> {
        let session = self.main_session()?;
        let sent = self.inner.send(session.as_ref(), "Page.navigateToHistoryEntry", json!({"entryId": id}));
        self.navigated_by(sent, timeout).await
    }

    /// Loads the page anew (`Page.reload`) and waits for its new document, as [`Page::goto`] does.
    pub async fn reload(&self, timeout: Duration) -> Result<(), CdpError> {
        let session = self.main_session()?;
        let sent = self.inner.send(session.as_ref(), "Page.reload", json!({}));
        self.navigated_by(sent, timeout).await
    }

    fn main_session(&self) -> Result<Option<SessionId>, CdpError> {
        let frame = self.inner.main_frame()?;
        let st = self.inner.state.lock();
        let f = st.frames.get(&frame).ok_or_else(|| CdpError::Other("Page has no main frame".into()))?;
        Ok(f.session.clone())
    }

    /// Sends `sent`, a command that navigates the main frame, then waits until the frame has a new
    /// document that has loaded (its loader changed and its lifecycle is complete), came back from the
    /// back-forward cache, or moved within its document. A zero `timeout` waits forever.
    async fn navigated_by(
        &self,
        sent: impl Future<Output = Result<Value, CdpError>>,
        timeout: Duration,
    ) -> Result<(), CdpError> {
        let inner = &self.inner;
        let mut changed = inner.changed.subscribe();
        let frame = inner.main_frame()?;
        let (loader, same_doc, swaps) = {
            let st = inner.state.lock();
            let f = st.frames.get(&frame).ok_or_else(|| CdpError::Other("Page has no main frame".into()))?;
            (f.loader_id.clone(), f.same_document_navigations, f.swaps)
        };
        let work = async {
            let res = sent.await?;
            if let Some(error) = res.get("errorText").and_then(Value::as_str).filter(|e| !e.is_empty()) {
                return Err(CdpError::Navigation(error.to_owned()));
            }
            loop {
                changed.borrow_and_update();
                if let Some(r) = inner.closed_reason() {
                    return Err(CdpError::Closed(r));
                }
                {
                    let st = inner.state.lock();
                    let Some(f) = st.frames.get(&frame) else {
                        return Err(CdpError::Navigation("Navigating frame was detached".into()));
                    };
                    let moved =
                        f.loader_id != loader || f.swaps != swaps || f.same_document_navigations != same_doc;
                    if moved && st.lifecycle_complete(&frame) {
                        return Ok(());
                    }
                }
                if changed.changed().await.is_err() {
                    return Err(CdpError::Closed("Target closed".into()));
                }
            }
        };
        if timeout.is_zero() {
            return work.await;
        }
        match tokio::time::timeout(timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(CdpError::NavigationTimeout(millis(timeout))),
        }
    }

    /// Sends the main frame to `about:blank` by script in the page (phantab's isolated world, as every
    /// [`Page::evaluate`]) and waits for that document. A navigation the renderer starts stays in its
    /// process, where one the browser starts (`goto`) can move it to a new one, which then the next
    /// navigation pays for. Fails, leaving the page where it is, when it is not on `about:blank` within
    /// `timeout` (its script is busy, or it kept itself with a "Leave site?").
    pub async fn blank_from_page(&self, timeout: Duration) -> Result<(), CdpError> {
        let inner = &self.inner;
        let mut changed = inner.changed.subscribe();
        let frame = inner.main_frame()?;
        let initial_loader = inner.state.lock().frames.get(&frame).map(|f| f.loader_id.clone());
        let work = async {
            // The document goes away under the call, so its own answer may be an error.
            let _ = self.evaluate(&frame, "() => { location.replace('about:blank'); }", vec![]).await;
            loop {
                changed.borrow_and_update();
                if let Some(r) = inner.closed_reason() {
                    return Err(CdpError::Closed(r));
                }
                {
                    let st = inner.state.lock();
                    let Some(f) = st.frames.get(&frame) else {
                        return Err(CdpError::Navigation("Navigating frame was detached".into()));
                    };
                    if f.url == "about:blank"
                        && Some(&f.loader_id) != initial_loader.as_ref()
                        && st.lifecycle_complete(&frame)
                    {
                        return Ok(());
                    }
                }
                if changed.changed().await.is_err() {
                    return Err(CdpError::Closed("Target closed".into()));
                }
            }
        };
        match tokio::time::timeout(timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(CdpError::NavigationTimeout(millis(timeout))),
        }
    }

    /// Tells when the page closed: `None` while open, then the reason.
    pub fn closed(&self) -> watch::Receiver<Option<String>> {
        self.inner.closed.subscribe()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed_reason().is_some()
    }

    /// Closes the page and waits (up to the protocol timeout) for it to report closed.
    pub async fn close(&self) -> Result<(), CdpError> {
        if self.is_closed() {
            return Ok(());
        }
        let mut closed = self.closed();
        match &self.inner.opts.target_id {
            Some(tid) => self.inner.send(None, "Target.closeTarget", json!({"targetId": tid})).await?,
            None => self.send("Page.close", json!({})).await?,
        };
        let _ =
            tokio::time::timeout(self.inner.opts.protocol_timeout, closed.wait_for(Option::is_some)).await;
        self.inner.mark_closed("Page closed");
        Ok(())
    }

    // ---- input -------------------------------------------------------------------------------------

    async fn send_mouse(&self, txn: Txn, params: Value) -> Result<(), CdpError> {
        let r = self.send("Input.dispatchMouseEvent", params).await;
        self.inner.mouse.lock().settle(txn, r.is_ok());
        r.map(drop)
    }

    /// Puppeteer's `mouse.click`: move, press and release are all in flight at once, in that order.
    pub async fn mouse_click(&self, x: f64, y: f64) -> Result<(), CdpError> {
        let mods = self.inner.keyboard.lock().modifiers();
        let (mv, down, up) = {
            let mut mouse = self.inner.mouse.lock();
            let mv = mouse.move_to(x, y, mods);
            let down = mouse.down(MouseButton::Left, 1, mods);
            let up = mouse.up(MouseButton::Left, 1, mods);
            (mv, down, up)
        };
        let down = match down {
            Ok(d) => d,
            Err(err) => {
                // The move was staged; let it go out (and settle) before reporting, as puppeteer would.
                self.send_mouse(mv.0, mv.1).await?;
                return Err(err);
            }
        };
        let (moved, pressed) =
            futures_util::future::join(self.send_mouse(mv.0, mv.1), self.send_press(down, up.ok())).await;
        moved.and(pressed)
    }

    /// The second half of [`Page::mouse_click`]: press and release the left button where the pointer is.
    pub(crate) async fn mouse_press_release(&self) -> Result<(), CdpError> {
        let mods = self.inner.keyboard.lock().modifiers();
        let (down, up) = {
            let mut mouse = self.inner.mouse.lock();
            let down = mouse.down(MouseButton::Left, 1, mods);
            (down, mouse.up(MouseButton::Left, 1, mods))
        };
        self.send_press(down?, up.ok()).await
    }

    /// Sends a staged press and its release together, press first.
    async fn send_press(&self, down: (Txn, Value), up: Option<(Txn, Value)>) -> Result<(), CdpError> {
        let f_up = async {
            match up {
                Some((txn, params)) => self.send_mouse(txn, params).await,
                None => Err(CdpError::Other("'left' is not pressed.".into())),
            }
        };
        let (pressed, released) = futures_util::future::join(self.send_mouse(down.0, down.1), f_up).await;
        pressed.and(released)
    }

    /// Moves the pointer, keeping any held button (a drag), and waits for the page to take the move: the
    /// covered-click check in `press_element` reads the hit only after it.
    pub async fn mouse_move(&self, x: f64, y: f64) -> Result<(), CdpError> {
        let mods = self.inner.keyboard.lock().modifiers();
        let (txn, params) = self.inner.mouse.lock().move_to(x, y, mods);
        self.send_mouse(txn, params).await
    }

    /// Moves to (x, y) and presses the left button, held until [`Self::mouse_up`]: a press-and-hold or the
    /// start of a drag.
    pub async fn mouse_down(&self, x: f64, y: f64) -> Result<(), CdpError> {
        self.mouse_move(x, y).await?;
        let mods = self.inner.keyboard.lock().modifiers();
        let (txn, params) = self.inner.mouse.lock().down(MouseButton::Left, 1, mods)?;
        self.send_mouse(txn, params).await
    }

    /// Moves to (x, y) and releases the left button.
    pub async fn mouse_up(&self, x: f64, y: f64) -> Result<(), CdpError> {
        self.mouse_move(x, y).await?;
        let mods = self.inner.keyboard.lock().modifiers();
        let (txn, params) = self.inner.mouse.lock().up(MouseButton::Left, 1, mods)?;
        self.send_mouse(txn, params).await
    }

    /// A wheel event at the current mouse position.
    pub async fn mouse_wheel(&self, delta_y: f64) -> Result<(), CdpError> {
        let m = self.inner.keyboard.lock().modifiers();
        let params = self.inner.mouse.lock().wheel(0.0, delta_y, m);
        self.send("Input.dispatchMouseEvent", params).await.map(drop)
    }

    /// Releases held buttons and moves the pointer back to (0, 0).
    pub async fn mouse_reset(&self) -> Result<(), CdpError> {
        let m = self.inner.keyboard.lock().modifiers();
        let ops = self.inner.mouse.lock().reset(m);
        let results = join_all(ops.into_iter().map(|(t, p)| self.send_mouse(t, p))).await;
        results.into_iter().collect::<Result<Vec<_>, _>>().map(drop)
    }

    /// Presses a key by puppeteer's name for it (`"Enter"`, `"Shift"`, `"a"`).
    pub async fn key_down(&self, key: &str) -> Result<(), CdpError> {
        let params = self.inner.keyboard.lock().down(key)?;
        self.send("Input.dispatchKeyEvent", params).await.map(drop)
    }

    pub async fn key_up(&self, key: &str) -> Result<(), CdpError> {
        let params = self.inner.keyboard.lock().up(key)?;
        self.send("Input.dispatchKeyEvent", params).await.map(drop)
    }

    /// Presses a key or a combination ([`crate::combo_keys`]: `Enter`, `Control+A`, `Shift+Tab`): each
    /// key down in order, then each up in reverse. Control+A and Meta+A also ask Chrome to select all
    /// ([`crate::input::selects_all`]). A key whose down or up failed, and every key held with it, is
    /// released in the background: a held key the next press would send as a repeat, and a held
    /// modifier would change every later key.
    pub async fn press_combo(&self, combo: &str) -> Result<(), CdpError> {
        let keys = crate::input::combo_keys(combo)?;
        let select_all = crate::input::selects_all(&keys);
        let mut held: Vec<String> = Vec::new();
        let mut pressed = Ok(());
        for (i, key) in keys.iter().enumerate() {
            let mut params = match self.inner.keyboard.lock().down(key) {
                Ok(p) => p,
                Err(e) => {
                    pressed = Err(e);
                    break;
                }
            };
            held.push(key.clone());
            if select_all && i + 1 == keys.len() {
                params["commands"] = json!(["selectAll"]);
            }
            if let Err(e) = self.send("Input.dispatchKeyEvent", params).await {
                pressed = Err(e);
                break;
            }
        }
        while pressed.is_ok()
            && let Some(key) = held.pop()
        {
            if let Err(e) = self.key_up(&key).await {
                held.push(key);
                pressed = Err(e);
            }
        }
        if !held.is_empty() {
            let page = self.clone();
            tokio::spawn(async move {
                for key in held.iter().rev() {
                    let _ = page.key_up(key).await;
                }
            });
        }
        pressed
    }

    /// Down then up. Like puppeteer, a failed down skips the up (the engine releases the key itself).
    pub async fn key_press(&self, key: &str) -> Result<(), CdpError> {
        self.key_down(key).await?;
        self.key_up(key).await
    }

    /// Types `text`: layout characters are pressed as keys, anything else is inserted as text.
    ///
    /// The same commands in the same order as pressing each key in turn. A key's down and up go out
    /// together (one round trip per character, not two), and the next character waits for both answers,
    /// so after a failure, an abort or an owner stop nothing past the character in flight is sent: the
    /// bound pressing in turn had.
    pub async fn type_text(&self, text: &str) -> Result<(), CdpError> {
        let mut buf = [0u8; 4];
        for c in text.chars() {
            let s: &str = c.encode_utf8(&mut buf);
            if char_is_key(c) {
                self.press_key_at_once(s).await?;
            } else {
                self.send("Input.insertText", json!({"text": s})).await?;
            }
        }
        Ok(())
    }

    /// [`Self::key_press`] with the up sent beside the down (`send` queues on its first poll, and `join`
    /// polls the down first). Both are on the wire whatever the down's answer, and Chrome runs a session's
    /// input in order, so the keyboard state is the one after both: the key is released even when its
    /// down failed. The first error is returned.
    async fn press_key_at_once(&self, key: &str) -> Result<(), CdpError> {
        let (down, up) = {
            let mut k = self.inner.keyboard.lock();
            let down = k.down(key)?;
            (down, k.up(key))
        };
        let Ok(up) = up else {
            // Not reached (the up describes the key the down just did); pressing in turn keeps it exact.
            self.send("Input.dispatchKeyEvent", down).await?;
            return up.map(drop);
        };
        let (down, up) = futures_util::future::join(
            self.send("Input.dispatchKeyEvent", down),
            self.send("Input.dispatchKeyEvent", up),
        )
        .await;
        down.and(up).map(drop)
    }

    // ---- frames ------------------------------------------------------------------------------------

    /// Puppeteer's `CdpFrame.frameElement`: the `<iframe>` element hosting `frame`, as a handle in the
    /// parent's isolated world (so the offset and hit-test reads on it are the page-proof ones). `None`
    /// for the main frame.
    pub async fn frame_element(&self, frame: &FrameId) -> Result<Option<JsHandle>, CdpError> {
        let Some(parent) = self.inner.parent_of(frame) else {
            self.inner.session_of(frame)?;
            return Ok(None);
        };
        let session = self.inner.session_of(&parent)?;
        let owner = self.inner.send(session.as_ref(), "DOM.getFrameOwner", json!({"frameId": frame})).await?;
        let backend = owner
            .get("backendNodeId")
            .cloned()
            .ok_or_else(|| CdpError::Other("DOM.getFrameOwner returned no node".into()))?;
        let ctx = self.inner.world_for(&parent).await?;
        // `DOM.resolveNode` takes only the number. Were it another context's by now, the object is that
        // context's, and calls made by the world's unique id refuse it as an argument from another world.
        let resolved = self
            .inner
            .send(
                ctx.session.as_ref(),
                "DOM.resolveNode",
                json!({"backendNodeId": backend, "executionContextId": ctx.id}),
            )
            .await?;
        let object = resolved
            .get("object")
            .cloned()
            .ok_or_else(|| CdpError::Other("DOM.resolveNode returned no object".into()))?;
        Ok(Some(JsHandle::new(self.inner.clone(), ctx, object)))
    }

    pub(crate) fn parent_frame(&self, frame: &FrameId) -> Option<FrameId> {
        self.inner.parent_of(frame)
    }
}

#[cfg(test)]
pub(crate) mod tests;
