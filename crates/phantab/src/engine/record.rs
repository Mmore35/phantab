//! One agent page and its mutable state.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use futures_util::future::{BoxFuture, Shared};
use phantab_cdp::{Browser, Page};
use phantab_window::NativeHandle;
use serde_json::Value;
use tokio::sync::{Notify, watch};
use tokio::time::Instant;

use super::Engine;
use super::relay::Link;
use crate::bridge::{Profile, TabId};
use crate::signin::{Leftover, OnPage, Phase};
use crate::util::lock;

/// `r.detached`: why Chrome detached the page and who did it.
#[derive(Debug, Clone)]
pub(crate) struct Detached {
    pub message: String,
    pub at: Instant,
    /// The other extension's name, or `The other extension`.
    pub name: String,
    /// `autofill menu` or `frame`.
    pub menu: &'static str,
}

pub(crate) type Recovery = Shared<BoxFuture<'static, Result<(), String>>>;

#[derive(Debug)]
pub(crate) struct Rec {
    pub id: String,
    /// The Chrome profile its tab is in (`bridge::USUAL` for the usual one and for an isolated page). A
    /// record never moves: every op on it goes through this profile's link.
    pub profile: Profile,
    /// Chrome's name for a profile other than the usual one (`Work`), else its folder; `describe` reports it
    /// as `profileName` beside the folder. `None` for the usual profile, so its pages read as they always did.
    pub profile_name: Option<String>,
    /// For the sign-in call, which holds the record (`crate::signin::SignInRecord`).
    pub engine: Weak<Engine>,
    st: Mutex<RecState>,
    /// Woken by each `detach`, so a failed call waits for the detach event rather than polling for it.
    pub detached_event: Notify,
}

#[allow(clippy::struct_excessive_bools, reason = "a page record's independent flags, one field each")]
pub(crate) struct RecState {
    pub page: Page,
    /// Bumped each time `page` is replaced, so a watch on the old page does not end the record.
    pub generation: u64,
    /// The relay route of a shared page; `None` for an isolated one.
    pub link: Option<Link>,
    pub isolated: Option<Arc<Browser>>,
    pub owner: String,
    pub owned: bool,
    pub mode: String,
    pub paused: bool,
    pub touched: Instant,
    pub detaches: u64,
    pub tab_id: Option<TabId>,
    pub window_id: Option<Value>,
    /// A hidden agent window this engine created (a truthy `nativeHandle`). True on every
    /// platform for a `shared-hidden` page; `native` is its OS handle where the OS hides it.
    pub workspace: bool,
    pub native: Option<NativeHandle>,
    /// The owner has seen this window: it closes with its page, never kept as a spare (`window::Spare`).
    pub shown_once: bool,
    pub orphaned: bool,
    pub handback: bool,
    pub viewer_token: Option<String>,
    pub viewer_tab: Option<TabId>,
    pub detached: Option<Detached>,
    pub recovering: Option<Recovery>,
    pub recoveries: Vec<Instant>,
    /// Calls in flight on the page (`r.calls`): sending `true` aborts one.
    pub calls: HashMap<u64, watch::Sender<bool>>,
    pub next_call: u64,
    pub closed: bool,
    pub sign_in: Option<Phase>,
    /// What an unconfirmed sign-in left for the re-blank: digests, never a value.
    pub sign_in_leftover: Option<Arc<Leftover>>,
    /// `r.signInAccount`: the account key a sign-in used, and when.
    pub sign_in_account: Option<(String, Instant)>,
    pub sign_in_blanking: bool,
    /// While a sign-up's password sits in the page: digests, never a value.
    pub sign_up_on_page: Option<Arc<OnPage>>,
    /// Viewer actions in the last second (SR-8).
    pub viewer_actions: VecDeque<Instant>,
    /// Viewer pointer moves in the last second, counted apart: a drag sends many.
    pub viewer_moves: VecDeque<Instant>,
    /// Where the owner's relayed pointer is held down, until its release arrives.
    pub pointer_held: Option<(f64, f64)>,
    /// The verification check on the page: live, or ended and not yet reported (`super::verify`).
    pub verification: Option<Verification>,
    /// When this page last popped a check up for the owner by itself (the per-page rate limit).
    pub verify_history: VecDeque<Instant>,
}

/// What kind of verification check a page shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckKind {
    /// The whole page is the check: nothing else on it can be used until it clears.
    Wall,
    /// A check inside a form (a widget next to other content).
    Widget,
    /// Not a check: the site asked for the owner's passkey, which only he can give (a sign-in's
    /// `wall` / `passkey`). It goes through the same hand-off.
    Passkey,
}

/// Where a passkey hand-off started, to tell when the owner has given it: the page's address without
/// its fragment, and its passkey requests then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasskeyFrom {
    pub url: String,
    pub asks: phantab_cdp::PasskeyAsks,
}

/// Where a verification hand-off stands, as `verification.state` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckState {
    /// Found; nothing touches it while it gets the chance to clear by itself.
    Checking,
    /// Shown to the owner.
    WithOwner,
    Cleared,
    /// The owner chose Not now.
    Declined,
    Expired,
    /// More checks than a real site shows; nothing popped up.
    Suspected,
}

impl CheckState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Checking => "checking",
            Self::WithOwner => "with-owner",
            Self::Cleared => "cleared",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::Suspected => "suspected",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Checking | Self::WithOwner)
    }
}

/// One verification hand-off on a record.
#[allow(clippy::struct_excessive_bools, reason = "independent facts about one hand-off, not a state machine")]
pub(crate) struct Verification {
    /// Tells a watcher its hand-off is still the record's current one.
    pub id: u64,
    pub kind: CheckKind,
    pub started: Instant,
    /// `started`, as an ISO time for the agent.
    pub since: String,
    /// Waiters (`browser_wait {verification:true}`) watch this.
    pub state: watch::Sender<CheckState>,
    /// The owner already held the page, so its end leaves the page with him.
    pub prior_paused: bool,
    /// The pop-up has happened: the end has a window to hide.
    pub shown: bool,
    /// The site, for the refusal message and the per-site rate limit.
    pub origin: String,
    /// The remote viewer token, minted at the pop-up (`None` without `remoteViewer`).
    pub link_token: Option<String>,
    /// The wake token, minted with the link: it lets `phantab check-wait` learn when this check ends,
    /// and nothing else (no page content, no control). Never in a log.
    pub watch_token: Option<String>,
    /// The owner pressed Done and Phantab saw the page clear.
    pub owner_done: bool,
    /// The owner pressed Not now.
    pub declined: bool,
    /// For [`CheckKind::Passkey`]: where it started.
    pub passkey: Option<PasskeyFrom>,
}

impl Verification {
    pub fn current(&self) -> CheckState {
        *self.state.borrow()
    }
}

impl std::fmt::Debug for Verification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the link token.
        f.debug_struct("Verification")
            .field("kind", &self.kind)
            .field("state", &self.current())
            .field("prior_paused", &self.prior_paused)
            .field("shown", &self.shown)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RecState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the viewer token.
        f.debug_struct("RecState")
            .field("mode", &self.mode)
            .field("owned", &self.owned)
            .field("paused", &self.paused)
            .field("tab_id", &self.tab_id)
            .field("detached", &self.detached.as_ref().map(|d| &d.message))
            .finish_non_exhaustive()
    }
}

/// The fields a new record starts with besides its page and owner (`fields` in `record()`).
#[derive(Debug, Default)]
pub(crate) struct Fields {
    pub profile: Profile,
    pub profile_name: Option<String>,
    pub owned: Option<bool>,
    pub mode: String,
    pub tab_id: Option<TabId>,
    pub window_id: Option<Value>,
    pub workspace: bool,
    pub native: Option<NativeHandle>,
    pub link: Option<Link>,
    pub isolated: Option<Arc<Browser>>,
}

impl Rec {
    pub fn new(id: String, engine: Weak<Engine>, page: Page, owner: String, f: Fields) -> Self {
        Self {
            id,
            profile: f.profile,
            profile_name: f.profile_name,
            engine,
            detached_event: Notify::new(),
            st: Mutex::new(RecState {
                page,
                generation: 0,
                link: f.link,
                isolated: f.isolated,
                owner,
                owned: f.owned.unwrap_or(true),
                mode: f.mode,
                paused: false,
                touched: Instant::now(),
                detaches: 0,
                tab_id: f.tab_id,
                window_id: f.window_id,
                workspace: f.workspace,
                native: f.native,
                shown_once: false,
                orphaned: false,
                handback: false,
                viewer_token: None,
                viewer_tab: None,
                detached: None,
                recovering: None,
                recoveries: Vec::new(),
                calls: HashMap::new(),
                next_call: 0,
                closed: false,
                sign_in: None,
                sign_in_leftover: None,
                sign_in_account: None,
                sign_in_blanking: false,
                sign_up_on_page: None,
                viewer_actions: VecDeque::new(),
                viewer_moves: VecDeque::new(),
                pointer_held: None,
                verification: None,
                verify_history: VecDeque::new(),
            }),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, RecState> {
        lock(&self.st)
    }

    pub fn page(&self) -> Page {
        self.lock().page.clone()
    }

    pub fn is_isolated(&self) -> bool {
        self.lock().isolated.is_some()
    }

    /// `hiddenWorkspace(r)`: an agent window nobody can see.
    pub fn hidden_workspace(&self) -> bool {
        let s = self.lock();
        s.owned && s.workspace && !s.paused
    }

    /// In a phantab-made window, shown or not.
    pub fn workspace(&self) -> bool {
        self.lock().workspace
    }
}
