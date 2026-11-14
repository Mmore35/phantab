//! Agent windows: `createWorkspace` and `visibility`, per [`HideStrategy`].
//!
//! - **`OsHook` (Windows)**: the hide is armed before `createWindow` so the OS hides
//!   the window at its first appearance; once the page title shows the window exists the guard settles
//!   with its handle, or the window is found by its title token and hidden. Show and hide go by that
//!   handle; show maximizes.
//! - **`ExtensionMinimize` (macOS, docs/MAC.md)**: macOS has no hook that hides a window before it is
//!   drawn, so the extension creates it minimized (`state: 'minimized'`, no bounds: Chrome refuses bounds
//!   with a minimized state). Show is `windowState maximized`; the re-hide on resume is
//!   `windowState minimized`, then `markShown false`. A minimized window stops painting unless the page
//!   is told it has focus, so focus emulation (`prepare`) stays on as on Windows, and `keepRendering`
//!   still runs. The differences from Windows: the window appears in the Dock's minimized row while it
//!   is hidden, there is no native handle, and a hidden window's first frames can come late.
//! - **`None`** (headless test lanes): the window is created at the workspace bounds and never hidden or
//!   shown; `visibility` checks the window and does nothing else.
//!
//! On every platform `markShown(true)` goes before the reveal, so a bridge drop
//! mid-takeover leaves the owner's window open.

use std::sync::Arc;
use std::time::Duration;

use phantab_window::{HideStrategy, NativeHandle, TOKEN_PREFIX, WindowError, WindowSpec};
use serde_json::{Value, json};
use tokio::time::Instant;

use super::record::Rec;
use super::relay::Linked;
use super::{Creating, Engine};
use crate::bridge::{Profile, TabId};
use crate::engine_api::{EngineError, EngineResult};
use crate::page_js::TITLE_IS;
use crate::util::uuid_v4;

/// A new hidden agent window and its page.
#[derive(Debug)]
pub(crate) struct Workspace {
    pub linked: Linked,
    pub tab_id: TabId,
    pub window_id: Option<Value>,
    pub native: Option<NativeHandle>,
}

fn tab_of(v: &Value) -> EngineResult<TabId> {
    v.get("tabId")
        .and_then(Value::as_i64)
        .ok_or_else(|| EngineError("The bridge answered without a tabId.".to_owned()))
}

/// A closed page's hidden window, kept a short while so its client's next `open` navigates it instead of
/// waiting for Chrome to make a new window (about half of an open). Only a quiet hidden workspace is kept:
/// never one the owner has seen, paused, checked, signed in, viewed or detached, and only the same client takes it
/// back, so no page state (history, sessionStorage) crosses between clients. It is blanked at once and
/// closed after [`SPARE_KEEP`], when its client releases, or when its tab or the bridge ends.
#[derive(Debug)]
pub(crate) struct Spare {
    owner: String,
    linked: Linked,
    tab_id: TabId,
    window_id: Option<Value>,
    native: Option<NativeHandle>,
    /// Answers when the page's own blank is done or has failed.
    from_page: tokio::sync::oneshot::Receiver<()>,
    /// The navigation to `about:blank` that ends the closed page; a reuse cuts short the browser's.
    blanked: tokio::task::JoinHandle<()>,
}

/// How long a spare window waits for its client's next open.
const SPARE_KEEP: Duration = Duration::from_secs(30);

/// How long a closed page has to blank itself before the browser blanks it.
const PAGE_BLANK: Duration = Duration::from_millis(250);

impl Engine {
    /// Keeps a closing page's window as the spare instead of closing it; false when it is not kept (then
    /// the caller closes it). One spare at a time.
    ///
    /// Only when agent windows are not hidden (strategy `None`). The blank is a navigation, so it runs the
    /// closed page's beforeunload, and every call phantab makes into a page is a user gesture
    /// (`userGesture` in `Runtime.callFunctionOn`, the blank's own included), so any page may answer it
    /// with "Leave site?". Chrome draws that on the owner's screen: on macOS it restores the minimized
    /// window (lane 4, docs/MAC.md); on Windows it drew the dialog alone (THREAT-MODEL T67), and only
    /// SR-60's answer, a race no lane measures there, would stop it. A hidden page closes through
    /// `closeTab`, which runs no beforeunload (SR-60).
    pub(crate) async fn keep_spare(&self, r: &Arc<Rec>) -> bool {
        if self.strategy() != HideStrategy::None {
            return false;
        }
        let Some((tab, window)) = Self::spare_candidate(r) else { return false };
        if self.st().spare.is_some() {
            return false;
        }
        // A tab the page opened in its window (a popup as a tab) goes with the window, as at a close.
        let alone = match self.bridge().op_in(&r.profile, "tabs", json!({})).await {
            Ok(Value::Array(tabs)) => !tabs.iter().any(|t| {
                t.get("windowId") == Some(&window) && t.get("tabId").and_then(Value::as_i64) != Some(tab)
            }),
            _ => false,
        };
        if !alone {
            return false;
        }
        let mut st = self.st();
        if st.spare.is_some() || Self::spare_candidate(r).is_none() {
            return false;
        }
        let mut s = r.lock();
        let Some(link) = s.link.take() else { return false };
        // The record no longer holds the route, so forgetting it leaves the page attached.
        let page = s.page.clone();
        let blank = page.clone();
        let (page_blanked, from_page) = tokio::sync::oneshot::channel();
        let blanked = tokio::spawn(async move {
            // The page blanks itself in its own renderer process; the browser's blank, which can swap the
            // process for the next page to swap back, is only for a page that cannot.
            let ok = blank.blank_from_page(PAGE_BLANK).await.is_ok();
            let _ = page_blanked.send(());
            if !ok {
                let _ = blank.goto("about:blank", Duration::from_secs(5)).await;
            }
        });
        st.spare = Some(Spare {
            owner: s.owner.clone(),
            linked: Linked { page, link },
            tab_id: tab,
            window_id: Some(window),
            native: s.native,
            from_page,
            blanked,
        });
        drop(s);
        drop(st);
        let link_profile = r.profile.clone();
        if let Some(engine) = self.arc() {
            tokio::spawn(async move {
                tokio::time::sleep(SPARE_KEEP).await;
                engine.close_spare(|s| s.tab_id == tab && s.linked.link.profile == link_profile).await;
            });
        }
        true
    }

    /// The tab and window of a page that may be kept as the spare: a quiet hidden workspace.
    fn spare_candidate(r: &Rec) -> Option<(TabId, Value)> {
        let s = r.lock();
        let quiet = s.owned
            && s.workspace
            && s.mode == "shared-hidden"
            && !s.paused
            && !s.shown_once
            && !s.closed
            && !s.orphaned
            && s.link.is_some()
            && s.detached.is_none()
            && s.recovering.is_none()
            && s.sign_in.is_none()
            && s.sign_in_account.is_none()
            && s.sign_in_leftover.is_none()
            && s.verification.is_none()
            && s.viewer_tab.is_none()
            && s.viewer_token.is_none()
            && s.isolated.is_none();
        match (s.tab_id, s.window_id.clone(), quiet) {
            (Some(tab), Some(window), true) => Some((tab, window)),
            _ => None,
        }
    }

    fn take_spare(&self, which: impl Fn(&Spare) -> bool) -> Option<Spare> {
        let mut st = self.st();
        if st.spare.as_ref().is_some_and(which) { st.spare.take() } else { None }
    }

    /// Closes the spare window, when `which` picks it.
    async fn close_spare(&self, which: impl Fn(&Spare) -> bool) {
        if let Some(s) = self.take_spare(which) {
            s.blanked.abort();
            self.close_link(&s.linked.link);
            let _ =
                self.bridge().op_in(&s.linked.link.profile, "closeTab", json!({ "tabId": s.tab_id })).await;
        }
    }

    /// `owner` released: its spare window closes.
    pub(crate) async fn release_spare(&self, owner: &str) {
        self.close_spare(|s| s.owner == owner).await;
    }

    /// The spare's tab (`Some(tab)`) or its profile's whole link (`None`) ended: Chrome already closed it.
    pub(crate) fn spare_gone(&self, profile: &Profile, tab: Option<TabId>) {
        if let Some(s) =
            self.take_spare(|s| s.linked.link.profile == *profile && tab.is_none_or(|t| s.tab_id == t))
        {
            s.blanked.abort();
            self.close_route(profile, s.tab_id, s.linked.link.route, false);
        }
    }

    pub(crate) fn is_spare(&self, profile: &Profile, tab: TabId) -> bool {
        self.st().spare.as_ref().is_some_and(|s| s.tab_id == tab && s.linked.link.profile == *profile)
    }

    /// `owner`'s spare window in `profile`, navigated to `url`, as a new workspace; `None` when there is
    /// none or its navigation failed (then it is closed and the caller makes a new window). A spare in
    /// another profile stays: its window holds that profile's login.
    pub(crate) async fn reuse_spare(&self, profile: &Profile, owner: &str, url: &str) -> Option<Workspace> {
        let spare = self.take_spare(|s| s.owner == owner && s.linked.link.profile == *profile)?;
        // A blank the page started itself commits late enough to cut short a navigation sent before it, so
        // the new page waits for it (a few ms, at most `PAGE_BLANK`). The browser's blank that follows when
        // the page could not is replaced by the new page's navigation (`goto` waits for its own loader).
        let _ = spare.from_page.await;
        spare.blanked.abort();
        let _ = spare.blanked.await;
        // What the closed page left (an answered "Leave site?") is not the new page's to report.
        let _ = spare.linked.page.take_dialogs();
        if spare.linked.page.goto(url, Duration::from_secs(30)).await.is_err() {
            self.close_link(&spare.linked.link);
            let _ = self.bridge().op_in(profile, "closeTab", json!({ "tabId": spare.tab_id })).await;
            return None;
        }
        Some(Workspace {
            linked: spare.linked,
            tab_id: spare.tab_id,
            window_id: spare.window_id,
            native: spare.native,
        })
    }

    /// `createWorkspace(url)`, in `profile`. CDP hidden targets have no screenshot surface. A real Chrome
    /// window, hidden at its first appearance and kept rendering, can be shown intact.
    pub(crate) async fn create_workspace(&self, profile: &Profile, url: &str) -> EngineResult<Workspace> {
        let strategy = self.strategy();
        let token = format!("{TOKEN_PREFIX}{}", uuid_v4().map_err(|e| EngineError(e.to_string()))?);
        let spec = WindowSpec::workspace(token.clone());
        let mut guard = match strategy {
            HideStrategy::OsHook => Some(self.windows.arm_hide(&spec).await?),
            HideStrategy::ExtensionMinimize | HideStrategy::None => None,
        };
        let start = format!("data:text/html,<title>{token}</title>");
        let args = match strategy {
            HideStrategy::ExtensionMinimize => json!({ "url": start, "state": "minimized" }),
            HideStrategy::OsHook | HideStrategy::None => json!({
                "url": start, "left": spec.left, "top": spec.top, "width": spec.width, "height": spec.height,
            }),
        };
        let created = match self.bridge().op_in(profile, "createWindow", args).await {
            Ok(v) => v,
            Err(e) => {
                if let Some(g) = guard.as_mut() {
                    g.settle().await;
                }
                return Err(e.into());
            }
        };
        let tab = tab_of(&created)?;
        let window_id = created.get("windowId").cloned();
        let key = (profile.clone(), tab);
        self.st().creating.insert(key.clone(), Creating::default());
        let mut linked: Option<Linked> = None;
        let result = self.fill_workspace(&key, url, &token, guard.as_mut(), &mut linked).await;
        let out = match result {
            Ok(native) => match linked.take() {
                Some(linked) => Ok(Workspace { linked, tab_id: tab, window_id, native }),
                None => Err(EngineError("Chrome did not expose the tab as a page.".to_owned())),
            },
            Err(e) => {
                let end = Instant::now() + Duration::from_millis(500);
                while self.creating_detached(&key).is_none() && Instant::now() < end {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                if let Some(p) = linked.take() {
                    self.close_link(&p.link);
                }
                let _ = self.bridge().op_in(profile, "closeTab", json!({ "tabId": tab })).await;
                if let Some(g) = guard.as_mut() {
                    g.settle().await;
                }
                Err(match self.creating_detached(&key) {
                    Some(d) => EngineError(format!(
                        "{d} The page was not opened and its window was closed; open it again."
                    )),
                    None => e,
                })
            }
        };
        self.st().creating.remove(&key);
        out
    }

    fn creating_detached(&self, key: &(Profile, TabId)) -> Option<String> {
        self.st().creating.get(key).and_then(|c| c.detached.clone())
    }

    async fn fill_workspace(
        &self,
        key: &(Profile, TabId),
        url: &str,
        token: &str,
        guard: Option<&mut phantab_window::ArmGuard>,
        linked: &mut Option<Linked>,
    ) -> EngineResult<Option<NativeHandle>> {
        let (profile, tab) = (&key.0, key.1);
        let p = self.page_for(profile, tab, true).await?;
        if let Some(c) = self.st().creating.get_mut(key) {
            c.route = Some(p.link.route);
        }
        let page = p.page.clone();
        *linked = Some(p);
        // Fails on a bridge extension not yet reloaded; its window then takes the find-by-title path below.
        let _ = self.bridge().op_in(profile, "keepRendering", json!({ "tabId": tab })).await;
        super::until(
            &page,
            "New agent window",
            TITLE_IS,
            &[Value::String(token.to_owned())],
            Duration::from_secs(10),
            None,
        )
        .await?;
        let native = match (self.strategy(), guard) {
            (HideStrategy::OsHook, Some(guard)) => {
                let handle = match guard.settle().await {
                    Some(handle) => handle,
                    None => self.windows.find(token).await?,
                };
                // Kept hidden from here on: a popup or tab the page opens makes Chrome show its window again.
                // The hide runs whatever the keep answers, so a keep that failed (a timed-out or unhooked
                // keeper) still leaves the window hidden; the keep's error is still the answer.
                let kept = self.windows.keep_hidden(handle, true).await;
                let hidden = self.windows.hide(handle).await;
                kept?;
                hidden?;
                Some(handle)
            }
            _ => None,
        };
        Self::prepare(&page).await?;
        page.goto(url, Duration::from_secs(30)).await?;
        if let Some(d) = self.creating_detached(key) {
            return Err(EngineError(d));
        }
        Ok(native)
    }

    /// Whether the record's own window is a workspace window this engine hides itself (`OsHook`) and reads
    /// hidden now. A keep that failed still leaves its window hidden (`visibility`), so a hand-back that
    /// answered that error has a hidden window whatever its record said before. False on any other strategy,
    /// and when the window cannot be read: only a window known hidden counts.
    pub(crate) async fn reads_hidden(&self, r: &Rec) -> bool {
        let (workspace, native) = {
            let s = r.lock();
            (s.workspace, s.native)
        };
        match (self.strategy(), workspace, native) {
            (HideStrategy::OsHook, true, Some(handle)) => {
                matches!(self.windows.is_visible(handle).await, Ok(false))
            }
            _ => false,
        }
    }

    /// `visibility(r, action)`: shows or hides the record's own window, after checking the tab is still in
    /// it.
    pub(crate) async fn visibility(&self, r: &Arc<Rec>, show: bool) -> EngineResult<()> {
        let (tab, window_id, native) = {
            let s = r.lock();
            (s.tab_id, s.window_id.clone(), s.native)
        };
        let t = self.bridge().op_in(&r.profile, "tab", json!({ "tabId": tab })).await?;
        if t.get("windowId") != window_id.as_ref() {
            return Err(EngineError(
                "Page moved to a different window. Refusing to change an unrelated window.".to_owned(),
            ));
        }
        match self.strategy() {
            HideStrategy::OsHook => {
                let handle = native.ok_or(WindowError::InvalidHandle)?;
                if show {
                    self.windows.keep_hidden(handle, false).await?;
                    self.windows.show(handle, true).await?;
                } else {
                    // As at creation: hidden whatever the keep answers, then the keep's error, if any.
                    let kept = self.windows.keep_hidden(handle, true).await;
                    let hidden = self.windows.hide(handle).await;
                    kept?;
                    hidden?;
                }
            }
            HideStrategy::ExtensionMinimize => {
                let state = if show { "maximized" } else { "minimized" };
                self.bridge()
                    .op_in(&r.profile, "windowState", json!({ "windowId": window_id, "state": state }))
                    .await?;
            }
            HideStrategy::None => {}
        }
        Ok(())
    }
}
