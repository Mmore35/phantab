//! The two marks that keep an agent's script and a password phantab filled off the same page
//! (THREAT-MODEL SR-90), in either order:
//!
//! - **A script ran here.** `browser_evaluate` marks the page's tab the moment its script starts, in any
//!   frame, and the mark stays until the tab closes: a navigation does not clear it, since a script can
//!   leave work behind that outlives its document (a window it opened that reaches back, for one).
//!   `browser_sign_in` and `browser_sign_up` refuse on a marked tab before any provider is asked, and
//!   their queued fill looks again, for a script that ran while the provider was answering. A script
//!   refused before it started (the setting off, a held page, the owner not yet asked) marks nothing.
//! - **A password was filled here.** A sign-in's or sign-up's fill first marks the main document it
//!   fills, by its `performance.timeOrigin`, and does not fill when that cannot be read.
//!   `browser_evaluate` refuses while the tab shows a marked document: until a reload or navigation
//!   replaces it, which brings a new script world with no old field (a document Chrome restores from its
//!   back-forward cache is the same document, and is refused again).
//!
//! A shared tab is marked by its profile and tab ID, so a fresh attach to it is the same tab; an isolated
//! page by its record, which ends with it ([`TabMark`]). Marks live in the service's memory: a restarted
//! service starts with none.

use std::time::Duration;

use phantab_cdp::Page;

use super::Engine;
use super::record::Rec;
use crate::bridge::{Profile, TabId};

/// `browser_evaluate`'s answer on a page a password was filled into.
pub(crate) const FILLED_REFUSED: &str = "evaluate refused: phantab filled a password into this page, and no script runs on a page that may still hold one. A reload of the page, or a fresh page, lifts this.";

/// `browser_sign_in`'s or `browser_sign_up`'s answer on a page a script ran on (`what`: `sign-in` or
/// `sign-up`).
pub(crate) fn scripted_refused(what: &str) -> String {
    format!(
        "{what} refused: a script ran on this page (browser_evaluate), and phantab fills no password where a script may be waiting for it. Open a fresh page for the {what}."
    )
}

/// The page's tab, as a mark names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TabMark {
    /// A shared tab: a fresh attach to it is the same tab.
    Tab(Profile, TabId),
    /// An isolated page, by record ID: its tab IDs are its own browser's.
    Page(String),
}

impl TabMark {
    pub(crate) fn of(r: &Rec) -> Self {
        let s = r.lock();
        match s.tab_id {
            Some(tab) if s.isolated.is_none() => TabMark::Tab(r.profile.clone(), tab),
            _ => TabMark::Page(r.id.clone()),
        }
    }
}

/// The main document's `performance.timeOrigin`, read in phantab's own world: the same for a document
/// however often phantab re-attaches to it, and new for every document the tab loads.
pub(crate) async fn document_of(page: &Page) -> Option<u64> {
    let main = page.main_frame().ok()?;
    let read = page.evaluate(&main, "()=>performance.timeOrigin", vec![]);
    let at = tokio::time::timeout(Duration::from_secs(3), read).await.ok()?.ok()?;
    at.as_f64().filter(|t| t.is_finite() && *t > 0.0).map(f64::to_bits)
}

impl Engine {
    /// A script is about to run on `r`'s page.
    pub(crate) fn mark_script(&self, r: &Rec) {
        let mark = TabMark::of(r);
        let mut st = self.st();
        if !st.script_marks.contains(&mark) {
            st.script_marks.push(mark);
        }
    }

    /// Whether a script ran on `r`'s tab.
    pub(crate) fn script_marked(&self, r: &Rec) -> bool {
        let mark = TabMark::of(r);
        self.st().script_marks.contains(&mark)
    }

    /// A password is about to be filled into the document `document` ([`document_of`]) of `r`'s tab.
    pub(crate) fn mark_document_filled(&self, r: &Rec, document: u64) {
        let mark = (TabMark::of(r), document);
        let mut st = self.st();
        if !st.fill_marks.contains(&mark) {
            st.fill_marks.push(mark);
        }
    }

    /// Whether a password was filled into the document `document` of `r`'s tab.
    pub(crate) fn document_filled(&self, r: &Rec, document: u64) -> bool {
        let mark = (TabMark::of(r), document);
        self.st().fill_marks.contains(&mark)
    }

    /// Whether any password was filled into a document of `r`'s tab, so a script must read which
    /// document the tab shows first.
    pub(crate) fn any_fill(&self, r: &Rec) -> bool {
        let mark = TabMark::of(r);
        self.st().fill_marks.iter().any(|(m, _)| *m == mark)
    }

    /// The tab closed: nothing is marked on it any more.
    pub(crate) fn marks_tab_closed(&self, profile: &Profile, tab: TabId) {
        let closed = TabMark::Tab(profile.clone(), tab);
        let mut st = self.st();
        st.script_marks.retain(|m| *m != closed);
        st.fill_marks.retain(|(m, _)| *m != closed);
    }

    /// The isolated page `id` is gone, and its browser with it.
    pub(crate) fn marks_page_gone(&self, id: &str) {
        let gone = TabMark::Page(id.to_owned());
        let mut st = self.st();
        st.script_marks.retain(|m| *m != gone);
        st.fill_marks.retain(|(m, _)| *m != gone);
    }
}
