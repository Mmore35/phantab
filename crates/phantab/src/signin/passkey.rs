//! The page's passkey requests: what `phantab_cdp::PASSKEY_WATCH` counted
//! in each frame, summed over the page. A request still pending means a pop-up only the owner can
//! answer may be open (Bitwarden's, or the OS's), so a sign-in that meets one hands the tab to him
//! (`wall` / `passkey`) instead of reading the page as submitted or not taken.
//!
//! Only the three numbers are read, never what the page asked for or got. They come from the page's
//! main world, so a page can forge them; that only gets its tab shown to the owner (THREAT-MODEL
//! SR-75). A page with no watch script (an owner's tab) reads as nothing asked.

use std::time::Duration;

use futures_util::future::join_all;
use phantab_cdp::{Page, PasskeyAsks};
use tokio::time::timeout;

/// Frames read per look, as `scan` caps its frames.
const FRAMES: usize = 20;
/// Per frame: a frame with no context yet would otherwise wait out the page's default timeout.
const PER_FRAME: Duration = Duration::from_millis(1000);

/// The page's passkey requests so far, summed over its frames. A frame that does not answer counts
/// as nothing asked.
pub(crate) async fn asks(page: &Page) -> PasskeyAsks {
    read(page).await.unwrap_or_default()
}

/// [`asks`], or `None` when no frame answered at all (the page is busy or between documents): neither
/// a request nor its absence.
pub(crate) async fn read(page: &Page) -> Option<PasskeyAsks> {
    let frames: Vec<_> = page.frames().into_iter().filter(|f| !f.detached).take(FRAMES).collect();
    let reads = join_all(frames.iter().map(|f| timeout(PER_FRAME, page.passkey_asks(&f.id)))).await;
    let answers: Vec<_> = reads.into_iter().filter_map(|r| r.ok().and_then(Result::ok)).collect();
    if answers.is_empty() {
        return None;
    }
    Some(answers.into_iter().flatten().fold(PasskeyAsks::default(), |sum, a| PasskeyAsks {
        asked: sum.asked.saturating_add(a.asked),
        pending: sum.pending.saturating_add(a.pending),
        answered: sum.answered.saturating_add(a.answered),
    }))
}

/// Whether a passkey request on the page is waiting for an answer now.
pub(crate) async fn waiting(page: &Page) -> bool {
    !page.is_closed() && asks(page).await.pending > 0
}
