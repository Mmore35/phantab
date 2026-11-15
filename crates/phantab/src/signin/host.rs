//! What the sign-in call needs from its engine: the record it runs on and a few engine services. The
//! engine implements them over its own records; the Chrome tests implement them over a launched browser.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use phantab_cdp::Page;
use serde_json::Value;
use tokio::time::Instant;

use super::{Echo, Leftover, OnPage, Options};
use crate::engine_api::{EngineError, Serializer};

/// `r.signIn`: a sign-in is running, or ended without confirming it blanked the password field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Running,
    Unblanked,
}

/// One agent page, as sign-in sees it. Every getter reads the record's state now: a recovery replaces
/// the page, and the call reads `r.page` afresh each time.
#[async_trait]
pub trait SignInRecord: Send + Sync {
    /// `r.page`.
    fn page(&self) -> Page;
    /// `!!r.detached`.
    fn detached(&self) -> bool;
    /// `r.detaches`: how many times the page has re-attached.
    fn detaches(&self) -> u64;
    /// `engine.recover(r)`: re-attaches a detached page; a no-op otherwise.
    ///
    /// # Errors
    /// The page could not be re-attached.
    async fn recover(&self) -> Result<(), EngineError>;
    /// `engine.records.get(r.id)===r`.
    fn is_current(&self) -> bool;
    /// `r.paused`: the owner has the page.
    fn paused(&self) -> bool;
    /// `r.touched=Date.now()`.
    fn touch(&self);
    /// `r.signIn`.
    fn sign_in(&self) -> Option<Phase>;
    /// Sets or clears `r.signIn`.
    fn set_sign_in(&self, phase: Option<Phase>);
    /// What an unconfirmed sign-in left for the re-blank to find. Set with [`Phase::Unblanked`], cleared with it.
    fn leftover(&self) -> Option<Arc<Leftover>>;
    /// Sets or clears [`SignInRecord::leftover`].
    fn set_leftover(&self, leftover: Option<Arc<Leftover>>);
    /// `r.signInBlanking`: sets it and answers true, or answers false when it was already set.
    fn begin_blanking(&self) -> bool;
    /// Clears `r.signInBlanking`.
    fn end_blanking(&self);
    /// `r.signInAccount`: the account key a sign-in used on this page, and when.
    fn account(&self) -> Option<(String, Instant)>;
    /// `r.signInAccount={key,at:Date.now()}`.
    fn set_account(&self, key: String);
    /// What `browser_sign_up` left while its password sits in the page (phantab's own).
    fn on_page(&self) -> Option<Arc<OnPage>>;
    /// Sets or clears [`SignInRecord::on_page`].
    fn set_on_page(&self, mark: Option<Arc<OnPage>>);
}

/// The engine, as sign-in sees it.
#[async_trait]
pub trait Host: Send + Sync {
    /// `engine.records.get(pageId)`, when `client` owns it. `None` for an unknown page or another
    /// session's (the call then throws `Unknown page or page belongs to another agent session.`).
    fn record(&self, page_id: &Value, client: &str) -> Option<Arc<dyn SignInRecord>>;
    /// `engine.config.signInProvider`, or the `signInProviders` list with it
    /// ([`crate::signin::source::provider_config`]).
    fn provider(&self) -> Option<Value>;
    /// `engine.config.signInGuard`.
    fn guard_file(&self) -> PathBuf;
    /// `<runtime>/bitwarden`: the built-in Bitwarden source's session store and CLI data (BITWARDEN.md).
    /// Beside the guard file, which is `<runtime>/sign-in-guard.json`.
    fn bitwarden_dir(&self) -> PathBuf {
        self.guard_file().with_file_name("bitwarden")
    }
    /// `engine.options` as sign-in reads them.
    fn options(&self) -> Options;
    /// The service's queue (`engine.serialize`).
    fn serializer(&self) -> Serializer;
    /// `engine.lock(r)`: takes the record's site lease for changes.
    ///
    /// # Errors
    /// Another page holds the site (`Another agent or human handoff holds this site for changes. Wait for
    /// its release or handback.`).
    fn lock(&self, record: &dyn SignInRecord) -> Result<(), EngineError>;
    /// A sign-up's new password showed in the page's address or text, where blanking cannot reach it:
    /// closes the tab when the engine opened it, then forgets the record. A sign-in's echo never comes
    /// here; it goes on through [`Host::echoed`].
    async fn end_leak(&self, record: &dyn SignInRecord);
    /// The site showed the password or code back on the record's page after the submit. The call
    /// goes on rather than closing the tab and stopping the account. From now on the host redacts `echo` from everything the agent receives, and refuses screenshots of the
    /// record's tab until it closes. Not async, and nothing to fail: the call goes on either way.
    fn echoed(&self, record: &dyn SignInRecord, echo: Arc<Echo>);
    /// After a `wall` / `passkey` outcome: hands the tab to the owner to give the passkey, and returns
    /// the hand-off's `verification` report for the result. `None` when nothing was
    /// handed over; a host with no owner to show a page to (a test's) keeps the default.
    async fn passkey_hand_off(&self, _record: &dyn SignInRecord) -> Option<Value> {
        None
    }
}

/// For the engine's other calls on a page: refuses while a sign-in runs, and
/// while one ended without confirming it blanked the password field, starting a re-blank then.
///
/// # Errors
/// The two messages the agent sees.
pub fn check_call(record: &Arc<dyn SignInRecord>) -> Result<(), EngineError> {
    match record.sign_in() {
        None => Ok(()),
        Some(Phase::Running) => {
            Err(EngineError("A sign-in is running on this page. Retry when it answers.".into()))
        }
        Some(Phase::Unblanked) => {
            super::pipeline::start_reblank(record);
            Err(EngineError(
                "A sign-in could not confirm it blanked the password field. Retry in a moment.".into(),
            ))
        }
    }
}
