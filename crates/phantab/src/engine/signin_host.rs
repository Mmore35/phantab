//! The engine as the sign-in call sees it: [`Host`] for the engine, [`SignInRecord`] for its records.
//!
//! A record handed to sign-in is the engine's own `Arc<Rec>`, so `Host::lock` and `Host::echoed` find
//! it again by identity, not only by id.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use phantab_cdp::Page;
use serde_json::Value;
use tokio::time::Instant;

use super::Engine;
use super::record::Rec;
use crate::engine_api::{EngineError, Serializer};
use crate::signin::{Echo, Host, Leftover, OnPage, Options, Phase, SignInRecord};

#[async_trait]
impl SignInRecord for Rec {
    fn page(&self) -> Page {
        Rec::page(self)
    }

    fn detached(&self) -> bool {
        self.lock().detached.is_some()
    }

    fn detaches(&self) -> u64 {
        self.lock().detaches
    }

    async fn recover(&self) -> Result<(), EngineError> {
        let engine =
            self.engine.upgrade().ok_or_else(|| EngineError("The page has since ended.".to_owned()))?;
        let Some(r) = engine.find(&self.id) else {
            return Err(EngineError("The page has since ended.".to_owned()));
        };
        Engine::recover(&engine, &r).await
    }

    fn is_current(&self) -> bool {
        self.engine.upgrade().is_some_and(|e| {
            e.st().records.iter().any(|r| std::ptr::eq(Arc::as_ptr(r), std::ptr::from_ref(self)))
        })
    }

    fn paused(&self) -> bool {
        self.lock().paused
    }

    fn touch(&self) {
        self.lock().touched = Instant::now();
    }

    fn sign_in(&self) -> Option<Phase> {
        self.lock().sign_in
    }

    fn set_sign_in(&self, phase: Option<Phase>) {
        self.lock().sign_in = phase;
    }

    fn leftover(&self) -> Option<Arc<Leftover>> {
        self.lock().sign_in_leftover.clone()
    }

    fn set_leftover(&self, leftover: Option<Arc<Leftover>>) {
        self.lock().sign_in_leftover = leftover;
    }

    fn begin_blanking(&self) -> bool {
        !std::mem::replace(&mut self.lock().sign_in_blanking, true)
    }

    fn end_blanking(&self) {
        self.lock().sign_in_blanking = false;
    }

    fn account(&self) -> Option<(String, Instant)> {
        self.lock().sign_in_account.clone()
    }

    fn set_account(&self, key: String) {
        self.lock().sign_in_account = Some((key, Instant::now()));
    }

    fn on_page(&self) -> Option<Arc<OnPage>> {
        self.lock().sign_up_on_page.clone()
    }

    fn set_on_page(&self, mark: Option<Arc<OnPage>>) {
        self.lock().sign_up_on_page = mark;
    }
}

impl Engine {
    /// The engine's record behind a sign-in record, while it is still current.
    fn rec_of(&self, record: &dyn SignInRecord) -> Option<Arc<Rec>> {
        let at = std::ptr::from_ref(record).cast::<()>();
        self.st().records.iter().find(|r| std::ptr::eq(Arc::as_ptr(r).cast::<()>(), at)).cloned()
    }
}

#[async_trait]
impl Host for Engine {
    fn record(&self, page_id: &Value, client: &str) -> Option<Arc<dyn SignInRecord>> {
        // `records` is keyed by string; any other pageId matches nothing.
        let r = self.find(page_id.as_str()?)?;
        let mine = r.lock().owner == client;
        mine.then_some(r as Arc<dyn SignInRecord>)
    }

    /// None while `work` is on, whatever the config sets up: no provider is ever started (SR-92).
    fn provider(&self) -> Option<Value> {
        if self.setup.config.work() {
            return None;
        }
        crate::signin::source::provider_config(&self.setup.config)
    }

    /// The sign-in limits and stops are a `guardrails: full` guard (`docs/GUARDRAILS.md`); otherwise no
    /// guard file, which [`crate::sign_in_guard`] reads as an empty guard that records nothing.
    fn guard_file(&self) -> PathBuf {
        if self.guardrails().full() { self.setup.sign_in_guard.clone() } else { PathBuf::new() }
    }

    /// Always beside the real guard path, whatever the mode: the vault session store is not a guardrail,
    /// and the trait's default would follow [`Self::guard_file`]'s empty path to a relative `bitwarden`.
    fn bitwarden_dir(&self) -> PathBuf {
        self.setup.sign_in_guard.with_file_name("bitwarden")
    }

    fn options(&self) -> Options {
        self.options.clone()
    }

    fn serializer(&self) -> Serializer {
        self.setup.serializer.clone()
    }

    fn lock(&self, record: &dyn SignInRecord) -> Result<(), EngineError> {
        // A record no longer current holds no lease; the call finds it gone at its next step.
        match self.rec_of(record) {
            Some(r) => self.lock_site(&r, None),
            None => Ok(()),
        }
    }

    async fn end_leak(&self, record: &dyn SignInRecord) {
        let Some(r) = self.rec_of(record) else { return };
        if r.lock().owned {
            let _ = self.close_tab(&r).await;
        }
        self.forget(&r.id);
    }

    /// The echo is kept even when the record is no longer current: the value is on the site's page
    /// either way. Only the screenshot mark needs the record.
    fn echoed(&self, record: &dyn SignInRecord, echo: Arc<Echo>) {
        match self.rec_of(record) {
            Some(r) => self.add_echo(&r, echo),
            None => self.keep_echo(echo),
        }
    }

    async fn passkey_hand_off(&self, record: &dyn SignInRecord) -> Option<Value> {
        let r = self.rec_of(record)?;
        self.hand_off_passkey(&r).await
    }
}
