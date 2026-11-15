//! A minimal sign-in host over a launched Chrome, for the sign-in browser lanes: records keyed by page id,
//! the fake provider, a temp runtime with the guard file, and the sign-in tests' helpers (`open`,
//! `sign`, `once`, `reset`, `control`, `requests`). Only a temp profile and the Chrome it launched.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use phantab::engine_api::{EngineError, EngineResult, Serializer};
use phantab::signin::{Echo, Host, Leftover, OnPage, Options, Phase, SignInRecord};
use phantab_cdp::{Browser, LaunchOptions, Page, PageOptions, Transport as _};
use phantab_testkit::FixtureServer;
use phantab_testkit::sign_in::{CODE, PASSWORD, USERNAME};
use serde_json::{Value, json};
use tokio::time::Instant;

pub const FAKE: &str = env!("CARGO_BIN_EXE_phantab-fake-provider");

/// Every status a sign-in gives. `leak-stopped` is still parsed but never given: an echo goes on and says
/// `echoed`.
pub const ALL_STATUSES: &[&str] = &[
    "submitted",
    "next-step",
    "still-asking",
    "unknown",
    "wall",
    "not-a-sign-in",
    "not-ready",
    "none",
    "ambiguous",
    "refused",
    "ask-first",
    "locked",
    "provider-failed",
    "busy",
    "stopped",
    "owner-has-page",
    "failed",
    "no-provider",
];

/// Every input's value in every frame and open shadow root (`inputValues`).
const INPUT_VALUES: &str = "()=>{const roots=[document];for(let i=0;i<roots.length;i++)for(const el of roots[i].querySelectorAll('*'))if(el.shadowRoot)roots.push(el.shadowRoot);return roots.flatMap(x=>[...x.querySelectorAll('input')]).map(el=>el.value);}";

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // The engine record's flags, one each.
struct RecState {
    detached: bool,
    detaches: u64,
    paused: bool,
    sign_in: Option<Phase>,
    leftover: Option<Arc<Leftover>>,
    on_page: Option<Arc<OnPage>>,
    blanking: bool,
    account: Option<(String, Instant)>,
    current: bool,
    /// The test makes the next re-attach fail (`e.recover=...Promise.reject`).
    fail_recover: bool,
}

/// One agent page.
pub struct Rec {
    pub id: String,
    pub owner: String,
    /// Opened by the engine, or the owner's tab.
    pub owned: bool,
    target: String,
    browser: Arc<Browser>,
    page: Mutex<Page>,
    st: Mutex<RecState>,
}

impl Rec {
    pub fn set_paused(&self, on: bool) {
        self.st.lock().unwrap().paused = on;
    }

    pub fn set_phase(&self, phase: Option<Phase>) {
        self.st.lock().unwrap().sign_in = phase;
    }

    /// Whether a sign-up's password is marked on the page.
    pub fn marked(&self) -> bool {
        self.st.lock().unwrap().on_page.is_some()
    }

    /// The record's sign-up mark as its `Debug` prints it (the no-leak check).
    pub fn mark_debug(&self) -> String {
        format!("{:?}", self.st.lock().unwrap().on_page)
    }

    pub fn phase(&self) -> Option<Phase> {
        self.st.lock().unwrap().sign_in
    }

    pub fn fail_recover(&self, on: bool) {
        self.st.lock().unwrap().fail_recover = on;
    }

    /// `e.detach(r)`: the link drops (every handle from before dies), and the record waits for a recover.
    pub async fn detach(&self) {
        let session = {
            let mut s = self.st.lock().unwrap();
            s.detached = true;
            s.detaches += 1;
            self.page.lock().unwrap().session().cloned()
        };
        if let Some(sid) = session {
            let _ = self
                .browser
                .connection()
                .send(None, "Target.detachFromTarget", json!({"sessionId": sid.as_str()}))
                .await;
        }
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    /// `INPUT_VALUES` on this page.
    pub async fn input_values(&self) -> Vec<String> {
        let page = SignInRecord::page(self);
        let mut out = Vec::new();
        for f in page.frames() {
            if let Ok(Ok(Value::Array(vals))) =
                tokio::time::timeout(Duration::from_secs(5), page.evaluate(&f.id, INPUT_VALUES, vec![])).await
            {
                out.extend(vals.into_iter().filter_map(|v| v.as_str().map(str::to_owned)));
            }
        }
        out
    }

    pub async fn eval_main(&self, js: &str) -> Value {
        let page = SignInRecord::page(self);
        let main = page.main_frame().unwrap();
        page.evaluate_main(&main, js, vec![]).await.unwrap()
    }
}

async fn prepare(page: &Page) {
    let _ = page.set_viewport(Some((1280, 900))).await;
    let _ = page.emulate_focus(true).await;
}

#[async_trait]
impl SignInRecord for Rec {
    fn page(&self) -> Page {
        self.page.lock().unwrap().clone()
    }

    fn detached(&self) -> bool {
        self.st.lock().unwrap().detached
    }

    fn detaches(&self) -> u64 {
        self.st.lock().unwrap().detaches
    }

    async fn recover(&self) -> Result<(), EngineError> {
        {
            let s = self.st.lock().unwrap();
            if !s.detached {
                return Ok(());
            }
            if s.fail_recover {
                return Err(EngineError("no".into()));
            }
        }
        let page = self
            .browser
            .attach_target(&self.target, PageOptions::default())
            .await
            .map_err(|e| EngineError(e.to_string()))?;
        prepare(&page).await;
        *self.page.lock().unwrap() = page;
        self.st.lock().unwrap().detached = false;
        Ok(())
    }

    fn is_current(&self) -> bool {
        self.st.lock().unwrap().current
    }

    fn paused(&self) -> bool {
        self.st.lock().unwrap().paused
    }

    fn touch(&self) {}

    fn sign_in(&self) -> Option<Phase> {
        self.st.lock().unwrap().sign_in
    }

    fn set_sign_in(&self, phase: Option<Phase>) {
        self.st.lock().unwrap().sign_in = phase;
    }

    fn leftover(&self) -> Option<Arc<Leftover>> {
        self.st.lock().unwrap().leftover.clone()
    }

    fn set_leftover(&self, leftover: Option<Arc<Leftover>>) {
        self.st.lock().unwrap().leftover = leftover;
    }

    fn begin_blanking(&self) -> bool {
        !std::mem::replace(&mut self.st.lock().unwrap().blanking, true)
    }

    fn end_blanking(&self) {
        self.st.lock().unwrap().blanking = false;
    }

    fn account(&self) -> Option<(String, Instant)> {
        self.st.lock().unwrap().account.clone()
    }

    fn set_account(&self, key: String) {
        self.st.lock().unwrap().account = Some((key, Instant::now()));
    }

    fn on_page(&self) -> Option<Arc<OnPage>> {
        self.st.lock().unwrap().on_page.clone()
    }

    fn set_on_page(&self, mark: Option<Arc<OnPage>>) {
        self.st.lock().unwrap().on_page = mark;
    }
}

type Records = Arc<Mutex<HashMap<String, Arc<Rec>>>>;

/// The engine as sign-in sees it. Hosts made with [`Lane::with`] share records, browser and queue, so a
/// stricter or shorter-timed host still sees the first host's records.
#[derive(Clone)]
pub struct Lane {
    pub browser: Arc<Browser>,
    records: Records,
    provider: Option<Value>,
    pub guard: PathBuf,
    options: Options,
    serializer: Serializer,
    /// What `Host::echoed` was handed: the engine's redaction, which these lanes leave to the test.
    pub echoes: Arc<Mutex<Vec<Arc<Echo>>>>,
}

#[async_trait]
impl Host for Lane {
    fn record(&self, page_id: &Value, client: &str) -> Option<Arc<dyn SignInRecord>> {
        let r = self.records.lock().unwrap().get(page_id.as_str()?).cloned()?;
        (r.owner == client).then_some(r as Arc<dyn SignInRecord>)
    }

    fn provider(&self) -> Option<Value> {
        self.provider.clone()
    }

    fn guard_file(&self) -> PathBuf {
        self.guard.clone()
    }

    fn options(&self) -> Options {
        self.options.clone()
    }

    fn serializer(&self) -> Serializer {
        self.serializer.clone()
    }

    fn lock(&self, _record: &dyn SignInRecord) -> Result<(), EngineError> {
        Ok(())
    }

    fn echoed(&self, _record: &dyn SignInRecord, echo: Arc<Echo>) {
        self.echoes.lock().unwrap().push(echo);
    }

    async fn end_leak(&self, record: &dyn SignInRecord) {
        let found = {
            let at = std::ptr::from_ref(record).cast::<()>();
            self.records
                .lock()
                .unwrap()
                .values()
                .find(|r| std::ptr::eq(Arc::as_ptr(r).cast::<()>(), at))
                .cloned()
        };
        let Some(r) = found else { return };
        if r.owned {
            let _ = record.page().close().await;
        }
        self.forget(&r.id);
    }
}

static NEXT: AtomicU64 = AtomicU64::new(1);

impl Lane {
    /// The sign-in lanes' engine options (loopback allowed, `settleMs:1200, findMs:600`), except observe:
    /// 4000 ms, not 1500. On the macOS CI runner a submit into a cross-site frame (a new renderer
    /// process) once took over 1.5 s to replace the form, which read as still-asking. Only cases that
    /// end still-asking wait the whole window; production observes for 15 s.
    pub fn test_options() -> Options {
        Options::default().with_loopback(true).with_times(|t| {
            t.observe_ms = 4000;
            t.settle_ms = 1200;
            t.find_ms = 600;
        })
    }

    pub async fn launch(chrome: &Path, profile: &Path, provider: Value, guard: PathBuf) -> Lane {
        let browser = Browser::launch(LaunchOptions {
            executable: chrome.to_owned(),
            headless: true,
            user_data_dir: Some(profile.to_owned()),
            args: vec![],
        })
        .await
        .unwrap();
        Lane {
            browser: Arc::new(browser),
            records: Arc::default(),
            provider: Some(provider),
            guard,
            options: Self::test_options(),
            serializer: Serializer::default(),
            echoes: Arc::default(),
        }
    }

    /// Another engine on the same records (`new Engine(config, e.bridge, options)`).
    pub fn with(&self, provider: Option<Value>, options: Options) -> Lane {
        Lane { provider, options, ..self.clone() }
    }

    pub fn get(&self, id: &str) -> Option<Arc<Rec>> {
        self.records.lock().unwrap().get(id).cloned()
    }

    pub fn has(&self, id: &str) -> bool {
        self.records.lock().unwrap().contains_key(id)
    }

    pub fn forget(&self, id: &str) {
        if let Some(r) = self.records.lock().unwrap().remove(id) {
            r.st.lock().unwrap().current = false;
        }
    }

    async fn adopt(&self, page: Page, owner: &str, by_engine: bool) -> Arc<Rec> {
        prepare(&page).await;
        let id = format!("p{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let target = page.target_id().unwrap_or_default().to_owned();
        let r = Arc::new(Rec {
            id: id.clone(),
            owner: owner.to_owned(),
            owned: by_engine,
            target,
            browser: Arc::clone(&self.browser),
            page: Mutex::new(page),
            st: Mutex::new(RecState { current: true, ..RecState::default() }),
        });
        self.records.lock().unwrap().insert(id, Arc::clone(&r));
        r
    }

    /// `e.open(owner, {url})`: an agent page.
    pub async fn open(&self, owner: &str, url: &str) -> Arc<Rec> {
        let page = self.browser.new_page().await.unwrap();
        page.goto(url, Duration::from_secs(30)).await.unwrap();
        self.adopt(page, owner, true).await
    }

    /// [`Self::open`] as the engine opens an agent page: its passkey requests counted
    /// (`PageOptions::watch_passkeys`). A virtual authenticator answers its `WebAuthn` first, so a
    /// request that reaches the browser's own never opens an OS dialog (docs/TESTING.md § 4 rule 9).
    pub async fn open_watched(&self, owner: &str, url: &str) -> Arc<Rec> {
        let page = self
            .browser
            .new_page_with(PageOptions { watch_passkeys: true, ..PageOptions::default() })
            .await
            .unwrap();
        page.send("WebAuthn.enable", json!({})).await.unwrap();
        let options = json!({"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": true,
            "hasUserVerification": true, "isUserVerified": true,
        }});
        page.send("WebAuthn.addVirtualAuthenticator", options).await.unwrap();
        page.goto(url, Duration::from_secs(30)).await.unwrap();
        self.adopt(page, owner, true).await
    }

    /// `e.attach(owner, {tabId})` on a tab the owner opened.
    pub async fn attach_owner_tab(&self, owner: &str, url: &str) -> Arc<Rec> {
        let page = self.browser.new_page().await.unwrap();
        page.goto(url, Duration::from_secs(30)).await.unwrap();
        self.adopt(page, owner, false).await
    }

    /// `e.close(owner, page)`.
    pub async fn close(&self, r: &Rec) {
        let _ = SignInRecord::page(r).close().await;
        self.forget(&r.id);
    }

    /// Whether a page target is still open in the browser.
    pub async fn tab_open(&self, target: &str) -> bool {
        let res = self.browser.connection().send(None, "Target.getTargets", json!({})).await.unwrap();
        res["targetInfos"].as_array().is_some_and(|ts| ts.iter().any(|t| t["targetId"] == target))
    }

    pub async fn close_all(&self) {
        let all: Vec<Arc<Rec>> = self.records.lock().unwrap().values().cloned().collect();
        for r in all {
            self.close(&r).await;
        }
    }

    /// Another agent's call through the engine's queue: the page title.
    pub async fn serializer_run_title(&self, r: &Rec) -> Value {
        self.serializer.run(r.eval_main("()=>document.title")).await
    }

    pub async fn sign(&self, client: &str, id: &str, args: &Value) -> EngineResult {
        let mut a = json!({"pageId": id});
        for (k, v) in args.as_object().into_iter().flatten() {
            a[k] = v.clone();
        }
        phantab::signin::sign_in(self, client, &a).await
    }
}

/// The fake provider's control file and log, in a temp runtime with the guard file.
pub struct Fixture {
    pub runtime: tempfile::TempDir,
    pub server: FixtureServer,
}

impl Fixture {
    pub fn new() -> Fixture {
        let runtime = tempfile::Builder::new().prefix("phantab-sign-in-").tempdir().unwrap();
        Fixture { runtime, server: FixtureServer::start().unwrap() }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.runtime.path().join(name)
    }

    pub fn guard(&self) -> PathBuf {
        self.path("sign-in-guard.json")
    }

    pub fn profile(&self) -> PathBuf {
        self.path("profile")
    }

    pub fn provider(&self) -> Value {
        json!({"command": [FAKE, self.path("provider.json")]})
    }

    pub fn url(&self, page: &str) -> String {
        self.server.url(&format!("/sign-in/{page}"))
    }

    pub fn signup_url(&self, page: &str) -> String {
        self.server.url(&format!("/signup/{page}"))
    }

    pub fn control(&self, fields: &Value) {
        let mut c = json!({
            "log": self.path("asked.jsonl"),
            "values": {"username": USERNAME, "password": PASSWORD, "code": CODE},
        });
        for (k, v) in fields.as_object().into_iter().flatten() {
            c[k] = v.clone();
        }
        std::fs::write(self.path("provider.json"), c.to_string()).unwrap();
    }

    pub fn requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.path("asked.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// `reset()`: no guard file, no log, no posts, the default control.
    pub fn reset(&self) {
        let _ = std::fs::remove_file(self.guard());
        let _ = std::fs::remove_file(self.path("asked.jsonl"));
        self.server.clear_requests();
        self.control(&json!({}));
    }
}

/// The statuses reached and every result, for the no-leak check at the end.
#[derive(Default)]
pub struct Seen {
    pub statuses: Mutex<BTreeSet<String>>,
    pub results: Mutex<Vec<String>>,
}

impl Seen {
    pub fn note(&self, result: &Value) {
        if let Some(s) = result["status"].as_str() {
            self.statuses.lock().unwrap().insert(s.to_owned());
        }
        self.results.lock().unwrap().push(result.to_string());
    }
}
