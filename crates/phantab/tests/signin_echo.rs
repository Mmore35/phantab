//! Lane 3 for a site that shows the password back: `phantab serve` → bridge → engine,
//! against the fake extension on a real headless Chrome (`common/cdp_extension.rs`), the fake provider,
//! and the testkit `sign-in/*` echo fixtures. The sign-in goes on and says `echoed`; from then on no
//! answer the agent gets holds any form of the value (the testkit's `leak_forms`), a screenshot of the
//! tab is refused, a fresh attach to it is still redacted, and the account is not stopped.
//!
//! Skips without `PHANTAB_TEST_CHROME`. Window strategy `None`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/cdp_extension.rs"]
mod cdp_extension;
mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cdp_extension::CdpExtension;
use common::{Runtime, Service, upgrade};
use phantab_cdp::Browser;
use phantab_testkit::FixtureServer;
use phantab_testkit::sign_in::{CODE, PASSWORD, USERNAME, fixture_leak_forms};
use serde_json::{Value, json};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The engine's refusal (`engine::echo::SCREENSHOT_REFUSED`), as far as a test needs it.
const REFUSED: &str = "Screenshot refused: a sign-in on this tab saw the site show the password or code back";

/// The fixtures that show the value back: in the page after a POST, in the URL's query, in the DOM, in
/// the hash as base64, and in the DOM past clobbered globals.
const ECHOES: &[&str] = &["echo", "leak-url", "leak-dom", "leak-hash", "leak-clobber"];

struct Lane {
    ext: CdpExtension,
    browser: Arc<Browser>,
    svc: Service,
    rt: Runtime,
    fixtures: FixtureServer,
    /// Every answer and error the agent got, for the search at the end.
    seen: std::sync::Mutex<Vec<String>>,
}

impl Lane {
    async fn start(chrome: &Path, guardrails: &str) -> Self {
        let fixtures = FixtureServer::start().unwrap();
        let rt = Runtime::new();
        rt.install_extension_in_profile();
        let provider = rt.path().join("provider.json");
        let lane_config = json!({
            "profileDirectory": "test", "userDataDir": rt.user_data_dir(), "chromeExecutable": chrome,
            "guardrails": guardrails,
            "signInProvider": {"command": [env!("CARGO_BIN_EXE_phantab-fake-provider"), provider]},
        });
        rt.write_config(&lane_config);
        let svc = tokio::task::block_in_place(|| {
            let child = rt
                .command(&["serve"])
                .env("PHANTAB_TEST_ALLOW_LOOPBACK", "1")
                .env("PHANTAB_TEST_WINDOWS", "none")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Service { child: Some(child), endpoint: rt.wait_endpoint() }
        });
        let browser = cdp_extension::launch_chrome(chrome).await;
        let auth = format!("Bearer {}", svc.endpoint.token);
        let port = svc.endpoint.port;
        let stream = tokio::task::block_in_place(|| upgrade(port, &[("Authorization", &auth)], "/bridge").1)
            .expect("the bridge upgrade");
        let ext = tokio::task::block_in_place(|| CdpExtension::connect(stream, "echo", Arc::clone(&browser)));
        let lane = Self { ext, browser, svc, rt, fixtures, seen: std::sync::Mutex::default() };
        lane.account("account-one");
        let end = Instant::now() + Duration::from_secs(10);
        while lane.call("status", json!({}), "test").await.map_or(true, |s| s["connected"] != json!(true)) {
            assert!(Instant::now() < end, "the bridge connects");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let status = lane.ok("connect", json!({}), "test").await;
        assert_eq!(status["profileVerified"], json!(true), "{status}");
        lane
    }

    /// The fake provider answers the fixture login under `key`, so each case's limits are its own.
    fn account(&self, key: &str) {
        let control = json!({
            "values": {"username": USERNAME, "password": PASSWORD, "code": CODE}, "accountKey": key,
        });
        std::fs::write(self.rt.path().join("provider.json"), control.to_string()).unwrap();
    }

    async fn call(&self, method: &str, args: Value, client: &str) -> Result<Value, String> {
        let (port, token) = (self.svc.endpoint.port, self.svc.endpoint.token.clone());
        let (method, client) = (method.to_owned(), client.to_owned());
        let v = tokio::task::spawn_blocking(move || common::rpc(port, &token, &method, &args, &client))
            .await
            .unwrap();
        let out = match v.get("error") {
            Some(e) => Err(e.as_str().unwrap_or_default().to_owned()),
            None => Ok(v["result"].clone()),
        };
        let text = match &out {
            Ok(v) => v.to_string(),
            Err(e) => e.clone(),
        };
        self.seen.lock().unwrap().push(text);
        out
    }

    async fn ok(&self, method: &str, args: Value, client: &str) -> Value {
        match self.call(method, args.clone(), client).await {
            Ok(v) => v,
            Err(e) => panic!("{method} {args} for {client}: {e}"),
        }
    }

    /// Whether the tab really shows a value: read through its own session, never printed.
    async fn shows_a_value(&self, tab: i64) -> bool {
        let shown = self
            .ext
            .eval(tab, "[location.href, document.title, document.documentElement.outerHTML].join(' ')")
            .await;
        let shown = shown.as_str().unwrap_or_default().to_owned();
        fixture_leak_forms().iter().any(|f| shown.contains(f.as_str()))
    }

    /// A sign-in on `page` that saw the site show the value back: it went on and said so.
    async fn sign_echoed(&self, page: &str) -> Value {
        let signed = self.ok("sign_in", json!({ "pageId": page }), "a").await;
        assert_ne!(signed["status"], json!("leak-stopped"), "{signed}");
        assert_eq!(signed["echoed"], json!(true), "{signed}");
        let note = signed["note"].as_str().unwrap_or_default();
        assert!(note.contains("redacts") && note.contains("reset"), "{signed}");
        signed
    }

    /// Every read of `page` the agent has: none holds a form of the value, and together they show the
    /// redaction where the value was.
    async fn reads_are_redacted(&self, page: &str) {
        let id = json!({ "pageId": page });
        let mut answers = vec![
            self.ok("snapshot", id.clone(), "a").await,
            self.ok("pages", json!({}), "a").await,
            self.ok("wait", json!({ "pageId": page, "seconds": 0.1 }), "a").await,
            self.ok("act", json!({ "pageId": page, "action": "scroll", "deltaY": 50 }), "a").await,
            self.ok("status", json!({}), "a").await,
        ];
        // The tab list leaves out tabs an agent holds; a released one is in it.
        answers.push(self.ok("tabs", json!({}), "a").await);
        let all: Vec<String> = answers.iter().map(Value::to_string).collect();
        assert_eq!(leaked(&all.join("\n")), None, "an answer holds a form of the value");
        assert!(all[0].contains("[redacted]") || all[1].contains("[redacted]"), "the value was in the page");
        let shot = self.call("screenshot", id, "a").await.unwrap_err();
        assert!(shot.starts_with(REFUSED), "{shot}");
    }

    async fn finish(self) {
        let all = self.seen.lock().unwrap().join("\n");
        assert_eq!(leaked(&all), None, "an answer or error holds a form of the value");
        // The runtime folder, but the fake provider's own control file, which holds the fixture login.
        let mut searched = 0;
        for file in walk(self.rt.path()) {
            if file.file_name().is_some_and(|n| n == "provider.json") {
                continue;
            }
            let text = String::from_utf8_lossy(&std::fs::read(&file).unwrap_or_default()).into_owned();
            searched += 1;
            assert_eq!(leaked(&text), None, "{} holds a form of the value", file.display());
        }
        assert!(searched >= 2, "searched {searched} files");
        let Self { ext, browser, svc, rt, fixtures, .. } = self;
        drop(ext);
        tokio::task::block_in_place(|| drop(svc));
        let _ = browser.close().await;
        drop(rt);
        drop(fixtures);
    }
}

/// The index of the first leak form in `text`: a failure names it, never the form.
fn leaked(text: &str) -> Option<usize> {
    fixture_leak_forms().iter().position(|f| text.contains(f.as_str()))
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// On an agent page of each echo fixture, under `guardrails: full` (whose sign-in stops are on): the
/// sign-in goes on and says `echoed`, every read comes back redacted, a screenshot of the tab is
/// refused, and the account is not stopped (its next sign-in submits).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_echo_is_redacted_from_every_answer_and_the_sign_in_goes_on() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome, "full").await;

    for fixture in ECHOES {
        lane.account(&format!("account-{fixture}"));
        let opened =
            lane.ok("open", json!({ "url": lane.fixtures.url(&format!("/sign-in/{fixture}")) }), "a").await;
        let page = opened["pageId"].as_str().unwrap().to_owned();
        let tab = lane.ext.last_window_tab();
        lane.sign_echoed(&page).await;
        assert!(lane.shows_a_value(tab).await, "{fixture}: the page still shows the value");
        lane.reads_are_redacted(&page).await;

        // Not stopped: the same account signs in again on a page that does not echo.
        let one = lane.ok("open", json!({ "url": lane.fixtures.url("/sign-in/one") }), "a").await;
        let one = one["pageId"].as_str().unwrap().to_owned();
        let signed = lane.ok("sign_in", json!({ "pageId": one }), "a").await;
        assert_eq!(signed, json!({"status": "submitted"}), "{fixture}");
        // The text stays redacted on every page, the screenshot refusal only on the echo's tab.
        let shot = lane.ok("screenshot", json!({ "pageId": one }), "a").await;
        assert!(shot["data"].as_str().is_some_and(|d| !d.is_empty()), "{fixture}");
        lane.ok("close", json!({ "pageId": one }), "a").await;
        lane.ok("close", json!({ "pageId": page }), "a").await;
    }
    lane.finish().await;
}

/// On the owner's own tab, under `guardrails: light`: the sign-in goes on, the tab stays open after the
/// agent lets it go, its title and URL in the tab list come back redacted, and a fresh attach to it is
/// still redacted and still refuses screenshots.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_attach_to_an_echoing_tab_is_still_redacted_and_refuses_screenshots() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome, "light").await;

    let url = lane.fixtures.url("/sign-in/leak-url");
    let tab = lane.ext.open_owner_tab(&url).await;
    let end = Instant::now() + Duration::from_secs(10);
    let loaded = format!("location.href === {} && document.readyState === 'complete'", json!(url));
    while lane.ext.eval(tab, &loaded).await != json!(true) {
        assert!(Instant::now() < end, "the owner's tab loads");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let attached = lane.ok("attach", json!({ "tabId": tab.to_string() }), "a").await;
    let page = attached["pageId"].as_str().unwrap().to_owned();
    lane.sign_echoed(&page).await;
    lane.reads_are_redacted(&page).await;
    lane.ok("close", json!({ "pageId": page }), "a").await;
    assert!(lane.ext.tab_open(tab).await, "the owner's tab stays open");
    assert!(lane.shows_a_value(tab).await, "the owner's tab still shows the value");

    // Let go, it is in the tab list: its URL is redacted there.
    let tabs = lane.ok("tabs", json!({}), "a").await;
    let listed = tabs.to_string();
    assert!(listed.contains(&tab.to_string()) && listed.contains("[redacted]"), "{tabs}");
    assert_eq!(leaked(&listed), None);

    // Another session attaches it afresh: a new record, the same tab.
    let again = lane.ok("attach", json!({ "tabId": tab.to_string() }), "b").await;
    let page = again["pageId"].as_str().unwrap().to_owned();
    assert_eq!(leaked(&again.to_string()), None);
    let snap = lane.ok("snapshot", json!({ "pageId": page }), "b").await;
    assert!(snap.to_string().contains("[redacted]"), "{snap}");
    let shot = lane.call("screenshot", json!({ "pageId": page }), "b").await.unwrap_err();
    assert!(shot.starts_with(REFUSED), "{shot}");
    lane.ok("close", json!({ "pageId": page }), "b").await;

    // Closed by hand, the tab's mark goes with it; another tab's screenshots work.
    lane.ext.close_tab_by_hand(tab).await;
    let opened = lane.ok("open", json!({ "url": lane.fixtures.url("/sign-in/one") }), "b").await;
    let other = opened["pageId"].as_str().unwrap().to_owned();
    lane.ok("screenshot", json!({ "pageId": other }), "b").await;
    lane.ok("close", json!({ "pageId": other }), "b").await;
    lane.finish().await;
}
