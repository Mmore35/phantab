//! Lane 3: the whole path, `phantab serve` → bridge → engine → relay pages, against a fake extension that
//! does every bridge op on a real headless Chrome (`common/cdp_extension.rs`). The real-browser engine
//! cases that need no OS window: ownership and site locks, waits, actions, snapshots of
//! shadow roots and frames, screenshots, show and resume, the isolated live view, tab end, release and a
//! dropped bridge; plus the same service driven through `phantab mcp` and the command line.
//!
//! Skips without `PHANTAB_TEST_CHROME`. Window strategy `None` (`PHANTAB_TEST_WINDOWS=none`): the windows
//! are headless. The tests take turns, so at most one test Chrome (and one isolated one) runs at a time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "a lane test reads as one story of pages a, b, c"
)]

#[path = "common/cdp_extension.rs"]
mod cdp_extension;
mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cdp_extension::CdpExtension;
use common::{Runtime, Service, upgrade};
use phantab_cdp::Browser;
use phantab_testkit::FixtureServer;
use serde_json::{Value, json};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One service on a temp runtime, with the CDP-backed extension connected to it.
struct Lane {
    ext: CdpExtension,
    browser: Arc<Browser>,
    svc: Service,
    rt: Runtime,
    fixtures: FixtureServer,
}

impl Lane {
    /// `full`, so the handback rules below still hold (docs/GUARDRAILS.md).
    async fn start(chrome: &PathBuf) -> Self {
        Self::start_with(chrome, "full").await
    }

    /// `full`, with one writer per site (`siteLock: exclusive`, docs/GUARDRAILS.md).
    async fn start_exclusive(chrome: &PathBuf) -> Self {
        Self::start_config(chrome, "full", &json!({ "siteLock": "exclusive" })).await
    }

    async fn start_with(chrome: &PathBuf, guardrails: &str) -> Self {
        Self::start_config(chrome, guardrails, &json!({})).await
    }

    /// With the developer tools on (`"devTools": true`, THREAT-MODEL SR-90).
    async fn start_dev_tools(chrome: &PathBuf, guardrails: &str) -> Self {
        Self::start_config(chrome, guardrails, &json!({ "devTools": true })).await
    }

    /// `more`: the config's other settings, such as `siteLock` or `devTools`.
    async fn start_config(chrome: &PathBuf, guardrails: &str, more: &Value) -> Self {
        Self::start_all(chrome, guardrails, more, false).await
    }

    /// With sign-in: the service's one provider is the fixture provider (never a real vault) over
    /// `vault.json` in the runtime, the fixture login saved for the fixture site, and it may fill on the
    /// loopback fixture server. A sign-up saves its new login in the same file;
    /// [`Lane::provider_asked`] counts what was asked.
    async fn start_signing(chrome: &PathBuf, guardrails: &str, more: &Value) -> Self {
        Self::start_all(chrome, guardrails, more, true).await
    }

    async fn start_all(chrome: &PathBuf, guardrails: &str, more: &Value, signing: bool) -> Self {
        let fixtures = FixtureServer::start().unwrap();
        let rt = Runtime::new();
        rt.install_extension_in_profile();
        let mut config = json!({
            "profileDirectory": "test", "userDataDir": rt.user_data_dir(), "chromeExecutable": chrome,
            "guardrails": guardrails,
        });
        for (k, v) in more.as_object().into_iter().flatten() {
            config[k] = v.clone();
        }
        if signing {
            use phantab_testkit::sign_in::{CODE, PASSWORD, USERNAME};
            use sha2::{Digest as _, Sha256};
            let provider = env!("CARGO_BIN_EXE_phantab-fixture-provider");
            let vault = rt.path().join("vault.json");
            let saved = json!({ "log": rt.path().join("provider-log.jsonl"),
                                "logins": [{ "id": "fixture-1", "origin": fixtures.origin(), "username": USERNAME,
                                             "password": PASSWORD, "totp": CODE }] });
            std::fs::write(&vault, saved.to_string()).unwrap();
            let pin = phantab::util::hex(&Sha256::digest(std::fs::read(provider).unwrap()));
            config["signInProviders"] = json!([{ "name": "default", "command": [provider, vault],
                                                 "caps": ["lookup", "totp", "create"], "pin": { provider: pin } }]);
        }
        rt.write_config(&config);
        let svc = tokio::task::block_in_place(|| {
            let mut serve = rt.command(&["serve"]);
            if signing {
                serve.env("PHANTAB_TEST_ALLOW_LOOPBACK", "1");
            }
            let child = serve
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
        let ext =
            tokio::task::block_in_place(|| CdpExtension::connect(stream, "lane3", Arc::clone(&browser)));
        let lane = Self { ext, browser, svc, rt, fixtures };
        assert!(
            lane.until(Duration::from_secs(10), async || lane.status().await["connected"] == json!(true))
                .await
        );
        let status = lane.call("connect", json!({}), "test").await.unwrap();
        assert_eq!(status["profileVerified"], json!(true), "{status}");
        lane
    }

    async fn call(&self, method: &str, args: Value, client: &str) -> Result<Value, String> {
        let (port, token) = (self.svc.endpoint.port, self.svc.endpoint.token.clone());
        let (method, client) = (method.to_owned(), client.to_owned());
        let v = tokio::task::spawn_blocking(move || common::rpc(port, &token, &method, &args, &client))
            .await
            .unwrap();
        match v.get("error") {
            Some(e) => Err(e.as_str().unwrap_or_default().to_owned()),
            None => Ok(v["result"].clone()),
        }
    }

    async fn ok(&self, method: &str, args: Value, client: &str) -> Value {
        match self.call(method, args.clone(), client).await {
            Ok(v) => v,
            Err(e) => panic!("{method} {args} for {client}: {e}"),
        }
    }

    async fn err(&self, method: &str, args: Value, client: &str) -> String {
        match self.call(method, args.clone(), client).await {
            Ok(v) => panic!("{method} {args} for {client} succeeded: {v}"),
            Err(e) => e,
        }
    }

    /// How many requests the fixture provider was sent ([`Lane::start_signing`]).
    fn provider_asked(&self) -> usize {
        std::fs::read_to_string(self.rt.path().join("provider-log.jsonl"))
            .map_or(0, |log| log.lines().filter(|l| !l.trim().is_empty()).count())
    }

    async fn status(&self) -> Value {
        self.call("status", json!({}), "test").await.unwrap_or(Value::Null)
    }

    async fn open(&self, client: &str, path: &str) -> String {
        let r = self.ok("open", json!({ "url": self.fixtures.url(path) }), client).await;
        r["pageId"].as_str().unwrap().to_owned()
    }

    async fn act(&self, client: &str, page: &str, mut args: Value) -> Result<Value, String> {
        args["pageId"] = json!(page);
        self.call("act", args, client).await
    }

    async fn snap(&self, client: &str, page: &str) -> Value {
        self.ok("snapshot", json!({ "pageId": page }), client).await
    }

    async fn viewer(&self, token: &str, action: &str, args: Value) -> Result<Value, String> {
        let port = self.svc.endpoint.port;
        let auth = format!("Bearer {token}");
        let body = json!({ "action": action, "args": args }).to_string();
        let v = tokio::task::spawn_blocking(move || {
            common::request(port, "POST", "/viewer", &[("Authorization", &auth)], body.as_bytes())
                .unwrap()
                .json()
        })
        .await
        .unwrap();
        match v.get("error") {
            Some(e) => Err(e.as_str().unwrap_or_default().to_owned()),
            None => Ok(v["result"].clone()),
        }
    }

    async fn until(&self, within: Duration, mut check: impl AsyncFnMut() -> bool) -> bool {
        let end = Instant::now() + within;
        while Instant::now() < end {
            if check().await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        check().await
    }

    async fn finish(self) {
        let Self { ext, browser, svc, rt, fixtures } = self;
        drop(ext);
        tokio::task::block_in_place(|| drop(svc));
        let _ = browser.close().await;
        drop(rt);
        drop(fixtures);
    }
}

fn element<'a>(snap: &'a Value, id: &str) -> Option<&'a Value> {
    snap["elements"].as_array()?.iter().find(|e| e["id"] == json!(id))
}

fn text(snap: &Value) -> &str {
    snap["text"].as_str().unwrap_or_default()
}

fn ms(since: Instant) -> u128 {
    since.elapsed().as_millis()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_pages_through_the_service_ownership_site_locks_waits_actions_and_tab_end() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    // One writer per site, so the site lock below is the one a write takes (the default shares the site:
    // `agents_share_a_site_by_default_*`).
    let lane = Lane::start_exclusive(&chrome).await;

    let t = Instant::now();
    let a = lane.open("a", "/engine/basic").await;
    let open_ms = ms(t);
    let b = lane.open("b", "/engine/basic").await;
    let t = Instant::now();
    let snap = lane.snap("a", &a).await;
    let snapshot_ms = ms(t);
    assert_eq!(snap["title"], json!("Browser fixture"));
    assert_eq!(snap["mode"], json!("shared-hidden"), "{snap}");
    assert_eq!(snap["ownsTab"], json!(true));
    assert!(element(&snap, "name").is_some() && element(&snap, "go").is_some(), "{snap}");

    // Ownership and the site lock a write takes.
    let t = Instant::now();
    lane.act("a", &a, json!({ "action": "fill", "selector": "#name", "text": "unsaved draft" }))
        .await
        .unwrap();
    let act_ms = ms(t);
    assert!(lane.err("snapshot", json!({ "pageId": a }), "b").await.contains("belongs"));
    let held = lane.act("b", &b, json!({ "action": "click", "selector": "#go" })).await.unwrap_err();
    assert!(held.contains("holds this site"), "{held}");
    lane.act("a", &a, json!({ "action": "click", "selector": "#go" })).await.unwrap();
    assert!(text(&lane.snap("a", &a).await).contains("unsaved draft"));
    // The other page shares the profile, not the page.
    assert!(!text(&lane.snap("b", &b).await).contains("unsaved draft"));
    let pages = lane.ok("pages", json!({}), "a").await;
    assert_eq!(pages.as_array().unwrap().len(), 1, "{pages}");

    // Show with no OS window work (strategy None), then the handback rules.
    let t = Instant::now();
    let shown = lane.ok("show", json!({ "pageId": a }), "a").await;
    let show_ms = ms(t);
    assert_eq!(shown["handoff"], json!("actual-tab"), "{shown}");
    let handed = lane.act("a", &a, json!({ "action": "click", "selector": "#go" })).await.unwrap_err();
    assert!(handed.contains("handed"), "{handed}");
    assert!(lane.err("resume", json!({ "pageId": a }), "a").await.contains("Wait for owner handback"));
    assert!(lane.err("close", json!({ "pageId": a }), "a").await.contains("handed"));
    lane.ok("resume", json!({ "pageId": a, "ownerConfirmed": true }), "a").await;
    assert!(text(&lane.snap("a", &a).await).contains("unsaved draft"));
    let shot = lane.ok("screenshot", json!({ "pageId": a }), "a").await;
    assert!(shot["data"].as_str().unwrap().starts_with("/9j/"), "a JPEG");

    // Closing frees the site for the other agent.
    let t = Instant::now();
    lane.ok("close", json!({ "pageId": a }), "a").await;
    assert!(t.elapsed() < Duration::from_secs(5), "close returns promptly");
    lane.act("b", &b, json!({ "action": "fill", "selector": "#name", "text": "agent b" })).await.unwrap();
    lane.act("b", &b, json!({ "action": "click", "selector": "#go" })).await.unwrap();
    assert!(text(&lane.snap("b", &b).await).contains("agent b"));
    lane.ok("close", json!({ "pageId": b }), "b").await;

    // Controls: fill, select, press, scroll, navigate.
    let c = lane.open("c", "/forms/controls").await;
    lane.act("c", &c, json!({ "action": "fill", "selector": "#text", "text": "typed words" })).await.unwrap();
    lane.act("c", &c, json!({ "action": "select", "selector": "#choice", "text": "two" })).await.unwrap();
    // A select also takes the label a person sees, and one that matches no option fails, naming them; a
    // snapshot shows the option a select shows and which boxes are ticked.
    lane.act("c", &c, json!({ "action": "select", "selector": "#choice", "text": "One" })).await.unwrap();
    let wrong =
        lane.act("c", &c, json!({ "action": "select", "selector": "#choice", "text": "Three" })).await;
    let wrong = wrong.unwrap_err();
    assert!(
        wrong.starts_with("#choice: no option has the value or label \"Three\"")
            && wrong.contains("\"Two\" (value \"two\")"),
        "{wrong}"
    );
    lane.act("c", &c, json!({ "action": "click", "selector": "#agree" })).await.unwrap();
    let snap = lane.snap("c", &c).await;
    let control =
        |id: &str| snap["elements"].as_array().unwrap().iter().find(|e| e["id"] == json!(id)).cloned();
    assert_eq!(control("choice").unwrap()["selected"], json!("One"), "{snap}");
    assert_eq!(control("agree").unwrap()["checked"], json!(true), "{snap}");
    assert!(control("radio-a").unwrap().get("checked").is_none(), "{snap}");
    assert!(control("filled").unwrap().get("selected").is_none() && !snap.to_string().contains("never-read"));
    lane.act("c", &c, json!({ "action": "click", "selector": "#text" })).await.unwrap();
    lane.act("c", &c, json!({ "action": "press", "key": "Enter" })).await.unwrap();
    assert!(text(&lane.snap("c", &c).await).contains("submitted typed words"));
    lane.act("c", &c, json!({ "action": "scroll", "deltaY": 400 })).await.unwrap();
    let missing = lane.act("c", &c, json!({ "action": "click", "selector": "#disabled" })).await.unwrap_err();
    assert!(missing.starts_with("#disabled: disabled after"), "{missing}");
    // A selector the loaded page has no element for fails once the page has stopped changing, not after
    // the full 10 s.
    let t = Instant::now();
    let absent = lane.act("c", &c, json!({ "action": "click", "selector": "#nowhere" })).await.unwrap_err();
    assert!(
        absent.starts_with("#nowhere: not found after ") && absent.contains("stopped changing"),
        "{absent}"
    );
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    let bad = lane.act("c", &c, json!({ "action": "click", "selector": "a >> nth=0" })).await.unwrap_err();
    assert!(bad.contains("not a valid selector"), "{bad}");
    let twin = lane.fixtures.twin_url("/engine/basic");
    let moved = lane.act("c", &c, json!({ "action": "navigate", "url": twin })).await.unwrap();
    assert_eq!(moved["url"], json!(twin), "{moved}");
    assert_eq!(lane.snap("c", &c).await["title"], json!("Browser fixture"));

    // Waits: selector and text across a navigation, seconds, and none of them.
    let w = lane.open("c", "/engine/moves").await;
    lane.ok("wait", json!({ "pageId": w, "selector": "#ok", "text": "Visible words" }), "c").await;
    let t = Instant::now();
    lane.ok("wait", json!({ "pageId": w, "seconds": 0.3 }), "c").await;
    assert!(t.elapsed() >= Duration::from_millis(290));
    assert!(
        lane.err("wait", json!({ "pageId": w }), "c").await.contains("selector, visible text or seconds")
    );
    // A page closed during a wait says so promptly.
    let waiting = {
        let (port, token) = (lane.svc.endpoint.port, lane.svc.endpoint.token.clone());
        let w = w.clone();
        tokio::task::spawn_blocking(move || {
            common::rpc(port, &token, "wait", &json!({ "pageId": w, "selector": "#never" }), "c")
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    let t = Instant::now();
    lane.ok("close", json!({ "pageId": w }), "c").await;
    let ended = waiting.await.unwrap();
    assert!(ended["error"].as_str().unwrap_or_default().contains("closed"), "{ended}");
    assert!(t.elapsed() < Duration::from_secs(5));

    // The owner closing an agent tab by hand ends its record.
    let tab = lane.ext.last_window_tab();
    let gone = lane.open("d", "/engine/basic").await;
    let gone_tab = lane.ext.last_window_tab();
    assert_ne!(tab, gone_tab);
    lane.ext.close_tab_by_hand(gone_tab).await;
    assert!(
        lane.until(Duration::from_secs(5), async || lane.ok("pages", json!({}), "d").await == json!([]))
            .await,
        "the record of a closed tab ends ({gone})"
    );

    // An owner tab: listed, attached, and left open by close.
    let owner_url = lane.fixtures.url("/engine/login");
    let owner_tab = lane.ext.open_owner_tab(&owner_url).await;
    let tabs = lane.ok("tabs", json!({}), "e").await;
    let listed = tabs.as_array().unwrap().iter().find(|t| t["url"] == json!(owner_url)).cloned();
    assert_eq!(listed.as_ref().map(|t| t["tabId"].clone()), Some(json!(owner_tab.to_string())), "{tabs}");
    let attached = lane.ok("attach", json!({ "tabId": owner_tab.to_string() }), "e").await;
    assert_eq!(attached["ownsTab"], json!(false), "{attached}");
    assert_eq!(lane.snap("e", attached["pageId"].as_str().unwrap()).await["title"], json!("Login fixture"));
    lane.ok("close", json!({ "pageId": attached["pageId"] }), "e").await;
    assert!(lane.ext.tab_open(owner_tab).await, "an owner tab stays open");

    // Release ends a client's pages; its tab closes.
    let b_tab = lane.ext.last_window_tab();
    let r = lane.open("r", "/engine/handoff").await;
    let r_tab = lane.ext.last_window_tab();
    assert_ne!(b_tab, r_tab);
    lane.ok("release", json!({}), "r").await;
    assert!(lane.until(Duration::from_secs(5), async || !lane.ext.tab_open(r_tab).await).await, "{r}");

    // A dropped bridge ends every relay page.
    let kept = lane.open("h", "/engine/basic").await;
    let mut lane = lane;
    lane.ext.hang_up();
    assert!(
        lane.until(Duration::from_secs(10), async || lane.status().await["connected"] == json!(false)).await
    );
    let after = lane.err("snapshot", json!({ "pageId": kept }), "h").await;
    assert!(after.contains("Unknown page"), "{after}");
    let status = lane.status().await;
    assert!(status["lastDisconnect"]["reason"].is_string(), "{status}");
    let _ = tab;

    eprintln!(
        "lane3 timings: open {open_ms} ms, snapshot {snapshot_ms} ms, act {act_ms} ms, show {show_ms} ms"
    );
    lane.finish().await;
}

/// The fill a second agent makes on a site where the first agent has a page (the plan's run E).
fn fill_b() -> Value {
    json!({ "action": "fill", "selector": "#name", "text": "agent b" })
}

/// `siteLock` absent (`shared`): a second agent's fill on the same site works while the first agent's page
/// is open and while it is handed to the owner. The handed-over page still refuses its own agent's write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_share_a_site_by_default_and_a_handed_over_page_refuses_only_itself() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;

    let a = lane.open("a", "/engine/basic").await;
    let b = lane.open("b", "/engine/basic").await;
    lane.act("a", &a, json!({ "action": "fill", "selector": "#name", "text": "agent a" })).await.unwrap();
    lane.act("b", &b, fill_b()).await.unwrap();
    lane.act("b", &b, json!({ "action": "click", "selector": "#go" })).await.unwrap();
    assert!(text(&lane.snap("b", &b).await).contains("agent b"));

    lane.ok("show", json!({ "pageId": a }), "a").await;
    let own = lane.act("a", &a, json!({ "action": "click", "selector": "#go" })).await.unwrap_err();
    assert!(own.contains("handed to the owner"), "{own}");
    lane.act("b", &b, json!({ "action": "fill", "selector": "#name", "text": "while a is shown" }))
        .await
        .unwrap();
    lane.act("b", &b, json!({ "action": "click", "selector": "#go" })).await.unwrap();
    assert!(text(&lane.snap("b", &b).await).contains("while a is shown"));
    // The first agent's draft is still its own.
    assert!(!text(&lane.snap("a", &a).await).contains("agent b"));
    lane.finish().await;
}

/// `siteLock: exclusive`: the same fill is refused while the first agent's page is open and while it is
/// handed over, as before the setting; the handed-over page refuses its own agent too. Then the step-1
/// measurement: a shown page the owner submits stays a paused record that holds the site and that
/// `browser_pages` lists, until the owner closes its tab, which ends the record and frees the site.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_site_lock_exclusive_one_writer_holds_the_site_until_the_owner_closes_the_tab() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_exclusive(&chrome).await;

    let a = lane.open("a", "/engine/basic").await;
    let a_tab = lane.ext.last_window_tab();
    let b = lane.open("b", "/engine/basic").await;
    lane.act("a", &a, json!({ "action": "fill", "selector": "#name", "text": "agent a" })).await.unwrap();
    let held = lane.act("b", &b, fill_b()).await.unwrap_err();
    assert!(held.contains("holds this site"), "{held}");

    lane.ok("show", json!({ "pageId": a }), "a").await;
    let own = lane.act("a", &a, json!({ "action": "click", "selector": "#go" })).await.unwrap_err();
    assert!(own.contains("handed to the owner"), "{own}");
    let held = lane.act("b", &b, fill_b()).await.unwrap_err();
    assert!(held.contains("holds this site"), "{held}");

    // The owner submits the shown page: the record stays, paused, and still holds the site.
    lane.ext.eval(a_tab, "document.querySelector('#go').click()").await;
    assert_eq!(lane.ext.eval(a_tab, "document.querySelector('#result').textContent").await, json!("agent a"));
    let pages = lane.ok("pages", json!({}), "a").await;
    let listed = pages.as_array().unwrap();
    assert_eq!(listed.len(), 1, "{pages}");
    assert_eq!((listed[0]["pageId"].as_str(), &listed[0]["paused"]), (Some(a.as_str()), &json!(true)));
    assert!(lane.act("b", &b, fill_b()).await.unwrap_err().contains("holds this site"));
    eprintln!("measurement: after the owner's submit, browser_pages lists {pages}");

    // The owner closes the tab: the record ends, and with it the hold.
    lane.ext.close_tab_by_hand(a_tab).await;
    assert!(
        lane.until(Duration::from_secs(5), async || lane.ok("pages", json!({}), "a").await == json!([]))
            .await
    );
    assert!(lane.err("snapshot", json!({ "pageId": a }), "a").await.contains("Unknown page"));
    lane.act("b", &b, fill_b()).await.unwrap();
    eprintln!("measurement: after the owner closes the tab, browser_pages lists []");
    lane.finish().await;
}

/// `browser_show` with `release: true`: the page is the owner's ordinary tab from then on. `browser_pages`
/// no longer lists it, the tab stays open with what the agent left in it, its debugger is detached, and no
/// hold on the site remains, not even under `siteLock: exclusive`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn show_with_release_gives_the_tab_to_the_owner_for_good() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_exclusive(&chrome).await;

    let a = lane.open("a", "/engine/basic").await;
    let a_tab = lane.ext.last_window_tab();
    let b = lane.open("b", "/engine/basic").await;
    lane.act("a", &a, json!({ "action": "fill", "selector": "#name", "text": "for the owner" }))
        .await
        .unwrap();
    let released = lane.ok("show", json!({ "pageId": a, "release": true }), "a").await;
    assert_eq!(released["handoff"], json!("released"), "{released}");
    assert_eq!(released["pageId"], json!(a), "{released}");
    assert_eq!(lane.ok("pages", json!({}), "a").await, json!([]));
    assert!(lane.err("snapshot", json!({ "pageId": a }), "a").await.contains("Unknown page"));
    assert!(lane.err("resume", json!({ "pageId": a }), "a").await.contains("Unknown page"));
    assert!(lane.ext.tab_open(a_tab).await, "the tab stays open");
    assert_eq!(
        lane.ext.eval(a_tab, "document.querySelector('#name').value").await,
        json!("for the owner"),
        "what the agent left in it stays"
    );
    assert!(lane.ext.ops().iter().any(|o| o == "detach"), "{:?}", lane.ext.ops());
    lane.act("b", &b, fill_b()).await.unwrap();
    lane.ok("close", json!({ "pageId": b }), "b").await;
    // A page already handed over can be released as well.
    let c = lane.open("c", "/engine/basic").await;
    let c_tab = lane.ext.last_window_tab();
    lane.ok("show", json!({ "pageId": c }), "c").await;
    lane.ok("show", json!({ "pageId": c, "release": true }), "c").await;
    assert_eq!(lane.ok("pages", json!({}), "c").await, json!([]));
    assert!(lane.ext.tab_open(c_tab).await);
    lane.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshots_read_shadow_roots_and_website_frames_and_click_xy_reaches_them() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;

    let a = lane.open("a", "/snapshot/deep").await;
    let mut snap = Value::Null;
    let both = lane
        .until(Duration::from_secs(30), async || {
            snap = lane.snap("a", &a).await;
            ["sameframe", "otherframe"].iter().all(|id| element(&snap, id).is_some())
        })
        .await;
    assert!(both, "{snap}");
    for words in ["Page words", "Shadow words", "Frame words"] {
        assert!(text(&snap).contains(words), "{words}: {}", text(&snap));
    }
    assert!(!text(&snap).contains("css-text"));
    assert!(!snap.to_string().contains("never-read"));
    assert_eq!(
        (
            &snap["frames"],
            &snap["framesUnread"],
            &snap["framesSkipped"],
            &snap["elementsOmitted"],
            &snap["shadowRoots"]
        ),
        (&json!(3), &json!(0), &json!(0), &json!(0), &json!(1)),
        "{snap}"
    );
    assert!(element(&snap, "noarea").is_none());
    assert_eq!(element(&snap, "far").unwrap()["offscreen"], json!(true));
    assert_eq!(element(&snap, "light").unwrap()["offscreen"], Value::Null);
    assert_eq!(element(&snap, "shadow").unwrap()["inShadow"], json!(true));
    assert_eq!(element(&snap, "otherframe").unwrap()["frame"], json!(lane.fixtures.twin_origin()));
    // A fill for an open shadow root's element fails saying where click_xy reaches it; a click goes there.
    let inside = element(&snap, "shadow").unwrap();
    let told =
        lane.act("a", &a, json!({ "action": "fill", "selector": "#shadow", "text": "x" })).await.unwrap_err();
    let place = format!("an open shadow root has it at {},{}: click_xy reaches it", inside["x"], inside["y"]);
    assert!(told.starts_with("#shadow: not found in the document (") && told.contains(&place), "{told}");
    let r = lane.act("a", &a, json!({ "action": "click", "selector": "#shadow" })).await;
    assert!(r.is_ok(), "{r:?}");
    for id in ["light", "shadow", "sameframe", "otherframe"] {
        let e = element(&snap, id).unwrap();
        let r = lane.act("a", &a, json!({ "action": "click_xy", "x": e["x"], "y": e["y"] })).await;
        assert!(r.is_ok(), "click_xy on {id} at {},{}: {r:?}", e["x"], e["y"]);
    }
    // A click with a point and no selector clicks there; one with neither says what it needs.
    let r = lane.act("a", &a, json!({ "action": "click", "x": inside["x"], "y": inside["y"] })).await;
    assert!(r.is_ok(), "{r:?}");
    let told = lane.act("a", &a, json!({ "action": "click" })).await.unwrap_err();
    assert!(told.starts_with("Supply a selector to click, or x and y to click at a point."), "{told}");
    // A cross-site frame that has just loaded can miss its first synthetic click in headless Chrome
    // (the browser's hit test does not route to it yet), so a
    // miss is clicked again, and the repeats are counted.
    let mut after = Value::Null;
    let mut again = 0;
    let hit = lane
        .until(Duration::from_secs(10), async || {
            after = lane.snap("a", &a).await;
            let missed: Vec<Value> = ["light", "shadow", "sameframe", "otherframe"]
                .iter()
                .filter_map(|id| element(&after, id).filter(|e| e["text"] != json!("hit")).cloned())
                .collect();
            for e in &missed {
                again += 1;
                let _ = lane.act("a", &a, json!({ "action": "click_xy", "x": e["x"], "y": e["y"] })).await;
            }
            missed.is_empty()
        })
        .await;
    eprintln!("lane3 click_xy repeats {again}");
    assert!(hit, "every click_xy landed: {after}");

    // Past the limits the snapshot keeps the form's controls and counts what it left out.
    let many = lane.open("a", "/snapshot/many").await;
    let mut full = Value::Null;
    let read = lane
        .until(Duration::from_secs(30), async || {
            full = lane.snap("a", &many).await;
            full["framesUnread"] == json!(0) && full["frames"] == json!(20)
        })
        .await;
    assert!(read, "{full}");
    assert_eq!(full["elements"].as_array().unwrap().len(), 180);
    assert_eq!((&full["framesSkipped"], &full["elementsOmitted"]), (&json!(5), &json!(41)), "{full}");
    assert!(element(&full, "last").is_some());

    // Long pages are cut at the text cap; nested open shadow roots are read, closed ones are not.
    let long = lane.open("a", "/snapshot/long-text").await;
    let long = lane.snap("a", &long).await;
    assert!(text(&long).contains("Paragraph 001") && !text(&long).contains("END-OF-LONG-TEXT"));
    assert!(text(&long).encode_utf16().count() <= 18_000);
    let nested = lane.open("a", "/shadow/nested").await;
    let nested = lane.snap("a", &nested).await;
    for words in ["Light words", "Outer shadow words", "Inner shadow words"] {
        assert!(text(&nested).contains(words), "{words}");
    }
    assert!(!text(&nested).contains("Closed shadow words") && !nested.to_string().contains("never-read"));
    assert_eq!(nested["shadowRoots"], json!(2), "{nested}");

    // A same-origin link is written as its path: an agent pays for every repeated origin, and a path
    // resolves against the page it came from. Other origins and schemes stay whole.
    let links = lane.open("a", "/snapshot/links").await;
    let links = lane.snap("a", &links).await;
    assert_eq!(element(&links, "near").unwrap()["href"], json!("/snapshot/inner?n=x#part"), "{links}");
    let away = format!("{}/snapshot/inner?n=y", lane.fixtures.twin_origin());
    assert_eq!(element(&links, "away").unwrap()["href"], json!(away), "{links}");
    assert_eq!(element(&links, "mail").unwrap()["href"], json!("mailto:someone@example.com"), "{links}");

    // A cross-site frame alone.
    let framed = lane.open("a", "/frames/cross-site").await;
    let mut f = Value::Null;
    assert!(
        lane.until(Duration::from_secs(30), async || {
            f = lane.snap("a", &framed).await;
            element(&f, "otherframe").is_some()
        })
        .await,
        "{f}"
    );
    lane.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_isolated_headless_page_is_handed_over_through_the_live_view() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;

    let url = lane.fixtures.url("/engine/handoff");
    let g = lane.ok("open", json!({ "url": url, "mode": "isolated-headless" }), "g").await;
    let g = g["pageId"].as_str().unwrap().to_owned();
    let snap = lane.snap("g", &g).await;
    assert_eq!((&snap["title"], &snap["mode"]), (&json!("Handoff fixture"), &json!("isolated-headless")));
    assert!(lane.ok("screenshot", json!({ "pageId": g }), "g").await["data"].as_str().unwrap().len() > 100);
    lane.act("g", &g, json!({ "action": "fill", "selector": "#draft", "text": "kept" })).await.unwrap();

    let t = Instant::now();
    let shown = lane.ok("show", json!({ "pageId": g }), "g").await;
    let show_ms = ms(t);
    assert_eq!(shown["handoff"], json!("interactive-live-view"), "{shown}");
    assert!(!shown.to_string().contains("/view#"), "the viewer token never goes back to the agent");
    let token = lane.ext.viewer_token().expect("the live view opened in a tab");
    let frame = lane.viewer(&token, "frame", json!({})).await.unwrap();
    assert!(frame["image"].as_str().unwrap().len() > 100);
    lane.viewer(&token, "click", json!({ "x": 20, "y": 20 })).await.unwrap();
    assert_eq!(
        lane.viewer("not-the-token", "frame", json!({})).await.unwrap_err(),
        "This handoff has ended."
    );
    assert!(lane.err("resume", json!({ "pageId": g }), "g").await.contains("Return to agent"));
    assert_eq!(lane.viewer(&token, "handback", json!({})).await.unwrap(), json!({ "ready": true }));
    assert_eq!(
        lane.viewer(&token, "click", json!({ "x": 1, "y": 1 })).await.unwrap_err(),
        "Control has been returned to the agent."
    );
    lane.ok("resume", json!({ "pageId": g }), "g").await;
    assert_eq!(lane.viewer(&token, "frame", json!({})).await.unwrap_err(), "This handoff has ended.");
    lane.act("g", &g, json!({ "action": "click", "selector": "#draft" })).await.unwrap();
    // An isolated page holds no site lock against a shared one.
    let s = lane.open("s", "/engine/handoff").await;
    lane.act("s", &s, json!({ "action": "fill", "selector": "#draft", "text": "shared" })).await.unwrap();
    lane.ok("close", json!({ "pageId": g }), "g").await;
    eprintln!("lane3 isolated show {show_ms} ms");
    lane.finish().await;
}

/// The same service through `phantab mcp` and the command line, as an agent uses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_tools_and_cli_calls_drive_real_pages() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;
    let url = lane.fixtures.url("/engine/basic");

    let (text_of, page) = tokio::task::block_in_place(|| {
        let mut child = lane
            .rt
            .command(&["mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut send = |v: Value| {
            writeln!(stdin, "{v}").unwrap();
            stdin.flush().unwrap();
        };
        send(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "lane3", "version": "1" } } }));
        lines.next().unwrap().unwrap();
        send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        let mut id = 1;
        let mut call = |name: &str, arguments: Value| -> Value {
            id += 1;
            send(
                json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": arguments } }),
            );
            let answer: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
            answer["result"].clone()
        };
        // One call opens the page and reads it.
        let opened = call("browser_open", json!({ "url": url, "snapshot": true }));
        assert_eq!(opened["isError"], Value::Null, "{opened}");
        let read = opened["content"][0]["text"].as_str().unwrap().to_owned();
        let (first, rest) = read.split_once('\n').unwrap();
        let page: Value = serde_json::from_str(first).unwrap();
        let page = page["pageId"].as_str().unwrap().to_owned();
        assert!(rest.starts_with(&format!("{{\"pageId\":\"{page}\"")), "{read}");
        assert!(rest.contains("\nCONTROLS\n") && rest.contains("#go"), "{read}");
        // One call fills, clicks and reads the page after: `then` and `snapshot` are the MCP server's own.
        let filled = call(
            "browser_act",
            json!({ "pageId": page, "action": "fill", "selector": "#name", "text": "from mcp",
                "then": [{ "action": "click", "selector": "#go" }], "snapshot": true }),
        );
        assert_eq!(filled["isError"], Value::Null, "{filled}");
        let text_of = filled["content"][0]["text"].as_str().unwrap_or_default().to_owned();
        // Every action said nothing past its page, so the answer is the snapshot alone.
        assert!(text_of.starts_with(&format!("{{\"pageId\":\"{page}\"")), "{text_of}");
        assert!(text_of.contains("\nCONTROLS"), "{text_of}");
        // A step that fails stops the run and names itself; the ones before it were done.
        let stopped = call(
            "browser_act",
            json!({ "pageId": page, "action": "click", "selector": "#go",
                "then": [{ "action": "navigate", "url": "file:///etc/passwd" }, { "action": "click", "selector": "#go" }] }),
        );
        assert_eq!(stopped["isError"], json!(true), "{stopped}");
        let said = stopped["content"][0]["text"].as_str().unwrap_or_default();
        assert!(said.starts_with("Step 2 of 3 (navigate) failed, the 1 before it was done: "), "{said}");
        assert!(said.contains("Only HTTP(S) website URLs are accepted."), "{said}");
        // `steps` writes each action as a list, and its snapshot comes unasked.
        let listed =
            call("browser_act", json!({ "steps": [["fill", "#name", "by steps"], ["click", "#go"]] }));
        assert_eq!(listed["isError"], Value::Null, "{listed}");
        let said = listed["content"][0]["text"].as_str().unwrap_or_default();
        assert!(said.starts_with(&format!("{{\"pageId\":\"{page}\"")) && said.contains("by steps"), "{said}");
        let quiet =
            call("browser_act", json!({ "steps": [["fill", "#name", "from mcp"]], "snapshot": false }));
        assert_eq!(quiet["isError"], Value::Null, "{quiet}");
        assert!(!quiet["content"][0]["text"].as_str().unwrap_or_default().contains("CONTROLS"), "{quiet}");
        // With snapshot true, the snapshot follows the failure.
        let missed = call(
            "browser_act",
            json!({ "pageId": page, "action": "click", "selector": "#nowhere", "snapshot": true }),
        );
        assert_eq!(missed["isError"], json!(true), "{missed}");
        let said = missed["content"][0]["text"].as_str().unwrap_or_default();
        assert!(said.starts_with("#nowhere: not found after ") && said.contains("\nCONTROLS"), "{said}");
        // A call that leaves pageId out reaches the page the last one named.
        let shot = call("browser_screenshot", json!({}));
        assert_eq!(shot["content"][0]["type"], json!("image"), "{shot}");
        // One saved to a file answers the file, as text.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shot.png");
        let saved = call("browser_screenshot", json!({ "path": path }));
        assert_eq!(saved["content"][0]["type"], json!("text"), "{saved}");
        let said: Value = serde_json::from_str(saved["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(said["path"], json!(path.display().to_string()), "{said}");
        assert_eq!(said["mimeType"], json!("image/png"), "{said}");
        assert!(path.is_file());
        let read = call("browser_snapshot", json!({ "full": true }));
        let said = read["content"][0]["text"].as_str().unwrap_or_default();
        assert!(said.starts_with(&format!("{{\"pageId\":\"{page}\"")), "{said}");
        let closed = call("browser_close", json!({ "pageId": page }));
        assert_eq!(closed["isError"], Value::Null, "{closed}");
        // Once that page is closed, there is none to default to.
        let none = call("browser_act", json!({ "action": "click", "selector": "#go" }));
        assert_eq!(none["isError"], json!(true), "{none}");
        assert!(
            none["content"][0]["text"].as_str().unwrap_or_default().starts_with("No page yet to default to"),
            "{none}"
        );
        drop(stdin);
        let _ = child.wait();
        (text_of, page)
    });
    assert!(text_of.contains("from mcp"), "{text_of}");
    assert_ne!(page, "");

    // The command line, with its client id.
    let cli = |args: &[&str]| {
        let out = lane
            .rt
            .command(args)
            .env("PHANTAB_CLIENT", "cli-task")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        (out.status.code(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
    };
    let (code, out, err) = tokio::task::block_in_place(|| cli(&["open", &json!({ "url": url }).to_string()]));
    assert_eq!(code, Some(0), "{err}");
    let opened: Value = serde_json::from_str(&out).unwrap();
    let id = opened["pageId"].as_str().unwrap().to_owned();
    let (code, out, err) =
        tokio::task::block_in_place(|| cli(&["snapshot", &json!({ "pageId": id }).to_string()]));
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("Browser fixture"), "{out}");
    let (code, _, err) =
        tokio::task::block_in_place(|| cli(&["close", &json!({ "pageId": id }).to_string()]));
    assert_eq!(code, Some(0), "{err}");
    lane.finish().await;
}

/// The values a record's fields hold, as `engine/record`'s snapshot shows them at parity.
const RECORD_VALUES: [(&str, &str); 3] = [
    ("short", "VPN token expired for a test user"),
    ("group", "Network Operations"),
    ("notes", "Called user at 09:10, reset pending."),
];
/// What `engine/record` holds that no snapshot shows, in any mode: a password, a password-change form's
/// other field, a card number and a one-time code.
const RECORD_HIDDEN: [&str; 5] = ["hunter2", "new-secret-1", "a.test.user", "4111111111111111", "123456"];

/// At parity (the default), a task form in a frame inside open shadow roots, the way some apps (such as
/// `ServiceNow`) hold theirs, is filled by selector in one `browser_act`, and the snapshot after shows what
/// each field now holds; `type` types at the focus; and a record shows its text fields' values but never a
/// password's, nor any field of a form that holds a new password, a card field, a code field or two
/// password fields (THREAT-MODEL R8).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn framed_forms_are_filled_by_selector_and_show_their_values_at_parity() {
    const FILLED: [(&str, &str); 7] = [
        ("#task\\.short_description", "VPN token expired"),
        ("#sys_display\\.task\\.assignment_group", "Network Operations"),
        ("#task\\.state", "Work in Progress"),
        ("#task\\.priority", "2 - High"),
        ("#task\\.due_date", "2026-12-01"),
        ("#task\\.work_notes", "Called the user."),
        ("#task\\.description", "The token expired overnight."),
    ];
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "parity").await;
    let url = lane.fixtures.url("/engine/framed-task");

    let said = tokio::task::block_in_place(|| {
        let mut child = lane
            .rt
            .command(&["mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut send = |v: Value| {
            writeln!(stdin, "{v}").unwrap();
            stdin.flush().unwrap();
        };
        send(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "lane3", "version": "1" } } }));
        lines.next().unwrap().unwrap();
        send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        let mut id = 1;
        let mut call = |name: &str, arguments: Value| -> Value {
            id += 1;
            send(
                json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": arguments } }),
            );
            let answer: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
            answer["result"].clone()
        };
        let opened = call("browser_open", json!({ "url": url }));
        assert_eq!(opened["isError"], Value::Null, "{opened}");
        // Proof 1: one call fills all seven fields by selector, with no step failing.
        let steps: Vec<Value> = FILLED
            .iter()
            .map(|(sel, v)| {
                let verb =
                    if sel.ends_with("state") || sel.ends_with("priority") { "select" } else { "fill" };
                json!([verb, sel, v])
            })
            .collect();
        let filled = call("browser_act", json!({ "steps": steps }));
        assert_eq!(filled["isError"], Value::Null, "{filled}");
        let said = filled["content"][0]["text"].as_str().unwrap_or_default().to_owned();
        // Its page holds the site's lease; closing it leaves the site to the RPC client below.
        let head: Value = serde_json::from_str(said.lines().next().unwrap_or_default()).unwrap();
        let closed = call("browser_close", json!({ "pageId": head["pageId"] }));
        assert_eq!(closed["isError"], Value::Null, "{closed}");
        drop(stdin);
        let _ = child.wait();
        said
    });
    // Proof 2: the snapshot that ends the call shows each field's value.
    assert!(!said.contains("failed"), "{said}");
    for (sel, v) in FILLED {
        let shown = if sel.ends_with("state") || sel.ends_with("priority") {
            format!("selected={}", json!(v))
        } else {
            format!("value={}", json!(v))
        };
        assert!(said.contains(&shown), "{sel}: {shown} in {said}");
    }

    // Proof 3: a click at the field's point, then `type`, fills it.
    let a = lane.open("a", "/engine/framed-task").await;
    let mut snap = Value::Null;
    assert!(
        lane.until(Duration::from_secs(30), async || {
            snap = lane.snap("a", &a).await;
            element(&snap, "task.short_description").is_some()
        })
        .await,
        "{snap}"
    );
    let field = element(&snap, "task.short_description").unwrap().clone();
    lane.act("a", &a, json!({ "action": "click_xy", "x": field["x"], "y": field["y"] })).await.unwrap();
    lane.act("a", &a, json!({ "action": "type", "text": "Reset the VPN token" })).await.unwrap();
    let after = lane.snap("a", &a).await;
    assert_eq!(element(&after, "task.short_description").unwrap()["value"], json!("Reset the VPN token"));

    // Proof 4: a record shows its text fields' values, and never a password's.
    let rec = lane.open("a", "/engine/record").await;
    let snap = lane.snap("a", &rec).await;
    for (id, v) in RECORD_VALUES {
        assert_eq!(element(&snap, id).unwrap()["value"], json!(v), "{id}: {snap}");
    }
    for id in ["pw", "login", "newpw", "card", "otp"] {
        assert_eq!(element(&snap, id).unwrap()["value"], Value::Null, "{id}: {snap}");
    }
    for secret in RECORD_HIDDEN {
        assert!(!snap.to_string().contains(secret), "{secret}: {snap}");
    }
    lane.finish().await;
}

/// With guardrails `light`, no snapshot shows a field's value (proof 5), and a framed control in the
/// sensitive set is still asked about when it is clicked by selector.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_guardrails_on_no_value_is_shown_and_framed_controls_are_checked() {
    const ASK: &str = "Confirm first: this looks like a payment or checkout.";
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "light").await;
    let rec = lane.open("a", "/engine/record").await;
    let snap = lane.snap("a", &rec).await;
    for (id, _) in RECORD_VALUES {
        assert!(element(&snap, id).is_some(), "{id}: {snap}");
    }
    let shown: Vec<&Value> =
        snap["elements"].as_array().unwrap().iter().filter(|e| e.get("value").is_some()).collect();
    assert_eq!(shown, Vec::<&Value>::new(), "{snap}");
    for (_, v) in RECORD_VALUES {
        assert!(!snap.to_string().contains(v), "{v}: {snap}");
    }
    for secret in RECORD_HIDDEN {
        assert!(!snap.to_string().contains(secret), "{secret}: {snap}");
    }

    let pay = lane.open("a", "/engine/framed-pay").await;
    let refused = lane.act("a", &pay, json!({ "action": "click", "selector": "#pay" })).await.unwrap_err();
    assert!(refused.starts_with(ASK), "{refused}");
    lane.act("a", &pay, json!({ "action": "click", "selector": "#plain" })).await.unwrap();
    lane.finish().await;
}

/// With guardrails on, `type` is checked for the keys it presses: a space in its text presses Space at
/// the focus, so `["type", " "]` on a focused pay button is asked about exactly as `["press", " "]` is.
/// Typing a sentence into a text field is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_typed_space_is_checked_as_a_press_of_space() {
    const ASK: &str = "Confirm first: this looks like a payment or checkout.";
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "light").await;
    let a = lane.open("a", "/engine/clobber-pay").await;
    let said = async |lane: &Lane| text(&lane.snap("a", &a).await).to_owned();
    // The focus on the card form's submit button: the field, then Tab.
    lane.act("a", &a, json!({ "action": "fill", "selector": "#number", "text": "4111" })).await.unwrap();
    lane.act("a", &a, json!({ "action": "press", "key": "Tab" })).await.unwrap();
    for args in [json!({ "action": "type", "text": " " }), json!({ "action": "press", "key": " " })] {
        let refused = lane.act("a", &a, args.clone()).await.unwrap_err();
        assert!(refused.starts_with(ASK), "{args}: {refused}");
    }
    assert!(said(&lane).await.contains("nothing pressed"), "a refused act reached the page");
    // The owner's yes: the space presses the focused button, so the focus was there.
    lane.act("a", &a, json!({ "action": "type", "text": " ", "ownerConfirmed": true })).await.unwrap();
    assert!(said(&lane).await.contains("sent the card form"));

    let rec = lane.open("a", "/engine/record").await;
    lane.act("a", &rec, json!({ "action": "fill", "selector": "#short", "text": "Note:" })).await.unwrap();
    lane.act("a", &rec, json!({ "action": "type", "text": " reset the VPN token" })).await.unwrap();
    lane.finish().await;
}

/// A selector's readiness wait, its sensitive-set check and its action all land on one element. An
/// earlier website frame holds a match only inside an open shadow root, which the wait passes over (its
/// point is the frame's, not the page's); a later frame holds one in its document. Whatever the
/// guardrails, the click, the fill, a hover, an upload and a drag reach the later frame's element, the one
/// that was waited for and checked, and never the earlier frame's pay button or file input.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_selector_acts_on_the_element_its_wait_and_check_read() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    for guardrails in ["parity", "light", "full"] {
        let lane = Lane::start_with(&chrome, guardrails).await;
        let a = lane.open("a", "/engine/two-frames").await;
        let said = async |lane: &Lane| text(&lane.snap("a", &a).await).to_owned();
        let mut now = String::new();
        assert!(
            lane.until(Duration::from_secs(30), async || {
                now = said(&lane).await;
                now.contains("the shadow frame is ready") && now.contains("the plain frame is ready")
            })
            .await,
            "{guardrails}: {now}"
        );
        // Phase 4's selector steps hold to it too: a hover, an upload and a drag.
        lane.act("a", &a, json!({ "action": "hover", "selector": "#go" })).await.unwrap();
        let now = said(&lane).await;
        assert!(now.contains("hovered in the plain frame"), "{guardrails}: {now}");
        lane.act("a", &a, json!({ "action": "click", "selector": "#go" })).await.unwrap();
        let now = said(&lane).await;
        assert!(now.contains("pressed in the plain frame"), "{guardrails}: {now}");
        lane.act("a", &a, json!({ "action": "fill", "selector": "#field", "text": "x" })).await.unwrap();
        let now = said(&lane).await;
        assert!(now.contains("filled in the plain frame"), "{guardrails}: {now}");
        let file = lane.rt.path().join("note.txt");
        std::fs::write(&file, "a note").unwrap();
        let upload =
            json!({ "action": "upload", "selector": "#pick", "files": [file], "ownerConfirmed": true });
        lane.act("a", &a, upload).await.unwrap();
        let now = said(&lane).await;
        assert!(now.contains("uploaded in the plain frame"), "{guardrails}: {now}");
        lane.act("a", &a, json!({ "action": "drag", "selector": "#go", "to": "#field" })).await.unwrap();
        let now = said(&lane).await;
        assert!(now.contains("dropped in the plain frame"), "{guardrails}: {now}");
        lane.finish().await;
    }
}

/// SR-89 under `light` and `full`: a drop is checked at its target and a key combination by its last
/// key, as a click and a press are. A `drag` whose `to` is a pay button, a `drag_xy` dropped on it and
/// `Shift+Enter` in a card form are each asked about first, reach nothing on the page, and go through
/// with the owner's yes. Under `parity` none is asked about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_guardrails_on_a_drop_on_a_pay_button_and_shift_enter_in_a_card_form_are_asked_about_first() {
    const ASK: &str = "Confirm first: this looks like a payment or checkout.";
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    for guardrails in ["light", "full", "parity"] {
        let asks = guardrails != "parity";
        let lane = Lane::start_with(&chrome, guardrails).await;
        let snap = lane.snap("a", &lane.open("a", "/engine/clobber-pay").await).await;
        let (plain, pay) = (element(&snap, "plain").unwrap().clone(), element(&snap, "pay").unwrap().clone());
        let steps = [
            json!({ "action": "drag", "selector": "#plain", "to": "#pay" }),
            json!({ "action": "drag_xy", "x": plain["x"], "y": plain["y"], "toX": pay["x"], "toY": pay["y"] }),
            json!({ "action": "press", "key": "Shift+Enter" }),
        ];
        for mut args in steps {
            // A fresh page for each, so what one step did is not read as the next one's.
            let a = lane.open("a", "/engine/clobber-pay").await;
            let said = async |lane: &Lane| text(&lane.snap("a", &a).await).to_owned();
            let enter = args["action"] == "press";
            if enter {
                // The focus in the card form's field, where Enter submits the form.
                let fill = json!({ "action": "fill", "selector": "#number", "text": "4111" });
                lane.act("a", &a, fill).await.unwrap();
            }
            if asks {
                let refused = lane.act("a", &a, args.clone()).await.unwrap_err();
                assert!(refused.starts_with(ASK), "{guardrails} {args}: {refused}");
                assert!(
                    said(&lane).await.contains("nothing pressed"),
                    "{guardrails} {args}: reached the page"
                );
                args["ownerConfirmed"] = json!(true);
            }
            lane.act("a", &a, args.clone()).await.unwrap();
            let now = said(&lane).await;
            let landed =
                if enter { now.contains("sent the card form") } else { !now.contains("nothing pressed") };
            assert!(landed, "{guardrails} {args}: {now}");
        }
        lane.finish().await;
    }
}

/// A closed hidden page's window comes back for its client's next open, on the next page, every time and
/// across sites: the closed page blanks itself, and its blank never cuts the next page's navigation short
/// (that sends the open to a new window).
/// SR-77: the sensitive-set check (`guardrails` `light` and `full`) reads the page through the prototypes'
/// own getters and methods. Before, markup alone could silence it: a form field named `querySelector`
/// made `form.querySelector` an element, the check threw, and an act whose page cannot be read goes
/// through unasked. The page here shadows every name the check used to read, on the form and on the
/// document. The form's names are the proof: the `#next` case fails on the old script, and the Enter
/// case reads the same names. The document's names (`<img name=querySelector>`) did not reach the
/// check's isolated world in Chrome 157, so the first two cases hold on the old script too; they stay to
/// show the reads still work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn markup_that_shadows_dom_properties_cannot_silence_the_sensitive_check() {
    const ASK: &str = "Confirm first: this looks like a payment or checkout.";
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;
    let a = lane.open("a", "/engine/clobber-pay").await;
    let said = async |lane: &Lane| text(&lane.snap("a", &a).await).to_owned();

    // By selector, where the page's own world sees `document.querySelector` as an <img>.
    let refused = lane.act("a", &a, json!({ "action": "click", "selector": "#pay" })).await.unwrap_err();
    assert!(refused.starts_with(ASK), "{refused}");
    // By point, where it sees `document.elementFromPoint` as one.
    let snap = lane.snap("a", &a).await;
    let pay = element(&snap, "pay").unwrap();
    let refused = lane.act("a", &a, json!({ "action": "click_xy", "x": pay["x"], "y": pay["y"] })).await;
    assert!(refused.as_ref().is_err_and(|e| e.starts_with(ASK)), "{refused:?}");
    // A submit button with neutral words in a form that holds a card field, where the form's
    // `querySelector` and `querySelectorAll` are its own inputs.
    let refused = lane.act("a", &a, json!({ "action": "click", "selector": "#next" })).await.unwrap_err();
    assert!(refused.starts_with(ASK), "{refused}");
    // Enter in that form's field. `fill` puts the focus there: a click in a hidden window is a DOM click,
    // which moves no focus, and Enter outside a field is not in the sensitive set.
    lane.act("a", &a, json!({ "action": "fill", "selector": "#number", "text": "4111" })).await.unwrap();
    let refused = lane.act("a", &a, json!({ "action": "press", "key": "Enter" })).await.unwrap_err();
    assert!(refused.starts_with(ASK), "{refused}");
    assert!(said(&lane).await.contains("nothing pressed"), "a refused act reached the page");

    // What is not in the sensitive set goes through on the same page, and so does the owner's yes.
    lane.act("a", &a, json!({ "action": "click", "selector": "#plain" })).await.unwrap();
    assert!(said(&lane).await.contains("pressed plain"));
    lane.act("a", &a, json!({ "action": "click", "selector": "#pay", "ownerConfirmed": true }))
        .await
        .unwrap();
    assert!(said(&lane).await.contains("pressed pay"));
    lane.act("a", &a, json!({ "action": "fill", "selector": "#number", "text": "4242" })).await.unwrap();
    lane.act("a", &a, json!({ "action": "press", "key": "Enter", "ownerConfirmed": true })).await.unwrap();
    assert!(said(&lane).await.contains("sent the card form"));
    lane.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_window_takes_each_next_page_of_its_client() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;
    for n in 0..100 {
        let path = format!("/engine/basic?visit={n}");
        let url = if n % 3 == 2 { lane.fixtures.twin_url(&path) } else { lane.fixtures.url(&path) };
        let opened = lane.ok("open", json!({ "url": url }), "kept").await;
        assert_eq!(opened["url"], json!(url), "{opened}");
        lane.ok("close", json!({ "pageId": opened["pageId"] }), "kept").await;
    }
    let windows = lane.ext.ops().iter().filter(|op| *op == "createWindow").count();
    assert_eq!(windows, 1, "{:?}", lane.ext.ops());
}

/// Per-call latency, the number a latency climb is judged on. Each round is one agent's whole visit to a
/// fixture page: open, snapshot, fill, click, wait for the click's text, close. Every call is timed at the
/// client, so the HTTP hop, the bridge and Chrome are all inside the number. Two warm-up rounds are not
/// counted (the first open starts the profile's work). `PHANTAB_TEST_LATENCY_ROUNDS` sets the rounds
/// (default 3, so the normal lane run keeps the test alive cheaply). Prints one `lane3 latency` JSON line
/// with each method's median and p95 in milliseconds, and asserts nothing about speed: it is a reading.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_call_latency_of_open_snapshot_act_wait_and_close() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let rounds: usize =
        std::env::var("PHANTAB_TEST_LATENCY_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    let lane = Lane::start(&chrome).await;
    let methods = ["open", "snapshot", "act", "wait", "close"];
    let mut samples: Vec<Vec<f64>> = vec![Vec::new(); methods.len()];

    for round in 0..rounds + 2 {
        let mut took = Vec::with_capacity(6);
        let t = Instant::now();
        let page = lane.open("lat", "/engine/basic").await;
        took.push((0, t.elapsed()));
        let t = Instant::now();
        let snap = lane.snap("lat", &page).await;
        took.push((1, t.elapsed()));
        assert!(element(&snap, "go").is_some(), "{snap}");
        let word = format!("measured {round}");
        let t = Instant::now();
        lane.act("lat", &page, json!({ "action": "fill", "selector": "#name", "text": word })).await.unwrap();
        took.push((2, t.elapsed()));
        let t = Instant::now();
        lane.act("lat", &page, json!({ "action": "click", "selector": "#go" })).await.unwrap();
        took.push((2, t.elapsed()));
        let t = Instant::now();
        lane.ok("wait", json!({ "pageId": page, "selector": "#result", "text": word }), "lat").await;
        took.push((3, t.elapsed()));
        let t = Instant::now();
        lane.ok("close", json!({ "pageId": page }), "lat").await;
        took.push((4, t.elapsed()));
        if round >= 2 {
            for (i, d) in took {
                samples[i].push(d.as_secs_f64() * 1000.0);
            }
        }
    }

    let mut out = serde_json::Map::new();
    for (name, mut s) in methods.iter().zip(samples) {
        s.sort_by(f64::total_cmp);
        let n = s.len();
        let median = if n % 2 == 0 { f64::midpoint(s[n / 2 - 1], s[n / 2]) } else { s[n / 2] };
        // Nearest rank: the smallest sample at or above 95% of them.
        let p95 = s[(n * 95).div_ceil(100) - 1];
        out.insert(
            (*name).to_owned(),
            json!({ "n": n, "median": (median * 10.0).round() / 10.0, "p95": (p95 * 10.0).round() / 10.0 }),
        );
    }
    eprintln!("lane3 latency {}", Value::Object(out));
    lane.finish().await;
}

/// A PNG's size in pixels, from its header.
fn png_size(bytes: &[u8]) -> (u32, u32) {
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"), "not a PNG");
    let be = |i: usize| u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    (be(16), be(20))
}

/// SR-88, L3: results as files. A screenshot with `path` saves the picture there at the size asked (a
/// 390-wide view, a full page taller than the view, one element in the document, in an open shadow
/// root or in a website frame) and answers the file, not the image; the view is back to its usual size
/// after each, also after one that failed. A relative path, a missing folder and an existing file
/// without `overwrite` are refused. A snapshot with `path` saves its JSON and answers the path. On a
/// page handed to the owner and scrolled partway, `selector`, `fullPage` and `width` are refused at
/// once and the scroll stays; the plain picture is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn screenshots_and_snapshots_are_saved_as_files_at_the_size_asked() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;
    let dir = tempfile::tempdir().unwrap();
    let a = lane.open("a", "/engine/shots").await;
    let tab = lane.ext.last_window_tab();
    let framed = "document.querySelector('iframe').contentDocument?.getElementById('inframe') != null";
    assert!(
        lane.until(Duration::from_secs(15), async || lane.ext.eval(tab, framed).await == json!(true)).await
    );
    let view = async || lane.ext.eval(tab, "[innerWidth, innerHeight]").await;
    let usual = view().await;
    assert_eq!(usual, json!([1280, 900]));
    let shot = async |args: Value| {
        let mut args = args;
        args["pageId"] = json!(a);
        lane.call("screenshot", args, "a").await
    };

    // A phone-wide PNG: the file, not the image.
    let phone = dir.path().join("phone.png");
    let out = shot(json!({ "path": phone, "format": "png", "width": 390 })).await.unwrap();
    let bytes = std::fs::read(&phone).unwrap();
    assert_eq!(png_size(&bytes).0, 390, "{out}");
    assert_eq!(out.get("data"), None, "{out}");
    assert_eq!(
        out,
        json!({ "path": phone.display().to_string(), "bytes": bytes.len(), "width": 390,
                "height": png_size(&bytes).1, "mimeType": "image/png" })
    );
    assert_eq!(view().await, usual, "the view is put back");

    // The full page is taller than the view.
    let full = dir.path().join("full.png");
    let out = shot(json!({ "path": full, "fullPage": true })).await.unwrap();
    let (w, h) = png_size(&std::fs::read(&full).unwrap());
    assert!(w == 1280 && h > 3000, "{w}x{h}: {out}");
    assert_eq!(view().await, usual);

    // One element, wherever an act would find it; JPEG unless asked or the name says .png.
    for (selector, size) in [("#box", (200, 120)), ("#inshadow", (150, 80)), ("#inframe", (90, 70))] {
        let path = dir.path().join(format!("{}.jpg", &selector[1..]));
        let out = shot(json!({ "path": path, "selector": selector })).await.unwrap();
        assert!(std::fs::read(&path).unwrap().starts_with(&[0xFF, 0xD8]), "{selector}: a JPEG");
        assert_eq!(
            (&out["width"], &out["height"], &out["mimeType"]),
            (&json!(size.0), &json!(size.1), &json!("image/jpeg")),
            "{selector}: {out}"
        );
    }
    // A disabled or aria-disabled element is pictured at once: a picture does not need it enabled, so the
    // wait an act makes for that (10 s, then "disabled") is not this one's.
    for (selector, size) in [("#off", (110, 40)), ("#ariaoff", (130, 50))] {
        let path = dir.path().join(format!("{}.png", &selector[1..]));
        let asked = Instant::now();
        let out = shot(json!({ "path": path, "selector": selector })).await;
        let took = asked.elapsed();
        let out = out.unwrap_or_else(|e| panic!("{selector}: {e} (after {took:?})"));
        assert_eq!(png_size(&std::fs::read(&path).unwrap()), size, "{selector}: {out}");
        assert!(took < Duration::from_secs(3), "{selector}: took {took:?}");
    }
    // A picture that fails puts the view back too.
    let missing = shot(json!({ "selector": "#nowhere", "width": 390, "height": 844 })).await.unwrap_err();
    assert!(missing.contains("#nowhere"), "{missing}");
    assert_eq!(view().await, usual, "put back after a failure");

    // Refusals: a relative path, a folder that is not there, an existing file without overwrite.
    let relative = shot(json!({ "path": "shot.png" })).await.unwrap_err();
    assert!(relative.contains("not an absolute path"), "{relative}");
    let gone = dir.path().join("gone");
    let folder = shot(json!({ "path": gone.join("shot.png") })).await.unwrap_err();
    assert!(folder.contains(&gone.display().to_string()) && folder.contains("does not exist"), "{folder}");
    let taken = dir.path().join("taken.png");
    std::fs::write(&taken, b"old").unwrap();
    let kept = shot(json!({ "path": taken })).await.unwrap_err();
    assert!(kept.contains("already exists") && kept.contains("overwrite"), "{kept}");
    assert_eq!(std::fs::read(&taken).unwrap(), b"old");
    shot(json!({ "path": taken, "overwrite": true })).await.unwrap();
    png_size(&std::fs::read(&taken).unwrap());

    // Without path, the image comes back as before.
    let inline = shot(json!({ "width": 390 })).await.unwrap();
    assert_eq!(inline["mimeType"], json!("image/jpeg"));
    assert!(inline["data"].as_str().is_some_and(|d| d.len() > 100), "{inline}");

    // A snapshot saved to a file: the path and size, not the snapshot.
    let saved = dir.path().join("snapshot.json");
    let out = lane.ok("snapshot", json!({ "pageId": a, "path": saved }), "a").await;
    let file = std::fs::read_to_string(&saved).unwrap();
    assert_eq!(out, json!({ "pageId": a, "path": saved.display().to_string(), "bytes": file.len() }));
    let read: Value = serde_json::from_str(&file).unwrap();
    assert!(read["text"].as_str().is_some_and(|t| t.contains("Shot words")), "{file}");
    assert!(read["elements"].is_array(), "{file}");
    let again = lane.err("snapshot", json!({ "pageId": a, "path": saved }), "a").await;
    assert!(again.contains("already exists"), "{again}");

    // A page handed to the owner keeps his window as he left it, scrolled partway: no width or height
    // then, no picture of one element (it would scroll his view to it) and none of the full page (it
    // stretches his view for the capture), each refused at once with Chrome not asked; a plain picture
    // of the view, yes.
    lane.ok("show", json!({ "pageId": a }), "a").await;
    lane.ext.eval(tab, "scrollTo(0, 600)").await;
    let scrolled = async || lane.ext.eval(tab, "scrollY").await;
    let at = scrolled().await;
    assert_eq!(at, json!(600));
    let unsaved = dir.path().join("held-full.png");
    for (args, named) in [
        (json!({ "selector": "#far" }), "selector"),
        (json!({ "fullPage": true, "path": unsaved }), "fullPage"),
        (json!({ "width": 390 }), "width"),
    ] {
        let asked = Instant::now();
        let out = shot(args).await;
        let (took, now) = (asked.elapsed(), scrolled().await);
        let held =
            out.err().unwrap_or_else(|| panic!("{named}: taken on a held page; scrollY {at} -> {now}"));
        assert!(held.starts_with(&format!("{named}: the owner holds this page")), "{held}");
        assert!(held.contains("his window") && held.contains("after handback"), "{held}");
        assert!(took < Duration::from_secs(3), "{named}: took {took:?}");
        assert_eq!(now, at, "{named}: his view did not move");
    }
    assert!(!unsaved.exists(), "a refused picture saves nothing");
    shot(json!({ "path": dir.path().join("held.png") })).await.unwrap();
    assert_eq!(scrolled().await, at);
    lane.finish().await;
}

/// Phase 4 proof 1: `hover` and `hover_xy` open a menu that opens only on hover (CSS `:hover`), and its
/// item then shows in the snapshot. Moving the mouse away closes it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hover_and_hover_xy_open_a_menu_that_opens_on_hover() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "parity").await;
    let a = lane.open("a", "/engine/hover").await;
    let snap = lane.snap("a", &a).await;
    assert!(element(&snap, "sign-out").is_none(), "closed before the hover: {snap}");
    let account = element(&snap, "account").unwrap().clone();
    lane.act("a", &a, json!({ "action": "hover", "selector": "#account" })).await.unwrap();
    let snap = lane.snap("a", &a).await;
    assert!(element(&snap, "sign-out").is_some(), "open after hover: {snap}");
    lane.act("a", &a, json!({ "action": "hover_xy", "x": 700, "y": 500 })).await.unwrap();
    let snap = lane.snap("a", &a).await;
    assert!(element(&snap, "sign-out").is_none(), "closed once the mouse left: {snap}");
    lane.act("a", &a, json!({ "action": "hover_xy", "x": account["x"], "y": account["y"] })).await.unwrap();
    let snap = lane.snap("a", &a).await;
    assert!(element(&snap, "sign-out").is_some(), "open after hover_xy: {snap}");
    lane.finish().await;
}

/// Phase 4 proof 2: `drag` moves a list's first item below its second, and `drag_xy` does the same by
/// points. The list sorts on mouse events, as many list widgets do. An HTML5 drag-and-drop list
/// (`draggable`, `dragstart`/`drop`) sorts the same way: Chrome starts an HTML5 drag from the same
/// mouse events.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drag_and_drag_xy_sort_a_list() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "parity").await;
    let a = lane.open("a", "/engine/drag").await;
    assert!(text(&lane.snap("a", &a).await).contains("order: First, Second, Third"));
    lane.act("a", &a, json!({ "action": "drag", "selector": "#first", "to": "#second" })).await.unwrap();
    let snap = lane.snap("a", &a).await;
    assert!(text(&snap).contains("order: Second, First, Third"), "{snap}");
    // A list item is no control, so the snapshot gives it no point. The fixture's rows are fixed: 42 px
    // tall from y 8, 4 px apart, so the third row's middle is at y 121 and the first's at y 29.
    let by_point = json!({ "action": "drag_xy", "x": 100, "y": 121, "toX": 100, "toY": 29 });
    lane.act("a", &a, by_point).await.unwrap();
    let snap = lane.snap("a", &a).await;
    assert!(text(&snap).contains("order: Second, Third, First"), "{snap}");

    let h = lane.open("a", "/engine/drag-html5").await;
    lane.act("a", &h, json!({ "action": "drag", "selector": "#first", "to": "#second" })).await.unwrap();
    let seen = text(&lane.snap("a", &h).await).to_owned();
    assert!(
        seen.contains("order: Second, First, Third") && seen.contains("dragstart, dragover, drop"),
        "{seen}"
    );
    lane.finish().await;
}

/// A `drag` by selector presses and releases at points, and a mouse event goes to whatever is on top
/// there. Each end is checked as a click's point is, before the first mouse event, so a clear submit
/// button laid over the whole list, or over the drop item alone, takes no press, no drop and no click:
/// the drag is refused as covered, naming its end, the form is not sent and the page gets no mouse event
/// at all. The refusal is the drag's own: nothing was pressed, and `drag_xy` drags between two points.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drag_onto_a_covered_list_is_refused_before_any_mouse_event() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    for guardrails in ["parity", "light"] {
        let lane = Lane::start_with(&chrome, guardrails).await;
        for (page, end) in [
            ("/engine/drag-covered", "from end (#first)"),
            ("/engine/drag-covered?over=drop", "to end (#second)"),
        ] {
            let a = lane.open("a", page).await;
            let drag = json!({ "action": "drag", "selector": "#first", "to": "#second" });
            let refused = lane.act("a", &a, drag).await.unwrap_err();
            assert!(
                refused.starts_with("Element is covered at its click point by <button#send>")
                    && refused.contains(&format!("That is the drag's {end}, so nothing was pressed."))
                    && refused.contains("use drag_xy to drag between two points on purpose")
                    && !refused.contains("click_xy")
                    && !refused.contains("the click was not sent"),
                "{guardrails} {page}: {refused}"
            );
            let seen = text(&lane.snap("a", &a).await).to_owned();
            assert!(seen.contains("not sent") && seen.contains("mouse: none"), "{guardrails} {page}: {seen}");
        }
        lane.finish().await;
    }
}

/// The page's own handlers run as the pointer arrives at the drag's start, before anything is pressed,
/// so a page can slide an overlay in then. A drag checks both its ends again once the pointer is there
/// and the page has had a frame, as a click checks its point, and presses only after that: a clear
/// submit button shown on the first `mousemove`, over the whole view or over the drop item alone, is
/// seen, the drag is refused naming that end, the form is not sent and the page saw the arrival move
/// but no press, no release and no click. Over the whole view the button covers both ends, and `to` is
/// checked first once the pointer is there, so that refusal names `to`; the start covered on arrival is
/// `a_drag_checks_its_start_last_so_a_page_holding_the_drop_check_open_gets_no_press`'s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drag_whose_page_covers_an_end_as_the_pointer_arrives_presses_nothing() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "light").await;
    let cases = [
        ("/engine/drag-covered?later=1", "to end (#second)"),
        ("/engine/drag-covered?over=drop&later=1", "to end (#second)"),
    ];
    for (page, end) in cases {
        let a = lane.open("a", page).await;
        let drag = json!({ "action": "drag", "selector": "#first", "to": "#second" });
        let refused = lane.act("a", &a, drag).await.unwrap_err();
        assert!(
            refused.starts_with("Element is covered at its click point by <button#send>")
                && refused.contains(&format!("That is the drag's {end}, covered once the pointer"))
                && refused.contains("the pointer moved there, and nothing was pressed")
                && refused.contains("use drag_xy to drag between two points on purpose"),
            "{page}: {refused}"
        );
        let seen = text(&lane.snap("a", &a).await).to_owned();
        assert!(seen.contains("not sent") && seen.contains("mouse: mousemove"), "{page}: {seen}");
        assert!(
            !seen.contains("mousedown") && !seen.contains("mouseup") && !seen.contains("click"),
            "{page}: {seen}"
        );
    }
    lane.finish().await;
}

/// A page can hold one end's check open (a covered end is retried) and change the other end meanwhile,
/// so the press must follow a check of its own point: once the pointer arrives, a drag checks `to`, then
/// `from`, and presses. The page covers the drop item with something clear for 600 ms on the arrival
/// `mousemove` and lays the submit button over the start at 300 ms, where it stays. `from` is checked
/// only after `to` passes, finds the button, and the drag is refused naming its start; the press never
/// reaches the button. The timings: the 300 ms between the button and the cover going are ordered by the
/// page's own timers, so a slow machine cannot swap them, and the 600 ms cover leaves `to`'s check 400 ms
/// inside the 1 s covered grace, so a slow check is not refused at `to` instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drag_checks_its_start_last_so_a_page_holding_the_drop_check_open_gets_no_press() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "light").await;
    let page = "/engine/drag-covered?slide=1";
    let a = lane.open("a", page).await;
    let drag = json!({ "action": "drag", "selector": "#first", "to": "#second" });
    let refused = lane.act("a", &a, drag).await.unwrap_err();
    assert!(
        refused.starts_with("Element is covered at its click point by <button#send>")
            && refused.contains("That is the drag's from end (#first), covered once the pointer")
            && refused.contains("the pointer moved there, and nothing was pressed")
            && refused.contains("use drag_xy to drag between two points on purpose")
            && !refused.contains("click_xy"),
        "{page}: {refused}"
    );
    let seen = text(&lane.snap("a", &a).await).to_owned();
    assert!(seen.contains("not sent") && seen.contains("mouse: mousemove"), "{page}: {seen}");
    assert!(
        !seen.contains("mousedown") && !seen.contains("mouseup") && !seen.contains("click"),
        "{page}: {seen}"
    );
    lane.finish().await;
}

/// Phase 4 proof 3: `upload` sets a file input's files, and the page shows each file's name and size, on
/// the page and in another site's frame. A relative path, a missing file, a folder and an element that is
/// not a file input are each refused, saying which, and the page is left as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_sets_a_file_input_and_refuses_what_it_cannot_send() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "parity").await;
    let dir = lane.rt.path().join("to-send");
    std::fs::create_dir_all(&dir).unwrap();
    let (report, notes) = (dir.join("report.txt"), dir.join("notes.txt"));
    std::fs::write(&report, "twelve bytes").unwrap();
    std::fs::write(&notes, "five!").unwrap();
    let upload =
        |selector: &str, files: Value| json!({ "action": "upload", "selector": selector, "files": files });

    let a = lane.open("a", "/engine/upload").await;
    for (args, wants) in [
        (upload("#file", json!(["report.txt"])), "upload: \"report.txt\" is not an absolute path."),
        (upload("#file", json!([dir.join("absent.txt")])), "\" does not exist."),
        (upload("#file", json!([dir])), "\" is not a file."),
        (upload("#name", json!([report])), "upload: #name is not a file input (<input type=file>)"),
        (upload("#file", json!([report, notes])), "upload: #file "),
        (upload("#file", json!([7])), "upload: each file must be a path, as text."),
    ] {
        let refused = lane.act("a", &a, args.clone()).await.unwrap_err();
        assert!(refused.contains(wants), "{args}: {refused}");
    }
    assert!(text(&lane.snap("a", &a).await).contains("no file chosen"), "a refused upload reached the page");
    lane.act("a", &a, upload("#file", json!([report]))).await.unwrap();
    assert!(text(&lane.snap("a", &a).await).contains("chose report.txt (12 bytes)"));
    lane.act("a", &a, upload("#files", json!([report, notes]))).await.unwrap();
    let shown = text(&lane.snap("a", &a).await).to_owned();
    assert!(shown.contains("chose report.txt (12 bytes); chose notes.txt (5 bytes)"), "{shown}");

    let f = lane.open("a", "/engine/upload-frame").await;
    let mut seen = String::new();
    assert!(
        lane.until(Duration::from_secs(10), async || {
            seen = lane.snap("a", &f).await.to_string();
            seen.contains("no file chosen")
        })
        .await,
        "the frame loads: {seen}"
    );
    lane.act("a", &f, upload("#file", json!([report]))).await.unwrap();
    let snap = lane.snap("a", &f).await;
    assert!(snap.to_string().contains("chose report.txt (12 bytes)"), "{snap}");
    lane.finish().await;
}

/// Phase 4 proof 4, on a hidden workspace page (the extension answers its dialogs) and on an
/// isolated headless one (phantab answers them): without a `dialog` step a confirm is dismissed, and
/// the click's result reports it with its message. `["dialog", "accept"]` before the click accepts it,
/// once: the next confirm is dismissed again. `["dialog", "accept", text]` answers a prompt with text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dialog_step_answers_the_next_dialog_once_and_every_dialog_is_reported() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "parity").await;
    let isolated = json!({ "url": lane.fixtures.url("/engine/dialogs"), "mode": "isolated-headless" });
    let isolated = lane.ok("open", isolated, "a").await;
    let pages = [lane.open("a", "/engine/dialogs").await, isolated["pageId"].as_str().unwrap().to_owned()];
    for p in &pages {
        let said = async || text(&lane.snap("a", p).await).to_owned();
        let click =
            async |id: &str| lane.act("a", p, json!({ "action": "click", "selector": id })).await.unwrap();
        let reported = |r: &Value, kind: &str, message: &str, answer: &str| {
            assert_eq!(
                r["dialogs"],
                json!([{ "type": kind, "message": message, "answer": answer }]),
                "{p}: {r}"
            );
        };
        let r = click("#ask").await;
        assert!(said().await.contains("false"), "{p}: dismissed by default");
        reported(&r, "confirm", "Delete it?", "dismissed");
        lane.act("a", p, json!({ "action": "dialog", "answer": "accept" })).await.unwrap();
        let r = click("#ask").await;
        assert!(said().await.contains("true"), "{p}: accepted");
        reported(&r, "confirm", "Delete it?", "accepted");
        let r = click("#ask").await;
        assert!(said().await.contains("false"), "{p}: the answer is used once");
        reported(&r, "confirm", "Delete it?", "dismissed");
        lane.act("a", p, json!({ "action": "dialog", "answer": "accept", "text": "Ada" })).await.unwrap();
        let r = click("#name").await;
        assert!(said().await.contains("name Ada"), "{p}: the prompt's text");
        reported(&r, "prompt", "Your name?", "accepted");
        click("#name").await;
        assert!(said().await.contains("no name"), "{p}: a prompt is dismissed by default");
        lane.act("a", p, json!({ "action": "dialog", "answer": "dismiss" })).await.unwrap();
        let r = click("#tell").await;
        assert!(said().await.contains("told"), "{p}");
        reported(&r, "alert", "Saved", "dismissed");
    }
    lane.finish().await;
}

/// Phase 4 proof 5: `back`, `forward` and `reload` move through the tab's history; a reload resets the
/// page's in-memory counter. `back` on a tab with no earlier website page is an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn back_forward_and_reload_move_through_the_tabs_history() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "parity").await;
    let a = lane.open("a", "/engine/history").await;
    let title = async || lane.snap("a", &a).await["title"].as_str().unwrap_or_default().to_owned();
    let step = async |action: &str| lane.act("a", &a, json!({ "action": action })).await;
    let refused = step("back").await.unwrap_err();
    assert_eq!(refused, "Nothing to go back to: this tab has no earlier website page.");
    let refused = step("forward").await.unwrap_err();
    assert_eq!(refused, "Nothing to go forward to: this tab has no later website page.");

    lane.act("a", &a, json!({ "action": "click", "selector": "#more" })).await.unwrap();
    lane.act("a", &a, json!({ "action": "click", "selector": "#more" })).await.unwrap();
    assert!(text(&lane.snap("a", &a).await).contains("count 2"));
    step("reload").await.unwrap();
    assert!(text(&lane.snap("a", &a).await).contains("count 0"), "a reload resets the counter");

    lane.act("a", &a, json!({ "action": "click", "selector": "#on" })).await.unwrap();
    assert!(lane.until(Duration::from_secs(10), async || title().await == "Browser fixture").await);
    step("back").await.unwrap();
    assert_eq!(title().await, "History fixture");
    step("forward").await.unwrap();
    assert_eq!(title().await, "Browser fixture");
    step("back").await.unwrap();
    assert_eq!(title().await, "History fixture");
    lane.finish().await;
}

/// Phase 4 proof 5 under `light`: `reload`, `back` or `forward` onto a page a form sent may send the
/// form again, so each is asked about first; a move onto any other page is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moving_onto_a_page_a_form_sent_is_asked_about_first() {
    const ASK: &str = "Confirm first: this loads a page a form sent";
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "light").await;
    let a = lane.open("a", "/engine/resend").await;
    let step = async |action: &str, confirmed: bool| {
        lane.act("a", &a, json!({ "action": action, "ownerConfirmed": confirmed })).await
    };
    let title = async || lane.snap("a", &a).await["title"].as_str().unwrap_or_default().to_owned();
    lane.act("a", &a, json!({ "action": "click", "selector": "#send", "ownerConfirmed": true }))
        .await
        .unwrap();
    assert!(lane.until(Duration::from_secs(10), async || title().await != "A form that posts").await);
    let sent = lane.fixtures.posts().len();
    assert_eq!(sent, 1, "the form was sent once");
    let refused = step("reload", false).await.unwrap_err();
    assert!(refused.starts_with(ASK), "{refused}");
    step("back", false).await.unwrap();
    assert_eq!(title().await, "A form that posts");
    let refused = step("forward", false).await.unwrap_err();
    assert!(refused.starts_with(ASK), "{refused}");
    step("reload", false).await.unwrap();
    assert_eq!(lane.fixtures.posts().len(), sent, "no refused move sent the form");
    step("forward", true).await.unwrap();
    eprintln!("lane3 posts after a confirmed forward onto the sent page: {}", lane.fixtures.posts().len());
    lane.finish().await;
}

/// Phase 4 proof 6: `["press", "Control+A"]` selects a field's text, so the typing after it replaces it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_combination_selects_all_and_typing_replaces_it() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "parity").await;
    let a = lane.open("a", "/engine/basic").await;
    lane.act("a", &a, json!({ "action": "fill", "selector": "#name", "text": "the old text" }))
        .await
        .unwrap();
    lane.act("a", &a, json!({ "action": "press", "key": "Control+A" })).await.unwrap();
    lane.act("a", &a, json!({ "action": "type", "text": "new" })).await.unwrap();
    lane.act("a", &a, json!({ "action": "click", "selector": "#go" })).await.unwrap();
    let shown = text(&lane.snap("a", &a).await).to_owned();
    assert!(shown.contains("new") && !shown.contains("old text"), "{shown}");
    lane.finish().await;
}

/// Phase 4 proof 7: a page handed to the owner refuses every step phase 4 added, the owner's yes or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handed_over_page_refuses_every_new_step() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;
    let file = lane.rt.path().join("report.txt");
    std::fs::write(&file, "twelve bytes").unwrap();
    let a = lane.open("a", "/engine/upload").await;
    lane.ok("show", json!({ "pageId": a }), "a").await;
    for mut args in [
        json!({ "action": "hover", "selector": "#file" }),
        json!({ "action": "hover_xy", "x": 10, "y": 10 }),
        json!({ "action": "drag", "selector": "#file", "to": "#name" }),
        json!({ "action": "drag_xy", "x": 10, "y": 10, "toX": 20, "toY": 20 }),
        json!({ "action": "upload", "selector": "#file", "files": [file] }),
        json!({ "action": "dialog", "answer": "accept" }),
        json!({ "action": "dialog", "answer": "dismiss" }),
        json!({ "action": "back" }),
        json!({ "action": "forward" }),
        json!({ "action": "reload" }),
        json!({ "action": "press", "key": "Control+A" }),
    ] {
        for confirmed in [false, true] {
            args["ownerConfirmed"] = json!(confirmed);
            let refused = lane.act("a", &a, args.clone()).await.unwrap_err();
            assert!(refused.contains("handed to the owner"), "{args}: {refused}");
        }
    }
    lane.finish().await;
}

/// Phase 4 proof 8: under `light` and `full` every upload and every dialog accept is asked about first,
/// and goes through with the owner's yes; a dismiss is not asked about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_guardrails_on_uploads_and_dialog_accepts_are_asked_about_first() {
    const SENDS: &str = "Confirm first: this sends a file from this computer to the site.";
    const ACCEPTS: &str = "Confirm first: this accepts the page's next dialog";
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    for guardrails in ["light", "full"] {
        let lane = Lane::start_with(&chrome, guardrails).await;
        let file = lane.rt.path().join("report.txt");
        std::fs::write(&file, "twelve bytes").unwrap();
        let a = lane.open("a", "/engine/upload").await;
        let upload = |confirmed: bool| json!({ "action": "upload", "selector": "#file", "files": [file], "ownerConfirmed": confirmed });
        let refused = lane.act("a", &a, upload(false)).await.unwrap_err();
        assert!(refused.starts_with(SENDS), "{guardrails}: {refused}");
        assert!(text(&lane.snap("a", &a).await).contains("no file chosen"), "{guardrails}");
        lane.act("a", &a, upload(true)).await.unwrap();
        assert!(text(&lane.snap("a", &a).await).contains("chose report.txt (12 bytes)"), "{guardrails}");

        let d = lane.open("a", "/engine/dialogs").await;
        let refused = lane.act("a", &d, json!({ "action": "dialog", "answer": "accept" })).await.unwrap_err();
        assert!(refused.starts_with(ACCEPTS), "{guardrails}: {refused}");
        lane.act("a", &d, json!({ "action": "click", "selector": "#ask" })).await.unwrap();
        assert!(
            text(&lane.snap("a", &d).await).contains("false"),
            "{guardrails}: the refused accept set nothing"
        );
        lane.act("a", &d, json!({ "action": "dialog", "answer": "dismiss" })).await.unwrap();
        let accept = json!({ "action": "dialog", "answer": "accept", "ownerConfirmed": true });
        lane.act("a", &d, accept).await.unwrap();
        lane.act("a", &d, json!({ "action": "click", "selector": "#ask" })).await.unwrap();
        assert!(text(&lane.snap("a", &d).await).contains("true"), "{guardrails}");
        lane.finish().await;
    }
}

/// THREAT-MODEL SR-90's lane 3 proof, and phase 5 proof 1: `engine/devtools` logs an error and a
/// warning, throws, fails two requests and is sent an httpOnly cookie that a later request carries back
/// with an `Authorization` header. The console gives the error, the warning and the exception; the
/// network lists the failed requests first; a request's detail has neither header; evaluate reads a page
/// object. Neither the cookie's value nor the header's is in any answer or saved file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn developer_tools_read_the_console_and_network_and_run_scripts() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_dev_tools(&chrome, "parity").await;
    let a = lane.open("a", "/engine/devtools").await;
    let mut said: Vec<String> = Vec::new();
    // The first call on a page starts its recording, and says so; the next one does not.
    let first = lane.ok("console", json!({ "pageId": a }), "a").await;
    assert!(first["recording"].as_str().unwrap().starts_with("Recording started now"), "{first}");
    let first = lane.ok("network", json!({ "pageId": a }), "a").await;
    assert!(first["recording"].as_str().unwrap().starts_with("Recording started now"), "{first}");
    assert_eq!(first["requests"], json!([]), "nothing from before the recording: {first}");
    let again = lane.ok("console", json!({ "pageId": a }), "a").await;
    assert!(again.get("recording").is_none(), "{again}");

    lane.act("a", &a, json!({ "action": "reload" })).await.unwrap();
    lane.ok("wait", json!({ "pageId": a, "selector": "#state", "text": "done" }), "a").await;
    let console = async || lane.ok("console", json!({ "pageId": a }), "a").await;
    let has = |c: &Value, level: &str, text: &str| {
        c["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["level"] == json!(level) && m["text"].as_str().unwrap().contains(text))
    };
    assert!(
        lane.until(Duration::from_secs(10), async || has(
            &console().await,
            "exception",
            "an uncaught exception"
        ))
        .await
    );
    let c = console().await;
    said.push(c.to_string());
    assert!(has(&c, "error", "devtools fixture: an error was logged"), "{c}");
    assert!(has(&c, "warning", "devtools fixture: a warning was logged"), "{c}");
    assert!(!c.to_string().contains("a plain log"), "a plain log is not kept: {c}");

    let n = lane.ok("network", json!({ "pageId": a }), "a").await;
    said.push(n.to_string());
    let requests = n["requests"].as_array().unwrap();
    let failed = |q: &Value| q.get("failed").is_some() || q["status"].as_u64().is_some_and(|s| s >= 400);
    let first_ok = requests.iter().position(|q| !failed(q)).unwrap();
    assert!(requests[first_ok..].iter().all(|q| !failed(q)), "failed ones first: {n}");
    let url = |q: &Value| q["url"].as_str().unwrap_or_default().to_owned();
    assert!(
        requests[..first_ok]
            .iter()
            .any(|q| url(q).ends_with("/status?code=500") && q["status"] == json!(500)),
        "{n}"
    );
    assert!(
        requests[..first_ok]
            .iter()
            .any(|q| url(q).starts_with("http://127.0.0.1:1/") && q["failed"].is_string()),
        "{n}"
    );
    let id_of = |end: &str| {
        requests.iter().find(|q| url(q).ends_with(end)).unwrap()["id"].as_str().unwrap().to_owned()
    };

    // The cookie went out and came back, and the header with it: the site saw both.
    let seen = lane.fixtures.requests();
    let check = seen.iter().find(|r| r.path == "/cookie/check").unwrap();
    let header =
        |n: &str| check.headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap_or_default();
    assert!(header("cookie").contains(phantab_testkit::DEVTOOLS_COOKIE), "the cookie was sent");
    assert!(header("authorization").contains(phantab_testkit::DEVTOOLS_TOKEN), "the header was sent");
    for (end, body) in [("/cookie/set", "set"), ("/cookie/check", "cookie sent, authorization sent")] {
        let d = lane.ok("network", json!({ "pageId": a, "id": id_of(end) }), "a").await;
        said.push(d.to_string());
        assert_eq!(d["body"], json!(body), "{d}");
        for headers in [&d["requestHeaders"], &d["responseHeaders"]] {
            let names: Vec<String> =
                headers.as_object().unwrap().keys().map(|k| k.to_ascii_lowercase()).collect();
            assert!(
                !names.iter().any(|k| ["cookie", "set-cookie", "authorization", "proxy-authorization"]
                    .contains(&k.as_str())),
                "{d}"
            );
        }
    }
    let doc = lane.ok("network", json!({ "pageId": a, "id": id_of("/engine/devtools") }), "a").await;
    said.push(doc.to_string());
    assert!(doc["body"].as_str().unwrap().contains("Developer tools"), "the page's own source: {doc}");
    let only = lane.ok("network", json!({ "pageId": a, "filter": "/cookie/" }), "a").await;
    assert_eq!(only["requests"].as_array().unwrap().len(), 2, "{only}");
    let unknown = lane.err("network", json!({ "pageId": a, "id": "no-such-request" }), "a").await;
    assert!(unknown.starts_with("No request no-such-request in this page's recording"), "{unknown}");

    // evaluate reads the page's own objects, and no httpOnly cookie.
    let v = lane.ok("evaluate", json!({ "pageId": a, "function": "() => window.appState" }), "a").await;
    assert_eq!(v["type"], json!("object"));
    assert_eq!(
        v["result"],
        json!({ "user": "fixture", "items": [1, 2, 3], "nested": { "ok": true } }),
        "{v}"
    );
    let v = lane.ok("evaluate", json!({ "pageId": a, "function": "() => document.cookie" }), "a").await;
    said.push(v.to_string());

    // Saved files: the whole console, the list and a detail.
    let dir = lane.rt.path().join("saved");
    std::fs::create_dir_all(&dir).unwrap();
    let mut files = Vec::new();
    for (method, mut args) in [
        ("console", json!({})),
        ("network", json!({})),
        ("network", json!({ "id": id_of("/cookie/check") })),
        ("evaluate", json!({ "function": "() => [document.cookie, document.title]" })),
    ] {
        let file = dir.join(format!("{method}-{}.json", files.len()));
        args["pageId"] = json!(a);
        args["path"] = json!(file);
        let saved = lane.ok(method, args, "a").await;
        said.push(saved.to_string());
        assert_eq!(saved["path"], json!(file), "{saved}");
        files.push(std::fs::read_to_string(&file).unwrap());
    }
    assert!(files[2].contains("cookie sent, authorization sent"), "{}", files[2]);
    assert!(files[3].contains("Developer tools"), "{}", files[3]);
    for text in said.iter().chain(&files) {
        for secret in [phantab_testkit::DEVTOOLS_COOKIE, phantab_testkit::DEVTOOLS_TOKEN] {
            assert!(!text.contains(secret), "a secret left the service: {text}");
        }
    }
    lane.finish().await;
}

/// Phase 5 proof 2: evaluate in a frame named by its origin, with arguments and a promise; a result over
/// the limit is cut and says so, and `path` saves it whole; a throw is its message; a script that never
/// returns, or never settles, ends at its time limit and leaves the page answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evaluate_reads_a_frame_cuts_saves_throws_and_times_out() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_dev_tools(&chrome, "parity").await;
    let a = lane.open("a", "/engine/devtools").await;
    lane.ok("wait", json!({ "pageId": a, "selector": "#state", "text": "done" }), "a").await;
    let run = async |more: Value| {
        let mut args = json!({ "pageId": a });
        for (k, v) in more.as_object().unwrap() {
            args[k] = v.clone();
        }
        lane.call("evaluate", args, "a").await
    };
    let twin = lane.fixtures.twin_origin().to_owned();
    let read = "() => window.frameValue";
    let framed = run(json!({ "function": read, "frame": twin })).await.unwrap();
    assert_eq!(framed["result"], json!(format!("read in the twin frame at {twin}")), "{framed}");
    let framed =
        run(json!({ "function": read, "frame": format!("{twin}/engine/devtools-frame") })).await.unwrap();
    assert_eq!(framed["type"], json!("string"), "a frame's URL names it by its origin: {framed}");
    let main = run(json!({ "function": read })).await.unwrap();
    assert_eq!(main["type"], json!("undefined"), "the main document has none: {main}");
    let no = run(json!({ "function": read, "frame": "http://elsewhere.example" })).await.unwrap_err();
    assert!(
        no.contains("http://elsewhere.example") && no.contains(&twin),
        "it names the frames there are: {no}"
    );

    let sum = run(json!({ "function": "(a, b) => a + b", "args": [2, 3] })).await.unwrap();
    assert_eq!((sum["result"].clone(), sum["type"].clone()), (json!(5), json!("number")));
    let later = "async () => { await new Promise((r) => setTimeout(r, 100)); return 'settled'; }";
    assert_eq!(run(json!({ "function": later })).await.unwrap()["result"], json!("settled"));

    let long = "() => 'x'.repeat(30000)";
    let cut = run(json!({ "function": long })).await.unwrap();
    assert_eq!(cut["result"].as_str().unwrap().chars().count(), 20_000, "{}", cut["cut"]);
    assert!(
        cut["cut"].as_str().unwrap().starts_with("The result is 30002 characters of JSON"),
        "{}",
        cut["cut"]
    );
    let file = lane.rt.path().join("long.json");
    let saved = run(json!({ "function": long, "path": file })).await.unwrap();
    assert_eq!(saved["type"], json!("string"));
    let whole: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(whole["result"].as_str().unwrap().len(), 30_000);
    let again = run(json!({ "function": long, "path": file })).await.unwrap_err();
    assert!(again.contains("overwrite"), "an existing file is replaced only with overwrite: {again}");

    let threw =
        run(json!({ "function": "() => { throw new Error('the fixture threw this'); }" })).await.unwrap_err();
    assert!(threw.starts_with("The script threw: ") && threw.contains("the fixture threw this"), "{threw}");
    let t = Instant::now();
    let spun = run(json!({ "function": "() => { for (;;) {} }", "seconds": 1 })).await.unwrap_err();
    assert_eq!(spun, "The script did not answer within 1 s. It was still running, so it was stopped.");
    assert!(t.elapsed() < Duration::from_secs(8), "{:?}", t.elapsed());
    assert_eq!(lane.snap("a", &a).await["title"], json!("Developer tools"), "the page answers again");
    let waits = run(json!({ "function": "() => new Promise(() => {})", "seconds": 1 })).await.unwrap_err();
    assert!(waits.contains("did not answer within 1 s. It was waiting"), "{waits}");
    assert_eq!(run(json!({ "function": "() => 1" })).await.unwrap()["result"], json!(1));
    lane.finish().await;
}

/// Phase 5 proof 3: without `"devTools": true`, as JSON `true`, every developer tool is refused naming
/// the setting, and no developer-tools event crosses the bridge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn developer_tools_are_off_unless_set() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_config(&chrome, "parity", &json!({ "devTools": "true" })).await;
    let a = lane.open("a", "/engine/devtools").await;
    lane.ok("wait", json!({ "pageId": a, "selector": "#state", "text": "done" }), "a").await;
    for (method, args) in [
        ("evaluate", json!({ "pageId": a, "function": "() => 1" })),
        ("console", json!({ "pageId": a })),
        ("network", json!({ "pageId": a })),
    ] {
        let off = lane.err(method, args, "a").await;
        assert!(off.contains("off unless \"devTools\": true is set"), "{method}: {off}");
    }
    lane.act("a", &a, json!({ "action": "reload" })).await.unwrap();
    lane.ok("wait", json!({ "pageId": a, "selector": "#state", "text": "done" }), "a").await;
    let traffic = lane.ext.traffic_total();
    assert_eq!(traffic.devtools, 0, "{traffic:?}");
    assert!(
        !lane.ext.timeline().iter().any(|(_, op)| op.contains("Log.enable") || op.contains("Network.enable"))
    );
    lane.finish().await;
}

/// Phase 5 proof 6: evaluate is a write. A page handed to the owner refuses it, the owner's yes or not,
/// as it refuses a click; under `light` and `full` every script is asked about first and runs with the
/// owner's yes. Reading the console and the network is not asked about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evaluate_is_a_write_and_is_asked_about_under_guardrails() {
    const ASK: &str = "Confirm first: a script can do whatever the page's own scripts can.";
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    for guardrails in ["light", "full"] {
        let lane = Lane::start_dev_tools(&chrome, guardrails).await;
        let a = lane.open("a", "/engine/basic").await;
        let script = |confirmed: bool| json!({ "pageId": a, "function": "() => document.title", "ownerConfirmed": confirmed });
        let asked = lane.err("evaluate", script(false), "a").await;
        assert!(asked.starts_with(ASK), "{guardrails}: {asked}");
        assert_eq!(lane.ok("evaluate", script(true), "a").await["result"], json!("Browser fixture"));
        lane.ok("console", json!({ "pageId": a }), "a").await;
        lane.ok("network", json!({ "pageId": a }), "a").await;

        lane.ok("show", json!({ "pageId": a }), "a").await;
        for confirmed in [false, true] {
            let handed = lane.err("evaluate", script(confirmed), "a").await;
            assert!(handed.contains("handed to the owner"), "{guardrails}: {handed}");
            let click = lane
                .act("a", &a, json!({ "action": "click", "selector": "#go", "ownerConfirmed": confirmed }))
                .await;
            assert!(click.unwrap_err().contains("handed to the owner"), "{guardrails}");
        }
        lane.finish().await;
    }
}

/// One reload of `engine/devtools` on a fresh page: the CDP events Chrome sent the extension, and those
/// it forwarded (`CdpExtension::traffic_total`), after `before` ran on the page.
async fn reload_traffic(lane: &Lane, before: impl AsyncFnOnce(&str)) -> cdp_extension::Traffic {
    let a = lane.open("a", "/engine/devtools").await;
    lane.ok("wait", json!({ "pageId": a, "selector": "#state", "text": "done" }), "a").await;
    before(&a).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let start = lane.ext.traffic_total();
    lane.act("a", &a, json!({ "action": "reload" })).await.unwrap();
    lane.ok("wait", json!({ "pageId": a, "selector": "#state", "text": "done" }), "a").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let end = lane.ext.traffic_total();
    lane.ok("close", json!({ "pageId": a }), "a").await;
    cdp_extension::Traffic {
        sent: end.sent - start.sent,
        forwarded: end.forwarded - start.forwarded,
        devtools: end.devtools - start.devtools,
    }
}

/// Phase 5 proof 5: a page nobody asks about forwards no developer-tools event and about as many events
/// as before the developer tools, with them off or on; a recording page forwards its console and network
/// events besides. The counts are printed for the PR. The exact rule, event by event, is proven in
/// `extension/test/events.test.mjs`; Chrome's counts move by a few between loads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recording_traffic_is_counted() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_with(&chrome, "parity").await;
    let off = reload_traffic(&lane, async |_| {}).await;
    lane.finish().await;
    let lane = Lane::start_dev_tools(&chrome, "parity").await;
    let unasked = reload_traffic(&lane, async |_| {}).await;
    let recording = reload_traffic(&lane, async |a| {
        lane.ok("console", json!({ "pageId": a }), "a").await;
        lane.ok("network", json!({ "pageId": a }), "a").await;
    })
    .await;
    lane.finish().await;
    eprintln!(
        "lane3 traffic, one reload of engine/devtools (events forwarded / sent by Chrome): devTools off {}/{}, \
         on but never asked {}/{}, recording {}/{} of them {} developer-tools events",
        off.forwarded,
        off.sent,
        unasked.forwarded,
        unasked.sent,
        recording.forwarded,
        recording.sent,
        recording.devtools
    );
    // No developer-tools event crosses for a page nobody asked about: what crosses is what crossed before.
    assert_eq!((off.devtools, unasked.devtools), (0, 0));
    assert!(recording.devtools > 0, "{recording:?}");
    // Chrome's own count of a load's events (lifecycle, frames, its iframe's) moves by a few from run to
    // run with timing, so the other counts are compared within that: 4 events, or a tenth.
    let near = |a: usize, b: usize| a.abs_diff(b) <= 4.max(a.max(b) / 10);
    assert!(near(unasked.forwarded, off.forwarded), "a page never asked forwards what it did before");
    assert!(near(recording.forwarded - recording.devtools, unasked.forwarded), "{recording:?} {unasked:?}");
}

/// What a password phantab filled could be written as: the fixture password's leak forms and the
/// password reversed (the reviewer's script hands it back reversed, past the echo redaction).
fn password_forms() -> Vec<String> {
    use phantab_testkit::sign_in::{CODE, PASSWORD, fixture_leak_forms};
    let mut forms: Vec<String> = fixture_leak_forms().into_iter().filter(|f| f != CODE).collect();
    forms.push(PASSWORD.chars().rev().collect());
    forms
}

/// `text` holds no form of the fixture password; a failure names where, never the text.
fn no_password(text: &str, what: &str) {
    let found = password_forms().iter().position(|f| text.contains(f.as_str()));
    assert_eq!(found, None, "{what}: a form of the password reached the agent");
}

/// The page's inputs' values, by a script (which marks the page; that only refuses fills).
async fn inputs(lane: &Lane, page: &str) -> Value {
    let read = "() => [...document.querySelectorAll('input')].map((i) => i.value)";
    lane.ok("evaluate", json!({ "pageId": page, "function": read }), "a").await["result"].clone()
}

const SCRIPTED_SIGN_IN: &str = "sign-in refused: a script ran on this page (browser_evaluate)";
const SCRIPTED_SIGN_UP: &str = "sign-up refused: a script ran on this page (browser_evaluate)";
const FILLED: &str = "evaluate refused: phantab filled a password into this page";
const SIGN_UP_ON_PAGE: &str = "evaluate refused: this page holds the new password a sign-up filled";

/// THREAT-MODEL SR-90, a script first, with the review's own case: a script leaves an `input` listener
/// and a timer that copy any password field's value, reversed, into the title and the console. The
/// sign-in that follows is refused before the provider is asked, nothing is filled, and no later script
/// or console read holds the password in any form. The tab stays refused for sign-in and sign-up after
/// a navigation or reload; a fresh page signs in and signs up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tab_a_script_ran_on_is_never_signed_in_or_up() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_signing(&chrome, "parity", &json!({ "devTools": true })).await;
    let mut said: Vec<String> = Vec::new();
    let a = lane.open("a", "/sign-in/one").await;
    lane.ok("console", json!({ "pageId": a }), "a").await;
    let hook = "() => {
        const reversed = (s) => [...s].reverse().join('');
        const copy = () => {
            for (const f of document.querySelectorAll('input[type=password]')) {
                if (f.value) { document.title = reversed(f.value); console.error('copied ' + reversed(f.value)); }
            }
        };
        document.addEventListener('input', copy, true);
        setInterval(copy, 50);
        return 'installed';
    }";
    let installed = lane.ok("evaluate", json!({ "pageId": a, "function": hook }), "a").await;
    assert_eq!(installed["result"], json!("installed"), "{installed}");
    let refused = lane.err("sign_in", json!({ "pageId": a }), "a").await;
    let fresh = refused.ends_with("Open a fresh page for the sign-in.");
    assert!(refused.starts_with(SCRIPTED_SIGN_IN) && fresh, "{refused}");
    said.push(refused);
    assert_eq!(lane.provider_asked(), 0, "the provider was never asked");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(inputs(&lane, &a).await, json!(["", ""]), "nothing was filled");
    let title = lane.ok("evaluate", json!({ "pageId": a, "function": "() => document.title" }), "a").await;
    assert_eq!(title["result"], json!("Sign in"), "{title}");
    said.push(title.to_string());
    said.push(lane.ok("console", json!({ "pageId": a }), "a").await.to_string());

    // The same tab after a navigation: still refused, for both.
    let to = |path: &str| json!({ "action": "navigate", "url": lane.fixtures.url(path) });
    lane.act("a", &a, to("/sign-in/one")).await.unwrap();
    let again = lane.err("sign_in", json!({ "pageId": a }), "a").await;
    assert!(again.starts_with(SCRIPTED_SIGN_IN), "{again}");
    lane.act("a", &a, to("/signup/basic")).await.unwrap();
    let up = json!({ "pageId": a, "username": "new-user@example.test" });
    let up_refused = lane.err("sign_up", up, "a").await;
    assert!(
        up_refused.starts_with(SCRIPTED_SIGN_UP) && up_refused.ends_with("for the sign-up."),
        "{up_refused}"
    );

    // A sign-up page a script ran on, then after a reload of it.
    let b = lane.open("a", "/signup/basic").await;
    lane.ok("evaluate", json!({ "pageId": b, "function": "() => 1" }), "a").await;
    let up = json!({ "pageId": b, "username": "new-user@example.test" });
    assert!(lane.err("sign_up", up.clone(), "a").await.starts_with(SCRIPTED_SIGN_UP));
    lane.act("a", &b, json!({ "action": "reload" })).await.unwrap();
    assert!(lane.err("sign_up", up, "a").await.starts_with(SCRIPTED_SIGN_UP));
    assert_eq!(inputs(&lane, &b).await, json!(["", ""]), "nothing was filled");
    assert_eq!(lane.provider_asked(), 0, "the provider was never asked");

    // Fresh pages: both work.
    let c = lane.open("a", "/sign-in/one").await;
    let signed = lane.ok("sign_in", json!({ "pageId": c }), "a").await;
    assert_eq!(signed["status"], json!("submitted"), "{signed}");
    let d = lane.open("a", "/signup/basic").await;
    let up = lane.ok("sign_up", json!({ "pageId": d, "username": "new-user@example.test" }), "a").await;
    assert_eq!(up["status"], json!("filled"), "{up}");
    assert!(lane.provider_asked() > 0, "the fresh pages asked the provider");
    said.push(signed.to_string());
    said.push(up.to_string());
    for text in &said {
        no_password(text, "an answer");
    }
    lane.finish().await;
}

/// THREAT-MODEL SR-90, a fill first: a sign-in fills a page that keeps its document (the fixture's
/// form sends by `fetch`, and its own code keeps what was typed). No script runs there until the page
/// reloads; then one runs and cannot read the password. A sign-up's page refuses scripts while its new
/// password is in the field (SR-80), and after the field is emptied, until its document is replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_a_password_was_filled_into_runs_no_script() {
    use phantab_testkit::sign_in::PASSWORD;
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_signing(&chrome, "parity", &json!({ "devTools": true })).await;
    let a = lane.open("a", "/sign-in/react").await;
    let signed = lane.ok("sign_in", json!({ "pageId": a }), "a").await;
    assert!(signed["status"].is_string(), "{signed}");
    let sent = async || lane.fixtures.posts().iter().any(|p| p.form("pass").as_deref() == Some(PASSWORD));
    assert!(lane.until(Duration::from_secs(5), sent).await, "the password was filled, and the site sent it");
    let read =
        json!({ "pageId": a, "function": "() => [document.querySelector('#p').value, window.reactState]" });
    let refused = lane.err("evaluate", read.clone(), "a").await;
    let lifts = refused.ends_with("A reload of the page, or a fresh page, lifts this.");
    assert!(refused.starts_with(FILLED) && lifts, "{refused}");
    assert!(lane.err("evaluate", read.clone(), "a").await.starts_with(FILLED), "refused again");
    no_password(&lane.ok("console", json!({ "pageId": a }), "a").await.to_string(), "the console");
    lane.act("a", &a, json!({ "action": "reload" })).await.unwrap();
    let after = lane.ok("evaluate", read, "a").await;
    assert_eq!(after["result"], json!(["", ""]), "{after}");
    no_password(&after.to_string(), "a script after the reload");

    // Sign-up: refused while the new password is in its field, then by the fill's own mark.
    let b = lane.open("a", "/signup/basic").await;
    let up = lane.ok("sign_up", json!({ "pageId": b, "username": "new-user@example.test" }), "a").await;
    assert_eq!(up["status"], json!("filled"), "{up}");
    let script = json!({ "pageId": b, "function": "() => document.querySelector('[name=pw]').value" });
    let on_page = lane.err("evaluate", script.clone(), "a").await;
    assert!(on_page.starts_with(SIGN_UP_ON_PAGE), "{on_page}");
    lane.act("a", &b, json!({ "action": "fill", "selector": "[name=pw]", "text": "" })).await.unwrap();
    let filled = lane.err("evaluate", script.clone(), "a").await;
    assert!(filled.starts_with(FILLED), "{filled}");
    lane.act("a", &b, json!({ "action": "reload" })).await.unwrap();
    let after = lane.ok("evaluate", script, "a").await;
    assert_eq!(after["result"], json!(""), "{after}");
    lane.finish().await;
}

/// THREAT-MODEL SR-90: a script that never started marks nothing. Refused with the setting off,
/// refused for the owner's yes under `light`, refused on a page handed to the owner: the sign-in after
/// each goes on and fills.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_script_leaves_its_page_open_to_sign_in() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let script = |page: &str| json!({ "pageId": page, "function": "() => document.title" });
    let lane = Lane::start_signing(&chrome, "parity", &json!({})).await;
    let a = lane.open("a", "/sign-in/one").await;
    let off = lane.err("evaluate", script(&a), "a").await;
    assert!(off.contains("off unless \"devTools\": true is set"), "{off}");
    let signed = lane.ok("sign_in", json!({ "pageId": a }), "a").await;
    assert_eq!(signed["status"], json!("submitted"), "{signed}");
    lane.finish().await;

    let lane = Lane::start_signing(&chrome, "light", &json!({ "devTools": true })).await;
    let a = lane.open("a", "/sign-in/one").await;
    let ask = lane.err("evaluate", script(&a), "a").await;
    assert!(ask.starts_with("Confirm first"), "{ask}");
    lane.ok("show", json!({ "pageId": a }), "a").await;
    let mut held = script(&a);
    held["ownerConfirmed"] = json!(true);
    let handed = lane.err("evaluate", held, "a").await;
    assert!(handed.contains("handed to the owner"), "{handed}");
    lane.ok("resume", json!({ "pageId": a, "ownerConfirmed": true }), "a").await;
    let signed = lane.ok("sign_in", json!({ "pageId": a }), "a").await;
    assert_eq!(signed["status"], json!("submitted"), "{signed}");
    lane.finish().await;
}
