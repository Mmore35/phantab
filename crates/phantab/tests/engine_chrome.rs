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
    async fn start(chrome: &PathBuf) -> Self {
        let fixtures = FixtureServer::start().unwrap();
        let rt = Runtime::new();
        rt.install_extension_in_profile();
        // `full`, so the handback rules below still hold (docs/GUARDRAILS.md).
        rt.write_config(&json!({
            "profileDirectory": "test", "userDataDir": rt.user_data_dir(), "chromeExecutable": chrome,
            "guardrails": "full",
        }));
        let svc = tokio::task::block_in_place(|| {
            let child = rt
                .command(&["serve"])
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
    let lane = Lane::start(&chrome).await;

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
    let wrong = lane.act("c", &c, json!({ "action": "select", "selector": "#choice", "text": "Three" })).await;
    let wrong = wrong.unwrap_err();
    assert!(wrong.starts_with("#choice: no option has the value or label \"Three\"") && wrong.contains("\"Two\" (value \"two\")"), "{wrong}");
    lane.act("c", &c, json!({ "action": "click", "selector": "#agree" })).await.unwrap();
    let snap = lane.snap("c", &c).await;
    let control = |id: &str| snap["elements"].as_array().unwrap().iter().find(|e| e["id"] == json!(id)).cloned();
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
    assert!(absent.starts_with("#nowhere: not found after ") && absent.contains("stopped changing"), "{absent}");
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
    // A selector for an open shadow root's element fails saying where click_xy reaches it.
    let inside = element(&snap, "shadow").unwrap();
    let told = lane.act("a", &a, json!({ "action": "click", "selector": "#shadow" })).await.unwrap_err();
    let place = format!("an open shadow root has it at {},{}: click_xy reaches it", inside["x"], inside["y"]);
    assert!(told.starts_with("#shadow: not found in the document (") && told.contains(&place), "{told}");
    for id in ["light", "shadow", "sameframe", "otherframe"] {
        let e = element(&snap, id).unwrap();
        let r = lane.act("a", &a, json!({ "action": "click_xy", "x": e["x"], "y": e["y"] })).await;
        assert!(r.is_ok(), "click_xy on {id} at {},{}: {r:?}", e["x"], e["y"]);
    }
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
        let stepped = call("browser_act", json!({ "steps": [["fill", "#name", "by steps"], ["click", "#go"]] }));
        assert_eq!(stepped["isError"], Value::Null, "{stepped}");
        let said = stepped["content"][0]["text"].as_str().unwrap_or_default();
        assert!(said.starts_with(&format!("{{\"pageId\":\"{page}\"")) && said.contains("by steps"), "{said}");
        let quiet = call("browser_act", json!({ "steps": [["fill", "#name", "from mcp"]], "snapshot": false }));
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
        let read = call("browser_snapshot", json!({ "full": true }));
        let said = read["content"][0]["text"].as_str().unwrap_or_default();
        assert!(said.starts_with(&format!("{{\"pageId\":\"{page}\"")), "{said}");
        let closed = call("browser_close", json!({ "pageId": page }));
        assert_eq!(closed["isError"], Value::Null, "{closed}");
        // Once that page is closed, there is none to default to.
        let none = call("browser_act", json!({ "action": "click", "selector": "#go" }));
        assert_eq!(none["isError"], json!(true), "{none}");
        assert!(none["content"][0]["text"].as_str().unwrap_or_default().starts_with("No page yet to default to"), "{none}");
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
