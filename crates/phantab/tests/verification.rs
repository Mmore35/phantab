//! Lane 3 for the verification hand-off: `phantab serve` → bridge → engine, against
//! the fake extension that does every bridge op on a real headless Chrome (`common/cdp_extension.rs`), and
//! the stand-in checks in `phantab-testkit/fixtures/verify/` (never a real provider's). Each test is one of
//! the owner's requirements, measured end to end:
//!
//! - a wall pops up after its grace and goes down by itself once the owner clears it, with no agent call;
//! - the agent keeps working on other sites meanwhile, and same-site writes say why they wait;
//! - a check that clears by itself never pops up;
//! - a page the owner already holds stays with him;
//! - a widget on a working page waits for the agent to ask; a closed page ends its check;
//! - and throughout, Phantab sends no input to a page with a check on it: the owner's own presses here
//!   come from outside the relay, so any `Input.*` on that tab would be Phantab's.
//!
//! Skips without `PHANTAB_TEST_CHROME`. Window strategy `None`: a pop-up is the `markShown true` op, its end
//! `markShown false`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::too_many_lines, reason = "each test reads as one hand-off from start to end")]

#[path = "common/cdp_extension.rs"]
mod cdp_extension;
mod common;

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

/// `engine::verify::GRACE`: how long a wall may clear by itself before it pops up.
const GRACE: Duration = Duration::from_secs(8);

/// The owner pressing the stand-in check in the page's first frame, as his own click would.
const PRESS_THE_CHECK: &str =
    "document.querySelector('iframe').contentDocument.getElementById('human').click(); true";

struct Lane {
    ext: CdpExtension,
    browser: Arc<Browser>,
    svc: Service,
    rt: Runtime,
    fixtures: FixtureServer,
    /// The remote view's listener, when the lane set `remoteViewer`.
    remote_port: Option<u16>,
}

/// What the remote lane's `publicBaseUrl` names: the Host the owner's device sends through his route.
const REMOTE_HOST: &str = "mypc.test:8490";
const IDENTITY: (&str, &str) = ("Tailscale-User-Login", "owner@example.test");

impl Lane {
    async fn start(chrome: &PathBuf) -> Self {
        Self::start_with(chrome, None, None).await
    }

    /// A lane whose service signs in with the fake provider, answering from `provider.json` in its
    /// runtime directory, on the loopback fixtures.
    /// It runs the remote view too, as [`Self::start_remote`].
    async fn start_signing(chrome: &PathBuf) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        Self::start_with(chrome, Some(port), Some(json!({"values": {"username": "me@example.test"}}))).await
    }

    /// A lane whose service also runs the remote view, on a free loopback port.
    async fn start_remote(chrome: &PathBuf) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        Self::start_with(chrome, Some(port), None).await
    }

    async fn start_with(chrome: &PathBuf, remote_port: Option<u16>, provider: Option<Value>) -> Self {
        let fixtures = FixtureServer::start().unwrap();
        let rt = Runtime::new();
        rt.install_extension_in_profile();
        let mut config = json!({
            "profileDirectory": "test", "userDataDir": rt.user_data_dir(), "chromeExecutable": chrome,
        });
        if let Some(p) = remote_port {
            config["remoteViewer"] = json!({
                "listen": format!("127.0.0.1:{p}"),
                "publicBaseUrl": format!("http://{REMOTE_HOST}/"),
                "trustedIdentity": { "header": IDENTITY.0, "equals": IDENTITY.1 },
            });
        }
        if let Some(control) = &provider {
            let path = rt.path().join("provider.json");
            std::fs::write(&path, control.to_string()).unwrap();
            config["signInProvider"] =
                json!({"command": [env!("CARGO_BIN_EXE_phantab-fake-provider"), path]});
        }
        rt.write_config(&config);
        let svc = tokio::task::block_in_place(|| {
            let mut serve = rt.command(&["serve"]);
            if provider.is_some() {
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
            tokio::task::block_in_place(|| CdpExtension::connect(stream, "verify", Arc::clone(&browser)));
        let lane = Self { ext, browser, svc, rt, fixtures, remote_port };
        assert!(
            lane.until(Duration::from_secs(10), async || {
                lane.call("status", json!({}), "test").await.is_ok_and(|s| s["connected"] == json!(true))
            })
            .await
        );
        let status = lane.call("connect", json!({}), "test").await.unwrap();
        assert_eq!(status["profileVerified"], json!(true), "{status}");
        lane
    }

    /// A call that runs on its own, so the test can go on while it waits.
    fn spawn_call(
        &self,
        method: &str,
        args: Value,
        client: &str,
    ) -> tokio::task::JoinHandle<Result<Value, String>> {
        let (port, token) = (self.svc.endpoint.port, self.svc.endpoint.token.clone());
        let (method, client) = (method.to_owned(), client.to_owned());
        tokio::task::spawn_blocking(move || {
            let v = common::rpc(port, &token, &method, &args, &client);
            match v.get("error") {
                Some(e) => Err(e.as_str().unwrap_or_default().to_owned()),
                None => Ok(v["result"].clone()),
            }
        })
    }

    async fn call(&self, method: &str, args: Value, client: &str) -> Result<Value, String> {
        self.spawn_call(method, args, client).await.unwrap()
    }

    async fn ok(&self, method: &str, args: Value, client: &str) -> Value {
        match self.call(method, args.clone(), client).await {
            Ok(v) => v,
            Err(e) => panic!("{method} {args} for {client}: {e}"),
        }
    }

    /// Opens `url` and returns the page's result and its tab in the fake extension.
    async fn open_url(&self, client: &str, url: &str) -> (Value, String, i64) {
        let r = self.ok("open", json!({ "url": url }), client).await;
        let id = r["pageId"].as_str().unwrap().to_owned();
        (r, id, self.ext.last_window_tab())
    }

    async fn open(&self, client: &str, path: &str) -> (Value, String, i64) {
        self.open_url(client, &self.fixtures.url(path)).await
    }

    async fn act(&self, client: &str, page: &str, mut args: Value) -> Result<Value, String> {
        args["pageId"] = json!(page);
        self.call("act", args, client).await
    }

    async fn text(&self, client: &str, page: &str) -> String {
        let snap = self.ok("snapshot", json!({ "pageId": page }), client).await;
        snap["text"].as_str().unwrap_or_default().to_owned()
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

    /// When the fake extension first logged `entry` at or after `since`.
    fn logged(&self, entry: &str, since: Instant) -> Option<Instant> {
        self.ext.timeline().into_iter().find(|(t, e)| *t >= since && e == entry).map(|(t, _)| t)
    }

    async fn wait_logged(&self, entry: &str, since: Instant, within: Duration) -> Instant {
        let end = Instant::now() + within;
        loop {
            if let Some(t) = self.logged(entry, since) {
                return t;
            }
            assert!(Instant::now() < end, "no {entry} within {within:?}: {:?}", self.ext.timeline());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Every `Input.*` command sent to `tab` in `[from, to)`.
    fn input_sent(&self, tab: i64, from: Instant, to: Instant) -> Vec<String> {
        let prefix = format!("send {tab} Input.");
        self.ext
            .timeline()
            .into_iter()
            .filter(|(t, e)| *t >= from && *t < to && e.starts_with(&prefix))
            .map(|(_, e)| e)
            .collect()
    }

    /// A request to the remote listener as the owner's route sends it: his Host and identity, unless
    /// `headers` sets its own.
    fn remote(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> common::Reply {
        let mut all: Vec<(&str, &str)> = headers.to_vec();
        for (k, v) in [("Host", REMOTE_HOST), IDENTITY] {
            if !headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(k)) {
                all.push((k, v));
            }
        }
        all.retain(|(_, v)| !v.is_empty());
        let port = self.remote_port.unwrap();
        tokio::task::block_in_place(|| common::request(port, method, path, &all, body)).unwrap()
    }

    /// One viewer call over the remote listener with a link's token.
    fn relay(&self, token: &str, action: &str, args: &Value) -> common::Reply {
        let auth = format!("Bearer {token}");
        let body = json!({ "action": action, "args": args }).to_string();
        self.remote(
            "POST",
            "/viewer",
            &[("Authorization", &auth), ("Content-Type", "application/json")],
            body.as_bytes(),
        )
    }

    /// The link's token, from a result's `verification`.
    fn token_of(result: &Value) -> String {
        let link = result["verification"]["link"].as_str().unwrap_or_else(|| panic!("no link: {result}"));
        let prefix = format!("http://{REMOTE_HOST}/view#");
        link.strip_prefix(&prefix).unwrap_or_else(|| panic!("{link}")).to_owned()
    }

    /// Waits for the hand-off's link: the pop-up adds it a moment after the check goes to the owner.
    async fn link_token(&self, client: &str, page: &str) -> String {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let snap = self.ok("snapshot", json!({ "pageId": page }), client).await;
            if snap["verification"]["link"].is_string() {
                return Self::token_of(&snap);
            }
            assert!(Instant::now() < end, "no link: {snap}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// An element's box in the page's viewport, `[x, y, width, height]`.
    async fn box_of(&self, tab: i64, expression: &str) -> (f64, f64, f64, f64) {
        let js = format!(
            "(() => {{ const b = ({expression}).getBoundingClientRect(); return [b.x, b.y, b.width, b.height]; }})()"
        );
        let v = self.ext.eval(tab, &js).await;
        let n = |i: usize| v[i].as_f64().unwrap_or_else(|| panic!("{v}"));
        (n(0), n(1), n(2), n(3))
    }

    async fn finish(self) {
        let Self { ext, browser, svc, rt, fixtures, .. } = self;
        drop(ext);
        tokio::task::block_in_place(|| drop(svc));
        let _ = browser.close().await;
        drop(rt);
        drop(fixtures);
    }
}

fn ms(d: Duration) -> u128 {
    d.as_millis()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wall_pops_up_after_its_grace_and_goes_down_by_itself_while_the_agent_keeps_working() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;

    let (_, a, a_tab) = lane.open("a", "/verify/shop").await;
    let (_, same_site, _) = lane.open("a", "/engine/basic").await;
    lane.act("a", &a, json!({ "action": "fill", "selector": "#keep", "text": "draft before the wall" }))
        .await
        .unwrap();
    // The site's wall takes the page over in place.
    let walled = lane.act("a", &a, json!({ "action": "click", "selector": "#more" })).await.unwrap();
    let began = Instant::now();
    let check = &walled["verification"];
    assert_eq!(check["state"], json!("checking"), "{walled}");
    assert_eq!(check["kind"], json!("wall"), "{walled}");
    assert!(
        check.get("link").is_none(),
        "no link before the pop-up, and none without remoteViewer: {walled}"
    );
    let grace_refusal =
        lane.act("a", &a, json!({ "action": "click", "selector": "#more" })).await.unwrap_err();
    assert!(grace_refusal.contains("giving itself a few seconds"), "{grace_refusal}");
    let waiting = lane.spawn_call("wait", json!({ "pageId": a, "verification": true }), "a");

    // One click: the pop-up, after the grace, with no agent call asking for it.
    let shown = lane.wait_logged("markShown true", began, GRACE + Duration::from_secs(3)).await;
    let popped_after = shown - began;
    assert!(
        popped_after >= GRACE.saturating_sub(Duration::from_millis(600)),
        "popped up early: {popped_after:?}"
    );
    assert!(popped_after <= GRACE + Duration::from_secs(1), "popped up late: {popped_after:?}");
    // The wait wakes as the owner gets it, so the agent can tell him (and post a link, with remoteViewer).
    let woken = waiting.await.unwrap().unwrap();
    assert_eq!(woken["verification"]["state"], json!("with-owner"), "{woken}");
    let waiting = lane.spawn_call("wait", json!({ "pageId": a, "verification": true }), "a");

    // The agent keeps running: another site works while the owner has this one.
    let work = Instant::now();
    let (_, other, _) = lane.open_url("a", &lane.fixtures.twin_url("/engine/basic")).await;
    lane.act("a", &other, json!({ "action": "fill", "selector": "#name", "text": "still working" }))
        .await
        .unwrap();
    lane.act("a", &other, json!({ "action": "click", "selector": "#go" })).await.unwrap();
    assert!(lane.text("a", &other).await.contains("still working"));
    let other_site_ms = ms(work.elapsed());
    let same_site_refusal =
        lane.act("a", &same_site, json!({ "action": "click", "selector": "#go" })).await.unwrap_err();
    assert!(same_site_refusal.contains("is with the owner"), "{same_site_refusal}");
    assert!(same_site_refusal.contains("verification: true"), "it says how to wait: {same_site_refusal}");
    // Another session writing to the site is refused as before, with nothing of this page's check.
    let (_, theirs, _) = lane.open("b", "/engine/basic").await;
    let other = lane.act("b", &theirs, json!({ "action": "click", "selector": "#go" })).await.unwrap_err();
    assert!(other.contains("Another agent or human handoff holds this site"), "{other}");
    assert!(!other.contains(&a) && !other.contains("verification"), "{other}");
    assert!(lane.logged("markShown false", began).is_none(), "still with the owner");

    // The owner clears it; the page goes back by itself.
    lane.ext.eval(a_tab, PRESS_THE_CHECK).await;
    let cleared_at = Instant::now();
    let hidden = lane.wait_logged("markShown false", shown, Duration::from_secs(5)).await;
    let hidden_after = hidden - cleared_at;
    assert!(hidden_after <= Duration::from_secs(3), "hid {hidden_after:?} after the clear");
    let waited = waiting.await.unwrap().unwrap();
    assert_eq!(waited["verification"]["state"], json!("cleared"), "{waited}");

    // Phantab never touched the check: no input reached the page between the wall and its end.
    let touched = lane.input_sent(a_tab, began, hidden);
    assert!(touched.is_empty(), "input sent to a page with a check on it: {touched:?}");

    // The next write works, and the draft typed before the wall is still there.
    lane.act("a", &a, json!({ "action": "click", "selector": "#keep" })).await.unwrap();
    assert!(lane.text("a", &a).await.contains("passed via"));
    let kept = lane.ext.eval(a_tab, "document.getElementById('keep').value").await;
    assert_eq!(kept, json!("draft before the wall"));
    lane.act("a", &same_site, json!({ "action": "click", "selector": "#go" })).await.unwrap();

    eprintln!(
        "wall: popped up {}ms after it began (grace {}ms); another site's open+fill+snapshot {other_site_ms}ms \
         during the hand-off; hidden {}ms after the clear",
        ms(popped_after),
        ms(GRACE),
        ms(hidden_after)
    );
    lane.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_check_that_clears_by_itself_never_pops_up() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;

    let start = Instant::now();
    let (opened, a, a_tab) = lane.open("a", "/verify/autoclear").await;
    assert_eq!(opened["verification"]["state"], json!("checking"), "{opened}");
    let (_, unwatched, _) = lane.open("a", "/verify/autoclear").await;
    let waited = lane.ok("wait", json!({ "pageId": a, "verification": true }), "a").await;
    let took = start.elapsed();
    assert_eq!(waited["verification"]["state"], json!("cleared"), "{waited}");
    assert!(took < GRACE, "cleared within the grace: {took:?}");
    assert!(lane.logged("markShown true", start).is_none(), "no pop-up: {:?}", lane.ext.timeline());
    assert!(lane.input_sent(a_tab, start, Instant::now()).is_empty(), "the watcher only reads");
    lane.act("a", &a, json!({ "action": "fill", "selector": "#keep", "text": "carry on" })).await.unwrap();
    // The other page cleared with no call watching it; the first wait after says so.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = lane.ok("wait", json!({ "pageId": unwatched, "verification": true }), "a").await;
    assert_eq!(after["verification"]["state"], json!("cleared"), "{after}");
    eprintln!("autoclear: cleared {}ms after open, no pop-up", ms(took));
    lane.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_the_owner_already_holds_stays_with_him() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;

    let (_, a, a_tab) = lane.open("a", "/verify/shop").await;
    let start = Instant::now();
    lane.ok("show", json!({ "pageId": a }), "a").await;
    lane.wait_logged("markShown true", start, Duration::from_secs(2)).await;
    // The owner, using the page, runs into the wall himself.
    lane.ext.eval(a_tab, "document.getElementById('more').click(); true").await;
    let waiting = lane.spawn_call("wait", json!({ "pageId": a, "verification": true }), "a");
    tokio::time::sleep(Duration::from_secs(1)).await;
    lane.ext.eval(a_tab, PRESS_THE_CHECK).await;
    let waited = waiting.await.unwrap().unwrap();
    assert_eq!(waited["verification"]["state"], json!("cleared"), "{waited}");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        lane.logged("markShown false", start).is_none(),
        "the page stays shown: {:?}",
        lane.ext.timeline()
    );
    let still = lane.act("a", &a, json!({ "action": "click", "selector": "#keep" })).await.unwrap_err();
    assert!(still.contains("handed to the owner"), "{still}");
    // His handback, as before.
    lane.ok("resume", json!({ "pageId": a, "ownerConfirmed": true }), "a").await;
    lane.wait_logged("markShown false", start, Duration::from_secs(2)).await;
    assert_eq!(lane.input_sent(a_tab, start, Instant::now()), Vec::<String>::new());
    lane.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_widget_waits_for_the_agent_to_ask_and_a_closed_page_ends_its_check() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;

    // A page with nothing but a word in its title is not a check.
    let (plain, _, _) = lane.open("a", "/verify/captcha-word-title").await;
    assert!(plain.get("verification").is_none(), "{plain}");
    // A check parked offscreen, as auth.tesla.com keeps one, asks nothing of the owner: no check, no pop-up.
    let parked = Instant::now();
    let (offscreen, o, _) = lane.open("a", "/verify/offscreen").await;
    assert!(offscreen.get("verification").is_none(), "{offscreen}");
    let snap = lane.ok("snapshot", json!({ "pageId": o }), "a").await;
    assert!(snap.get("verification").is_none(), "{snap}");
    lane.ok("close", json!({ "pageId": o }), "a").await;
    assert!(lane.logged("markShown true", parked).is_none(), "no pop-up for an offscreen check");

    // A widget on a page that still works: Phantab says so and does nothing until asked.
    let start = Instant::now();
    let (opened, w, w_tab) = lane.open("a", "/verify/widget").await;
    assert_eq!(opened["verification"]["state"], json!("widget"), "{opened}");
    assert!(opened["verification"]["next"].as_str().unwrap_or_default().contains("verification: true"));
    lane.act("a", &w, json!({ "action": "fill", "selector": "#email", "text": "me@example.test" }))
        .await
        .unwrap();
    assert!(lane.logged("markShown true", start).is_none(), "no pop-up for a widget unasked");
    let asked = Instant::now();
    let shown = lane.ok("show", json!({ "pageId": w, "verification": true }), "a").await;
    assert_eq!(shown["verification"]["state"], json!("with-owner"), "{shown}");
    let popped = lane.wait_logged("markShown true", asked, Duration::from_secs(2)).await;
    let waiting = lane.spawn_call("wait", json!({ "pageId": w, "verification": true }), "a");
    lane.ext.eval(w_tab, PRESS_THE_CHECK).await;
    let waited = waiting.await.unwrap().unwrap();
    assert_eq!(waited["verification"]["state"], json!("cleared"), "{waited}");
    let hidden = lane.wait_logged("markShown false", popped, Duration::from_secs(2)).await;
    assert_eq!(lane.input_sent(w_tab, asked, hidden), Vec::<String>::new());
    lane.act("a", &w, json!({ "action": "click", "selector": "#send" })).await.unwrap();

    // A page whose only content is the challenge frame is a wall, whatever its title.
    let (only, c, _) = lane.open("a", "/verify/challenge-only").await;
    assert_eq!(only["verification"]["kind"], json!("wall"), "{only}");
    lane.ok("close", json!({ "pageId": c }), "a").await;

    // A wall nobody passes: closing its page, even shown, ends the check.
    let start = Instant::now();
    let (_, n, _) = lane.open("a", "/verify/never").await;
    lane.wait_logged("markShown true", start, GRACE + Duration::from_secs(3)).await;
    lane.ok("close", json!({ "pageId": n }), "a").await;
    let pages = lane.ok("pages", json!({}), "a").await;
    assert!(
        pages.as_array().unwrap().iter().all(|p| p["pageId"] != json!(n) && p["pageId"] != json!(c)),
        "{pages}"
    );
    // The closed challenge-only page never popped up after its close.
    assert_eq!(
        lane.ext.timeline().iter().filter(|(t, e)| *t >= start && e == "markShown true").count(),
        1,
        "{:?}",
        lane.ext.timeline()
    );
    lane.finish().await;
}

/// Every file under `dir`, read whole.
fn files_under(dir: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for e in entries.flatten() {
        let path = e.path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push((path, bytes));
        }
    }
    out
}

/// The owner's other device: the remote listener answers only the live view, only through
/// his route (exact Host, his identity), only with a live link's token. A press-and-hold clears through his
/// own relayed pointer, Phantab sends nothing of its own, and the link dies with the check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_hands_the_check_to_another_device_and_opens_nothing_else() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_remote(&chrome).await;

    let status = lane.ok("status", json!({}), "a").await;
    assert_eq!(
        status["remoteViewer"],
        json!({ "listening": true, "url": format!("http://{REMOTE_HOST}"), "identityChecked": true }),
        "{status}"
    );

    // The page itself, through the owner's route.
    let page = lane.remote("GET", "/view", &[], b"");
    assert_eq!(page.status, 200);
    assert!(String::from_utf8_lossy(&page.body).contains("fetch('/viewer'"));
    assert!(page.header("content-security-policy").is_some_and(|c| c.contains("frame-ancestors 'none'")));
    // Anything else, or anyone else, is refused.
    let port = lane.remote_port.unwrap();
    let local_host = format!("127.0.0.1:{port}");
    for (why, headers, want) in [
        ("the loopback Host", vec![("Host", local_host.as_str())], 403),
        ("the MagicDNS Host", vec![("Host", "mypc.tail0000.ts.net:8490")], 403),
        ("no identity", vec![(IDENTITY.0, "")], 403),
        ("another identity", vec![(IDENTITY.0, "someone@example.test")], 403),
        ("another site's page", vec![("Origin", "http://evil.test")], 403),
    ] {
        assert_eq!(lane.remote("GET", "/view", &headers, b"").status, want, "{why}");
    }
    let auth = format!("Bearer {}", lane.svc.endpoint.token);
    let rpc = json!({ "method": "status", "args": {}, "client": "a" }).to_string();
    assert_eq!(lane.remote("POST", "/rpc", &[("Authorization", &auth)], rpc.as_bytes()).status, 404);
    for path in ["/health", "/hello?nonce=00000000000000000000000000000000", "/rpc"] {
        assert_eq!(lane.remote("GET", path, &[], b"").status, 404, "{path}");
    }
    let join = lane.remote("GET", "/bridge", &[("Authorization", &auth), ("Upgrade", "phantab-bridge")], b"");
    assert_eq!(join.status, 404, "the bridge cannot join here");

    // A press-and-hold wall. Its link reaches the agent once it pops up.
    let (opened, a, a_tab) = lane.open("a", "/verify/hold").await;
    let began = Instant::now();
    assert_eq!(opened["verification"]["kind"], json!("wall"), "{opened}");
    assert!(opened["verification"].get("link").is_none(), "no link during the grace: {opened}");
    let waiting = lane.spawn_call("wait", json!({ "pageId": a, "verification": true }), "a");
    lane.wait_logged("markShown true", began, GRACE + Duration::from_secs(3)).await;
    // The wait wakes as the owner gets it, with a link that already works.
    let woken = waiting.await.unwrap().unwrap();
    assert_eq!(woken["verification"]["state"], json!("with-owner"), "{woken}");
    let token = Lane::token_of(&woken);
    assert_eq!(lane.relay(&token, "frame", &json!({})).status, 200, "the link works as it is given");
    // With the link comes the wake: this binary, then check-wait and a token that is not the link's.
    let wake = woken["verification"]["wake"].as_str().unwrap_or_else(|| panic!("no wake: {woken}"));
    let bin = common::BIN.replace('\\', "/");
    let watch = wake
        .strip_prefix(&format!("\"{bin}\" check-wait "))
        .unwrap_or_else(|| panic!("{wake} is not {bin}'s check-wait"))
        .to_owned();
    assert!(watch.len() == 48 && watch != token, "{wake}");
    assert_eq!(lane.relay(&watch, "frame", &json!({})).status, 400, "the wake token opens no view");
    // The agent starts it in the background before ending its turn; it exits once the check ends.
    let waker = lane
        .rt
        .command(&["check-wait", &watch])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let waiting = lane.spawn_call("wait", json!({ "pageId": a, "verification": true }), "a");
    // A write to the page is refused with the same link, for the agent to post once.
    let refused = lane.act("a", &a, json!({ "action": "click", "selector": "#b" })).await.unwrap_err();
    assert!(refused.contains(&format!("http://{REMOTE_HOST}/view#{token}")), "{refused}");

    // The link is for the remote listener only; the local one does not take it.
    let body = json!({ "action": "frame", "args": {} }).to_string();
    let local = tokio::task::block_in_place(|| {
        common::request(
            lane.svc.endpoint.port,
            "POST",
            "/viewer",
            &[("Authorization", &format!("Bearer {token}"))],
            body.as_bytes(),
        )
    })
    .unwrap();
    assert_eq!(local.status, 400);
    assert_eq!(local.json()["error"], json!("This handoff has ended."));
    // The route checks hold for the viewer calls too.
    let wrong = lane.remote(
        "POST",
        "/viewer",
        &[(IDENTITY.0, "someone@example.test"), ("Authorization", &format!("Bearer {token}"))],
        body.as_bytes(),
    );
    assert_eq!(wrong.status, 403);

    let frame = lane.relay(&token, "frame", &json!({})).json();
    let seen = &frame["result"];
    assert_eq!(seen["checking"], json!(true), "{frame}");
    assert!(seen["image"].as_str().is_some_and(|i| i.len() > 1000));
    assert!(seen["clip"]["width"].as_f64().is_some_and(|w| w > 100.0), "{frame}");

    // The owner holds the button for 1.6 s from his device: his pointer, relayed as he moves it.
    let (left, top, width, height) = lane.box_of(a_tab, "document.getElementById('b')").await;
    let (cx, cy) = (left + width / 2.0, top + height / 2.0);
    let held_from = Instant::now();
    assert_eq!(lane.relay(&token, "pointer", &json!({ "type": "down", "x": cx, "y": cy })).status, 200);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let held = lane.ext.eval(a_tab, "getComputedStyle(document.getElementById('b')).backgroundColor").await;
    assert_eq!(held, json!("rgb(0, 170, 0)"), "the press reached the page");
    assert_eq!(lane.relay(&token, "pointer", &json!({ "type": "up", "x": cx, "y": cy })).status, 200);
    let hidden = lane.wait_logged("markShown false", held_from, Duration::from_secs(5)).await;
    let waited = waiting.await.unwrap().unwrap();
    assert_eq!(waited["verification"]["state"], json!("cleared"), "{waited}");
    let exited = tokio::task::spawn_blocking(move || waker.wait_with_output()).await.unwrap().unwrap();
    assert!(exited.status.success(), "{exited:?}");
    assert_eq!(String::from_utf8_lossy(&exited.stdout), format!("verification cleared on page {a}\n"));
    assert!(lane.text("a", &a).await.contains("Order history"));

    // The only input the page got was the owner's: two moves, a press, a release.
    let sent = lane.input_sent(a_tab, began, hidden);
    assert_eq!(sent.len(), 4, "{sent:?}");
    assert!(sent.iter().all(|e| e.ends_with("Input.dispatchMouseEvent")), "{sent:?}");
    assert!(lane.input_sent(a_tab, began, held_from).is_empty(), "nothing before the owner's press");

    // The link died with the check, and its token was never written down.
    let after = lane.relay(&token, "frame", &json!({}));
    assert_eq!(after.status, 400);
    assert_eq!(after.json()["error"], json!("This handoff has ended."));
    let status = lane.ok("status", json!({}), "a").await;
    assert!(!status.to_string().contains(&token) && !status.to_string().contains(&watch));
    for (path, bytes) in files_under(lane.rt.path()) {
        for t in [&token, &watch] {
            assert!(!bytes.windows(t.len()).any(|w| w == t.as_bytes()), "a token in {}", path.display());
        }
    }
    eprintln!(
        "remote: hold cleared {}ms after the owner's release",
        ms((hidden - held_from).saturating_sub(Duration::from_millis(1600)))
    );
    lane.finish().await;
}

/// A slider and a widget, cleared from the owner's device through the relayed pointer: the slider by his
/// drag, the widget by his tap on the zoomed view mapped back onto the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slider_and_a_widget_clear_through_the_owners_relayed_pointer() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_remote(&chrome).await;

    let (_, s, s_tab) = lane.open("a", "/verify/slider").await;
    let began = Instant::now();
    let waiting = lane.spawn_call("wait", json!({ "pageId": s, "verification": true }), "a");
    lane.wait_logged("markShown true", began, GRACE + Duration::from_secs(3)).await;
    let token = Lane::token_of(&waiting.await.unwrap().unwrap());
    let waiting = lane.spawn_call("wait", json!({ "pageId": s, "verification": true }), "a");
    let (left, top, width, height) = lane.box_of(s_tab, "document.getElementById('k')").await;
    let (x0, cy) = (left + width / 2.0, top + height / 2.0);
    let dragged_from = Instant::now();
    assert_eq!(lane.relay(&token, "pointer", &json!({ "type": "down", "x": x0, "y": cy })).status, 200);
    for step in 1..=8 {
        let px = x0 + 270.0 * f64::from(step) / 8.0;
        assert_eq!(lane.relay(&token, "pointer", &json!({ "type": "move", "x": px, "y": cy })).status, 200);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(lane.relay(&token, "pointer", &json!({ "type": "up", "x": x0 + 270.0, "y": cy })).status, 200);
    let hidden = lane.wait_logged("markShown false", dragged_from, Duration::from_secs(5)).await;
    assert_eq!(waiting.await.unwrap().unwrap()["verification"]["state"], json!("cleared"));
    assert!(lane.input_sent(s_tab, began, dragged_from).is_empty(), "nothing before the owner's drag");
    assert!(
        lane.input_sent(s_tab, dragged_from, hidden).iter().all(|e| e.ends_with("Input.dispatchMouseEvent"))
    );

    // A widget: the agent asks, and the link opens zoomed onto the check.
    let (_, wg, w_tab) = lane.open("a", "/verify/widget").await;
    let asked = Instant::now();
    let shown = lane.ok("show", json!({ "pageId": wg, "verification": true }), "a").await;
    let token = if shown["verification"]["link"].is_string() {
        Lane::token_of(&shown)
    } else {
        lane.link_token("a", &wg).await
    };
    let frame = lane.relay(&token, "frame", &json!({})).json();
    let seen = &frame["result"];
    assert_eq!(seen["zoomed"], json!(true), "{frame}");
    let whole = lane.relay(&token, "frame", &json!({ "whole": true })).json();
    assert_eq!(whole["result"]["zoomed"], json!(false), "the owner can see the whole page: {whole}");
    // His tap on the zoomed image, a third of the way in, mapped back as the viewer page maps it.
    let (fx, fy, _, _) = lane.box_of(w_tab, "document.querySelector('iframe')").await;
    let (tx, ty) = (fx + 26.0, fy + 26.0);
    let clip = &seen["clip"];
    let (cx, cy) = (clip["x"].as_f64().unwrap(), clip["y"].as_f64().unwrap());
    assert!(tx > cx && ty > cy, "the check is inside the zoomed view: {clip}");
    let tapped = Instant::now();
    for kind in ["down", "up"] {
        assert_eq!(lane.relay(&token, "pointer", &json!({ "type": kind, "x": tx, "y": ty })).status, 200);
    }
    let hidden = lane.wait_logged("markShown false", tapped, Duration::from_secs(5)).await;
    let filled = lane.ext.eval(w_tab, "document.getElementById('g-recaptcha-response').value").await;
    assert!(filled.as_str().is_some_and(|v| v.starts_with("tok-")), "{filled}");
    assert!(lane.input_sent(w_tab, asked, tapped).is_empty(), "nothing before the owner's tap");
    assert_eq!(lane.input_sent(w_tab, tapped, hidden).len(), 4);
    lane.act("a", &wg, json!({ "action": "click", "selector": "#send" })).await.unwrap();
    lane.finish().await;
}

/// The viewer's own buttons, from the owner's device: Done while the site still shows its check is refused
/// (Phantab looks for itself), and Not now ends the check as declined, hides the page and kills the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn done_is_refused_while_the_check_shows_and_not_now_hands_the_page_back() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_remote(&chrome).await;

    let (_, a, a_tab) = lane.open("a", "/verify/hold").await;
    let began = Instant::now();
    let waiting = lane.spawn_call("wait", json!({ "pageId": a, "verification": true }), "a");
    lane.wait_logged("markShown true", began, GRACE + Duration::from_secs(3)).await;
    let token = Lane::token_of(&waiting.await.unwrap().unwrap());
    let waiting = lane.spawn_call("wait", json!({ "pageId": a, "verification": true }), "a");

    let done = lane.relay(&token, "done", &json!({}));
    assert_eq!(done.status, 400);
    assert_eq!(
        done.json()["error"],
        json!("The site still shows a check. Finish it, then press Done again.")
    );
    assert_eq!(
        lane.relay(&token, "frame", &json!({})).json()["result"]["checking"],
        json!(true),
        "still live"
    );

    assert!(lane.input_sent(a_tab, began, Instant::now()).is_empty(), "Done sends the page nothing");

    // His device presses the button, then he gives up before letting go (or his phone locks mid-hold).
    let (left, top, width, height) = lane.box_of(a_tab, "document.getElementById('b')").await;
    let pressed = Instant::now();
    let at = json!({ "type": "down", "x": left + width / 2.0, "y": top + height / 2.0 });
    assert_eq!(lane.relay(&token, "pointer", &at).status, 200);
    let declined_at = Instant::now();
    assert_eq!(lane.relay(&token, "decline", &json!({})).status, 200);
    lane.wait_logged("markShown false", declined_at, Duration::from_secs(5)).await;
    let waited = waiting.await.unwrap().unwrap();
    assert_eq!(waited["verification"]["state"], json!("declined"), "{waited}");
    assert_eq!(lane.relay(&token, "frame", &json!({})).json()["error"], json!("This handoff has ended."));
    assert!(lane.input_sent(a_tab, began, pressed).is_empty(), "the buttons send the page nothing");

    // The press he left down is let go once the check is over, where he held it (the page's pointerup,
    // too short a hold to pass), and the page takes the agent's clicks again.
    let let_go = lane
        .until(Duration::from_secs(3), async || {
            let log = lane.ext.eval(a_tab, "document.getElementById('log').textContent").await;
            log.as_str().is_some_and(|l| l.contains("up:true"))
        })
        .await;
    assert!(let_go, "the held press was released: {:?}", lane.input_sent(a_tab, pressed, Instant::now()));
    assert!(!lane.input_sent(a_tab, declined_at, Instant::now()).is_empty(), "released after Not now");
    let basic = lane.fixtures.url("/engine/basic");
    lane.act("a", &a, json!({ "action": "navigate", "url": basic })).await.unwrap();
    lane.act("a", &a, json!({ "action": "click", "selector": "#go" })).await.unwrap();
    lane.finish().await;
}

/// A passkey request is the owner's to give: a sign-in that meets one hands the tab to him
/// at once, with no grace, the agent's writes on the page wait, Done is refused while the request is
/// open, and the page's answer hands it back. The fixture's passkey pop-up is a stand-in that never
/// calls the browser's own `WebAuthn` (docs/TESTING.md § 4 rule 9).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_passkey_request_goes_to_the_owner_at_once_and_its_answer_hands_the_page_back() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start_signing(&chrome).await;

    let (_, p, tab) = lane.open("a", "/sign-in/passkey-ask").await;
    let began = Instant::now();
    let signed = lane.ok("sign_in", json!({ "pageId": p }), "a").await;
    assert_eq!((&signed["status"], &signed["reason"]), (&json!("wall"), &json!("passkey")), "{signed}");
    let v = &signed["verification"];
    assert_eq!((&v["kind"], &v["state"]), (&json!("passkey"), &json!("with-owner")), "{signed}");
    assert!(v["next"].as_str().unwrap_or_default().contains("passkey"), "{signed}");
    let shown = lane.wait_logged("markShown true", began, Duration::from_secs(3)).await;
    assert!(shown - began < GRACE, "no grace for a passkey");

    let refused = lane.act("a", &p, json!({ "action": "click", "selector": "button" })).await.unwrap_err();
    assert!(refused.contains("passkey"), "{refused}");
    let token = lane.link_token("a", &p).await;
    let frame = lane.relay(&token, "frame", &json!({})).json();
    assert_eq!(frame["result"]["passkey"], json!(true), "the viewer says passkey");
    let done = lane.relay(&token, "done", &json!({}));
    assert_eq!(done.status, 400);
    assert_eq!(
        done.json()["error"],
        json!(
            "The site is still waiting for your passkey. Give it in the pop-up, or close the pop-up, then press Done again."
        )
    );
    let waiting = lane.spawn_call("wait", json!({ "pageId": p, "verification": true }), "a");

    // The owner confirms it in the pop-up: the page gets its answer and signs in.
    let answered = Instant::now();
    lane.ext.eval(tab, "window.answerPasskey(); true").await;
    let waited = waiting.await.unwrap().unwrap();
    assert_eq!(waited["verification"]["state"], json!("cleared"), "{waited}");
    let hidden = lane.wait_logged("markShown false", answered, Duration::from_secs(5)).await;
    assert_eq!(lane.input_sent(tab, shown, hidden), Vec::<String>::new(), "the owner's alone");
    assert!(lane.text("a", &p).await.contains("Welcome back"), "{}", lane.text("a", &p).await);
    lane.finish().await;
}

/// `browser_show {verification: true}` hands over a page whose passkey request waits (the agent clicked
/// the site's passkey button itself), the same way a sign-in does; before it, the same
/// page has no check to show.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn show_hands_over_a_page_whose_passkey_request_waits() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;

    let (_, p, tab) = lane.open("a", "/sign-in/passkey-ask").await;
    let none = lane.call("show", json!({ "pageId": p, "verification": true }), "a").await.unwrap_err();
    assert!(none.contains("No verification check"), "{none}");

    lane.act("a", &p, json!({ "action": "click", "selector": "button" })).await.unwrap();
    let asked = Instant::now();
    let shown = lane.ok("show", json!({ "pageId": p, "verification": true }), "a").await;
    let v = &shown["verification"];
    assert_eq!((&v["kind"], &v["state"]), (&json!("passkey"), &json!("with-owner")), "{shown}");
    let popped = lane.wait_logged("markShown true", asked, Duration::from_secs(3)).await;
    assert!(popped - asked < GRACE, "no grace for a passkey");
    let waiting = lane.spawn_call("wait", json!({ "pageId": p, "verification": true }), "a");

    let answered = Instant::now();
    lane.ext.eval(tab, "window.answerPasskey(); true").await;
    let waited = waiting.await.unwrap().unwrap();
    assert_eq!(waited["verification"]["state"], json!("cleared"), "{waited}");
    let hidden = lane.wait_logged("markShown false", answered, Duration::from_secs(5)).await;
    assert_eq!(lane.input_sent(tab, popped, hidden), Vec::<String>::new(), "the owner's alone");
    lane.finish().await;
}
