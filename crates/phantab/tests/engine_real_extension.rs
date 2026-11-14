//! Lane 4: the real bridge extension in branded Chrome, with the platform's window strategy (`OsHook` on
//! Windows, `ExtensionMinimize` on macOS). open (a hidden agent window), snapshot, act, show, resume and
//! close, through `phantab serve`, the native host (this binary, started by Chrome) and the extension
//! built from `extension/`. A second Chrome profile then gets its own copy of the bridge (SR-76) and is
//! driven through `profile`. Last, the service is killed and the extension's cleanup closes a hidden page.
//!
//! Everything is the test's own: a temp runtime and Chrome user-data dir, a Chrome it starts, and a
//! test-only native host name, `dev.phantab.bridge_test_<pid>`. On Windows that name is registered under
//! HKCU for the run and deleted after. On macOS its manifest goes in the temp user-data dir's own
//! `NativeMessagingHosts`, which Chrome reads for a custom `--user-data-dir`, so nothing outside the temp
//! dir is written. The owner's `dev.phantab.bridge`, Chrome and profile are never touched.
//!
//! Opt-in: `PHANTAB_TEST_CHROME` (branded Chrome, which still honours `Extensions.loadUnpacked` with
//! `--enable-unsafe-extension-debugging`) and `PHANTAB_TEST_REAL_EXTENSION=1`, since `show` puts a
//! window on the desktop for a moment. Needs `npm` for the extension build.
#![cfg(any(windows, target_os = "macos"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{BIN, Runtime, Service};
use phantab_cdp::{Browser, Transport as _, TransportEvent};
use phantab_testkit::FixtureServer;
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

const TEST_HOST_PREFIX: &str = "dev.phantab.bridge_test_";
#[cfg(windows)]
const HOSTS_KEY: &str = r"HKCU\Software\Google\Chrome\NativeMessagingHosts";

/// The test host's HKCU key, deleted on drop. Refuses any name but a test one.
#[cfg(windows)]
struct HostKey(String);

#[cfg(windows)]
impl HostKey {
    fn register(name: &str, manifest: &Path, _user_data: &Path) -> Self {
        assert!(name.starts_with(TEST_HOST_PREFIX) && name.len() > TEST_HOST_PREFIX.len(), "{name}");
        let key = format!(r"{HOSTS_KEY}\{name}");
        let manifest = manifest.to_str().unwrap();
        let ok = Command::new("reg")
            .args(["add", &key, "/ve", "/t", "REG_SZ", "/d", manifest, "/f"])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "reg add {key}");
        Self(key)
    }

    fn is_gone(name: &str) -> bool {
        let query = Command::new("reg")
            .args(["query", &format!(r"{HOSTS_KEY}\{name}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        !query.success()
    }
}

#[cfg(windows)]
impl Drop for HostKey {
    fn drop(&mut self) {
        let _ = Command::new("reg")
            .args(["delete", &self.0, "/f"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// macOS: the test host's manifest in the temp user-data dir's `NativeMessagingHosts`, removed on drop.
/// Refuses any name but a test one.
#[cfg(target_os = "macos")]
struct HostKey(PathBuf);

#[cfg(target_os = "macos")]
impl HostKey {
    fn register(name: &str, manifest: &Path, user_data: &Path) -> Self {
        assert!(name.starts_with(TEST_HOST_PREFIX) && name.len() > TEST_HOST_PREFIX.len(), "{name}");
        let dir = user_data.join("NativeMessagingHosts");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.json"));
        std::fs::copy(manifest, &path).unwrap();
        Self(path)
    }

    fn is_gone(_name: &str) -> bool {
        // Drop removed the file and asserted it; nothing outside the temp dir was written.
        true
    }
}

#[cfg(target_os = "macos")]
impl Drop for HostKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        assert!(!self.0.exists(), "the test host manifest was removed");
    }
}

/// The Chrome this test started: closed over CDP, then its own process killed if it is still there.
struct Chrome {
    child: Child,
    browser: Option<Arc<Browser>>,
}

impl Chrome {
    async fn close(mut self) {
        if let Some(b) = self.browser.take() {
            let _ = b.close().await;
        }
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end && self.child.try_wait().ok().flatten().is_none() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for Chrome {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn build_extension(host: &str, out: &Path) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extension");
    let mut npm = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "npm"]);
        c
    } else {
        Command::new("npm")
    };
    let ok = npm
        .args(["run", "build:test", "--", "--host", host, "--out"])
        .arg(out)
        .current_dir(&dir)
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "npm run build:test in {}", dir.display());
}

async fn rpc(svc: &Service, method: &str, args: Value, client: &str) -> Result<Value, String> {
    let (port, token) = (svc.endpoint.port, svc.endpoint.token.clone());
    let (method, client) = (method.to_owned(), client.to_owned());
    let v = tokio::task::spawn_blocking(move || common::rpc(port, &token, &method, &args, &client))
        .await
        .unwrap();
    match v.get("error") {
        Some(e) => Err(e.as_str().unwrap_or_default().to_owned()),
        None => Ok(v["result"].clone()),
    }
}

async fn ok(svc: &Service, method: &str, args: Value) -> Value {
    match rpc(svc, method, args.clone(), "l4").await {
        Ok(v) => v,
        Err(e) => panic!("{method} {args}: {e}"),
    }
}

/// Chrome's own `windowState` for the window holding the page at `url`.
async fn window_state_of(browser: &Browser, url: &str) -> String {
    let targets = browser.connection().send(None, "Target.getTargets", json!({})).await.unwrap();
    let target = targets["targetInfos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["type"] == "page" && t["url"] == url)
        .unwrap_or_else(|| panic!("no page at {url}: {targets}"));
    let window = browser
        .connection()
        .send(None, "Browser.getWindowForTarget", json!({ "targetId": target["targetId"] }))
        .await
        .unwrap();
    window["bounds"]["windowState"].as_str().unwrap_or_default().to_owned()
}

/// The target id of the page at `url`, if one is open.
async fn target_of(browser: &Browser, url: &str) -> Option<String> {
    let targets = browser.connection().send(None, "Target.getTargets", json!({})).await.unwrap();
    targets["targetInfos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["type"] == "page" && t["url"] == url)
        .and_then(|t| t["targetId"].as_str().map(str::to_owned))
}

/// Chrome's own `windowState` for a window; `None` once the window is gone.
#[cfg(target_os = "macos")]
async fn bounds_state(browser: &Browser, window: &Value) -> Option<String> {
    let bounds =
        browser.connection().send(None, "Browser.getWindowBounds", json!({ "windowId": window })).await;
    bounds.ok().map(|b| b["bounds"]["windowState"].as_str().unwrap_or_default().to_owned())
}

/// A CDP session of the test's own on a page: it sees the page's dialogs and answers none.
async fn watch_dialogs(browser: &Browser, target: &str) -> UnboundedReceiver<TransportEvent> {
    let observer = browser
        .connection()
        .send(None, "Target.attachToTarget", json!({ "targetId": target, "flatten": true }))
        .await;
    let observer = phantab_cdp::SessionId(observer.unwrap()["sessionId"].as_str().unwrap().to_owned());
    let events = browser.connection().take_events(&observer);
    browser.connection().send(Some(&observer), "Page.enable", json!({})).await.unwrap();
    events
}

/// The dialogs a `watch_dialogs` session has seen open so far.
fn dialogs_opened(events: &mut UnboundedReceiver<TransportEvent>) -> Vec<Value> {
    let mut opened = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let TransportEvent::Event { method, params, .. } = event
            && method == "Page.javascriptDialogOpening"
        {
            opened.push(params);
        }
    }
    opened
}

/// Watches a hidden page's window through its close: every state it reads, every 20 ms, until it is gone
/// or the returned flag is set.
///
/// A leave on navigation restores the window for a moment, and it is minimized again (the extension's
/// keepMinimized). The state can read minimized before that restore starts and before a minimize animation
/// ends, and a close in either was not seen to restore the window even on the old close path (window
/// server, 2026-11-05). So the watch starts after 3 s of minimized reads in a row.
#[cfg(target_os = "macos")]
async fn watch_close(
    browser: &Arc<Browser>,
    target: &str,
) -> (tokio::task::JoinHandle<Vec<String>>, Arc<AtomicBool>) {
    let window = browser
        .connection()
        .send(None, "Browser.getWindowForTarget", json!({ "targetId": target }))
        .await
        .unwrap()["windowId"]
        .clone();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut since = Instant::now();
    while since.elapsed() < Duration::from_secs(3) {
        if bounds_state(browser, &window).await.as_deref() != Some("minimized") {
            since = Instant::now();
        }
        assert!(Instant::now() < deadline, "the hidden window stays minimized before its close");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (browser, flag) = (Arc::clone(browser), Arc::clone(&stop));
    let polling = tokio::spawn(async move {
        let mut seen = Vec::<String>::new();
        loop {
            let state = bounds_state(&browser, &window).await.unwrap_or_else(|| "gone".to_owned());
            if seen.last() != Some(&state) {
                seen.push(state.clone());
            }
            if state == "gone" || flag.load(Ordering::SeqCst) {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    (polling, stop)
}

/// What the extension itself sees, for a failure message: every window's state and tabs, and its session
/// storage. A macOS agent window that reads normal needs both sides to tell which one is wrong.
#[cfg(target_os = "macos")]
async fn extension_view(browser: &Browser) -> String {
    let targets = browser.connection().send(None, "Target.getTargets", json!({})).await.unwrap();
    let Some(worker) = targets["targetInfos"].as_array().unwrap().iter().find(|t| {
        t["type"] == "service_worker"
            && t["url"].as_str().unwrap_or_default().starts_with("chrome-extension://")
    }) else {
        return format!("no extension worker: {targets}");
    };
    let attached = browser
        .connection()
        .send(None, "Target.attachToTarget", json!({ "targetId": worker["targetId"], "flatten": true }))
        .await;
    let session = match attached {
        Ok(v) => phantab_cdp::SessionId(v["sessionId"].as_str().unwrap_or_default().to_owned()),
        Err(e) => return format!("attach failed: {e}"),
    };
    let expression = r"(async () => JSON.stringify({
        windows: (await chrome.windows.getAll({ populate: true })).map(w => ({
            id: w.id, state: w.state, focused: w.focused, type: w.type,
            tabs: (w.tabs || []).map(t => t.url || t.pendingUrl),
        })),
        session: await chrome.storage.session.get(null),
    }))()";
    let value = browser
        .connection()
        .send(
            Some(&session),
            "Runtime.evaluate",
            json!({ "expression": expression, "awaitPromise": true, "returnByValue": true }),
        )
        .await;
    let _ =
        browser.connection().send(None, "Target.detachFromTarget", json!({ "sessionId": session.0 })).await;
    match value {
        Ok(v) => v["result"]["value"].as_str().map_or_else(|| v.to_string(), str::to_owned),
        Err(e) => format!("evaluate failed: {e}"),
    }
}

fn ms(t: Instant) -> u128 {
    t.elapsed().as_millis()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_extension_opens_a_hidden_window_shows_it_and_resumes() {
    let Some(chrome) = std::env::var_os("PHANTAB_TEST_CHROME").map(PathBuf::from) else { return };
    if std::env::var("PHANTAB_TEST_REAL_EXTENSION").as_deref() != Ok("1") {
        eprintln!("lane4 skipped: set PHANTAB_TEST_REAL_EXTENSION=1");
        return;
    }
    let fixtures = FixtureServer::start().unwrap();
    let rt = Runtime::new();
    let host = format!("{TEST_HOST_PREFIX}{}", std::process::id());
    let ext_dir = rt.path().join("extension");
    build_extension(&host, &ext_dir);

    let manifest = rt.path().join(format!("{host}.json"));
    let id = phantab::bridge::EXTENSION_ID.as_str();
    let body = json!({
        "name": host, "description": "phantab lane-4 test host", "path": BIN, "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{id}/")],
    });
    std::fs::write(&manifest, body.to_string()).unwrap();
    let user_data = rt.path().join("chrome-l4");
    std::fs::create_dir_all(&user_data).unwrap();
    let key = HostKey::register(&host, &manifest, &user_data);
    // SR-76: Profile 2 is allowed besides the usual Default, with its own copy of the bridge where install
    // puts one: the built bridge and a profile.json naming the folder.
    let other = "Profile 2";
    let other_ext = rt.path().join("extension-profiles").join(other).join("extension");
    build_extension(&host, &other_ext);
    std::fs::write(other_ext.join("profile.json"), json!({ "profile": other }).to_string()).unwrap();
    rt.write_config(&json!({
        "profileDirectory": "Default", "userDataDir": user_data, "chromeExecutable": chrome,
        "otherProfiles": [other],
    }));
    let mut svc = tokio::task::block_in_place(|| rt.serve());

    // Chrome, and the native host it starts, see only the test runtime.
    let env = rt.command(&[]);
    let mut cmd = Command::new(&chrome);
    for (k, v) in env.get_envs() {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    let child = cmd
        .arg(format!("--user-data-dir={}", user_data.display()))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "--remote-debugging-port=0",
            "--enable-unsafe-extension-debugging",
            // macOS: Chrome runs with the test's own HOME, where the Keychain holds no "Chrome Safe
            // Storage" key. Without these the network service waits on the Keychain for it, and the
            // first http navigation never commits ("Page.navigate timed out"; a data: page still loads).
            // phantab-cdp's launcher passes the same two.
            "--use-mock-keychain",
            "--password-store=basic",
            "--window-position=-2400,-2400",
            "--window-size=800,600",
            "about:blank",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut chrome_proc = Chrome { child, browser: None };
    let port_file = user_data.join("DevToolsActivePort");
    let end = Instant::now() + Duration::from_secs(20);
    let ws = loop {
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                break format!("ws://127.0.0.1:{port}{path}");
            }
        }
        assert!(Instant::now() < end, "Chrome wrote no DevToolsActivePort");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let browser = Arc::new(Browser::connect(&ws).await.unwrap());
    chrome_proc.browser = Some(Arc::clone(&browser));
    let t = Instant::now();
    let loaded =
        browser.connection().send(None, "Extensions.loadUnpacked", json!({ "path": ext_dir })).await.unwrap();
    assert_eq!(loaded["id"], json!(id), "the manifest key keeps the real ID");

    // The extension starts the host, the host joins the service; Chrome writes the profile's
    // extension list a little later.
    let mut status = Value::Null;
    let end = Instant::now() + Duration::from_secs(45);
    while Instant::now() < end {
        status = rpc(&svc, "connect", json!({}), "l4").await.unwrap_or(Value::Null);
        if status["profileVerified"] == json!(true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(status["profileVerified"], json!(true), "{status}");
    let connect_ms = ms(t);

    let t = Instant::now();
    let opened = ok(&svc, "open", json!({ "url": fixtures.url("/engine/basic") })).await;
    let open_ms = ms(t);
    let page = opened["pageId"].as_str().unwrap().to_owned();
    assert_eq!(opened["mode"], json!("shared-hidden"), "{opened}");
    // macOS hides by minimizing, so the agent window must be minimized as Chrome itself reports it. A
    // `focused: false` create once left it normal, on the owner's screen.
    if cfg!(target_os = "macos") {
        let state = window_state_of(&browser, &fixtures.url("/engine/basic")).await;
        assert_eq!(state, "minimized", "the agent window is hidden");
    }

    let t = Instant::now();
    let snap = ok(&svc, "snapshot", json!({ "pageId": page })).await;
    let snap_ms = ms(t);
    assert_eq!(snap["title"], json!("Browser fixture"), "{snap}");

    let t = Instant::now();
    ok(&svc, "act", json!({ "pageId": page, "action": "fill", "selector": "#name", "text": "lane four" }))
        .await;
    let act_ms = ms(t);
    let shot = ok(&svc, "screenshot", json!({ "pageId": page })).await;
    assert!(shot["data"].as_str().unwrap().starts_with("/9j/"), "a hidden window still paints");

    let t = Instant::now();
    let shown = ok(&svc, "show", json!({ "pageId": page })).await;
    let show_ms = ms(t);
    assert_eq!(shown["handoff"], json!("actual-tab"), "{shown}");
    let t = Instant::now();
    ok(&svc, "resume", json!({ "pageId": page, "ownerConfirmed": true })).await;
    let resume_ms = ms(t);
    let after = ok(&svc, "snapshot", json!({ "pageId": page })).await;
    assert_eq!(after["paused"], json!(false), "{after}");
    let closed = ok(&svc, "close", json!({ "pageId": page })).await;
    assert_eq!(closed["closedOwnedTab"], json!(true), "{closed}");
    eprintln!(
        "lane4 timings: connect {connect_ms} ms, open {open_ms} ms, snapshot {snap_ms} ms, act {act_ms} ms, show {show_ms} ms, resume {resume_ms} ms"
    );

    // A hidden page's dialogs: Chrome drew its "Leave site?" on the owner's screen with no window behind it,
    // and the close or navigation waited for an answer. The extension answers them and the agent is told.
    let opened = ok(&svc, "open", json!({ "url": fixtures.url("/engine/dialogs") })).await;
    // Every new agent window is hidden, also after the owner was shown and closed one.
    if cfg!(target_os = "macos") {
        let state = window_state_of(&browser, &fixtures.url("/engine/dialogs")).await;
        assert_eq!(state, "minimized", "the second agent window is hidden");
    }
    let page = opened["pageId"].as_str().unwrap().to_owned();
    let act = |action: Value| {
        let mut args = action;
        args["pageId"] = json!(page);
        ok(&svc, "act", args)
    };
    let asked = act(json!({ "action": "click", "selector": "#ask" })).await;
    assert_eq!(
        asked["dialogs"],
        json!([{ "type": "confirm", "message": "Delete it?", "answer": "dismissed" }]),
        "{asked}"
    );
    let told = act(json!({ "action": "click", "selector": "#tell" })).await;
    assert_eq!(
        told["dialogs"],
        json!([{ "type": "alert", "message": "Saved", "answer": "accepted" }]),
        "{told}"
    );
    let snap = ok(&svc, "snapshot", json!({ "pageId": page })).await;
    assert!(snap["text"].as_str().unwrap_or_default().contains("told"), "{snap}");
    assert!(snap.get("dialogs").is_none(), "each dialog is reported once: {snap}");
    // A key press is user activation, which Chrome needs before it asks "Leave site?".
    act(json!({ "action": "press", "key": "a" })).await;
    let t = Instant::now();
    let left = act(json!({ "action": "navigate", "url": fixtures.url("/engine/basic") })).await;
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "the navigation did not wait on Leave site? ({} ms)",
        ms(t)
    );
    assert!(left.get("dialogs").is_none(), "the accepted leave is the navigation asked for: {left}");
    act(json!({ "action": "navigate", "url": fixtures.url("/engine/dialogs") })).await;
    act(json!({ "action": "press", "key": "a" })).await;
    // Closing it must ask nothing: Chrome restored the minimized window to draw that "Leave site?", on the
    // owner's screen until the window went (docs/MAC.md). The extension closes a hidden page without running
    // its beforeunload, so no dialog opens and the window stays minimized all through the close. A CDP
    // session of the test's own sees the page's dialogs; it answers none.
    let dialogs = fixtures.url("/engine/dialogs");
    let target = target_of(&browser, &dialogs).await.expect("the dialogs page");
    let mut page_events = watch_dialogs(&browser, &target).await;
    #[cfg(target_os = "macos")]
    let (polling, stop) = watch_close(&browser, &target).await;
    let t = Instant::now();
    let closed = ok(&svc, "close", json!({ "pageId": page })).await;
    let close_ms = ms(t);
    assert!(t.elapsed() < Duration::from_secs(5), "the close did not wait on Leave site? ({close_ms} ms)");
    assert_eq!(closed["closedOwnedTab"], json!(true), "{closed}");
    let deadline = Instant::now() + Duration::from_secs(2);
    while target_of(&browser, &dialogs).await.is_some() {
        assert!(Instant::now() < deadline, "the dialogs page is still open 2 s after its close");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let opened = dialogs_opened(&mut page_events);
    #[cfg(target_os = "macos")]
    {
        stop.store(true, Ordering::SeqCst);
        let seen = polling.await.unwrap();
        assert!(
            seen.iter().all(|s| s == "minimized" || s == "gone"),
            "the hidden window left minimized during its close: {seen:?}; dialogs {opened:?}"
        );
        eprintln!("lane4 hidden close: {close_ms} ms, window states {seen:?}");
    }
    assert!(opened.is_empty(), "closing the hidden page opened a dialog: {opened:?}");

    // A hidden page's popup was a new top-level window that nothing hid, drawn on the owner's screen. It opens
    // as a tab of the agent's own hidden window instead, its opener intact, and goes with that window. Chrome
    // shows the window a new tab lands in, so the window is kept hidden through that too.
    let opened = ok(&svc, "open", json!({ "url": fixtures.url("/engine/popup") })).await;
    let page = opened["pageId"].as_str().unwrap().to_owned();
    let child = fixtures.url("/engine/popup?child");
    let window_of = |url: String| {
        let browser = browser.clone();
        async move {
            let targets = browser.connection().send(None, "Target.getTargets", json!({})).await.unwrap();
            let target = targets["targetInfos"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["type"] == "page" && t["url"] == url)
                .cloned();
            match target {
                Some(t) => Some(
                    browser
                        .connection()
                        .send(None, "Browser.getWindowForTarget", json!({ "targetId": t["targetId"] }))
                        .await
                        .unwrap()["windowId"]
                        .clone(),
                ),
                None => None,
            }
        }
    };
    let home = window_of(fixtures.url("/engine/popup")).await.expect("the agent page");
    // macOS hides an agent window by minimizing it (docs/MAC.md), and Chrome restores the window a new tab
    // lands in, so the extension minimizes it again: it must read minimized once that has settled.
    #[cfg(target_os = "macos")]
    let window_state = || {
        let browser = browser.clone();
        let home = home.clone();
        async move {
            let bounds = browser
                .connection()
                .send(None, "Browser.getWindowBounds", json!({ "windowId": home }))
                .await
                .unwrap();
            bounds["bounds"]["windowState"].as_str().unwrap_or_default().to_owned()
        }
    };
    // The states the window reads until it reads minimized, for at most 5 s.
    #[cfg(target_os = "macos")]
    let settles_minimized = || async {
        let (deadline, mut seen) = (Instant::now() + Duration::from_secs(5), Vec::<String>::new());
        loop {
            let state = window_state().await;
            if seen.last() != Some(&state) {
                seen.push(state.clone());
            }
            if state == "minimized" || Instant::now() >= deadline {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    #[cfg(target_os = "macos")]
    {
        let seen = settles_minimized().await;
        assert_eq!(
            seen.last().map(String::as_str),
            Some("minimized"),
            "the agent window is hidden: {seen:?}; by target: {}; the extension sees {}; set by CDP it reads {}",
            window_state_of(&browser, &fixtures.url("/engine/popup")).await,
            extension_view(&browser).await,
            {
                let _ = browser
                    .connection()
                    .send(
                        None,
                        "Browser.setWindowBounds",
                        json!({ "windowId": home, "bounds": { "windowState": "minimized" } }),
                    )
                    .await;
                tokio::time::sleep(Duration::from_millis(1000)).await;
                window_state().await
            }
        );
    }
    #[cfg(windows)]
    let visible_before = phantab_window::platform().snapshot().await.unwrap().chrome_windows;
    ok(&svc, "act", json!({ "pageId": page, "action": "click", "selector": "#pop" })).await;
    ok(&svc, "wait", json!({ "pageId": page, "text": "Opener kept" })).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    #[cfg(target_os = "macos")]
    {
        let seen = settles_minimized().await;
        assert_eq!(
            seen.last().map(String::as_str),
            Some("minimized"),
            "the popup left the agent window shown: {seen:?}; the extension sees {}",
            extension_view(&browser).await
        );
    }
    #[cfg(windows)]
    {
        let shown: Vec<_> = phantab_window::platform()
            .snapshot()
            .await
            .unwrap()
            .chrome_windows
            .into_iter()
            .filter(|w| !visible_before.contains(w))
            .collect();
        assert!(shown.is_empty(), "the popup showed a window on the desktop: {shown:?}");
    }
    assert_eq!(window_of(child.clone()).await, Some(home), "the popup is a tab of the agent's window");
    let shot = ok(&svc, "screenshot", json!({ "pageId": page })).await;
    assert!(shot["data"].as_str().unwrap().starts_with("/9j/"), "the agent page still paints");
    let closed = ok(&svc, "close", json!({ "pageId": page })).await;
    assert_eq!(closed["closedOwnedTab"], json!(true), "{closed}");
    assert_eq!(window_of(child).await, None, "the popup went with the agent's window");

    // SR-76: a second profile, driven by name through the same calls. A second start with the same
    // user-data dir hands its command line to the running Chrome, which opens Profile 2 (made new) and
    // exits; that window's tab is the owner's own. Extensions.loadUnpacked loads into the last-active
    // profile, and the load lasts only for this Chrome run, so the copy is loaded once Profile 2's window is
    // the active one.
    let owner_tab = fixtures.url("/engine/popup");
    let mut cmd = Command::new(&chrome);
    for (k, v) in env.get_envs() {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    let handed = cmd
        .arg(format!("--user-data-dir={}", user_data.display()))
        .arg(format!("--profile-directory={other}"))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "--use-mock-keychain",
            "--password-store=basic",
            "--window-position=-2400,-2400",
            "--window-size=800,600",
        ])
        .arg(&owner_tab)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(handed.success(), "the second start handed Profile 2 to the running Chrome: {handed}");
    let end = Instant::now() + Duration::from_secs(20);
    while !user_data.join(other).join("Preferences").exists() {
        assert!(Instant::now() < end, "Chrome made no {other}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let t = Instant::now();
    let loaded = browser
        .connection()
        .send(None, "Extensions.loadUnpacked", json!({ "path": other_ext }))
        .await
        .unwrap();
    assert_eq!(loaded["id"], json!(id), "a profile's copy keeps the real ID");
    let mut status = Value::Null;
    let end = Instant::now() + Duration::from_secs(45);
    while Instant::now() < end {
        // connect answers with the whole status: the top-level fields are the usual profile's.
        status = rpc(&svc, "connect", json!({ "profile": other }), "l4").await.unwrap_or(Value::Null);
        if status["otherProfiles"][other]["profileVerified"] == json!(true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let verified = &status["otherProfiles"][other]["profileVerified"];
    assert_eq!(verified, &json!(true), "{other} connects with its own copy: {status}");
    let other_connect_ms = ms(t);
    // The load landed where it was meant to: Profile 2 lists its own copy and the usual profile its own.
    for (dir, want) in [(other, &other_ext), ("Default", &ext_dir)] {
        let listed = ["Secure Preferences", "Preferences"].iter().find_map(|f| {
            let prefs: Value =
                serde_json::from_slice(&std::fs::read(user_data.join(dir).join(f)).ok()?).ok()?;
            prefs["extensions"]["settings"][id]["path"].as_str().map(PathBuf::from)
        });
        let listed = listed.unwrap_or_else(|| panic!("{dir} lists no bridge"));
        assert_eq!(
            std::fs::canonicalize(&listed).unwrap(),
            std::fs::canonicalize(want).unwrap(),
            "{dir} lists the bridge from {}",
            listed.display()
        );
    }
    let usual = ok(&svc, "connect", json!({})).await;
    assert_eq!(usual["profileVerified"], json!(true), "the usual profile is still verified: {usual}");
    let both = ok(&svc, "status", json!({})).await;
    assert_eq!(both["otherProfiles"][other]["connected"], json!(true), "{both}");

    let opened = ok(&svc, "open", json!({ "url": fixtures.url("/engine/basic"), "profile": other })).await;
    assert_eq!(opened["mode"], json!("shared-hidden"), "{opened}");
    let page = opened["pageId"].as_str().unwrap().to_owned();
    if cfg!(target_os = "macos") {
        let state = window_state_of(&browser, &fixtures.url("/engine/basic")).await;
        assert_eq!(state, "minimized", "{other}'s agent window is hidden");
    }
    let snap = ok(&svc, "snapshot", json!({ "pageId": page })).await;
    assert_eq!(snap["title"], json!("Browser fixture"), "{snap}");
    ok(&svc, "act", json!({ "pageId": page, "action": "fill", "selector": "#name", "text": "profile two" }))
        .await;
    // Each profile's tabs are its own: the owner's tab in Profile 2 is listed there and not in the usual
    // profile, and the agent's page is in neither, as an agent holds it.
    let tabs = ok(&svc, "tabs", json!({ "profile": other })).await.to_string();
    assert!(tabs.contains("/engine/popup") && !tabs.contains("/engine/basic"), "{other}'s tabs: {tabs}");
    let tabs = ok(&svc, "tabs", json!({})).await.to_string();
    assert!(!tabs.contains("/engine/popup"), "the usual profile's tabs: {tabs}");
    // Hand-off goes through the page's own link.
    let t = Instant::now();
    let shown = ok(&svc, "show", json!({ "pageId": page })).await;
    let other_show_ms = ms(t);
    assert_eq!(shown["handoff"], json!("actual-tab"), "{other}'s page is shown: {shown}");
    ok(&svc, "resume", json!({ "pageId": page, "ownerConfirmed": true })).await;
    let after = ok(&svc, "snapshot", json!({ "pageId": page })).await;
    assert_eq!(after["paused"], json!(false), "{after}");
    let closed = ok(&svc, "close", json!({ "pageId": page })).await;
    assert_eq!(closed["closedOwnedTab"], json!(true), "{closed}");

    // Closing every Profile 2 window ends only Profile 2's pages: a usual page still answers. Profile 2
    // is not used again, since its copy, loaded over CDP, leaves with it.
    let usual_url = fixtures.url("/engine/basic?in=usual");
    let other_url = fixtures.url("/engine/basic?in=other");
    let usual_page =
        ok(&svc, "open", json!({ "url": usual_url })).await["pageId"].as_str().unwrap().to_owned();
    let opened = ok(&svc, "open", json!({ "url": other_url, "profile": other })).await;
    let other_page = opened["pageId"].as_str().unwrap().to_owned();
    for url in [&other_url, &owner_tab] {
        let target = target_of(&browser, url).await.unwrap_or_else(|| panic!("no {other} page at {url}"));
        browser.connection().send(None, "Target.closeTarget", json!({ "targetId": target })).await.unwrap();
    }
    let end = Instant::now() + Duration::from_secs(10);
    let mut pages = ok(&svc, "pages", json!({})).await.to_string();
    while pages.contains(&other_page) && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(100)).await;
        pages = ok(&svc, "pages", json!({})).await.to_string();
    }
    assert!(!pages.contains(&other_page), "{other}'s page ended with its window: {pages}");
    assert!(pages.contains(&usual_page), "the usual page is still held: {pages}");
    let snap = ok(&svc, "snapshot", json!({ "pageId": usual_page })).await;
    assert_eq!(snap["title"], json!("Browser fixture"), "the usual page still answers: {snap}");
    // With no window left, Chrome unloads Profile 2 and its host ends (11.5 s in the 2026-11 trials on
    // Windows). Lane 3 asserts what a profile's disconnect ends, so this is a measurement only.
    let t = Instant::now();
    let end = t + Duration::from_secs(20);
    let mut dropped = false;
    while !dropped && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(250)).await;
        dropped = ok(&svc, "status", json!({})).await["otherProfiles"][other]["connected"] == json!(false);
    }
    let drop_note = if dropped {
        format!("link dropped {} ms after its windows", ms(t))
    } else {
        "link still up after 20 s".to_owned()
    };
    let snap = ok(&svc, "snapshot", json!({ "pageId": usual_page })).await;
    assert_eq!(snap["title"], json!("Browser fixture"), "the usual page answers after {other} went: {snap}");
    let closed = ok(&svc, "close", json!({ "pageId": usual_page })).await;
    assert_eq!(closed["closedOwnedTab"], json!(true), "{closed}");
    eprintln!("lane4 {other}: connect {other_connect_ms} ms, show {other_show_ms} ms, {drop_note}");

    // A dropped service link, like a worker start, closes the hidden windows the service left (cleanup in
    // background.ts). cleanup detached the page first and then called chrome.windows.remove, so the page's
    // "Leave site?" had nobody to answer it. Killing the service ends the native host, Chrome drops the
    // extension's port, and the page must close as closeTab closes it: no dialog, the window minimized.
    let opened = ok(&svc, "open", json!({ "url": dialogs })).await;
    let page = opened["pageId"].as_str().unwrap().to_owned();
    ok(&svc, "act", json!({ "pageId": page, "action": "press", "key": "a" })).await;
    let target = target_of(&browser, &dialogs).await.expect("the dialogs page");
    let mut page_events = watch_dialogs(&browser, &target).await;
    #[cfg(target_os = "macos")]
    let (polling, stop) = watch_close(&browser, &target).await;
    let t = Instant::now();
    let mut service = svc.child.take().expect("the service is the test's child");
    service.kill().unwrap();
    service.wait().unwrap();
    // A page left open waits on a dialog; the asserts below name it before the one for the open page.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut gone = false;
    while !gone && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        gone = target_of(&browser, &dialogs).await.is_none();
    }
    let cleanup_ms = ms(t);
    let opened = dialogs_opened(&mut page_events);
    #[cfg(target_os = "macos")]
    {
        stop.store(true, Ordering::SeqCst);
        let seen = polling.await.unwrap();
        assert!(
            seen.iter().all(|s| s == "minimized" || s == "gone"),
            "the hidden window left minimized during cleanup: {seen:?}; dialogs {opened:?}"
        );
        eprintln!("lane4 cleanup close: {cleanup_ms} ms after the service went, window states {seen:?}");
    }
    assert!(opened.is_empty(), "cleanup opened a dialog: {opened:?}");
    assert!(gone, "the dialogs page is still open {cleanup_ms} ms after the service went");

    chrome_proc.close().await;
    tokio::task::block_in_place(|| drop(svc));
    drop(key);
    assert!(HostKey::is_gone(&host), "the test host registration was removed");
    drop(rt);
    drop(fixtures);
}
