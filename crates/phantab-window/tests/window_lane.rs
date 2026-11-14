//! Window lane (docs/ARCHITECTURE.md § Test lanes, 5): real headful Chrome windows, hidden at their first
//! SHOW, found, shown and hidden again; and the quiet Run-key edit on a scratch key.
//!
//! Runs only on Windows with `PHANTAB_TEST_CHROME` set to a Chrome executable; otherwise it says why and
//! passes. It touches only what it starts: its own Chrome (own temp profile; once killed outright and started
//! again, then closed with `Browser.close` and its own child process killed), and
//! `HKCU\Software\phantab-test-<pid>`, deleted afterwards. Its show log reads the owning process id of each
//! window the desktop shows, and records only its own Chrome's.
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: a failed step should fail the test"
)]

#[cfg(not(windows))]
#[test]
fn window_lane() {
    println!("skip: the window lane runs on Windows only (macOS does no OS window work, docs/MAC.md)");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn window_lane() {
    let Some(chrome) = std::env::var_os("PHANTAB_TEST_CHROME") else {
        println!("skip: set PHANTAB_TEST_CHROME to a Chrome executable to run the window lane");
        return;
    };
    lane::run(std::path::PathBuf::from(chrome)).await;
}

#[cfg(windows)]
mod lane {
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    use futures_util::{SinkExt, StreamExt};
    use phantab_window::{
        Browser, HideStrategy, NativeHandle, QUIET_FLAG, QuietRequest, WindowControl, WindowSpec, seams,
    };
    use serde_json::{Value, json};
    use tokio::net::TcpStream;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    /// Our Chrome: killed and its profile removed on drop, even when an assertion fails first.
    struct Launched {
        child: Child,
        dir: PathBuf,
    }

    impl Drop for Launched {
        fn drop(&mut self) {
            // Our own child only, never chrome.exe by name.
            let _ = self.child.kill();
            let _ = self.child.wait();
            for _ in 0..50 {
                if std::fs::remove_dir_all(&self.dir).is_ok() || !self.dir.exists() {
                    break;
                }
                // Chrome's helper processes let go of the profile shortly after the browser exits.
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    impl Launched {
        /// Waits for the browser to exit after `Browser.close`; whether it did.
        fn wait_exit(&mut self, limit: Duration) -> bool {
            let deadline = Instant::now() + limit;
            while Instant::now() < deadline {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        }
    }

    /// The scratch Run key, deleted on drop.
    struct ScratchKey(String);

    impl Drop for ScratchKey {
        fn drop(&mut self) {
            let _ = windows_registry::CURRENT_USER.remove_tree(&self.0);
        }
    }

    struct Cdp {
        ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
        next: u64,
    }

    impl Cdp {
        async fn call(&mut self, method: &str, params: Value) -> Value {
            self.call_in(None, method, params).await
        }

        /// A command on the browser (`session` `None`) or on an attached page's flat session.
        async fn call_in(&mut self, session: Option<&str>, method: &str, params: Value) -> Value {
            match self.try_call_in(session, method, params).await {
                Ok(result) => result,
                Err(error) => panic!("{method}: {error}"),
            }
        }

        /// As `call_in`, with Chrome's error reply as the `Err`.
        async fn try_call_in(
            &mut self,
            session: Option<&str>,
            method: &str,
            params: Value,
        ) -> Result<Value, Value> {
            self.next += 1;
            let id = self.next;
            let mut command = json!({"id": id, "method": method, "params": params});
            if let Some(session) = session {
                command["sessionId"] = json!(session);
            }
            self.ws.send(Message::Text(command.to_string().into())).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let Ok(next) = tokio::time::timeout(left, self.ws.next()).await else {
                    panic!("{method} timed out");
                };
                let Some(msg) = next else { panic!("CDP closed during {method}") };
                let Message::Text(text) = msg.unwrap() else { continue };
                let reply: Value = serde_json::from_str(&text).unwrap();
                if reply["id"].as_u64() == Some(id) {
                    return match reply.get("error") {
                        Some(error) => Err(error.clone()),
                        None => Ok(reply["result"].clone()),
                    };
                }
            }
        }

        /// What the engine does for a hidden agent page. Without it a hidden window's page title, the token's
        /// only carrier, can stall: in this lane a hidden decoy's title had not arrived after 10 s. A tiny,
        /// rare screencast keeps the page rendering (the engine's `keepRendering`); focus emulation keeps it
        /// from being treated as backgrounded (docs/MAC.md). With both, a hidden page reaches its title as
        /// fast as a visible one does.
        async fn attach(&mut self, target: &str) -> String {
            let attached =
                self.call("Target.attachToTarget", json!({"targetId": target, "flatten": true})).await;
            attached["sessionId"].as_str().unwrap().to_owned()
        }

        /// The id and URL of each open page target.
        async fn pages(&mut self) -> Vec<(String, String)> {
            let targets = self.call("Target.getTargets", json!({})).await;
            let infos = targets["targetInfos"].as_array().unwrap().iter();
            infos
                .filter(|t| t["type"].as_str() == Some("page"))
                .map(|t| {
                    (t["targetId"].as_str().unwrap().to_owned(), t["url"].as_str().unwrap_or("").to_owned())
                })
                .collect()
        }

        async fn keep_rendering(&mut self, target: &str) {
            let session = self.attach(target).await;
            self.call_in(Some(&session), "Emulation.setFocusEmulationEnabled", json!({"enabled": true}))
                .await;
            self.call_in(
                Some(&session),
                "Page.startScreencast",
                json!({"format": "jpeg", "quality": 1, "maxWidth": 32, "maxHeight": 32, "everyNthFrame": 60}),
            )
            .await;
        }
    }

    fn launch(chrome: &Path, spec: &WindowSpec) -> Launched {
        let dir = std::env::temp_dir().join(format!("phantab-window-lane-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let child = Command::new(chrome)
            .arg(format!("--user-data-dir={}", dir.display()))
            // Every new window's initial bounds. Chrome applies these before a window is first shown, the way
            // chrome.windows.create applies its bounds; Target.createTarget's own left/top/width/height are set
            // only after the first SHOW (a cascaded or default rect), which the hook rightly ignores.
            .arg(format!("--window-position={},{}", spec.left, spec.top))
            .arg(format!("--window-size={},{}", spec.width, spec.height))
            .args([
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-port=0",
                // So `quiet` sees a running browser with the flag, whatever else runs from this path.
                QUIET_FLAG,
                "about:blank",
            ])
            .spawn()
            .unwrap();
        Launched { child, dir }
    }

    async fn connect(dir: &Path) -> Cdp {
        let file = dir.join("DevToolsActivePort");
        let deadline = Instant::now() + Duration::from_secs(30);
        let text = loop {
            if let Ok(text) = std::fs::read_to_string(&file)
                && text.lines().count() >= 2
            {
                break text;
            }
            assert!(Instant::now() < deadline, "Chrome never wrote DevToolsActivePort");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let mut lines = text.lines();
        let (port, path) = (lines.next().unwrap().trim(), lines.next().unwrap().trim());
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}{path}")).await.unwrap();
        Cdp { ws, next: 0 }
    }

    fn token(label: &str) -> String {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        format!("PHANTAB-lane-{label}-{}-{nanos}", std::process::id())
    }

    /// A new window at `spec`'s rect whose page title is `title`. The rect at its first SHOW comes from the
    /// launch flags (see `launch`); the bounds here only keep it there afterwards.
    async fn create_window(cdp: &mut Cdp, spec: &WindowSpec, title: &str) -> String {
        let result = cdp
            .call(
                "Target.createTarget",
                json!({
                    "url": format!("data:text/html,<title>{title}</title>"),
                    "newWindow": true,
                    "left": spec.left, "top": spec.top, "width": spec.width, "height": spec.height,
                }),
            )
            .await;
        result["targetId"].as_str().unwrap().to_owned()
    }

    async fn wait_title(cdp: &mut Cdp, target: &str, title: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let info = cdp.call("Target.getTargetInfo", json!({"targetId": target})).await;
            if info["targetInfo"]["title"].as_str() == Some(title) {
                return;
            }
            assert!(Instant::now() < deadline, "the page title never became {title}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub(super) async fn run(chrome: PathBuf) {
        let w = phantab_window::platform();
        assert_eq!(w.strategy(), HideStrategy::OsHook);
        // Smaller than the engine's workspace rect so it fits a 1024x768 CI desktop: Chrome clamps a window
        // larger than the work area, and a clamped window never matches the armed rect.
        let spec = WindowSpec { left: 20, top: 20, width: 900, height: 650, token: token("main") };
        let browser = launch(&chrome, &spec);
        let mut cdp = connect(&browser.dir).await;

        // Nothing appears at the rect: settle answers at once with None and stops the hook.
        let t = Instant::now();
        let mut idle = w
            .arm_hide(&WindowSpec { left: 3, top: 3, width: 111, height: 77, token: token("idle") })
            .await
            .unwrap();
        assert_eq!(idle.settle().await, None);
        assert_eq!(idle.settle().await, None, "settling twice is safe");
        println!("timing: arm + uncaught settle {:?}", t.elapsed());
        drop(idle);

        // The real flow: arm, create, title, settle, then find/show/hide.
        let t = Instant::now();
        let mut guard = w.arm_hide(&spec).await.unwrap();
        let armed = t.elapsed();
        let t = Instant::now();
        let target = create_window(&mut cdp, &spec, &spec.token).await;
        let created = t.elapsed();
        while !guard.caught() {
            assert!(t.elapsed() < Duration::from_secs(10), "the hook never caught the new window");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let caught = t.elapsed();
        cdp.keep_rendering(&target).await;
        let rendering = t.elapsed();
        wait_title(&mut cdp, &target, &spec.token).await;
        let titled = t.elapsed();
        let handle = guard.settle().await.expect("the hook confirmed the window by its token");
        let settled = t.elapsed();
        println!(
            "timing: arm_hide {armed:?}; createTarget reply {created:?}; caught (hidden) {caught:?} after create; keep-rendering on {rendering:?}; page title {titled:?}; settled {settled:?}"
        );
        assert_eq!(guard.settle().await, Some(handle), "settling twice gives the same handle");
        assert!(!w.is_visible(handle).await.unwrap(), "hidden at its first SHOW");
        assert_eq!(w.find(&spec.token).await.unwrap(), handle);
        let snap = w.snapshot().await.unwrap();
        assert!(!snap.chrome_windows.contains(&handle), "a hidden window is not in the snapshot");

        let t = Instant::now();
        w.show(handle, false).await.unwrap();
        println!("timing: show {:?}", t.elapsed());
        assert!(w.is_visible(handle).await.unwrap());
        assert!(w.snapshot().await.unwrap().chrome_windows.contains(&handle));
        let t = Instant::now();
        w.hide(handle).await.unwrap();
        println!("timing: hide {:?}", t.elapsed());
        assert!(!w.is_visible(handle).await.unwrap());

        // Kept hidden, a show is undone at once: Chrome shows a window when a page in it opens a popup or tab.
        w.keep_hidden(handle, true).await.unwrap();
        w.show(handle, false).await.unwrap();
        let t = Instant::now();
        while w.is_visible(handle).await.unwrap() {
            assert!(t.elapsed() < Duration::from_secs(2), "a kept window was left shown");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        println!("timing: kept window hidden again {:?} after its show", t.elapsed());
        w.keep_hidden(handle, false).await.unwrap();
        w.show(handle, false).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(w.is_visible(handle).await.unwrap(), "a released window stays shown");
        w.hide(handle).await.unwrap();
        kept_cases(w.as_ref(), &mut cdp, browser.child.id(), handle, &target).await;
        assert!(w.keep_hidden(NativeHandle(0), true).await.is_err(), "a non-window is refused");
        assert!(w.show(NativeHandle(0), false).await.is_err(), "a non-window is refused");

        // A window at the rect that never shows the token is shown again, unactivated, at the timeout.
        let decoy = token("decoy");
        let armed_for = WindowSpec { token: token("other"), ..spec.clone() };
        let mut guard = w.arm_hide_within(&armed_for, Duration::from_millis(1500)).await.unwrap();
        let target = create_window(&mut cdp, &armed_for, &decoy).await;
        cdp.keep_rendering(&target).await;
        wait_title(&mut cdp, &target, &decoy).await;
        // The hook thread can trail the title on a slow runner; it has until the arm timeout.
        let t = Instant::now();
        while !guard.caught() && t.elapsed() < Duration::from_millis(1200) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        if !guard.caught() {
            let placed = cdp.call("Browser.getWindowForTarget", json!({"targetId": target})).await;
            panic!(
                "the decoy was not hidden at the rect; Chrome placed it at {placed}, armed for {armed_for:?}"
            );
        }
        assert_eq!(guard.settle().await, None, "never confirmed");
        let restored = w.find(&decoy).await.unwrap();
        assert!(w.is_visible(restored).await.unwrap(), "never left hidden on a guess");

        quiet(w.as_ref(), &chrome, &browser.dir).await;
        let (mut browser, cdp) = killed_and_again(w.as_ref(), &chrome, &spec, browser, cdp, handle).await;

        // The clean quit `phantab chrome restart-quiet` makes: only the browser on this user-data dir, by its
        // pid, and it exits by itself.
        let t = Instant::now();
        let target = lane_browser(&chrome, &browser.dir);
        let quit = w.quit_browser(&target).await.unwrap();
        assert_eq!(quit, Some(browser.child.id()), "the lane's own browser, by its user-data dir");
        let exited = browser.wait_exit(Duration::from_secs(10));
        println!("timing: quit {:?} (exited by itself: {exited})", t.elapsed());
        assert!(exited, "Chrome closed itself when asked");
        assert_eq!(w.quit_browser(&target).await.unwrap(), None, "none runs on that dir now");
        drop(cdp);
        drop(browser);
    }

    /// How long a kept window may stay shown before the keeper hides it again, as in the kept check in `run`.
    const REHIDE_BOUND: Duration = Duration::from_secs(2);

    /// Watches the kept `handle` for `span`: every show is undone within `REHIDE_BOUND`, and it ends hidden.
    /// Returns how many shows the polling saw, and the longest.
    async fn stays_hidden(
        w: &dyn WindowControl,
        handle: NativeHandle,
        span: Duration,
        case: &str,
    ) -> (usize, Duration) {
        let start = Instant::now();
        let (mut shows, mut longest, mut since) = (0, Duration::ZERO, None::<Instant>);
        while start.elapsed() < span || since.is_some() {
            match (w.is_visible(handle).await.unwrap(), since) {
                (true, None) => {
                    shows += 1;
                    since = Some(Instant::now());
                }
                (true, Some(at)) => {
                    let lasted = at.elapsed();
                    assert!(lasted < REHIDE_BOUND, "{case}: the kept window was left shown for {lasted:?}");
                }
                (false, Some(at)) => {
                    longest = longest.max(at.elapsed());
                    since = None;
                }
                (false, None) => {}
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        (shows, longest)
    }

    /// The first page target not in `before`, with its URL.
    async fn new_page(cdp: &mut Cdp, before: &[(String, String)], case: &str) -> (String, String) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let pages = cdp.pages().await;
            if let Some(page) = pages.iter().find(|p| !before.iter().any(|b| b.0 == p.0)) {
                return page.clone();
            }
            assert!(Instant::now() < deadline, "{case}: no new page opened; pages {pages:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Prints each window the browser's process tree showed since `from`, and checks every one is the browser
    /// process's own, the process the keeper's hook is scoped to. Returns where the next case starts.
    fn owned_by_browser(log: &seams::ShowLog, from: usize, browser: u32, case: &str) -> usize {
        let shown = log.shown();
        for s in &shown[from..] {
            println!(
                "lane window: {case}: pid {} (browser {browser}), class {}, handle {}",
                s.pid, s.class, s.handle.0
            );
        }
        let strays: Vec<_> = shown[from..].iter().filter(|s| s.pid != browser).collect();
        assert!(
            strays.is_empty(),
            "{case}: windows shown by a process other than browser {browser}: {strays:?}"
        );
        shown.len()
    }

    /// What review r1 said only a real Chrome can prove: a page in a kept window opening a popup, a tab and an
    /// alert leaves that window hidden, and every window Chrome shows for them is the browser process's.
    /// These hold on main's desktop-wide hook too; the per-process scope (`kept_processes`) is this design's.
    async fn kept_cases(w: &dyn WindowControl, cdp: &mut Cdp, child: u32, handle: NativeHandle, page: &str) {
        let browser = seams::window_pid(handle);
        assert_eq!(browser, child, "the kept window belongs to the Chrome this lane started");
        let log = seams::record_shows(browser).expect("the show log started");
        w.keep_hidden(handle, true).await.unwrap();
        assert_eq!(seams::kept_processes(), vec![browser], "the keeper hooks the browser process only");
        let session = cdp.attach(page).await;
        let mark = token("open");
        let mut seen = 0;

        // 1. A popup window. Nothing arms a hide for it in this bare lane (the engine's extension would), so it
        // shows; its opener, the kept window, must not.
        let before = cdp.pages().await;
        let t = Instant::now();
        let open =
            format!("window.open('about:blank#popup-{mark}', '_blank', 'popup,width=200,height=150'); 1");
        cdp.call_in(Some(&session), "Runtime.evaluate", json!({"expression": open, "userGesture": true}))
            .await;
        let (popup, url) = new_page(cdp, &before, "popup").await;
        let (shows, longest) = stays_hidden(w, handle, Duration::from_millis(1500), "popup").await;
        let log_now = log.shown();
        let popup_window = log_now[seen..].iter().find(|s| s.handle != handle).map(|s| s.handle);
        let popup_window =
            popup_window.unwrap_or_else(|| panic!("popup: its window was never shown: {log_now:?}"));
        let popup_pid = seams::window_pid(popup_window);
        assert_eq!(popup_pid, browser, "popup: its window is the browser process's, not {popup_pid}");
        println!(
            "timing: popup ({url}): kept window shown {shows}x (longest {longest:?}), hidden throughout {:?}; popup window {} pid {popup_pid} visible: {}",
            t.elapsed(),
            popup_window.0,
            w.is_visible(popup_window).await.unwrap()
        );
        seen = owned_by_browser(&log, seen, browser, "popup");
        cdp.call("Target.closeTarget", json!({"targetId": popup})).await;

        // 2. A new tab, in the kept window itself.
        let before = cdp.pages().await;
        let t = Instant::now();
        let open = format!("window.open('about:blank#tab-{mark}'); 1");
        cdp.call_in(Some(&session), "Runtime.evaluate", json!({"expression": open, "userGesture": true}))
            .await;
        let (tab, url) = new_page(cdp, &before, "tab").await;
        let (shows, longest) = stays_hidden(w, handle, Duration::from_millis(1500), "tab").await;
        let placed = cdp.call("Browser.getWindowForTarget", json!({"targetId": tab})).await;
        println!(
            "timing: tab ({url}, window {}): kept window shown {shows}x (longest {longest:?}), hidden throughout {:?}",
            placed["windowId"],
            t.elapsed()
        );
        seen = owned_by_browser(&log, seen, browser, "tab");
        cdp.call("Target.closeTarget", json!({"targetId": tab})).await;
        let (shows, _) = stays_hidden(w, handle, Duration::from_millis(500), "tab closed").await;
        println!("timing: tab closed: kept window shown {shows}x");

        // 3. An alert, dismissed through CDP.
        cdp.call_in(Some(&session), "Page.enable", json!({})).await;
        let t = Instant::now();
        let alert = "setTimeout(() => alert('phantab window lane'), 0); 1";
        cdp.call_in(Some(&session), "Runtime.evaluate", json!({"expression": alert})).await;
        let (shows, longest) = stays_hidden(w, handle, Duration::from_millis(1500), "alert").await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let dismiss = json!({"accept": true});
        let mut tries = 0;
        while let Err(error) =
            cdp.try_call_in(Some(&session), "Page.handleJavaScriptDialog", dismiss.clone()).await
        {
            assert!(
                Instant::now() < deadline,
                "alert: no dialog to dismiss after {:?}: {error}",
                t.elapsed()
            );
            tries += 1;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let dismissed = t.elapsed();
        let (after, _) = stays_hidden(w, handle, Duration::from_millis(500), "alert dismissed").await;
        println!(
            "timing: alert: kept window shown {shows}x (longest {longest:?}) while open, {after}x after; dismissed {dismissed:?} after it was raised ({tries} early tries)"
        );
        owned_by_browser(&log, seen, browser, "alert");

        // 4. Every window kind 1-3 showed, by owner; the per-case lines above checked each is the browser's.
        let kinds: Vec<_> = log.shown().iter().map(|s| (s.pid, s.class.clone())).collect();
        println!(
            "lane window: browser {browser}, process tree {:?}; shown in 1-3: {kinds:?}",
            seams::process_tree(browser)
        );
        drop(log);
        w.keep_hidden(handle, false).await.unwrap();
    }

    /// Case 5: the browser killed outright, as a crash or Task Manager does: no `Browser.close`, so its windows get no
    /// orderly close. New behaviour (main had one desktop-wide hook and nothing per process): the keeper drops
    /// the dead process's hook and windows within a bound, so a later process given the same id starts afresh.
    /// Then a second Chrome's window is kept as the first's was. Returns the second Chrome.
    async fn killed_and_again(
        w: &dyn WindowControl,
        chrome: &Path,
        spec: &WindowSpec,
        mut browser: Launched,
        cdp: Cdp,
        handle: NativeHandle,
    ) -> (Launched, Cdp) {
        let pid = browser.child.id();
        w.keep_hidden(handle, true).await.unwrap();
        assert_eq!(
            seams::kept_processes(),
            vec![pid],
            "kill: the kept window's browser is hooked before the kill"
        );
        let t = Instant::now();
        browser.child.kill().unwrap();
        let _ = browser.child.wait();
        while seams::kept_processes().contains(&pid) {
            let after = t.elapsed();
            let hooked = seams::kept_processes();
            assert!(
                after < Duration::from_secs(5),
                "kill: killed browser {pid} still hooked after {after:?}: {hooked:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        println!("timing: kill: browser {pid}'s hook dropped {:?} after the kill", t.elapsed());
        drop(cdp);
        drop(browser);

        let second = WindowSpec { token: token("second"), ..spec.clone() };
        let browser = launch(chrome, &second);
        let mut cdp = connect(&browser.dir).await;
        let again = browser.child.id();
        // Its startup window opens at the same rect (the launch flags); wait for it to show before arming, so
        // the hook catches the window created below, not that one.
        let deadline = Instant::now() + Duration::from_secs(10);
        while cdp.pages().await.is_empty() {
            assert!(Instant::now() < deadline, "second: Chrome {again} opened no startup page");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        loop {
            let shown = w.snapshot().await.unwrap().chrome_windows;
            if shown.iter().any(|&h| seams::window_pid(h) == again) {
                break;
            }
            assert!(Instant::now() < deadline, "second: Chrome {again}'s startup window never showed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let t = Instant::now();
        let mut guard = w.arm_hide(&second).await.unwrap();
        let target = create_window(&mut cdp, &second, &second.token).await;
        cdp.keep_rendering(&target).await;
        wait_title(&mut cdp, &target, &second.token).await;
        let kept = guard.settle().await.expect("second: the hook confirmed the window by its token");
        println!(
            "timing: second: browser {again} (first {pid}) window settled {:?} after arming",
            t.elapsed()
        );
        w.keep_hidden(kept, true).await.unwrap();
        assert_eq!(
            seams::kept_processes(),
            vec![again],
            "second: only browser {again} is hooked (the first was {pid})"
        );
        w.show(kept, false).await.unwrap();
        let t = Instant::now();
        while w.is_visible(kept).await.unwrap() {
            assert!(
                t.elapsed() < REHIDE_BOUND,
                "second: the kept window was left shown for {:?}",
                t.elapsed()
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        println!("timing: second: kept window hidden again {:?} after its show", t.elapsed());
        w.keep_hidden(kept, false).await.unwrap();
        (browser, cdp)
    }

    /// The lane's browser as quiet and quit name it: its Chrome, on its scratch user-data dir.
    fn lane_browser(chrome: &Path, dir: &Path) -> Browser {
        // Quiet matches the configured path as written, and Windows reports the running image with
        // backslashes. Git Bash hands `PHANTAB_TEST_CHROME=/c/...` over as `C:/...`.
        Browser {
            chrome_path: chrome.to_str().unwrap().replace('/', "\\"),
            user_data_dir: dir.display().to_string(),
            default_dir: false,
        }
    }

    async fn quiet(w: &dyn WindowControl, chrome: &Path, dir: &Path) {
        let target = lane_browser(chrome, dir);
        let path = &target.chrome_path.clone();
        // Run key and shortcuts on scratch places only: a key of this test's own and an empty folder.
        let shortcuts = std::env::temp_dir().join(format!("phantab-window-lane-lnk-{}", std::process::id()));
        std::fs::create_dir_all(&shortcuts).unwrap();
        let ask = |mode_on: bool, chrome_path: &str, run_key: &str| QuietRequest {
            run_key: Some(run_key.to_owned()),
            shortcut_dirs: Some(vec![phantab_window::ShortcutDir { path: shortcuts.clone(), recurse: true }]),
            ..QuietRequest::new(mode_on, Browser { chrome_path: chrome_path.to_owned(), ..target.clone() })
        };
        let subkey = format!(r"Software\phantab-test-{}", std::process::id());
        let key_name = format!(r"HKCU\{subkey}");
        let scratch = ScratchKey(subkey.clone());
        let key = windows_registry::CURRENT_USER.create(&subkey).unwrap();
        let entry = format!("\"{path}\" --profile-directory=Default --no-startup-window");
        let other = r#""C:\Other\app.exe" --profile-directory=Default"#;
        key.set_string("browser", &entry).unwrap();
        key.set_expand_string("expandable", format!("\"{path}\" --x")).unwrap();
        key.set_string("other", other).unwrap();
        key.set_u32("number", 7).unwrap();

        let t = Instant::now();
        let on = w.quiet(&ask(true, path, &key_name)).await.unwrap();
        println!("timing: quiet {:?}", t.elapsed());
        // Our own browser runs from this path, on this dir, with the flag.
        assert_eq!((on.run_value, on.running, on.shortcuts), (Some(true), Some(true), 0));
        let elsewhere = QuietRequest {
            browser: Browser { user_data_dir: format!("{}-not", dir.display()), ..target.clone() },
            ..ask(true, path, &key_name)
        };
        assert_eq!(w.quiet(&elsewhere).await.unwrap().running, None, "no browser runs on another dir");
        let flagged = format!("\"{path}\" {QUIET_FLAG} --profile-directory=Default --no-startup-window");
        assert_eq!(key.get_string("browser").unwrap(), flagged);
        assert_eq!(key.get_type("expandable").unwrap(), windows_registry::Type::ExpandString, "type kept");
        assert_eq!(key.get_string("expandable").unwrap(), format!("\"{path}\" {QUIET_FLAG} --x"));
        assert_eq!(key.get_string("other").unwrap(), other);
        assert_eq!(key.get_u32("number").unwrap(), 7);
        assert_eq!(w.quiet(&ask(true, path, &key_name)).await.unwrap().run_value, Some(true));
        assert_eq!(key.get_string("browser").unwrap(), flagged, "on is idempotent");

        let off = w.quiet(&ask(false, path, &key_name)).await.unwrap();
        assert_eq!(off.run_value, Some(false));
        assert_eq!(key.get_string("browser").unwrap(), entry);
        assert_eq!(key.get_string("other").unwrap(), other);
        w.quiet(&ask(false, path, &key_name)).await.unwrap();
        assert_eq!(key.get_string("browser").unwrap(), entry, "off is idempotent");

        // No entry for this browser, and no key at all: run_value is None.
        key.remove_value("browser").unwrap();
        key.remove_value("expandable").unwrap();
        assert_eq!(w.quiet(&ask(true, path, &key_name)).await.unwrap().run_value, None);
        drop(scratch);
        assert_eq!(w.quiet(&ask(true, path, &key_name)).await.unwrap().run_value, None);
        assert!(w.quiet(&ask(true, "", &key_name)).await.is_err());
        assert!(w.quiet(&ask(true, path, r"HKLM\Software\x")).await.is_err());
        std::fs::remove_dir_all(&shortcuts).unwrap();
    }
}
