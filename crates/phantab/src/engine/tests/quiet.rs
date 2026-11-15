//! Quiet debugging: what status says while the running Chrome lacks the flag, and `restart_quiet`, which
//! restarts only the configured Chrome, only on the owner's word, never while agent pages are open.

use phantab_window::{Browser, QUIET_FLAG, QuietState, Quit};

use super::*;
use crate::engine::quiet::{QUIET_PENDING, restart_args};

/// Each start of Chrome, and the usual profile's link that came back up after it.
type Restarts = (Arc<Mutex<Vec<Started>>>, Arc<Mutex<Vec<Ext>>>);

/// A fixture whose Chrome runs as `windows` says, that `restart_quiet` may start again: each start is
/// recorded, and the usual profile's link comes back up after it.
fn restartable(windows: Recording, quiet_on: bool) -> (Fixture, Restarts) {
    let started: Arc<Mutex<Vec<Started>>> = Arc::default();
    let up: Arc<Mutex<Vec<Ext>>> = Arc::default();
    let start: Starter = {
        let (started, up) = (Arc::clone(&started), Arc::clone(&up));
        Box::new(move |bridge| {
            crate::engine_api::StartProfile(Arc::new(move |chrome, args| {
                started.lock().unwrap().push((chrome.to_path_buf(), args.to_vec()));
                let (bridge, up) = (Arc::clone(&bridge), Arc::clone(&up));
                tokio::spawn(async move {
                    let ext = Ext::connect(&bridge).await;
                    up.lock().unwrap().push(ext);
                });
                Ok(())
            }))
        })
    };
    let f = fixture_profiles(windows, None, None, &[], Some(start));
    if quiet_on {
        std::fs::write(&f.engine.setup.quiet_marker, "").unwrap();
    }
    (f, (started, up))
}

fn running(running: Option<bool>) -> Recording {
    Recording::new().with_quiet(QuietState { run_value: Some(true), running, ..QuietState::default() })
}

/// The browser the fake quits: pid 77, running with these switches.
fn quit(args: &[&str]) -> Option<Quit> {
    Some(Quit { pid: 77, args: args.iter().map(|a| (*a).to_owned()).collect() })
}

fn quits(f: &Fixture) -> Vec<Browser> {
    f.windows
        .calls()
        .into_iter()
        .filter_map(|c| if let Call::QuitBrowser(b) = c { Some(b) } else { None })
        .collect()
}

#[tokio::test]
async fn restart_quiet_needs_quiet_debugging_on_and_no_agent_pages() {
    let (f, (started, _up)) = restartable(running(Some(false)).with_quit(quit(&[])), false);
    let e = &f.engine;
    assert!(err(e.restart_quiet().await).starts_with("Quiet debugging is off"));
    std::fs::write(&e.setup.quiet_marker, "").unwrap();
    let _r = rec(e, "a", FIXTURE, Fields { tab_id: Some(5), ..Fields::default() }).await;
    assert!(err(e.restart_quiet().await).starts_with("Agent pages are open"));
    assert!(quits(&f).is_empty(), "nothing was closed");
    assert!(started.lock().unwrap().is_empty(), "nothing was started");

    let none = fixture(running(Some(false)));
    std::fs::write(&none.engine.setup.quiet_marker, "").unwrap();
    assert!(err(none.engine.restart_quiet().await).starts_with("config.json names no chromeExecutable"));
}

#[tokio::test]
async fn a_chrome_with_the_flag_or_none_running_is_not_restarted() {
    for (state, answer) in [(Some(true), json!(true)), (None, Value::Null)] {
        let (f, (started, _up)) = restartable(running(state).with_quit(quit(&[])), true);
        let said = f.engine.restart_quiet().await.unwrap();
        assert_eq!(said["restarted"], false, "{said}");
        assert_eq!(said["running"], answer, "{said}");
        assert!(quits(&f).is_empty(), "{state:?}: nothing was closed");
        assert!(started.lock().unwrap().is_empty(), "{state:?}: nothing was started");
    }
}

/// The Chrome running without the flag closes (only the configured one, by its path and user-data dir)
/// and starts again with the switches it ran with, the flag and the session it saved.
#[tokio::test]
async fn a_chrome_without_the_flag_closes_and_starts_again_with_it() {
    let ran = ["--proxy-server=127.0.0.1:8080", "--no-startup-window", "https://example.com/"];
    let (f, (started, up)) = restartable(running(Some(false)).with_quit(quit(&ran)), true);
    let e = &f.engine;
    // The link of the Chrome about to close is still up: only the restarted one's is a reconnect.
    let _old = Ext::connect(e.bridge()).await;
    let said = e.restart_quiet().await.unwrap();
    assert_eq!(said["restarted"], true, "{said}");
    assert_eq!(said["quitPid"], 77, "{said}");
    assert_eq!(said["reconnected"], true, "{said}");
    let udd = e.setup.config.user_data_dir.clone().unwrap();
    assert_eq!(
        quits(&f),
        [Browser {
            chrome_path: udd.join("chrome.exe").display().to_string(),
            user_data_dir: udd.display().to_string(),
            default_dir: false,
        }]
    );
    let started = started.lock().unwrap().clone();
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].0, udd.join("chrome.exe"));
    let args: Vec<String> = started[0].1.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    assert_eq!(
        args,
        [
            format!("--user-data-dir={}", udd.display()),
            "--proxy-server=127.0.0.1:8080".to_owned(),
            QUIET_FLAG.to_owned(),
            "--restore-last-session".to_owned()
        ]
    );
    assert_eq!(up.lock().unwrap().len(), 1);
}

/// A link that was up before the restart is not the restarted Chrome's, however long it stays.
#[tokio::test]
async fn only_a_new_link_counts_as_reconnected() {
    let f = fixture(Recording::new());
    let bridge = f.engine.bridge();
    assert!(!bridge.wait_new_link_in(USUAL, None, Duration::from_millis(20)).await, "no link at all");
    let _old = Ext::connect(bridge).await;
    let before = bridge.link_id_in(USUAL);
    assert!(before.is_some());
    assert!(!bridge.wait_new_link_in(USUAL, before, Duration::from_millis(50)).await, "the old link");
    let _new = Ext::connect(bridge).await;
    assert!(bridge.wait_new_link_in(USUAL, before, Duration::from_millis(50)).await, "its replacement");
}

#[tokio::test]
async fn a_chrome_that_does_not_close_is_not_started_again() {
    let (f, (started, _up)) = restartable(running(Some(false)), true);
    f.windows.fail_quits(true);
    let error = err(f.engine.restart_quiet().await);
    assert!(error.starts_with("Chrome did not close, so nothing was restarted"), "{error}");
    assert_eq!(quits(&f).len(), 1);
    assert!(started.lock().unwrap().is_empty());
}

#[test]
fn chromes_default_dir_is_not_named_on_the_restart() {
    assert_eq!(restart_args(None, &[]), [QUIET_FLAG, "--restore-last-session"]);
}

/// The owner's switches come back; Chrome's own flags block, a sign-in start's switches, what is not a
/// switch, and a second copy of the flag or the restore do not.
#[test]
fn the_restart_keeps_the_owners_switches_only() {
    let ran: Vec<String> = [
        "--user-data-dir=D:\\Chrome Data",
        "--proxy-server=socks5://127.0.0.1:1080",
        "--flag-switches-begin",
        "--enable-features=X",
        "--flag-switches-end",
        "--no-startup-window",
        "--win-session-start",
        QUIET_FLAG,
        "--restore-last-session",
        "https://example.com/",
        "--",
        "--not-a-switch",
    ]
    .iter()
    .map(|a| (*a).to_owned())
    .collect();
    let dir = std::path::Path::new(r"C:\configured");
    assert_eq!(
        restart_args(Some(dir), &ran),
        [
            "--user-data-dir=D:\\Chrome Data",
            "--proxy-server=socks5://127.0.0.1:1080",
            QUIET_FLAG,
            "--restore-last-session"
        ],
        "the dir it ran on, not named twice"
    );
}

/// While the Chrome running lacks the flag, status says so plainly and names the restart.
#[tokio::test]
async fn status_says_the_bar_still_shows_until_chrome_restarts() {
    let f = fixture(Recording::new());
    let e = &f.engine;
    e.st().quiet = Some(json!({ "runValue": true, "running": true, "shortcuts": 2, "unwritable": [] }));
    assert!(e.status_map()["quietDebugging"].get("note").is_none());
    e.st().quiet = Some(json!({
        "runValue": true, "running": true, "shortcuts": 2, "unwritable": [],
        "sharedShortcuts": ["C:/Users/Public/Desktop/Chrome.lnk"], "syncedShortcuts": ["C:/o/Desktop/c.lnk"]
    }));
    let q = e.status_map()["quietDebugging"].clone();
    assert!(q.get("note").is_none(), "shared and synced ones are listed, not nagged about: {q}");
    assert_eq!(q["sharedShortcuts"][0], "C:/Users/Public/Desktop/Chrome.lnk");
    e.st().quiet =
        Some(json!({ "runValue": true, "running": false, "shortcuts": 2, "unwritable": ["C:/x.lnk"] }));
    let note = e.status_map()["quietDebugging"]["note"].as_str().unwrap().to_owned();
    assert!(note.starts_with(QUIET_PENDING), "{note}");
    assert!(note.contains("phantab chrome restart-quiet"), "{note}");
    assert!(note.contains("unwritable"), "{note}");
}
