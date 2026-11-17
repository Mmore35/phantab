//! The bridge against a fake extension on an in-memory pipe. Offline: no
//! service, no Chrome.
// Test helpers fail by panicking, like the tests themselves (clippy.toml allows it only inside #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use phantab::bridge::{
    self, Bridge, BridgeError, BridgeEvent, EXTENSION_ID, ForeignPage, FrameDecoder, ProfileCheck,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::broadcast;

/// The extension's end of one link.
struct Ext {
    io: DuplexStream,
    decoder: FrameDecoder,
}

impl Ext {
    async fn send(&mut self, value: &Value) {
        self.io.write_all(&bridge::frame(value).unwrap()).await.unwrap();
    }

    /// The next frame, or `None` once the bridge ended the link.
    async fn next(&mut self) -> Option<Value> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if let Some(f) = self.decoder.next_frame().unwrap() {
                return Some(serde_json::from_slice(&f).unwrap());
            }
            match tokio::time::timeout(Duration::from_secs(10), self.io.read(&mut buf))
                .await
                .expect("bridge silent")
            {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.decoder.push(&buf[..n]),
            }
        }
    }

    /// Reads until the bridge closes this link.
    async fn closed(&mut self) {
        while self.next().await.is_some() {}
    }
}

fn link(bridge: &Arc<Bridge>) -> Ext {
    let (ours, theirs) = tokio::io::duplex(4 * 1024 * 1024);
    bridge.accept(ours);
    Ext { io: theirs, decoder: FrameDecoder::default() }
}

async fn extension(bridge: &Arc<Bridge>, instance: &str) -> Ext {
    let mut ext = link(bridge);
    ext.send(&json!({ "hello": { "version": "1.0.0", "protocol": 1, "instance": instance } })).await;
    assert_eq!(ext.next().await, Some(json!({ "welcome": true, "events": phantab_cdp::EVENTS })));
    ext
}

/// Answers ping, and every other op with `answer`, until the link ends.
fn serve(
    mut ext: Ext,
    answer: impl Fn(&Value) -> Option<Value> + Send + 'static,
) -> tokio::task::JoinHandle<Ext> {
    tokio::spawn(async move {
        while let Some(m) = ext.next().await {
            let reply =
                if m["op"] == "ping" { Some(json!({ "id": m["id"], "result": {} })) } else { answer(&m) };
            if let Some(r) = reply {
                ext.send(&r).await;
            }
        }
        ext
    })
}

async fn event(
    rx: &mut broadcast::Receiver<BridgeEvent>,
    mut want: impl FnMut(&BridgeEvent) -> bool,
) -> BridgeEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let e = rx.recv().await.unwrap();
            if want(&e) {
                return e;
            }
        }
    })
    .await
    .expect("event")
}

#[test]
fn frames_survive_arbitrary_chunking() {
    let mut data = bridge::frame(&json!({ "a": 1 })).unwrap().to_vec();
    data.extend_from_slice(&bridge::frame(&json!({ "b": "é".repeat(3) })).unwrap());
    let mut decoder = FrameDecoder::default();
    let mut got = Vec::new();
    for byte in data {
        decoder.push(&[byte]);
        while let Some(f) = decoder.next_frame().unwrap() {
            got.push(serde_json::from_slice::<Value>(&f).unwrap());
        }
    }
    assert_eq!(got, [json!({ "a": 1 }), json!({ "b": "ééé" })]);
}

#[tokio::test]
async fn requests_events_and_tab_end() {
    let bridge = Arc::new(Bridge::new());
    let mut events = bridge.subscribe();
    let mut ext = extension(&bridge, "one").await;
    let send = tokio::spawn({
        let bridge = Arc::clone(&bridge);
        async move {
            bridge.op("send", json!({ "tabId": 7, "sessionId": "s", "method": "Runtime.callFunctionOn", "params": { "functionDeclaration": "() => 1" } })).await
        }
    });
    let m = ext.next().await.unwrap();
    assert_eq!(m["op"], "send");
    ext.send(&json!({ "id": m["id"], "result": { "echo": m["args"] } })).await;
    assert_eq!(
        send.await.unwrap().unwrap(),
        json!({ "echo": { "tabId": 7, "sessionId": "s", "method": "Runtime.callFunctionOn", "params": { "functionDeclaration": "() => 1" } } })
    );
    let tabs = tokio::spawn({
        let bridge = Arc::clone(&bridge);
        async move { bridge.op("tabs", json!({})).await }
    });
    let m = ext.next().await.unwrap();
    ext.send(&json!({ "id": m["id"], "error": "nope" })).await;
    assert!(matches!(tabs.await.unwrap(), Err(BridgeError::Remote(e)) if e == "nope"));

    // perf-data-3: an event phantab does not read (from an extension that ignores the welcome's
    // `events`) is dropped here; the first one through is the read one sent after it.
    ext.send(&json!({ "event": "cdp", "tabId": 7, "method": "Runtime.consoleAPICalled", "params": { "type": "log" } })).await;
    ext.send(&json!({ "event": "cdp", "tabId": 7, "sessionId": "s", "method": "Page.frameNavigated", "params": { "timestamp": 1 } })).await;
    ext.send(&json!({ "event": "detach", "tabId": 7, "reason": "canceled_by_user" })).await;
    let BridgeEvent::Cdp(cdp) = event(&mut events, |e| matches!(e, BridgeEvent::Cdp(_))).await else {
        unreachable!()
    };
    assert_eq!(
        (cdp.tab_id, cdp.session_id.as_deref(), cdp.method.as_str()),
        (7, Some("s"), "Page.frameNavigated")
    );
    assert_eq!(cdp.params.as_ref().map(|p| p.get()), Some(r#"{"timestamp":1}"#));
    let ended = event(&mut events, |e| matches!(e, BridgeEvent::TabEnded { .. })).await;
    assert!(
        matches!(ended, BridgeEvent::TabEnded { tab_id: 7, reason: Some(r), tab_open: None, foreign: None, .. } if r == "canceled_by_user")
    );

    // A 1.1 extension says whether the tab stayed open and which other extension's page appeared.
    let foreign = json!({ "id": "abc", "url": "chrome-extension://abc/overlay/menu.html" });
    ext.send(&json!({ "event": "detach", "tabId": 7, "reason": "target_closed", "tabOpen": true, "foreign": foreign })).await;
    let kept = event(&mut events, |e| matches!(e, BridgeEvent::TabEnded { .. })).await;
    let want = ForeignPage { id: "abc".into(), url: "chrome-extension://abc/overlay/menu.html".into() };
    assert!(
        matches!(kept, BridgeEvent::TabEnded { tab_id: 7, reason: Some(r), tab_open: Some(true), foreign: Some(f), .. } if r == "target_closed" && f == want)
    );
    bridge.close();
}

fn write(file: &Path, data: &Value) {
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, data.to_string()).unwrap();
}

#[test]
fn extension_names_come_from_the_profile_with_localized_names_and_unpacked_paths() {
    let dir = tempfile::tempdir().unwrap();
    let unpacked = dir.path().join("unpacked");
    let profile = dir.path().join("Profile 4");
    write(
        &profile.join("Secure Preferences"),
        &json!({ "extensions": { "settings": { "store": { "path": "store/1.0_0" }, "dev": { "path": unpacked } } } }),
    );
    let store = profile.join("Extensions").join("store").join("1.0_0");
    write(&store.join("manifest.json"), &json!({ "name": "__MSG_extName__", "default_locale": "en_GB" }));
    write(
        &store.join("_locales").join("en_GB").join("messages.json"),
        &json!({ "extname": { "message": "Store Manager" } }),
    );
    write(&unpacked.join("manifest.json"), &json!({ "name": "Dev Manager" }));
    assert_eq!(bridge::extension_name(dir.path(), "Profile 4", "store"), "Store Manager");
    assert_eq!(bridge::extension_name(dir.path(), "Profile 4", "dev"), "Dev Manager");
    assert_eq!(bridge::extension_name(dir.path(), "Profile 4", "unknown"), "unknown");
}

#[tokio::test]
async fn a_disconnect_rejects_pending_calls_and_reports_its_reason_then_the_extension_reconnects() {
    let bridge = Arc::new(Bridge::new());
    let mut events = bridge.subscribe();
    let mut ext = extension(&bridge, "one").await;
    let pending = tokio::spawn({
        let bridge = Arc::clone(&bridge);
        async move { bridge.op("tabs", json!({})).await }
    });
    assert_eq!(ext.next().await.unwrap()["op"], "tabs");
    drop(ext);
    let err = pending.await.unwrap().unwrap_err();
    assert!(err.to_string().contains("disconnected"), "{err}");
    let BridgeEvent::Disconnect { reason, .. } =
        event(&mut events, |e| matches!(e, BridgeEvent::Disconnect { .. })).await
    else {
        unreachable!()
    };
    assert!(reason.contains("closed the connection"), "{reason}");
    assert!(!bridge.connected());
    let err = bridge.op("tabs", json!({})).await.unwrap_err();
    assert!(err.to_string().contains("not connected"), "{err}");
    let waiting = tokio::spawn({
        let bridge = Arc::clone(&bridge);
        async move { bridge.wait_connected(Duration::from_secs(5)).await }
    });
    let _two = extension(&bridge, "two").await;
    assert!(waiting.await.unwrap());
    assert!(bridge.wait_connected(Duration::ZERO).await);
    bridge.close();
}

#[tokio::test]
async fn protocol_mismatch_and_a_second_live_profile_are_refused_and_a_restarted_worker_replaces_its_link() {
    let bridge = Arc::new(Bridge::new());
    let mut events = bridge.subscribe();
    let mut old = link(&bridge);
    old.send(&json!({ "hello": { "version": "0", "protocol": 2, "instance": "x" } })).await;
    let refused = old.next().await.unwrap();
    assert!(
        refused["refused"].as_str().unwrap().to_lowercase().contains("reload it at chrome://extensions"),
        "{refused}"
    );
    assert_eq!(bridge.last_error().as_deref(), refused["refused"].as_str());

    let first = serve(extension(&bridge, "one").await, |_| None);
    let mut second = link(&bridge);
    second.send(&json!({ "hello": { "version": "1.0.0", "protocol": 1, "instance": "other" } })).await;
    let refused = second.next().await.unwrap();
    assert!(refused["refused"].as_str().unwrap().contains("more than one Chrome profile"), "{refused}");
    assert!(bridge.connected());

    // Same instance: a reconnect, not a second profile. The old link is closed.
    let again = serve(extension(&bridge, "one").await, |_| None);
    first.await.unwrap();
    // A different instance whose predecessor no longer answers replaces it.
    let silent = extension(&bridge, "one").await;
    again.await.unwrap();
    let silent_closed = tokio::spawn(async move {
        let mut silent = silent;
        silent.closed().await;
    });
    let replacement = extension(&bridge, "fresh").await;
    silent_closed.await.unwrap();

    let mut refusals = 0;
    while let Ok(e) = events.try_recv() {
        if matches!(e, BridgeEvent::Refused { .. }) {
            refusals += 1;
        }
    }
    assert_eq!(refusals, 2);
    assert!(bridge.connected());
    drop(replacement);
    bridge.close();
}

#[tokio::test]
async fn oversized_requests_are_refused_before_reaching_chrome() {
    let bridge = Arc::new(Bridge::new());
    let _ext = extension(&bridge, "one").await;
    let err = bridge.op("send", json!({ "params": { "data": "x".repeat(1024 * 1024) } })).await.unwrap_err();
    assert!(err.to_string().contains("1 MB"), "{err}");
    bridge.close();
}

/// THREAT-MODEL SR-20: the service refuses an off-list CDP method itself, so even a bridge extension
/// that relayed it would never be asked.
#[tokio::test]
async fn send_relays_only_listed_cdp_methods() {
    let bridge = Arc::new(Bridge::new());
    let mut ext = extension(&bridge, "one").await;
    for method in
        [json!("Network.getAllCookies"), json!("Storage.getCookies"), json!("Browser.close"), json!(null)]
    {
        let err = bridge.op("send", json!({ "tabId": 7, "method": method, "params": {} })).await.unwrap_err();
        assert!(matches!(err, BridgeError::MethodNotAllowed(_)), "{method}: {err}");
    }
    let err = bridge.op("send", json!({ "tabId": 7 })).await.unwrap_err();
    assert!(matches!(err, BridgeError::MethodNotAllowed(_)), "{err}");
    // A listed method is still refused with universal access, which phantab's own world never asks for.
    for grant in [json!(true), json!(1), json!("yes")] {
        let params = json!({ "frameId": "F", "worldName": "phantab", "grantUniveralAccess": grant });
        let args = json!({ "tabId": 7, "method": "Page.createIsolatedWorld", "params": params });
        let err = bridge.op("send", args).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "phantab does not relay the CDP method Page.createIsolatedWorld with grantUniveralAccess.",
            "{grant}"
        );
    }
    let ok = tokio::spawn({
        let bridge = Arc::clone(&bridge);
        async move { bridge.op("send", json!({ "tabId": 7, "method": "Page.enable" })).await }
    });
    // The first frame the extension sees is the listed one: the refused ones never left the service.
    let m = ext.next().await.unwrap();
    assert_eq!(m["args"]["method"], "Page.enable");
    ext.send(&json!({ "id": m["id"], "result": {} })).await;
    assert_eq!(ok.await.unwrap().unwrap(), json!({}));
    // Without universal access, the world is relayed: the flag false, null or left out.
    for params in [
        json!({ "frameId": "F", "worldName": "phantab" }),
        json!({ "frameId": "F", "worldName": "phantab", "grantUniveralAccess": false }),
        json!({ "frameId": "F", "worldName": "phantab", "grantUniveralAccess": null }),
    ] {
        let ok = tokio::spawn({
            let (bridge, params) = (Arc::clone(&bridge), params.clone());
            async move {
                let args = json!({ "tabId": 7, "method": "Page.createIsolatedWorld", "params": params });
                bridge.op("send", args).await
            }
        });
        let m = ext.next().await.unwrap();
        assert_eq!(
            (&m["args"]["method"], &m["args"]["params"]),
            (&json!("Page.createIsolatedWorld"), &params)
        );
        ext.send(&json!({ "id": m["id"], "result": { "executionContextId": 3 } })).await;
        assert_eq!(ok.await.unwrap().unwrap(), json!({ "executionContextId": 3 }), "{params}");
    }
    bridge.close();
}

#[tokio::test]
async fn a_silent_extension_times_out_the_op_and_frees_its_slot() {
    let bridge = Arc::new(Bridge::new());
    let _ext = extension(&bridge, "one").await;
    let err = bridge.op_with_timeout("tabs", json!({}), Duration::from_millis(100)).await.unwrap_err();
    assert_eq!(err.to_string(), "The phantab bridge did not answer tabs in 0.1 s.");
    bridge.close();
}

#[test]
fn profile_check_reads_the_configured_profile_only() {
    let dir = tempfile::tempdir().unwrap();
    let ext = dir.path().join("runtime").join("extension");
    std::fs::create_dir_all(&ext).unwrap();
    let prefs = |name: &str, file: &str, ids: &[&str]| {
        let settings: serde_json::Map<String, Value> =
            ids.iter().map(|i| ((*i).to_owned(), json!({ "path": ext }))).collect();
        write(&dir.path().join(name).join(file), &json!({ "extensions": { "settings": settings } }));
    };
    prefs("Profile 4", "Preferences", &[]);
    prefs("Default", "Preferences", &[]);
    let check = || bridge::profile_check_at(dir.path(), "Profile 4", &EXTENSION_ID, &ext, false).unwrap();
    assert!(matches!(check(), ProfileCheck::Failed { final_: false, .. }));
    prefs("Profile 4", "Secure Preferences", &[&EXTENSION_ID]);
    assert_eq!(check(), ProfileCheck::Ok);
    prefs("Default", "Preferences", &[&EXTENSION_ID]);
    let ProfileCheck::Failed { final_, error } = check() else { panic!("listed twice passed") };
    assert!(final_);
    assert!(error.contains(r#"also installed in Chrome profile folder "Default"."#), "{error}");
    // Review r4 R4-6: a planted profile folder name is shown escaped too.
    prefs("Default", "Preferences", &[]);
    prefs("Profile\u{202e}lmth.x", "Preferences", &[&EXTENSION_ID]);
    let ProfileCheck::Failed { error, .. } = check() else { panic!("listed twice passed") };
    assert!(error.contains(r#"folder "Profile\u{202e}lmth.x"."#) && !error.contains('\u{202e}'), "{error}");
}

/// SR-19, L1: the public manifest key gives anyone the bridge's ID, so the profile entry must also be
/// an unpacked install from the installed extension folder. Another folder is final; no folder yet
/// is not.
#[test]
fn a_same_id_extension_from_another_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ext = dir.path().join("runtime").join("extension");
    let impostor = dir.path().join("impostor");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::create_dir_all(&impostor).unwrap();
    let prefs = |file: &str, entry: &Value| {
        let settings = json!({ (EXTENSION_ID.as_str()): entry });
        write(&dir.path().join("Default").join(file), &json!({ "extensions": { "settings": settings } }));
    };
    let check = || bridge::profile_check_at(dir.path(), "Default", &EXTENSION_ID, &ext, false).unwrap();

    prefs("Secure Preferences", &json!({ "path": impostor, "location": 4 }));
    let ProfileCheck::Failed { final_, error } = check() else { panic!("an impostor folder passed") };
    assert!(final_, "{error}");
    assert!(error.contains("not loaded from"), "{error}");

    // A store-style relative path, and the same folder named through `..`, which canonicalises.
    prefs("Secure Preferences", &json!({ "path": "extension" }));
    assert!(matches!(check(), ProfileCheck::Failed { final_: true, .. }));
    prefs("Secure Preferences", &json!({ "path": ext.join("..").join("extension") }));
    assert_eq!(check(), ProfileCheck::Ok);

    // One good entry does not excuse a bad one in the other Preferences file.
    prefs("Preferences", &json!({ "path": impostor }));
    assert!(matches!(check(), ProfileCheck::Failed { final_: true, .. }));
    prefs("Preferences", &json!({}));
    assert_eq!(check(), ProfileCheck::Ok);

    // Listed without a folder: Chrome has not written it yet, so wait.
    prefs("Secure Preferences", &json!({ "location": 4 }));
    assert!(matches!(check(), ProfileCheck::Failed { final_: false, .. }));

    // The installed folder is gone: nothing can match it.
    prefs("Secure Preferences", &json!({ "path": ext }));
    std::fs::remove_dir(&ext).unwrap();
    assert!(matches!(check(), ProfileCheck::Failed { final_: true, .. }));
}

/// SR-19: a re-check reuses the parse of an unchanged Preferences file, and only that. A rewrite
/// that keeps the file's size and puts its modification time back is still read as rewritten.
#[test]
fn a_rewritten_profile_is_checked_again_even_with_its_size_and_time_put_back() {
    let dir = tempfile::tempdir().unwrap();
    let ext = dir.path().join("runtime").join("extension");
    let impostor = dir.path().join("runtime").join("impostorr");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::create_dir_all(&impostor).unwrap();
    let file = dir.path().join("Default").join("Secure Preferences");
    let prefs = |folder: &Path| {
        let settings = json!({ (EXTENSION_ID.as_str()): { "path": folder } });
        write(&file, &json!({ "extensions": { "settings": settings } }));
    };
    let check = || bridge::profile_check_at(dir.path(), "Default", &EXTENSION_ID, &ext, false).unwrap();

    prefs(&ext);
    assert_eq!(check(), ProfileCheck::Ok);
    assert_eq!(check(), ProfileCheck::Ok);
    let before = std::fs::metadata(&file).unwrap();
    prefs(&impostor);
    let f = std::fs::File::options().write(true).open(&file).unwrap();
    f.set_modified(before.modified().unwrap()).unwrap();
    drop(f);
    let after = std::fs::metadata(&file).unwrap();
    assert_eq!((after.len(), after.modified().unwrap()), (before.len(), before.modified().unwrap()));
    assert!(matches!(check(), ProfileCheck::Failed { final_: true, .. }));
    prefs(&ext);
    assert_eq!(check(), ProfileCheck::Ok);
}

/// SR-74, L1: the installed folder itself is refused, finally, once a file install recorded beside it
/// changed or the record cannot be read; with no record it passes as before for an older install, and
/// is refused for one whose config.json says a record was written (review F1: deleting it is no bypass).
#[test]
fn a_changed_file_in_the_installed_extension_is_refused() {
    use phantab::extension_files::{hashes, record_path, render};
    let dir = tempfile::tempdir().unwrap();
    let ext = dir.path().join("runtime").join("extension");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(ext.join("manifest.json"), b"{}").unwrap();
    std::fs::write(ext.join("background.js"), b"the bridge").unwrap();
    let settings = json!({ (EXTENSION_ID.as_str()): { "path": ext, "location": 4 } });
    write(
        &dir.path().join("Default").join("Secure Preferences"),
        &json!({ "extensions": { "settings": settings } }),
    );
    let check_with =
        |required| bridge::profile_check_at(dir.path(), "Default", &EXTENSION_ID, &ext, required).unwrap();
    let check = || check_with(true);
    assert_eq!(check_with(false), ProfileCheck::Ok, "no record, from an install before SR-74");
    let ProfileCheck::Failed { final_, error } = check() else { panic!("a deleted record passed") };
    assert!(final_ && error.contains("is missing") && error.contains("extension-files.json"), "{error}");
    std::fs::write(record_path(&ext), render(&hashes(&ext).unwrap())).unwrap();
    assert_eq!(check(), ProfileCheck::Ok);

    // Review r2 R2-1: Chrome opens any file in the folder as an extension page, so one the record does not
    // name is refused too, whatever its name.
    std::fs::write(ext.join(".page.html"), b"<script src=.page.js></script>").unwrap();
    let ProfileCheck::Failed { final_, error } = check() else { panic!("a planted page passed") };
    assert!(
        final_ && error.contains(r#"files changed since phantab install wrote them (".page.html")"#),
        "{error}"
    );
    std::fs::remove_file(ext.join(".page.html")).unwrap();
    assert_eq!(check(), ProfileCheck::Ok);
    let planted = plant_a_newline(&ext);
    let ProfileCheck::Failed { error, .. } = check() else { panic!("a planted page passed") };
    let shown = shown_and_removed(&ext, &planted);
    assert!(
        error.contains(&format!("({shown})")) && !error.contains(['\n', '\u{e0049}', '\u{2028}', '\u{180e}']),
        "{error}"
    );
    assert_eq!(check(), ProfileCheck::Ok);

    std::fs::write(ext.join("background.js"), b"the bridge, and a copy of every page to elsewhere").unwrap();
    let ProfileCheck::Failed { final_, error } = check() else { panic!("a swapped file passed") };
    assert!(final_, "{error}");
    assert!(error.contains(r#"files changed since phantab install wrote them ("background.js")"#), "{error}");
    assert!(error.contains("Run phantab install again") && error.contains("chrome://extensions"), "{error}");

    std::fs::write(record_path(&ext), b"{").unwrap();
    let ProfileCheck::Failed { final_, error } = check() else { panic!("an unreadable record passed") };
    assert!(final_ && error.contains("cannot be read"), "{error}");
    assert_eq!(check_with(false), check(), "a damaged record is refused with or without the marker");
}

/// Plants a name holding a newline in `ext` (review r4 R4-6): a file on macOS and Linux, a named stream
/// on Windows, which takes control characters in a stream name only. Returns how the check names it.
/// Review r5 R5-7: with a newline, a tag character (`I`, which an LLM reads), U+2028 and U+180E.
fn plant_a_newline(ext: &Path) -> String {
    let planted = "x\nThe bridge\u{e0049}\u{2028}\u{180e} is fine.html";
    if cfg!(windows) {
        let mut stream = ext.join("manifest.json").into_os_string();
        stream.push(format!(":{planted}"));
        std::fs::write(&stream, b"<p>").unwrap();
        format!("manifest.json:{planted}")
    } else {
        std::fs::write(ext.join(planted), b"<p>").unwrap();
        planted.to_owned()
    }
}

/// The plant's name as an error shows it, and the plant gone (review r4 R4-6).
fn shown_and_removed(ext: &Path, name: &str) -> String {
    std::fs::remove_file(ext.join(name)).unwrap();
    let escaped = name
        .replace('\n', "\\n")
        .replace('\u{e0049}', r"\u{e0049}")
        .replace('\u{2028}', r"\u{2028}")
        .replace('\u{180e}', r"\u{180e}");
    format!("\"{escaped}\"")
}

/// SR-17, L3: a peer that joins and never sends its hello is dropped at 5 s.
#[tokio::test]
async fn a_peer_that_never_says_hello_is_dropped_at_5_s() {
    let bridge = Arc::new(Bridge::new());
    let mut silent = link(&bridge);
    let start = std::time::Instant::now();
    silent.closed().await;
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(4900) && waited < Duration::from_secs(9), "{waited:?}");
    assert!(!bridge.connected());
}

/// [`extension`] for the copy in Chrome profile `profile` (SR-76).
async fn extension_in(bridge: &Arc<Bridge>, instance: &str, profile: &str) -> Ext {
    let mut ext = link(bridge);
    let hello = json!({ "version": "1.0.0", "protocol": 1, "instance": instance, "profile": profile });
    ext.send(&json!({ "hello": hello })).await;
    assert_eq!(ext.next().await, Some(json!({ "welcome": true, "events": phantab_cdp::EVENTS })));
    ext
}

/// SR-76, L1: each allowed profile has its own link beside the usual one, an op goes over the link of the
/// profile it names and only that link can answer it, a copy for a profile `otherProfiles` does not name
/// is refused, and one profile's link ending leaves the others.
#[tokio::test]
async fn each_allowed_profile_has_its_own_link_and_only_that_link_answers_its_ops() {
    let bridge = Arc::new(Bridge::with_profiles(vec!["Profile 2".to_owned()]));
    let mut events = bridge.subscribe();
    let mut usual = extension(&bridge, "one").await;
    let mut work = extension_in(&bridge, "two", "Profile 2").await;
    assert!(bridge.connected_in(bridge::USUAL) && bridge.connected_in("Profile 2"));

    let mut stranger = link(&bridge);
    let hello = json!({ "version": "1.0.0", "protocol": 1, "instance": "three", "profile": "Profile 9" });
    stranger.send(&json!({ "hello": hello })).await;
    let refused = stranger.next().await.unwrap();
    assert!(
        refused["refused"]
            .as_str()
            .unwrap()
            .contains("profile folder Profile 9 connected, but config.json's otherProfiles does not name it"),
        "{refused}"
    );

    // An op for the usual profile reaches its link only; a reply to it from another link is ignored.
    let asked = {
        let bridge = Arc::clone(&bridge);
        tokio::spawn(async move { bridge.op_in(bridge::USUAL, "tabs", json!({})).await })
    };
    let op = usual.next().await.unwrap();
    assert_eq!(op["op"], "tabs");
    work.send(&json!({ "id": op["id"], "result": "forged" })).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    usual.send(&json!({ "id": op["id"], "result": "real" })).await;
    assert_eq!(asked.await.unwrap().unwrap(), json!("real"));

    let work = serve(work, |m| Some(json!({ "id": m["id"], "result": "work's" })));
    assert_eq!(bridge.op_in("Profile 2", "tabs", json!({})).await.unwrap(), json!("work's"));
    assert!(bridge.op_in("Profile 9", "tabs", json!({})).await.is_err());

    work.abort();
    let gone = event(&mut events, |e| matches!(e, BridgeEvent::Disconnect { .. })).await;
    let BridgeEvent::Disconnect { profile, .. } = gone else { unreachable!() };
    assert_eq!(&*profile, "Profile 2");
    assert!(bridge.connected_in(bridge::USUAL) && !bridge.connected_in("Profile 2"));
    drop(usual);
    bridge.close();
}

/// SR-76, L1: a second live instance of a profile's copy is refused, naming that profile, only when that
/// profile's own link answers ping. The usual link answering says nothing about it, so a second instance
/// whose predecessor is silent replaces it.
#[tokio::test]
async fn a_second_live_instance_of_a_profiles_copy_is_judged_by_that_profiles_link() {
    let bridge = Arc::new(Bridge::with_profiles(vec!["Profile 2".to_owned()]));
    let usual = serve(extension(&bridge, "one").await, |_| None);
    let silent = extension_in(&bridge, "two", "Profile 2").await;
    let silent_closed = tokio::spawn(async move {
        let mut silent = silent;
        silent.closed().await;
    });
    // Profile 2's link does not answer: the usual link's answer must not make this a second profile.
    let live = serve(extension_in(&bridge, "three", "Profile 2").await, |_| None);
    silent_closed.await.unwrap();
    assert!(bridge.connected_in("Profile 2"));

    let mut second = link(&bridge);
    let hello = json!({ "version": "1.0.0", "protocol": 1, "instance": "four", "profile": "Profile 2" });
    second.send(&json!({ "hello": hello })).await;
    let refused = second.next().await.unwrap();
    assert!(
        refused["refused"]
            .as_str()
            .unwrap()
            .contains("copy for Chrome profile folder Profile 2 is loaded in more than one Chrome profile"),
        "{refused}"
    );
    assert!(bridge.connected_in(bridge::USUAL) && bridge.connected_in("Profile 2"));
    live.abort();
    usual.abort();
    bridge.close();
}

/// SR-76, L1: with other profiles allowed, each must have loaded the bridge from exactly its own copy's
/// folder, and no profile phantab does not allow may list any copy: the usual copy in an extra profile
/// would claim to be the usual profile, and an extra profile's copy elsewhere would claim to be it.
#[test]
fn every_allowed_profile_uses_its_own_copy_and_no_other_profile_lists_one() {
    let dir = tempfile::tempdir().unwrap();
    let usual = dir.path().join("runtime").join("extension");
    let work = dir.path().join("runtime").join("extension-profiles").join("Profile 2").join("extension");
    std::fs::create_dir_all(&usual).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let prefs = |name: &str, path: Option<&Path>| {
        let settings = match path {
            Some(p) => json!({ (EXTENSION_ID.as_str()): { "path": p, "location": 4 } }),
            None => json!({}),
        };
        write(&dir.path().join(name).join("Preferences"), &json!({ "extensions": { "settings": settings } }));
    };
    let allowed = [
        bridge::Allowed { folder: "Default", extension_dir: &usual },
        bridge::Allowed { folder: "Profile 2", extension_dir: &work },
    ];
    let check =
        |which: &str| bridge::profiles_check(dir.path(), &allowed, which, &EXTENSION_ID, false).unwrap();
    prefs("Default", Some(&usual));
    prefs("Profile 2", None);
    prefs("Profile 5", None);
    assert_eq!(check("Default"), ProfileCheck::Ok, "an allowed profile need not have its copy loaded");
    let ProfileCheck::Failed { final_, error } = check("Profile 2") else { panic!("unlisted passed") };
    assert!(!final_ && error.contains(&work.display().to_string()), "not loaded yet, so wait: {error}");

    prefs("Profile 2", Some(&work));
    assert_eq!((check("Default"), check("Profile 2")), (ProfileCheck::Ok, ProfileCheck::Ok));

    for (folder, path) in [("Profile 2", &usual), ("Profile 5", &work), ("Profile 5", &usual)] {
        prefs(folder, Some(path));
        for which in ["Default", "Profile 2"] {
            assert!(
                matches!(check(which), ProfileCheck::Failed { final_: true, .. }),
                "{folder} listing {} passed for {which}",
                path.display()
            );
        }
        prefs(folder, if folder == "Profile 2" { Some(&work) } else { None });
    }
    assert_eq!(check("Profile 2"), ProfileCheck::Ok);
}

/// SR-74, SR-76, L1 (review round 2): the profile is the worker's own claim, so every loaded copy's files
/// are checked on each link, not only the claimed profile's. A changed usual copy claiming Profile 2 is
/// refused, finally, and so is a link of either profile while an extra profile's copy is changed.
#[test]
fn a_changed_copy_is_refused_whichever_profile_the_worker_claims() {
    use phantab::extension_files::{hashes, record_path, render};
    let dir = tempfile::tempdir().unwrap();
    let usual = dir.path().join("runtime").join("extension");
    let work = dir.path().join("runtime").join("extension-profiles").join("Profile 2").join("extension");
    for (folder, ext) in [("Default", &usual), ("Profile 2", &work)] {
        std::fs::create_dir_all(ext).unwrap();
        std::fs::write(ext.join("manifest.json"), b"{}").unwrap();
        std::fs::write(ext.join("background.js"), b"the bridge").unwrap();
        std::fs::write(record_path(ext), render(&hashes(ext).unwrap())).unwrap();
        let settings = json!({ (EXTENSION_ID.as_str()): { "path": ext, "location": 4 } });
        write(
            &dir.path().join(folder).join("Preferences"),
            &json!({ "extensions": { "settings": settings } }),
        );
    }
    let allowed = [
        bridge::Allowed { folder: "Default", extension_dir: &usual },
        bridge::Allowed { folder: "Profile 2", extension_dir: &work },
    ];
    let check =
        |which: &str| bridge::profiles_check(dir.path(), &allowed, which, &EXTENSION_ID, true).unwrap();
    assert_eq!((check("Default"), check("Profile 2")), (ProfileCheck::Ok, ProfileCheck::Ok));

    for (ext, named) in [(&usual, "The usual Chrome profile"), (&work, "Chrome profile folder Profile 2")] {
        std::fs::write(ext.join("background.js"), b"the bridge, and every page to elsewhere").unwrap();
        for which in ["Default", "Profile 2"] {
            let ProfileCheck::Failed { final_, error } = check(which) else { panic!("{which} passed") };
            assert!(
                final_
                    && error.contains(r#"files changed since phantab install wrote them ("background.js")"#),
                "{which}: {error}"
            );
            let claimed = (which == "Default") == (ext == &usual);
            assert_eq!(error.contains(named), !claimed, "{which}: {error}");
        }
        std::fs::write(ext.join("background.js"), b"the bridge").unwrap();
    }
    assert_eq!((check("Default"), check("Profile 2")), (ProfileCheck::Ok, ProfileCheck::Ok));
}

/// SR-90: off (the default), a developer-tools command is refused before it leaves the service with an
/// error naming the setting, the welcome does not declare `devTools`, and a developer-tools event is
/// dropped. On, the welcome declares it, the commands are relayed and the events kept. A cookie command
/// and an `...ExtraInfo` event stay refused and dropped either way.
#[tokio::test]
async fn devtools_commands_are_relayed_only_with_the_setting() {
    for on in [false, true] {
        let bridge = Arc::new(Bridge::new().with_dev_tools(on));
        let mut events = bridge.subscribe();
        let mut ext = link(&bridge);
        ext.send(&json!({ "hello": { "version": "1.0.0", "protocol": 1, "instance": "one" } })).await;
        let mut welcome = json!({ "welcome": true, "events": phantab_cdp::EVENTS });
        if on {
            welcome["devTools"] = json!(true);
        }
        assert_eq!(ext.next().await, Some(welcome), "devTools {on}");
        for method in
            ["Network.getAllCookies", "Network.getCookies", "Storage.getCookies", "Network.setCookie"]
        {
            let err = bridge.op("send", json!({ "tabId": 7, "method": method })).await.unwrap_err();
            assert!(matches!(err, BridgeError::MethodNotAllowed(_)), "{method}: {err}");
        }
        for method in
            ["Log.enable", "Network.enable", "Network.getResponseBody", "Runtime.terminateExecution"]
        {
            let sent = tokio::spawn({
                let bridge = Arc::clone(&bridge);
                async move { bridge.op("send", json!({ "tabId": 7, "method": method, "params": {} })).await }
            });
            if !on {
                let err = sent.await.unwrap().unwrap_err();
                assert_eq!(
                    err.to_string(),
                    format!(
                        "phantab does not relay the CDP method {method}: it is a developer tool, off unless \
                         \"devTools\": true is set in config.json."
                    )
                );
                continue;
            }
            let m = ext.next().await.unwrap();
            assert_eq!(m["args"]["method"], method);
            ext.send(&json!({ "id": m["id"], "result": {} })).await;
            assert_eq!(sent.await.unwrap().unwrap(), json!({}));
        }
        // Events: an ExtraInfo one and a developer-tools one, then a marker phantab always reads.
        let extra = json!({ "headers": { "cookie": "sid=secret" } });
        ext.send(&json!({ "event": "cdp", "tabId": 7, "method": "Network.requestWillBeSentExtraInfo", "params": extra })).await;
        ext.send(&json!({ "event": "cdp", "tabId": 7, "method": "Network.requestWillBeSent", "params": { "requestId": "1" } })).await;
        ext.send(&json!({ "event": "cdp", "tabId": 7, "method": "Page.frameNavigated", "params": {} })).await;
        let mut seen = Vec::new();
        loop {
            let BridgeEvent::Cdp(cdp) = event(&mut events, |e| matches!(e, BridgeEvent::Cdp(_))).await else {
                unreachable!()
            };
            seen.push(cdp.method.clone());
            if cdp.method == "Page.frameNavigated" {
                break;
            }
        }
        let want: &[&str] =
            if on { &["Network.requestWillBeSent", "Page.frameNavigated"] } else { &["Page.frameNavigated"] };
        assert_eq!(seen, want, "devTools {on}");
        bridge.close();
    }
}
