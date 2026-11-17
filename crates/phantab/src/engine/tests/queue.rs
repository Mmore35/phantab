//! The service queue with the real engine: which calls wait for which.

use std::time::Instant;

use super::*;

/// A page like [`fake_page`] whose `Page.navigate` answers after `delay`: a slow site.
async fn slow_page(url: &str, delay: Duration) -> Page {
    let (tx, rx) = mpsc::unbounded_channel();
    let url = url.to_owned();
    let transport = RelayTransport::from_fn(move |_session, method: String, params: Value| {
        let (tx, url) = (tx.clone(), url.clone());
        async move {
            let event = |method: &str, params: Value| {
                let _ = tx.send(TransportEvent::Event { session: None, method: method.into(), params });
            };
            Ok(match method.as_str() {
                "Page.getFrameTree" => json!({ "frameTree": { "frame": { "id": "F", "url": url } } }),
                "Runtime.enable" => {
                    event(
                        "Runtime.executionContextCreated",
                        json!({ "context": { "id": 1, "auxData": { "frameId": "F", "isDefault": true } } }),
                    );
                    json!({})
                }
                // Page script runs in phantab's isolated world (SR-34): Chrome reports it, then answers.
                "Page.createIsolatedWorld" => {
                    let world = json!({ "id": 2, "name": "phantab", "uniqueId": "w2", "auxData": { "frameId": "F", "isDefault": false, "type": "isolated" } });
                    event("Runtime.executionContextCreated", json!({ "context": world }));
                    json!({ "executionContextId": 2 })
                }
                "Runtime.callFunctionOn" => json!({ "result": { "type": "boolean", "value": true } }),
                "Page.navigate" => {
                    tokio::time::sleep(delay).await;
                    event(
                        "Page.lifecycleEvent",
                        json!({ "frameId": "F", "loaderId": "", "name": "DOMContentLoaded" }),
                    );
                    event("Page.navigatedWithinDocument", json!({ "frameId": "F", "url": params["url"] }));
                    json!({ "frameId": "F" })
                }
                "Page.close" => {
                    let _ = tx.send(TransportEvent::Closed("Page closed".into()));
                    json!({})
                }
                _ => json!({}),
            })
        }
    });
    Page::attach(Arc::new(transport), None, rx, PageOptions::default()).await.unwrap()
}

/// One call as the service's `dispatch` runs it.
fn call(e: &Arc<Engine>, method: EngineMethod, args: Value, client: &str) -> JoinHandle<EngineResult> {
    let engine = Arc::clone(e) as Arc<dyn PageService>;
    crate::engine_api::spawn_call(engine, &e.setup.serializer, method, args, client.to_owned())
}

fn navigate(r: &Rec) -> Value {
    json!({ "pageId": r.id, "action": "navigate", "url": format!("{FIXTURE}slow") })
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn summary(mut v: Vec<Duration>) -> String {
    v.sort();
    // The value at `pct` percent of the way up the sorted list.
    let at = |pct: usize| v.get(v.len().saturating_sub(1) * pct / 100).copied().unwrap_or_default();
    format!(
        "n={} p50={:.2}ms p95={:.2}ms max={:.2}ms",
        v.len(),
        ms(at(50)),
        ms(at(95)),
        ms(v.last().copied().unwrap_or_default())
    )
}

/// The numbers in the PR: B's snapshot latency while A navigates to a site that takes 10 s, and one
/// agent's snapshot latency alone. `cargo test -p phantab --lib measure_ -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, not a check: run it with --ignored --nocapture"]
#[allow(clippy::print_stdout, reason = "the measurement is its printout")]
async fn measure_snapshot_latency_beside_a_slow_navigate() {
    let f = fixture(Recording::new());
    let e = &f.engine;
    let a = e.record(slow_page(FIXTURE, Duration::from_secs(10)).await, "a", Fields::default()).unwrap();
    let b = rec(e, "b", "https://other.invalid/", Fields::default()).await;
    let snap_b = json!({ "pageId": b.id });

    for _ in 0..50 {
        call(e, EngineMethod::Snapshot, snap_b.clone(), "b").await.unwrap().unwrap();
    }
    let mut alone = Vec::new();
    for _ in 0..500 {
        let t = Instant::now();
        call(e, EngineMethod::Snapshot, snap_b.clone(), "b").await.unwrap().unwrap();
        alone.push(t.elapsed());
    }
    println!("one agent, snapshot: {}", summary(alone));

    let started = Instant::now();
    let act = call(e, EngineMethod::Act, navigate(&a), "a");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut beside = Vec::new();
    while !act.is_finished() {
        let t = Instant::now();
        call(e, EngineMethod::Snapshot, snap_b.clone(), "b").await.unwrap().unwrap();
        beside.push(t.elapsed());
    }
    act.await.unwrap().unwrap();
    println!("A's navigate took {:.0}ms", ms(started.elapsed()));
    println!("B's snapshots during it: {}", summary(beside));
}

/// The finding's case: a site that takes about 10 s to load.
const SLOW: Duration = Duration::from_secs(10);
const OTHER: &str = "https://other.invalid/";

/// Gives a call that should wait a moment to go wrongly. Only for checking that something has not
/// happened, which a slow machine cannot make fail.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Waits until `n` calls hold or wait for a place in the queue.
async fn until_in_line(e: &Engine, n: usize) {
    let wait = async {
        while e.setup.serializer.places() < n {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), wait).await.expect("the calls took their places");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_agents_snapshots_never_wait_for_a_slow_navigate() {
    let f = fixture(Recording::new());
    let e = &f.engine;
    let a = e.record(slow_page(FIXTURE, SLOW).await, "a", Fields::default()).unwrap();
    let b = rec(e, "b", OTHER, Fields::default()).await;
    let started = Instant::now();
    let act = call(e, EngineMethod::Act, navigate(&a), "a");
    settle().await;
    let (mut snapshots, mut slowest) = (0, Duration::ZERO);
    while !act.is_finished() {
        let t = Instant::now();
        let out = call(e, EngineMethod::Snapshot, json!({ "pageId": b.id }), "b").await.unwrap().unwrap();
        assert_eq!(out["pageId"], json!(b.id));
        slowest = slowest.max(t.elapsed());
        snapshots += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let acted = act.await.unwrap().unwrap();
    assert!(started.elapsed() >= SLOW, "the navigate really took its time");
    assert_eq!(acted["url"], format!("{FIXTURE}slow"));
    assert!(snapshots >= 20, "B took {snapshots} snapshots during A's navigate");
    assert!(slowest < Duration::from_secs(5), "B's slowest snapshot took {slowest:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_pages_calls_keep_their_order() {
    let f = fixture(Recording::new());
    let e = &f.engine;
    let a = e.record(slow_page(FIXTURE, Duration::from_secs(1)).await, "a", Fields::default()).unwrap();
    let act = call(e, EngineMethod::Act, navigate(&a), "a");
    let snapshot = call(e, EngineMethod::Snapshot, json!({ "pageId": a.id }), "a");
    assert_eq!(act.await.unwrap().unwrap()["url"], format!("{FIXTURE}slow"));
    let snapped = snapshot.await.unwrap().unwrap();
    assert_eq!(snapped["url"], format!("{FIXTURE}slow"), "the snapshot ran after the navigate");
}

// rmcp answers each request in its own task, so one agent's calls on two of its pages can be in flight
// at once; they still run in the order sent, while another agent's go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_agents_call_on_another_of_its_pages_waits_for_its_slow_navigate() {
    let f = fixture(Recording::new());
    let e = &f.engine;
    let p1 = e.record(slow_page(FIXTURE, Duration::from_millis(1500)).await, "a", Fields::default()).unwrap();
    let p2 = rec(e, "a", OTHER, Fields::default()).await;
    let b = rec(e, "b", OTHER, Fields::default()).await;
    let act = call(e, EngineMethod::Act, navigate(&p1), "a");
    let own = call(e, EngineMethod::Snapshot, json!({ "pageId": p2.id }), "a");
    let others = call(e, EngineMethod::Snapshot, json!({ "pageId": b.id }), "b");
    let others = tokio::time::timeout(Duration::from_secs(5), others).await.expect("agent b's snapshot ran");
    assert_eq!(others.unwrap().unwrap()["pageId"], json!(b.id));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!act.is_finished() && !own.is_finished(), "agent a's snapshot waits for its navigate");
    assert_eq!(act.await.unwrap().unwrap()["url"], format!("{FIXTURE}slow"));
    assert_eq!(own.await.unwrap().unwrap()["pageId"], json!(p2.id));
}

// The OS hook `open` arms hides the first Chrome window to appear at the workspace's position, and a
// click on another page can open one; so an open waits for running page calls, and page calls after it
// wait for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_waits_for_running_page_calls_and_later_page_calls_wait_for_it() {
    let (f, ext) = connected(Recording::new().with_arm_answer(Some(NativeHandle(7)))).await;
    let e = &f.engine;
    let a = e.record(slow_page(FIXTURE, Duration::from_millis(1500)).await, "a", Fields::default()).unwrap();
    let b = rec(e, "b", OTHER, Fields::default()).await;
    let act = call(e, EngineMethod::Act, navigate(&a), "a");
    // The open takes its place only after its browser check, in its own task.
    let open = call(e, EngineMethod::Open, json!({ "url": FIXTURE }), "c");
    until_in_line(e, 2).await;
    let snapshot = call(e, EngineMethod::Snapshot, json!({ "pageId": b.id }), "b");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!ext.ops().contains(&"createWindow".to_owned()));
    assert!(!f.windows.calls().iter().any(|c| matches!(c, Call::Arm(_))), "no hook armed during A's call");
    assert!(!snapshot.is_finished(), "B's snapshot waits behind the open");
    act.await.unwrap().unwrap();
    assert_eq!(open.await.unwrap().unwrap()["mode"], "shared-hidden");
    snapshot.await.unwrap().unwrap();
}

// A close ends a record and may close its window, so it waits for every running call, its own
// agent's and another's, and the navigate it waited for finished rather than being cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_during_page_calls_waits_for_them_then_closes_the_page() {
    let f = fixture(Recording::new());
    let e = &f.engine;
    let a = e.record(slow_page(FIXTURE, Duration::from_millis(500)).await, "a", Fields::default()).unwrap();
    let b = e.record(slow_page(OTHER, Duration::from_millis(2000)).await, "b", Fields::default()).unwrap();
    let act = call(e, EngineMethod::Act, navigate(&a), "a");
    let other = json!({ "pageId": b.id, "action": "navigate", "url": format!("{OTHER}slow") });
    let others = call(e, EngineMethod::Act, other, "b");
    let close = call(e, EngineMethod::Close, json!({ "pageId": a.id }), "a");
    let acted = act.await.unwrap();
    assert_eq!(acted.unwrap()["url"], format!("{FIXTURE}slow"), "the navigate finished, not cut");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(has(e, &a) && !close.is_finished(), "the close waits for another agent's navigate too");
    assert_eq!(others.await.unwrap().unwrap()["url"], format!("{OTHER}slow"));
    assert_eq!(close.await.unwrap().unwrap()["released"], true);
    let after = call(e, EngineMethod::Snapshot, json!({ "pageId": a.id }), "a").await.unwrap();
    assert_eq!(err(after), "Unknown page or page belongs to another agent session.");
}

// `tabs` waits up to 10 s for the bridge, then up to 15 s for the profile; it waits before taking its
// place, so the calls behind it go on. An invalid url still answers before any browser wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiting_for_the_browser_holds_no_other_call() {
    let f = fixture(Recording::new());
    let e = &f.engine;
    let b = rec(e, "b", OTHER, Fields::default()).await;
    let tabs = call(e, EngineMethod::Tabs, json!({}), "x");
    settle().await;
    let t = Instant::now();
    let invalid = call(e, EngineMethod::Open, json!({ "url": "not a url" }), "x").await.unwrap();
    assert_eq!(err(invalid), "Invalid URL");
    let closed = call(e, EngineMethod::Close, json!({ "pageId": b.id }), "b").await.unwrap();
    assert_eq!(closed.unwrap()["released"], true);
    assert!(t.elapsed() < Duration::from_secs(5), "took {:?}", t.elapsed());
    assert!(!tabs.is_finished());
    let _ext = Ext::connect(e.bridge()).await;
    assert!(tabs.await.unwrap().unwrap().is_array());
}

// Under `siteLock: exclusive`, two agents' pages on one site now act at the same moment; the lease's check-and-take is one step
// under the engine's state lock, so one gets it and the other is refused, as when they ran in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_agents_acting_on_one_site_at_once_get_one_lease() {
    let f = fixture_exclusive(Recording::new());
    let e = &f.engine;
    for _ in 0..10 {
        let a =
            e.record(slow_page(FIXTURE, Duration::from_millis(50)).await, "a", Fields::default()).unwrap();
        let c =
            e.record(slow_page(FIXTURE, Duration::from_millis(50)).await, "c", Fields::default()).unwrap();
        let x = call(e, EngineMethod::Act, navigate(&a), "a");
        let y = call(e, EngineMethod::Act, navigate(&c), "c");
        let (x, y) = (x.await.unwrap(), y.await.unwrap());
        assert!(x.is_ok() != y.is_ok(), "{x:?} {y:?}");
        let refused = x.err().or(y.err()).unwrap();
        assert!(refused.0.contains("holds this site"), "{refused}");
        e.close("a", &json!({ "pageId": a.id })).await.unwrap();
        e.close("c", &json!({ "pageId": c.id })).await.unwrap();
        assert_eq!(e.st().origins.len(), 0);
    }
}
