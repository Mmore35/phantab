//! Page bookkeeping against a scripted transport; no Chrome needed.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::*;
use crate::{CdpError, ClickError, SessionId, Transport, TransportEvent, Unsettled};

pub(crate) enum Reply {
    Ok(Value),
    Err(CdpError),
    /// Answers after a while, so other calls can run meanwhile.
    Later(Duration, Value),
    Hang,
}

type Handler = Box<dyn Fn(Option<&SessionId>, &str, &Value) -> Reply + Send + Sync>;

pub(crate) struct Mock {
    log: Mutex<Vec<(Option<SessionId>, String, Value)>>,
    handler: Handler,
    /// Where the mock reports each isolated world it makes, as Chrome does before it answers; `None`
    /// keeps them back, for a test to send itself.
    /// Weak, so dropping the rig's sender still ends the event stream.
    events: Mutex<Option<mpsc::WeakUnboundedSender<TransportEvent>>>,
}

/// The `uniqueId` the mock gives isolated world `id`.
fn unique_of(id: i64) -> String {
    format!("world-{id}")
}

/// The `executionContextCreated` of isolated world `id` in `frame`.
fn world_event(frame: &str, id: i64) -> Value {
    json!({"context": {"id": id, "name": ISOLATED_WORLD, "uniqueId": unique_of(id),
        "auxData": {"frameId": frame, "isDefault": false, "type": "isolated"}}})
}

#[async_trait]
impl Transport for Mock {
    async fn send(
        &self,
        session: Option<&SessionId>,
        method: &str,
        params: Value,
    ) -> Result<Value, CdpError> {
        let reply = (self.handler)(session, method, &params);
        if method == "Page.createIsolatedWorld"
            && let Reply::Ok(v) | Reply::Later(_, v) = &reply
            && let (Some(id), Some(frame)) = (v["executionContextId"].as_i64(), params["frameId"].as_str())
            && let Some(tx) = self.events.lock().as_ref().and_then(mpsc::WeakUnboundedSender::upgrade)
        {
            let params = world_event(frame, id);
            let method = "Runtime.executionContextCreated".into();
            let _ = tx.send(TransportEvent::Event { session: session.cloned(), method, params });
        }
        self.log.lock().push((session.cloned(), method.to_owned(), params));
        match reply {
            Reply::Ok(v) => Ok(v),
            Reply::Err(e) => Err(e),
            Reply::Later(d, v) => {
                tokio::time::sleep(d).await;
                Ok(v)
            }
            Reply::Hang => std::future::pending().await,
        }
    }
}

impl Mock {
    fn calls(&self) -> Vec<(Option<SessionId>, String, Value)> {
        self.log.lock().clone()
    }

    fn methods_on(&self, session: Option<&str>) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|(s, _, _)| s.as_ref().map(SessionId::as_str) == session)
            .map(|c| c.1)
            .collect()
    }

    fn last(&self, method: &str) -> Option<(Option<SessionId>, Value)> {
        self.calls().into_iter().rev().find(|c| c.1 == method).map(|c| (c.0, c.2))
    }

    fn count(&self, method: &str) -> usize {
        self.calls().iter().filter(|c| c.1 == method).count()
    }
}

/// The first isolated world the default handler makes; each later one is the next number.
const FIRST_WORLD: i64 = 100;

fn main_tree() -> Value {
    json!({"frameTree": {"frame": {"id": "MAIN", "loaderId": "L0", "url": "about:blank"}}})
}

/// Answers the init commands, and makes isolated worlds numbered from [`FIRST_WORLD`]; `extra` gets
/// the first say.
fn handler(
    extra: impl Fn(Option<&SessionId>, &str, &Value) -> Option<Reply> + Send + Sync + 'static,
) -> Handler {
    let worlds = std::sync::atomic::AtomicI64::new(FIRST_WORLD);
    Box::new(move |s, m, p| {
        if let Some(r) = extra(s, m, p) {
            return r;
        }
        match m {
            "Page.getFrameTree" if s.is_none() => Reply::Ok(main_tree()),
            "Page.createIsolatedWorld" => Reply::Ok(
                json!({"executionContextId": worlds.fetch_add(1, std::sync::atomic::Ordering::SeqCst)}),
            ),
            _ => Reply::Ok(json!({})),
        }
    })
}

struct Rig {
    page: Page,
    mock: Arc<Mock>,
    tx: mpsc::UnboundedSender<TransportEvent>,
}

impl Rig {
    async fn new(h: Handler) -> Rig {
        Rig::with_options(h, quick_options()).await
    }

    async fn with_options(h: Handler, opts: PageOptions) -> Rig {
        let (tx, rx) = mpsc::unbounded_channel();
        let mock = Arc::new(Mock {
            log: Mutex::new(Vec::new()),
            handler: h,
            events: Mutex::new(Some(tx.downgrade())),
        });
        let transport: Arc<dyn Transport> = mock.clone();
        let page = Page::attach(transport, None, rx, opts).await.unwrap();
        Rig { page, mock, tx }
    }

    fn event(&self, session: Option<&str>, method: &str, params: Value) {
        self.tx
            .send(TransportEvent::Event {
                session: session.map(SessionId::from),
                method: method.into(),
                params,
            })
            .unwrap();
    }

    /// Waits until the event task has applied everything sent so far.
    async fn settle(&self) {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    fn context(&self, session: Option<&str>, frame: &str, id: i64) {
        self.event(
            session,
            "Runtime.executionContextCreated",
            json!({"context": {"id": id, "auxData": {"frameId": frame, "isDefault": true}}}),
        );
    }
}

fn quick_options() -> PageOptions {
    PageOptions {
        protocol_timeout: Duration::from_millis(300),
        default_timeout: Duration::from_millis(300),
        locator_timeout: Duration::from_millis(300),
        target_id: None,
        answer_dialogs: false,
        popups_as_tabs: false,
        watch_passkeys: false,
    }
}

fn eval_handler() -> Handler {
    handler(|_, m, _| {
        (m == "Runtime.callFunctionOn").then(|| Reply::Ok(json!({"result": {"type": "number", "value": 42}})))
    })
}

async fn wait_for(mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition never held");
}

#[tokio::test]
async fn attach_enables_domains_in_order_and_never_network() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    assert_eq!(
        rig.mock.methods_on(None),
        [
            "Page.enable",
            "Page.getFrameTree",
            "Page.setLifecycleEventsEnabled",
            "Runtime.enable",
            "Target.setAutoAttach",
            "Runtime.runIfWaitingForDebugger"
        ]
    );
    let (_, p) = rig.mock.last("Target.setAutoAttach").unwrap();
    assert_eq!(p, json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}));
    assert_eq!(rig.mock.last("Page.setLifecycleEventsEnabled").unwrap().1, json!({"enabled": true}));
    assert!(rig.mock.calls().iter().all(|c| !c.1.starts_with("Network.") && !c.1.starts_with("Audits.")));
    assert_eq!(rig.page.main_frame().unwrap(), FrameId::from("MAIN"));
    assert_eq!(rig.page.url(), "about:blank");
}

#[tokio::test]
async fn attach_fails_when_an_init_command_fails() {
    let mock = Arc::new(Mock {
        log: Mutex::new(Vec::new()),
        events: Mutex::new(None),
        handler: handler(|_, m, _| {
            (m == "Runtime.enable")
                .then(|| Reply::Err(CdpError::Other("Protocol error (Runtime.enable): nope".into())))
        }),
    });
    let (_tx, rx) = mpsc::unbounded_channel();
    let transport: Arc<dyn Transport> = mock;
    let err = Page::attach(transport, None, rx, quick_options()).await.unwrap_err();
    assert!(err.to_string().contains("nope"));
}

#[tokio::test]
async fn frame_tree_attach_navigate_detach() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    rig.event(None, "Page.frameAttached", json!({"frameId": "C1", "parentFrameId": "MAIN"}));
    rig.event(
        None,
        "Page.frameNavigated",
        json!({"frame": {"id": "C1", "parentId": "MAIN", "url": "https://a/x", "urlFragment": "#f"}}),
    );
    rig.event(None, "Page.frameAttached", json!({"frameId": "C2", "parentFrameId": "C1"}));
    rig.settle().await;
    let frames = rig.page.frames();
    let ids: Vec<&str> = frames.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["MAIN", "C1", "C2"]);
    assert_eq!(frames[1].url, "https://a/x#f");
    assert_eq!(frames[2].parent, Some(FrameId::from("C1")));

    // A swap keeps the frame (it moves to an OOPIF target).
    rig.event(None, "Page.frameDetached", json!({"frameId": "C2", "reason": "swap"}));
    rig.settle().await;
    assert_eq!(rig.page.frames().len(), 3);

    rig.event(None, "Page.frameDetached", json!({"frameId": "C1", "reason": "remove"}));
    rig.settle().await;
    assert_eq!(rig.page.frames().len(), 1);
    let gone = rig.page.frame_info(&FrameId::from("C2")).unwrap();
    assert!(gone.detached);

    // A cross-document navigation of the main frame drops its children.
    rig.event(None, "Page.frameAttached", json!({"frameId": "C3", "parentFrameId": "MAIN"}));
    rig.event(
        None,
        "Page.frameNavigated",
        json!({"frame": {"id": "MAIN", "url": "https://b/"}, "type": "Navigation"}),
    );
    rig.settle().await;
    let frames = rig.page.frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(rig.page.url(), "https://b/");

    rig.event(None, "Page.navigatedWithinDocument", json!({"frameId": "MAIN", "url": "https://b/#2"}));
    rig.settle().await;
    assert_eq!(rig.page.url(), "https://b/#2");
}

#[tokio::test]
async fn evaluate_waits_for_the_default_context() {
    let rig = Rig::new(eval_handler()).await;
    let page = rig.page.clone();
    let main = FrameId::from("MAIN");
    let task =
        tokio::spawn(async move { page.evaluate(&main, "(a) => a + 41", vec![json!(1).into()]).await });
    rig.settle().await;
    assert!(rig.mock.last("Runtime.callFunctionOn").is_none());
    // A non-default (isolated) world is not the main world.
    rig.event(
        None,
        "Runtime.executionContextCreated",
        json!({"context": {"id": 5, "auxData": {"frameId": "MAIN", "isDefault": false}}}),
    );
    rig.context(None, "MAIN", 7);
    assert_eq!(task.await.unwrap().unwrap(), json!(42));
    // It runs in phantab's own world of that document, made once it was there.
    let (s, p) = rig.mock.last("Page.createIsolatedWorld").unwrap();
    assert_eq!(s, None);
    assert_eq!(p, json!({"frameId": "MAIN", "worldName": ISOLATED_WORLD}));
    let (s, p) = rig.mock.last("Runtime.callFunctionOn").unwrap();
    assert_eq!(s, None);
    assert_eq!(p["uniqueContextId"], unique_of(FIRST_WORLD));
    assert_eq!(p["arguments"], json!([{"value": 1}]));
    assert_eq!(p["returnByValue"], true);
    assert_eq!(p["awaitPromise"], true);

    // Cleared contexts: the next evaluate waits, then times out.
    rig.event(None, "Runtime.executionContextsCleared", json!({}));
    rig.settle().await;
    let err = rig.page.evaluate(&FrameId::from("MAIN"), "() => 1", vec![]).await.unwrap_err();
    assert!(err.is_timeout(), "{err}");

    // A destroyed context is forgotten too.
    rig.context(None, "MAIN", 8);
    rig.event(None, "Runtime.executionContextDestroyed", json!({"executionContextId": 8}));
    rig.settle().await;
    assert!(rig.page.evaluate(&FrameId::from("MAIN"), "() => 1", vec![]).await.unwrap_err().is_timeout());
}

#[tokio::test]
async fn evaluate_in_unknown_frame_is_detached() {
    let rig = Rig::new(eval_handler()).await;
    let err = rig.page.evaluate(&FrameId::from("NOPE"), "() => 1", vec![]).await.unwrap_err();
    assert!(matches!(err, CdpError::DetachedFrame(_)));
    assert!(err.is_navigating());
    assert_eq!(err.to_string(), "Attempted to use detached Frame 'NOPE'.");
}

#[tokio::test]
async fn frame_detached_while_waiting_is_context_destroyed() {
    let rig = Rig::new(eval_handler()).await;
    rig.event(None, "Page.frameAttached", json!({"frameId": "C1", "parentFrameId": "MAIN"}));
    rig.settle().await;
    let page = rig.page.clone();
    let task = tokio::spawn(async move { page.evaluate(&FrameId::from("C1"), "() => 1", vec![]).await });
    rig.settle().await;
    rig.event(None, "Page.frameDetached", json!({"frameId": "C1", "reason": "remove"}));
    let err = task.await.unwrap().unwrap_err();
    assert_eq!(err, CdpError::ContextDestroyed);
    assert!(err.is_navigating());
}

#[tokio::test]
async fn context_reported_before_its_frame_is_kept() {
    let rig = Rig::new(eval_handler()).await;
    rig.context(None, "LATE", 11);
    rig.settle().await;
    rig.event(None, "Page.frameAttached", json!({"frameId": "LATE", "parentFrameId": "MAIN"}));
    rig.settle().await;
    rig.page.evaluate(&FrameId::from("LATE"), "() => 1", vec![]).await.unwrap();
    assert_eq!(rig.mock.last("Page.createIsolatedWorld").unwrap().1["frameId"], "LATE");
    assert_eq!(rig.mock.last("Runtime.callFunctionOn").unwrap().1["uniqueContextId"], unique_of(FIRST_WORLD));
}

fn oopif_handler() -> Handler {
    handler(|s, m, _| match (s.map(SessionId::as_str), m) {
        (Some("S1"), "Page.getFrameTree") => Some(Reply::Ok(
            json!({"frameTree": {"frame": {"id": "OOP", "parentId": "MAIN", "url": "http://localhost/c"}}}),
        )),
        (_, "Runtime.callFunctionOn") => {
            Some(Reply::Ok(json!({"result": {"type": "string", "value": "child"}})))
        }
        _ => None,
    })
}

#[tokio::test]
async fn popups_as_tabs_patches_every_session_before_it_resumes() {
    let opts = PageOptions { popups_as_tabs: true, ..quick_options() };
    let rig = Rig::with_options(oopif_handler(), opts).await;
    rig.event(None, "Page.frameAttached", json!({"frameId": "OOP", "parentFrameId": "MAIN"}));
    rig.event(
        None,
        "Target.attachedToTarget",
        json!({"sessionId": "S1", "targetInfo": {"type": "iframe", "targetId": "OOP"}, "waitingForDebugger": true}),
    );
    let mock = rig.mock.clone();
    wait_for(|| mock.methods_on(Some("S1")).len() == 7).await;
    for session in [None, Some("S1")] {
        let methods = rig.mock.methods_on(session);
        let script = methods.iter().position(|m| m == "Page.addScriptToEvaluateOnNewDocument");
        let resume = methods.iter().position(|m| m == "Runtime.runIfWaitingForDebugger");
        assert!(script.is_some() && script < resume, "{session:?}: {methods:?}");
    }
    let sent: Vec<_> =
        rig.mock.calls().into_iter().filter(|c| c.1 == "Page.addScriptToEvaluateOnNewDocument").collect();
    assert_eq!(sent.len(), 2);
    for (_, _, p) in sent {
        assert_eq!(p, json!({"source": POPUPS_AS_TABS, "runImmediately": true}));
    }
}

#[tokio::test]
async fn popups_as_tabs_is_off_by_default_and_a_refusal_does_not_fail_attach() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    assert!(rig.mock.calls().iter().all(|c| c.1 != "Page.addScriptToEvaluateOnNewDocument"));

    let opts = PageOptions { popups_as_tabs: true, ..quick_options() };
    let refuse = handler(|_, m, _| {
        (m == "Page.addScriptToEvaluateOnNewDocument").then(|| Reply::Err(CdpError::Other("no".into())))
    });
    let rig = Rig::with_options(refuse, opts).await;
    assert_eq!(rig.page.main_frame().unwrap(), FrameId::from("MAIN"));
}

#[tokio::test]
async fn watch_passkeys_counts_in_every_session_before_it_resumes() {
    let opts = PageOptions { watch_passkeys: true, ..quick_options() };
    let rig = Rig::with_options(oopif_handler(), opts).await;
    rig.event(None, "Page.frameAttached", json!({"frameId": "OOP", "parentFrameId": "MAIN"}));
    rig.event(
        None,
        "Target.attachedToTarget",
        json!({"sessionId": "S1", "targetInfo": {"type": "iframe", "targetId": "OOP"}, "waitingForDebugger": true}),
    );
    let mock = rig.mock.clone();
    wait_for(|| mock.methods_on(Some("S1")).len() == 7).await;
    for session in [None, Some("S1")] {
        let methods = rig.mock.methods_on(session);
        let script = methods.iter().position(|m| m == "Page.addScriptToEvaluateOnNewDocument");
        let resume = methods.iter().position(|m| m == "Runtime.runIfWaitingForDebugger");
        assert!(script.is_some() && script < resume, "{session:?}: {methods:?}");
    }
    let sent: Vec<_> =
        rig.mock.calls().into_iter().filter(|c| c.1 == "Page.addScriptToEvaluateOnNewDocument").collect();
    assert_eq!(sent.len(), 2);
    for (_, _, p) in sent {
        assert_eq!(p, json!({"source": PASSKEY_WATCH, "runImmediately": true}));
    }
}

#[tokio::test]
async fn both_scripts_go_to_an_agent_page_and_a_refused_watch_does_not_fail_attach() {
    let opts = PageOptions { popups_as_tabs: true, watch_passkeys: true, ..quick_options() };
    let rig = Rig::with_options(handler(|_, _, _| None), opts).await;
    let sources: Vec<_> = rig
        .mock
        .calls()
        .into_iter()
        .filter(|c| c.1 == "Page.addScriptToEvaluateOnNewDocument")
        .map(|c| c.2["source"].clone())
        .collect();
    assert_eq!(sources, [json!(POPUPS_AS_TABS), json!(PASSKEY_WATCH)]);

    let opts = PageOptions { watch_passkeys: true, ..quick_options() };
    let refuse = handler(|_, m, _| {
        (m == "Page.addScriptToEvaluateOnNewDocument").then(|| Reply::Err(CdpError::Other("no".into())))
    });
    let rig = Rig::with_options(refuse, opts).await;
    assert_eq!(rig.page.main_frame().unwrap(), FrameId::from("MAIN"));
}

#[tokio::test]
async fn passkey_asks_reads_the_main_world_and_takes_only_three_numbers() {
    for (value, want) in [
        (
            json!({"asked": 2, "pending": 1, "answered": 0}),
            Some(PasskeyAsks { asked: 2, pending: 1, answered: 0 }),
        ),
        (Value::Null, None),
        (json!({"asked": "2", "pending": 1, "answered": 0}), None),
        (json!({"asked": -1, "pending": 0, "answered": 0}), None),
        (json!("child"), None),
    ] {
        let reply = value.clone();
        let rig = Rig::new(handler(move |_, m, _| {
            (m == "Runtime.callFunctionOn")
                .then(|| Reply::Ok(json!({"result": {"type": "object", "value": reply.clone()}})))
        }))
        .await;
        rig.context(None, "MAIN", 7);
        rig.settle().await;
        assert_eq!(rig.page.passkey_asks(&FrameId::from("MAIN")).await.unwrap(), want, "{value}");
        let p = rig.mock.last("Runtime.callFunctionOn").unwrap().1;
        assert_eq!(p["functionDeclaration"], PASSKEY_READ);
        assert_eq!(p["executionContextId"], 7, "the main world: {p}");
        assert_eq!(rig.mock.count("Page.createIsolatedWorld"), 0);
    }
}

#[tokio::test]
async fn oopif_session_is_initialised_and_owns_its_frame() {
    let rig = Rig::new(oopif_handler()).await;
    rig.event(None, "Page.frameAttached", json!({"frameId": "OOP", "parentFrameId": "MAIN"}));
    rig.context(None, "OOP", 3);
    rig.event(None, "Page.frameDetached", json!({"frameId": "OOP", "reason": "swap"}));
    rig.event(
        None,
        "Target.attachedToTarget",
        json!({"sessionId": "S1", "targetInfo": {"type": "iframe", "targetId": "OOP"}, "waitingForDebugger": true}),
    );
    let mock = rig.mock.clone();
    wait_for(|| mock.methods_on(Some("S1")).len() == 6).await;
    assert_eq!(
        rig.mock.methods_on(Some("S1")),
        [
            "Page.enable",
            "Page.getFrameTree",
            "Page.setLifecycleEventsEnabled",
            "Runtime.enable",
            "Target.setAutoAttach",
            "Runtime.runIfWaitingForDebugger"
        ]
    );
    rig.settle().await;
    let info = rig.page.frame_info(&FrameId::from("OOP")).unwrap();
    assert_eq!(info.url, "http://localhost/c");
    assert_eq!(info.parent, Some(FrameId::from("MAIN")));

    // The old in-process context went with the swap; a late one from the root session is stale.
    rig.context(None, "OOP", 4);
    rig.context(Some("S1"), "OOP", 9);
    rig.settle().await;
    assert_eq!(rig.page.evaluate(&FrameId::from("OOP"), "() => 'x'", vec![]).await.unwrap(), json!("child"));
    let (s, p) = rig.mock.last("Runtime.callFunctionOn").unwrap();
    assert_eq!(s.as_ref().map(SessionId::as_str), Some("S1"));
    assert_eq!(p["uniqueContextId"], unique_of(FIRST_WORLD));
    let (s, _) = rig.mock.last("Page.createIsolatedWorld").unwrap();
    assert_eq!(s.as_ref().map(SessionId::as_str), Some("S1"), "the world is made by the frame's session");

    // Events of the child session update its frames.
    rig.event(
        Some("S1"),
        "Page.navigatedWithinDocument",
        json!({"frameId": "OOP", "url": "http://localhost/c#h"}),
    );
    rig.settle().await;
    assert_eq!(rig.page.frame_info(&FrameId::from("OOP")).unwrap().url, "http://localhost/c#h");

    // Losing the session forgets its contexts.
    rig.event(None, "Target.detachedFromTarget", json!({"sessionId": "S1"}));
    rig.settle().await;
    assert!(rig.page.evaluate(&FrameId::from("OOP"), "() => 1", vec![]).await.unwrap_err().is_timeout());
}

#[tokio::test]
async fn oopif_attached_before_its_frame_is_known() {
    let rig = Rig::new(oopif_handler()).await;
    rig.event(
        None,
        "Target.attachedToTarget",
        json!({"sessionId": "S1", "targetInfo": {"type": "iframe", "targetId": "OOP"}}),
    );
    rig.context(Some("S1"), "OOP", 21);
    let mock = rig.mock.clone();
    wait_for(|| mock.methods_on(Some("S1")).len() == 6).await;
    rig.settle().await;
    assert_eq!(rig.page.evaluate(&FrameId::from("OOP"), "() => 1", vec![]).await.unwrap(), json!("child"));
    let (s, p) = rig.mock.last("Runtime.callFunctionOn").unwrap();
    assert_eq!(s.as_ref().map(SessionId::as_str), Some("S1"));
    assert_eq!(p["uniqueContextId"], unique_of(FIRST_WORLD));
}

#[tokio::test]
async fn other_targets_are_only_resumed() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    rig.event(
        None,
        "Target.attachedToTarget",
        json!({"sessionId": "W1", "targetInfo": {"type": "worker", "targetId": "W"}}),
    );
    let mock = rig.mock.clone();
    wait_for(|| !mock.methods_on(Some("W1")).is_empty()).await;
    rig.settle().await;
    assert_eq!(rig.mock.methods_on(Some("W1")), ["Runtime.runIfWaitingForDebugger"]);
    // Its events are ignored.
    rig.event(
        Some("W1"),
        "Runtime.executionContextCreated",
        json!({"context": {"id": 1, "auxData": {"frameId": "MAIN", "isDefault": true}}}),
    );
    rig.settle().await;
    assert!(rig.page.evaluate(&FrameId::from("MAIN"), "() => 1", vec![]).await.unwrap_err().is_timeout());
}

#[tokio::test]
async fn hanging_command_times_out() {
    let rig = Rig::new(handler(|_, m, _| (m == "Slow.method").then_some(Reply::Hang))).await;
    let err = rig.page.send("Slow.method", json!({})).await.unwrap_err();
    assert!(err.is_timeout());
    assert_eq!(err.to_string(), "Slow.method timed out.");
}

#[tokio::test]
async fn transport_close_fails_pending_and_later_sends() {
    let rig = Rig::new(handler(|_, m, _| (m == "Slow.method").then_some(Reply::Hang))).await;
    let page = rig.page.clone();
    let pending = tokio::spawn(async move { page.send("Slow.method", json!({})).await });
    rig.settle().await;
    rig.tx.send(TransportEvent::Closed("bye".into())).unwrap();
    assert_eq!(pending.await.unwrap().unwrap_err(), CdpError::Closed("bye".into()));
    assert_eq!(rig.page.closed().borrow().as_deref(), Some("bye"));
    assert!(rig.page.is_closed());
    let err = rig.page.send("Page.reload", json!({})).await.unwrap_err();
    assert!(err.is_closed());
    assert!(rig.page.main_frame().is_err());
}

#[tokio::test]
async fn dropped_event_channel_closes_the_page() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    let Rig { page, tx, .. } = rig;
    drop(tx);
    let mut closed = page.closed();
    tokio::time::timeout(Duration::from_secs(1), closed.wait_for(Option::is_some)).await.unwrap().unwrap();
    assert_eq!(page.closed().borrow().as_deref(), Some("Transport closed"));
}

#[tokio::test]
async fn inspector_detached_closes_the_page() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    rig.event(None, "Inspector.detached", json!({"reason": "Render process gone."}));
    rig.settle().await;
    assert_eq!(rig.page.closed().borrow().as_deref(), Some("Render process gone."));
}

#[tokio::test]
async fn goto_waits_for_the_new_document() {
    let rig = Rig::new(handler(|_, m, _| {
        (m == "Page.navigate").then(|| Reply::Ok(json!({"frameId": "MAIN", "loaderId": "L1"})))
    }))
    .await;
    let page = rig.page.clone();
    let task = tokio::spawn(async move { page.goto("https://a/", Duration::from_secs(5)).await });
    rig.settle().await;
    assert!(!task.is_finished());
    rig.event(None, "Page.lifecycleEvent", json!({"frameId": "MAIN", "loaderId": "L1", "name": "init"}));
    rig.event(
        None,
        "Page.frameNavigated",
        json!({"frame": {"id": "MAIN", "url": "https://a/", "loaderId": "L1"}}),
    );
    rig.settle().await;
    assert!(!task.is_finished());
    rig.event(
        None,
        "Page.lifecycleEvent",
        json!({"frameId": "MAIN", "loaderId": "L1", "name": "DOMContentLoaded"}),
    );
    task.await.unwrap().unwrap();
    let (_, p) = rig.mock.last("Page.navigate").unwrap();
    assert_eq!(p, json!({"url": "https://a/", "frameId": "MAIN"}));
}

#[tokio::test]
async fn goto_reports_error_text_and_accepts_http_errors() {
    let rig = Rig::new(handler(|_, m, p| {
        (m == "Page.navigate").then(|| {
            if p["url"] == "http://bad/" {
                Reply::Ok(json!({"frameId": "MAIN", "errorText": "net::ERR_CONNECTION_REFUSED"}))
            } else {
                Reply::Ok(json!({"frameId": "MAIN", "loaderId": "L2", "errorText": "net::ERR_HTTP_RESPONSE_CODE_FAILURE"}))
            }
        })
    }))
    .await;
    let err = rig.page.goto("http://bad/", Duration::from_secs(5)).await.unwrap_err();
    assert_eq!(err.to_string(), "net::ERR_CONNECTION_REFUSED at http://bad/");
    assert!(!err.is_timeout());
    rig.page.goto("http://404/", Duration::from_secs(5)).await.unwrap();
}

#[tokio::test]
async fn blank_from_page_navigates_by_script_and_waits_for_the_blank_document() {
    let rig = Rig::new(eval_handler()).await;
    rig.event(
        None,
        "Page.frameNavigated",
        json!({"frame": {"id": "MAIN", "url": "https://a/", "loaderId": "L1"}}),
    );
    rig.event(
        None,
        "Page.lifecycleEvent",
        json!({"frameId": "MAIN", "loaderId": "L1", "name": "DOMContentLoaded"}),
    );
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let page = rig.page.clone();
    let task = tokio::spawn(async move { page.blank_from_page(Duration::from_secs(5)).await });
    rig.settle().await;
    let (_, p) = rig.mock.last("Runtime.callFunctionOn").unwrap();
    assert!(p["functionDeclaration"].as_str().unwrap().contains("location.replace('about:blank')"), "{p}");
    assert!(!task.is_finished());
    rig.event(None, "Page.lifecycleEvent", json!({"frameId": "MAIN", "loaderId": "L2", "name": "init"}));
    rig.event(
        None,
        "Page.frameNavigated",
        json!({"frame": {"id": "MAIN", "url": "about:blank", "loaderId": "L2"}}),
    );
    rig.settle().await;
    assert!(!task.is_finished());
    rig.event(
        None,
        "Page.lifecycleEvent",
        json!({"frameId": "MAIN", "loaderId": "L2", "name": "DOMContentLoaded"}),
    );
    task.await.unwrap().unwrap();
    assert!(rig.mock.last("Page.navigate").is_none());
}

#[tokio::test]
async fn blank_from_page_fails_when_the_page_stays() {
    let rig = Rig::new(eval_handler()).await;
    rig.event(
        None,
        "Page.frameNavigated",
        json!({"frame": {"id": "MAIN", "url": "https://a/", "loaderId": "L1"}}),
    );
    rig.event(
        None,
        "Page.lifecycleEvent",
        json!({"frameId": "MAIN", "loaderId": "L1", "name": "DOMContentLoaded"}),
    );
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let err = rig.page.blank_from_page(Duration::from_millis(100)).await.unwrap_err();
    assert_eq!(err, CdpError::NavigationTimeout(100));
    assert_eq!(rig.page.url(), "https://a/");
}

#[tokio::test]
async fn goto_times_out() {
    let rig = Rig::new(handler(|_, m, _| {
        (m == "Page.navigate").then(|| Reply::Ok(json!({"frameId": "MAIN", "loaderId": "L1"})))
    }))
    .await;
    let err = rig.page.goto("https://slow/", Duration::from_millis(100)).await.unwrap_err();
    assert_eq!(err, CdpError::NavigationTimeout(100));
    assert_eq!(err.to_string(), "Navigation timeout of 100 ms exceeded");
    assert!(err.is_timeout());
}

#[tokio::test]
async fn goto_same_document() {
    let rig =
        Rig::new(handler(|_, m, _| (m == "Page.navigate").then(|| Reply::Ok(json!({"frameId": "MAIN"})))))
            .await;
    rig.event(
        None,
        "Page.lifecycleEvent",
        json!({"frameId": "MAIN", "loaderId": "L0", "name": "DOMContentLoaded"}),
    );
    rig.settle().await;
    let page = rig.page.clone();
    let task = tokio::spawn(async move { page.goto("about:blank#x", Duration::from_secs(5)).await });
    rig.settle().await;
    assert!(!task.is_finished());
    rig.event(None, "Page.navigatedWithinDocument", json!({"frameId": "MAIN", "url": "about:blank#x"}));
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn goto_waits_for_loading_children() {
    let rig = Rig::new(handler(|_, m, _| {
        (m == "Page.navigate").then(|| Reply::Ok(json!({"frameId": "MAIN", "loaderId": "L1"})))
    }))
    .await;
    let page = rig.page.clone();
    let task = tokio::spawn(async move { page.goto("https://a/", Duration::from_secs(5)).await });
    rig.settle().await;
    rig.event(None, "Page.lifecycleEvent", json!({"frameId": "MAIN", "loaderId": "L1", "name": "init"}));
    rig.event(None, "Page.frameAttached", json!({"frameId": "C1", "parentFrameId": "MAIN"}));
    rig.event(None, "Page.frameStartedLoading", json!({"frameId": "C1"}));
    rig.event(
        None,
        "Page.lifecycleEvent",
        json!({"frameId": "MAIN", "loaderId": "L1", "name": "DOMContentLoaded"}),
    );
    rig.settle().await;
    assert!(!task.is_finished());
    rig.event(
        None,
        "Page.lifecycleEvent",
        json!({"frameId": "C1", "loaderId": "X", "name": "DOMContentLoaded"}),
    );
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn mouse_click_sends_move_press_release() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    rig.page.mouse_click(10.0, 20.5).await.unwrap();
    let events: Vec<Value> =
        rig.mock.calls().into_iter().filter(|c| c.1 == "Input.dispatchMouseEvent").map(|c| c.2).collect();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["type"], "mouseMoved");
    assert_eq!(events[0]["x"], 10.0);
    assert_eq!(events[0]["y"], 20.5);
    assert_eq!(events[1]["type"], "mousePressed");
    assert_eq!(events[1]["button"], "left");
    assert_eq!(events[1]["clickCount"], 1);
    assert_eq!(events[2]["type"], "mouseReleased");
    assert_eq!(events[2]["button"], "left");
    // The mouse is released again, so a second click works.
    rig.page.mouse_click(1.0, 1.0).await.unwrap();
}

#[tokio::test]
async fn type_text_presses_layout_keys_and_inserts_the_rest() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    rig.page.type_text("a\u{e9}").await.unwrap();
    let calls: Vec<(String, Value)> =
        rig.mock.calls().into_iter().filter(|c| c.1.starts_with("Input.")).map(|c| (c.1, c.2)).collect();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].0, "Input.dispatchKeyEvent");
    assert_eq!(calls[0].1["type"], "keyDown");
    assert_eq!(calls[0].1["text"], "a");
    assert_eq!(calls[1].1["type"], "keyUp");
    assert_eq!(calls[2], ("Input.insertText".to_owned(), json!({"text": "\u{e9}"})));

    rig.page.key_press("Enter").await.unwrap();
    let (_, p) = rig.mock.last("Input.dispatchKeyEvent").unwrap();
    assert_eq!(p["type"], "keyUp");
    assert_eq!(p["key"], "Enter");
    assert!(rig.page.key_press("NotAKey").await.is_err());
}

// perf-ops-5: sending each character's down and up together types exactly what pressing each key in
// turn does, and a failure stops it after the failing character.
#[tokio::test]
async fn type_text_sends_what_pressing_in_turn_does_and_stops_after_a_failing_character() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let text = "Hi, World! p\u{e4}ss\nw\u{f6}rd 12345 ABC~ and more keys after them";
    let input = |rig: &Rig| -> Vec<(String, Value)> {
        rig.mock.calls().into_iter().filter(|c| c.1.starts_with("Input.")).map(|c| (c.1, c.2)).collect()
    };
    let together = Rig::new(handler(|_, _, _| None)).await;
    together.page.type_text(text).await.unwrap();
    let turn = Rig::new(handler(|_, _, _| None)).await;
    for c in text.chars() {
        let s = c.to_string();
        if char_is_key(c) {
            turn.page.key_press(&s).await.unwrap();
        } else {
            turn.page.send("Input.insertText", json!({ "text": s })).await.unwrap();
        }
    }
    assert_eq!(input(&together), input(&turn));

    // Commands 2 and 3 are b's down and up. Whichever fails, both were sent, c and d never are, and b is
    // released as Chrome has it: a b typed next is a fresh press, not an auto-repeat.
    for fail in [2, 3] {
        let sent = Arc::new(AtomicUsize::new(0));
        let n = Arc::clone(&sent);
        let rig = Rig::new(handler(move |_, m, _| {
            (m == "Input.dispatchKeyEvent" && n.fetch_add(1, Ordering::SeqCst) == fail)
                .then(|| Reply::Err(CdpError::Timeout { method: m.to_owned() }))
        }))
        .await;
        let e = rig.page.type_text("abcd").await.unwrap_err();
        assert_eq!(e, CdpError::Timeout { method: "Input.dispatchKeyEvent".into() });
        let keys: Vec<(String, String)> = input(&rig)
            .into_iter()
            .map(|(_, p)| (p["type"].as_str().unwrap().to_owned(), p["key"].as_str().unwrap().to_owned()))
            .collect();
        let want = [("keyDown", "a"), ("keyUp", "a"), ("keyDown", "b"), ("keyUp", "b")];
        assert_eq!(keys, want.map(|(t, k)| (t.to_owned(), k.to_owned())), "failed command {fail}");
        rig.page.key_down("b").await.unwrap();
        let (_, p) = rig.mock.last("Input.dispatchKeyEvent").unwrap();
        assert_eq!(p["autoRepeat"], false, "failed command {fail}");
    }
}

#[tokio::test]
async fn protocol_errors_during_evaluate_are_classified() {
    let rig = Rig::new(handler(|_, m, _| {
        (m == "Runtime.callFunctionOn").then(|| {
            Reply::Err(CdpError::protocol(
                "Runtime.callFunctionOn",
                &json!({"code": -32000, "message": "Cannot find context with specified id"}),
            ))
        })
    }))
    .await;
    rig.context(None, "MAIN", 1);
    rig.settle().await;
    let err = rig.page.evaluate(&FrameId::from("MAIN"), "() => 1", vec![]).await.unwrap_err();
    assert_eq!(err, CdpError::ContextDestroyed);
    assert!(err.is_navigating());
}

// F2 and F1: a frame's box read dropped mid-way (its snapshot failed, timed out or was aborted) still
// releases the <iframe> handles it held: the frame's own and, for a nested frame, its parent frame's.
// One that finishes releases each once. Frames MAIN > C1 > C2; frame Cn's <iframe> is `el-Cn`.
#[tokio::test]
async fn a_frame_box_read_dropped_midway_releases_its_iframe_handles() {
    for (frame, hang, want) in [
        ("C1", true, vec!["el-C1"]),
        ("C2", true, vec!["el-C1", "el-C2"]),
        ("C2", false, vec!["el-C1", "el-C2"]),
    ] {
        let rig = Rig::new(handler(move |_, m, p| match m {
            "DOM.getFrameOwner" => Some(Reply::Ok(json!({"backendNodeId": p["frameId"]}))),
            "DOM.resolveNode" => {
                let id = format!("el-{}", p["backendNodeId"].as_str().unwrap());
                Some(Reply::Ok(json!({"object": {"type": "object", "objectId": id}})))
            }
            // C1's <iframe> is read for C1's box and for C2's offset; `hang` holds that read.
            "Runtime.callFunctionOn" if hang && p["arguments"][0]["objectId"] == "el-C1" => Some(Reply::Hang),
            "Runtime.callFunctionOn" => Some(Reply::Ok(json!({"result": {"type": "object", "value": {
                "x": 1, "y": 2, "width": 30, "height": 40, "left": 5, "top": 6
            }}}))),
            _ => None,
        }))
        .await;
        rig.event(None, "Page.frameAttached", json!({"frameId": "C1", "parentFrameId": "MAIN"}));
        rig.event(None, "Page.frameAttached", json!({"frameId": "C2", "parentFrameId": "C1"}));
        rig.context(None, "MAIN", 1);
        rig.context(None, "C1", 2);
        rig.settle().await;
        // Dropped well inside the 300 ms protocol timeout, so no evaluate fails on its own.
        let read = tokio::time::timeout(
            Duration::from_millis(100),
            rig.page.frame_element_box(&FrameId::from(frame)),
        )
        .await;
        assert_eq!(read.is_err(), hang, "{frame}: {read:?}");
        rig.settle().await;
        let mut released: Vec<String> = rig
            .mock
            .calls()
            .into_iter()
            .filter(|c| c.1 == "Runtime.releaseObject")
            .map(|c| c.2["objectId"].as_str().unwrap().to_owned())
            .collect();
        released.sort();
        assert_eq!(released, want, "{frame}, hang {hang}");
    }
}

// perf-ops-5: a character's key up goes out before its key down is answered: one round trip a
// character, not two. Here a key down is answered only once its key up has arrived.
#[tokio::test]
async fn a_characters_key_up_is_sent_before_its_key_down_is_answered() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Paired {
        downs: AtomicUsize,
        ups: tokio::sync::watch::Sender<usize>,
    }
    #[async_trait]
    impl Transport for Paired {
        async fn send(
            &self,
            session: Option<&SessionId>,
            method: &str,
            params: Value,
        ) -> Result<Value, CdpError> {
            match (method, params["type"].as_str()) {
                ("Page.getFrameTree", _) if session.is_none() => Ok(main_tree()),
                ("Input.dispatchKeyEvent", Some("keyDown")) => {
                    let n = self.downs.fetch_add(1, Ordering::SeqCst) + 1;
                    let mut ups = self.ups.subscribe();
                    let _ = ups.wait_for(|u| *u >= n).await;
                    Ok(json!({}))
                }
                ("Input.dispatchKeyEvent", Some("keyUp")) => {
                    self.ups.send_modify(|u| *u += 1);
                    Ok(json!({}))
                }
                _ => Ok(json!({})),
            }
        }
    }
    let transport: Arc<dyn Transport> =
        Arc::new(Paired { downs: AtomicUsize::new(0), ups: tokio::sync::watch::Sender::new(0) });
    let (_tx, rx) = mpsc::unbounded_channel();
    let page = Page::attach(transport, None, rx, quick_options()).await.unwrap();
    let typed = tokio::time::timeout(Duration::from_secs(2), page.type_text("abc")).await;
    assert!(matches!(typed, Ok(Ok(()))), "{typed:?}");
}

#[tokio::test]
async fn handles_pass_by_reference_and_dispose() {
    let rig = Rig::new(handler(|_, m, _| match m {
        "Runtime.callFunctionOn" => {
            Some(Reply::Ok(json!({"result": {"type": "object", "objectId": "obj-1"}})))
        }
        _ => None,
    }))
    .await;
    rig.context(None, "MAIN", 2);
    rig.settle().await;
    let h = rig.page.evaluate_handle(&FrameId::from("MAIN"), "() => document", vec![]).await.unwrap();
    assert_eq!(h.object_id(), Some("obj-1"));
    assert_eq!(rig.mock.last("Runtime.callFunctionOn").unwrap().1["returnByValue"], false);
    h.evaluate("(d, x) => d.title + x", vec![json!("!").into()]).await.unwrap();
    let (_, p) = rig.mock.last("Runtime.callFunctionOn").unwrap();
    assert_eq!(p["arguments"], json!([{"objectId": "obj-1"}, {"value": "!"}]));
    h.dispose().await;
    assert_eq!(rig.mock.last("Runtime.releaseObject").unwrap().1, json!({"objectId": "obj-1"}));
    let err = rig.page.evaluate(&FrameId::from("MAIN"), "(d) => d", vec![(&h).into()]).await.unwrap_err();
    assert_eq!(err.to_string(), "JSHandle is disposed!");

    // A handle from another context cannot be passed.
    let h2 = rig.page.evaluate_handle(&FrameId::from("MAIN"), "() => 1", vec![]).await.unwrap();
    rig.context(None, "MAIN", 3);
    rig.settle().await;
    let err = rig.page.evaluate(&FrameId::from("MAIN"), "(d) => d", vec![(&h2).into()]).await.unwrap_err();
    assert_eq!(err.to_string(), "JSHandles can be evaluated only in the context they were created!");
}

#[tokio::test]
async fn close_uses_close_target_for_browser_pages() {
    let mut opts = quick_options();
    opts.target_id = Some("T1".into());
    let rig = Rig::with_options(handler(|_, _, _| None), opts).await;
    rig.page.close().await.unwrap();
    assert!(rig.page.is_closed());
    let (s, p) = rig.mock.last("Target.closeTarget").unwrap();
    assert_eq!(s, None);
    assert_eq!(p, json!({"targetId": "T1"}));
}

#[tokio::test]
async fn dialogs_are_recorded_with_their_answer_and_taken_once() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    rig.event(None, "Page.javascriptDialogOpening", json!({"type": "confirm", "message": "Sure?"}));
    rig.settle().await;
    let open = rig.page.take_dialogs();
    assert_eq!(open, vec![Dialog { kind: "confirm".into(), message: "Sure?".into(), accepted: None }]);
    assert!(
        rig.mock.last("Page.handleJavaScriptDialog").is_none(),
        "a shared page leaves answering to the extension"
    );
    rig.event(None, "Page.javascriptDialogClosed", json!({"result": false}));
    rig.settle().await;
    assert_eq!(rig.page.take_dialogs()[0].accepted, Some(false), "the open one stayed for its answer");
    assert_eq!(rig.page.take_dialogs(), Vec::new());
}

#[tokio::test]
async fn dialog_memory_is_bounded_and_messages_are_cut() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    for i in 0..(DIALOG_MEMORY + 3) {
        rig.event(
            None,
            "Page.javascriptDialogOpening",
            json!({"type": "alert", "message": format!("{i}{}", "x".repeat(900))}),
        );
        rig.event(None, "Page.javascriptDialogClosed", json!({"result": true}));
    }
    rig.settle().await;
    let got = rig.page.take_dialogs();
    assert_eq!(got.len(), DIALOG_MEMORY);
    assert!(got[0].message.starts_with('3'), "the oldest went first");
    assert!(
        got.iter().all(|d| d.message.chars().count() == DIALOG_MESSAGE_LIMIT && d.accepted == Some(true))
    );
}

#[tokio::test]
async fn answer_dialogs_accepts_leave_and_alert_and_dismisses_questions() {
    let opts = PageOptions { answer_dialogs: true, ..quick_options() };
    let rig = Rig::with_options(handler(|_, _, _| None), opts).await;
    for (kind, accept) in [("beforeunload", true), ("alert", true), ("confirm", false), ("prompt", false)] {
        rig.event(None, "Page.javascriptDialogOpening", json!({"type": kind, "message": ""}));
        let mock = rig.mock.clone();
        let before = mock.calls().len();
        wait_for(|| mock.calls().len() > before).await;
        let (session, params) = rig.mock.last("Page.handleJavaScriptDialog").unwrap();
        assert!(session.is_none(), "{kind}: answered on the page's own session");
        assert_eq!(params, json!({"accept": accept}), "{kind}");
    }
}

/// The isolated world the last `Runtime.callFunctionOn` ran in, by the number its unique id is for.
fn last_call_context(rig: &Rig) -> i64 {
    let p = rig.mock.last("Runtime.callFunctionOn").unwrap().1;
    assert!(p.get("executionContextId").is_none(), "by the unique id alone: {p}");
    let unique = p["uniqueContextId"].as_str().unwrap();
    unique.strip_prefix("world-").unwrap().parse().unwrap()
}

#[tokio::test]
async fn a_world_whose_answer_comes_before_its_event_waits_for_the_event() {
    let rig = Rig::new(eval_handler()).await;
    let held = rig.mock.events.lock().take();
    assert!(held.is_some());
    let main = FrameId::from("MAIN");
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let drive = async {
        wait_for(|| rig.mock.count("Page.createIsolatedWorld") == 1).await;
        rig.settle().await;
        assert_eq!(rig.mock.count("Runtime.callFunctionOn"), 0, "not called on a bare number");
        // The document changed before the world's event came: that world was the old document's.
        rig.context(None, "MAIN", 8);
        rig.event(None, "Runtime.executionContextCreated", world_event("MAIN", FIRST_WORLD));
        wait_for(|| rig.mock.count("Page.createIsolatedWorld") == 2).await;
        rig.settle().await;
        assert_eq!(rig.mock.count("Runtime.callFunctionOn"), 0);
        rig.event(None, "Runtime.executionContextCreated", world_event("MAIN", FIRST_WORLD + 1));
    };
    let (r, ()) = tokio::join!(rig.page.evaluate(&main, "() => 1", vec![]), drive);
    r.unwrap();
    assert_eq!(rig.mock.count("Runtime.callFunctionOn"), 1);
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 1, "the new document's world, by its unique id");
}

#[tokio::test]
async fn a_world_reported_for_another_frame_is_not_kept() {
    let rig = Rig::new(eval_handler()).await;
    let held = rig.mock.events.lock().take();
    assert!(held.is_some());
    let main = FrameId::from("MAIN");
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let drive = async {
        wait_for(|| rig.mock.count("Page.createIsolatedWorld") == 1).await;
        rig.event(None, "Runtime.executionContextCreated", world_event("ELSEWHERE", FIRST_WORLD));
        wait_for(|| rig.mock.count("Page.createIsolatedWorld") == 2).await;
        rig.event(None, "Runtime.executionContextCreated", world_event("MAIN", FIRST_WORLD + 1));
    };
    let (r, ()) = tokio::join!(rig.page.evaluate(&main, "() => 1", vec![]), drive);
    r.unwrap();
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 1);
}

#[tokio::test]
async fn a_world_destroyed_before_its_answer_is_applied_is_made_again() {
    let worlds = std::sync::atomic::AtomicI64::new(FIRST_WORLD);
    let rig = Rig::new(handler(move |_, m, _| match m {
        "Page.createIsolatedWorld" => {
            let id = worlds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(Reply::Later(Duration::from_millis(50), json!({"executionContextId": id})))
        }
        "Runtime.callFunctionOn" => Some(Reply::Ok(json!({"result": {"type": "number", "value": 1}}))),
        _ => None,
    }))
    .await;
    let held = rig.mock.events.lock().take();
    assert!(held.is_some());
    let main = FrameId::from("MAIN");
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let drive = async {
        wait_for(|| rig.mock.count("Page.createIsolatedWorld") == 1).await;
        rig.event(None, "Runtime.executionContextCreated", world_event("MAIN", FIRST_WORLD));
        rig.event(None, "Runtime.executionContextDestroyed", json!({"executionContextId": FIRST_WORLD}));
        wait_for(|| rig.mock.count("Page.createIsolatedWorld") == 2).await;
        rig.event(None, "Runtime.executionContextCreated", world_event("MAIN", FIRST_WORLD + 1));
    };
    let (r, ()) = tokio::join!(rig.page.evaluate(&main, "() => 1", vec![]), drive);
    r.unwrap();
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 1);
}

#[tokio::test]
async fn the_isolated_world_is_made_once_per_document() {
    let rig = Rig::new(eval_handler()).await;
    let main = FrameId::from("MAIN");
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    for _ in 0..3 {
        rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap();
    }
    assert_eq!(rig.mock.count("Page.createIsolatedWorld"), 1, "kept for the document");
    assert_eq!(last_call_context(&rig), FIRST_WORLD);
    // Universal access would let page code in that world read other origins; it is never asked for.
    assert!(rig.mock.calls().iter().all(|c| c.2.get("grantUniveralAccess").is_none()));

    // A new main context is a new document.
    rig.context(None, "MAIN", 8);
    rig.settle().await;
    rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap();
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 1);

    // The world's own context going away.
    rig.event(None, "Runtime.executionContextDestroyed", json!({"executionContextId": FIRST_WORLD + 1}));
    rig.settle().await;
    rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap();
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 2);

    // A cross-document navigation, even before its new context is reported.
    rig.event(
        None,
        "Page.frameNavigated",
        json!({"frame": {"id": "MAIN", "loaderId": "L1", "url": "https://a/"}}),
    );
    rig.settle().await;
    rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap();
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 3);

    // A same-document one keeps it.
    rig.event(None, "Page.navigatedWithinDocument", json!({"frameId": "MAIN", "url": "https://a/#x"}));
    rig.settle().await;
    rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap();
    assert_eq!(rig.mock.count("Page.createIsolatedWorld"), 4);

    // Cleared contexts take the world with them; the next call waits for the new document's context.
    rig.event(None, "Runtime.executionContextsCleared", json!({}));
    rig.context(None, "MAIN", 9);
    rig.settle().await;
    rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap();
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 4);
}

fn slow_world_handler(delay: Duration) -> Handler {
    handler(move |_, m, _| match m {
        "Page.createIsolatedWorld" => Some(Reply::Later(delay, json!({"executionContextId": 55}))),
        "Runtime.callFunctionOn" => Some(Reply::Ok(json!({"result": {"type": "number", "value": 1}}))),
        _ => None,
    })
}

#[tokio::test]
async fn calls_at_once_share_one_new_world() {
    let rig = Rig::new(slow_world_handler(Duration::from_millis(40))).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let main = FrameId::from("MAIN");
    let calls = (0..4).map(|_| rig.page.evaluate(&main, "() => 1", vec![]));
    for r in join_all(calls).await {
        r.unwrap();
    }
    assert_eq!(rig.mock.count("Page.createIsolatedWorld"), 1);
    let ran = rig.mock.calls().into_iter().filter(|c| c.1 == "Runtime.callFunctionOn").collect::<Vec<_>>();
    assert_eq!(ran.len(), 4);
    assert!(ran.iter().all(|c| c.2["uniqueContextId"] == unique_of(55).as_str()));
}

#[tokio::test]
async fn a_world_answered_after_a_navigation_is_not_kept() {
    let rig = Rig::new(slow_world_handler(Duration::from_millis(60))).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let page = rig.page.clone();
    let task = tokio::spawn(async move { page.evaluate(&FrameId::from("MAIN"), "() => 1", vec![]).await });
    let mock = rig.mock.clone();
    wait_for(|| mock.count("Page.createIsolatedWorld") == 1).await;
    // The document changes while the request is out: its answer may name the old document's world.
    rig.context(None, "MAIN", 8);
    task.await.unwrap().unwrap();
    assert_eq!(rig.mock.count("Page.createIsolatedWorld"), 2, "made again for the new document");
}

#[tokio::test]
async fn a_lost_world_is_made_again_on_the_next_call() {
    let failed = Arc::new(AtomicBool::new(false));
    let once = failed.clone();
    let rig = Rig::new(handler(move |_, m, _| {
        (m == "Runtime.callFunctionOn").then(|| {
            if once.swap(true, Ordering::SeqCst) {
                Reply::Ok(json!({"result": {"type": "number", "value": 1}}))
            } else {
                Reply::Err(CdpError::protocol(
                    "Runtime.callFunctionOn",
                    &json!({"code": -32000, "message": "Cannot find context with specified id"}),
                ))
            }
        })
    }))
    .await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let main = FrameId::from("MAIN");
    assert_eq!(rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap_err(), CdpError::ContextDestroyed);
    rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap();
    assert_eq!(rig.mock.count("Page.createIsolatedWorld"), 2);
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 1);
}

#[tokio::test]
async fn a_world_gone_by_its_unique_id_is_navigating_and_made_again() {
    // V8 answers a call by a unique id it no longer knows with InvalidParams, not "Cannot find context"
    // (review R1): the engine's waits must retry it as a navigation, and the world must not stay cached.
    let failed = Arc::new(AtomicBool::new(false));
    let once = failed.clone();
    let rig = Rig::new(handler(move |_, m, _| {
        (m == "Runtime.callFunctionOn").then(|| {
            if once.swap(true, Ordering::SeqCst) {
                Reply::Ok(json!({"result": {"type": "number", "value": 1}}))
            } else {
                Reply::Err(CdpError::protocol(
                    "Runtime.callFunctionOn",
                    &json!({"code": -32602, "message": "uniqueContextId not found"}),
                ))
            }
        })
    }))
    .await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let main = FrameId::from("MAIN");
    let err = rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap_err();
    assert_eq!(err, CdpError::ContextDestroyed);
    assert!(err.is_navigating());
    rig.page.evaluate(&main, "() => 1", vec![]).await.unwrap();
    assert_eq!(rig.mock.count("Page.createIsolatedWorld"), 2, "the gone world was dropped");
    assert_eq!(last_call_context(&rig), FIRST_WORLD + 1);
}

#[tokio::test]
async fn a_refused_world_is_an_error_never_the_main_world() {
    let rig = Rig::new(handler(|_, m, _| {
        (m == "Page.createIsolatedWorld").then(|| {
            Reply::Err(CdpError::protocol(
                "Page.createIsolatedWorld",
                &json!({"code": -32000, "message": "no"}),
            ))
        })
    }))
    .await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let err = rig.page.evaluate(&FrameId::from("MAIN"), "() => 1", vec![]).await.unwrap_err();
    assert!(err.to_string().contains("no"), "{err}");
    assert!(rig.mock.last("Runtime.callFunctionOn").is_none());
}

#[tokio::test]
async fn evaluate_main_runs_in_the_page_world() {
    let rig = Rig::new(eval_handler()).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    rig.page.evaluate_main(&FrameId::from("MAIN"), "() => window.x", vec![]).await.unwrap();
    // A context reported without a unique id is called by its number.
    assert_eq!(rig.mock.last("Runtime.callFunctionOn").unwrap().1["executionContextId"], 7);
    assert_eq!(rig.mock.count("Page.createIsolatedWorld"), 0);
    // With one, by that alone: Chrome takes one or the other.
    let main = json!({"context": {"id": 8, "uniqueId": "main-8", "auxData": {"frameId": "MAIN", "isDefault": true}}});
    rig.event(None, "Runtime.executionContextCreated", main);
    rig.settle().await;
    rig.page.evaluate_main(&FrameId::from("MAIN"), "() => window.x", vec![]).await.unwrap();
    let p = rig.mock.last("Runtime.callFunctionOn").unwrap().1;
    assert_eq!(p["uniqueContextId"], "main-8");
    assert!(p.get("executionContextId").is_none(), "{p}");
}

/// Answers the page functions in dom.rs by what they contain. `hit` is what the hit test reports
/// (`null` for "the element is on top").
fn dom_handler(hit: Value) -> Handler {
    dom_handler_with(hit, json!({"editable": false, "text": ""}))
}

/// As [`dom_handler`], with `now` as the field's current text.
fn dom_handler_with(hit: Value, now: Value) -> Handler {
    handler(move |_, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        let by_value = |v: Value| Some(Reply::Ok(json!({"result": {"type": "object", "value": v}})));
        match m {
            // `JS_QUERY` only: the hit test's box rule calls `querySelectorAll` too.
            "Runtime.callFunctionOn" if f.contains("querySelector.call") => {
                let node = json!({"type": "object", "subtype": "node", "objectId": "el-world"});
                Some(Reply::Ok(json!({ "result": node })))
            }
            "Runtime.callFunctionOn" if f.contains("isConnected") => by_value(Value::Null),
            "Runtime.callFunctionOn" if f.contains("[scrollX, scrollY]") => by_value(json!([0, 0])),
            "Runtime.callFunctionOn" if f.contains("IntersectionObserver") => by_value(json!(true)),
            "Runtime.callFunctionOn" if f.contains("getClientRects.call(element)]") => {
                by_value(json!([{"x": 10, "y": 20, "width": 30, "height": 40}]))
            }
            "Runtime.callFunctionOn" if f.contains("documentWidth") => {
                by_value(json!({"documentWidth": 800, "documentHeight": 600}))
            }
            "Runtime.callFunctionOn" if f.contains("elementFromPoint") => by_value(hit.clone()),
            "Runtime.callFunctionOn" if f.contains("'typeable-input'") => by_value(json!("typeable-input")),
            "Runtime.callFunctionOn" if f.contains("'isContentEditable'") => by_value(now.clone()),
            // The node on top is the element's own.
            "Runtime.callFunctionOn" if f.contains("(found, target, own)") => by_value(Value::Null),
            "DOM.describeNode" => Some(Reply::Ok(json!({"node": {"backendNodeId": 31}}))),
            // The node at the click point is in the main frame and no frame element.
            "DOM.getNodeForLocation" => Some(Reply::Ok(json!({"backendNodeId": 31, "frameId": "MAIN"}))),
            "DOM.resolveNode" => {
                let node = json!({"type": "object", "subtype": "node", "objectId": "el-main"});
                Some(Reply::Ok(json!({ "object": node })))
            }
            _ => None,
        }
    })
}

fn calls_of(rig: &Rig, needle: &str) -> Vec<Value> {
    rig.mock
        .calls()
        .into_iter()
        .filter(|c| c.2["functionDeclaration"].as_str().is_some_and(|f| f.contains(needle)))
        .map(|c| c.2)
        .collect()
}

#[tokio::test]
async fn a_selector_click_checks_what_is_on_top_first() {
    let rig = Rig::new(dom_handler(Value::Null)).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    rig.page.click_selector("#go").await.unwrap();
    let hit = &calls_of(&rig, "elementFromPoint")[0];
    assert_eq!(hit["uniqueContextId"], unique_of(FIRST_WORLD), "in the isolated world");
    assert_eq!(
        hit["arguments"],
        json!([{"objectId": "el-world"}, {"value": 25.0}, {"value": 40.0}, {"value": false}]),
        "not strict: the node at the point answered for frames"
    );
    // Asked twice at the one point, `pointer-events: none` ignored and honoured.
    let asked: Vec<Value> = rig
        .mock
        .calls()
        .into_iter()
        .filter(|c| c.1 == "DOM.getNodeForLocation")
        .map(|c| c.2)
        .take(2)
        .collect();
    let at = |ignore: bool| json!({"x": 25, "y": 40, "includeUserAgentShadowDOM": false, "ignorePointerEventsNone": ignore});
    assert_eq!(asked, [at(true), at(false)]);
    assert!(rig.mock.count("Input.dispatchMouseEvent") > 0, "the click went out");
}

#[tokio::test]
async fn the_point_pressed_is_the_point_checked() {
    // The box's centre is (25.3, 40.25), between pixels: the check and the press both use (25, 40).
    let inner = dom_handler(Value::Null);
    let h: Handler = Box::new(move |s, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        match m {
            "Runtime.callFunctionOn" if f.contains("getClientRects.call(element)]") => {
                by_value(&json!([{"x": 10.3, "y": 20, "width": 30, "height": 40.5}]))
            }
            _ => inner(s, m, p),
        }
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    rig.page.click_selector("#go").await.unwrap();
    for hit in calls_of(&rig, "elementFromPoint") {
        let args = &hit["arguments"];
        assert_eq!((args[1].clone(), args[2].clone()), (json!({"value": 25.0}), json!({"value": 40.0})));
        assert_eq!(args[3], json!({"value": false}), "whole, so not strict");
    }
    let asked: Vec<(Value, Value)> = rig
        .mock
        .calls()
        .into_iter()
        .filter(|c| c.1 == "DOM.getNodeForLocation")
        .map(|c| (c.2["x"].clone(), c.2["y"].clone()))
        .collect();
    assert_eq!(asked.len(), 4, "twice in each check");
    assert!(asked.iter().all(|a| *a == (json!(25), json!(40))), "{asked:?}");
    let pressed: Vec<(String, Value, Value)> = rig
        .mock
        .calls()
        .into_iter()
        .filter(|c| c.1 == "Input.dispatchMouseEvent")
        .map(|c| (c.2["type"].as_str().unwrap().to_owned(), c.2["x"].clone(), c.2["y"].clone()))
        .collect();
    assert_eq!(pressed.len(), 3);
    assert!(pressed.iter().all(|(_, x, y)| (x, y) == (&json!(25.0), &json!(40.0))), "{pressed:?}");
}

/// Why each check on `page` fell back to the box rule, a reason for each, in [`Unsettled::ALL`]'s order.
fn fallbacks(page: &Page) -> Vec<Unsettled> {
    Unsettled::ALL.into_iter().flat_map(|why| std::iter::repeat_n(why, page.strict_fallbacks(why))).collect()
}

/// Whether each hit test was strict.
fn strictness(rig: &Rig) -> Vec<bool> {
    calls_of(rig, "elementFromPoint").into_iter().map(|c| c["arguments"][3]["value"] == true).collect()
}

/// Clicks `#go` with [`dom_handler`] answering, `DOM.getNodeForLocation` by `node_at` (`ignore`d
/// `pointer-events: none` or not) and the scroll read by `scroll`; whether each hit test was strict,
/// and why each check fell back.
async fn strict_when(node_at: fn(bool) -> Reply, scroll: Value) -> (Vec<bool>, Vec<Unsettled>) {
    let inner = dom_handler(Value::Null);
    let h: Handler = Box::new(move |s, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        match m {
            "DOM.getNodeForLocation" => node_at(p["ignorePointerEventsNone"] == true),
            "Runtime.callFunctionOn" if f.contains("[scrollX, scrollY]") => by_value(&scroll),
            _ => inner(s, m, p),
        }
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    rig.page.click_selector("#go").await.unwrap();
    assert!(rig.mock.count("Input.dispatchMouseEvent") > 0, "with no frame at the point, it clicks");
    (strictness(&rig), fallbacks(&rig.page))
}

#[tokio::test]
async fn what_the_two_answers_cannot_settle_the_box_rule_does() {
    fn node(id: i64) -> Reply {
        Reply::Ok(json!({"backendNodeId": id, "frameId": "MAIN"}))
    }
    let fell_back = |why| (vec![false, true, false, true], vec![why, why]);
    // Agreeing, at a whole point: the plain test alone, in each check.
    assert_eq!(strict_when(|_| node(31), json!([0, 0])).await, (vec![false, false], vec![]));
    // Something that takes no pointer events lies over the point (a decoy over a frame, or an icon):
    // in each check, the plain test and then the box rule.
    let decoy = |ignore: bool| node(if ignore { 40 } else { 31 });
    assert_eq!(strict_when(decoy, json!([0, 0])).await, fell_back(Unsettled::Decoy));
    // The same node in another frame is another answer.
    let elsewhere = |ignore: bool| {
        Reply::Ok(json!({"backendNodeId": 31, "frameId": if ignore { "MAIN" } else { "OTHER" }}))
    };
    assert_eq!(strict_when(elsewhere, json!([0, 0])).await, fell_back(Unsettled::Decoy));
    // Only one of the two answers.
    let one = |ignore: bool| if ignore { node(31) } else { Reply::Err(CdpError::Other("gone".into())) };
    assert_eq!(strict_when(one, json!([0, 0])).await, fell_back(Unsettled::Failed));
    // A scroll that does not read as two numbers is not taken for 0.
    for scroll in [Value::Null, json!(["0", 0]), json!([0]), json!({"x": 0, "y": 0})] {
        assert_eq!(strict_when(|_| node(31), scroll.clone()).await, fell_back(Unsettled::Failed), "{scroll}");
    }
    // A point between pixels in the document (a fractional scroll) cannot be asked about.
    assert_eq!(strict_when(|_| node(31), json!([0, 0.5])).await, fell_back(Unsettled::BetweenPixels));
}

#[tokio::test]
async fn a_page_that_scrolls_during_the_check_fails_closed() {
    // The scroll is read beside the hit test and again beside what the node is: here the page scrolled
    // between the two, so the command was asked about another point, and the box rule answers.
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let inner = dom_handler(Value::Null);
    let counted = reads.clone();
    let h: Handler = Box::new(move |s, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        match m {
            "DOM.getNodeForLocation" => Reply::Ok(json!({"backendNodeId": 31, "frameId": "MAIN"})),
            "Runtime.callFunctionOn" if f.contains("[scrollX, scrollY]") => {
                let n = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                by_value(&if n.is_multiple_of(2) { json!([0, 0]) } else { json!([0, 4]) })
            }
            _ => inner(s, m, p),
        }
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    rig.page.click_selector("#go").await.unwrap();
    assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 4, "twice in each check");
    assert_eq!(strictness(&rig), [false, true, false, true]);
    assert_eq!(fallbacks(&rig.page), [Unsettled::Failed, Unsettled::Failed]);
}

#[tokio::test]
async fn what_is_on_top_must_be_the_targets_own() {
    // Both answers agree on a node that is no frame. The page's hit test found the target just before,
    // yet the node is not the target's (a timer slid an overlay in since): refused, nothing pressed.
    let (rig, r) =
        press_with(|_, f, _| f.contains("(found, target, own)").then(|| by_value(&json!("div#overlay"))))
            .await;
    match r {
        Err(ClickError::NotPressed(CdpError::Covered(e))) => assert!(e.contains("by <div#overlay>"), "{e}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(mouse_events(&rig), Vec::<String>::new());
    let own = &calls_of(&rig, "(found, target, own)")[0];
    assert_eq!(own["uniqueContextId"], unique_of(FIRST_WORLD), "in the isolated world");
    assert_eq!(own["arguments"], json!([{"objectId": "el-main"}, {"objectId": "el-world"}, {"value": true}]));
    assert_eq!(rig.mock.last("DOM.resolveNode").unwrap().1["backendNodeId"], 31);
    assert_eq!(fallbacks(&rig.page), []);

    // A `::after` both answers put on top has no element to check: the box rule answers.
    let (rig, r) = press_with(|m, _, _| {
        (m == "DOM.describeNode").then(|| {
            Reply::Ok(json!({"node": {"backendNodeId": 31, "localName": "", "pseudoType": "after"}}))
        })
    })
    .await;
    assert_eq!(r, Ok(()), "with no frame at the point, it clicks");
    assert_eq!(strictness(&rig), [false, true, false, true]);
    assert_eq!(fallbacks(&rig.page), [Unsettled::Pseudo, Unsettled::Pseudo]);
}

/// Presses `#b` in an out-of-process frame (session `S1`), its `<iframe>` placed as `offset` says
/// (`JS_FRAME_OFFSET`'s answer) and `model` answering `DOM.getBoxModel` (`None`: refused). The rig,
/// whether each hit test was strict, and why each check fell back.
async fn in_a_frame(offset: Value, model: Option<Value>) -> (Rig, Vec<bool>, Vec<Unsettled>) {
    let (rig, r) = press_in_a_frame(offset, model).await;
    r.unwrap();
    let (strict, why) = (strictness(&rig), fallbacks(&rig.page));
    (rig, strict, why)
}

/// What only `JS_PLACE`, the frame query's second read of where a frame element is, says.
const PLACE: &str = "return [rect.left, rect.top, rect.left + left, rect.top + top]";

/// [`in_a_frame`]'s press, and how it ended. The one element above the `<iframe>` that could host a
/// closed shadow root (`offset`'s `hosts`, when 1) has one when `offset` says `closed`, and the
/// `<iframe>` has moved when the frame query reads it again when `offset` says `slides`, or only its
/// content box (a padding or border changed) when it says `pads` (keys only this rig reads).
async fn press_in_a_frame(offset: Value, model: Option<Value>) -> (Rig, Result<(), ClickError>) {
    let inner = dom_handler(Value::Null);
    let h: Handler = Box::new(move |s, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        match (s.map(SessionId::as_str), m) {
            (Some("S1"), "Page.getFrameTree") => Reply::Ok(
                json!({"frameTree": {"frame": {"id": "OOP", "parentId": "MAIN", "url": "http://localhost/c"}}}),
            ),
            (Some("S1"), "DOM.getNodeForLocation") => {
                Reply::Ok(json!({"backendNodeId": 31, "frameId": "OOP"}))
            }
            (None, "DOM.getFrameOwner") => Reply::Ok(json!({"backendNodeId": 77})),
            (None, "DOM.resolveNode") if p["backendNodeId"] == 77 => {
                Reply::Ok(json!({"object": {"type": "object", "subtype": "node", "objectId": "frame-owner"}}))
            }
            (None, "DOM.getBoxModel") => match &model {
                Some(model) => Reply::Ok(model.clone()),
                None => Reply::Err(CdpError::Other("CDP method not allowed".into())),
            },
            // Where the <iframe>'s border box and content box are, read again in the frame query: both
            // moved by 4 px when `offset` says `slides`, as a scroll above it would; the content box
            // alone by 3 px when it says `pads`, as a padding a timer changed would.
            (None, "Runtime.callFunctionOn") if f.contains(PLACE) => {
                let n = |key: &str| offset[key].as_f64().unwrap_or_default();
                let dy = if offset["slides"] == true { 4.0 } else { 0.0 };
                let dx = if offset["pads"] == true { 3.0 } else { 0.0 };
                by_value(&json!([n("x"), n("y") + dy, n("left") + dx, n("top") + dy]))
            }
            (_, "Runtime.callFunctionOn") if f.contains("'padding-left'") => {
                if p["returnByValue"] == true {
                    by_value(&offset)
                } else {
                    Reply::Ok(json!({"result": {"type": "object", "subtype": "array", "objectId": "hosts"}}))
                }
            }
            (None, "Runtime.callFunctionOn")
                if p["arguments"][0]["objectId"] == "hosts" && f.contains("a.length") =>
            {
                by_value(&json!(1))
            }
            (None, "Runtime.callFunctionOn")
                if p["arguments"][0]["objectId"] == "hosts" && f.contains("a[i]") =>
            {
                Reply::Ok(json!({"result": {"type": "object", "subtype": "node", "objectId": "host-0"}}))
            }
            (None, "DOM.describeNode") if p["objectId"] == "host-0" => {
                let roots =
                    if offset["closed"] == true { json!([{"shadowRootType": "closed"}]) } else { json!([]) };
                Reply::Ok(json!({"node": {"backendNodeId": 90, "localName": "div", "shadowRoots": roots}}))
            }
            _ => inner(s, m, p),
        }
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.event(
        None,
        "Target.attachedToTarget",
        json!({"sessionId": "S1", "targetInfo": {"type": "iframe", "targetId": "OOP"}}),
    );
    rig.context(Some("S1"), "OOP", 21);
    let mock = rig.mock.clone();
    wait_for(|| mock.methods_on(Some("S1")).len() == 6).await;
    rig.settle().await;
    let js = "(s) => Document.prototype.querySelector.call(document, s)";
    let el =
        rig.page.evaluate_handle(&FrameId::from("OOP"), js, vec![Arg::Value(json!("#b"))]).await.unwrap();
    let r = rig.page.press_element(&el).await;
    (rig, r)
}

/// `JS_FRAME_OFFSET`'s answer for the <iframe> at (30, 40), 200 x 100 inside, its content box `left`
/// past its border box's corner, and nothing on its way.
fn offset(left: f64) -> Value {
    json!({"left": left, "top": 40, "x": 30, "y": 40, "width": 200, "height": 100, "transformed": false, "why": "", "hosts": 0})
}

fn quad(l: f64, t: f64, r: f64, b: f64) -> Value {
    json!([l, t, r, t, r, b, l, b])
}

/// `DOM.getBoxModel`'s answer for that <iframe>, its content quad `content`.
fn model(content: &Value) -> Value {
    json!({"model": {"content": content, "border": quad(30.0, 40.0, 231.0, 140.0)}})
}

/// [`model`], its content box upright and its style's size, at `left`.
fn upright(left: f64) -> Value {
    model(&quad(left, 40.0, left + 200.0, 140.0))
}

fn pressed(rig: &Rig) {
    assert!(mouse_events(rig).contains(&"mousePressed".to_owned()));
}

/// The click was refused as in a frame the page turns, before the pointer moved.
fn refused(rig: &Rig, r: Result<(), ClickError>, what: &str) {
    refused_as(rig, r, what, "scales, rotates or zooms");
}

/// The click was refused, its error saying `words`, before the pointer moved.
fn refused_as(rig: &Rig, r: Result<(), ClickError>, what: &str, words: &str) {
    match r {
        Err(ClickError::NotPressed(CdpError::Covered(e))) => {
            assert!(e.contains(words) && !e.contains("timed out"), "{what}: {e}");
        }
        other => panic!("{what}: {other:?}"),
    }
    assert_eq!(mouse_events(rig), Vec::<String>::new(), "{what}: nothing moved or pressed");
}

#[tokio::test]
async fn a_frame_is_placed_by_its_box_model_and_a_doubt_about_it_goes_to_the_box_rule() {
    // A whole offset: the node at the point settles it, asked at the frame's own pixel, and then, in
    // the process above, at the page's.
    let (rig, strict, why) = in_a_frame(offset(31.0), Some(upright(31.0))).await;
    assert_eq!((strict, why), (vec![false; 4], vec![]));
    let asked: Vec<(Option<String>, Value, Value)> = rig
        .mock
        .calls()
        .into_iter()
        .filter(|c| c.1 == "DOM.getNodeForLocation")
        .map(|c| (c.0.map(|s| s.as_str().to_owned()), c.2["x"].clone(), c.2["y"].clone()))
        .take(4)
        .collect();
    let s1 = (Some("S1".to_owned()), json!(25), json!(40));
    let top = (None, json!(56), json!(80));
    assert_eq!(asked, [s1.clone(), s1, top.clone(), top]);
    let model_of = rig.mock.last("DOM.getBoxModel").unwrap();
    assert_eq!((model_of.0, model_of.1), (None, json!({"objectId": "frame-owner"})), "the owner's session");
    pressed(&rig);

    // A `0.9px` padding, which layout has as 57/64 px: the point falls between pixels in the frame.
    let (rig, strict, why) = in_a_frame(offset(30.9), Some(upright(30.890_625))).await;
    assert_eq!(strict, [false, false, true, true, false, false, true, true]);
    assert_eq!(why, [Unsettled::BetweenPixels, Unsettled::BetweenPixels]);
    pressed(&rig);
    // Layout's fraction counts even where computed style would read whole.
    let (_, _, why) = in_a_frame(offset(31.0), Some(upright(30.890_625))).await;
    assert_eq!(why, [Unsettled::BetweenPixels, Unsettled::BetweenPixels]);

    // Drawn at half its size, which page zoom can do too: where the point falls in the frame is not
    // known exactly, and the box rule answers.
    let (_, strict, why) = in_a_frame(offset(31.0), Some(model(&quad(31.0, 40.0, 131.0, 90.0)))).await;
    assert_eq!(strict, [false, false, true, true, false, false, true, true]);
    assert_eq!(why, [Unsettled::Transformed, Unsettled::Transformed]);

    // A frame 10,000.25 px wide, which computed style reads to six digits (10000.2): one size, so the
    // node at the point settles it.
    let mut wide = offset(31.0);
    wide["width"] = json!(10_000.2);
    let (_, strict, why) = in_a_frame(wide.clone(), Some(model(&quad(31.0, 40.0, 10_031.25, 140.0)))).await;
    assert_eq!((strict, why), (vec![false; 4], vec![]));
    // Far out, where a `float32` quad no longer holds every layout unit: only rough.
    let far = model(&quad(300_031.0, 40.0, 300_231.0, 140.0));
    let (_, _, why) = in_a_frame(offset(31.0), Some(far)).await;
    assert_eq!(why, [Unsettled::Transformed, Unsettled::Transformed]);
}

#[tokio::test]
async fn a_frame_the_page_turns_is_refused_before_the_pointer_moves() {
    // Turned, or mirrored (`rotate(180deg)` keeps the size): no point in the frame is known.
    let turned = model(&json!([31, 40, 231, 41, 230, 141, 30, 140]));
    let mirrored = model(&json!([231, 140, 31, 140, 31, 40, 231, 40]));
    for (what, model) in [("turned", turned), ("mirrored", mirrored)] {
        let (rig, r) = press_in_a_frame(offset(31.0), Some(model)).await;
        refused(&rig, r, what);
    }
    // The same with only what may move it seen on the way (a `translate: 0px` on a closed shadow root's
    // host, a <details>): the quads are checked all the same, and the box rule, which cannot see a
    // mirror, never answers (review r9 M-1). So a box model refused (an extension older than the
    // service), or not quads, is refused too: a turn is not ruled out.
    let mut moved = offset(31.0);
    moved["transformed"] = json!("moved");
    moved["why"] = json!("translate");
    let mirrored_x = model(&json!([231, 40, 31, 40, 31, 140, 231, 140]));
    let half_turn = model(&json!([231, 140, 31, 140, 31, 40, 231, 40]));
    for (what, model) in [
        ("moved, mirrored", Some(mirrored_x)),
        ("moved, turned half round", Some(half_turn)),
        ("moved, no box model", None),
        ("no box model", None),
        ("not quads", Some(json!({"model": {"content": [1, 2]}}))),
    ] {
        let style = if what.starts_with("moved") { moved.clone() } else { offset(31.0) };
        let read = model.as_ref().is_some_and(|m| m.pointer("/model/border").is_some());
        let (rig, r) = press_in_a_frame(style, model).await;
        if read {
            refused(&rig, r, what);
        } else {
            // A box model that did not read is phantab's failure: the page is not blamed (review r10 N-2).
            refused_as(&rig, r, what, "phantab could not read where the element's frame is drawn");
        }
        assert_eq!(fallbacks(&rig.page), [], "{what}: the box rule never answered");
    }
    // What scales, rotates or zooms it, or any other word on it, or none: refused, and the reason said.
    let mut turned = offset(31.0);
    for (transformed, word) in [(json!("turned"), "scale"), (json!(true), ""), (Value::Null, "")] {
        turned["transformed"] = transformed.clone();
        turned["why"] = json!(word);
        let (rig, r) = press_in_a_frame(turned.clone(), Some(upright(31.0))).await;
        let what = format!("{transformed}");
        if let Err(ClickError::NotPressed(CdpError::Covered(e))) = &r {
            assert!(
                e.contains(&format!(
                    "({})",
                    if word.is_empty() { "the frame element or one above it" } else { word }
                )),
                "{e}"
            );
        }
        refused(&rig, r, &what);
    }
}

#[tokio::test]
async fn a_frame_something_may_move_or_slot_unseen_goes_to_the_box_rule() {
    // Something on the frame element or above it that may move it by a fraction (a `translate(0.5px)`)
    // the box model need not show: the box rule answers.
    let mut moved = offset(31.0);
    moved["transformed"] = json!("moved");
    moved["why"] = json!("translate");
    let (rig, strict, why) = in_a_frame(moved, Some(upright(31.0))).await;
    assert_eq!(strict, [false, false, true, true, false, false, true, true]);
    assert_eq!(why, [Unsettled::Transformed, Unsettled::Transformed]);
    pressed(&rig);

    // An element above the frame element hosts a shadow root the world cannot open: the frame is
    // slotted into it, through wrappers the world cannot read, and the box rule answers. With no shadow
    // root there, the node at the point settles it, the element asked about once in each check.
    let mut hosted = offset(31.0);
    hosted["hosts"] = json!(1);
    hosted["closed"] = json!(true);
    let (rig, strict, why) = in_a_frame(hosted.clone(), Some(upright(31.0))).await;
    assert_eq!(strict, [false, false, true, true, false, false, true, true]);
    assert_eq!(why, [Unsettled::Transformed, Unsettled::Transformed]);
    let asked = rig.mock.last("DOM.describeNode").unwrap().1;
    assert_eq!(asked, json!({"objectId": "host-0", "depth": 0}));
    pressed(&rig);
    hosted["closed"] = json!(false);
    let (rig, strict, why) = in_a_frame(hosted.clone(), Some(upright(31.0))).await;
    assert_eq!((strict, why), (vec![false; 4], vec![]));
    assert_eq!(
        rig.mock.calls().iter().filter(|c| c.1 == "DOM.describeNode" && c.2["objectId"] == "host-0").count(),
        2
    );
    // A document or scroller above the frame scrolled during the frame query: the <iframe> is not
    // where it was read, so the command was asked about another point, and the box rule answers
    // (review r9 S-1).
    // So when a timer changed its padding or border, its border box where it was: its content box,
    // and so the frame's document, is not (review r10 F-1).
    for key in ["slides", "pads"] {
        let mut moved = offset(31.0);
        moved[key] = json!(true);
        let (rig, strict, why) = in_a_frame(moved, Some(upright(31.0))).await;
        assert_eq!(strict, [false, false, true, true, false, false, true, true], "{key}");
        assert_eq!(why, [Unsettled::Failed, Unsettled::Failed], "{key}");
        assert_eq!(calls_of(&rig, PLACE)[0]["arguments"][0]["objectId"], "frame-owner", "{key}");
        pressed(&rig);
    }
    // Too many to ask about, or no count: in doubt.
    for hosts in [json!(201), Value::Null] {
        hosted["hosts"] = hosts.clone();
        let (_, _, why) = in_a_frame(hosted.clone(), Some(upright(31.0))).await;
        assert_eq!(why.len(), 2, "{hosts}");
        assert!(
            why.iter().all(|w| matches!(w, Unsettled::Transformed | Unsettled::Failed)),
            "{hosts}: {why:?}"
        );
    }
}

#[tokio::test]
async fn a_frame_on_top_at_the_point_is_not_clicked() {
    // What layout has on top, `pointer-events: none` ignored, is another frame element: refused, even
    // though the page's own hit test sees through it to the target.
    let inner = dom_handler(Value::Null);
    let h: Handler = Box::new(move |s, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        match m {
            "DOM.getNodeForLocation" => Reply::Ok(json!({"backendNodeId": 55, "frameId": "MAIN"})),
            "DOM.describeNode" if p["backendNodeId"] == 55 => {
                Reply::Ok(json!({"node": {"backendNodeId": 55, "localName": "iframe"}}))
            }
            "DOM.resolveNode" if p["backendNodeId"] == 55 => {
                Reply::Ok(json!({"object": {"type": "object", "subtype": "node", "objectId": "on-top"}}))
            }
            "Runtime.callFunctionOn" if f.contains("scrollX") => by_value(&json!([0, 100])),
            "Runtime.callFunctionOn" if f.contains("(found, target, own)") => by_value(&json!("iframe#ad")),
            _ => inner(s, m, p),
        }
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let err = rig.page.click_selector("#go").await.unwrap_err();
    assert!(matches!(err, CdpError::Covered(_)), "{err:?}");
    assert!(err.to_string().starts_with("Element is covered at its click point by <iframe#ad>, so"), "{err}");
    assert_eq!(rig.mock.count("Input.dispatchMouseEvent"), 0);
    // In document coordinates: the scroll is added.
    let at = rig.mock.last("DOM.getNodeForLocation").unwrap().1;
    assert_eq!((at["x"].clone(), at["y"].clone()), (json!(25), json!(140)));
    let on_top = &calls_of(&rig, "(found, target, own)")[0];
    assert_eq!(on_top["uniqueContextId"], unique_of(FIRST_WORLD));
    assert_eq!(
        on_top["arguments"],
        json!([{"objectId": "on-top"}, {"objectId": "el-world"}, {"value": false}])
    );
    // Let go without waiting for the answer: the release goes out from a task of its own.
    rig.settle().await;
    let released: Vec<Value> = rig
        .mock
        .calls()
        .into_iter()
        .filter(|c| c.1 == "Runtime.releaseObject")
        .map(|c| c.2["objectId"].clone())
        .collect();
    assert!(released.contains(&json!("on-top")), "{released:?}");
}

#[tokio::test]
async fn a_node_inside_a_child_frame_is_that_frame_on_top() {
    // A same-process frame over the target: the node is in the child's document, so the child's
    // <iframe> element is what is on top.
    let inner = dom_handler(Value::Null);
    let h: Handler = Box::new(move |s, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        match m {
            "DOM.getNodeForLocation" => Reply::Ok(json!({"backendNodeId": 90, "frameId": "CHILD"})),
            "DOM.getFrameOwner" => Reply::Ok(json!({"backendNodeId": 77})),
            "DOM.resolveNode" if p["backendNodeId"] == 77 => {
                Reply::Ok(json!({"object": {"type": "object", "subtype": "node", "objectId": "frame-owner"}}))
            }
            "Runtime.callFunctionOn" if f.contains("(found, target, own)") => by_value(&json!("iframe")),
            _ => inner(s, m, p),
        }
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.event(None, "Page.frameAttached", json!({"frameId": "CHILD", "parentFrameId": "MAIN"}));
    rig.settle().await;
    let err = rig.page.click_selector("#go").await.unwrap_err();
    assert!(err.to_string().contains("by <iframe>"), "{err}");
    let on_top = &calls_of(&rig, "(found, target, own)")[0];
    assert_eq!(
        on_top["arguments"],
        json!([{"objectId": "frame-owner"}, {"objectId": "el-world"}, {"value": false}])
    );
    assert_eq!(rig.mock.count("Input.dispatchMouseEvent"), 0);
}

#[tokio::test]
async fn a_covered_target_is_not_clicked() {
    let rig = Rig::new(dom_handler(json!("div#cookie-banner"))).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let err = rig.page.click_selector("#go").await.unwrap_err();
    assert!(matches!(err, CdpError::Covered(_)), "the covered error, not a timeout: {err:?}");
    assert_eq!(
        err.to_string(),
        "Element is covered at its click point by <div#cookie-banner>, so the click was not sent. Close \
         what covers it (a dialog or banner) or scroll it into view, and try again, or use click_xy to \
         click that point on purpose."
    );
    assert!(!err.is_timeout() && !err.is_navigating());
    assert_eq!(rig.mock.count("Input.dispatchMouseEvent"), 0);

    let rig = Rig::new(dom_handler(json!(""))).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let err = rig.page.click_selector("#go").await.unwrap_err();
    assert!(err.to_string().contains("by nothing the page shows (the point is outside the view)"), "{err}");
    assert_eq!(rig.mock.count("Input.dispatchMouseEvent"), 0);
}

#[tokio::test]
async fn a_covered_target_is_retried_for_a_second_then_reported() {
    let opts = PageOptions { locator_timeout: Duration::from_secs(5), ..quick_options() };
    let rig = Rig::with_options(dom_handler(json!("div")), opts).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let start = std::time::Instant::now();
    let err = rig.page.click_selector("#go").await.unwrap_err();
    let took = start.elapsed();
    assert!(matches!(err, CdpError::Covered(_)), "{err:?}");
    assert!(took >= crate::dom::COVERED_GRACE && took < Duration::from_secs(3), "{took:?}");
    assert!(calls_of(&rig, "elementFromPoint").len() > 1, "retried while covered");
    assert_eq!(rig.mock.count("Input.dispatchMouseEvent"), 0);
}

/// The kinds of the mouse events sent, in order.
fn mouse_events(rig: &Rig) -> Vec<String> {
    rig.mock
        .calls()
        .into_iter()
        .filter(|c| c.1 == "Input.dispatchMouseEvent")
        .map(|c| c.2["type"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn the_check_runs_again_after_the_move_and_before_the_press() {
    let rig = Rig::new(dom_handler(Value::Null)).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    rig.page.click_selector("#go").await.unwrap();
    let order: Vec<String> = rig
        .mock
        .calls()
        .into_iter()
        .filter_map(|c| match c.1.as_str() {
            "Input.dispatchMouseEvent" => c.2["type"].as_str().map(str::to_owned),
            "DOM.getNodeForLocation" => Some("node".to_owned()),
            _ if c.2["functionDeclaration"].as_str().is_some_and(|f| f.contains("elementFromPoint")) => {
                Some("hit".to_owned())
            }
            _ if c.2["functionDeclaration"].as_str().is_some_and(|f| f.contains("requestAnimationFrame")) => {
                Some("frame".to_owned())
            }
            _ => None,
        })
        .collect();
    // The frame query last in each check, just before the move and just before the press.
    assert_eq!(
        order,
        [
            "hit",
            "node",
            "node",
            "mouseMoved",
            "frame",
            "hit",
            "node",
            "node",
            "mousePressed",
            "mouseReleased"
        ]
    );
}

#[tokio::test]
async fn something_the_move_brings_over_the_target_stops_the_press() {
    let inner = dom_handler(Value::Null);
    let hits = std::sync::atomic::AtomicUsize::new(0);
    let h: Handler = Box::new(move |s, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        if m == "Runtime.callFunctionOn" && f.contains("elementFromPoint") {
            // On top before the pointer arrives; covered once the page has seen it move.
            let first = hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            let v = if first { Value::Null } else { json!("div#overlay") };
            return Reply::Ok(json!({"result": {"type": "object", "value": v}}));
        }
        inner(s, m, p)
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let err = rig.page.click_selector("#go").await.unwrap_err();
    assert!(matches!(err, CdpError::Covered(_)), "{err:?}");
    assert!(err.to_string().contains("by <div#overlay>"), "{err}");
    assert_eq!(mouse_events(&rig), ["mouseMoved"], "moved once, never pressed");
}

/// Presses `#go` in the main frame with [`dom_handler`] answering, except where `instead` does.
async fn press_with(
    instead: impl Fn(&str, &str, &Value) -> Option<Reply> + Send + Sync + 'static,
) -> (Rig, Result<(), ClickError>) {
    let inner = dom_handler(Value::Null);
    let h: Handler = Box::new(move |s, m, p| {
        let f = p.get("functionDeclaration").and_then(Value::as_str).unwrap_or("");
        instead(m, f, p).unwrap_or_else(|| inner(s, m, p))
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    let el = rig.page.query_selector("#go").await.unwrap().unwrap();
    let r = rig.page.press_element(&el).await;
    (rig, r)
}

fn by_value(v: &Value) -> Reply {
    Reply::Ok(json!({"result": {"type": "object", "value": v}}))
}

#[tokio::test]
async fn every_failure_before_the_press_says_nothing_was_pressed() {
    fn gone() -> CdpError {
        CdpError::Protocol {
            method: "Runtime.callFunctionOn".into(),
            code: Some(-32000),
            message: "Cannot find context with specified id".into(),
            data: None,
        }
    }
    type Case = Box<dyn Fn(&str, &str, &Value) -> Option<Reply> + Send + Sync>;
    let cases: Vec<(&str, Case)> = vec![
        // A framework drew the control again between the aim and the click.
        (
            "detached",
            Box::new(|_, f, _| {
                f.contains("isConnected").then(|| by_value(&json!("Node is detached from document")))
            }),
        ),
        (
            "no box",
            Box::new(|_, f, _| f.contains("getClientRects.call(element)]").then(|| by_value(&json!([])))),
        ),
        (
            "covered",
            Box::new(|_, f, _| f.contains("elementFromPoint").then(|| by_value(&json!("div#banner")))),
        ),
        (
            "navigated in the hit test",
            Box::new(|_, f, _| f.contains("elementFromPoint").then(|| Reply::Err(gone()))),
        ),
        (
            "the hit test never answers",
            Box::new(|_, f, _| f.contains("elementFromPoint").then_some(Reply::Hang)),
        ),
        (
            "the frame wait never answers",
            Box::new(|_, f, _| f.contains("requestAnimationFrame").then_some(Reply::Hang)),
        ),
        (
            "the scroll check never answers",
            Box::new(|_, f, _| f.contains("IntersectionObserver").then_some(Reply::Hang)),
        ),
        (
            "the move fails",
            Box::new(|m, _, p| {
                (m == "Input.dispatchMouseEvent" && p["type"] == "mouseMoved")
                    .then(|| Reply::Err(CdpError::Other("move failed".into())))
            }),
        ),
    ];
    for (name, case) in cases {
        let (rig, r) = press_with(case).await;
        assert!(matches!(r, Err(ClickError::NotPressed(_))), "{name}: {r:?}");
        let pressed = mouse_events(&rig).iter().filter(|e| *e != "mouseMoved").count();
        assert_eq!(pressed, 0, "{name}: nothing is pressed");
    }
    let (_, r) = press_with(|_, f, _| f.contains("elementFromPoint").then(|| Reply::Err(gone()))).await;
    assert!(matches!(&r, Err(ClickError::NotPressed(e)) if e.is_navigating()), "{r:?}");
    let (_, r) = press_with(|_, f, _| f.contains("elementFromPoint").then(|| by_value(&json!("div")))).await;
    assert!(matches!(r, Err(ClickError::NotPressed(CdpError::Covered(_)))), "{r:?}");
}

#[tokio::test]
async fn a_frame_with_no_owner_is_not_pressed() {
    // The control is in a child frame whose <iframe> the parent no longer has: no click point.
    let rig = Rig::new(dom_handler(Value::Null)).await;
    rig.context(None, "MAIN", 7);
    rig.event(None, "Page.frameAttached", json!({"frameId": "CHILD", "parentFrameId": "MAIN"}));
    rig.context(None, "CHILD", 9);
    rig.settle().await;
    let js = "(s) => Document.prototype.querySelector.call(document, s)";
    let el =
        rig.page.evaluate_handle(&FrameId::from("CHILD"), js, vec![Arg::Value(json!("#go"))]).await.unwrap();
    let r = rig.page.press_element(&el).await;
    assert!(matches!(r, Err(ClickError::NotPressed(_))), "{r:?}");
    assert_eq!(mouse_events(&rig), Vec::<String>::new());
}

#[tokio::test]
async fn a_failure_at_the_press_may_have_pressed() {
    let (rig, r) = press_with(|m, _, p| {
        (m == "Input.dispatchMouseEvent" && p["type"] == "mousePressed")
            .then(|| Reply::Err(CdpError::Other("press failed".into())))
    })
    .await;
    assert!(matches!(r, Err(ClickError::Pressed(_))), "{r:?}");
    assert!(mouse_events(&rig).contains(&"mousePressed".to_owned()));
    // With nothing failing, it presses.
    let (_, r) = press_with(|_, _, _| None).await;
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn without_the_node_at_the_point_the_hit_test_refuses_every_frame_box() {
    // `DOM.getNodeForLocation` fails (an extension older than the service refuses it): the hit test is
    // strict, and a child frame's owner element is resolved in the main frame's isolated world and
    // handed to it, so one hidden in a closed shadow root still counts.
    let inner = dom_handler(Value::Null);
    let h: Handler = Box::new(move |s, m, p| match m {
        "DOM.getNodeForLocation" => Reply::Err(CdpError::Other("CDP method not allowed".into())),
        "DOM.getFrameOwner" => Reply::Ok(json!({"backendNodeId": 77})),
        "DOM.resolveNode" if p["backendNodeId"] == 77 => {
            Reply::Ok(json!({"object": {"type": "object", "subtype": "node", "objectId": "frame-owner"}}))
        }
        _ => inner(s, m, p),
    });
    let rig = Rig::new(h).await;
    rig.context(None, "MAIN", 7);
    rig.event(None, "Page.frameAttached", json!({"frameId": "CHILD", "parentFrameId": "MAIN"}));
    rig.settle().await;
    rig.page.click_selector("#go").await.unwrap();
    // The plain test, then the box rule, in each check.
    let hits = calls_of(&rig, "elementFromPoint");
    let strict: Vec<Value> = hits.iter().map(|c| c["arguments"][3]["value"].clone()).collect();
    assert_eq!(strict, [false, true, false, true]);
    let hit = &hits[1];
    assert_eq!(hit["uniqueContextId"], unique_of(FIRST_WORLD));
    assert_eq!(
        hit["arguments"],
        json!([
            {"objectId": "el-world"},
            {"value": 25.0},
            {"value": 40.0},
            {"value": true},
            {"objectId": "frame-owner"}
        ])
    );
    rig.settle().await;
    let released: Vec<Value> = rig
        .mock
        .calls()
        .into_iter()
        .filter(|c| c.1 == "Runtime.releaseObject")
        .map(|c| c.2["objectId"].clone())
        .collect();
    assert!(released.contains(&json!("frame-owner")), "{released:?}");
}

#[tokio::test]
async fn fill_reads_in_the_isolated_world_and_writes_in_the_page_world() {
    let long = "x".repeat(120);
    // (text in the field, value, the main world's writes, whether events follow them, the keys typed)
    let cases = [
        ("", "Ada", json!([""]), false, "Ada"),
        ("Ad", "Ada", json!(["", "Ad"]), false, "a"),
        ("xyz", "Ada", json!([""]), false, "Ada"),
        ("Ada", "Ada", Value::Null, false, ""),
        ("", long.as_str(), json!([long]), true, ""),
    ];
    for (now, value, writes, events, keys) in cases {
        let rig = Rig::new(dom_handler_with(Value::Null, json!({"editable": false, "text": now}))).await;
        rig.context(None, "MAIN", 7);
        rig.settle().await;
        rig.page.fill("#name", value).await.unwrap();
        let ctx_of = |needle: &str| {
            let c = &calls_of(&rig, needle)[0];
            (c["uniqueContextId"].clone(), c["arguments"][0].clone())
        };
        let world = (json!(unique_of(FIRST_WORLD)), json!({"objectId": "el-world"}));
        assert_eq!(ctx_of("'typeable-input'"), world);
        // The field's text is read in the isolated world: the page cannot choose what is typed.
        assert_eq!(ctx_of("'isContentEditable'"), world);
        let typed: String = rig
            .mock
            .calls()
            .into_iter()
            .filter(|c| c.1 == "Input.dispatchKeyEvent" && c.2["type"] == "keyDown")
            .map(|c| c.2["key"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(typed, keys, "{now:?} -> {value:?}");
        if writes.is_null() {
            assert!(calls_of(&rig, "element.value = text").is_empty(), "nothing to write");
            continue;
        }
        let write = &calls_of(&rig, "element.value = text")[0];
        assert_eq!(write["executionContextId"], 7, "the write alone is in the main world");
        assert_eq!(
            write["arguments"],
            json!([{"objectId": "el-main"}, {"value": false}, {"value": writes}, {"value": events}])
        );
        assert_eq!(ctx_of("Cannot focus"), world, "focus from the isolated world");
        assert_eq!(rig.mock.last("DOM.describeNode").unwrap().1, json!({"objectId": "el-world"}));
        assert_eq!(
            rig.mock.last("DOM.resolveNode").unwrap().1,
            json!({"backendNodeId": 31, "executionContextId": 7})
        );
        // Both handles are let go.
        let released: Vec<Value> = rig
            .mock
            .calls()
            .into_iter()
            .filter(|c| c.1 == "Runtime.releaseObject")
            .map(|c| c.2["objectId"].clone())
            .collect();
        assert!(
            released.contains(&json!("el-main")) && released.contains(&json!("el-world")),
            "{released:?}"
        );
    }
}

/// An extension too old to allow `Page.getLayoutMetrics` refuses it; the viewport then comes from the
/// page's own `visualViewport`, so a phone's live view of a check keeps working (2026-11-06).
#[tokio::test]
async fn a_refused_layout_metrics_reads_the_viewport_from_the_page() {
    let rig = Rig::new(handler(|_, m, p| match m {
        "Page.getLayoutMetrics" => Some(Reply::Err(CdpError::Other("CDP method not allowed".into()))),
        "Runtime.callFunctionOn" if p["functionDeclaration"] == VISUAL_VIEWPORT => Some(Reply::Ok(
            json!({"result": {"type": "object", "value": {"x": 3, "y": 400, "width": 390, "height": 844}}}),
        )),
        _ => None,
    }))
    .await;
    rig.context(None, "MAIN", 7);
    let v = rig.page.visual_viewport().await.unwrap();
    assert_eq!(v, BoundingBox { x: 3.0, y: 400.0, width: 390.0, height: 844.0 });
    assert_eq!(rig.mock.count("Page.getLayoutMetrics"), 1);
}

/// A handler whose trace stream holds `chunks`, read in order.
fn stream_handler(chunks: Vec<(&'static str, bool)>) -> Handler {
    let next = std::sync::atomic::AtomicUsize::new(0);
    handler(move |_, m, _| {
        (m == "IO.read").then(|| {
            let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (data, eof) = chunks.get(i).copied().unwrap_or(("", true));
            Reply::Ok(json!({"data": data, "eof": eof}))
        })
    })
}

#[tokio::test]
async fn a_trace_records_only_its_categories_and_reads_its_stream_to_the_end() {
    let rig = Rig::new(stream_handler(vec![("{\"traceEvents\":", false), ("[]}", true)])).await;
    rig.page.trace_start(&["loading", "devtools.timeline"], 4096).await.unwrap();
    let (_, start) = rig.mock.last("Tracing.start").unwrap();
    assert_eq!(start["transferMode"], "ReturnAsStream");
    assert_eq!(start["traceConfig"]["includedCategories"], json!(["loading", "devtools.timeline"]));
    assert_eq!(start["traceConfig"]["excludedCategories"], json!(["*"]));
    assert_eq!(start["traceConfig"]["recordMode"], "recordUntilFull");
    // One trace at a time: the second start sends nothing.
    assert!(rig.page.trace_start(&["loading"], 4096).await.is_err());
    assert_eq!(rig.mock.count("Tracing.start"), 1);

    rig.event(None, "Tracing.bufferUsage", json!({"percentFull": 0.25}));
    rig.settle().await;
    assert_eq!(rig.page.trace_fill(), Some(0.25));

    let ending = rig.page.trace_end(Duration::from_secs(2), 1 << 20);
    let completing = async {
        wait_for(|| rig.mock.count("Tracing.end") == 1).await;
        rig.event(None, "Tracing.tracingComplete", json!({"dataLossOccurred": false, "stream": "s-1"}));
    };
    let (data, ()) = tokio::join!(ending, completing);
    let data = data.unwrap();
    assert_eq!(data.bytes, b"{\"traceEvents\":[]}");
    assert!(!data.data_lost && !data.full);
    let reads: Vec<Value> = rig.mock.calls().into_iter().filter(|c| c.1 == "IO.read").map(|c| c.2).collect();
    assert_eq!(reads.len(), 2);
    assert!(reads.iter().all(|r| r["handle"] == "s-1"));
    assert_eq!(rig.mock.last("IO.close").unwrap().1["handle"], "s-1");
    assert_eq!(rig.page.trace_fill(), None, "the page has no trace afterwards");
}

#[tokio::test]
async fn a_trace_over_its_size_is_refused_and_its_stream_still_closed() {
    let rig = Rig::new(stream_handler(vec![("0123456789", false), ("0123456789", true)])).await;
    rig.page.trace_start(&["loading"], 4096).await.unwrap();
    let ending = rig.page.trace_end(Duration::from_secs(2), 15);
    let completing = async {
        wait_for(|| rig.mock.count("Tracing.end") == 1).await;
        rig.event(None, "Tracing.tracingComplete", json!({"dataLossOccurred": true, "stream": "s-2"}));
    };
    let (data, ()) = tokio::join!(ending, completing);
    let e = data.unwrap_err().to_string();
    assert!(e.contains("over 15 bytes"), "{e}");
    assert_eq!(rig.mock.last("IO.close").unwrap().1["handle"], "s-2");
    assert_eq!(rig.page.trace_fill(), None);
}

#[tokio::test]
async fn a_trace_that_never_completes_ends_at_its_wait_and_frees_the_page() {
    let rig = Rig::new(handler(|_, _, _| None)).await;
    assert!(rig.page.trace_end(Duration::from_millis(50), 100).await.is_err(), "no trace is running");
    rig.page.trace_start(&["loading"], 4096).await.unwrap();
    let e = rig.page.trace_end(Duration::from_millis(50), 100).await.unwrap_err();
    assert!(matches!(e, CdpError::WaitTimeout { .. }), "{e}");
    assert_eq!(rig.mock.count("IO.read"), 0);
    rig.page.trace_start(&["loading"], 4096).await.unwrap();
}

#[tokio::test]
async fn the_measuring_world_is_its_own_and_its_answer_comes_back_by_value() {
    let rig = Rig::new(handler(|_, m, p| match m {
        "Page.addScriptToEvaluateOnNewDocument" => Some(Reply::Ok(json!({"identifier": "7"}))),
        "Runtime.callFunctionOn" if p["functionDeclaration"].as_str().is_some_and(|f| f.contains("throw")) => {
            Some(Reply::Ok(json!({"exceptionDetails": {"text": "Uncaught", "exception": {"description": "Error: no"}}})))
        }
        "Runtime.callFunctionOn" => Some(Reply::Ok(json!({"result": {"type": "object", "value": {"n": 1}}}))),
        _ => None,
    }))
    .await;
    rig.context(None, "MAIN", 7);
    rig.settle().await;
    assert_eq!(rig.page.add_measure_script("globalThis.x = 1;").await.unwrap(), "7");
    let (_, add) = rig.mock.last("Page.addScriptToEvaluateOnNewDocument").unwrap();
    assert_eq!(add["worldName"], MEASURE_WORLD);
    assert_ne!(MEASURE_WORLD, ISOLATED_WORLD);
    let (_, world) = rig.mock.last("Page.createIsolatedWorld").unwrap();
    assert_eq!(world["worldName"], MEASURE_WORLD);
    assert_eq!(rig.page.evaluate_measure("() => ({n: 1})").await.unwrap(), json!({"n": 1}));
    let e = rig.page.evaluate_measure("() => { throw 1 }").await.unwrap_err();
    assert!(e.to_string().contains("Error: no"), "{e}");
    rig.page.remove_measure_script("7").await.unwrap();
    assert_eq!(rig.mock.last("Page.removeScriptToEvaluateOnNewDocument").unwrap().1["identifier"], "7");
}
