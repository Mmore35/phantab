//! Sign-in over a scripted page, without Chrome: the cases a real page cannot stage on cue
//! (THREAT-MODEL SR-45). The page answers each in-page function by its source, so
//! a test decides what a field's type is now, which frame holds a value and which call never answers.
//! The provider is the fake provider; no browser, no vault.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use phantab::engine_api::{EngineError, Serializer};
use phantab::signin::{Echo, Host, Leftover, Options, Phase, SignInRecord};
use phantab_cdp::{Page, PageOptions, RelayTransport, TransportEvent};
use phantab_testkit::sign_in::{CODE, PASSWORD, USERNAME};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;

const FAKE: &str = env!("CARGO_BIN_EXE_phantab-fake-provider");

// The pipeline's own sources, so the page knows each call by its exact text.
const FIND_SIGN_IN: &str = include_str!("../src/page_js/signin_find.js");
const FILL_FIELDS: &str = include_str!("../src/page_js/signin_fill.js");
const READ_INPUTS: &str = include_str!("../src/page_js/signin_read_inputs.js");
const BLANK_INPUTS: &str = include_str!("../src/page_js/signin_blank_inputs.js");
const HREF: &str = "()=>location.href";

const LOGIN: &str = "https://example.test/login";
const WIDGET: &str = "https://example.test/widget";

/// How a frame answers a read or an index blank.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Answer,
    /// Answers, and changes nothing (a page that puts the value straight back).
    Ignore,
    /// Never answers.
    Hang,
}

struct Input {
    kind: &'static str,
    name: &'static str,
    value: String,
}

fn input(kind: &'static str, name: &'static str) -> Input {
    Input { kind, name, value: String::new() }
}

struct Doc {
    id: &'static str,
    ctx: i64,
    url: &'static str,
    text: String,
    inputs: Vec<Input>,
    read: Mode,
    blank: Mode,
}

fn doc(id: &'static str, ctx: i64, url: &'static str, inputs: Vec<Input>) -> Doc {
    Doc { id, ctx, url, text: String::new(), inputs, read: Mode::Answer, blank: Mode::Answer }
}

type OnSubmit = Box<dyn FnMut(&mut Vec<Doc>) + Send>;

/// The page: the main frame first, then its children. The report is the main frame's sign-in, until the
/// submit; after it the form is gone.
struct Script {
    docs: Vec<Doc>,
    report: Value,
    submitted: bool,
    on_submit: Option<OnSubmit>,
    /// A frame and the URL Chrome reports it moved to, at the first `location.href` read after the
    /// provider was asked.
    moves_when_asked: Option<(&'static str, &'static str)>,
}

impl Script {
    fn new(docs: Vec<Doc>, report: Value) -> Script {
        Script { docs, report, submitted: false, on_submit: None, moves_when_asked: None }
    }

    fn moves_when_asked(mut self, frame: &'static str, url: &'static str) -> Script {
        self.moves_when_asked = Some((frame, url));
        self
    }

    fn on_submit(mut self, f: impl FnMut(&mut Vec<Doc>) + Send + 'static) -> Script {
        self.on_submit = Some(Box::new(f));
        self
    }
}

/// A main-frame sign-in report for `fields`.
fn report(fields: &[&str]) -> Value {
    let mut r = json!({"passwordCount": 0, "href": LOGIN, "ancestors": [], "action": LOGIN});
    for f in fields {
        r[*f] = json!(true);
    }
    if fields.contains(&"password") {
        r["passwordCount"] = json!(1);
    }
    r
}

enum Reply {
    Now(Value),
    Hang,
}

fn by_value(v: Value) -> Reply {
    let mut remote = json!({"result": {"type": "object"}});
    remote["result"]["value"] = v;
    Reply::Now(remote)
}

/// How far above a frame's main-world number its isolated world's number is.
const WORLD: i64 = 1000;

/// The isolated world `Page.createIsolatedWorld` makes in the frame whose main world is `ctx`: its number
/// and its unique id. phantab's page functions run there (THREAT-MODEL SR-34); it reads the same
/// document, so the page answers a call in either world alike.
fn world(ctx: i64) -> (i64, String) {
    (ctx + WORLD, format!("world-{ctx}"))
}

/// The main-world number of the document a call runs in, whether it names its context by number or, as
/// a call in an isolated world does, by the unique id.
fn main_ctx(params: &Value) -> i64 {
    if let Some(unique) = params["uniqueContextId"].as_str() {
        return unique.strip_prefix("world-").and_then(|c| c.parse().ok()).unwrap_or_default();
    }
    params["executionContextId"].as_i64().map_or(0, |c| if c > WORLD { c - WORLD } else { c })
}

fn call(script: &Mutex<Script>, params: &Value) -> Reply {
    let js = params["functionDeclaration"].as_str().unwrap_or_default();
    let ctx = main_ctx(params);
    let args = params["arguments"].as_array().cloned().unwrap_or_default();
    let mut s = script.lock().unwrap();
    let Some(at) = s.docs.iter().position(|d| d.ctx == ctx) else { return by_value(Value::Null) };
    match js {
        _ if js == FIND_SIGN_IN => Reply::Now(json!({"result": {"type": "object", "objectId": "sign-in"}})),
        "o=>o.report" => by_value(if s.submitted { json!({}) } else { s.report.clone() }),
        _ if js == HREF => by_value(json!(s.docs[at].url)),
        "o=>o.submitByForm" => by_value(json!(true)),
        "o=>o.state()" => by_value(json!({"gone": true})),
        "o=>HTMLFormElement.prototype.requestSubmit.call(o.form)" => {
            s.submitted = true;
            if let Some(mut f) = s.on_submit.take() {
                f(&mut s.docs);
            }
            by_value(Value::Null)
        }
        _ if js == FILL_FIELDS => {
            let values = args.get(2).and_then(|a| a["value"].as_object()).cloned().unwrap_or_default();
            for (name, v) in values {
                if let Some(i) = s.docs[at].inputs.iter_mut().find(|i| i.name == name) {
                    v.as_str().unwrap_or_default().clone_into(&mut i.value);
                }
            }
            by_value(json!("filled"))
        }
        _ if js == READ_INPUTS => {
            let d = &s.docs[at];
            if d.read == Mode::Hang {
                return Reply::Hang;
            }
            let values: Vec<&str> = d.inputs.iter().map(|i| i.value.as_str()).collect();
            by_value(json!({"href": d.url, "text": d.text, "values": values}))
        }
        _ if js == BLANK_INPUTS => {
            let d = &mut s.docs[at];
            match &args.first().map(|a| a["value"].clone()).unwrap_or_default() {
                Value::String(w) if w == "passwords" => {
                    d.inputs.iter_mut().filter(|i| i.kind == "password").for_each(|i| i.value.clear());
                }
                Value::Array(wanted) => match d.blank {
                    Mode::Hang => return Reply::Hang,
                    Mode::Ignore => {}
                    Mode::Answer => {
                        for i in wanted.iter().filter_map(Value::as_u64) {
                            if let Some(i) = usize::try_from(i).ok().and_then(|i| d.inputs.get_mut(i)) {
                                i.value.clear();
                            }
                        }
                    }
                },
                _ => {}
            }
            by_value(Value::Null)
        }
        // `blank`, a frame's box (none, so a child frame is not read for a form), anything else.
        _ => by_value(Value::Null),
    }
}

fn frame_tree(s: &Script) -> Value {
    let main = &s.docs[0];
    let children: Vec<Value> = s.docs[1..]
        .iter()
        .map(|d| json!({"frame": {"id": d.id, "parentId": main.id, "url": d.url}}))
        .collect();
    json!({"frameTree": {"frame": {"id": main.id, "url": main.url}, "childFrames": children}})
}

/// One agent page.
#[derive(Default)]
struct RecState {
    sign_in: Option<Phase>,
    leftover: Option<Arc<Leftover>>,
    blanking: bool,
    account: Option<(String, Instant)>,
    echo: Option<Arc<Echo>>,
}

struct Rec {
    page: Page,
    st: Mutex<RecState>,
}

#[async_trait]
impl SignInRecord for Rec {
    fn page(&self) -> Page {
        self.page.clone()
    }

    fn detached(&self) -> bool {
        false
    }

    fn detaches(&self) -> u64 {
        0
    }

    async fn recover(&self) -> Result<(), EngineError> {
        Ok(())
    }

    fn is_current(&self) -> bool {
        true
    }

    fn paused(&self) -> bool {
        false
    }

    fn touch(&self) {}

    fn sign_in(&self) -> Option<Phase> {
        self.st.lock().unwrap().sign_in
    }

    fn set_sign_in(&self, phase: Option<Phase>) {
        self.st.lock().unwrap().sign_in = phase;
    }

    fn leftover(&self) -> Option<Arc<Leftover>> {
        self.st.lock().unwrap().leftover.clone()
    }

    fn set_leftover(&self, leftover: Option<Arc<Leftover>>) {
        self.st.lock().unwrap().leftover = leftover;
    }

    fn begin_blanking(&self) -> bool {
        !std::mem::replace(&mut self.st.lock().unwrap().blanking, true)
    }

    fn end_blanking(&self) {
        self.st.lock().unwrap().blanking = false;
    }

    fn account(&self) -> Option<(String, Instant)> {
        self.st.lock().unwrap().account.clone()
    }

    fn set_account(&self, key: String) {
        self.st.lock().unwrap().account = Some((key, Instant::now()));
    }
}

/// The engine as sign-in sees it: one page, `p1`, of agent `a`.
struct Lane {
    rec: Arc<Rec>,
    script: Arc<Mutex<Script>>,
    events: mpsc::UnboundedSender<TransportEvent>,
    dir: tempfile::TempDir,
    serializer: Serializer,
}

#[async_trait]
impl Host for Lane {
    fn record(&self, page_id: &Value, client: &str) -> Option<Arc<dyn SignInRecord>> {
        (page_id == "p1" && client == "a").then(|| Arc::clone(&self.rec) as Arc<dyn SignInRecord>)
    }

    fn provider(&self) -> Option<Value> {
        Some(json!({"command": [FAKE, self.path("provider.json")]}))
    }

    fn guard_file(&self) -> PathBuf {
        self.path("sign-in-guard.json")
    }

    fn options(&self) -> Options {
        Options::default().with_times(|t| {
            t.observe_ms = 2000;
            t.settle_ms = 200;
            t.find_ms = 300;
        })
    }

    fn serializer(&self) -> Serializer {
        self.serializer.clone()
    }

    fn lock(&self, _record: &dyn SignInRecord) -> Result<(), EngineError> {
        Ok(())
    }

    fn echoed(&self, _record: &dyn SignInRecord, echo: Arc<Echo>) {
        self.rec.st.lock().unwrap().echo = Some(echo);
    }
}

impl Lane {
    async fn new(script: Script) -> Lane {
        let script = Arc::new(Mutex::new(script));
        let dir = tempfile::Builder::new().prefix("phantab-sign-in-fake-page-").tempdir().unwrap();
        let asked = dir.path().join("asked.jsonl");
        let seen: Arc<OnceLock<Page>> = Arc::default();
        let (tx, rx) = mpsc::unbounded_channel();
        let (page_script, events, page_seen) = (Arc::clone(&script), tx.clone(), Arc::clone(&seen));
        let transport = RelayTransport::from_fn(move |_session, method: String, params: Value| {
            let (script, events, seen, asked) =
                (Arc::clone(&page_script), events.clone(), Arc::clone(&page_seen), asked.clone());
            async move {
                let reply = match method.as_str() {
                    "Page.getFrameTree" => Reply::Now(frame_tree(&script.lock().unwrap())),
                    "Runtime.enable" => {
                        for d in &script.lock().unwrap().docs {
                            let context = json!({"context": {"id": d.ctx, "auxData": {"frameId": d.id, "isDefault": true}}});
                            let _ = events.send(TransportEvent::Event {
                                session: None,
                                method: "Runtime.executionContextCreated".into(),
                                params: context,
                            });
                        }
                        Reply::Now(json!({}))
                    }
                    // As Chrome does: the world's own event first, then the answer with its number. The
                    // name is phantab_cdp's `ISOLATED_WORLD`.
                    "Page.createIsolatedWorld" => {
                        let frame = params["frameId"].as_str().unwrap_or_default();
                        let ctx = script.lock().unwrap().docs.iter().find(|d| d.id == frame).map(|d| d.ctx);
                        match ctx {
                            Some(ctx) => {
                                let (id, unique) = world(ctx);
                                let context = json!({"context": {"id": id, "name": "phantab", "uniqueId": unique,
                                    "auxData": {"frameId": frame, "isDefault": false, "type": "isolated"}}});
                                let _ = events.send(TransportEvent::Event {
                                    session: None,
                                    method: "Runtime.executionContextCreated".into(),
                                    params: context,
                                });
                                Reply::Now(json!({"executionContextId": id}))
                            }
                            None => Reply::Now(json!({})),
                        }
                    }
                    "Runtime.callFunctionOn" => {
                        let reply = call(&script, &params);
                        if params["functionDeclaration"] == HREF && provider_asked(&asked) {
                            let moving = script.lock().unwrap().moves_when_asked.take();
                            if let Some((frame, url)) = moving {
                                move_frame(&events, seen.get().unwrap(), frame, url).await;
                            }
                        }
                        reply
                    }
                    "DOM.getFrameOwner" => Reply::Now(json!({"backendNodeId": 7})),
                    "DOM.resolveNode" => {
                        Reply::Now(json!({"object": {"type": "object", "objectId": "owner"}}))
                    }
                    "Page.close" => {
                        let _ = events.send(TransportEvent::Closed("Page closed".into()));
                        Reply::Now(json!({}))
                    }
                    _ => Reply::Now(json!({})),
                };
                match reply {
                    Reply::Now(v) => Ok(v),
                    Reply::Hang => std::future::pending().await,
                }
            }
        });
        let page = Page::attach(Arc::new(transport), None, rx, PageOptions::default()).await.unwrap();
        seen.set(page.clone()).ok().unwrap();
        let control = json!({
            "log": dir.path().join("asked.jsonl"),
            "values": {"username": USERNAME, "password": PASSWORD, "code": CODE},
        });
        std::fs::write(dir.path().join("provider.json"), control.to_string()).unwrap();
        let rec = Arc::new(Rec { page, st: Mutex::default() });
        Lane { rec, script, events: tx, dir, serializer: Serializer::default() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    async fn sign(&self) -> Value {
        phantab::signin::sign_in(self, "a", &json!({"pageId": "p1"})).await.unwrap()
    }

    /// A call on an unblanked page: answers `blank-unconfirmed` and re-blanks; returns once that ends.
    async fn reblank(&self) {
        assert_eq!(self.sign().await, json!({"status": "failed", "reason": "blank-unconfirmed"}));
        let end = Instant::now() + Duration::from_secs(20);
        while self.rec.st.lock().unwrap().blanking {
            assert!(Instant::now() < end, "the re-blank did not end");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn phase(&self) -> Option<Phase> {
        self.rec.sign_in()
    }

    fn requests(&self) -> usize {
        std::fs::read_to_string(self.path("asked.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .count()
    }

    fn value(&self, frame: &str, name: &str) -> String {
        let s = self.script.lock().unwrap();
        let d = s.docs.iter().find(|d| d.id == frame).unwrap();
        d.inputs.iter().find(|i| i.name == name).unwrap().value.clone()
    }

    fn set(&self, frame: &str, change: impl FnOnce(&mut Doc)) {
        let mut s = self.script.lock().unwrap();
        change(s.docs.iter_mut().find(|d| d.id == frame).unwrap());
    }

    /// Chrome removes a frame.
    async fn detach(&self, frame: &str) {
        let params = json!({"frameId": frame, "reason": "remove"});
        self.events
            .send(TransportEvent::Event { session: None, method: "Page.frameDetached".into(), params })
            .unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while self.rec.page.frames().iter().any(|f| f.id.as_str() == frame) {
            assert!(Instant::now() < end, "the frame did not go");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn provider_asked(log: &Path) -> bool {
    std::fs::read_to_string(log).is_ok_and(|l| !l.trim().is_empty())
}

/// Chrome reports an in-page navigation of `frame` to `url`; returns once the page has it.
async fn move_frame(events: &mpsc::UnboundedSender<TransportEvent>, page: &Page, frame: &str, url: &str) {
    let params = json!({"frameId": frame, "url": url});
    events
        .send(TransportEvent::Event { session: None, method: "Page.navigatedWithinDocument".into(), params })
        .unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while !page.frames().iter().any(|f| f.id.as_str() == frame && f.url == url) {
        assert!(Instant::now() < end, "the frame did not move");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn sign_in_form() -> Vec<Input> {
    vec![input("text", "username"), input("password", "password")]
}

/// A show-password toggle makes the field `text` after the fill. The old re-blank cleared only
/// `type=password` fields, so it confirmed with the password still showing; now the page stays held
/// until the field that holds it is blank.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shown_password_holds_the_page_until_it_is_blank() {
    let mut main = doc("F", 1, LOGIN, sign_in_form());
    main.blank = Mode::Ignore;
    let script = Script::new(vec![main], report(&["username", "password"]))
        .on_submit(|docs| docs[0].inputs[1].kind = "text");
    let lane = Lane::new(script).await;

    assert_eq!(lane.sign().await, json!({"status": "submitted"}));
    assert_eq!(lane.requests(), 1);
    assert_eq!(lane.phase(), Some(Phase::Unblanked));

    lane.reblank().await;
    assert_eq!(lane.phase(), Some(Phase::Unblanked), "a text field still holds the password");
    assert_eq!(lane.value("F", "password"), PASSWORD);

    lane.set("F", |d| d.blank = Mode::Answer);
    lane.reblank().await;
    assert_eq!(lane.phase(), None);
    assert!(lane.rec.leftover().is_none());
    assert_eq!(lane.value("F", "password"), "");
    assert_eq!(lane.value("F", "username"), USERNAME);
    assert_eq!(lane.requests(), 1);
}

/// A code sits in a `tel` field, which no password blank touches; the re-blank finds it by value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_field_of_any_type_is_blanked() {
    let mut main = doc("F", 1, LOGIN, vec![input("tel", "code")]);
    main.blank = Mode::Ignore;
    let lane = Lane::new(Script::new(vec![main], report(&["code"]))).await;

    assert_eq!(lane.sign().await, json!({"status": "submitted"}));
    assert_eq!(lane.phase(), Some(Phase::Unblanked));
    lane.reblank().await;
    assert_eq!(lane.phase(), Some(Phase::Unblanked));
    assert_eq!(lane.value("F", "code"), CODE);

    lane.set("F", |d| d.blank = Mode::Answer);
    lane.reblank().await;
    assert_eq!(lane.phase(), None);
    assert_eq!(lane.value("F", "code"), "");
}

/// The page copies the password into a child frame the sign-in did not fill, and that frame does not
/// blank it. The old re-blank counted only the main frame and the filled one; now that frame holds the
/// page while it does not answer, and frees it once Chrome removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_that_kept_the_password_holds_the_page_until_it_answers_or_goes() {
    let main = doc("F", 1, LOGIN, sign_in_form());
    let mut widget = doc("C", 2, WIDGET, vec![input("text", "note")]);
    widget.blank = Mode::Ignore;
    let script = Script::new(vec![main, widget], report(&["username", "password"]))
        .on_submit(|docs| docs[1].inputs[0].value = PASSWORD.to_owned());
    let lane = Lane::new(script).await;

    assert_eq!(lane.sign().await, json!({"status": "submitted"}));
    assert_eq!(lane.value("F", "password"), "", "the filled frame confirmed");
    assert_eq!(lane.phase(), Some(Phase::Unblanked));

    lane.set("C", |d| d.read = Mode::Hang);
    lane.reblank().await;
    assert_eq!(lane.phase(), Some(Phase::Unblanked), "a frame that held the password did not answer");
    assert_eq!(lane.value("C", "note"), PASSWORD);

    lane.detach("C").await;
    lane.reblank().await;
    assert_eq!(lane.phase(), None);
}

/// The site shows the code back in the page after the submit: the call goes on and says so, the engine
/// is handed what redacts the code (as a whole token, as the sweep finds it), not a leak stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_shown_back_in_the_page_is_redacted_and_the_sign_in_goes_on() {
    let main = doc("F", 1, LOGIN, vec![input("tel", "code")]);
    let script = Script::new(vec![main], report(&["code"]))
        .on_submit(|docs| docs[0].text = format!("Code {CODE} accepted"));
    let lane = Lane::new(script).await;

    let signed = lane.sign().await;
    assert_ne!(signed["status"], json!("leak-stopped"), "{signed}");
    assert_eq!(signed["echoed"], json!(true), "{signed}");
    let note = signed["note"].as_str().unwrap();
    assert!(note.contains("code") && !note.contains("reset"), "{note}");
    assert!(!signed.to_string().contains(CODE));
    let echo = lane.rec.st.lock().unwrap().echo.clone().expect("the engine was handed the echo");
    assert!(!echo.password(), "only the code was shown");
    assert_eq!(echo.redact(&format!("Code {CODE} accepted")).as_deref(), Some("Code [redacted] accepted"));
    assert_eq!(echo.redact(&format!("ref 1{CODE}")), None, "the code as a whole token only");
    let guard = std::fs::read_to_string(lane.guard_file()).unwrap_or_default();
    assert!(!guard.contains(CODE));
}

/// A frame that reports a URL Chrome's frame tree does not show gets nothing: the provider is never
/// asked, so no other site's login goes into it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_that_disagrees_with_the_frame_tree_gets_nothing() {
    let main = || vec![doc("F", 1, LOGIN, sign_in_form())];
    let mut elsewhere = report(&["username", "password"]);
    elsewhere["href"] = json!("https://bank.test/login");
    elsewhere["action"] = json!("https://bank.test/login");
    let mut framed = report(&["username", "password"]);
    framed["ancestors"] = json!(["https://bank.test"]);
    for wrong in [elsewhere, framed] {
        let lane = Lane::new(Script::new(main(), wrong)).await;
        assert_eq!(lane.sign().await, json!({"status": "not-ready"}));
        assert_eq!(lane.requests(), 0);
        assert_eq!(lane.value("F", "password"), "");
        assert_eq!(lane.phase(), None);
    }
}

/// Chrome's frame tree shows the sign-in frame moved on (an in-page navigation) after the call's check,
/// while the provider was asked. The page's own `location.href` still says the login, so only the check
/// the fill makes against the frame tree stands between: it refuses, and what was asked for goes nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_that_moves_while_the_provider_is_asked_gets_nothing() {
    let script = Script::new(vec![doc("F", 1, LOGIN, sign_in_form())], report(&["username", "password"]))
        .moves_when_asked("F", "https://example.test/elsewhere");
    let lane = Lane::new(script).await;

    assert_eq!(lane.sign().await, json!({"status": "not-ready"}));
    assert!(lane.script.lock().unwrap().moves_when_asked.is_none(), "the frame moved");
    assert_eq!(lane.requests(), 1);
    assert_eq!(lane.value("F", "username"), "");
    assert_eq!(lane.value("F", "password"), "");
    assert_eq!(lane.phase(), None);
}
