//! What an agent pays to use phantab: six browser-heavy tasks on local fixtures (`fixtures/cost/`), sign in,
//! sign up, a long article, a 1,200-row orders table, a shadow-DOM SPA with a virtualized 4,800-row list and
//! a cross-site frame, and a five-step checkout.
//!
//! `scripted_tasks_cost_and_keep_what_agents_need` drives each task through `phantab mcp` the way an agent
//! does today (open, snapshot, act, snapshot again), checks the task's end state from the fixture server's
//! recorded posts, checks that the facts an agent needs to finish appear in what it read, and prints one
//! `lane3 cost {json}` line: the characters of every tool result, by tool and by task, and of `tools/list`
//! (the tool definitions a harness resends every turn). Deterministic, so a change to what phantab returns
//! shows exactly.
//!
//! `hold_a_lane_for_real_agents` (only with `PHANTAB_TEST_COST_HOLD=<dir>`) starts the same lane and keeps it
//! up for a real agent: it writes `<dir>/lane.json` (the binary, the environment `phantab mcp` needs to reach
//! this lane, the task URLs), appends every recorded post to `<dir>/posts.jsonl`, and stops when `<dir>/stop`
//! exists or after `PHANTAB_TEST_COST_HOLD_SECS` (default 1800).
//!
//! Skips without `PHANTAB_TEST_CHROME`. Headless (`PHANTAB_TEST_WINDOWS=none`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::too_many_lines, reason = "each task reads as one story")]

#[path = "common/cdp_extension.rs"]
mod cdp_extension;
mod common;

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead as _, BufReader, Lines, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cdp_extension::CdpExtension;
use common::{Runtime, Service, upgrade};
use phantab_cdp::Browser;
use phantab_testkit::FixtureServer;
use serde_json::{Value, json};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The tasks, by name, and the fixture each starts on.
const TASKS: &[(&str, &str)] = &[
    ("signin", "/cost/signin"),
    ("signup", "/cost/signup"),
    ("article", "/cost/article"),
    ("orders", "/cost/orders"),
    ("app", "/cost/app#/home"),
    ("shop", "/cost/shop"),
];

/// One service on a temp runtime, with the CDP-backed extension connected (as in `engine_chrome.rs`).
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
        rt.write_config(&json!({
            "profileDirectory": "test", "userDataDir": rt.user_data_dir(), "chromeExecutable": chrome,
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
        let ext = tokio::task::block_in_place(|| CdpExtension::connect(stream, "cost", Arc::clone(&browser)));
        let lane = Self { ext, browser, svc, rt, fixtures };
        let end = Instant::now() + Duration::from_secs(10);
        while lane.rpc("status")["connected"] != json!(true) {
            assert!(Instant::now() < end, "the extension never connected");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let status = lane.rpc("connect");
        assert_eq!(status["profileVerified"], json!(true), "{status}");
        lane
    }

    fn rpc(&self, method: &str) -> Value {
        let (port, token) = (self.svc.endpoint.port, self.svc.endpoint.token.clone());
        tokio::task::block_in_place(|| common::rpc(port, &token, method, &json!({}), "test"))["result"]
            .clone()
    }

    /// The environment `phantab mcp` needs to reach this lane and nothing else (`Runtime::command`).
    fn mcp_env(&self) -> BTreeMap<String, String> {
        let cmd = self.rt.command(&["mcp"]);
        cmd.get_envs().filter_map(|(k, v)| Some((k.to_str()?.to_owned(), v?.to_str()?.to_owned()))).collect()
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

/// `phantab mcp` over stdio, counting what every call returns.
struct Mcp {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    id: u64,
    tools_list_chars: usize,
    /// (task, tool, result characters, argument characters)
    calls: Vec<(String, String, usize, usize)>,
    task: String,
    /// Every text result of the current task, for the information checks.
    read: String,
    /// Each page's last snapshot, whole, so one shown as changes since then reads back whole.
    shown: HashMap<String, String>,
}

impl Mcp {
    fn start(rt: &Runtime) -> Self {
        let mut child = rt
            .command(&["mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut m = Self {
            child,
            stdin,
            lines,
            id: 0,
            tools_list_chars: 0,
            calls: Vec::new(),
            task: String::new(),
            read: String::new(),
            shown: HashMap::new(),
        };
        m.request("initialize", &json!({
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "cost", "version": "1" } }));
        m.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        let tools = m.request("tools/list", &json!({}));
        m.tools_list_chars = tools["tools"].to_string().chars().count();
        m
    }

    fn send(&mut self, v: &Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: &Value) -> Value {
        self.id += 1;
        let id = self.id;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let line = self.lines.next().expect("phantab mcp ended").unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(id) {
                return v["result"].clone();
            }
        }
    }

    /// A tool call; the parsed JSON of its text result (a string if it is not JSON).
    fn call(&mut self, tool: &str, args: &Value) -> Value {
        let result =
            self.request("tools/call", &json!({ "name": format!("browser_{tool}"), "arguments": args }));
        let mut chars = 0;
        let mut text = String::new();
        for c in result["content"].as_array().into_iter().flatten() {
            if let Some(t) = c["text"].as_str() {
                chars += t.chars().count();
                text.push_str(t);
            }
        }
        self.calls.push((self.task.clone(), tool.to_owned(), chars, args.to_string().chars().count()));
        assert_ne!(result["isError"], json!(true), "{tool} {args}: {text}");
        self.read.push_str(&text);
        self.read.push('\n');
        if let Ok(v) = serde_json::from_str(&text) {
            return v;
        }
        let page = args["pageId"].as_str().unwrap_or_default().to_owned();
        let whole = match self.shown.get(&page) {
            Some(last) if text.contains(SINCE) => {
                rebuild(last, &text).unwrap_or_else(|| panic!("unreadable changes {text:?}"))
            }
            _ => text.clone(),
        };
        match compact_snapshot(&whole) {
            Some(snap) => {
                self.shown.insert(page, whole);
                snap
            }
            None => Value::String(text),
        }
    }

    fn act(&mut self, page: &str, mut args: Value) -> Value {
        args["pageId"] = json!(page);
        self.call("act", &args)
    }

    fn snap(&mut self, page: &str) -> Value {
        self.call("snapshot", &json!({ "pageId": page }))
    }

    fn begin(&mut self, task: &str) {
        task.clone_into(&mut self.task);
        self.read.clear();
    }

    /// Each fact must appear in something this task read.
    fn must_have_read(&self, facts: &[&str]) {
        for f in facts {
            assert!(self.read.contains(f), "task {}: never read {f:?}", self.task);
        }
    }

    fn report(&self) -> Value {
        let mut by_task: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
        let mut by_tool: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for (task, tool, chars, arg_chars) in &self.calls {
            let t = by_task.entry(task).or_default();
            t.0 += 1;
            t.1 += chars;
            t.2 += arg_chars;
            let u = by_tool.entry(tool).or_default();
            u.0 += 1;
            u.1 += chars;
        }
        let total: usize = self.calls.iter().map(|c| c.2).sum();
        json!({
            "resultChars": total,
            "toolsListChars": self.tools_list_chars,
            "calls": self.calls.len(),
            "tasks": by_task.iter().map(|(k, (n, c, a))| (k.to_string(), json!({ "calls": n, "resultChars": c, "argChars": a }))).collect::<serde_json::Map<_, _>>(),
            "tools": by_tool.iter().map(|(k, (n, c))| (k.to_string(), json!({ "calls": n, "resultChars": c }))).collect::<serde_json::Map<_, _>>(),
        })
    }

    fn end(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

fn page_id(opened: &Value) -> String {
    opened["pageId"].as_str().unwrap().to_owned()
}

/// A snapshot as the MCP server shows it (mcp.rs `snapshot_text`), read back into `{elements, text}`
/// with each control's `x`, `y` and quoted `text`: the JSON head line, `FRAMES`, a line per control after
/// `CONTROLS`, then the page text after `TEXT:`. `None` when `text` is not one.
fn compact_snapshot(text: &str) -> Option<Value> {
    let (head, rest) = text.split_once("\nCONTROLS\n")?;
    let (controls, page) =
        if let Some(r) = rest.strip_prefix("TEXT:\n") { ("", r) } else { rest.split_once("\nTEXT:\n")? };
    let head = head.split_once("\nFRAMES").map_or(head, |(h, _)| h);
    let mut snap: Value = serde_json::from_str(head).ok()?;
    let elements: Vec<Value> = controls.lines().map(control_line).collect::<Option<_>>()?;
    snap["elements"] = Value::Array(elements);
    snap["text"] = json!(page);
    Some(snap)
}

/// How mcp.rs's `Shown::since` starts its control lines.
const SINCE: &str = "\nCONTROLS since your last snapshot of this page (";

/// The whole snapshot that `changes` (mcp.rs `Shown::since`) makes of `last`: `last`'s controls and text
/// lines without the gone ones, then the new ones.
fn rebuild(last: &str, changes: &str) -> Option<String> {
    let (head, rest) = changes.split_once(SINCE)?;
    let (_, rest) = rest.split_once('\n')?;
    let (_, last_rest) = last.split_once("\nCONTROLS\n")?;
    let (last_controls, last_text) = last_rest
        .strip_prefix("TEXT:\n")
        .map_or_else(|| last_rest.split_once("\nTEXT:\n"), |t| Some(("", t)))?;
    let (sections, text_new) = rest.split_once("TEXT since your last snapshot of this page (")?;
    let (_, text_new) = text_new.split_once("):\n")?;
    let (mut new, mut gone, mut text_gone) = (Vec::new(), Vec::new(), Vec::new());
    let mut into = &mut new;
    for line in sections.lines() {
        match line {
            "GONE" => into = &mut gone,
            "TEXT GONE" => into = &mut text_gone,
            l => into.push(l.to_owned()),
        }
    }
    let text_gone: Vec<String> =
        text_gone.iter().map(|t| serde_json::from_str(t).ok()).collect::<Option<_>>()?;
    let without = |lines: Vec<&str>, gone: &[String]| -> Vec<String> {
        let mut gone = gone.to_vec();
        lines
            .into_iter()
            .filter(|l| match gone.iter().position(|g| g == l) {
                Some(i) => {
                    gone.remove(i);
                    false
                }
                None => true,
            })
            .map(str::to_owned)
            .collect()
    };
    let mut controls = without(last_controls.lines().collect(), &gone);
    controls.extend(new);
    let mut text = without(last_text.lines().filter(|l| !l.trim().is_empty()).collect(), &text_gone);
    text.extend(text_new.lines().map(str::to_owned));
    let mut out = format!("{head}\nCONTROLS\n");
    for c in controls {
        out.push_str(&c);
        out.push('\n');
    }
    out.push_str("TEXT:\n");
    out.push_str(&text.join("\n"));
    Some(out)
}

/// The changes mcp.rs's `a_repeat_snapshot_shows_what_changed` shows, read back whole.
#[test]
fn a_snapshot_since_reads_back() {
    let last = "{\"pageId\":\"p\"}\nCONTROLS\n0,0 a \"Nav\" /n\n1,50 button \"Add\"\nTEXT:\nLine 0\nCart: 0";
    let changes = "{\"pageId\":\"p\"}\n\
                   CONTROLS since your last snapshot of this page (1 more as before, not repeated)\n\
                   1,50 button \"Added\"\n\
                   GONE\n\
                   1,50 button \"Add\"\n\
                   TEXT GONE\n\
                   \"Cart: 0\"\n\
                   TEXT since your last snapshot of this page (1 more lines as before, not repeated):\n\
                   Cart: 1\nThanks";
    let whole = rebuild(last, changes).unwrap();
    assert_eq!(
        whole,
        "{\"pageId\":\"p\"}\nCONTROLS\n0,0 a \"Nav\" /n\n1,50 button \"Added\"\nTEXT:\nLine 0\nCart: 1\nThanks"
    );
    assert_eq!(control(&compact_snapshot(&whole).unwrap(), "Added")["y"], 50);
    assert_eq!(rebuild(last, "{}\nCONTROLS\nTEXT:\n"), None);
}

/// One control line, `x,y tag#id name=.. "text" href flags`: its x, y and its first standalone quoted
/// string as `text` (a quoted value inside `#..` or `name=..` is skipped whole).
fn control_line(line: &str) -> Option<Value> {
    let (xy, mut rest) = line.split_once(' ')?;
    let (x, y) = xy.split_once(',')?;
    let mut el = json!({ "x": x.parse::<i64>().ok()?, "y": y.parse::<i64>().ok()? });
    let quoted = |s: &str| -> Option<(String, usize)> {
        let mut it = serde_json::Deserializer::from_str(s).into_iter::<String>();
        let v = it.next()?.ok()?;
        Some((v, it.byte_offset()))
    };
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if rest.starts_with('"') {
            let (v, used) = quoted(rest)?;
            if el.get("text").is_none() {
                el["text"] = json!(v);
            }
            rest = &rest[used..];
            continue;
        }
        let end = rest.find(|c: char| c.is_whitespace() || c == '"').unwrap_or(rest.len());
        rest = &rest[end..];
        if rest.starts_with('"') {
            let (_, used) = quoted(rest)?;
            rest = &rest[used..];
        }
    }
    Some(el)
}

/// The text mcp.rs's `a_snapshot_is_shown_as_lines` expects, read back.
#[test]
fn a_compact_snapshot_reads_back() {
    let shown = "{\"pageId\":\"p\",\"url\":\"http://h/a\",\"title\":\"T\",\"elementsOmitted\":0}\n\
                 FRAMES f1=http://twin:9\n\
                 CONTROLS\n\
                 3,4 a \"Home\" /a#home\n\
                 10,20 input#email name=email type=email \"Your email\" offscreen\n\
                 1,2 button shadow f1\n\
                 -5,6 a \"Go \\\"now\\\"\" \"https://x.test/a b\" f1 role=\"tab\"\n\
                 TEXT:\n\
                 Line one\nLine \"two\"";
    let snap = compact_snapshot(shown).unwrap();
    assert_eq!(snap["pageId"], "p");
    assert_eq!(snap["text"], "Line one\nLine \"two\"");
    assert_eq!(control(&snap, "Go \"now\"")["x"], -5);
    assert_eq!(control(&snap, "Your email")["y"], 20);
    assert_eq!(snap["elements"][2], json!({ "x": 1, "y": 2 }));
    let id_quoted = compact_snapshot("{}\nCONTROLS\n7,8 a#\"a b\" name=\"c d\" \"Real\"\nTEXT:\n").unwrap();
    assert_eq!(id_quoted["elements"][0]["text"], "Real");
    assert_eq!(compact_snapshot("{}\nCONTROLS\nTEXT:\nonly text").unwrap()["text"], "only text");
    assert_eq!(compact_snapshot("{\"a\":1}"), None);
}

/// The control a snapshot lists with this text (exact), for `click_xy`.
fn control<'a>(snap: &'a Value, text: &str) -> &'a Value {
    snap["elements"]
        .as_array()
        .and_then(|es| es.iter().find(|e| e["text"] == json!(text)))
        .unwrap_or_else(|| panic!("no control {text:?} in {snap}"))
}

fn click_xy(m: &mut Mcp, page: &str, el: &Value) -> Value {
    m.act(page, json!({ "action": "click_xy", "x": el["x"], "y": el["y"] }))
}

fn post<'a>(
    posts: &'a [phantab_testkit::RecordedRequest],
    path: &str,
) -> &'a phantab_testkit::RecordedRequest {
    let mine: Vec<_> = posts.iter().filter(|p| p.path == path).collect();
    assert_eq!(mine.len(), 1, "posts to {path}: {posts:?}");
    mine[0]
}

/// The scripted tasks. Each is the plain path a careful agent takes today; none uses a selector the page
/// does not show it, except where the snapshot lists the control's id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_tasks_cost_and_keep_what_agents_need() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;
    let url = |task: &str| lane.fixtures.url(TASKS.iter().find(|t| t.0 == task).unwrap().1);
    let report = tokio::task::block_in_place(|| {
        let mut m = Mcp::start(&lane.rt);
        m.call("status", &json!({}));

        // Sign in: dismiss the cookie bar, email, continue, password, keep me signed in, sign in.
        m.begin("signin");
        let p = page_id(&m.call("open", &json!({ "url": url("signin") })));
        m.snap(&p);
        m.act(&p, json!({ "action": "click", "selector": "#cookies-reject" }));
        m.act(&p, json!({ "action": "fill", "selector": "#email", "text": "ava.lindqvist@example.test" }));
        m.act(&p, json!({ "action": "click", "selector": "#continue" }));
        m.snap(&p);
        m.act(&p, json!({ "action": "fill", "selector": "#password", "text": "Fjord-Lantern-42" }));
        m.act(&p, json!({ "action": "click", "selector": "#remember" }));
        m.act(&p, json!({ "action": "click", "selector": "#submit" }));
        m.call("wait", &json!({ "pageId": p, "text": "Welcome back" }));
        m.snap(&p);
        m.must_have_read(&["Signing in as", "Keep me signed in", "Welcome back"]);
        m.call("close", &json!({ "pageId": p }));

        // Sign up: every field, the date of birth from three selects, terms on, marketing off.
        m.begin("signup");
        let p = page_id(&m.call("open", &json!({ "url": url("signup") })));
        m.snap(&p);
        for (sel, text) in [
            ("#first", "Jonas"),
            ("#last", "Weber"),
            ("#email", "jonas.weber@example.test"),
            ("#password", "Tidal#Spruce7x"),
            ("#confirm", "Tidal#Spruce7x"),
            ("#phone", "+1 902 555 0143"),
        ] {
            m.act(&p, json!({ "action": "fill", "selector": sel, "text": text }));
        }
        for (sel, value) in
            [("#dob-month", "3"), ("#dob-day", "14"), ("#dob-year", "1988"), ("#country", "Canada")]
        {
            m.act(&p, json!({ "action": "select", "selector": sel, "text": value }));
        }
        m.act(&p, json!({ "action": "click", "selector": "#terms" }));
        m.act(&p, json!({ "action": "click", "selector": "#marketing" }));
        m.act(&p, json!({ "action": "click", "selector": "#create" }));
        m.call("wait", &json!({ "pageId": p, "text": "NW-58213" }));
        m.snap(&p);
        m.must_have_read(&["Send me offers", "At least 10 characters", "NW-58213"]);
        m.call("close", &json!({ "pageId": p }));

        // A long article: one fact deep in the page, with a distractor that closed the same year.
        m.begin("article");
        let p = page_id(&m.call("open", &json!({ "url": url("article") })));
        m.snap(&p);
        m.must_have_read(&["The Tillamook spur closed in 1957", "Surveyed at 38.6 km"]);
        m.call("close", &json!({ "pageId": p }));

        // Large data: one customer's refunds out of 1,200 orders, by search and a status filter.
        m.begin("orders");
        let p = page_id(&m.call("open", &json!({ "url": url("orders") })));
        m.snap(&p);
        m.act(&p, json!({ "action": "fill", "selector": "#search", "text": "Marta Quist" }));
        m.act(&p, json!({ "action": "select", "selector": "#status", "text": "Refunded" }));
        m.snap(&p);
        m.must_have_read(&[
            "3 orders",
            "NW-10190",
            "NW-10455",
            "NW-10877",
            "2026-08-08",
            "$23.75",
            "$64.95",
            "$149.50",
        ]);
        m.call("close", &json!({ "pageId": p }));

        // A heavy SPA: shadow-DOM nav and cards, a filtered virtualized list of shadow rows, a cross-site frame.
        m.begin("app");
        let p = page_id(&m.call("open", &json!({ "url": url("app") })));
        let s = m.snap(&p);
        click_xy(&mut m, &p, control(&s, "Projects"));
        let s = m.snap(&p);
        click_xy(&mut m, &p, control(&s, "Open Orion"));
        m.call("wait", &json!({ "pageId": p, "selector": "#task-filter" }));
        m.snap(&p);
        m.act(&p, json!({ "action": "fill", "selector": "#task-filter", "text": "billing exports" }));
        let s = m.snap(&p);
        m.must_have_read(&[
            "ORI-3127 · Migrate billing exports",
            "Priya Nandakumar",
            "ORI-3128",
            "Mark all read",
        ]);
        click_xy(&mut m, &p, control(&s, "Mark Migrate billing exports done"));
        // wait reads the main document only, and the row is in a shadow root: read again instead.
        m.snap(&p);
        m.must_have_read(&["Migrate billing exports (done)"]);
        m.call("close", &json!({ "pageId": p }));

        // A five-step checkout: two products with options, a coupon, an address, delivery, payment, review.
        m.begin("shop");
        let p = page_id(&m.call("open", &json!({ "url": url("shop") })));
        m.snap(&p);
        m.act(&p, json!({ "action": "click", "selector": "#view-NW-500" }));
        m.snap(&p);
        m.act(&p, json!({ "action": "select", "selector": "#size", "text": "M" }));
        m.act(&p, json!({ "action": "click", "selector": "#colour-slate" }));
        m.act(&p, json!({ "action": "fill", "selector": "#qty", "text": "2" }));
        m.act(&p, json!({ "action": "click", "selector": "#add" }));
        m.act(&p, json!({ "action": "click", "selector": "#more" }));
        m.act(&p, json!({ "action": "click", "selector": "#view-NW-505" }));
        m.act(&p, json!({ "action": "click", "selector": "#add" }));
        m.act(&p, json!({ "action": "click", "selector": "#go-cart" }));
        m.act(&p, json!({ "action": "fill", "selector": "#coupon", "text": "TRAIL15" }));
        m.act(&p, json!({ "action": "click", "selector": "#apply" }));
        m.snap(&p);
        m.act(&p, json!({ "action": "click", "selector": "#checkout" }));
        m.snap(&p);
        for (sel, text) in [
            ("#name", "Jonas Weber"),
            ("#line1", "12 Harbour St"),
            ("#line2", "Apt 4"),
            ("#city", "Halifax"),
            ("#postal", "B3H 1A1"),
            ("#phone", "902-555-0143"),
        ] {
            m.act(&p, json!({ "action": "fill", "selector": sel, "text": text }));
        }
        m.act(&p, json!({ "action": "select", "selector": "#region", "text": "NS" }));
        m.act(&p, json!({ "action": "select", "selector": "#country", "text": "Canada" }));
        m.act(&p, json!({ "action": "click", "selector": "#next" }));
        m.snap(&p);
        m.act(&p, json!({ "action": "click", "selector": "#d-standard" }));
        m.act(&p, json!({ "action": "click", "selector": "#next" }));
        m.act(&p, json!({ "action": "click", "selector": "#p-invoice" }));
        m.act(&p, json!({ "action": "click", "selector": "#next" }));
        m.snap(&p);
        m.act(&p, json!({ "action": "click", "selector": "#place" }));
        m.call("wait", &json!({ "pageId": p, "text": "NW-ORD-77341" }));
        m.snap(&p);
        m.must_have_read(&["TRAIL15", "Total $395.40", "NW-ORD-77341", "$395.40"]);
        m.call("close", &json!({ "pageId": p }));

        let report = m.report();
        m.end();
        report
    });

    // End states, from what the pages sent (the task board posts after it repaints, so give it a moment).
    let end = Instant::now() + Duration::from_secs(10);
    while !lane.fixtures.posts().iter().any(|p| p.path == "/post/cost-task") && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let posts = lane.fixtures.posts();
    let signin = post(&posts, "/post/cost-signin");
    assert_eq!(signin.form("email").as_deref(), Some("ava.lindqvist@example.test"));
    assert_eq!(signin.form("password").as_deref(), Some("Fjord-Lantern-42"));
    assert_eq!(signin.form("remember").as_deref(), Some("on"));
    let signup = post(&posts, "/post/cost-signup");
    for (k, v) in [
        ("first", "Jonas"),
        ("last", "Weber"),
        ("email", "jonas.weber@example.test"),
        ("password", "Tidal#Spruce7x"),
        ("dob", "1988-3-14"),
        ("country", "Canada"),
        ("phone", "+1 902 555 0143"),
        ("terms", "on"),
        ("marketing", "off"),
    ] {
        assert_eq!(signup.form(k).as_deref(), Some(v), "signup {k}: {}", signup.body);
    }
    let task = post(&posts, "/post/cost-task");
    assert_eq!(task.form("task").as_deref(), Some("ORI-3127"), "{}", task.body);
    let order: Value = serde_json::from_str(&post(&posts, "/post/cost-order").body).unwrap();
    assert_eq!(order["total"], json!(395.4), "{order}");
    assert_eq!(order["coupon"], json!("TRAIL15"));
    assert_eq!(order["delivery"], json!("standard"));
    assert_eq!(order["payment"], json!("invoice"));
    assert_eq!(order["ship"]["region"], json!("NS"));
    assert_eq!(
        order["items"],
        json!([
            { "sku": "NW-500", "name": "Ridgeline Rain Shell", "size": "M", "colour": "Slate", "qty": 2 },
            { "sku": "NW-505", "name": "Trailhead Daypack 22L", "size": null, "colour": null, "qty": 1 },
        ])
    );
    eprintln!("lane3 cost {report}");
    lane.finish().await;
}

/// Keeps one lane up for a real agent (see the module comment). Each agent run takes its own lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hold_a_lane_for_real_agents() {
    let Some(dir) = std::env::var_os("PHANTAB_TEST_COST_HOLD").map(PathBuf::from) else { return };
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let secs: u64 =
        std::env::var("PHANTAB_TEST_COST_HOLD_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(1800);
    let lane = Lane::start(&chrome).await;
    std::fs::create_dir_all(&dir).unwrap();
    let urls: serde_json::Map<String, Value> =
        TASKS.iter().map(|(name, path)| ((*name).to_owned(), json!(lane.fixtures.url(path)))).collect();
    let info = json!({
        "bin": env!("CARGO_BIN_EXE_phantab"),
        "runtime": lane.rt.path(),
        "env": lane.mcp_env(),
        "scrub": ["PHANTAB_CLIENT", "CODEX_THREAD_ID", "CODEX_SESSION_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID", "RUST_LOG"],
        "urls": urls,
        "pid": std::process::id(),
    });
    write_atomic(&dir.join("lane.json"), &info.to_string());
    let (stop, end) = (dir.join("stop"), Instant::now() + Duration::from_secs(secs));
    let mut written = 0;
    let mut log =
        std::fs::OpenOptions::new().create(true).append(true).open(dir.join("posts.jsonl")).unwrap();
    loop {
        let posts = lane.fixtures.posts();
        for p in &posts[written..] {
            let record = json!({ "method": p.method, "path": p.path, "query": p.query, "body": p.body, "form": p.form_pairs() });
            writeln!(log, "{record}").unwrap();
        }
        log.flush().unwrap();
        written = posts.len();
        if stop.exists() || Instant::now() >= end {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    lane.finish().await;
}

fn write_atomic(path: &Path, text: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}
