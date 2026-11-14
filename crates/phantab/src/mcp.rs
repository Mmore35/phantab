//! `phantab mcp`: the MCP stdio server agents load. Each tool is one service method under the
//! name `browser_<method>`; the service does the work.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, InitializeResult,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt as _};
use serde_json::{Value, json};

use crate::paths;
use crate::runtime::rpc;

/// The server name clients show, unless `--server-name` gives another.
pub const DEFAULT_SERVER_NAME: &str = "phantab";
pub(crate) const HEARTBEAT_EVERY: Duration = Duration::from_secs(30);

/// `(method, description, properties, required)`, in the order `tools/list` gives them (ARCHITECTURE §
/// Names and constants; `tests/mcp.rs` checks the list byte for byte against its golden file).
fn defs() -> Vec<(&'static str, &'static str, Value, &'static [&'static str])> {
    let s = || json!({ "type": "string" });
    let page = || json!({ "pageId": s() });
    let number = || json!({ "type": "number" });
    // An action's own fields: `act`'s, and each of its `then` steps'.
    let action = || json!({ "action": { "type": "string", "enum": ["navigate", "click", "fill", "select", "press", "scroll", "click_xy"] }, "selector": s(), "text": s(), "url": s(), "key": s(), "x": number(), "y": number(), "deltaY": number() });
    let mut act = json!({ "pageId": s() });
    if let (Value::Object(a), Value::Object(fields)) = (&mut act, action()) {
        a.extend(fields);
        let step = json!({ "type": "object", "properties": action(), "required": ["action"], "additionalProperties": false });
        a.insert("then".into(), json!({ "type": "array", "items": step }));
        let list = json!({ "type": "array", "items": { "type": ["string", "number"] } });
        a.insert("steps".into(), json!({ "type": "array", "items": list }));
        a.insert("snapshot".into(), json!({ "type": "boolean" }));
        // The guardrails' owner confirmation (docs/GUARDRAILS.md) is the first action's alone: a `then`
        // step it would refuse is repeated on its own, once the owner approves that step.
        a.insert("ownerConfirmed".into(), json!({ "type": "boolean" }));
    }
    vec![
        (
            "status",
            "Check the shared browser connection without opening Chrome or showing prompts.",
            json!({}),
            &[],
        ),
        (
            "pages",
            "Find your current working pages after a conversation resumes. Recover an orphaned human handoff with browser_resume; with guardrails full, only after explicit owner confirmation.",
            json!({}),
            &[],
        ),
        (
            "connect",
            "Wait up to 10 s for the phantab bridge extension in the configured everyday Chrome profile and report the connection. Never shows a prompt; other tools wait for the bridge themselves, so this is not a required first step. profile asks about another Chrome profile the owner allowed, by its name or folder; a closed one starts without a window first, which can take up to 15 s.",
            json!({ "profile": s() }),
            &[],
        ),
        (
            "open",
            "Open an independent invisible page sharing the owner Chrome login by default. visible explicitly opens a normal owner tab. isolated-headless has separate login. Does not control existing tabs. With snapshot true, the result ends with the new page's snapshot, as browser_snapshot shows it, so opening a page and reading it is one call. profile opens it in another Chrome profile the owner allowed, by its name or folder (default: the everyday one); a closed one starts without a window.",
            json!({ "url": s(), "mode": { "type": "string", "enum": ["shared-hidden", "visible", "isolated-headless"] }, "snapshot": { "type": "boolean" }, "profile": s() }),
            &["url"],
        ),
        (
            "tabs",
            "List available existing website tabs with stable IDs; no focus changes. Use only when the task needs an existing owner tab. profile lists another allowed Chrome profile's tabs.",
            json!({ "profile": s() }),
            &[],
        ),
        (
            "attach",
            "Attach to the exact existing tab requested by the owner. Never choose merely by matching a domain when multiple tabs exist. profile names the allowed Chrome profile the tab is in.",
            json!({ "tabId": s(), "profile": s() }),
            &["tabId"],
        ),
        (
            "snapshot",
            "Read a page: its text and the controls a person could use, through open shadow roots and website frames. The result is one JSON line of page fields, then a line per control after CONTROLS: x,y for the click_xy action, tag#id, name=, type=, its text in quotes, a link's href (only its #part when it goes to a place on this page), then flags; offscreen means scroll to it first. Controls marked fN (frame N of the FRAMES line) or shadow take click_xy and press, because selectors reach the main document only. The page text comes last, after TEXT:. framesUnread above 0 means some frames did not answer in time, so read again. framesSkipped and elementsOmitted count what the size limits left out. Typed values in input fields are not read, but a ticked box or radio shows checked and a select its chosen option as selected=; text the page displays is read, including editable areas. A repeat snapshot of a page shows only the controls and text lines changed since your last one, when that is shorter, and every result leaves out page fields unchanged since your last one for that page; full true shows everything. Leave pageId out for the page your last call named.",
            json!({ "pageId": s(), "full": { "type": "boolean" } }),
            &[],
        ),
        ("screenshot", "Capture the assigned page for visual inspection. Leave pageId out for the page your last call named.", page(), &[]),
        (
            "wait",
            "Wait for a CSS selector or visible text in the assigned page without stealing focus; or, with only seconds (up to 60), just pause. With verification true, wait instead for the page's verification check to reach the owner or end (up to seconds, at most 60): its verification.state says how, and its next says what to do; while the owner has it, verification.wake is a command to start in the background before you end your turn, which exits once the check ends. Leave pageId out for the page your last call named.",
            json!({ "pageId": s(), "selector": s(), "text": s(), "seconds": { "type": "number" }, "verification": { "type": "boolean" } }),
            &[],
        ),
        (
            "act",
            "Interact with your assigned page. steps lists the actions to do, in order, each a list: [\"click\", selector], [\"fill\", selector, text], [\"select\", selector, value or label], [\"press\", key], [\"scroll\", deltaY], [\"click_xy\", x, y] or [\"navigate\", url]. The first that fails stops the rest and says which, and the result ends with the page's snapshot after them, or after the failure, as browser_snapshot shows it (snapshot false leaves it out), so a run of steps and its check is one call. action with its fields is the older form of one step, and then of the ones after it (each with this tool's fields but pageId); with them the snapshot comes only with snapshot true. Agent writes are blocked during owner takeover; site changes are reserved against other agents. With guardrails light or full, a click or press that reads as a payment or checkout, a password or two-factor change, or deleting an account or vault items is refused until you repeat it with ownerConfirmed true, set only after the owner explicitly approves that step; it covers the first step. Leave pageId out for the page your last call named.",
            act,
            &[],
        ),
        (
            "show",
            "Show the exact working page to the owner and pause agent writes. Shared workspaces reveal the actual Chrome window with unsaved state intact; isolated headless pages use a local interactive view. With verification true, hand the owner the page's verification check (one reported as state widget); Phantab takes the page back by itself once it clears, and the result's verification.wake, started in the background before you end your turn, exits then so your harness wakes you.",
            json!({ "pageId": s(), "verification": { "type": "boolean" } }),
            &["pageId"],
        ),
        (
            "resume",
            "Resume after owner handback. For live views the owner clicks Return to agent; for ordinary visible tabs set ownerConfirmed after explicit user handback. With guardrails full, resume waits for one of those. A shared page goes back to its fixed hidden size, so coordinates read during the takeover no longer apply.",
            json!({ "pageId": s(), "ownerConfirmed": { "type": "boolean" } }),
            &["pageId"],
        ),
        (
            "sign_in",
            "Sign in to the site on this page with its saved login, with no secret ever shown to you. Sign-in only: refuses sign-up and paying forms. Returns a status and never a secret; call again per step (next-step). Never claims signed-in: snapshot to see where it landed. account picks one saved login by its exact name when status is ambiguous. Statuses: README.md of phantab.",
            json!({ "pageId": s(), "account": s() }),
            &["pageId"],
        ),
        (
            "close",
            "Close only agent-created pages; detach from owner tabs without closing them. Refuses while owner takeover is active.",
            page(),
            &["pageId"],
        ),
    ]
}

/// The tool list exactly as `tools/list` returns it.
///
/// # Errors
/// Never in practice: the definitions are fixed.
pub fn tools() -> anyhow::Result<Vec<Tool>> {
    defs()
        .into_iter()
        .map(|(name, description, properties, required)| {
            let tool = json!({
                "name": format!("browser_{name}"),
                "description": description,
                "inputSchema": { "type": "object", "properties": properties, "required": required, "additionalProperties": false },
            });
            Ok(serde_json::from_value(tool)?)
        })
        .collect()
}

/// The agent session ids a client id is taken from, in order. Claude Code sets `CLAUDE_CODE_SESSION_ID`,
/// which stays the same when a host ends an idle `claude` process and a new one resumes the conversation,
/// so the resumed session keeps its pages; a random id would lose them.
const SESSION_ENV: &[&str] =
    &["CODEX_THREAD_ID", "CODEX_SESSION_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID"];

/// The id this server's calls carry: `PHANTAB_CLIENT` as given, else the agent session's, else a fresh
/// one. A session id survives a client reload, so its pages do too.
fn client_id() -> anyhow::Result<String> {
    client_id_from(|k| std::env::var(k).ok())
}

/// [`client_id`] over a given environment.
fn client_id_from(var: impl Fn(&str) -> Option<String>) -> anyhow::Result<String> {
    let env = |k: &str| var(k).filter(|v| !v.is_empty());
    if let Some(c) = env(paths::CLIENT_ENV) {
        // SR-26: 1 to 150 characters, checked here so a bad id fails at start, not on every call.
        anyhow::ensure!(
            crate::util::client_id_ok(&c),
            "{} must be at most {} characters.",
            paths::CLIENT_ENV,
            crate::util::CLIENT_ID_MAX
        );
        return Ok(c);
    }
    // A session id too long to fit is skipped, never cut: a cut id could name another session.
    if let Some(s) = SESSION_ENV
        .iter()
        .find_map(|k| env(k).map(|s| format!("session:{s}")).filter(|c| crate::util::client_id_ok(c)))
    {
        return Ok(s);
    }
    Ok(crate::util::uuid_v4()?)
}

#[derive(Debug, Clone)]
struct Server {
    name: Arc<str>,
    client: Arc<str>,
    tools: Arc<Vec<Tool>>,
    /// What this server showed its agent of each page.
    seen: Arc<Mutex<Seen>>,
}

/// The methods whose `pageId` may be left out for the page the agent's last call named or opened. In
/// climb 2026-11-13-phantab-2x-faster-than-competition's agent runs, wall time followed the agent's
/// output tokens, about 9 ms each, and each argument it wrote cost about 20 of them beyond its value:
/// nearly every call named the one page it had open. `close`, `show`, `resume` and `sign_in` still
/// name theirs, so none of them reaches a page by default.
const DEFAULT_PAGE: &[&str] = &["snapshot", "screenshot", "wait", "act"];

/// How many characters of a page id an agent is shown. Every call names its page, and a whole v4 UUID
/// is about 20 tokens of the agent's own output each time, the dearest tokens it writes (climb
/// 2026-11-10-phantab-2x-cheaper step 5). 8 hex digits tell an agent's pages apart; a page whose
/// first 8 another page already holds is shown with 8 more.
const SHORT_ID: usize = 8;

/// The page fields an answer leaves out when they are as this server last showed them for that page:
/// `describe`'s (engine/recover.rs) and a snapshot's. `pageId` stays, so each answer still names its
/// page, and so does `framesUnread`, which above 0 asks for another read; `detached`, `dialogs` and
/// `verification` say something new each time.
const PAGE_FIELDS: &[&str] = &[
    "url",
    "mode",
    "paused",
    "ownsTab",
    "title",
    "framesSkipped",
    "shadowRoots",
    "elementsOmitted",
    "frames",
];

/// What this server showed its agent, by the service's own page id.
#[derive(Debug, Default)]
struct Seen {
    /// Each page id as shown to the agent, to the service's.
    whole: HashMap<String, String>,
    /// The service's page id to the one shown.
    shown_as: HashMap<String, String>,
    /// The page fields last shown for each page.
    fields: HashMap<String, serde_json::Map<String, Value>>,
    /// The last snapshot shown of each page, so a repeat can show only what changed.
    snapshots: HashMap<String, Shown>,
    /// The service's id of the page the agent's last call named or opened, for a call that leaves
    /// `pageId` out ([`DEFAULT_PAGE`]).
    last: Option<String>,
}

impl Seen {
    /// The id `id` is shown as: its first [`SHORT_ID`] characters, or more when another page holds those.
    fn short(&mut self, id: &str) -> String {
        if let Some(s) = self.shown_as.get(id) {
            return s.clone();
        }
        let mut n = SHORT_ID;
        let short = loop {
            let s: String = id.chars().take(n).collect();
            if s.len() == id.len() || !self.whole.contains_key(&s) {
                break s;
            }
            n += SHORT_ID;
        };
        self.whole.insert(short.clone(), id.to_owned());
        self.shown_as.insert(id.to_owned(), short.clone());
        short
    }

    /// Every `pageId` in `value` as the agent is shown it.
    fn shorten(&mut self, value: &mut Value) {
        match value {
            Value::Object(m) => {
                for (k, v) in m.iter_mut() {
                    match v {
                        Value::String(id) if k == "pageId" => *id = self.short(id),
                        other => self.shorten(other),
                    }
                }
            }
            Value::Array(a) => {
                for v in a {
                    self.shorten(v);
                }
            }
            _ => {}
        }
    }

    /// Leaves out of `answer` (for `page`, the service's id) the [`PAGE_FIELDS`] that are as last shown,
    /// unless `everything`; then holds them all as last shown.
    fn trim(&mut self, page: &str, answer: &mut serde_json::Map<String, Value>, everything: bool) {
        let last = self.fields.entry(page.to_owned()).or_default();
        for k in PAGE_FIELDS {
            let Some(v) = answer.get(*k).cloned() else { continue };
            if !everything && last.get(*k) == Some(&v) {
                answer.remove(*k);
            }
            last.insert((*k).to_owned(), v);
        }
    }

    /// Drops what was shown of a closed page; its id stays known, so a late call still names it.
    fn forget(&mut self, page: &str) {
        self.fields.remove(page);
        self.snapshots.remove(page);
        if self.last.as_deref() == Some(page) {
            self.last = None;
        }
    }
}

/// Every string under a `pageId` key in `value`.
fn page_ids(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::Object(m) => {
            for (k, v) in m {
                match v {
                    Value::String(id) if k == "pageId" => into.push(id.clone()),
                    other => page_ids(other, into),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|v| page_ids(v, into)),
        _ => {}
    }
}

/// A snapshot in the parts an agent reads, as [`Shown::full`] puts them together.
///
/// An agent pays per token for all of it, and as JSON every control repeats its keys and the page text
/// escapes each line break: on lane 3's cost tasks (climb 2026-11-10-phantab-2x-cheaper) a 37 k character
/// article snapshot was 16 k tokens. So it is the page's other fields as one JSON line, a `FRAMES` legend
/// when controls sit in frames, one line per control, and the text last, as the page shows it: last, so no
/// text a page shows can pass for a control line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shown {
    /// The page's other fields, one JSON line.
    head: String,
    /// `\nFRAMES f1=..`, or empty when no control sits in a frame.
    frames: String,
    controls: Vec<String>,
    text: String,
}

impl Shown {
    /// Only `null` fields and an empty `text` are dropped; a field this does not know goes on its control's
    /// line as `key=<json>`. The service's own answer, which the CLI prints, stays JSON. `None` when the
    /// answer is not a snapshot.
    fn of(value: &Value) -> Option<Self> {
        let mut head = value.as_object()?.clone();
        let Some(Value::Array(elements)) = head.remove("elements") else { return None };
        let text = match head.remove("text") {
            Some(Value::String(t)) => t,
            Some(other) => other.to_string(),
            None => String::new(),
        };
        let mut frames: Vec<String> = Vec::new();
        let mut controls = Vec::with_capacity(elements.len());
        for e in &elements {
            let e = e.as_object()?;
            let field = |k: &str| e.get(k).map_or_else(|| "?".to_owned(), Value::to_string);
            let tag = e.get("tag").and_then(Value::as_str).unwrap_or("?");
            let mut line = format!("{},{} {tag}", field("x"), field("y"));
            for (k, v) in e {
                match (k.as_str(), v) {
                    ("x" | "y" | "tag", _) | (_, Value::Null) => {}
                    ("id", Value::String(s)) => {
                        let _ = write!(line, "#{}", word(s));
                    }
                    ("name" | "type", Value::String(s)) => {
                        let _ = write!(line, " {k}={}", word(s));
                    }
                    ("text", Value::String(s)) if s.is_empty() => {}
                    ("text", Value::String(s)) => {
                        let _ = write!(line, " {}", Value::String(s.clone()));
                    }
                    ("href", Value::String(s)) => {
                        let _ = write!(line, " {}", word(s));
                    }
                    ("inShadow", Value::Bool(true)) => line.push_str(" shadow"),
                    ("offscreen", Value::Bool(true)) => line.push_str(" offscreen"),
                    ("checked", Value::Bool(true)) => line.push_str(" checked"),
                    ("frame", Value::String(s)) => {
                        let n = frames.iter().position(|f| f == s).unwrap_or_else(|| {
                            frames.push(s.clone());
                            frames.len() - 1
                        });
                        let _ = write!(line, " f{}", n + 1);
                    }
                    _ => {
                        let _ = write!(line, " {k}={v}");
                    }
                }
            }
            controls.push(line);
        }
        let mut legend = String::new();
        if !frames.is_empty() {
            legend.push_str("\nFRAMES");
            for (i, f) in frames.iter().enumerate() {
                let _ = write!(legend, " f{}={}", i + 1, word(f));
            }
        }
        Some(Self { head: Value::Object(head).to_string(), frames: legend, controls, text })
    }

    /// Everything: the head, the frames, `CONTROLS` and a line per control, then `TEXT:` and the text.
    fn full(&self) -> String {
        let mut out = format!("{}{}\nCONTROLS\n", self.head, self.frames);
        for c in &self.controls {
            out.push_str(c);
            out.push('\n');
        }
        out.push_str("TEXT:\n");
        out.push_str(&self.text);
        out
    }

    /// Only what changed since `last`, the agent's last snapshot of the same page: a repeat snapshot is
    /// mostly the same controls and text again, which the agent already holds (on the cost tasks a fifth of
    /// all snapshot text, climb 2026-11-10-phantab-2x-cheaper step 4). The head is whole; then the control
    /// lines that are new or changed, those gone, the text lines gone (each a JSON string), and the new text
    /// lines last, in page order. A changed line counts as gone and new. `None` when the frames legend
    /// changed, since every `fN` would mean something else.
    fn since(&self, last: &Self) -> Option<String> {
        if self.frames != last.frames {
            return None;
        }
        let now: Vec<&str> = self.controls.iter().map(String::as_str).collect();
        let before: Vec<&str> = last.controls.iter().map(String::as_str).collect();
        let (new, gone, kept) = changes(&now, &before);
        let lines = |t: &str| -> Vec<String> {
            t.lines().filter(|l| !l.trim().is_empty()).map(str::to_owned).collect()
        };
        let (now_text, before_text) = (lines(&self.text), lines(&last.text));
        let now_text: Vec<&str> = now_text.iter().map(String::as_str).collect();
        let before_text: Vec<&str> = before_text.iter().map(String::as_str).collect();
        let (text_new, text_gone, text_kept) = changes(&now_text, &before_text);
        let mut out = format!(
            "{}{}\nCONTROLS since your last snapshot of this page ({kept} more as before, not repeated)\n",
            self.head, self.frames
        );
        for c in new {
            out.push_str(c);
            out.push('\n');
        }
        if !gone.is_empty() {
            out.push_str("GONE\n");
            for c in gone {
                out.push_str(c);
                out.push('\n');
            }
        }
        if !text_gone.is_empty() {
            out.push_str("TEXT GONE\n");
            for t in text_gone {
                let _ = writeln!(out, "{}", Value::String(t.to_owned()));
            }
        }
        let _ = writeln!(
            out,
            "TEXT since your last snapshot of this page ({text_kept} more lines as before, not repeated):"
        );
        out.push_str(&text_new.join("\n"));
        Some(out)
    }
}

/// `now` against `before`, counting repeats: the lines of `now` that `before` lacks, in order; the lines of
/// `before` that `now` lacks, in order; and how many lines both hold.
fn changes<'a, 'b>(now: &[&'a str], before: &[&'b str]) -> (Vec<&'a str>, Vec<&'b str>, usize) {
    let mut left: HashMap<&str, usize> = HashMap::new();
    for b in before {
        *left.entry(b).or_default() += 1;
    }
    let mut new = Vec::new();
    let mut kept = 0;
    for n in now {
        match left.get_mut(n) {
            Some(c) if *c > 0 => {
                *c -= 1;
                kept += 1;
            }
            _ => new.push(*n),
        }
    }
    let mut gone = Vec::new();
    for b in before {
        if let Some(c) = left.get_mut(b).filter(|c| **c > 0) {
            *c -= 1;
            gone.push(*b);
        }
    }
    (new, gone, kept)
}

/// What an agent reads for a snapshot: everything (see [`Shown`]). `None` when the answer is not a
/// snapshot.
#[cfg(test)]
fn snapshot_text(value: &Value) -> Option<String> {
    Shown::of(value).map(|s| s.full())
}

/// A value as one bare word when it is one, else as a JSON string, so a line still splits on spaces.
fn word(s: &str) -> String {
    if !s.is_empty() && !s.contains(|c: char| c.is_whitespace() || c == '"') {
        s.to_owned()
    } else {
        Value::String(s.to_owned()).to_string()
    }
}

fn result(value: Value) -> CallToolResult {
    serde_json::from_value(value)
        .unwrap_or_else(|e| failure(&format!("Browser service answer could not be shown: {e}")))
}

fn failure(message: &str) -> CallToolResult {
    let mut r = CallToolResult::default();
    r.is_error = Some(true);
    r.content = vec![rmcp::model::ContentBlock::text(message)];
    r
}

/// The method a call names, or why it is refused before it reaches the service. Reads the schemas
/// this server already lists, so a call costs no rebuild of the tool list (perf-idle-10).
fn checked<'a>(
    tools: &[Tool],
    name: &'a str,
    arguments: Option<&serde_json::Map<String, Value>>,
) -> Result<&'a str, String> {
    let method = name.strip_prefix("browser_").unwrap_or(name);
    let Some(tool) = tools.iter().find(|t| t.name.strip_prefix("browser_") == Some(method)) else {
        return Err("Unknown tool".to_owned());
    };
    let properties = tool.input_schema.get("properties").and_then(Value::as_object);
    // SR-33: `additionalProperties: false` holds, so an argument the tool does not define is an error,
    // not quietly dropped. The name is the agent's own text, so only a short piece is repeated.
    if let Some(extra) = arguments
        .into_iter()
        .flat_map(serde_json::Map::keys)
        .find(|k| !properties.is_some_and(|p| p.contains_key(k.as_str())))
    {
        let shown: String = extra.chars().take(40).collect();
        return Err(format!("Unknown argument {shown:?} for browser_{method}."));
    }
    Ok(method)
}

/// `act`'s own `then` and `snapshot`, taken out of its arguments and checked before any call reaches
/// the service: the further steps, without their page, and whether a snapshot follows. A `then` step's
/// argument that an action does not define is an error, as for the tool's own (SR-33). `steps` stands in
/// for the first action's fields and `then` (`act_step`), and with it the snapshot comes unless refused.
fn act_plan(
    arguments: &mut serde_json::Map<String, Value>,
    properties: &Value,
) -> Result<(Vec<serde_json::Map<String, Value>>, bool), String> {
    let fields = &properties["then"]["items"]["properties"];
    if let Some(steps) = arguments.remove("steps") {
        if let Some(both) = arguments.keys().find(|k| k.as_str() == "then" || fields.get(k.as_str()).is_some()) {
            let shown: String = both.chars().take(40).collect();
            return Err(format!("steps takes the place of action, its fields and then: leave {shown:?} out."));
        }
        let Value::Array(items) = steps else { return Err(STEPS_FORM.to_owned()) };
        if items.is_empty() {
            return Err(STEPS_FORM.to_owned());
        }
        let mut plan = items.iter().enumerate().map(|(i, item)| act_step(item, i + 1)).collect::<Result<Vec<_>, _>>()?;
        let then = plan.split_off(1);
        arguments.extend(plan.remove(0));
        // Every cost-task call that acted and then looked at the page asked for the snapshot, so the
        // compact form gives it unless refused.
        let snapshot = match arguments.remove("snapshot") {
            None | Some(Value::Bool(true)) => true,
            Some(Value::Bool(false)) => false,
            Some(_) => return Err("snapshot must be true or false.".to_owned()),
        };
        return Ok((then, snapshot));
    }
    if !arguments.contains_key("action") {
        return Err("browser_act needs steps, or action with its fields.".to_owned());
    }
    let snapshot = snapshot_after(arguments)?;
    let mut steps = Vec::new();
    match arguments.remove("then") {
        None => {}
        Some(Value::Array(then)) => {
            for (i, step) in then.into_iter().enumerate() {
                let Value::Object(step) = step else {
                    return Err(format!("then item {} must be an object of action fields.", i + 1));
                };
                if let Some(extra) = step.keys().find(|k| fields.get(k.as_str()).is_none()) {
                    let shown: String = extra.chars().take(40).collect();
                    return Err(format!("Unknown argument {shown:?} in then item {}.", i + 1));
                }
                steps.push(step);
            }
        }
        Some(_) => return Err("then must be a list of actions.".to_owned()),
    }
    Ok((steps, snapshot))
}

/// What `act`'s `steps` must be, said when they are not.
const STEPS_FORM: &str = "steps must be a list of actions, each a list: [\"click\", selector], [\"fill\", selector, text], [\"select\", selector, value or label], [\"press\", key], [\"scroll\", deltaY], [\"click_xy\", x, y] or [\"navigate\", url].";

/// Item `n` of `act`'s `steps` as the action fields it stands for: `["fill", "#qty", "2"]` is
/// `{"action": "fill", "selector": "#qty", "text": "2"}`. In climb
/// 2026-11-13-phantab-2x-faster-than-competition's agent runs, wall time followed the agent's output
/// tokens, and each field it named cost about 20 of them beyond its value: a five-step act wrote
/// `action` and `selector` five times over. A number stands for itself where one is wanted, and for its
/// digits where text is; a number written as text is read as one.
fn act_step(item: &Value, n: usize) -> Result<serde_json::Map<String, Value>, String> {
    let bad = || format!("steps item {n}: each must be {}", &STEPS_FORM["steps must be a list of actions, each ".len()..]);
    let Some(parts) = item.as_array() else { return Err(bad()) };
    let Some(action) = parts.first().and_then(Value::as_str) else { return Err(bad()) };
    let names: &[&str] = match action {
        "click" => &["selector"],
        "fill" | "select" => &["selector", "text"],
        "press" => &["key"],
        "scroll" => &["deltaY"],
        "click_xy" => &["x", "y"],
        "navigate" => &["url"],
        _ => return Err(bad()),
    };
    if parts.len() != names.len() + 1 {
        return Err(bad());
    }
    let mut step = serde_json::Map::new();
    step.insert("action".into(), Value::String(action.to_owned()));
    for (name, v) in names.iter().zip(&parts[1..]) {
        let number = matches!(*name, "deltaY" | "x" | "y");
        let v = match v {
            Value::Number(_) if number => v.clone(),
            Value::String(t) if number => t
                .trim()
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number)
                .ok_or_else(bad)?,
            Value::String(_) => v.clone(),
            Value::Number(d) => Value::String(d.to_string()),
            _ => return Err(bad()),
        };
        step.insert((*name).to_owned(), v);
    }
    Ok(step)
}

/// `act`'s and `open`'s own `snapshot`, taken out of their arguments: whether the page's snapshot follows.
fn snapshot_after(arguments: &mut serde_json::Map<String, Value>) -> Result<bool, String> {
    match arguments.remove("snapshot") {
        None | Some(Value::Bool(false)) => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(_) => Err("snapshot must be true or false.".to_owned()),
    }
}

/// A link to a place on the page itself, shown as its `#part` alone. The service writes a link on the
/// page's own site as its path (engine/read.rs `link_path`), so each one to a section of the page repeats
/// the page's path: on the cost article (climb 2026-11-10-phantab-2x-cheaper step 7) 180 links did, a
/// twelfth of its snapshot. `url` is the page's, as the service last gave it. Links in frames stay as
/// they are: theirs are written against their own frame's document.
fn own_page_links(answer: &mut serde_json::Map<String, Value>, url: &str) {
    let Some(Value::Array(elements)) = answer.get_mut("elements") else { return };
    let Some(path) = url.find("://").and_then(|i| url[i + 3..].find('/').map(|j| i + 3 + j)) else {
        return;
    };
    let end = url.find('#').unwrap_or(url.len());
    let Some(doc) = url.get(path..end) else { return };
    for e in elements.iter_mut().filter_map(Value::as_object_mut) {
        if e.contains_key("frame") {
            continue;
        }
        if let Some(Value::String(href)) = e.get_mut("href")
            && let Some(part) = href.strip_prefix(doc).filter(|p| p.starts_with('#'))
        {
            *href = part.to_owned();
        }
    }
}

impl Server {
    fn seen(&self) -> std::sync::MutexGuard<'_, Seen> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The service's id for the page an agent named `given`. A new server (a resumed conversation) has
    /// shown no page yet, so it looks among the agent's pages for the one whose id begins so; with no
    /// single one, `given` goes to the service as it is (a whole id, or one it will refuse).
    async fn whole_id(&self, given: &str) -> String {
        {
            let seen = self.seen();
            if let Some(w) = seen.whole.get(given) {
                return w.clone();
            }
            if seen.shown_as.contains_key(given) {
                return given.to_owned();
            }
        }
        let mut ids = Vec::new();
        if let Ok(pages) = rpc("pages", json!({}), &self.client, false).await {
            page_ids(&pages, &mut ids);
        }
        if ids.iter().any(|id| id == given) {
            return given.to_owned();
        }
        ids.retain(|id| id.starts_with(given));
        match ids.as_slice() {
            [one] if !given.is_empty() => {
                let mut seen = self.seen();
                seen.whole.insert(given.to_owned(), one.clone());
                seen.shown_as.insert(one.clone(), given.to_owned());
                one.clone()
            }
            _ => given.to_owned(),
        }
    }

    /// A snapshot as the agent reads it: only what changed since its last snapshot of `page` when that
    /// is at most three quarters of the whole, else everything. A new server (a resumed conversation)
    /// holds no last snapshot, so its first one of a page is whole.
    fn show(&self, page: Option<String>, now: Shown, everything: bool) -> String {
        let full = now.full();
        let Some(page) = page else { return full };
        let mut seen = self.seen();
        let shown = &mut seen.snapshots;
        let text = match shown.get(&page) {
            Some(last) if !everything => {
                now.since(last).filter(|d| d.len() * 4 <= full.len() * 3).unwrap_or(full)
            }
            _ => full,
        };
        shown.insert(page, now);
        text
    }

    /// A service answer as the agent reads it, for every method but `screenshot`: page ids short, page
    /// fields as last shown left out, and a snapshot as lines (only what changed on a repeat, unless
    /// `everything`).
    fn answer(&self, method: &str, mut value: Value, page: Option<String>, everything: bool) -> String {
        {
            let mut seen = self.seen();
            if let Value::Object(m) = &mut value
                && let Some(p) = m.get("pageId").and_then(Value::as_str).map(str::to_owned)
            {
                seen.trim(&p, m, everything);
                if let Some(Value::String(url)) = seen.fields.get(&p).and_then(|f| f.get("url")) {
                    own_page_links(m, url);
                }
            }
            seen.shorten(&mut value);
        }
        if method == "snapshot" {
            Shown::of(&value).map_or_else(|| value.to_string(), |now| self.show(page, now, everything))
        } else {
            value.to_string()
        }
    }

    /// `act` with this server's own `then` and `snapshot`, which the service never sees. In step 5's 150 cost
    /// runs (climb 2026-11-10-phantab-2x-cheaper) an agent wrote about 75 output tokens a tool call beyond
    /// its arguments, the dearest tokens it writes, and shop made 38 calls a run: an act each, then a
    /// snapshot to check. So one call takes the run of actions, done here one by one as the service's own
    /// `act`s in order, and the snapshot after them. The answer is each action's, one line apiece, but
    /// only the last when the others say nothing past their page; then the snapshot, when asked for, and
    /// no action line at all when every one said nothing past its page, since the snapshot names it too.
    async fn act(
        &self,
        first: serde_json::Map<String, Value>,
        then: Vec<serde_json::Map<String, Value>>,
        snapshot: bool,
        page: Option<String>,
    ) -> CallToolResult {
        let mut steps = vec![first];
        for mut step in then {
            if let Some(p) = steps[0].get("pageId") {
                step.insert("pageId".into(), p.clone());
            }
            steps.push(step);
        }
        let total = steps.len();
        let mut lines = Vec::with_capacity(total);
        for (i, step) in steps.into_iter().enumerate() {
            let what = [step.get("action"), step.get("selector")]
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            let said = match rpc("act", Value::Object(step), &self.client, true).await {
                Ok(value) => {
                    lines.push(self.answer("act", value, page.clone(), false));
                    continue;
                }
                Err(e) if total == 1 => e.to_string(),
                Err(e) => {
                    let done = match i {
                        0 => "none before it was done".to_owned(),
                        1 => "the 1 before it was done".to_owned(),
                        n => format!("the {n} before it were done"),
                    };
                    format!("Step {} of {total} ({what}) failed, {done}: {e}", i + 1)
                }
            };
            // The snapshot asked for comes after a failure too: in climb
            // 2026-11-13-phantab-2x-faster-than-competition's shop runs, an agent whose step failed read
            // the page in its very next call, a turn of its own.
            return failure(&if snapshot { self.and_snapshot(said, page, false, "the failure").await } else { said });
        }
        let bare = |l: &String| matches!(serde_json::from_str::<Value>(l), Ok(Value::Object(m)) if m.len() == 1 && m.contains_key("pageId"));
        let all_bare = lines.iter().all(bare);
        if lines[..lines.len() - 1].iter().all(bare) {
            lines.drain(..lines.len() - 1);
        }
        let mut text = lines.join("\n");
        if snapshot {
            text = self.and_snapshot(text, page, all_bare, "them").await;
        }
        result(json!({ "content": [{ "type": "text", "text": text }] }))
    }

    /// `text`, then the page's snapshot as `browser_snapshot` shows it, or the snapshot alone when
    /// `alone`. A snapshot that fails adds a line saying so after `what` it followed: what came before it
    /// was done, so the answer is no failure, and the agent reads the page itself.
    async fn and_snapshot(&self, text: String, page: Option<String>, alone: bool, what: &str) -> String {
        let args = json!({ "pageId": page.clone().map_or(Value::Null, Value::String) });
        match rpc("snapshot", args, &self.client, true).await {
            Ok(value) => {
                let shown = self.answer("snapshot", value, page, false);
                if alone { shown } else { format!("{text}\n{shown}") }
            }
            Err(e) => format!("{text}\nThe snapshot after {what} failed: {e}"),
        }
    }

    async fn call(&self, name: &str, arguments: Option<serde_json::Map<String, Value>>) -> CallToolResult {
        let method = match checked(&self.tools, name, arguments.as_ref()) {
            Ok(method) => method,
            Err(refused) => return failure(&refused),
        };
        let mut arguments = arguments;
        // `full` is this server's own: the service never sees it.
        let everything = method == "snapshot"
            && arguments.as_mut().and_then(|a| a.remove("full")) == Some(Value::Bool(true));
        // So are `act`'s `then` and `snapshot`.
        let plan = match (method, arguments.as_mut()) {
            ("act", Some(a)) => {
                let tool = self.tools.iter().find(|t| t.name == "browser_act");
                let properties = tool.and_then(|t| t.input_schema.get("properties")).unwrap_or(&Value::Null);
                match act_plan(a, properties) {
                    Ok(plan) => Some(plan),
                    Err(refused) => return failure(&refused),
                }
            }
            _ => None,
        };
        // And `open`'s `snapshot`: every cost task opened a page and read it at once (step 7).
        let read_opened = match (method, arguments.as_mut()) {
            ("open", Some(a)) => match snapshot_after(a) {
                Ok(read) => read,
                Err(refused) => return failure(&refused),
            },
            _ => false,
        };
        // The agent is shown short page ids (`SHORT_ID`); the service gets its own.
        let given =
            arguments.as_ref().and_then(|a| a.get("pageId")).and_then(Value::as_str).map(str::to_owned);
        let mut page = None;
        if let (Some(given), Some(a)) = (given, arguments.as_mut()) {
            let whole = self.whole_id(&given).await;
            a.insert("pageId".into(), Value::String(whole.clone()));
            page = Some(whole);
        } else if DEFAULT_PAGE.contains(&method) {
            let Some(last) = self.seen().last.clone() else {
                return failure("No page yet to default to: open one with browser_open, or name one with pageId.");
            };
            arguments.get_or_insert_with(serde_json::Map::new).insert("pageId".into(), Value::String(last.clone()));
            page = Some(last);
        }
        if page.is_some() {
            self.seen().last.clone_from(&page);
        }
        if let (Some((then, snapshot)), Some(a)) = (plan, arguments.as_ref()) {
            return self.act(a.clone(), then, snapshot, page).await;
        }
        let args = arguments.map_or_else(|| json!({}), Value::Object);
        match rpc(method, args, &self.client, true).await {
            Ok(value) => {
                let content = if method == "screenshot" {
                    let mut image = serde_json::Map::new();
                    image.insert("type".into(), json!("image"));
                    if let Value::Object(m) = value {
                        image.extend(m);
                    }
                    Value::Object(image)
                } else if method == "snapshot" {
                    json!({ "type": "text", "text": self.answer(method, value, page, everything) })
                } else {
                    let opened = value.get("pageId").and_then(Value::as_str).map(str::to_owned);
                    if opened.is_some() && method != "close" {
                        self.seen().last.clone_from(&opened);
                    }
                    let mut text = self.answer(method, value, page.clone(), everything);
                    if read_opened && opened.is_some() {
                        text = self.and_snapshot(text, opened, false, "it").await;
                    }
                    if method == "close"
                        && let Some(p) = &page
                    {
                        self.seen().forget(p);
                    }
                    json!({ "type": "text", "text": text })
                };
                result(json!({ "content": [content] }))
            }
            Err(e) => {
                let message = e.to_string();
                let old = message.contains("Invalid method or client") && name == "browser_sign_in";
                failure(if old {
                    "This browser service predates browser_sign_in: restart the browser service when its pages are drained."
                } else {
                    &message
                })
            }
        }
    }
}

impl ServerHandler for Server {
    fn get_info(&self) -> InitializeResult {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(self.name.to_string(), env!("CARGO_PKG_VERSION")))
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListToolsResult::with_all_items(self.tools.as_ref().clone())))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        Ok(self.call(&request.name, request.arguments).await.into())
    }
}

fn server_name(args: &[String]) -> Result<String, String> {
    match args {
        [] => Ok(DEFAULT_SERVER_NAME.to_owned()),
        [flag, name] if flag == "--server-name" && !name.is_empty() => Ok(name.clone()),
        _ => Err("Usage: phantab mcp [--server-name <name>]".to_owned()),
    }
}

/// Serves MCP on stdio until the client goes away. `args` follow `mcp`.
pub async fn run(args: &[String]) -> i32 {
    let name = match server_name(args) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let (client, tools) = match (client_id(), tools()) {
        (Ok(c), Ok(t)) => (c, t),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let server = Server {
        name: name.into(),
        client: client.clone().into(),
        tools: Arc::new(tools),
        seen: Arc::default(),
    };
    let running = match server.serve(rmcp::transport::io::stdio()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let heartbeat_client = client.clone();
    tokio::spawn(async move {
        let mut every =
            tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT_EVERY, HEARTBEAT_EVERY);
        loop {
            every.tick().await;
            let _ = rpc("heartbeat", json!({}), &heartbeat_client, true).await;
        }
    });
    tokio::select! {
        _ = running.waiting() => {}
        () = stop_signal() => {}
    }
    // The pages stay for a resume; the service gives a silent client ten minutes.
    let _ = rpc("disconnect", json!({}), &client, false).await;
    // stdin's reader thread would hold the runtime open; the process is done.
    std::process::exit(0)
}

#[cfg(unix)]
async fn stop_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn stop_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fourteen_tools_with_closed_schemas() {
        let tools = tools().unwrap();
        assert_eq!(tools.len(), 14);
        assert!(tools.iter().all(|t| t.input_schema.get("additionalProperties") == Some(&json!(false))));
    }

    /// SR-33: an argument the schema does not define is an error, before any call reaches the service.
    #[tokio::test]
    async fn an_undefined_argument_is_an_error() {
        let server = Server {
            name: "phantab".into(),
            client: "t".into(),
            tools: Arc::new(tools().unwrap()),
            seen: Arc::default(),
        };
        let args = json!({ "pageId": "p", "evil": 1 }).as_object().cloned();
        let r = server.call("browser_snapshot", args).await;
        assert_eq!(r.is_error, Some(true));
        assert_eq!(
            serde_json::to_value(&r.content).unwrap()[0]["text"],
            json!("Unknown argument \"evil\" for browser_snapshot.")
        );
        let r = server.call("bogus", None).await;
        assert_eq!(serde_json::to_value(&r.content).unwrap()[0]["text"], json!("Unknown tool"));
    }

    /// perf-idle-10: a call is checked against the schemas the server lists, not a fresh build of them.
    /// Both calls here are refused before any service call, with or without this change.
    #[tokio::test]
    async fn a_call_is_checked_against_the_listed_schemas() {
        let mut listed = tools().unwrap();
        let snapshot = listed.iter_mut().find(|t| t.name == "browser_snapshot").unwrap();
        let mut schema = snapshot.input_schema.as_ref().clone();
        schema["properties"].as_object_mut().unwrap().insert("aaa".into(), json!({ "type": "string" }));
        snapshot.input_schema = Arc::new(schema);
        let server = Server {
            name: "phantab".into(),
            client: "t".into(),
            tools: Arc::new(listed),
            seen: Arc::default(),
        };
        let mut args = serde_json::Map::new();
        args.insert("aaa".into(), json!("x"));
        args.insert("zzz".into(), json!(1));
        let r = server.call("browser_snapshot", Some(args)).await;
        assert_eq!(
            serde_json::to_value(&r.content).unwrap()[0]["text"],
            json!("Unknown argument \"zzz\" for browser_snapshot.")
        );
    }

    /// The listed schemas carry exactly the properties each definition gives, so checking against
    /// them accepts and refuses the same arguments the definitions did; an unprefixed name still works.
    #[test]
    fn listed_schemas_match_the_definitions() {
        let listed = tools().unwrap();
        for (name, _, properties, _) in defs() {
            let tool = listed.iter().find(|t| t.name == format!("browser_{name}")).unwrap();
            assert_eq!(tool.input_schema.get("properties"), Some(&properties), "{name}");
            let known: serde_json::Map<String, Value> =
                properties.as_object().unwrap().keys().map(|k| (k.clone(), json!(null))).collect();
            assert_eq!(checked(&listed, &format!("browser_{name}"), Some(&known)).ok(), Some(name));
            assert_eq!(checked(&listed, name, Some(&known)).ok(), Some(name));
        }
        assert!(checked(&listed, "browser_browser_snapshot", None).is_err());
    }

    /// A link to a place on the page itself is its `#part`; any other link, and one in a frame, stays.
    #[test]
    fn links_to_the_page_itself_are_their_part() {
        let mut answer = json!({ "elements": [
            { "tag": "a", "href": "/a?x=1#s" },
            { "tag": "a", "href": "/a#s" },
            { "tag": "a", "href": "/a?x=1" },
            { "tag": "a", "href": "/a?x=1#t", "frame": "http://h" },
            { "tag": "a", "href": "https://o.test/a?x=1#s" },
            { "tag": "button" },
        ] });
        let Value::Object(m) = &mut answer else { unreachable!() };
        own_page_links(m, "http://h/a?x=1#top");
        let hrefs: Vec<&Value> = answer["elements"].as_array().unwrap().iter().map(|e| &e["href"]).collect();
        assert_eq!(
            hrefs,
            [
                &json!("#s"),
                &json!("/a#s"),
                &json!("/a?x=1"),
                &json!("/a?x=1#t"),
                &json!("https://o.test/a?x=1#s"),
                &Value::Null
            ]
        );
        // A page with no path, or no web address, leaves every link.
        for url in ["http://h", "about:blank", "http://h#x/a?x=1"] {
            let mut again = json!({ "elements": [{ "tag": "a", "href": "/a?x=1#s" }] });
            let Value::Object(m) = &mut again else { unreachable!() };
            own_page_links(m, url);
            assert_eq!(again["elements"][0]["href"], json!("/a?x=1#s"), "{url}");
        }
    }

    /// `act`'s `then` steps are checked whole before the first action reaches the service.
    #[tokio::test]
    async fn act_then_is_checked_before_any_step() {
        let server = Server {
            name: "phantab".into(),
            client: "t".into(),
            tools: Arc::new(tools().unwrap()),
            seen: Arc::default(),
        };
        let refused = |args: Value| {
            let server = server.clone();
            async move {
                let r = server.call("browser_act", args.as_object().cloned()).await;
                assert_eq!(r.is_error, Some(true));
                serde_json::to_value(&r.content).unwrap()[0]["text"].clone()
            }
        };
        let first = json!({ "pageId": "p", "action": "click", "selector": "#a" });
        let with = |k: &str, v: Value| {
            let mut a = first.clone();
            a[k] = v;
            a
        };
        let then = |steps: Value| with("then", steps);
        assert_eq!(
            refused(then(json!([{ "action": "click" }, { "action": "fill", "pageId": "q" }]))).await,
            json!("Unknown argument \"pageId\" in then item 2.")
        );
        assert_eq!(
            refused(then(json!(["click"]))).await,
            json!("then item 1 must be an object of action fields.")
        );
        assert_eq!(
            refused(then(json!({ "action": "click" }))).await,
            json!("then must be a list of actions.")
        );
        assert_eq!(refused(with("snapshot", json!("yes"))).await, json!("snapshot must be true or false."));
        // `open`'s is checked before the page is opened.
        let opened = server
            .call("browser_open", json!({ "url": "https://a.test/", "snapshot": 1 }).as_object().cloned())
            .await;
        assert_eq!(opened.is_error, Some(true));
        assert_eq!(
            serde_json::to_value(&opened.content).unwrap()[0]["text"],
            json!("snapshot must be true or false.")
        );
        assert_eq!(tools().unwrap()[3].input_schema["properties"]["snapshot"], json!({ "type": "boolean" }));
        let schema = &tools().unwrap()[9].input_schema;
        assert_eq!(schema["properties"]["then"]["items"]["required"], json!(["action"]));
        assert_eq!(schema["properties"]["snapshot"], json!({ "type": "boolean" }));
        assert_eq!(schema["required"], json!([]));
        // The compact form: one list per step, never beside the older fields, checked whole first.
        let compact = |steps: Value| json!({ "pageId": "p", "steps": steps });
        let form = &STEPS_FORM["steps must be a list of actions, each ".len()..];
        assert_eq!(
            refused(json!({ "pageId": "p", "steps": [["click", "#a"]], "selector": "#b" })).await,
            json!("steps takes the place of action, its fields and then: leave \"selector\" out.")
        );
        assert_eq!(refused(compact(json!([]))).await, json!(STEPS_FORM));
        assert_eq!(refused(compact(json!({ "click": "#a" }))).await, json!(STEPS_FORM));
        for bad in [json!([["click", "#a"], ["fill", "#b"]]), json!([["click", "#a"], ["hover", "#b"]]), json!([["click", "#a"], ["scroll", "far"]])] {
            assert_eq!(refused(compact(bad)).await, json!(format!("steps item 2: each must be {form}")));
        }
        assert_eq!(
            refused(json!({ "pageId": "p" })).await,
            json!("browser_act needs steps, or action with its fields.")
        );
        let properties = &schema["properties"];
        let plan = |a: Value| {
            let mut a = a.as_object().cloned().unwrap();
            let (then, snapshot) = act_plan(&mut a, properties).unwrap();
            (Value::Object(a), Value::Array(then.into_iter().map(Value::Object).collect()), snapshot)
        };
        let (first, then, snapshot) =
            plan(json!({ "steps": [["fill", "#qty", 2], ["click_xy", "32", 192], ["press", "Enter"]], "ownerConfirmed": true }));
        assert_eq!(first, json!({ "action": "fill", "selector": "#qty", "text": "2", "ownerConfirmed": true }));
        assert_eq!(then, json!([{ "action": "click_xy", "x": 32.0, "y": 192 }, { "action": "press", "key": "Enter" }]));
        assert!(snapshot);
        assert!(!plan(json!({ "steps": [["click", "#a"]], "snapshot": false })).2);
        // The older form keeps its snapshot opt-in.
        assert!(!plan(json!({ "action": "click", "selector": "#a" })).2);
    }

    /// A Claude Code session's id names its pages, so a resumed conversation keeps them; an earlier
    /// session variable, or `PHANTAB_CLIENT`, still wins.
    #[test]
    fn the_client_id_follows_the_agent_session() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned())
        };
        assert_eq!(client_id_from(env(&[("CLAUDE_CODE_SESSION_ID", "c1")])).unwrap(), "session:c1");
        assert_eq!(
            client_id_from(env(&[("CLAUDE_CODE_SESSION_ID", "c1"), ("CODEX_THREAD_ID", "t1")])).unwrap(),
            "session:t1"
        );
        assert_eq!(
            client_id_from(env(&[("CLAUDE_CODE_SESSION_ID", "c1"), (paths::CLIENT_ENV, "mine")])).unwrap(),
            "mine"
        );
        let random = client_id_from(env(&[("CLAUDE_CODE_SESSION_ID", "")])).unwrap();
        assert!(!random.starts_with("session:"), "{random}");
    }

    /// A snapshot reaches the agent as lines: nothing it held is lost, and keys are not repeated.
    #[test]
    fn a_snapshot_is_shown_as_lines() {
        let snap = json!({
            "pageId": "p", "url": "http://h/a", "title": "T", "elementsOmitted": 0,
            "text": "Line one\nLine \"two\"",
            "elements": [
                { "tag": "a", "text": "Home", "href": "/a#home", "x": 3, "y": 4 },
                { "tag": "input", "id": "email", "name": "email", "type": "email", "text": "Your email", "x": 10, "y": 20, "offscreen": true },
                { "tag": "button", "text": "", "x": 1, "y": 2, "inShadow": true, "frame": "http://twin:9" },
                { "tag": "a", "text": "Go \"now\"", "href": "https://x.test/a b", "x": -5, "y": 6, "frame": "http://twin:9", "role": "tab" },
            ],
        });
        let shown = snapshot_text(&snap).unwrap();
        assert_eq!(
            shown,
            "{\"pageId\":\"p\",\"url\":\"http://h/a\",\"title\":\"T\",\"elementsOmitted\":0}\n\
             FRAMES f1=http://twin:9\n\
             CONTROLS\n\
             3,4 a \"Home\" /a#home\n\
             10,20 input#email name=email type=email \"Your email\" offscreen\n\
             1,2 button shadow f1\n\
             -5,6 a \"Go \\\"now\\\"\" \"https://x.test/a b\" f1 role=\"tab\"\n\
             TEXT:\n\
             Line one\nLine \"two\""
        );
        assert_eq!(snapshot_text(&json!({ "pageId": "p" })), None);
    }

    fn page(controls: &[&str], text: &str) -> Shown {
        Shown {
            head: "{\"pageId\":\"p\"}".into(),
            frames: String::new(),
            controls: controls.iter().map(|c| (*c).to_owned()).collect(),
            text: text.into(),
        }
    }

    /// A repeat snapshot shows only what changed: new and changed controls, gone controls and text lines,
    /// then the new text last.
    #[test]
    fn a_repeat_snapshot_shows_what_changed() {
        let nav: Vec<String> = (0..20).map(|i| format!("{i},0 a \"Nav {i}\" /n{i}")).collect();
        let mut before: Vec<&str> = nav.iter().map(String::as_str).collect();
        before.push("1,50 button \"Add\"");
        let mut now: Vec<&str> = nav.iter().map(String::as_str).collect();
        now.push("1,50 button \"Added\"");
        let body = (0..20).map(|i| format!("Line {i}")).collect::<Vec<_>>().join("\n");
        let last = page(&before, &format!("{body}\nCart: 0"));
        let next = page(&now, &format!("{body}\nCart: 1\n\nThanks"));
        assert_eq!(
            next.since(&last).unwrap(),
            "{\"pageId\":\"p\"}\n\
             CONTROLS since your last snapshot of this page (20 more as before, not repeated)\n\
             1,50 button \"Added\"\n\
             GONE\n\
             1,50 button \"Add\"\n\
             TEXT GONE\n\
             \"Cart: 0\"\n\
             TEXT since your last snapshot of this page (20 more lines as before, not repeated):\n\
             Cart: 1\nThanks"
        );
        let server = Server {
            name: "phantab".into(),
            client: "t".into(),
            tools: Arc::new(tools().unwrap()),
            seen: Arc::default(),
        };
        assert_eq!(
            server.show(Some("p".into()), last.clone(), false),
            last.full(),
            "a first snapshot is whole"
        );
        assert_eq!(server.show(Some("p".into()), next.clone(), false), next.since(&last).unwrap());
        assert_eq!(
            server.show(Some("p".into()), next.clone(), true),
            next.full(),
            "full true shows everything"
        );
        assert_eq!(
            server.show(Some("q".into()), next.clone(), false),
            next.full(),
            "another page is its own"
        );
        assert_eq!(server.show(None, next.clone(), false), next.full());
    }

    /// The whole snapshot when the changes are not much shorter, or the frames legend moved.
    #[test]
    fn a_snapshot_that_changed_much_is_whole() {
        let server = Server {
            name: "phantab".into(),
            client: "t".into(),
            tools: Arc::new(tools().unwrap()),
            seen: Arc::default(),
        };
        let last = page(&["1,1 a \"A\"", "1,2 a \"B\""], "One\nTwo");
        let scrolled = page(&["1,0 a \"A\"", "1,1 a \"B\""], "One\nTwo");
        server.show(Some("p".into()), last.clone(), false);
        assert_eq!(server.show(Some("p".into()), scrolled.clone(), false), scrolled.full());
        let mut framed = last.clone();
        framed.frames = "\nFRAMES f1=http://twin:9".into();
        assert_eq!(framed.since(&last), None);
        let same = page(&["1,1 a \"A\"", "1,1 a \"A\""], "");
        let one = page(&["1,1 a \"A\""], "");
        assert_eq!(
            one.since(&same).unwrap(),
            "{\"pageId\":\"p\"}\nCONTROLS since your last snapshot of this page (1 more as before, not repeated)\nGONE\n1,1 a \"A\"\nTEXT since your last snapshot of this page (0 more lines as before, not repeated):\n",
            "a repeated line counts each time"
        );
    }

    /// Page ids are shown short and taken back whole, and an answer leaves out the page fields shown
    /// before for that page.
    #[test]
    fn pages_are_shown_short_and_fields_once() {
        let mut seen = Seen::default();
        let a = "45e44901-9e30-436d-befc-b3a81844504f";
        let b = "45e44901-0000-4000-8000-000000000000";
        let mut list = json!([{ "pageId": a, "url": "http://h/a" }, { "pageId": b }]);
        seen.shorten(&mut list);
        assert_eq!(
            list,
            json!([{ "pageId": "45e44901", "url": "http://h/a" }, { "pageId": "45e44901-0000-40" }])
        );
        assert_eq!(seen.whole["45e44901"], a);
        assert_eq!(seen.whole["45e44901-0000-40"], b);
        assert_eq!(seen.short(a), "45e44901", "the same page keeps its short id");
        let mut ids = Vec::new();
        page_ids(&json!([{ "pageId": a }, { "x": [{ "pageId": b }] }]), &mut ids);
        assert_eq!(ids, [a, b]);

        let opened = json!({ "pageId": a, "url": "http://h/a", "mode": "shared-hidden", "paused": false, "ownsTab": true });
        let mut first = opened.as_object().cloned().unwrap();
        seen.trim(a, &mut first, false);
        assert_eq!(Value::Object(first), opened, "a first answer is whole");
        let mut acted = json!({ "pageId": a, "url": "http://h/b", "mode": "shared-hidden", "paused": false, "ownsTab": true, "dialogs": [] })
            .as_object()
            .cloned()
            .unwrap();
        seen.trim(a, &mut acted, false);
        assert_eq!(Value::Object(acted), json!({ "pageId": a, "url": "http://h/b", "dialogs": [] }));
        let mut snap = json!({ "pageId": a, "url": "http://h/b", "title": "T", "framesUnread": 0 })
            .as_object()
            .cloned()
            .unwrap();
        seen.trim(a, &mut snap, false);
        assert_eq!(Value::Object(snap), json!({ "pageId": a, "title": "T", "framesUnread": 0 }));
        let mut again =
            json!({ "pageId": a, "url": "http://h/b", "title": "T" }).as_object().cloned().unwrap();
        seen.trim(a, &mut again, true);
        assert_eq!(again.len(), 3, "full true shows everything");
        seen.forget(a);
        let mut after = opened.as_object().cloned().unwrap();
        seen.trim(a, &mut after, false);
        assert_eq!(Value::Object(after), opened, "a closed page's fields are forgotten");
    }

    #[test]
    fn server_name_flag() {
        assert_eq!(server_name(&[]).unwrap(), "phantab");
        assert_eq!(server_name(&["--server-name".into(), "my-browser".into()]).unwrap(), "my-browser");
        assert!(server_name(&["--bogus".into()]).is_err());
    }
}
