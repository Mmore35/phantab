//! The developer tools (THREAT-MODEL SR-90): `evaluate`, `console` and `network`, refused unless
//! `config.json` sets `"devTools": true`.
//!
//! `evaluate` is a write: it takes the site's lease, a page handed to the owner refuses it, and under
//! `guardrails` `light` and `full` every call waits for `ownerConfirmed`, since nothing can read what a
//! script will do. `console` and `network` are reads; each starts its page's recording at its first call
//! and says so. Every answer and saved file passes SR-45's redaction (`PageService::call` redacts the
//! answer; a saved file is redacted here), and the network's headers come cleaned from `phantab_cdp`
//! (`clean_headers`): no `Cookie`, `Set-Cookie`, `Authorization` or `Proxy-Authorization` in any case.

use std::sync::Arc;
use std::time::Duration;

use phantab_cdp::{CdpError, Evaluated, FrameId, Page};
use serde_json::{Map, Value, json};

use super::Engine;
use super::files::Target;
use super::recover::Failed;
use crate::engine_api::{EngineError, EngineMethod, EngineResult, page_id};
use crate::runtime::Config;
use crate::signin::SignInRecord;
use crate::util::truthy;

/// The longest a script may run, and the default.
const SCRIPT_SECONDS: f64 = 10.0;
/// An answer's result, list or body is cut at this many characters unless saved with `path`.
pub(crate) const ANSWER_CHARS: usize = 20_000;
/// A thrown error's message is cut at this many characters.
const THROWN_CHARS: usize = 300;

/// What every first call of a recording adds.
const RECORDING_STARTED: &str = "Recording started now, with this call: nothing from before it was kept. Reload the page or do what you want to watch, then ask again.";

/// The refusal while `devTools` is off: it names the setting.
fn off(method: EngineMethod) -> EngineError {
    EngineError(format!(
        "{} is a developer tool, off unless \"devTools\": true is set in phantab's config.json (docs/GUARDRAILS.md). The service reads it when it starts.",
        method.name()
    ))
}

/// Refuses a developer tool unless `config` turns them on: only the JSON boolean `true` does.
pub(super) fn require(config: &Config, method: EngineMethod) -> EngineResult<()> {
    if config.dev_tools() { Ok(()) } else { Err(off(method)) }
}

/// `text` cut at `most` characters, and whether it was.
fn cut(text: &str, most: usize) -> (String, bool) {
    match text.char_indices().nth(most) {
        Some((at, _)) => (text[..at].to_owned(), true),
        None => (text.to_owned(), false),
    }
}

/// `items` kept in order until their JSON reaches [`ANSWER_CHARS`]: the kept ones, and how many were
/// left out.
fn fit(items: impl IntoIterator<Item = Value>) -> (Vec<Value>, usize) {
    let (mut kept, mut used, mut omitted) = (Vec::new(), 0, 0);
    for item in items {
        let size = item.to_string().len() + 1;
        if omitted > 0 || used + size > ANSWER_CHARS {
            omitted += 1;
            continue;
        }
        used += size;
        kept.push(item);
    }
    (kept, omitted)
}

/// The optional string argument `key`.
fn text_arg<'a>(args: &'a Value, key: &str) -> EngineResult<Option<&'a str>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s)),
        Some(_) => Err(EngineError(format!("{key}: give it as a non-empty string."))),
    }
}

/// `evaluate`'s own arguments, checked before anything is sent.
struct Script {
    function: String,
    args: Vec<Value>,
    frame: Option<String>,
    limit: Duration,
}

impl Script {
    fn of(args: &Value) -> EngineResult<Self> {
        let Some(function) = text_arg(args, "function")? else {
            return Err(EngineError(
                "function: give the script as a function's source, such as \"() => document.title\"."
                    .to_owned(),
            ));
        };
        let given = match args.get("args") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            Some(_) => return Err(EngineError("args: give the function's arguments as a list.".to_owned())),
        };
        let seconds = match args.get("seconds") {
            None | Some(Value::Null) => SCRIPT_SECONDS,
            Some(v) => match v.as_f64() {
                Some(s) if s > 0.0 => s.min(SCRIPT_SECONDS),
                _ => {
                    return Err(EngineError(format!(
                        "seconds: give a number above 0; the most is {SCRIPT_SECONDS}."
                    )));
                }
            },
        };
        let frame = text_arg(args, "frame")?.map(str::to_owned);
        Ok(Self {
            function: function.to_owned(),
            args: given,
            frame,
            limit: Duration::from_secs_f64(seconds),
        })
    }
}

/// The frame a script runs in: the main document's, or the first website frame (as `Page::frames`
/// lists them) whose origin is `named`'s, a frame's origin as the snapshot's `FRAMES` line gives it.
fn frame_of(page: &Page, named: Option<&str>) -> Result<FrameId, Failed> {
    let main = page.main_frame().map_err(Failed::from)?;
    let Some(named) = named else { return Ok(main) };
    let origin = |u: &str| url::Url::parse(u).ok().map(|u| u.origin().ascii_serialization());
    let wanted = origin(named).ok_or_else(|| {
        Failed::Settled(EngineError(format!(
            "frame: {named} is not a frame's origin. Give it as the snapshot's FRAMES line shows it, such as https://example.com."
        )))
    })?;
    let frames = page.frames();
    let website = frames.iter().filter(|f| f.id != main && super::ops::is_website(&f.url));
    if let Some(f) = website.clone().find(|f| origin(&f.url).as_deref() == Some(wanted.as_str())) {
        return Ok(f.id.clone());
    }
    let mut have: Vec<String> = website.filter_map(|f| origin(&f.url)).collect();
    have.dedup();
    let have = if have.is_empty() { "none".to_owned() } else { have.join(", ") };
    Err(Failed::Settled(EngineError(format!(
        "frame: no frame of {wanted} on this page. Its frames' origins: {have}."
    ))))
}

/// A thrown script's error, its message cut.
fn thrown(e: CdpError) -> Failed {
    match e {
        CdpError::Evaluation { message, .. } => {
            let (message, was_cut) = cut(&message, THROWN_CHARS);
            let more = if was_cut { "…" } else { "" };
            Failed::Settled(EngineError(format!("The script threw: {message}{more}")))
        }
        e => Failed::from(e),
    }
}

impl Engine {
    /// `evaluate(owner, {pageId, function, args, frame, seconds, path, overwrite, ownerConfirmed})`.
    pub(crate) async fn evaluate(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&page_id(args), owner, true)?;
        let script = Script::of(args)?;
        let target = Target::of(args)?;
        if self.guardrails().confirms() && !args.get("ownerConfirmed").is_some_and(truthy) {
            return Err(EngineError(
                "Confirm first: a script can do whatever the page's own scripts can. Ask the owner, and only once they approve this script, repeat the same call with ownerConfirmed true.".to_owned(),
            ));
        }
        self.lock_site(&r, None)?;
        self.sweep_sign_up(&r).await?;
        // A sign-up's new password is never shown to the agent (SR-80); a script could read its field.
        if r.on_page().is_some() {
            return Err(EngineError(
                "evaluate refused: this page holds the new password a sign-up filled, which no script may read. Press the site's own button first; scripts run again once the password has left the page.".to_owned(),
            ));
        }
        let seconds = script.limit.as_secs_f64();
        let script = Arc::new(script);
        let ran = self
            .cdp(&r, Some("script"), |p, _| {
                let script = Arc::clone(&script);
                async move {
                    let frame = frame_of(&p, script.frame.as_deref())?;
                    p.evaluate_script(&frame, &script.function, script.args.clone(), script.limit)
                        .await
                        .map_err(thrown)
                }
            })
            .await?;
        let (value, kind) = match ran {
            Evaluated::Value { value, kind } => (value, kind),
            Evaluated::TimedOut { stopped: true } => {
                return Err(EngineError(format!(
                    "The script did not answer within {seconds} s. It was still running, so it was stopped."
                )));
            }
            Evaluated::TimedOut { stopped: false } => {
                return Err(EngineError(format!(
                    "The script did not answer within {seconds} s. It was waiting (a promise that did not settle) and is left waiting; the page itself still answers."
                )));
            }
        };
        let mut out = Map::new();
        out.insert("pageId".into(), json!(r.id));
        out.insert("type".into(), json!(kind));
        if let Some(target) = target {
            let mut saved = self.save(target, json!({ "type": kind, "result": value })).await?;
            saved.extend(out);
            return Ok(Value::Object(saved));
        }
        let text = value.to_string();
        let (shown, was_cut) = cut(&text, ANSWER_CHARS);
        if was_cut {
            out.insert("result".into(), json!(shown));
            out.insert(
                "cut".into(),
                json!(format!(
                    "The result is {} characters of JSON; this is its first {ANSWER_CHARS}, as text. Save it whole with path.",
                    text.chars().count()
                )),
            );
        } else {
            out.insert("result".into(), value);
        }
        Ok(Value::Object(out))
    }

    /// `console(owner, {pageId, path, overwrite})`: the page's errors, warnings and uncaught exceptions
    /// since its last navigation, the newest that fit the answer (all of them with `path`).
    pub(crate) async fn console(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&page_id(args), owner, false)?;
        let target = Target::of(args)?;
        self.sweep_sign_up(&r).await?;
        let (started, read) = self
            .cdp(&r, None, |p, _| async move {
                let started = p.record_console().await.map_err(Failed::from)?;
                Ok::<_, Failed>((started, p.console()))
            })
            .await?;
        let read = read.unwrap_or(phantab_cdp::ConsoleRead { messages: Vec::new(), dropped: 0 });
        let mut out = Map::new();
        out.insert("pageId".into(), json!(r.id));
        if started {
            out.insert("recording".into(), json!(RECORDING_STARTED));
        }
        if read.dropped > 0 {
            out.insert("dropped".into(), json!(read.dropped));
        }
        let all: Vec<Value> = read.messages.iter().map(phantab_cdp::ConsoleMessage::to_json).collect();
        if let Some(target) = target {
            out.insert("messages".into(), Value::Array(all));
            let saved = self.save(target, Value::Object(out)).await?;
            return Ok(Value::Object(with_page(saved, &r.id)));
        }
        // The newest first into the answer, then back in order.
        let (mut kept, omitted) = fit(all.into_iter().rev());
        kept.reverse();
        out.insert("messages".into(), Value::Array(kept));
        if omitted > 0 {
            out.insert(
                "omitted".into(),
                json!(format!("{omitted} older messages left out for size; save them all with path.")),
            );
        }
        Ok(Value::Object(out))
    }

    /// `network(owner, {pageId, id, filter, path, overwrite})`: the page's requests since its last
    /// navigation, failed ones first, or one request's detail and response body by `id`.
    pub(crate) async fn network(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&page_id(args), owner, false)?;
        let id = text_arg(args, "id")?.map(str::to_owned);
        let filter = text_arg(args, "filter")?.map(str::to_owned);
        if id.is_some() && filter.is_some() {
            return Err(EngineError("network takes id or filter, not both.".to_owned()));
        }
        let target = Target::of(args)?;
        self.sweep_sign_up(&r).await?;
        let (started, read) = self
            .cdp(&r, None, |p, _| async move {
                let started = p.record_network().await.map_err(Failed::from)?;
                Ok::<_, Failed>((started, p.network()))
            })
            .await?;
        let read = read.unwrap_or(phantab_cdp::NetworkRead { requests: Vec::new(), dropped: 0 });
        let mut out = Map::new();
        out.insert("pageId".into(), json!(r.id));
        if started {
            out.insert("recording".into(), json!(RECORDING_STARTED));
        }
        if let Some(id) = id {
            let Some(request) = read.requests.iter().find(|q| q.id == id) else {
                return Err(EngineError(format!(
                    "No request {id} in this page's recording, which holds what came since its last navigation (at most {}). List the requests again.",
                    phantab_cdp::REQUESTS_KEPT
                )));
            };
            return self.request_detail(&r, request, out, target).await;
        }
        if read.dropped > 0 {
            out.insert("dropped".into(), json!(read.dropped));
        }
        let (failed, rest): (Vec<_>, Vec<_>) = read
            .requests
            .iter()
            .filter(|q| filter.as_deref().is_none_or(|f| q.url.contains(f)))
            .partition(|q| q.is_failed());
        let all: Vec<Value> = failed.into_iter().chain(rest).map(phantab_cdp::Request::summary).collect();
        if let Some(target) = target {
            out.insert("requests".into(), Value::Array(all));
            let saved = self.save(target, Value::Object(out)).await?;
            return Ok(Value::Object(with_page(saved, &r.id)));
        }
        let (kept, omitted) = fit(all);
        out.insert("requests".into(), Value::Array(kept));
        if omitted > 0 {
            out.insert(
                "omitted".into(),
                json!(format!("{omitted} more requests left out for size; narrow them with filter, or save them all with path.")),
            );
        }
        Ok(Value::Object(out))
    }

    /// One request's detail, its headers already cleaned, with its response body as Chrome holds it:
    /// text when it is text, else `bodyBase64`. A request that failed or has not finished has none.
    async fn request_detail(
        &self,
        r: &Arc<super::record::Rec>,
        request: &phantab_cdp::Request,
        mut out: Map<String, Value>,
        target: Option<Target>,
    ) -> EngineResult {
        if let Value::Object(detail) = request.detail() {
            out.extend(detail);
        }
        if request.failed.is_none() && request.size.is_some() {
            let id = request.id.clone();
            let body = self
                .cdp(r, None, |p, _| {
                    let id = id.clone();
                    async move {
                        p.response_body(&id).await.map_err(|_| {
                            Failed::Settled(EngineError(
                                "Chrome no longer holds this request's body: it keeps bodies only for a while and drops them at a navigation. Repeat what sent the request, then ask again.".to_owned(),
                            ))
                        })
                    }
                })
                .await?;
            let (key, text) = match body {
                (bytes, false) => ("body", String::from_utf8_lossy(&bytes).into_owned()),
                (bytes, true) => match String::from_utf8(bytes) {
                    Ok(text) => ("body", text),
                    Err(e) => {
                        use base64::Engine as _;
                        ("bodyBase64", base64::engine::general_purpose::STANDARD.encode(e.as_bytes()))
                    }
                },
            };
            if target.is_none() {
                let (shown, was_cut) = cut(&text, ANSWER_CHARS);
                if was_cut {
                    out.insert(
                        "bodyCut".into(),
                        json!(format!(
                            "The body is {} characters; this is its first {ANSWER_CHARS}. Save it whole with path.",
                            text.chars().count()
                        )),
                    );
                }
                out.insert(key.into(), json!(shown));
            } else {
                out.insert(key.into(), json!(text));
            }
        } else if request.failed.is_none() {
            out.insert(
                "bodyNote".into(),
                json!("The response has not finished loading (or the page has not read it yet), so it has no body to show. Ask again once it has."),
            );
        }
        let Some(target) = target else { return Ok(Value::Object(out)) };
        let saved = self.save(target, Value::Object(out)).await?;
        Ok(Value::Object(with_page(saved, &r.id)))
    }

    /// Saves `value` as JSON at `target`, redacted as an answer is (SR-45, SR-88).
    async fn save(&self, target: Target, value: Value) -> EngineResult<Map<String, Value>> {
        let text = serde_json::to_string_pretty(&self.redacted(value, false))
            .map_err(|e| EngineError(format!("saving the result: {e}")))?;
        target.write(text.into_bytes()).await
    }
}

fn with_page(mut saved: Map<String, Value>, id: &str) -> Map<String, Value> {
    saved.insert("pageId".into(), json!(id));
    saved
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn only_the_boolean_true_turns_the_developer_tools_on() {
        let base = r#""profileDirectory":"Default""#;
        for (value, on) in [
            ("true", true),
            ("false", false),
            ("\"true\"", false),
            ("1", false),
            ("null", false),
            ("{}", false),
            ("[true]", false),
        ] {
            let c = config(&format!(r#"{{{base},"devTools":{value}}}"#));
            assert_eq!(c.dev_tools(), on, "{value}");
            assert_eq!(require(&c, EngineMethod::Evaluate).is_ok(), on, "{value}");
        }
        let missing = config(&format!("{{{base}}}"));
        for method in [EngineMethod::Evaluate, EngineMethod::Console, EngineMethod::Network] {
            let e = require(&missing, method).unwrap_err().0;
            assert!(e.starts_with(method.name()), "{e}");
            assert!(e.contains("\"devTools\": true") && e.contains("config.json"), "{e}");
        }
    }

    #[test]
    fn a_script_s_arguments_are_checked_before_anything_is_sent() {
        let ok = Script::of(&json!({ "function": "() => 1" })).unwrap();
        assert_eq!((ok.args.len(), ok.limit, ok.frame), (0, Duration::from_secs(10), None));
        let asked = Script::of(
            &json!({ "function": "(a) => a", "args": [1, "x"], "seconds": 2.5, "frame": "http://twin:9" }),
        )
        .unwrap();
        assert_eq!(
            (asked.args, asked.limit, asked.frame.as_deref()),
            (vec![json!(1), json!("x")], Duration::from_millis(2500), Some("http://twin:9"))
        );
        // More than the limit asks the limit.
        assert_eq!(
            Script::of(&json!({ "function": "() => 1", "seconds": 60 })).unwrap().limit,
            Duration::from_secs(10)
        );
        for bad in [
            json!({}),
            json!({ "function": "" }),
            json!({ "function": 5 }),
            json!({ "function": "() => 1", "args": "x" }),
            json!({ "function": "() => 1", "seconds": 0 }),
            json!({ "function": "() => 1", "seconds": "5" }),
            json!({ "function": "() => 1", "frame": 1 }),
        ] {
            assert!(Script::of(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn answers_are_cut_and_lists_fit() {
        assert_eq!(cut("abcdef", 3), ("abc".to_owned(), true));
        assert_eq!(cut("abc", 3), ("abc".to_owned(), false));
        assert_eq!(cut("ééé", 2), ("éé".to_owned(), true));
        let items: Vec<Value> = (0..3000).map(|i| json!({ "n": i })).collect();
        let (kept, omitted) = fit(items);
        let size: usize = kept.iter().map(|v| v.to_string().len() + 1).sum();
        assert!(size <= ANSWER_CHARS && kept.len() + omitted == 3000 && omitted > 0);
        assert_eq!(kept[0], json!({ "n": 0 }));
        assert_eq!(fit(vec![json!(1)]), (vec![json!(1)], 0));
    }

    #[test]
    fn a_thrown_message_is_cut_and_other_failures_pass() {
        let long = "x".repeat(THROWN_CHARS + 10);
        let e = thrown(CdpError::Evaluation { name: None, message: long, value: None });
        let Failed::Settled(EngineError(text)) = e else { panic!("settled") };
        assert_eq!(text.chars().count(), "The script threw: ".len() + THROWN_CHARS + 1);
        assert!(matches!(thrown(CdpError::Closed("gone".into())), Failed::Unsure(_)));
    }
}
