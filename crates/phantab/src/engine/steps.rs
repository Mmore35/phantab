//! `act`'s steps, once `act` has the page and the guardrails have let the step through: each acts on the
//! page and answers nothing, as the result is the page's description that `act` reads after it.
//!
//! The ones on an element (`click`, `fill`, `select`, `hover`, `drag`, `upload`) first wait for it
//! (`ready_in`) and act in the frame the wait found it in, so the element waited for, and with guardrails
//! on checked, is the one acted on. The ones at the focus or a point (`press`, `type`, `scroll`,
//! `click_xy`, `hover_xy`, `drag_xy`) wait for nothing. The ones on the page (`navigate`, `back`,
//! `forward`, `reload`, `dialog`) take the site lease of where they go.

use std::sync::Arc;
use std::time::Duration;

use phantab_cdp::{FrameId, Page};
use serde_json::{Value, json};

use super::ops::{
    NAVIGATE_TIMEOUT, abortable, arg, arg_str, click_at, in_shadow_at, is_website, pick_option, text_to,
    type_of, unconfirmed,
};
use super::read::{Abort, poll_actionable, poll_attached};
use super::record::Rec;
use super::recover::Failed;
use super::{Engine, PAGE_TEXT_LIMIT, cut};
use crate::engine_api::{EngineError, EngineResult};
use crate::page_js::{CLICK, SELECT_OPTIONS};
use crate::util::js_string;

/// The steps on an element, which wait for it first.
const ON_ELEMENT: &[&str] = &["click", "fill", "select", "hover", "drag", "upload"];

/// One `act` step: its action, its arguments and the name its failures go by.
pub(super) struct Step<'a> {
    pub args: &'a Value,
    pub action: String,
    pub what: String,
    pub selector: String,
    /// A hidden agent window, which paints no frames.
    pub workspace: bool,
}

/// What a step needs before anything is sent: `act`'s refusal of a step whose arguments cannot work.
pub(super) fn check_args(action: &str, args: &Value) -> EngineResult<()> {
    let has_str = |k: &str| matches!(arg(args, k), Some(Value::String(s)) if !s.is_empty());
    let has_num = |k: &str| arg(args, k).and_then(Value::as_f64).is_some_and(f64::is_finite);
    let refuse = |m: &str| Err(EngineError(m.to_owned()));
    match action {
        "hover" if !has_str("selector") => refuse("Supply a selector to hover, or x and y with hover_xy."),
        "hover_xy" if !(has_num("x") && has_num("y")) => refuse("Supply x and y to hover at a point."),
        "drag" if !(has_str("selector") && has_str("to")) => refuse(
            "Supply a selector to drag and the selector to drop it on (to), or drag_xy with x, y, toX and toY.",
        ),
        "drag_xy" if !["x", "y", "toX", "toY"].iter().all(|k| has_num(k)) => {
            refuse("Supply x and y to drag from and toX and toY to drop at.")
        }
        "upload"
            if !has_str("selector")
                || arg(args, "files").and_then(Value::as_array).is_none_or(Vec::is_empty) =>
        {
            refuse("Supply a selector and at least one file path to upload.")
        }
        "dialog" if !matches!(arg_str(args, "answer").as_deref(), Some("accept" | "dismiss")) => {
            refuse("Supply answer accept or dismiss for the page's next dialog.")
        }
        _ => Ok(()),
    }
}

/// The files an upload sends, each checked here before the page sees any: a full path to a file that is
/// there. The page is given the paths only; Chrome reads each file when the page does.
fn upload_files(args: &Value) -> Result<Vec<String>, EngineError> {
    let list = arg(args, "files").and_then(Value::as_array).cloned().unwrap_or_default();
    list.iter()
        .map(|v| {
            let Value::String(p) = v else {
                return Err(EngineError("upload: each file must be a path, as text.".to_owned()));
            };
            let shown = cut(p, PAGE_TEXT_LIMIT);
            let path = std::path::Path::new(p);
            if !path.is_absolute() {
                return Err(EngineError(format!(
                    "upload: {shown:?} is not an absolute path. Give the file's full path."
                )));
            }
            match std::fs::metadata(path) {
                Err(_) => Err(EngineError(format!("upload: {shown:?} does not exist."))),
                Ok(m) if !m.is_file() => Err(EngineError(format!("upload: {shown:?} is not a file."))),
                Ok(_) => Ok(p.clone()),
            }
        })
        .collect()
}

/// A step's wait before it acts: `Some` of the frame to act in, `None` once a click is done here.
///
/// A step on an element waits for it to be ready (an upload, only for it to be there: pages often hide
/// their file input behind a label) and answers that element's frame. The step finds its element in that
/// frame alone, so the element waited for (and, with guardrails on, checked) is the one acted on, never
/// another frame's match; a drag finds where it drops in the same frame. Any other step waits for nothing
/// and has no frame. A click whose element only an open shadow root has goes to that element's point, as
/// the failure would tell the agent to do with `click_xy` (a turn more for it); with guardrails on,
/// `confirm_first` has checked that point.
async fn ready_in(p: &Page, step: &Step<'_>, signal: &Abort) -> Result<Option<Option<FrameId>>, Failed> {
    let within = Duration::from_secs(10);
    match step.action.as_str() {
        "upload" => {
            return poll_attached(p, &step.selector, within, Some(signal)).await.map(|f| Some(Some(f)));
        }
        a if !ON_ELEMENT.contains(&a) => return Ok(Some(None)),
        _ => {}
    }
    let waited = poll_actionable(p, &step.selector, within, Some(signal), true).await;
    match (waited, step.action == "click") {
        (Err(e), true) => {
            let Some((x, y)) = in_shadow_at(&e) else { return Err(e) };
            click_at(p, x, y).await.map_err(|e| unconfirmed(e.into(), &step.what))?;
            Ok(None)
        }
        (waited, _) => waited.map(|frame| Some(Some(frame))),
    }
}

fn num(args: &Value, key: &str) -> f64 {
    arg(args, key).and_then(Value::as_f64).unwrap_or(f64::NAN)
}

impl Engine {
    /// Runs one step on `p` ([`Step`]).
    pub(super) async fn run_step(
        &self,
        r: &Arc<Rec>,
        p: &Page,
        signal: &Abort,
        s: &Step<'_>,
    ) -> Result<(), Failed> {
        let Some(frame) = ready_in(p, s, signal).await? else { return Ok(()) };
        match s.action.as_str() {
            "navigate" | "back" | "forward" | "reload" | "dialog" => self.page_step(r, p, s).await,
            a if ON_ELEMENT.contains(&a) => element_step(p, signal, frame.as_ref(), s).await,
            _ => point_step(p, s).await,
        }
    }

    async fn page_step(&self, r: &Arc<Rec>, p: &Page, s: &Step<'_>) -> Result<(), Failed> {
        match s.action.as_str() {
            "navigate" => {
                let url = Self::validate_url(arg(s.args, "url")).map_err(Failed::Settled)?;
                self.lock_site(r, Some(&url)).map_err(Failed::Settled)?;
                p.goto(&url, NAVIGATE_TIMEOUT).await?;
            }
            "reload" => {
                self.lock_site(r, None).map_err(Failed::Settled)?;
                p.reload(NAVIGATE_TIMEOUT).await?;
            }
            "back" | "forward" => {
                let back = s.action == "back";
                let history = p.history().await?;
                let at = if back { history.current.checked_sub(1) } else { history.current.checked_add(1) };
                // Only a website page: the entry before a new tab's first page is its blank start.
                let Some(entry) = at.and_then(|i| history.entries.get(i)).filter(|e| is_website(&e.url))
                else {
                    let why = if back {
                        "Nothing to go back to: this tab has no earlier website page."
                    } else {
                        "Nothing to go forward to: this tab has no later website page."
                    };
                    return Err(Failed::Settled(EngineError(why.to_owned())));
                };
                let url =
                    Self::validate_url(Some(&Value::String(entry.url.clone()))).map_err(Failed::Settled)?;
                self.lock_site(r, Some(&url)).map_err(Failed::Settled)?;
                p.go_to_history_entry(entry.id, NAVIGATE_TIMEOUT).await?;
            }
            _ => self.answer_next_dialog(r, p, s.args).await.map_err(Failed::Settled)?,
        }
        Ok(())
    }

    /// `["dialog", "accept"|"dismiss", text?]`: the answer for the page's next dialog, used once. An
    /// isolated page's dialogs are answered here; a hidden agent window's by the extension, before Chrome
    /// draws them. A page in a window the owner can see has dialogs that are his to answer.
    async fn answer_next_dialog(&self, r: &Arc<Rec>, p: &Page, args: &Value) -> EngineResult<()> {
        let accept = arg_str(args, "answer").as_deref() == Some("accept");
        let text = arg(args, "text").map(|v| js_string(Some(v)));
        let (isolated, hidden, tab) = {
            let s = r.lock();
            (s.isolated.is_some(), s.workspace && !s.paused, s.tab_id)
        };
        if isolated {
            p.answer_next_dialog(accept, text);
            return Ok(());
        }
        let Some(tab) = tab.filter(|_| hidden) else {
            return Err(EngineError(
                "dialog: this page is in a window the owner can see, so its dialogs are his to answer."
                    .to_owned(),
            ));
        };
        let mut a = json!({ "tabId": tab, "accept": accept });
        if let Some(t) = text {
            a["promptText"] = Value::String(t);
        }
        match self.bridge().op_in(&r.profile, "answerNextDialog", a).await {
            Err(crate::bridge::BridgeError::Remote(m)) if m.starts_with("Unknown bridge operation") => Err(EngineError(
                "dialog: the phantab bridge extension is older than this phantab. Reload it at chrome://extensions."
                    .to_owned(),
            )),
            r => r.map(drop).map_err(Into::into),
        }
    }
}

async fn element_step(p: &Page, signal: &Abort, frame: Option<&FrameId>, s: &Step<'_>) -> Result<(), Failed> {
    let said = |e: EngineError| unconfirmed(e, &s.what);
    let selector = s.selector.as_str();
    match s.action.as_str() {
        // A hidden workspace delivers no animation frames, so it clicks the element itself. The locator
        // click's own waits end on timers there (the sign-in's press uses it), but slowly, as a
        // background tab's timers run about once a second.
        "click" if s.workspace => {
            p.eval_on_selector_in(frame, selector, CLICK).await.map_err(|e| said(e.into()))?;
        }
        "click" => abortable(signal, p.click_selector_in(frame, selector)).await.map_err(said)?,
        "fill" => {
            let text = text_to(s.args, "fill")?;
            abortable(signal, p.fill_in(frame, selector, &text)).await.map_err(said)?;
        }
        "select" => {
            let value = arg(s.args, "text");
            let Some(Value::String(v)) = value else {
                return Err(Failed::Settled(EngineError(format!(
                    "Values must be strings. Found value \"{}\" of type \"{}\"",
                    cut(&js_string(value), PAGE_TEXT_LIMIT),
                    type_of(value)
                ))));
            };
            let options =
                p.eval_on_selector_in(frame, selector, SELECT_OPTIONS).await.map_err(|e| said(e.into()))?;
            let v = pick_option(&options, v)
                .map_err(|why| Failed::Settled(EngineError(format!("{selector}: {why}"))))?;
            p.select_in(frame, selector, &[v]).await.map_err(|e| said(e.into()))?;
        }
        "hover" => abortable(signal, p.hover_in(frame, selector)).await.map_err(said)?,
        "drag" => {
            let to = js_string(arg(s.args, "to"));
            abortable(signal, p.drag_in(frame, selector, &to)).await.map_err(said)?;
        }
        _ => {
            let files = upload_files(s.args).map_err(Failed::Settled)?;
            p.set_input_files_in(frame, selector, &files).await.map_err(|e| said(e.into()))?;
        }
    }
    Ok(())
}

async fn point_step(p: &Page, s: &Step<'_>) -> Result<(), Failed> {
    let said = |e: phantab_cdp::CdpError| unconfirmed(e.into(), &s.what);
    let args = s.args;
    match s.action.as_str() {
        // A key, or a combination such as Control+A: the modifiers held, the last key pressed, then all
        // released. A key-down that timed out still gets its key-up (`Page::press_combo`), so the next
        // press of that key does not go out as a repeat.
        "press" => p.press_combo(&js_string(arg(args, "key"))).await.map_err(said)?,
        // Text typed at the focus, as a person types it: what `press` sends for each key, and the text
        // itself for what no key on the layout makes.
        "type" => {
            let text = text_to(args, "type")?;
            p.type_text(&text).await.map_err(said)?;
        }
        "scroll" => {
            let dy = arg(args, "deltaY").and_then(Value::as_f64).unwrap_or(600.0);
            p.mouse_wheel(dy).await.map_err(said)?;
        }
        "click_xy" => click_at(p, num(args, "x"), num(args, "y")).await.map_err(said)?,
        "hover_xy" => p.mouse_move(num(args, "x"), num(args, "y")).await.map_err(said)?,
        "drag_xy" => {
            let (from, to) = ((num(args, "x"), num(args, "y")), (num(args, "toX"), num(args, "toY")));
            p.drag(from, to).await.map_err(said)?;
        }
        _ => return Err(Failed::Settled(EngineError("Unsupported action".to_owned()))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// An upload sends only a file named by its full path that exists and is a file; anything else is
    /// refused, saying which, before the page is touched.
    #[test]
    fn an_upload_sends_only_an_existing_file_named_by_its_full_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("report.txt");
        std::fs::write(&file, "twelve bytes").unwrap();
        let refused = |files: Value| upload_files(&json!({ "files": files })).unwrap_err().0;
        assert!(
            refused(json!(["report.txt"])).ends_with("is not an absolute path. Give the file's full path.")
        );
        assert!(refused(json!([dir.path().join("absent.txt")])).ends_with("does not exist."));
        assert!(refused(json!([dir.path()])).ends_with("is not a file."));
        assert_eq!(refused(json!([file, 7])), "upload: each file must be a path, as text.");
        let file = file.to_str().unwrap().to_owned();
        assert_eq!(upload_files(&json!({ "files": [file] })).unwrap(), vec![file]);
        assert!(check_args("upload", &json!({ "selector": "#f", "files": [] })).is_err());
        assert!(check_args("dialog", &json!({ "answer": "maybe" })).is_err());
        assert!(check_args("drag", &json!({ "selector": "#a" })).is_err());
    }
}
