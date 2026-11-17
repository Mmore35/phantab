//! Reading a page: `until` (polling from here), `readPage` (the page's frames) and `capture`.

use std::fmt::Write as _;
use std::time::Duration;

use futures_util::FutureExt as _;
use phantab_cdp::{Arg, CdpError, FrameId, FrameInfo, Page};
use serde_json::{Map, Value, json};
use tokio::sync::watch;
use tokio::time::Instant;

use super::recover::Failed;
use super::{PAGE_TEXT_LIMIT, cut};
use crate::engine_api::{EngineError, EngineResult};
use crate::page_js::{ACTIONABLE, ATTACHED, READ_FRAME};
use crate::util::js_string;

/// A frame that doesn't answer in this long is left out rather than holding up the page.
pub const READ_TIMEOUT_FRAME: Duration = Duration::from_secs(3);
const MAX_FRAMES: usize = 20;
const MAX_ELEMENTS: usize = 180;
/// In UTF-16 units, as JavaScript's `slice` counts.
const MAX_TEXT: usize = 18_000;
/// SR-34: what a page can put in each snapshot field, cut here as well as in readFrame, so the limits
/// hold whatever a frame answers. In UTF-16 units. The page title and an element's tag, id, name and type
/// get [`PAGE_TEXT_LIMIT`].
const MAX_ELEMENT_TEXT: usize = 160;
const MAX_HREF: usize = super::URL_LIMIT;
/// A field's value, which only a snapshot at parity reads (`read_frame.js`, THREAT-MODEL R8).
const MAX_VALUE: usize = 200;
const ELEMENT_FIELDS: [(&str, usize); 8] = [
    ("tag", PAGE_TEXT_LIMIT),
    ("id", PAGE_TEXT_LIMIT),
    ("name", PAGE_TEXT_LIMIT),
    ("type", PAGE_TEXT_LIMIT),
    ("text", MAX_ELEMENT_TEXT),
    ("href", MAX_HREF),
    ("selected", MAX_ELEMENT_TEXT),
    ("value", MAX_VALUE),
];

/// A call's abort signal (`AbortSignal`): set when the page detached or closed under the call.
pub(crate) type Abort = watch::Receiver<bool>;

pub(crate) fn aborted(signal: Option<&Abort>) -> bool {
    signal.is_some_and(|s| *s.borrow())
}

/// Resolves once `signal` is aborted (never without one).
pub(crate) async fn on_abort(signal: Option<&Abort>) {
    let Some(signal) = signal else { return std::future::pending().await };
    let mut signal = signal.clone();
    // A dropped sender means the call is over; nothing will abort it then.
    if signal.wait_for(|v| *v).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Polls `check` (a page function) from here, one evaluate per check; it returns true, or why not as a
/// short string, or `[why, mark]` (see [`GIVE_UP_QUIET`]).
///
/// Not a wait inside the page: that takes several round trips per wait, which a busy page's traffic
/// stretched past 10 s on a form that was there, and it waits out its timeout after losing the page to
/// a navigation, then reports only that the time ran out. A page too busy to answer holds an evaluate up
/// to the protocol timeout, so the deadline races it.
pub async fn until(
    page: &Page,
    label: &str,
    check: &str,
    args: &[Value],
    within: Duration,
    signal: Option<&watch::Receiver<bool>>,
) -> EngineResult<()> {
    poll(page, label, check, args, within, signal, false, false).await.map(drop).map_err(Into::into)
}

/// Checks come every 150 ms, except that `wait`'s and an action's (`poll_until`) come every 50 ms in the
/// first [`QUICK_FOR`] after a check that took at most [`QUICK_CHECK`]: most waits end early, and a check
/// that costs the page more than that (a heavy page's layout) is followed by the 150 ms that spares it
/// (perf-ops-15).
const QUICK_FOR: Duration = Duration::from_millis(300);
const QUICK_CHECK: Duration = Duration::from_millis(10);

/// A check that answers `[why, mark]` (`actionable` on a loaded page with no such element, its element
/// count as the mark) ends the wait once the mark has held this long: a page that has stopped changing is
/// not about to grow the element. An agent that guessed a selector waited out the whole 10 s in 9 of the
/// 10 app and shop runs of climb 2026-11-13-phantab-2x-faster-than-competition's benchmark. Longer than
/// the second a hidden window's timers can wait. A mark of null ends it at once: `actionable` answers that
/// for an element only an open shadow root has, which no selector will reach however long it waits.
const GIVE_UP_QUIET: Duration = Duration::from_millis(1500);

/// [`until`] with the quick start, saying whether a detach can be behind its failure: a timeout whose last
/// check the page answered is [`Failed::Settled`], as is a check that threw.
pub(crate) async fn poll_until(
    page: &Page,
    label: &str,
    check: &str,
    args: &[Value],
    within: Duration,
    signal: Option<&watch::Receiver<bool>>,
) -> Result<(), Failed> {
    poll(page, label, check, args, within, signal, true, false).await.map(drop)
}

/// The wait before an action on `selector`: `actionable` in the main frame, and, while the main document
/// has no such element, in each website frame too ([`check_frames`]). Answers the frame whose element is
/// ready: the sensitive-set check reads the element there, and the act finds it there alone
/// (`Page::query_selector_in`), so both land on the element waited for. With `quick`, as [`poll_until`].
pub(crate) async fn poll_actionable(
    page: &Page,
    selector: &str,
    within: Duration,
    signal: Option<&watch::Receiver<bool>>,
    quick: bool,
) -> Result<FrameId, Failed> {
    let args = [Value::String(selector.to_owned())];
    poll(page, selector, ACTIONABLE, &args, within, signal, quick, true).await
}

/// The wait before a picture of `selector`'s element: [`poll_actionable`]'s, in the same frames and order
/// and answering the same frame, except that a disabled or `aria-disabled` element is ready. A picture
/// changes nothing on the page, so it needs the element there with a size, not enabled.
pub(crate) async fn poll_pictured(
    page: &Page,
    selector: &str,
    within: Duration,
    signal: Option<&watch::Receiver<bool>>,
) -> Result<FrameId, Failed> {
    let args = [Value::String(selector.to_owned()), Value::Bool(true)];
    poll(page, selector, ACTIONABLE, &args, within, signal, true, true).await
}

/// [`poll_actionable`]'s wait for an element that need not be shown: an upload's file input, which pages often
/// hide behind a styled label. Answers the frame that has it, as that wait does.
pub(crate) async fn poll_attached(
    page: &Page,
    selector: &str,
    within: Duration,
    signal: Option<&watch::Receiver<bool>>,
) -> Result<FrameId, Failed> {
    let args = [Value::String(selector.to_owned())];
    poll(page, selector, ATTACHED, &args, within, signal, true, true).await
}

/// `actionable`'s answer for an element the document does not have: `'not found'` while it loads, or
/// `['not found', <element count>]` once loaded.
fn not_found(v: &Value) -> bool {
    match v {
        Value::String(s) => s == "not found",
        Value::Array(a) => a.len() == 2 && a[0] == json!("not found") && a[1].is_number(),
        _ => false,
    }
}

/// One check of [`poll_actionable`]'s, across frames: the main frame's answer unless it is
/// [`not_found`], then the first website frame (in `Page::frames` order, the first [`MAX_FRAMES`], each
/// given [`READ_TIMEOUT_FRAME`]) whose element is there, ready or not. A frame's own pointer into its open
/// shadow roots counts as not there: its point is the frame's, not the page's. While no frame has it, the
/// mark is every frame's element count added up, so a frame still loading keeps the wait going; a frame
/// that has not loaded yet leaves the mark off.
async fn check_frames(page: &Page, check: &str, args: &[Value]) -> Result<(Value, FrameId), CdpError> {
    let main = page.main_frame()?;
    let said = page.evaluate(&main, check, args.iter().cloned().map(Arg::Value).collect()).await?;
    if !not_found(&said) {
        return Ok((said, main));
    }
    let frames: Vec<FrameId> = page
        .frames()
        .into_iter()
        .filter(|f| f.id != main && is_website(&f.url))
        .take(MAX_FRAMES)
        .map(|f| f.id)
        .collect();
    let asks = frames.iter().map(|f| async move {
        let ask = page.evaluate(f, check, args.iter().cloned().map(Arg::Value).collect());
        (f, tokio::time::timeout(READ_TIMEOUT_FRAME, ask).await)
    });
    let mut total = said.get(1).and_then(Value::as_u64);
    for (frame, answer) in futures_util::future::join_all(asks).await {
        let Ok(Ok(v)) = answer else { continue };
        match &v {
            v if not_found(v) => total = total.zip(v.get(1).and_then(Value::as_u64)).map(|(a, b)| a + b),
            Value::Array(a) if a.len() == 2 && a[1].is_null() => {}
            _ => return Ok((v, frame.clone())),
        }
    }
    Ok((total.map_or_else(|| json!("not found"), |n| json!(["not found", n])), main))
}

#[allow(clippy::too_many_arguments, reason = "the waits' one loop, each caller naming its own")]
async fn poll(
    page: &Page,
    label: &str,
    check: &str,
    args: &[Value],
    within: Duration,
    signal: Option<&watch::Receiver<bool>>,
    quick: bool,
    in_frames: bool,
) -> Result<FrameId, Failed> {
    let start = Instant::now();
    let end = start + within;
    let mut why = "the page did not answer".to_owned();
    let mut answers = 0u32;
    let mut answered = false;
    // The last mark the page answered and when it first did; `quiet` once it has held GIVE_UP_QUIET.
    let mut mark: Option<(Value, Instant)> = None;
    let mut quiet = false;
    let mut last_word = false;
    while Instant::now() < end && !aborted(signal) {
        let attempt = async {
            if in_frames {
                return check_frames(page, check, args).await;
            }
            let frame = page.main_frame()?;
            let said = page.evaluate(&frame, check, args.iter().cloned().map(Arg::Value).collect()).await?;
            Ok((said, frame))
        };
        answered = false;
        let sent = Instant::now();
        match tokio::time::timeout_at(end, attempt).await {
            Err(_) => {}
            Ok(Err(e)) if !e.is_navigating() => return Err(e.into()),
            Ok(Err(_)) => "the page was navigating".clone_into(&mut why),
            Ok(Ok((Value::Bool(true), frame))) => return Ok(frame),
            Ok(Ok((v, _))) => {
                let (said, now) = match v {
                    Value::Array(mut a) if a.len() == 2 => {
                        let m = a.pop();
                        (a.pop().unwrap_or(Value::Null), m)
                    }
                    v => (v, None),
                };
                // The page's own words (SR-32).
                why = cut(&js_string(Some(&said)), PAGE_TEXT_LIMIT);
                answers += 1;
                answered = true;
                if now == Some(Value::Null) {
                    last_word = true;
                    break;
                }
                mark = match (now, mark) {
                    (Some(m), Some((last, since))) if m == last => Some((last, since)),
                    (m, _) => m.map(|m| (m, Instant::now())),
                };
                if mark.as_ref().is_some_and(|(_, since)| since.elapsed() >= GIVE_UP_QUIET) {
                    quiet = true;
                    break;
                }
            }
        }
        let gap =
            if quick && start.elapsed() < QUICK_FOR && sent.elapsed() <= QUICK_CHECK { 50 } else { 150 };
        tokio::time::sleep(end.saturating_duration_since(Instant::now()).min(Duration::from_millis(gap)))
            .await;
    }
    if aborted(signal) {
        return Err(Failed::Unsure(EngineError(format!(
            "{label}: the page detached or closed during the wait."
        ))));
    }
    if last_word {
        return Err(Failed::Settled(EngineError(format!("{label}: {why}."))));
    }
    if quiet {
        return Err(Failed::Settled(EngineError(format!(
            "{label}: {why} after {:.1} s, and the page had stopped changing (the page answered {answers} checks).",
            start.elapsed().as_secs_f64()
        ))));
    }
    let e = EngineError(format!(
        "{label}: {why} after {} s (the page answered {answers} checks).",
        (within.as_millis() + 500) / 1000
    ));
    Err(if answered { Failed::Settled(e) } else { Failed::Unsure(e) })
}

/// A hidden window can report 0 width for a moment across a cross-site navigation.
pub(crate) async fn capture(page: &Page, quality: u8) -> Result<String, CdpError> {
    match page.screenshot_jpeg(quality).await {
        Err(e) if e.to_string().contains("0 width") => {}
        other => return other,
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    page.screenshot_jpeg(quality).await
}

fn is_website(url: &str) -> bool {
    url.starts_with("http:") || url.starts_with("https:")
}

fn origin(url: &str) -> String {
    url::Url::parse(url).map_or_else(|_| "null".to_owned(), |u| u.origin().ascii_serialization())
}

/// One website frame's read: `None` when it has no area, `Err` when it failed or did not answer.
struct FrameRead {
    data: Map<String, Value>,
    /// The frame element's box in page coordinates.
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    origin: String,
}

async fn read_frame(page: &Page, f: &FrameInfo, values: bool) -> Result<Option<FrameRead>, CdpError> {
    let Some(b) = page.frame_element_box(&f.id).await? else { return Ok(None) };
    if b.width == 0.0 || b.height == 0.0 || b.width.is_nan() || b.height.is_nan() {
        return Ok(None);
    }
    let data = match page.evaluate(&f.id, READ_FRAME, vec![Arg::Value(Value::Bool(values))]).await? {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    Ok(Some(FrameRead { data, x: b.x, y: b.y, width: b.width, height: b.height, origin: origin(&f.url) }))
}

/// `Math.round` as JavaScript does it, to an integer.
#[allow(
    clippy::cast_possible_truncation,
    reason = "a page can send any coordinate; `as` saturates and maps NaN to 0, so none panics"
)]
fn js_round(v: f64) -> i64 {
    (v + 0.5).floor() as i64
}

fn num(v: Option<&Value>) -> f64 {
    v.and_then(Value::as_f64).unwrap_or(0.0)
}

fn count(v: Option<&Value>) -> i64 {
    v.and_then(Value::as_i64).unwrap_or(0)
}

/// The first `n` UTF-16 units of `s`, not splitting a character.
pub(crate) fn utf16_prefix(s: &str, n: usize) -> String {
    let mut units = 0;
    let mut end = s.len();
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > n {
            end = i;
            break;
        }
    }
    s[..end].to_owned()
}

/// Cuts an element's page-written fields to [`ELEMENT_FIELDS`]. Within the limits, unchanged.
fn cap_fields(e: &mut Map<String, Value>) {
    for (key, limit) in ELEMENT_FIELDS {
        if let Some(Value::String(v)) = e.get_mut(key)
            && v.len() > limit
        {
            *v = utf16_prefix(v, limit);
        }
    }
}

/// A frame's element in page coordinates. It is offscreen outside the main view, and also outside
/// its frame's box: a frame can report an element it clipped away (at `left: -300px`, say), whose
/// shifted x,y then fall on the embedding page's own controls, so a `click_xy` there would land on
/// those (sec-web-2).
fn place(e: &Value, f: &FrameRead, view: (f64, f64)) -> Value {
    let mut e = e.as_object().cloned().unwrap_or_default();
    let x = js_round(num(e.get("x")) + f.x);
    let y = js_round(num(e.get("y")) + f.y);
    e.insert("x".into(), json!(x));
    e.insert("y".into(), json!(y));
    link_path(&mut e, &f.origin);
    e.insert("frame".into(), Value::String(f.origin.clone()));
    #[allow(
        clippy::cast_precision_loss,
        reason = "x and y come from an f64 through js_round, so they convert back exactly; i64::MAX, \
                  the saturated case, becomes 2^63, past the view's far edge"
    )]
    let (px, py) = (x as f64, y as f64);
    let off_view = px < 0.0 || py < 0.0 || px >= view.0 || py >= view.1;
    let off_frame = px < f.x || py < f.y || px >= f.x + f.width || py >= f.y + f.height;
    if off_view || off_frame {
        e.insert("offscreen".into(), Value::Bool(true));
    }
    Value::Object(e)
}

/// A link on its frame's own origin, written as its path (`/a?b#c`): a snapshot is read by a model, and
/// a page's links repeat its origin in every one of them. This is done here, not in `read_frame.js`, so
/// the page runs the frame script unchanged (SR-34). A link elsewhere, or a frame with an opaque
/// origin (`null`), keeps its whole URL.
fn link_path(e: &mut Map<String, Value>, frame_origin: &str) {
    if frame_origin == "null" {
        return;
    }
    if let Some(Value::String(href)) = e.get_mut("href")
        && let Some(path) = href.strip_prefix(frame_origin).filter(|p| p.starts_with('/'))
    {
        *href = path.to_owned();
    }
}

/// Past the cap, links go last: a form's controls are what an agent needs most.
fn cap(elements: Vec<Value>) -> Vec<Value> {
    if elements.len() <= MAX_ELEMENTS {
        return elements;
    }
    let is_link = |e: &Value| e.get("tag").and_then(Value::as_str) == Some("a");
    let (links, controls): (Vec<Value>, Vec<Value>) = elements.into_iter().partition(is_link);
    controls.into_iter().chain(links).take(MAX_ELEMENTS).collect()
}

/// `readPage`: the main frame and each website frame, with x,y in the page's coordinates for
/// `click_xy`. Other extensions' frames stay unread: a password manager's menu lists saved logins.
/// `framesUnread` counts frames that failed or did not answer in 3 s (an empty page with framesUnread
/// above 0 is not yet read, not empty); `framesSkipped` and `elementsOmitted` count what the size limits
/// left out; a frame with no area holds nothing a person could use. With `values`, each text field
/// also says what it holds (`read_frame.js` leaves out every password, and every field of a form that
/// holds a new password, a card field, a code field or two password fields, THREAT-MODEL R8); the
/// snapshot asks for that at parity alone.
pub(crate) async fn read_page(page: &Page, values: bool) -> Result<Map<String, Value>, CdpError> {
    let main = page.main_frame()?;
    let all = page.frames();
    let main_origin = all.iter().find(|f| f.id == main).map_or_else(|| "null".to_owned(), |f| origin(&f.url));
    let website: Vec<FrameInfo> = all.into_iter().filter(|f| f.id != main && is_website(&f.url)).collect();
    let frames = &website[..website.len().min(MAX_FRAMES)];
    // The main frame and the website frames are read at once (the time is the slower of them, not the
    // sum); a failed main read still fails the snapshot straight away.
    let reads = futures_util::future::join_all(frames.iter().map(|f| async move {
        match tokio::time::timeout(READ_TIMEOUT_FRAME, read_frame(page, f, values)).await {
            Ok(Ok(read)) => Some(read),
            Ok(Err(_)) | Err(_) => None,
        }
    }));
    let (data, results): (Value, Vec<Option<Option<FrameRead>>>) = futures_util::future::try_join(
        page.evaluate(&main, READ_FRAME, vec![Arg::Value(Value::Bool(values))]),
        reads.map(Ok),
    )
    .await?;
    let data = match data {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    Ok(combine(&data, &main_origin, &results, frames.len(), website.len() - frames.len()))
}

/// The main frame's read and the website frames' reads as one `readPage` answer. Every count here comes
/// from a frame's script, which the page can tamper with (it runs in the page's own world), so the sums
/// saturate: a hostile page gets a capped count, never a wrapped one or an overflow.
#[allow(clippy::option_option, reason = "read_page's own shape: unanswered, no area, or a read")]
fn combine(
    data: &Map<String, Value>,
    main_origin: &str,
    results: &[Option<Option<FrameRead>>],
    frames: usize,
    skipped: usize,
) -> Map<String, Value> {
    let mut text = data.get("text").and_then(Value::as_str).unwrap_or("").to_owned();
    let mut elements: Vec<Value> = data
        .get("elements")
        .and_then(Value::as_array)
        .map(|es| {
            es.iter()
                .map(|e| {
                    let mut e = e.as_object().cloned().unwrap_or_default();
                    link_path(&mut e, main_origin);
                    Value::Object(e)
                })
                .collect()
        })
        .unwrap_or_default();
    let mut shadow_roots = count(data.get("shadowRoots"));
    let mut omitted = count(data.get("omitted"));
    let view = data.get("view").and_then(Value::as_array);
    let (width, height) = (num(view.and_then(|v| v.first())), num(view.and_then(|v| v.get(1))));
    for f in results.iter().flatten().flatten() {
        if let Some(t) = f.data.get("text").and_then(Value::as_str).filter(|t| !t.is_empty()) {
            let _ = write!(text, "\n[frame {}]\n{t}", f.origin);
        }
        shadow_roots = shadow_roots.saturating_add(count(f.data.get("shadowRoots")));
        omitted = omitted.saturating_add(count(f.data.get("omitted")));
        let list = f.data.get("elements").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        elements.extend(list.iter().map(|e| place(e, f, (width, height))));
    }
    for e in &mut elements {
        if let Some(e) = e.as_object_mut() {
            cap_fields(e);
        }
    }
    let total = elements.len();
    let kept = cap(elements);
    let unread = results.iter().filter(|r| r.is_none()).count();
    let omitted = omitted.saturating_add(i64::try_from(total - kept.len()).unwrap_or(i64::MAX));
    let mut out = Map::new();
    let title = match data.get("title") {
        Some(Value::String(t)) => Value::String(utf16_prefix(t, PAGE_TEXT_LIMIT)),
        other => other.cloned().unwrap_or(Value::Null),
    };
    out.insert("title".into(), title);
    out.insert("text".into(), Value::String(utf16_prefix(&text, MAX_TEXT)));
    out.insert("elements".into(), Value::Array(kept));
    out.insert("elementsOmitted".into(), json!(omitted));
    out.insert("frames".into(), json!(frames));
    out.insert("framesUnread".into(), json!(unread));
    out.insert("framesSkipped".into(), json!(skipped));
    out.insert("shadowRoots".into(), json!(shadow_roots));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounding_and_cutting_follow_javascript() {
        assert_eq!([js_round(2.5), js_round(-2.5), js_round(-0.4), js_round(3.49)], [3, -2, 0, 3]);
        assert_eq!(utf16_prefix("ab😀c", 3), "ab");
        assert_eq!(utf16_prefix("ab😀c", 4), "ab😀");
        assert_eq!(utf16_prefix("abc", 10), "abc");
    }

    fn frame_at(x: f64, y: f64, width: f64, height: f64) -> FrameRead {
        FrameRead { data: Map::new(), x, y, width, height, origin: "https://ad.example".into() }
    }

    #[test]
    fn frame_elements_outside_their_frame_are_offscreen() {
        // The sec-web-2 case: a 300x100 frame at (400, 80) reports a button it clipped at left:-290px.
        let f = frame_at(400.0, 80.0, 300.0, 100.0);
        let view = (1280.0, 900.0);
        let clipped = place(&json!({"tag": "button", "text": "Close ad", "x": -280, "y": 30}), &f, view);
        assert_eq!(clipped["x"], 120);
        assert_eq!(clipped["y"], 110);
        assert_eq!(clipped["offscreen"], true, "would land on the embedding page");
        assert_eq!(clipped["frame"], "https://ad.example");
        // Inside the box, an honest element is unchanged but for the shift.
        let shown = place(&json!({"tag": "button", "x": 150, "y": 50}), &f, view);
        assert_eq!(shown, json!({"tag": "button", "x": 550, "y": 130, "frame": "https://ad.example"}));
        // Each edge: the box is [x, x + width) by [y, y + height).
        for (x, y, off) in [
            (0, 0, false),
            (299, 99, false),
            (300, 50, true),
            (50, 100, true),
            (-1, 50, true),
            (50, -1, true),
        ] {
            let e = place(&json!({"x": x, "y": y}), &f, view);
            assert_eq!(e.get("offscreen").is_some(), off, "({x}, {y})");
        }
        // Inside the frame but outside the main view stays offscreen, as before.
        let low = frame_at(0.0, 850.0, 300.0, 200.0);
        assert_eq!(place(&json!({"x": 10, "y": 100}), &low, view)["offscreen"], true);
    }

    #[test]
    fn page_written_fields_are_cut() {
        let long = "x".repeat(5000);
        let mut e =
            json!({"tag": long, "id": long, "name": long, "type": long, "text": long, "href": long, "selected": long, "value": long, "x": 1})
                .as_object()
                .cloned()
                .unwrap();
        cap_fields(&mut e);
        for (key, limit) in [
            ("tag", 300),
            ("id", 300),
            ("name", 300),
            ("type", 300),
            ("text", 160),
            ("href", 2048),
            ("selected", 160),
            ("value", 200),
        ] {
            assert_eq!(e[key].as_str().unwrap().len(), limit, "{key}");
        }
        assert_eq!(e["x"], 1);
        // Within the limits nothing changes, and a cut never splits a character.
        let mut e =
            json!({"id": "a", "text": format!("{}😀", "t".repeat(159))}).as_object().cloned().unwrap();
        let before = e.clone();
        cap_fields(&mut e);
        assert_eq!(e["id"], before["id"]);
        assert_eq!(e["text"].as_str().unwrap(), "t".repeat(159));
    }

    /// A page's script can report any count (`read_frame.js` runs in the page's own world, where
    /// `Array.prototype.slice` can be replaced). Two frames each reporting about 4.7e18 sum past i64:
    /// the answer saturates instead of wrapping, and a debug build, which checks overflow, does not panic.
    #[test]
    fn huge_counts_from_two_frames_saturate() {
        let huge = json!(4_700_000_000_000_000_000_i64);
        let main = json!({ "text": "", "elements": [], "omitted": huge, "shadowRoots": huge });
        let Value::Object(main) = main else { unreachable!() };
        let frame = |data: Value| {
            let Value::Object(data) = data else { unreachable!() };
            Some(Some(FrameRead {
                data,
                x: 0.0,
                y: 0.0,
                width: 100.0,
                height: 100.0,
                origin: "https://a.example".into(),
            }))
        };
        let results = [
            frame(json!({ "omitted": huge, "shadowRoots": huge })),
            frame(json!({ "omitted": huge, "shadowRoots": huge })),
        ];
        let out = combine(&main, "https://m.example", &results, 2, 0);
        assert_eq!(out["elementsOmitted"], json!(i64::MAX), "{out:?}");
        assert_eq!(out["shadowRoots"], json!(i64::MAX), "{out:?}");
        let low = json!(-4_700_000_000_000_000_000_i64);
        let Value::Object(main) = json!({ "omitted": low }) else { unreachable!() };
        let results = [frame(json!({ "omitted": low })), frame(json!({ "omitted": low }))];
        assert_eq!(combine(&main, "https://m.example", &results, 2, 0)["elementsOmitted"], json!(i64::MIN));
    }

    #[test]
    fn links_on_their_frames_origin_are_paths() {
        let Value::Object(main) = json!({ "elements": [
            { "tag": "a", "href": "https://m.example/a?b#c" },
            { "tag": "a", "href": "https://m.example.evil/x" },
            { "tag": "a", "href": "https://a.example/y" },
            { "tag": "a", "href": "mailto:m@m.example" },
            { "tag": "button" },
        ] }) else {
            unreachable!()
        };
        let Value::Object(data) = json!({ "elements": [
            { "tag": "a", "href": "https://a.example/z" },
            { "tag": "a", "href": "https://m.example/w" },
        ] }) else {
            unreachable!()
        };
        let results = [Some(Some(FrameRead {
            data,
            x: 0.0,
            y: 0.0,
            width: 100.0,
            height: 100.0,
            origin: "https://a.example".into(),
        }))];
        let out = combine(&main, "https://m.example", &results, 1, 0);
        let hrefs: Vec<&Value> = out["elements"].as_array().unwrap().iter().map(|e| &e["href"]).collect();
        assert_eq!(
            hrefs,
            [
                &json!("/a?b#c"),
                &json!("https://m.example.evil/x"),
                &json!("https://a.example/y"),
                &json!("mailto:m@m.example"),
                &Value::Null,
                &json!("/z"),
                &json!("https://m.example/w"),
            ]
        );
        let Value::Object(opaque) = json!({ "elements": [{ "tag": "a", "href": "null/x" }] }) else {
            unreachable!()
        };
        assert_eq!(combine(&opaque, "null", &[], 0, 0)["elements"][0]["href"], json!("null/x"));
    }

    #[test]
    fn the_cap_keeps_controls_before_links() {
        let mut list: Vec<Value> = (0..150).map(|i| json!({"tag": "a", "i": i})).collect();
        list.extend((0..50).map(|i| json!({"tag": "button", "i": i})));
        let kept = cap(list);
        assert_eq!(kept.len(), 180);
        assert!(kept[..50].iter().all(|e| e["tag"] == "button"));
        assert_eq!(kept[50]["i"], 0);
    }
}
