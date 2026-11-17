//! The call (`scan`, `refusal`, `sweep`, `blankAll`, `reblank`, `observe`, `run`, `signIn`), one
//! function per step, with its order of checks and its timings fixed.
//!
//! A value lives in [`Values`] from the moment the seal opens until `run` returns; every read of the
//! page that can carry one back is [`Scrubbed`]. Nothing here formats a value, a page's text or a
//! provider's words into a log line, an error or the answer: only [`Outcome`] literals leave.

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use phantab_cdp::{Arg, CdpError, ClickError, FrameId, FrameInfo, JsHandle, Page};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep, timeout};

use super::host::{Host, Phase, SignInRecord};
use super::label::{Echoed, Outcome, label, reason};
use super::options::{debug_logging_on, ms};
use super::page::{
    AIM_AT, BLANK, BLANK_INPUTS, CONTROL, FILL_FIELDS, FIND_SIGN_IN, HREF, INPUT_SEEN, LANDED, READ_INPUTS,
    REPORT, REQUEST_SUBMIT, STATE, STOP_WATCH, SUBMIT_BY_FORM, WATCH_INPUT,
};
use super::passkey;
use super::provider::Answer;
use super::seal::Request;
use super::secret::{Echo, Leftover, Scrubbed, Secret, Values};
use super::source;
use super::web::{
    BadUrl, CODE_TOKEN_MIN, captcha_field, captcha_frame, challenge_frame, echo_forms, holds_token, host_of,
    origin_of, readable, same_document, secure, strip,
};
use crate::engine_api::{EngineError, EngineResult};
use crate::page_js::VERIFY_STATE;
use crate::sign_in_guard::{
    GuardError, account_stopped, host_stopped, now_millis, over_limit, read_guard, record_send, stop_account,
};
use crate::util::truthy;

/// What fails inside `run` without a label of its own (a URL the URL parser rejects, a guard entry of
/// the wrong shape). `signIn` answers it `failed` / `error`.
#[derive(Debug)]
struct Thrown;

impl From<BadUrl> for Thrown {
    fn from(_: BadUrl) -> Self {
        Thrown
    }
}

impl From<GuardError> for Thrown {
    fn from(_: GuardError) -> Self {
        Thrown
    }
}

/// How long `signInAccount` holds the page to one account.
const HELD: Duration = Duration::from_secs(600);

fn flag(report: &Value, name: &str) -> bool {
    report.get(name).is_some_and(truthy)
}

/// A report field the page set as a word (`refuse`, `wall`), when truthy: `Some(None)` for a truthy value
/// that is not a known reason.
#[expect(clippy::option_option, reason = "set or not, then known or not: two separate questions")]
fn word(report: &Value, name: &str) -> Option<Option<&'static str>> {
    let v = report.get(name).filter(|v| truthy(v))?;
    Some(v.as_str().and_then(reason))
}

/// One frame's sign-in object: its frame, the page-side handle and the report it brought back.
#[derive(Debug)]
struct Found {
    frame: FrameId,
    handle: JsHandle,
    report: Value,
}

#[derive(Debug)]
struct Scan {
    reports: Vec<Arc<Found>>,
    chosen: Option<Arc<Found>>,
    /// `r.detaches` when the read began: the link it read through.
    at: u64,
    unread: usize,
    main_read: bool,
    captcha: bool,
}

/// Whether a frame is detached now (a frame the page no longer knows is).
pub(super) fn gone(page: &Page, id: &FrameId) -> bool {
    // Puppeteer detaches every frame when a page's session drops; phantab_cdp marks the page closed and
    // keeps its frame list, so a closed page's frames count as detached here. Without this, a link that
    // drops after the click and does not come back leaves the page `unblanked` instead of `unknown`.
    page.is_closed() || page.frame_info(id).is_none_or(|f| f.detached)
}

async fn read_one(page: &Page, frame: &FrameId, main: bool) -> Result<Option<Arc<Found>>, CdpError> {
    if !main {
        // `!box?.width||!box.height`: a frame with no area holds nothing a person could use.
        let area =
            page.frame_element_box(frame).await?.is_some_and(|b| b.width.abs() > 0.0 && b.height.abs() > 0.0);
        if !area {
            return Ok(None);
        }
    }
    let handle = page.evaluate_handle(frame, FIND_SIGN_IN, vec![]).await?;
    let report = handle.evaluate(REPORT, vec![]).await?;
    Ok(Some(Arc::new(Found { frame: frame.clone(), handle, report })))
}

/// Whether a captcha frame's element is on the page where a person could act on it: at least 10 by 10
/// CSS pixels, visible, and not pushed off the top or left further than a person could scroll it back.
/// That reach is the sum, over the real scrollers above the check (overflow auto, scroll or overlay;
/// across shadow roots and open slots) and then the page itself, of how far each can scroll back from
/// where it is now. A reversed axis (right-to-left, row-reverse, column-reverse) reads a scroll of 0 as
/// its start, so it can scroll back its whole range. A fixed box is not moved by anything above it, so
/// the walk stops there. Content that only spills out (overflow visible or hidden) adds nothing: a check
/// parked at -10000 px stays hidden however long the page is. Not seen: a scroller inside a closed
/// shadow root that the check is slotted into. Invisible widgets (reCAPTCHA v3 or
/// enterprise score, hCaptcha and Turnstile in their invisible modes) sit in zero-size, hidden or
/// offscreen frames and ask nothing of a person, so they are not a wall.
const CHALLENGE_SHOWS: &str = concat!(
    "e=>{const b=e.getBoundingClientRect(),d=document,se=d.scrollingElement,cs=n=>getComputedStyle(n),",
    "up=n=>n.assignedSlot||n.parentElement||n.parentNode?.host,",
    "back=(s,r,rev)=>r<=0?0:s<0?r+s:s>0?s:rev?r:0,",
    "flex=(c,v)=>/flex/.test(c.display)&&c.flexDirection===v,can=v=>/auto|scroll|overlay/.test(v);",
    "let x=0,y=0,fixed=cs(e).position===\"fixed\";",
    "for(let p=up(e);p&&!fixed;p=up(p)){const c=cs(p);if(p!==se){",
    "if(can(c.overflowX))x+=back(p.scrollLeft,p.scrollWidth-p.clientWidth,(c.direction===\"rtl\")!==flex(c,\"row-reverse\"));",
    "if(can(c.overflowY))y+=back(p.scrollTop,p.scrollHeight-p.clientHeight,flex(c,\"column-reverse\"));}",
    "fixed=c.position===\"fixed\";}",
    "if(!fixed&&se){x+=back(se.scrollLeft,se.scrollWidth-se.clientWidth,",
    "[d.documentElement,d.body].some(n=>n&&cs(n).direction===\"rtl\"));",
    "y+=back(se.scrollTop,se.scrollHeight-se.clientHeight,false);}",
    "return b.width>=10&&b.height>=10&&b.right+x>0&&b.bottom+y>0",
    "&&e.checkVisibility({opacityProperty:true,visibilityProperty:true});}"
);

/// [`CHALLENGE_SHOWS`] for `frame`. A frame whose element cannot be found or read counts as shown: the
/// wall stays unless the page is known to show nothing. The owner hand-off (`engine::verify`) asks it too,
/// so a check parked offscreen (auth.tesla.com, 2026-11-05) neither walls a sign-in nor pops up the window.
pub(crate) async fn challenge_shows(page: &Page, frame: &FrameId) -> bool {
    match page.frame_element_evaluate(frame, CHALLENGE_SHOWS).await {
        Ok(Some(v)) => v.as_bool() != Some(false),
        Ok(None) | Err(_) => true,
    }
}

/// Whether the document `holder` has at least one response field of the check's own kind (`field`, by
/// [`captcha_field`]) and every one of them is filled, by [`VERIFY_STATE`]. Only the check's own kind
/// counts: a filled invisible reCAPTCHA score field does not answer for an hCaptcha checkbox beside it.
/// A field it cannot find (a renamed or switched-off one) leaves the check unsolved, a wall, unless
/// another widget of the same kind in the document has filled its own.
async fn captcha_solved(page: &Page, holder: &FrameId, field: &str) -> bool {
    let Ok(state) = page.evaluate(holder, VERIFY_STATE, Vec::new()).await else { return false };
    let n = |k: &str| {
        state.get("byName").and_then(|b| b.get(field)).and_then(|f| f.get(k)).and_then(Value::as_u64)
    };
    n("total").is_some_and(|t| t > 0) && n("empty") == Some(0)
}

/// Whether `frame` is a captcha wall: a [`captcha_frame`] that [`challenge_shows`], unless the document
/// that holds it has its kind's response fields, all filled. A check the owner solved keeps its box on the page (auth.tesla.com's
/// ticked "I am human", 2026-11-06, walled the sign-in it was solved for), but every response field is
/// then filled (the sign that `engine::verify` ends a hand-off by, which reads the main frame only). The fields are counted in the document that
/// holds the check's frame, so a sign-in inside a frame is judged by its own check, and a filled field
/// elsewhere on the page does not hide a check still asking.
async fn captcha_walls(page: &Page, frame: &FrameInfo, main: &FrameId) -> bool {
    let now = page.frame_info(&frame.id);
    let url = now.as_ref().map_or(frame.url.as_str(), |i| i.url.as_str());
    if !captcha_frame(url) {
        return false;
    }
    let field = captcha_field(url);
    // The nearest document above it that is not a check itself: `VERIFY_STATE` stays out of a live
    // check's frames (THREAT-MODEL SR-68), and a check's inner frame is held by the site's page, not by its
    // outer frame.
    let mut holder =
        now.and_then(|i| i.parent).or_else(|| frame.parent.clone()).unwrap_or_else(|| main.clone());
    while let Some(up) = page.frame_info(&holder).filter(|i| challenge_frame(&i.url)) {
        holder = up.parent.unwrap_or_else(|| main.clone());
        if holder == *main {
            break;
        }
    }
    let (shows, solved) =
        futures_util::join!(challenge_shows(page, &frame.id), captcha_solved(page, &holder, field));
    shows && !solved
}

/// `scan(r,engine)`. `None` where the scan cannot be read.
async fn scan(r: &dyn SignInRecord) -> Option<Scan> {
    if r.detached() {
        let _ = r.recover().await;
    }
    let at = r.detaches();
    let page = r.page();
    let main = page.main_frame().ok()?;
    let others: Vec<FrameInfo> =
        page.frames().into_iter().filter(|f| f.id != main && readable(&f.url)).take(20).collect();
    let frames: Vec<&FrameId> = std::iter::once(&main).chain(others.iter().map(|f| &f.id)).collect();
    // `undefined` (outer None) did not answer; `null` (inner None) has no area.
    let reads = join_all(frames.iter().map(|f| {
        let page = &page;
        let is_main = *f == &main;
        async move { timeout(ms(3000), read_one(page, f, is_main)).await.ok().and_then(Result::ok) }
    }));
    // Alongside the reads, in the same 3 s, so a scan stays inside its callers' budgets (4 s). A check
    // that does not answer in time keeps the wall: an unknown frame is not a clear one.
    let walls = join_all(others.iter().map(|f| {
        let (page, main) = (&page, &main);
        async move { timeout(ms(3000), captcha_walls(page, f, main)).await.unwrap_or(true) }
    }));
    let (results, walls) = futures_util::join!(reads, walls);
    let captcha = walls.into_iter().any(|wall| wall);
    let reports: Vec<Arc<Found>> = results.iter().flatten().flatten().cloned().collect();
    let pick = |name: &str| reports.iter().find(|x| flag(&x.report, name)).cloned();
    let chosen = pick("password").or_else(|| pick("code")).or_else(|| pick("username")).or_else(|| {
        reports
            .iter()
            .find(|x| x.report.get("wall").and_then(Value::as_str) == Some("field-not-editable"))
            .cloned()
    });
    Some(Scan {
        unread: results.iter().filter(|x| x.is_none()).count(),
        main_read: results.first().is_some_and(|x| x.as_ref().is_some_and(Option::is_some)),
        reports,
        chosen,
        at,
        captcha,
    })
}

/// `refusal(s)`: why this is not a page to sign in on, checked in a fixed order.
fn refusal(s: &Scan) -> Option<Outcome> {
    let any = |name: &str| s.reports.iter().any(|x| flag(&x.report, name));
    if any("cards") {
        return Some(Outcome::with("not-a-sign-in", "card-fields"));
    }
    if any("newPassword") {
        return Some(Outcome::with("not-a-sign-in", "new-password"));
    }
    // `reduce((n,x)=>n+x.report.passwordCount,0)>=2`; a missing count makes the sum NaN, never >= 2.
    let count: Option<f64> =
        s.reports.iter().map(|x| x.report.get("passwordCount").and_then(Value::as_f64)).sum();
    if count.is_some_and(|n| n >= 2.0) {
        return Some(Outcome::with("not-a-sign-in", "two-passwords"));
    }
    let chosen = s.chosen.as_ref().map(|c| &c.report);
    if let Some(why) = chosen.and_then(|c| word(c, "refuse")) {
        return Some(Outcome { reason: why, ..Outcome::of("not-a-sign-in") });
    }
    if s.captcha || (chosen.is_none() && any("captchaPage")) {
        return Some(Outcome::with("wall", "captcha"));
    }
    if let Some(why) = chosen.and_then(|c| word(c, "wall")) {
        return Some(Outcome { reason: why, ..Outcome::of("wall") });
    }
    if chosen.is_none() {
        return Some(if any("passkey") {
            passkey_wall()
        } else {
            Outcome::with("not-a-sign-in", "no-field")
        });
    }
    None
}

/// `wall` / `passkey`: the page wants a passkey, which only the owner can give.
fn passkey_wall() -> Outcome {
    Outcome::with("wall", "passkey")
}

fn is_passkey_wall(o: &Outcome) -> bool {
    o.status == "wall" && o.reason == Some("passkey")
}

/// Which value the sweep found shown back on the page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Shown {
    password: bool,
    code: bool,
}

impl Shown {
    fn any(self) -> bool {
        self.password || self.code
    }

    fn or(self, other: Shown) -> Shown {
        Shown { password: self.password || other.password, code: self.code || other.code }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cleaned {
    leak: Shown,
    confirmed: bool,
    /// Frames that held a value the sweep could not confirm it blanked: the re-blank's to confirm too.
    held: Vec<FrameId>,
}

impl Cleaned {
    const UNCONFIRMED: Cleaned =
        Cleaned { leak: Shown { password: false, code: false }, confirmed: false, held: Vec::new() };
}

/// One frame of the sweep.
struct Swept {
    leak: Shown,
    confirmed: bool,
    held: bool,
}

/// A frame read that does not have `readInputs`' shape: the sweep fails on it.
#[derive(Debug)]
struct Odd;

fn values_of(seen: &Value) -> Result<&Vec<Value>, Odd> {
    seen.get("values").and_then(Value::as_array).ok_or(Odd)
}

fn holds_secret(values: &[Value], secrets: &[&Secret]) -> bool {
    values.iter().any(|v| v.as_str().is_some_and(|v| secrets.iter().any(|s| s.matches(v))))
}

/// What the sweep looks for: the values to blank, and the forms of them that may not show anywhere.
struct Look<'a> {
    secrets: Vec<&'a Secret>,
    forms: Vec<Secret>,
    /// The code, looked for as a whole token (phantab's own addition).
    code: Option<&'a Secret>,
}

impl Look<'_> {
    fn found_in(&self, text: &str) -> Shown {
        Shown {
            password: self.forms.iter().any(|form| text.contains(form.expose())),
            code: self.code.is_some_and(|code| holds_token(text, code.expose())),
        }
    }
}

/// One frame of the sweep.
async fn sweep_frame(page: &Page, frame: &FrameId, matters: bool, look: &Look<'_>) -> Result<Swept, Odd> {
    let secrets = look.secrets.as_slice();
    let Some(seen) = timeout(ms(3000), page.evaluate(frame, READ_INPUTS, vec![]))
        .await
        .ok()
        .and_then(Result::ok)
        .map(Scrubbed)
    else {
        return Ok(Swept { leak: Shown::default(), confirmed: !matters || gone(page, frame), held: false });
    };
    let (Some(href), Some(text)) =
        (seen.0.get("href").and_then(Value::as_str), seen.0.get("text").and_then(Value::as_str))
    else {
        return Err(Odd);
    };
    let url = page.frame_info(frame).map(|f| f.url).unwrap_or_default();
    let leak = look.found_in(&url).or(look.found_in(href)).or(look.found_in(text));
    let wanted: Vec<Value> = values_of(&seen.0)?
        .iter()
        .enumerate()
        .filter(|(_, v)| holds_secret(std::slice::from_ref(*v), secrets))
        .map(|(i, _)| json!(i))
        .collect();
    if wanted.is_empty() {
        return Ok(Swept { leak, confirmed: true, held: false });
    }
    let left = timeout(ms(3000), async {
        page.evaluate(frame, BLANK_INPUTS, vec![Arg::Value(Value::Array(wanted))]).await?;
        page.evaluate(frame, READ_INPUTS, vec![]).await
    })
    .await
    .ok()
    .and_then(Result::ok)
    .map(Scrubbed);
    let confirmed = match &left {
        None => false,
        Some(left) => !holds_secret(values_of(&left.0)?, secrets),
    };
    Ok(Swept { leak, confirmed, held: !confirmed })
}

/// `sweep(r,found,values)`: what is left of each frame. A site that echoes a value is found here; no
/// value goes into a page to look for it. `Err` where a frame read has the wrong shape.
async fn sweep(r: &dyn SignInRecord, found: &Found, values: &Values) -> Result<Cleaned, Odd> {
    let look = Look {
        secrets: values.secrets(),
        forms: echo_forms(values.password.as_ref()),
        code: values.code.as_ref().filter(|c| !c.expose().is_empty()),
    };
    let page = r.page();
    let main = page.main_frame().ok();
    let frames: Vec<FrameInfo> = page.frames().into_iter().filter(|f| readable(&f.url)).collect();
    let results = join_all(frames.iter().map(|f| {
        let matters = main.as_ref() == Some(&f.id) || f.id == found.frame;
        sweep_frame(&page, &f.id, matters, &look)
    }))
    .await;
    let mut cleaned = Cleaned { leak: Shown::default(), confirmed: true, held: Vec::new() };
    for (f, result) in frames.iter().zip(results) {
        let swept = result?;
        cleaned.leak = cleaned.leak.or(swept.leak);
        cleaned.confirmed &= swept.confirmed;
        if swept.held {
            cleaned.held.push(f.id.clone());
        }
    }
    Ok(cleaned)
}

/// `blankAll`: nothing went out, so everything filled goes, the username too.
async fn blank_all(r: &dyn SignInRecord, found: &Found, values: &Values) {
    let _ = timeout(ms(3000), found.handle.evaluate(BLANK, vec![])).await;
    let _ = sweep(r, found, values).await;
}

/// Starts `reblank` unless one is running; `r.signInBlanking` is set before this returns, so
/// it is set synchronously.
pub(crate) fn start_reblank(r: &Arc<dyn SignInRecord>) {
    if r.begin_blanking() {
        tokio::spawn(reblank(Arc::clone(r)));
    }
}

/// `reblank(engine,r)` after its `signInBlanking` check: blanks every password field, and clears
/// `r.signIn` once every frame that matters confirms it.
///
/// phantab's own addition: it also blanks every input in every frame that
/// still holds the password or the code, whatever its type now (a show-password toggle makes it `text`; a
/// code field is `text` or `tel`), and reads the frame again. A frame the sign-in filled, or where the
/// sweep saw a value it could not blank, matters as the main frame does: while it does not answer, the
/// page stays held.
async fn reblank(r: Arc<dyn SignInRecord>) {
    let leftover = r.leftover();
    let blanked = async {
        r.recover().await.ok()?;
        let page = r.page();
        let frames: Vec<FrameInfo> = page.frames().into_iter().filter(|f| readable(&f.url)).collect();
        let main = page.main_frame().ok()?;
        let results = join_all(frames.iter().map(|f| {
            let is_main = f.id == main;
            let matters = is_main || leftover.as_ref().is_some_and(|l| l.frames().contains(&f.id));
            reblank_frame(&page, &f.id, is_main, matters, leftover.as_deref())
        }))
        .await;
        Some(results.into_iter().all(|ok| ok))
    }
    .await;
    if blanked == Some(true) {
        r.set_leftover(None);
        r.set_sign_in(None);
    }
    r.end_blanking();
}

/// The indices of the inputs that still hold the password or the code; `None` for a read of the wrong
/// shape.
fn still_held(seen: &Scrubbed, leftover: &Leftover) -> Option<Vec<Value>> {
    let values = values_of(&seen.0).ok()?;
    Some(
        values
            .iter()
            .enumerate()
            .filter(|(_, v)| v.as_str().is_some_and(|v| leftover.holds(v)))
            .map(|(i, _)| json!(i))
            .collect(),
    )
}

/// One frame of the re-blank: whether it confirms. A frame that does not answer confirms unless it
/// matters; one that matters may still have gone, unless it is the main frame.
async fn reblank_frame(
    page: &Page,
    frame: &FrameId,
    is_main: bool,
    matters: bool,
    leftover: Option<&Leftover>,
) -> bool {
    let unanswered = || !matters || (!is_main && gone(page, frame));
    let passwords =
        timeout(ms(3000), page.evaluate(frame, BLANK_INPUTS, vec![Arg::Value(json!("passwords"))])).await;
    if !matches!(passwords, Ok(Ok(_))) {
        return unanswered();
    }
    let Some(leftover) = leftover else { return true };
    let read = || async {
        timeout(ms(3000), page.evaluate(frame, READ_INPUTS, vec![]))
            .await
            .ok()
            .and_then(Result::ok)
            .map(Scrubbed)
    };
    let Some(seen) = read().await else { return unanswered() };
    let Some(wanted) = still_held(&seen, leftover).filter(|_| leftover.can_check()) else { return false };
    if wanted.is_empty() {
        return true;
    }
    let blanked =
        timeout(ms(3000), page.evaluate(frame, BLANK_INPUTS, vec![Arg::Value(Value::Array(wanted))]));
    if !matches!(blanked.await, Ok(Ok(_))) {
        return false;
    }
    read().await.and_then(|left| still_held(&left, leftover)).is_some_and(|left| left.is_empty())
}

/// What went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    Username,
    Password,
    Code,
}

/// `observe`: the outcome of a send, from the field's own state while its document lasts, then what the
/// page asks for next.
async fn observe(
    host: &dyn Host,
    r: &dyn SignInRecord,
    found: &Found,
    sent: Sent,
    start: Instant,
) -> Outcome {
    let t = host.options().times();
    let end = (Instant::now() + ms(t.observe_ms)).min(start + ms(t.call_ms));
    let mut decided = false;
    let mut answered = true;
    let mut recovered = false;
    // The form's document is gone: its context was destroyed (a navigation), not a form removed or hidden.
    let mut replaced = false;
    while Instant::now() < end && r.is_current() {
        if r.detached() {
            answered = false;
            if r.recover().await.is_err() {
                sleep(ms(500)).await;
                continue;
            }
            decided = true;
            recovered = true;
            break;
        }
        let state = match timeout(ms(2000), found.handle.evaluate(STATE, vec![])).await {
            Err(_) => None,
            Ok(Err(_)) if r.detached() => None,
            Ok(Err(_)) => Some(json!({ "gone": true })),
            Ok(Ok(v)) => Some(v),
        };
        let Some(state) = state else {
            answered = false;
            sleep(ms(200)).await;
            continue;
        };
        answered = true;
        if flag(&state, "stoppedGet") {
            return Outcome::with("wall", "form-posts-in-the-clear");
        }
        // The page asked for a passkey (its own `credentials.get`, a password manager's pop-up): only the
        // owner can answer it, however the form looks meanwhile.
        if passkey::waiting(&r.page()).await {
            return passkey_wall();
        }
        if flag(&state, "gone") || !flag(&state, "connected") || !flag(&state, "shown") {
            decided = true;
            replaced = flag(&state, "gone");
            break;
        }
        if sent == Sent::Password && flag(&state, "codeBeside") && !flag(&found.report, "code") {
            decided = true;
            break;
        }
        // Apple keeps the username showing and opens the password under it, on the same page.
        if sent == Sent::Username && (flag(&state, "passwordBeside") || flag(&state, "codeBeside")) {
            decided = true;
            break;
        }
        sleep(ms(300)).await;
    }
    if !r.is_current() {
        return Outcome::of("unknown");
    }
    if !decided {
        if !answered {
            return Outcome::of("unknown");
        }
        if passkey::waiting(&r.page()).await {
            return passkey_wall();
        }
        return if sent == Sent::Password {
            Outcome::of("still-asking")
        } else {
            Outcome::with("wall", "not-taken")
        };
    }
    let stop = (Instant::now() + ms(t.settle_ms)).min(start + ms(t.call_ms));
    let early = replaced && !recovered && r.page().main_frame().is_ok_and(|main| main == found.frame);
    let next = settle(r, stop, recovered, early, t.quiet_ms).await;
    let Some(next) = next else { return Outcome::of("unknown") };
    let refused = refusal(&next);
    // What the page asks for next is a passkey: by its words, or by a request waiting for an answer.
    // Neither is a submit to report as done.
    if refused.as_ref().is_some_and(is_passkey_wall) || passkey::waiting(&r.page()).await {
        return passkey_wall();
    }
    let asks = match (&next.chosen, refused) {
        (Some(c), None) => &c.report,
        _ => return Outcome::of("submitted"),
    };
    let (password, username, code) = (flag(asks, "password"), flag(asks, "username"), flag(asks, "code"));
    match sent {
        Sent::Password if password && !code => Outcome::of("still-asking"),
        Sent::Username if username && !password && !code => Outcome::with("wall", "not-taken"),
        Sent::Code if code && !password => Outcome::with("wall", "not-taken"),
        _ => Outcome::of("next-step"),
    }
}

/// A replaced document can take a moment to show what it asks. A read that fails after one that
/// worked tells nothing new, so the last good read stands. After a re-attach the submit may still be
/// in flight, with the old form showing, so a form seen then is read again until the settle time
/// ends rather than taken at once: it is no proof the password was refused. (Taking the first form
/// would, on a slow machine, read a password as refused and stop the account.)
///
/// A main-frame form whose document was replaced, with no re-attach, ends sooner: once the new
/// document has loaded, every frame answered with no sign-in form, and its elements have held still
/// for `quiet_ms`. A form a script brings in later changes the count and restarts the wait.
async fn settle(
    r: &dyn SignInRecord,
    stop: Instant,
    recovered: bool,
    early: bool,
    quiet_ms: u64,
) -> Option<Scan> {
    let mut next: Option<Scan> = None;
    let mut mark: Option<(Value, Instant)> = None;
    loop {
        let read = timeout(ms(4000), scan(r)).await.ok().flatten().filter(|s| s.main_read);
        let clear = read.as_ref().is_some_and(|s| s.chosen.is_none() && s.unread == 0);
        if let Some(read) = read {
            next = Some(read);
        }
        if (!recovered && next.as_ref().is_some_and(|n| n.chosen.is_some()))
            || Instant::now() >= stop
            || !r.is_current()
        {
            break;
        }
        if !early {
            sleep(ms(400)).await;
            continue;
        }
        let landed = if clear { landed_mark(r).await } else { None };
        mark = match (landed, mark) {
            (Some(m), Some((last, since))) if m == last => Some((last, since)),
            (m, _) => m.map(|m| (m, Instant::now())),
        };
        if mark.as_ref().is_some_and(|(_, since)| since.elapsed() >= ms(quiet_ms)) {
            break;
        }
        sleep(ms(150)).await;
    }
    next
}

/// Whether the report's `href` is the document Chrome's frame tree has in that frame, and its
/// `ancestors` the origins of the frames above it, parent first. An ancestor whose URL has no origin of
/// its own (`about:blank`, `about:srcdoc`) is counted but not compared.
pub(super) fn frame_tree_agrees(page: &Page, frame: &FrameId, report: &Value) -> bool {
    let Some(info) = page.frame_info(frame).filter(|f| !f.detached) else { return false };
    let Some(href) = report.get("href").and_then(Value::as_str) else { return false };
    if !same_document(href, &info.url) {
        return false;
    }
    let Some(ancestors) = report.get("ancestors").and_then(Value::as_array) else { return false };
    let mut parent = info.parent;
    for said in ancestors {
        let Some(above) = parent.and_then(|id| page.frame_info(&id)) else { return false };
        if origin_of(&above.url).is_some_and(|origin| said.as_str() != Some(origin.as_str())) {
            return false;
        }
        parent = above.parent;
    }
    parent.is_none()
}

/// [`LANDED`] in the main frame, raced at 1 s: the element count of a document that has loaded, else
/// None.
async fn landed_mark(r: &dyn SignInRecord) -> Option<Value> {
    let page = r.page();
    let main = page.main_frame().ok()?;
    let read = timeout(ms(1000), page.evaluate(&main, LANDED, vec![])).await.ok()?.ok()?;
    if read.get(0).and_then(Value::as_str) != Some("complete") {
        return None;
    }
    read.get(1).cloned()
}

/// `()=>location.href` in the main frame, raced at 3 s.
pub(super) async fn top_href(r: &dyn SignInRecord) -> Option<Value> {
    let page = r.page();
    let main = page.main_frame().ok()?;
    timeout(ms(3000), page.evaluate(&main, HREF, vec![])).await.ok().and_then(Result::ok)
}

/// `reread`: the handles die with a re-attach and nothing has gone out yet, so read again.
async fn reread(r: &dyn SignInRecord, found: &mut Arc<Found>, read_at: &mut u64) -> bool {
    let Some(again) = timeout(ms(4000), scan(r)).await.ok().flatten() else { return false };
    if !again.main_read || refusal(&again).is_some() {
        return false;
    }
    let Some(chosen) = again.chosen.clone() else { return false };
    *found = chosen;
    *read_at = again.at;
    true
}

enum Fill {
    Moved,
    NotTaken,
    TimedOut,
    Filled,
}

async fn fill(found: &Found, asking: &Value, values: &Values) -> Fill {
    // The values go as an argument, never as source text. The JSON copy is the CDP layer's to drop.
    let args = vec![Arg::Value(asking.clone()), Arg::Value(values.page_argument())];
    match timeout(ms(5000), found.handle.evaluate(FILL_FIELDS, args)).await {
        Ok(Ok(v)) => match v.as_str() {
            Some("moved") => Fill::Moved,
            Some("not-taken") => Fill::NotTaken,
            _ => Fill::Filled,
        },
        _ => Fill::TimedOut,
    }
}

fn point_of(v: &Value) -> Option<(f64, f64)> {
    Some((v.get("x")?.as_f64()?, v.get("y")?.as_f64()?))
}

/// What a call learned before its fill, for the queued part.
struct Asked<'a> {
    start: Instant,
    top: &'a Value,
    report: &'a Value,
    key: &'a str,
    hosts: &'a [String],
    sent: Sent,
}

/// The queued part: fill and click, as any page action is. `None` once the click went out.
async fn fill_and_click(
    host: &dyn Host,
    r: &dyn SignInRecord,
    asked: &Asked<'_>,
    values: &Values,
    found: &mut Arc<Found>,
    read_at: &mut u64,
) -> Option<Outcome> {
    let times = host.options().times();
    if !r.is_current() {
        return Some(Outcome::with("failed", "page-ended"));
    }
    if r.paused() {
        return Some(Outcome::of("owner-has-page"));
    }
    // A script that ran while the provider answered (THREAT-MODEL SR-90): the call began before it.
    if host.scripted(r, "sign-in").is_some() {
        return Some(Outcome::of("refused"));
    }
    if asked.start.elapsed() > ms(times.fill_by_ms) {
        return Some(Outcome::of("busy"));
    }
    let report = asked.report;
    let asking = json!({ "href": report.get("href"), "ancestors": report.get("ancestors"), "action": report.get("action") });
    if (r.detached() || r.detaches() != *read_at) && !reread(r, found, read_at).await {
        return Some(Outcome::of("not-ready"));
    }
    if top_href(r).await.as_ref() != Some(asked.top) {
        return Some(Outcome::of("not-ready"));
    }
    // The frame filled is the one whose URLs were checked, by Chrome's account too (a re-read frame).
    if !frame_tree_agrees(&r.page(), &found.frame, report) {
        return Some(Outcome::of("not-ready"));
    }
    // SR-90: the document is marked before the password goes in, so no agent script runs on it after.
    if !host.mark_fill(r).await {
        return Some(Outcome::of("not-ready"));
    }
    let mut filled = fill(found, &asking, values).await;
    if matches!(filled, Fill::TimedOut) {
        // Chrome fails the command a moment before it reports the detach.
        let end = Instant::now() + ms(500);
        while r.detaches() == *read_at && Instant::now() < end {
            sleep(ms(25)).await;
        }
        if r.detaches() != *read_at && reread(r, found, read_at).await && host.mark_fill(r).await {
            filled = fill(found, &asking, values).await;
        }
    }
    match filled {
        Fill::Moved => return Some(Outcome::of("not-ready")),
        Fill::TimedOut => {
            blank_all(r, found, values).await;
            return Some(Outcome::of("not-ready"));
        }
        Fill::NotTaken => {
            blank_all(r, found, values).await;
            return Some(Outcome::with("wall", "not-taken"));
        }
        Fill::Filled => {}
    }
    let by_form = found.handle.evaluate(SUBMIT_BY_FORM, vec![]).await.is_ok_and(|v| truthy(&v));
    let control = if by_form {
        None
    } else {
        match aim(r, found, values).await {
            Ok(c) => Some(c),
            Err(out) => return Some(out),
        }
    };
    // Before the click, durably: a crash after it must still count.
    let stopped = match record_send(
        &host.guard_file(),
        asked.key,
        asked.hosts,
        asked.sent == Sent::Password,
        now_millis(),
    )
    .await
    {
        Ok(None) => None,
        // SR-46: another call on this account stopped it or used the limit since the first check.
        Ok(Some(why)) => Some(Outcome::with("stopped", why)),
        Err(_) => Some(Outcome::with("stopped", "guard-file")),
    };
    if let Some(stopped) = stopped {
        if let Some(c) = &control {
            c.dispose().await;
        }
        blank_all(r, found, values).await;
        return Some(stopped);
    }
    // A click that errors at the press may still have landed, so from here this counts as sent unless
    // the click says nothing was pressed.
    if by_form {
        let _ = found.handle.evaluate(REQUEST_SUBMIT, vec![]).await;
    } else if let Some(control) = control {
        return press(r, found, values, &control).await;
    }
    None
}

/// Step 10's aim, for a click: the control, once `aimAt` has a point (`wall` / `no-clear-submit` when it
/// never has) and a child frame's element has a box (`not-ready` when not). Blanks all on either. In a
/// child frame the pointer goes to the aimed point first ([`hover_first`]).
async fn aim(r: &dyn SignInRecord, found: &Found, values: &Values) -> Result<JsHandle, Outcome> {
    let stop = Instant::now() + ms(1500);
    let mut point = None;
    while Instant::now() < stop {
        point = timeout(ms(2000), found.handle.evaluate(AIM_AT, vec![]))
            .await
            .ok()
            .and_then(Result::ok)
            .as_ref()
            .and_then(point_of);
        if point.is_some() {
            break;
        }
        sleep(ms(150)).await;
    }
    let Some((x, y)) = point else {
        blank_all(r, found, values).await;
        return Err(Outcome::with("wall", "no-clear-submit"));
    };
    let page = r.page();
    if page.main_frame().ok().as_ref() != Some(&found.frame) {
        let Some(frame_box) = page.frame_element_box(&found.frame).await.ok().flatten() else {
            blank_all(r, found, values).await;
            return Err(Outcome::of("not-ready"));
        };
        hover_first(&page, found, x + frame_box.x, y + frame_box.y).await;
    }
    // The aim is the gate, but the press is the locator click's, which finds a
    // frame in a closed shadow root inside the control by the frame tree and checks again once the
    // pointer has arrived (THREAT-MODEL T8), rather than pressing the aimed point itself.
    match found.handle.evaluate_handle(CONTROL, vec![]).await {
        Ok(c) if !c.is_nullish() => Ok(c),
        _ => {
            blank_all(r, found, values).await;
            Err(Outcome::of("not-ready"))
        }
    }
}

/// Step 12's click. `None` once the press may have gone out. Stopped before the press, nothing was sent:
/// blank all and say why ([`unpressed`]). The guard's entry for the send stays, which only errs towards
/// the limit sooner.
async fn press(r: &dyn SignInRecord, found: &Found, values: &Values, control: &JsHandle) -> Option<Outcome> {
    let page = r.page();
    let clicked = page.press_element(control).await;
    control.dispose().await;
    match clicked {
        Ok(()) => None,
        Err(ClickError::NotPressed(e)) => {
            blank_all(r, found, values).await;
            Some(unpressed(&e))
        }
        Err(ClickError::Pressed(_)) => {
            let _ = page.mouse_reset().await;
            None
        }
    }
}

/// What a click stopped before its press reports. Covered: something else, a frame among them, is where
/// the press would land, `wall` / `no-clear-submit`. Anything else (the control drawn again, a box that
/// was not there, a navigation, a page that did not answer in time) is a page still changing:
/// `not-ready`, never `still-asking`, which would stop the account for a send that never went out.
fn unpressed(e: &CdpError) -> Outcome {
    match e {
        CdpError::Covered(_) => Outcome::with("wall", "no-clear-submit"),
        _ => Outcome::of("not-ready"),
    }
}

/// phantab's own addition: in a frame, the pointer moves to the point until
/// the control's document has seen a trusted pointer move, every 100 ms for up to 1500 ms, before the
/// click. Chrome drops input aimed into a cross-site frame that has only just loaded, before it routes
/// input there; a click lost that way left the form showing and read as `still-asking`. A move that
/// arrived shows the routing is in place, so the click that follows on the same path lands (the first
/// move arrived about 15 ms in, on macOS). A move is what the click sends first anyway, so the page
/// sees nothing a person's pointer would not do. Each read is raced at 500 ms; a move is not raced
/// (cancelled mid-flight it would leave the pointer state pending), so it has the protocol timeout, as
/// the click has. Starting the watch that fails (the frame's document went) skips the wait; one that
/// timed out still waits, as a busy frame that has just loaded is the case the wait is for, and a watch
/// that started late is still read. A read or a move that fails ends the wait at once, and past the time
/// the click goes as it would without the wait. `INPUT_SEEN` ends the watch once a move is seen; every other
/// way out runs `STOP_WATCH`, a failed start too, as a page can make the start throw after its listener
/// is on. Commands on one session run in order, so that end is queued after a late start and before the
/// click.
async fn hover_first(page: &Page, found: &Found, x: f64, y: f64) {
    if let Ok(Err(_)) = timeout(ms(500), found.handle.evaluate(WATCH_INPUT, vec![])).await {
        let _ = timeout(ms(500), found.handle.evaluate(STOP_WATCH, vec![])).await;
        return;
    }
    let stop = Instant::now() + ms(1500);
    loop {
        if page.mouse_move(x, y).await.is_err() {
            break;
        }
        match timeout(ms(500), found.handle.evaluate(INPUT_SEEN, vec![])).await {
            Ok(Ok(v)) if truthy(&v) => return,
            Ok(Err(_)) => break,
            Ok(Ok(_)) | Err(_) => {}
        }
        if Instant::now() >= stop {
            break;
        }
        sleep(ms(100)).await;
    }
    let _ = timeout(ms(500), found.handle.evaluate(STOP_WATCH, vec![])).await;
}

/// `run(engine,r,args,start)`.
#[allow(clippy::too_many_lines)] // One function, so its order of checks reads top to bottom.
async fn run(host: &dyn Host, r: &dyn SignInRecord, args: &Value, start: Instant) -> Result<Outcome, Thrown> {
    let options = host.options();
    let (t, allow_loopback) = (options.times(), options.allow_loopback());
    let guard_file = host.guard_file();
    let mut s = timeout(ms(8000), scan(r)).await.ok().flatten();
    if s.as_ref().is_some_and(|s| s.unread > 0) {
        sleep(ms(1000)).await;
        s = timeout(ms(8000), scan(r)).await.ok().flatten();
    }
    let Some(mut s) = s.filter(|s| s.main_read && s.unread == 0) else { return Ok(Outcome::of("not-ready")) };
    // A form drawn by script, or in a frame still loading, arrives after the page says it has loaded.
    let stop = start + ms(t.find_ms);
    while s.chosen.is_none()
        && !refusal(&s).is_some_and(|x| x.status.starts_with("wall"))
        && Instant::now() < stop
    {
        sleep(ms(300)).await;
        if let Some(again) = timeout(ms(4000), scan(r)).await.ok().flatten().filter(|s| s.main_read) {
            s = again;
        }
    }
    let refused = refusal(&s);
    // A passkey request already waiting (the page asked on load, or the agent clicked "Sign in with a
    // passkey"): filling the form under the owner's pop-up would only race him.
    let fillable =
        refused.as_ref().is_none_or(|x| x.status == "not-a-sign-in" && x.reason == Some("no-field"));
    if fillable && passkey::waiting(&r.page()).await {
        return Ok(passkey_wall());
    }
    if let Some(refused) = refused {
        return Ok(refused);
    }
    let Some(mut found) = s.chosen.clone() else { return Err(Thrown) };
    let mut read_at = s.at;
    let report = found.report.clone();
    let Some(top) = top_href(r).await.filter(truthy) else { return Ok(Outcome::of("not-ready")) };
    let text = |v: &Value| v.as_str().map(str::to_owned).ok_or(Thrown);
    let mut full = vec![text(&top)?];
    for a in report.get("ancestors").and_then(Value::as_array).ok_or(Thrown)? {
        full.push(text(a)?);
    }
    full.push(report.get("href").map(text).ok_or(Thrown)??);
    // phantab: null is a form with no action of its own (or a `javascript:` one), which sends to `href`
    // above. Anything else that is not a URL, a missing key or the mark findSignIn leaves on an action it
    // could not resolve, is refused, never skipped: skipping would let page markup that breaks the read
    // (an <input name=baseURI>) send the fill to a form action on another site (THREAT-MODEL SR-34).
    match report.get("action") {
        Some(Value::Null) => {}
        Some(Value::String(action)) if !action.is_empty() => full.push(action.clone()),
        _ => return Ok(Outcome::of("refused")),
    }
    // `every` stops at the first URL that is not secure, before reading the rest.
    for url in &full {
        if !secure(url, allow_loopback)? {
            return Ok(Outcome::of("refused"));
        }
    }
    let mut urls: Vec<String> = Vec::new();
    for url in &full {
        let stripped = strip(url)?;
        if !urls.contains(&stripped) {
            urls.push(stripped);
        }
    }
    let mut hosts: Vec<String> = Vec::new();
    for url in &urls {
        let h = host_of(url)?;
        if !hosts.contains(&h) {
            hosts.push(h);
        }
    }
    // phantab's own addition: the frame URLs above are the page's own report, so
    // Chrome's frame tree must say the same before any of them goes to the provider.
    if !frame_tree_agrees(&r.page(), &found.frame, &report) {
        return Ok(Outcome::of("not-ready"));
    }
    let Ok(guard) = read_guard(&guard_file) else { return Ok(Outcome::with("stopped", "guard-file")) };
    if let Some(why) = host_stopped(&guard, &hosts)? {
        return Ok(Outcome::with("stopped", why));
    }
    if start.elapsed() >= ms(t.fill_by_ms) {
        return Ok(Outcome::of("busy"));
    }
    let want: Vec<&'static str> =
        ["username", "password", "code"].into_iter().filter(|n| flag(&report, n)).collect();
    let held = r.account().filter(|(_, at)| at.elapsed() < HELD).map(|(key, _)| key);
    let account = args.get("account").and_then(Value::as_str).filter(|a| !a.is_empty()).map(str::to_owned);
    let request = Request { urls, account, account_key: held.clone(), want };
    let left = (start + ms(t.fill_by_ms)).saturating_duration_since(Instant::now());
    let source = source::open_for(
        host.provider().as_ref(),
        &host.bitwarden_dir(),
        source::vault_arg(args).ok().flatten(),
    );
    let (values, key) = match source.ask(&request, ms(t.provider_ms).min(left)).await {
        Answer::Ok { values, account_key } => (values, account_key),
        Answer::Not(outcome) => return Ok(outcome),
    };
    // Local to this call, from here to its last line.
    let sent = if values.password.is_some() {
        Sent::Password
    } else if values.code.is_some() {
        Sent::Code
    } else {
        Sent::Username
    };
    if held.as_ref().is_some_and(|h| *h != key) {
        return Ok(Outcome::of("refused"));
    }
    let Ok(guard) = read_guard(&guard_file) else { return Ok(Outcome::with("stopped", "guard-file")) };
    if let Some(why) = account_stopped(&guard, &key)? {
        return Ok(Outcome::with("stopped", why));
    }
    if sent == Sent::Password && over_limit(&guard, &key, now_millis())? {
        return Ok(Outcome::with("stopped", "limit"));
    }
    r.set_account(key.clone());
    // Fill and click in the queue, as any page action is; asking and observing stay out so other agents'
    // calls answer meanwhile.
    let asked = Asked { start, top: &top, report: &report, key: &key, hosts: &hosts, sent };
    // Boxed: the fill holds every page read's state, and on the stack it would sit inside each caller's.
    let queued = Box::pin(fill_and_click(host, r, &asked, &values, &mut found, &mut read_at));
    let sent_out = host.serializer().run(queued).await;
    if let Some(out) = sent_out {
        return Ok(out);
    }
    let outcome = observe(host, r, &found, sent, start).await;
    let ended = !r.is_current();
    let mut cleaned = Cleaned { leak: Shown::default(), confirmed: true, held: Vec::new() };
    if !ended {
        if matches!(outcome.reason, Some("not-taken" | "form-posts-in-the-clear"))
            || outcome.status == "still-asking"
        {
            let _ = timeout(ms(3000), found.handle.evaluate(BLANK, vec![])).await;
        }
        cleaned = timeout(ms(12000), sweep(r, &found, &values))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(Cleaned::UNCONFIRMED);
    }
    // The site showed a value back: from here the engine redacts it from everything it returns and
    // refuses screenshots of the tab, and the call goes on to its outcome (it no longer
    // stops with `leak-stopped`). With no key to redact by, the page is held instead, as an
    // unconfirmed blank holds it.
    let mut outcome = outcome;
    if cleaned.leak.any() {
        let code = values.code.as_ref().filter(|c| c.expose().len() >= CODE_TOKEN_MIN);
        match Echo::new(&echo_forms(values.password.as_ref()), code, cleaned.leak.password) {
            Some(echo) => host.echoed(r, Arc::new(echo)),
            None => cleaned.confirmed = false,
        }
        outcome = outcome.echoed(if cleaned.leak.password { Echoed::Password } else { Echoed::Code });
    }
    if !cleaned.confirmed && !ended {
        // Before the phase, so a re-blank it starts finds what to look for.
        let mut frames = cleaned.held;
        if !frames.contains(&found.frame) {
            frames.push(found.frame.clone());
        }
        r.set_leftover(Some(Arc::new(Leftover::new(&values.secrets(), frames))));
        r.set_sign_in(Some(Phase::Unblanked));
    }
    match outcome.status {
        "still-asking" => drop(stop_account(&guard_file, &key, &hosts, "rejected").await),
        "unknown" => drop(stop_account(&guard_file, &key, &hosts, "unknown").await),
        _ => {}
    }
    Ok(outcome)
}

/// Clears `r.signIn` when the call ends while it is still `running`, however it ends.
pub(super) struct Running(pub(super) Arc<dyn SignInRecord>);

impl Drop for Running {
    fn drop(&mut self) {
        if self.0.sign_in() == Some(Phase::Running) {
            self.0.set_sign_in(None);
        }
    }
}

/// `signIn(engine,owner,args)`: the `browser_sign_in` call. Answers a label, or one of three errors
/// (an unknown page, a page a script ran on, a held site).
///
/// # Errors
/// `Unknown page or page belongs to another agent session.`, [`Host::scripted`]'s refusal, or the
/// engine's lock error.
pub async fn sign_in(host: &dyn Host, client: &str, args: &Value) -> EngineResult {
    let page_id = args.get("pageId").unwrap_or(&Value::Null);
    source::vault_arg(args).map_err(EngineError)?;
    let Some(r) = host.record(page_id, client) else {
        return Err(EngineError("Unknown page or page belongs to another agent session.".into()));
    };
    // No password goes where an agent's script ran (THREAT-MODEL SR-90): before anything is asked.
    if let Some(refused) = host.scripted(r.as_ref(), "sign-in") {
        return Err(refused);
    }
    if r.paused() {
        return Ok(label(&Outcome::of("owner-has-page")));
    }
    match r.sign_in() {
        Some(Phase::Running) => return Ok(label(&Outcome::of("busy"))),
        Some(Phase::Unblanked) => {
            start_reblank(&r);
            return Ok(label(&Outcome::with("failed", "blank-unconfirmed")));
        }
        None => {}
    }
    if !source::has_source(host.provider().as_ref()) {
        return Ok(label(&Outcome::of("no-provider")));
    }
    // A log above `info` could carry what the CDP layer sends and receives (SR-42).
    if debug_logging_on() && !host.options().ignore_debug_logging() {
        return Ok(label(&Outcome::with("failed", "debug-logging")));
    }
    host.lock(r.as_ref())?;
    let start = Instant::now();
    r.touch();
    r.set_sign_in(Some(Phase::Running));
    let _running = Running(Arc::clone(&r));
    let outcome = match r.recover().await {
        // Boxed, as the fill is: the sign-in's state goes on the heap, not into the engine's future.
        Ok(()) => Box::pin(run(host, r.as_ref(), args, start)).await.unwrap_or(Outcome::FAILED),
        Err(_) => Outcome::FAILED,
    };
    let mut out = label(&outcome);
    // A passkey is the owner's to give: the tab goes to him, as a verification hand-off of kind
    // `passkey`, and the result says what to tell him. Its `verification` field is the
    // hand-off's own report, the same as any call's, never page text.
    if is_passkey_wall(&outcome)
        && let Some(v) = host.passkey_hand_off(r.as_ref()).await
        && let Value::Object(m) = &mut out
    {
        m.insert("verification".into(), v);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_words_are_literals() {
        let report = json!({ "refuse": "pay-button", "wall": "code-boxes", "odd": "free text", "none": "" });
        assert_eq!(word(&report, "refuse"), Some(Some("pay-button")));
        assert_eq!(word(&report, "wall"), Some(Some("code-boxes")));
        assert_eq!(word(&report, "odd"), Some(None));
        assert_eq!(word(&report, "none"), None);
        assert_eq!(word(&report, "absent"), None);
        assert!(flag(&json!({ "password": true }), "password"));
        assert!(!flag(&json!({ "password": false }), "password"));
        assert!(!flag(&json!({}), "password"));
    }

    #[test]
    fn a_click_stopped_before_its_press_is_never_a_send() {
        let covered = unpressed(&CdpError::Covered("Element is covered".into()));
        assert_eq!((covered.status, covered.reason), ("wall", Some("no-clear-submit")));
        for e in [
            CdpError::Other("Node is detached from document".into()),
            CdpError::Other("Node is either not clickable or not an Element".into()),
            CdpError::Other("Unsupported frame type".into()),
            CdpError::Timeout { method: "Runtime.callFunctionOn".into() },
            CdpError::ContextDestroyed,
            CdpError::Evaluation { name: None, message: "Illegal invocation".into(), value: None },
        ] {
            let out = unpressed(&e);
            assert_eq!((out.status, out.reason), ("not-ready", None), "{e}");
        }
    }

    #[test]
    fn points() {
        assert_eq!(point_of(&json!({ "x": 1.5, "y": 2 })), Some((1.5, 2.0)));
        assert_eq!(point_of(&json!(null)), None);
        assert_eq!(point_of(&json!({ "x": 1 })), None);
    }
}
