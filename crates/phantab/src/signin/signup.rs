//! `browser_sign_up` (phantab's own: THREAT-MODEL T90, SR-78 to SR-83): makes the site's new
//! password for a sign-up the owner asked for, saves it in the owner's Bitwarden and reads it back, then
//! fills it into the form's new-password fields. The agent fills the rest and presses the site's button:
//! phantab never ticks a box or submits. Only an [`Outcome`] literal leaves; the password lives in a
//! [`Secret`] for the call, and on the record only as [`OnPage`]'s digests while it sits in the page.

use std::sync::Arc;

use futures_util::future::join_all;
use phantab_cdp::{Arg, CdpError, FrameId, FrameInfo, JsHandle, Page};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep, timeout};

use super::generate;
use super::host::{Host, Phase, SignInRecord};
use super::label::{Outcome, label_sign_up, sign_up_reason};
use super::options::{debug_logging_on, ms};
use super::page::{BLANK, BLANK_SIGN_UP, FILL_SIGN_UP, FIND_SIGN_UP, READ_SIGN_UP, REPORT};
use super::pipeline::{Running, frame_tree_agrees, gone, start_reblank, top_href};
use super::secret::{OnPage, Scrubbed, Secret};
use super::source::{self, CreateRequest, Created, CredentialSource, Saved};
use super::web::{host_of, origin_of, readable, secure};
use crate::engine_api::{EngineError, EngineResult};
use crate::sign_in_guard::{host_stopped, read_guard};

/// The longest username and item name a call may give.
const NAME_LIMIT: usize = 256;

/// One frame's sign-up object: its frame, the page-side handle and its report.
#[derive(Debug)]
struct Found {
    frame: FrameId,
    handle: JsHandle,
    report: Value,
}

struct Scan {
    reports: Vec<Found>,
    main_read: bool,
}

async fn read_one(page: &Page, frame: &FrameId, main: bool) -> Result<Option<Found>, CdpError> {
    if !main {
        let area =
            page.frame_element_box(frame).await?.is_some_and(|b| b.width.abs() > 0.0 && b.height.abs() > 0.0);
        if !area {
            return Ok(None);
        }
    }
    let handle = page.evaluate_handle(frame, FIND_SIGN_UP, vec![]).await?;
    let report = handle.evaluate(REPORT, vec![]).await?;
    Ok(Some(Found { frame: frame.clone(), handle, report }))
}

/// The frames a sign-up reads and sweeps: the main frame first, then up to 20 others with a readable URL.
fn frames_of(page: &Page) -> Option<(FrameId, Vec<FrameInfo>)> {
    let main = page.main_frame().ok()?;
    let others = page.frames().into_iter().filter(|f| f.id != main && readable(&f.url)).take(20).collect();
    Some((main, others))
}

async fn scan(r: &dyn SignInRecord) -> Option<Scan> {
    if r.detached() {
        let _ = r.recover().await;
    }
    let page = r.page();
    let (main, others) = frames_of(&page)?;
    let frames: Vec<&FrameId> = std::iter::once(&main).chain(others.iter().map(|f| &f.id)).collect();
    let results: Vec<Option<Option<Found>>> = join_all(frames.iter().map(|f| {
        let page = &page;
        let is_main = *f == &main;
        async move { timeout(ms(3000), read_one(page, f, is_main)).await.ok().and_then(Result::ok) }
    }))
    .await;
    let main_read = results.first().is_some_and(|x| x.as_ref().is_some_and(Option::is_some));
    Some(Scan { reports: results.into_iter().flatten().flatten().collect(), main_read })
}

fn fields(report: &Value) -> u64 {
    report.get("fields").and_then(Value::as_u64).unwrap_or(0)
}

fn refuse(report: &Value) -> Option<&'static str> {
    let word = report.get("refuse")?.as_str()?;
    Some(sign_up_reason(word).unwrap_or("unknown"))
}

/// The form to fill: the first frame with fields and no refusal; else why not.
fn choose(s: Scan) -> Result<Found, Outcome> {
    let mut refused = None;
    for found in s.reports {
        match refuse(&found.report) {
            None if fields(&found.report) > 0 => return Ok(found),
            Some(why) if refused.is_none() => refused = Some(why),
            _ => {}
        }
    }
    Err(Outcome::with("not-a-sign-up", refused.unwrap_or("no-field")))
}

/// Whether `action` sends to `page`'s host or a host above or below it (`www.` and `accounts.` of one
/// site). Never a bare top-level name: `co.uk` is not a site.
fn same_site(action: &str, page: &str) -> bool {
    let under =
        |a: &str, b: &str| b.contains('.') && a.strip_suffix(b).is_some_and(|rest| rest.ends_with('.'));
    action == page || under(action, page) || under(page, action)
}

/// What the call was asked, checked before anything starts.
struct Asks {
    username: String,
    name: Option<String>,
    regenerate: bool,
}

fn asks(args: &Value) -> Result<Asks, EngineError> {
    let text = |k: &str| args.get(k).and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty());
    let fits = |v: &str| v.chars().count() <= NAME_LIMIT && !v.chars().any(char::is_control);
    let Some(username) = text("username").filter(|u| fits(u)) else {
        return Err(EngineError(format!(
            "username must be the account name for the new login: text of 1 to {NAME_LIMIT} characters."
        )));
    };
    let name = match args.get("name") {
        None | Some(Value::Null) => None,
        Some(_) => Some(text("name").filter(|n| fits(n)).map(str::to_owned).ok_or_else(|| {
            EngineError(format!("name, when given, must be text of 1 to {NAME_LIMIT} characters."))
        })?),
    };
    let regenerate = args.get("regenerate").and_then(Value::as_bool) == Some(true);
    Ok(Asks { username: username.to_owned(), name, regenerate })
}

/// UTC `YYYY-MM-DD` (Howard Hinnant's `civil_from_days`).
fn today() -> String {
    let secs =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn length(report: &Value, key: &str) -> Option<usize> {
    report.get(key).and_then(Value::as_u64).and_then(|n| usize::try_from(n).ok())
}

/// Every URL the form's page sits under and sends to, checked: secure, one origin from the top down,
/// and actions to this site only. `Ok` with the page's origin and host.
fn urls_agree(top: &str, report: &Value, allow_loopback: bool) -> Result<(String, String), Outcome> {
    let refused = |why| Outcome::with("not-a-sign-up", why);
    let text = |v: &Value| v.as_str().map(str::to_owned).ok_or(Outcome::FAILED);
    let href = report.get("href").map(text).ok_or(Outcome::FAILED)??;
    let ancestors = report.get("ancestors").and_then(Value::as_array).ok_or(Outcome::FAILED)?;
    let mut above = vec![top.to_owned()];
    for a in ancestors {
        above.push(text(a)?);
    }
    let actions = report.get("actions").and_then(Value::as_array).ok_or(Outcome::FAILED)?;
    let mut sends = Vec::new();
    for a in actions {
        // The mark the page leaves on an action it could not resolve, and anything not a URL, refuse.
        match a.as_str() {
            Some(url) if !url.is_empty() => sends.push(url.to_owned()),
            _ => return Err(Outcome::of("refused")),
        }
    }
    for url in std::iter::once(&href).chain(&above).chain(&sends) {
        if !secure(url, allow_loopback).map_err(|_| Outcome::FAILED)? {
            return Err(refused("not-https"));
        }
    }
    let origin = origin_of(&href).ok_or(Outcome::FAILED)?;
    if above.iter().any(|u| origin_of(u).as_deref() != Some(origin.as_str())) {
        return Err(refused("third-party-frame"));
    }
    let host = host_of(&href).map_err(|_| Outcome::FAILED)?;
    for url in &sends {
        if !same_site(&host_of(url).map_err(|_| Outcome::FAILED)?, &host) {
            return Err(refused("form-posts-elsewhere"));
        }
    }
    Ok((origin, host))
}

async fn run(
    host: &dyn Host,
    r: &Arc<dyn SignInRecord>,
    asks: &Asks,
    given: Option<&dyn CredentialSource>,
    start: Instant,
) -> Outcome {
    let options = host.options();
    let (t, allow_loopback) = (options.times(), options.allow_loopback());
    // A form drawn by script, or in a frame still loading, arrives after the page says it has loaded.
    let stop = start + ms(t.find_ms);
    let found = loop {
        let s = timeout(ms(8000), scan(r.as_ref())).await.ok().flatten().filter(|s| s.main_read);
        match s.map(choose) {
            Some(Ok(found)) => break found,
            Some(Err(why)) if Instant::now() >= stop => return why,
            None if Instant::now() >= stop => return Outcome::of("not-ready"),
            _ => sleep(ms(300)).await,
        }
    };
    let report = found.report.clone();
    let Some(top) = top_href(r.as_ref()).await.and_then(|v| v.as_str().map(str::to_owned)) else {
        return Outcome::of("not-ready");
    };
    let (origin, site) = match urls_agree(&top, &report, allow_loopback) {
        Ok(v) => v,
        Err(why) => return why,
    };
    // The frame URLs above are the page's own report: Chrome's frame tree must say the same.
    if !frame_tree_agrees(&r.page(), &found.frame, &report) {
        return Outcome::of("not-ready");
    }
    let Ok(guard) = read_guard(&host.guard_file()) else { return Outcome::with("stopped", "guard-file") };
    match host_stopped(&guard, std::slice::from_ref(&site)) {
        Ok(Some(why)) => return Outcome::with("stopped", why),
        Ok(None) => {}
        Err(_) => return Outcome::FAILED,
    }
    // Before the source: a form phantab cannot make a password for writes nothing to the vault.
    let rules = match generate::rules(
        length(&report, "maxLength"),
        length(&report, "minLength"),
        report.get("rules").and_then(Value::as_str),
    ) {
        Ok(rules) => rules,
        Err(why) => return why,
    };
    if start.elapsed() >= ms(t.fill_by_ms) {
        return Outcome::of("busy");
    }
    let request = CreateRequest {
        origin,
        username: asks.username.clone(),
        name: asks.name.clone().unwrap_or_else(|| format!("{site} (sign-up {})", today())),
        rules,
        regenerate: asks.regenerate,
    };
    let opened;
    let source: &dyn CredentialSource = if let Some(s) = given {
        s
    } else {
        opened = source::open(host.provider().as_ref(), &host.bitwarden_dir());
        opened.as_ref()
    };
    let left = (start + ms(t.fill_by_ms)).saturating_duration_since(Instant::now());
    // Saved and read back before any character reaches the page (SR-78).
    let (password, saved) = match source.create(&request, ms(t.provider_ms).min(left)).await {
        Created::Ok { password, saved } => (password, saved),
        Created::Not(why) => return why,
    };
    let queued = Box::pin(fill(r, &found, &top, &password));
    let filled = host.serializer().run(queued).await;
    if let Some(why) = filled {
        return why;
    }
    // A page that copies what is typed into another field or its text: caught before the call answers.
    match timeout(ms(12000), sweep_sign_up(host, r)).await {
        Ok(Err(_)) => return Outcome::of("leak-stopped"),
        Ok(Ok(_)) | Err(_) => {}
    }
    Outcome::of(if saved == Saved::Existing { "filled-existing" } else { "filled" })
}

/// The fill, in the queue: `None` once every field holds the password.
async fn fill(r: &Arc<dyn SignInRecord>, found: &Found, top: &str, password: &Secret) -> Option<Outcome> {
    if !r.is_current() {
        return Some(Outcome::with("failed", "page-ended"));
    }
    if r.paused() {
        return Some(Outcome::of("owner-has-page"));
    }
    let now = top_href(r.as_ref()).await;
    if now.as_ref().and_then(Value::as_str) != Some(top)
        || !frame_tree_agrees(&r.page(), &found.frame, &found.report)
    {
        return Some(Outcome::with("failed", "page-moved"));
    }
    let asked = json!({
        "href": found.report.get("href"),
        "ancestors": found.report.get("ancestors"),
        "actions": found.report.get("actions"),
    });
    // Marked before the first character goes, so a screenshot taken meanwhile is refused.
    let earlier = r.on_page();
    r.set_on_page(Some(Arc::new(OnPage::new(password, vec![found.frame.clone()], earlier.as_deref()))));
    // The password goes as an argument, never as source text. The JSON copy is the CDP layer's to drop.
    let args = vec![Arg::Value(asked), Arg::Value(Value::String(password.expose().to_owned()))];
    match timeout(ms(5000), found.handle.evaluate(FILL_SIGN_UP, args)).await {
        Ok(Ok(v)) if v.as_str() == Some("filled") => None,
        Ok(Ok(v)) if v.as_str() == Some("moved") => {
            r.set_on_page(earlier);
            Some(Outcome::with("failed", "page-moved"))
        }
        Ok(Ok(_)) => {
            let _ = timeout(ms(3000), found.handle.evaluate(BLANK, vec![])).await;
            Some(Outcome::with("failed", "not-taken"))
        }
        // It may have gone in: the mark stays until a sweep finds the page without it.
        Ok(Err(_)) | Err(_) => Some(Outcome::FAILED),
    }
}

/// What one frame's sweep found.
struct Swept {
    /// The password is still in it, or it could not be read and might be.
    held: bool,
    /// It held a copy outside a password field: it matters from now on.
    copied: bool,
}

/// One frame's sweep: `Err` for a copy in its address or text.
async fn sweep_frame(page: &Page, frame: &FrameId, matters: bool, mark: &OnPage) -> Result<Swept, ()> {
    let read = || async { timeout(ms(3000), page.evaluate(frame, READ_SIGN_UP, vec![])).await.ok()?.ok() };
    let Some(seen) = read().await.map(Scrubbed) else { return Ok(Swept { held: matters, copied: false }) };
    let str_of = |k: &str| seen.0.get(k).and_then(Value::as_str).unwrap_or_default();
    if mark.found_in(str_of("href")) || mark.found_in(str_of("text")) {
        return Err(());
    }
    let (held, copies) = look(&seen.0, mark);
    if copies.is_empty() {
        return Ok(Swept { held, copied: false });
    }
    let blanked =
        timeout(ms(3000), page.evaluate(frame, BLANK_SIGN_UP, vec![Arg::Value(json!(copies))])).await;
    if !matches!(blanked, Ok(Ok(_))) {
        return Ok(Swept { held: true, copied: true });
    }
    let Some(again) = read().await.map(Scrubbed) else { return Ok(Swept { held: true, copied: true }) };
    let (held, copies) = look(&again.0, mark);
    Ok(Swept { held: held || !copies.is_empty(), copied: true })
}

/// Whether a read holds the password in a password field, and the indices of every other field that
/// holds it or a form of it.
fn look(seen: &Value, mark: &OnPage) -> (bool, Vec<usize>) {
    let empty = Vec::new();
    let values = seen.get("values").and_then(Value::as_array).unwrap_or(&empty);
    let types = seen.get("types").and_then(Value::as_array).unwrap_or(&empty);
    let mut held = false;
    let mut copies = Vec::new();
    for (i, v) in values.iter().enumerate() {
        let Some(v) = v.as_str().filter(|v| !v.is_empty()) else { continue };
        let password = types.get(i).and_then(Value::as_str) == Some("password");
        if password && mark.holds(v) {
            held = true;
        } else if mark.holds(v) || mark.found_in(v) {
            copies.push(i);
        }
    }
    (held, copies)
}

/// The sign-up sweep, before and after any other call on a page a sign-up filled (SR-80, SR-81): blanks
/// a copy of the password in any field but a password field, and ends the page on a copy in its address
/// or text. Answers whether the password is still on the page (a screenshot is then refused), and clears
/// the mark once it is not. Nothing to do on a page with no mark.
///
/// # Errors
/// A copy where blanking cannot reach it: the tab is closed and the record forgotten.
pub async fn sweep_sign_up(host: &dyn Host, r: &Arc<dyn SignInRecord>) -> Result<bool, EngineError> {
    let Some(mark) = r.on_page() else { return Ok(false) };
    if r.detached() {
        let _ = r.recover().await;
    }
    let page = r.page();
    let Some((main, others)) = frames_of(&page) else { return Ok(true) };
    let swept: Vec<&FrameId> = std::iter::once(&main).chain(others.iter().map(|f| &f.id)).collect();
    let results = join_all(swept.iter().map(|f| {
        let page = &page;
        let matters = **f == main || (mark.frames().contains(f) && !gone(page, f));
        let mark = &mark;
        async move { sweep_frame(page, f, matters, mark).await }
    }))
    .await;
    if results.iter().any(Result::is_err) {
        host.end_leak(r.as_ref()).await;
        return Err(EngineError(
            "leak-stopped: the page showed the new password where it could not be blanked, so phantab closed it."
                .into(),
        ));
    }
    let held = !mark.can_check() || results.iter().any(|x| x.as_ref().map_or(true, |s| s.held));
    // A frame that held a copy matters from now on, as the sign-in re-blank counts one: should it stop answering, the page stays held until it answers clean or goes.
    let copied: Vec<FrameId> = swept
        .iter()
        .zip(&results)
        .filter(|(f, s)| s.as_ref().is_ok_and(|s| s.copied) && !mark.frames().contains(f))
        .map(|(f, _)| (*f).clone())
        .collect();
    // Only the mark this sweep read: a fill that marked the page meanwhile keeps its own.
    if r.on_page().is_some_and(|now| Arc::ptr_eq(&now, &mark)) {
        if !held {
            r.set_on_page(None);
        } else if !copied.is_empty() {
            r.set_on_page(Some(Arc::new(mark.with_frames(&copied))));
        }
    }
    Ok(held)
}

/// What a screenshot of a page holding a sign-up's password answers (SR-82).
pub const SECRET_ON_PAGE: &str = "secret-on-page: the new password phantab filled is still on this page, so it takes no screenshot. Press the site's own button (or leave the page) first; browser_snapshot still works.";

/// Before a screenshot: the sweep, then a refusal while the password is on the page.
///
/// # Errors
/// [`SECRET_ON_PAGE`] while it is, or the sweep's own `leak-stopped`.
pub async fn before_screenshot(host: &dyn Host, r: &Arc<dyn SignInRecord>) -> Result<(), EngineError> {
    if sweep_sign_up(host, r).await? {
        return Err(EngineError(SECRET_ON_PAGE.into()));
    }
    Ok(())
}

/// The `browser_sign_up` call. Answers a label, or the errors the prologue throws (an unknown page, a
/// bad argument, a held site).
///
/// # Errors
/// `Unknown page or page belongs to another agent session.`, a bad `username` or `name`, or the engine's
/// lock error.
pub async fn sign_up(host: &dyn Host, client: &str, args: &Value) -> EngineResult {
    sign_up_from(host, client, args, None).await
}

/// Test builds only: [`sign_up`] with a source held in memory instead of the configured one.
///
/// # Errors
/// As [`sign_up`].
#[cfg(feature = "test-seams")]
pub async fn sign_up_with_source_for_test(
    host: &dyn Host,
    client: &str,
    args: &Value,
    source: &source::MemorySource,
) -> EngineResult {
    sign_up_from(host, client, args, Some(source as &dyn CredentialSource)).await
}

async fn sign_up_from(
    host: &dyn Host,
    client: &str,
    args: &Value,
    given: Option<&dyn CredentialSource>,
) -> EngineResult {
    let page_id = args.get("pageId").unwrap_or(&Value::Null);
    let Some(r) = host.record(page_id, client) else {
        return Err(EngineError("Unknown page or page belongs to another agent session.".into()));
    };
    if r.paused() {
        return Ok(label_sign_up(&Outcome::of("owner-has-page")));
    }
    match r.sign_in() {
        Some(Phase::Running) => return Ok(label_sign_up(&Outcome::of("busy"))),
        Some(Phase::Unblanked) => {
            start_reblank(&r);
            return Ok(label_sign_up(&Outcome::with("failed", "blank-unconfirmed")));
        }
        None => {}
    }
    let asks = asks(args)?;
    if given.is_none() && !source::has_source(host.provider().as_ref()) {
        return Ok(label_sign_up(&Outcome::of("no-provider")));
    }
    // A log above `info` could carry what the CDP layer sends and receives (SR-42).
    if debug_logging_on() && !host.options().ignore_debug_logging() {
        return Ok(label_sign_up(&Outcome::with("failed", "debug-logging")));
    }
    host.lock(r.as_ref())?;
    let start = Instant::now();
    r.touch();
    r.set_sign_in(Some(Phase::Running));
    let _running = Running(Arc::clone(&r));
    let outcome = match r.recover().await {
        Ok(()) => Box::pin(run(host, &r, &asks, given, start)).await,
        Err(_) => Outcome::FAILED,
    };
    Ok(label_sign_up(&outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_767), (2026, 11, 10));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(today().len(), 10);
    }

    #[test]
    fn sites() {
        assert!(same_site("a.test", "a.test"));
        assert!(!same_site("accounts.a.test", "www.a.test"));
        assert!(same_site("accounts.a.test", "a.test") && same_site("a.test", "www.a.test"));
        assert!(!same_site("b.test", "a.test") && !same_site("evila.test", "a.test"));
        assert!(!same_site("a.co.uk", "co") && !same_site("x.test", "test"));
    }

    #[test]
    fn arguments() {
        let ok = asks(&json!({"username": " me@a.test ", "regenerate": true})).unwrap();
        assert_eq!((ok.username.as_str(), ok.name, ok.regenerate), ("me@a.test", None, true));
        assert!(!asks(&json!({"username": "u", "regenerate": "yes"})).unwrap().regenerate);
        assert_eq!(asks(&json!({"username": "u", "name": "Mine"})).unwrap().name.as_deref(), Some("Mine"));
        for bad in [json!({}), json!({"username": ""}), json!({"username": 5}), json!({"username": "a\nb"})] {
            assert!(asks(&bad).is_err(), "{bad}");
        }
        assert!(asks(&json!({"username": "x".repeat(257)})).is_err());
        assert!(asks(&json!({"username": "u", "name": ""})).is_err());
    }

    #[test]
    fn the_urls_a_form_sits_under() {
        let report = |href: &str, ancestors: Value, actions: Value| json!({"href": href, "ancestors": ancestors, "actions": actions});
        let top = "https://a.test/join";
        let ok = urls_agree(top, &report(top, json!([]), json!(["https://a.test/new"])), false);
        assert_eq!(ok, Ok(("https://a.test".into(), "a.test".into())));
        let no = |why| Err(Outcome::with("not-a-sign-up", why));
        assert_eq!(
            urls_agree("http://a.test/", &report("http://a.test/", json!([]), json!([])), false),
            no("not-https")
        );
        assert_eq!(
            urls_agree(top, &report("https://b.test/f", json!(["https://a.test"]), json!([])), false),
            no("third-party-frame")
        );
        assert_eq!(
            urls_agree(top, &report(top, json!([]), json!(["https://b.test/new"])), false),
            no("form-posts-elsewhere")
        );
        assert_eq!(
            urls_agree(top, &report(top, json!([]), json!([{"unresolved": true}])), false),
            Err(Outcome::of("refused"))
        );
        assert_eq!(
            urls_agree("http://127.0.0.1:5/", &report("http://127.0.0.1:5/", json!([]), json!([])), true),
            Ok(("http://127.0.0.1:5".into(), "127.0.0.1".into()))
        );
    }
}
