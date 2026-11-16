//! The engine's calls: `get`, `pages`, `adopt`, `open`, `tabs`, `attach`, `snapshot`, `lock`,
//! `screenshot`, `wait`, `act`, `show`, `resume`, `close`, `release`, `viewer` and `dispose`.

use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use phantab_cdp::{BoundingBox, Browser, CdpError, FrameId, LaunchOptions, Page, PageOptions};
use serde_json::{Map, Value, json};
use tokio::time::Instant;

use super::read::{Abort, capture, on_abort, poll_actionable, poll_until, read_page};
use super::record::{Fields, Rec};
use super::recover::Failed;
use super::{Engine, PAGE_TEXT_LIMIT, cut};
use crate::bridge::{Profile, TabId};
use crate::engine_api::{EngineError, EngineResult};
use crate::page_js::{CLICK, PRESENT, SELECT_OPTIONS};
use crate::signin::{Phase, SignInRecord};
use crate::util::{js_string, random_hex, same_secret, truthy};

const UNKNOWN_PAGE: &str = "Unknown page or page belongs to another agent session.";
const NAVIGATE_TIMEOUT: Duration = Duration::from_secs(30);
/// SR-8: viewer actions per token per second.
pub(crate) const VIEWER_ACTIONS_PER_SECOND: usize = 20;
/// Pointer moves per second, counted apart from the actions: a drag across a slider sends a stream of
/// them, and 30 a second keeps it smooth (the plan's POC 3).
pub(crate) const VIEWER_MOVES_PER_SECOND: usize = 30;
/// Room around a check in the zoomed view, in CSS pixels, so its edges and labels show.
const ZOOM_PAD: f64 = 40.0;
/// How far the zoom may enlarge a check; past this a phone shows JPEG blur, not detail.
const ZOOM_MAX: f64 = 3.0;
/// The width a zoomed view aims for: a phone held upright.
const ZOOM_WIDTH: f64 = 480.0;

/// Spends one of `limit` a second from `times`, or refuses. "Too many …" is the wording the service
/// maps to 429 (SR-8).
fn spend(times: &mut std::collections::VecDeque<Instant>, limit: usize, what: &str) -> EngineResult<()> {
    let now = Instant::now();
    while times.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(1)) {
        times.pop_front();
    }
    if times.len() >= limit {
        return Err(EngineError(format!("Too many {what}: at most {limit} a second.")));
    }
    times.push_back(now);
    Ok(())
}

/// The zoomed view around a check's box: padded, kept inside the viewport, scaled up to fit a phone.
pub(crate) fn zoom_clip(b: BoundingBox, vw: f64, vh: f64) -> (BoundingBox, f64) {
    let x = (b.x - ZOOM_PAD).max(0.0);
    let y = (b.y - ZOOM_PAD).max(0.0);
    let right = (b.x + b.width + ZOOM_PAD).min(vw.max(x + 1.0));
    let bottom = (b.y + b.height + ZOOM_PAD).min(vh.max(y + 1.0));
    let clip = BoundingBox { x, y, width: (right - x).max(1.0), height: (bottom - y).max(1.0) };
    let scale = (ZOOM_WIDTH / clip.width).clamp(1.0, ZOOM_MAX);
    (clip, scale)
}

/// One live-view frame. During a check it is zoomed onto the check's frame (unless the owner asked for
/// the whole page), so a phone shows it big enough to use. `clip` says what the image covers, in the
/// page's viewport coordinates, so the viewer can turn a tap on the image into a page point.
async fn viewer_frame(page: &Page, checking: bool, passkey: bool, args: &Value) -> EngineResult {
    let whole = args.get("whole").is_some_and(truthy);
    let target = if checking && !passkey && !whole { super::verify::challenge_box(page).await } else { None };
    let view = page.visual_viewport().await?;
    let (image, clip, scale) = if let Some(b) = target {
        let (clip, scale) = zoom_clip(b, view.width, view.height);
        (page.screenshot_jpeg_clip(75, clip, scale).await?, clip, scale)
    } else {
        let clip = BoundingBox { x: 0.0, y: 0.0, width: view.width, height: view.height };
        (capture(page, 75).await?, clip, 1.0)
    };
    Ok(json!({
        "image": image,
        "url": super::report_url(&page.url()),
        "checking": checking,
        // A passkey hand-off: the page says so, and asks for the pop-up, not a check.
        "passkey": passkey,
        "zoomed": target.is_some(),
        "clip": { "x": clip.x, "y": clip.y, "width": clip.width, "height": clip.height, "scale": scale },
    }))
}

fn arg<'a>(args: &'a Value, key: &str) -> Option<&'a Value> {
    args.get(key).filter(|v| !v.is_null())
}

/// A `fill` or `type` step's text, which must be a string: `Supply text to <verb>.` otherwise.
fn text_to(args: &Value, verb: &str) -> Result<String, Failed> {
    match arg(args, "text") {
        Some(Value::String(text)) => Ok(text.clone()),
        _ => Err(Failed::Settled(EngineError(format!("Supply text to {verb}.")))),
    }
}

/// The point `actionable.js` gave for a selector's element that only an open shadow root has, read back
/// from the wait's failure: `… (an open shadow root has it at 32,192: click_xy reaches it …`.
pub(super) fn in_shadow_at(e: &Failed) -> Option<(f64, f64)> {
    let (Failed::Settled(EngineError(m)) | Failed::Unsure(EngineError(m))) = e;
    shadow_point(m)
}

/// [`in_shadow_at`] for the failure's words alone.
pub(super) fn shadow_point(m: &str) -> Option<(f64, f64)> {
    let (_, at) = m.split_once(": not found in the document (an open shadow root has it at ")?;
    let (x, rest) = at.split_once(',')?;
    let (y, _) = rest.split_once(": click_xy reaches it")?;
    Some((x.parse().ok()?, y.parse().ok()?))
}

/// `act`'s action. A click given a point and no selector is a click at that point: agents reading a
/// snapshot's `32,192` wrote `click` with x and y, in 5 of 25 of one task's runs in climb
/// 2026-11-13-phantab-2x-faster-than-competition, and each spent a call on the failure.
fn act_action(args: &Value) -> EngineResult<String> {
    let action = arg_str(args, "action").unwrap_or_else(|| "undefined".to_owned());
    let selector_given = matches!(arg(args, "selector"), Some(Value::String(_)));
    if action == "click" && !selector_given && arg(args, "x").is_some() && arg(args, "y").is_some() {
        return Ok("click_xy".to_owned());
    }
    if ["click", "fill", "select"].contains(&action.as_str()) && !selector_given {
        let point = if action == "click" { ", or x and y to click at a point" } else { "" };
        return Err(EngineError(format!("Supply a selector to {action}{point}.")));
    }
    Ok(action)
}

/// A mouse click at a point. If only the release times out, the button stays recorded as pressed and every
/// later click refuses, so a failed click resets the mouse.
async fn click_at(p: &Page, x: f64, y: f64) -> Result<(), CdpError> {
    let clicked = p.mouse_click(x, y).await;
    if clicked.is_err() {
        let page = p.clone();
        super::relay::fire(async move {
            let _ = page.mouse_reset().await;
        });
    }
    clicked
}

fn arg_str(args: &Value, key: &str) -> Option<String> {
    arg(args, key).map(|v| js_string(Some(v)))
}

/// JavaScript's `typeof` of a JSON value (absent is `undefined`).
fn type_of(v: Option<&Value>) -> &'static str {
    match v {
        None => "undefined",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Null | Value::Array(_) | Value::Object(_)) => "object",
    }
}

fn is_website(url: &str) -> bool {
    url.starts_with("http:") || url.starts_with("https:")
}

/// `unconfirmed(e, what)`: a slow page can outlast the protocol timeout on an input event and still apply
/// it, and a resend then types twice. phantab: a covered click is left as it is: nothing was sent, and
/// its text names what covers the element, which the page chose (an `id` can read "timed out").
fn unconfirmed(e: EngineError, what: &str) -> EngineError {
    if !e.0.starts_with(phantab_cdp::COVERED_PREFIX) && e.0.to_lowercase().contains("timed out") {
        EngineError(format!(
            "{what}: the page did not confirm in time, but it may still have landed. Screenshot before repeating it."
        ))
    } else {
        e
    }
}

/// Runs `f` unless `signal` aborts first (a locator's `{signal}`).
async fn abortable<T>(signal: &Abort, f: impl Future<Output = Result<T, CdpError>>) -> EngineResult<T> {
    tokio::select! {
        r = f => r.map_err(EngineError::from),
        () = on_abort(Some(signal)) => Err(EngineError("The operation was aborted.".to_owned())),
    }
}

/// A step's wait before it acts: `Some` of the frame to act in, `None` once a click is done here.
///
/// A `click`, `fill` or `select` waits for its element to be ready and answers that element's frame. The
/// act finds its element in that frame alone, so the element waited for (and, with guardrails on,
/// checked) is the one acted on, never another frame's match. Any other action waits for nothing and has
/// no frame. A click whose element only an open shadow root has goes to that element's point, as the
/// failure would tell the agent to do with `click_xy` (a turn more for it); with guardrails on,
/// `confirm_first` has checked that point.
async fn ready_in(
    p: &Page,
    selector: &str,
    action: &str,
    signal: &Abort,
    what: &str,
) -> Result<Option<Option<FrameId>>, Failed> {
    if !["click", "fill", "select"].contains(&action) {
        return Ok(Some(None));
    }
    let waited = poll_actionable(p, selector, Duration::from_secs(10), Some(signal), true).await;
    match (waited, action == "click") {
        (Err(e), true) => {
            let Some((x, y)) = in_shadow_at(&e) else { return Err(e) };
            click_at(p, x, y).await.map_err(|e| unconfirmed(e.into(), what))?;
            Ok(None)
        }
        (waited, _) => waited.map(|frame| Some(Some(frame))),
    }
}

fn origin(url: &str) -> EngineResult<String> {
    let u = url::Url::parse(url).map_err(|_| EngineError("Invalid URL".to_owned()))?;
    Ok(u.origin().ascii_serialization())
}

impl Engine {
    pub(crate) fn validate_url(url: Option<&Value>) -> EngineResult<String> {
        let u = url::Url::parse(&js_string(url)).map_err(|_| EngineError("Invalid URL".to_owned()))?;
        if !["http", "https"].contains(&u.scheme()) {
            return Err(EngineError("Only HTTP(S) website URLs are accepted.".to_owned()));
        }
        Ok(u.to_string())
    }

    /// `get(id, owner, write)`.
    pub(crate) fn get(&self, id: &str, owner: &str, write: bool) -> EngineResult<Arc<Rec>> {
        let r = self
            .find(id)
            .filter(|r| r.lock().owner == owner)
            .ok_or_else(|| EngineError(UNKNOWN_PAGE.to_owned()))?;
        // A filled password must not be left for a screenshot after a site's Show-password toggle, or a
        // later action.
        let held: Arc<dyn SignInRecord> = Arc::clone(&r) as Arc<dyn SignInRecord>;
        crate::signin::check_call(&held)?;
        if write && let Some(refusal) = self.verification_refusal(&r) {
            return Err(refusal);
        }
        let mut s = r.lock();
        if write && s.paused {
            return Err(EngineError(
                "Page is handed to the owner. Wait for handback, then resume.".to_owned(),
            ));
        }
        s.touched = Instant::now();
        drop(s);
        Ok(r)
    }

    /// `pages(owner)`. Another session's orphaned handoff shows only its pageId, mode and origin (SR-29).
    pub(crate) fn pages(&self, owner: &str) -> Value {
        let records = self.st().records.clone();
        let list = records
            .iter()
            .filter_map(|r| {
                let (mine, orphaned) = {
                    let s = r.lock();
                    (s.owner == owner, s.orphaned)
                };
                if !mine && !orphaned {
                    return None;
                }
                let mut d = Self::describe(r);
                if !mine {
                    // SR-29: pageId, mode and the origin (kept under `url`), nothing else: no path,
                    // query, fragment, title or detach text, which can carry what the page said.
                    let url = d.get("url").and_then(Value::as_str).unwrap_or("");
                    let origin = url::Url::parse(url)
                        .map_or_else(|_| String::new(), |u| u.origin().ascii_serialization());
                    d.retain(|k, _| k == "pageId" || k == "mode");
                    d.insert("url".into(), Value::String(origin));
                }
                d.insert("orphaned".into(), Value::Bool(orphaned));
                Some(Value::Object(d))
            })
            .collect();
        Value::Array(list)
    }

    /// `adopt(id, owner, confirmed)`. Only `guardrails: full` asks for the owner's confirmation first
    /// (`docs/GUARDRAILS.md`).
    pub(crate) fn adopt(&self, id: &str, owner: &str, confirmed: bool) -> EngineResult<Arc<Rec>> {
        let confirmed = confirmed || !self.guardrails().full();
        let r = self.find(id);
        let Some(r) = r.filter(|r| r.lock().orphaned && confirmed) else {
            return Err(EngineError(
                "Recover only an orphaned handoff after explicit owner confirmation.".to_owned(),
            ));
        };
        {
            let mut s = r.lock();
            owner.clone_into(&mut s.owner);
            s.orphaned = false;
        }
        Ok(r)
    }

    /// `open`'s url and mode, checked in its order. [`Self::ready_for`] reads them too.
    pub(crate) fn open_args(args: &Value) -> EngineResult<(String, String)> {
        let url = Self::validate_url(arg(args, "url"))?;
        let mode = arg_str(args, "mode").unwrap_or_else(|| "shared-hidden".to_owned());
        // SR-33: any other string is refused, not stored as the mode with a workspace opened; that text
        // would show in other sessions' `pages`.
        if !matches!(mode.as_str(), "shared-hidden" | "visible" | "isolated-headless") {
            return Err(EngineError("mode is shared-hidden, visible or isolated-headless.".to_owned()));
        }
        Ok((url, mode))
    }

    /// `open(owner, {url, mode, profile})`.
    pub(crate) async fn open(&self, owner: &str, args: &Value) -> EngineResult {
        let (url, mode) = Self::open_args(args)?;
        let target = self.open_target(args, &mode)?;
        if mode == "isolated-headless" {
            let executable = self.chrome_executable().ok_or_else(|| {
                EngineError(
                    "isolated-headless needs chromeExecutable in config.json; phantab has no bundled Chrome."
                        .to_owned(),
                )
            })?;
            let b = Arc::new(
                Browser::launch(LaunchOptions {
                    executable,
                    headless: true,
                    user_data_dir: None,
                    args: Vec::new(),
                })
                .await?,
            );
            // Nobody can see a headless page's dialog, so it would block the page until it closed. Its
            // passkey requests are counted, as an agent page's are.
            let options =
                PageOptions { answer_dialogs: true, watch_passkeys: true, ..PageOptions::default() };
            let page = match b.new_page_with(options).await {
                Ok(p) => p,
                Err(e) => {
                    let _ = b.close().await;
                    return Err(e.into());
                }
            };
            if let Err(e) = page.goto(&url, NAVIGATE_TIMEOUT).await {
                let _ = b.close().await;
                return Err(e.into());
            }
            let r = self.record(page, owner, Fields { mode, isolated: Some(b), ..Fields::default() })?;
            return Ok(Value::Object(self.looked(&r, Self::describe(&r)).await));
        }
        let profile = target.profile.clone();
        self.require_browser(&profile).await?;
        let fields = if mode == "visible" {
            let created = self.bridge().op_in(&profile, "createTab", json!({ "url": url })).await?;
            let tab = created
                .get("tabId")
                .and_then(Value::as_i64)
                .ok_or_else(|| EngineError("The bridge answered without a tabId.".to_owned()))?;
            let p = self.page_for(&profile, tab, false).await?;
            (
                p.page,
                Fields {
                    profile: target.profile,
                    profile_name: target.name,
                    mode,
                    tab_id: Some(tab),
                    window_id: created.get("windowId").cloned(),
                    link: Some(p.link),
                    ..Fields::default()
                },
            )
        } else {
            let w = match self.reuse_spare(&profile, owner, &url).await {
                Some(w) => w,
                None => self.create_workspace(&profile, &url).await?,
            };
            (
                w.linked.page,
                Fields {
                    profile: target.profile,
                    profile_name: target.name,
                    mode,
                    tab_id: Some(w.tab_id),
                    window_id: w.window_id,
                    workspace: true,
                    native: w.native,
                    link: Some(w.linked.link),
                    ..Fields::default()
                },
            )
        };
        let r = self.record(fields.0, owner, fields.1)?;
        Ok(Value::Object(self.looked(&r, Self::describe(&r)).await))
    }

    fn is_viewer(&self, url: &str) -> bool {
        url.starts_with(&format!("http://127.0.0.1:{}/view", self.setup.port))
            || self.setup.remote_base.as_ref().is_some_and(|b| url.starts_with(&format!("{b}/view")))
    }

    fn assigned(&self, profile: &Profile, tab: TabId) -> bool {
        // A kept window is no one's to adopt; asked first, as the records' check holds the state lock.
        self.is_spare(profile, tab)
            || self.st().records.iter().any(|r| {
                let s = r.lock();
                r.profile == *profile && (s.tab_id == Some(tab) || s.viewer_tab == Some(tab))
            })
    }

    /// `tabs({profile})`: the profile's website tabs no agent holds.
    pub(crate) async fn tabs(&self, args: &Value) -> EngineResult {
        let profile = self.target(args)?.profile;
        self.require_browser(&profile).await?;
        let tabs = self.bridge().op_in(&profile, "tabs", json!({})).await?;
        let list = tabs.as_array().map(Vec::as_slice).unwrap_or_default();
        let out = list
            .iter()
            .filter(|t| {
                let url = t.get("url").and_then(Value::as_str).unwrap_or("");
                let tab = t.get("tabId").and_then(Value::as_i64);
                is_website(url) && !self.is_viewer(url) && !tab.is_some_and(|id| self.assigned(&profile, id))
            })
            .map(|t| {
                let mut m = Map::new();
                m.insert("tabId".into(), Value::String(js_string(t.get("tabId"))));
                // Absent stays absent, as JSON.stringify drops undefined. Both are the page's own words: cut
                // as a snapshot cuts its title, and as every result cuts a page's URL (SR-34).
                for key in ["title", "url"] {
                    let v = match t.get(key) {
                        Some(Value::String(v)) if key == "url" => Value::String(super::report_url(v)),
                        Some(Value::String(v)) => {
                            Value::String(super::read::utf16_prefix(v, PAGE_TEXT_LIMIT))
                        }
                        Some(v) => v.clone(),
                        None => continue,
                    };
                    m.insert(key.into(), v);
                }
                Value::Object(m)
            })
            .collect();
        Ok(Value::Array(out))
    }

    /// `attach(owner, {tabId, profile})`: `Number(tabId)` must be an integer.
    pub(crate) async fn attach(&self, owner: &str, args: &Value) -> EngineResult {
        let target = self.target(args)?;
        let profile = target.profile.clone();
        self.require_browser(&profile).await?;
        let id = match arg(args, "tabId") {
            Some(Value::Number(n)) => {
                n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(js_int))
            }
            Some(Value::String(s)) => {
                let s = s.trim();
                if s.is_empty() {
                    Some(0)
                } else {
                    s.parse::<f64>().ok().filter(|f| f.fract() == 0.0).map(js_int)
                }
            }
            Some(Value::Bool(b)) => Some(i64::from(*b)),
            _ => None,
        };
        let Some(id) = id else { return Err(EngineError("Unknown tab id. List tabs again.".to_owned())) };
        if self.assigned(&profile, id) {
            return Err(EngineError("Tab is already assigned to an agent.".to_owned()));
        }
        let t = match self.bridge().op_in(&profile, "tab", json!({ "tabId": id })).await {
            Ok(t) if truthy(&t) => t,
            _ => return Err(EngineError("Tab no longer exists. List tabs again.".to_owned())),
        };
        let url = t.get("url").and_then(Value::as_str).unwrap_or("");
        if !is_website(url) || self.is_viewer(url) {
            return Err(EngineError("Select a normal website tab in the configured profile.".to_owned()));
        }
        let p = self.page_for(&profile, id, false).await?;
        let r = self.record(
            p.page,
            owner,
            Fields {
                profile: target.profile,
                profile_name: target.name,
                owned: Some(false),
                mode: "existing-tab".to_owned(),
                tab_id: Some(id),
                window_id: t.get("windowId").cloned(),
                link: Some(p.link),
                ..Fields::default()
            },
        )?;
        Ok(Value::Object(Self::describe(&r)))
    }

    // The queue keys page calls by the same function, so the page it holds for a call is the page the
    // call gets.
    fn page_id(args: &Value) -> String {
        crate::engine_api::page_id(args)
    }

    /// The sign-up sweep (SR-80, SR-81) on a page a sign-up filled: a copy of the new password is
    /// blanked, or the page ended, before the call reads or acts. Nothing on any other page.
    async fn sweep_sign_up(&self, r: &Arc<Rec>) -> EngineResult<()> {
        let held: Arc<dyn SignInRecord> = Arc::clone(r) as Arc<dyn SignInRecord>;
        crate::signin::sweep_sign_up(self, &held).await.map(drop)
    }

    /// `snapshot(owner, {pageId})`. At parity a text field also says what it holds (THREAT-MODEL R8),
    /// except on a page whose screenshot is refused: one that showed a password or code back, or holds a
    /// sign-up's new password.
    pub(crate) async fn snapshot(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&Self::page_id(args), owner, false)?;
        let held: Arc<dyn SignInRecord> = Arc::clone(&r) as Arc<dyn SignInRecord>;
        let new_password = crate::signin::sweep_sign_up(self, &held).await?;
        let values = self.guardrails() == super::guardrails::Guardrails::Parity
            && !new_password
            && r.on_page().is_none()
            && !self.echo_marked(&r);
        let data = self
            .cdp(&r, None, |page, _| async move { read_page(&page, values).await.map_err(Failed::from) })
            .await?;
        let mut out = Self::describe_reporting(&r);
        out.extend(data);
        Ok(Value::Object(self.looked(&r, out).await))
    }

    /// `lock(r, url)`: the site lease a write takes. An isolated page shares no site with anyone. A lease is
    /// a site in one Chrome profile: two profiles are two logins, so each can change the same site at once.
    /// Under `siteLock: shared` (the default) no other page holds the site against this one, handed over or
    /// not; a handed-over page refuses its own writes in `get`, not here.
    pub(crate) fn lock_site(&self, r: &Arc<Rec>, url: Option<&str>) -> EngineResult<()> {
        let (isolated, owner, current) = {
            let s = r.lock();
            (s.isolated.is_some(), s.owner.clone(), s.page.url())
        };
        if isolated || self.site_lock() == super::guardrails::SiteLock::Shared {
            return Ok(());
        }
        let origin = (r.profile.clone(), origin(url.unwrap_or(&current))?);
        let mut st = self.st();
        let holders: Vec<String> =
            st.origins.iter().find(|(o, _)| *o == origin).map(|(_, ids)| ids.clone()).unwrap_or_default();
        let held = holders.iter().find_map(|id| {
            if id == &r.id {
                return None;
            }
            st.records.iter().find(|x| &x.id == id).filter(|other| {
                let o = other.lock();
                o.owner != owner || o.paused
            })
        });
        if let Some(holder) = held.cloned() {
            drop(st);
            // A check on the site says so, and where its link is, rather than the generic refusal. Only to
            // the page's own session: the text carries its pageId and link (SR-29, SR-71).
            let same_owner = holder.lock().owner == owner;
            if same_owner && let Some(refusal) = self.verification_refusal(&holder) {
                return Err(refusal);
            }
            return Err(EngineError(
                "Another agent or human handoff holds this site for changes. Wait for its release or handback.".to_owned(),
            ));
        }
        match st.origins.iter_mut().find(|(o, _)| *o == origin) {
            Some((_, ids)) => {
                if !ids.contains(&r.id) {
                    ids.push(r.id.clone());
                }
            }
            None => st.origins.push((origin, vec![r.id.clone()])),
        }
        Ok(())
    }

    /// `screenshot(owner, {pageId})`.
    pub(crate) async fn screenshot(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&Self::page_id(args), owner, false)?;
        // An image of a page that showed a password or code back cannot be redacted.
        if self.echo_marked(&r) {
            return Err(EngineError(super::echo::SCREENSHOT_REFUSED.to_owned()));
        }
        // While a sign-up's new password is on the page, no picture of it (SR-82).
        let held: Arc<dyn SignInRecord> = Arc::clone(&r) as Arc<dyn SignInRecord>;
        crate::signin::before_screenshot(self, &held).await?;
        let data = self
            .cdp(&r, None, |page, _| async move {
                capture(&page, 80).await.map_err(|e| {
                    if e.to_string().contains("timed out") {
                        EngineError(
                            "Screenshot: the page did not paint in time, usually while it is loading. Retry in a few seconds."
                                .to_owned(),
                        )
                    } else {
                        e.into()
                    }
                })
            })
            .await?;
        Ok(json!({ "data": data, "mimeType": "image/jpeg" }))
    }

    /// `wait(owner, {pageId, selector, text, seconds})`.
    pub(crate) async fn wait(&self, owner: &str, args: &Value) -> EngineResult {
        let id = Self::page_id(args);
        let r = self.get(&id, owner, false)?;
        self.sweep_sign_up(&r).await?;
        if arg(args, "verification").is_some_and(truthy) {
            let within = arg(args, "seconds")
                .and_then(Value::as_f64)
                .filter(|s| *s > 0.0)
                .map_or(super::verify::WAIT_LIMIT, |s| Duration::from_secs_f64(s.min(60.0)));
            return Ok(self.wait_check(&r, within).await);
        }
        let selector = arg(args, "selector").filter(|v| truthy(v)).cloned();
        let text = arg(args, "text").filter(|v| truthy(v)).cloned();
        let seconds = arg(args, "seconds").and_then(Value::as_f64).filter(|s| *s > 0.0);
        if selector.is_none() && text.is_none() {
            let Some(seconds) = seconds else {
                return Err(EngineError(
                    "Supply a selector, visible text or seconds to wait for.".to_owned(),
                ));
            };
            tokio::time::sleep(Duration::from_secs_f64(seconds.min(60.0))).await;
            let r = self.get(&id, owner, false)?;
            return Ok(Value::Object(Self::describe(&r)));
        }
        let label = [&selector, &text]
            .into_iter()
            .flatten()
            .map(|v| js_string(Some(v)))
            .collect::<Vec<_>>()
            .join(" + ");
        let check_args = [selector.unwrap_or(Value::Null), text.unwrap_or(Value::Null)];
        let waited = self
            .cdp(&r, None, |page, signal| {
                let label = label.clone();
                let check_args = check_args.clone();
                async move {
                    poll_until(&page, &label, PRESENT, &check_args, Duration::from_secs(15), Some(&signal))
                        .await
                }
            })
            .await;
        if let Err(e) = waited {
            return Err(self.explain(&r, e).await);
        }
        Ok(Value::Object(self.looked(&r, Self::describe_reporting(&r)).await))
    }

    /// `act(owner, {pageId, action, selector, text, url, key, x, y, deltaY})`.
    pub(crate) async fn act(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&Self::page_id(args), owner, true)?;
        self.lock_site(&r, None)?;
        self.sweep_sign_up(&r).await?;
        let action = act_action(args)?;
        let what =
            if action == "press" { format!("press {}", js_string(arg(args, "key"))) } else { action.clone() };
        let workspace = r.lock().workspace;
        if let Err(e) = self.confirm_first(&r, args, &action).await {
            return Err(self.explain(&r, e).await);
        }
        let acted = self
            .cdp(&r, Some(&action), |p, signal| {
                let (action, what) = (action.clone(), what.clone());
                let r = Arc::clone(&r);
                async move {
                    let said = |e: EngineError| unconfirmed(e, &what);
                    let selector = js_string(arg(args, "selector"));
                    // The frame whose element the wait found ready, where the act finds it alone (`ready_in`).
                    let Some(frame) = ready_in(&p, &selector, &action, &signal, &what).await? else {
                        return Ok(());
                    };
                    let frame = frame.as_ref();
                    match action.as_str() {
                        "navigate" => {
                            let url = Self::validate_url(arg(args, "url")).map_err(Failed::Settled)?;
                            self.lock_site(&r, Some(&url)).map_err(Failed::Settled)?;
                            p.goto(&url, NAVIGATE_TIMEOUT).await?;
                        }
                        // A hidden workspace delivers no animation frames, so it clicks the
                        // element itself. The locator click's own waits end on timers there (the sign-in's
                        // press uses it), but slowly, as a background tab's timers run about once a second.
                        "click" if workspace => {
                            p.eval_on_selector_in(frame, &selector, CLICK)
                                .await
                                .map_err(|e| said(e.into()))?;
                        }
                        "click" => {
                            abortable(&signal, p.click_selector_in(frame, &selector))
                                .await
                                .map_err(said)
                                .map(drop)?;
                        }
                        "fill" => {
                            let text = text_to(args, "fill")?;
                            abortable(&signal, p.fill_in(frame, &selector, &text)).await.map_err(said)?;
                        }
                        "select" => {
                            let value = arg(args, "text");
                            let Some(Value::String(v)) = value else {
                                return Err(Failed::Settled(EngineError(format!(
                                    "Values must be strings. Found value \"{}\" of type \"{}\"",
                                    cut(&js_string(value), PAGE_TEXT_LIMIT),
                                    type_of(value)
                                ))));
                            };
                            let options = p
                                .eval_on_selector_in(frame, &selector, SELECT_OPTIONS)
                                .await
                                .map_err(|e| said(e.into()))?;
                            let v = pick_option(&options, v)
                                .map_err(|why| Failed::Settled(EngineError(format!("{selector}: {why}"))))?;
                            p.select_in(frame, &selector, &[v]).await.map_err(|e| said(e.into()))?;
                        }
                        // A timed-out key-down never gets its key-up, and the next press of that key would then go
                        // out as a repeat.
                        "press" => {
                            let key = js_string(arg(args, "key"));
                            if let Err(e) = p.key_down(&key).await {
                                let (page, key) = (p.clone(), key.clone());
                                super::relay::fire(async move {
                                    let _ = page.key_up(&key).await;
                                });
                                return Err(said(e.into()).into());
                            }
                            p.key_up(&key).await.map_err(|e| said(e.into()))?;
                        }
                        // Text typed at the focus, as a person types it: what `press` sends for each key,
                        // and the text itself for what no key on the layout makes.
                        "type" => {
                            let text = text_to(args, "type")?;
                            p.type_text(&text).await.map_err(|e| said(e.into()))?;
                        }
                        "scroll" => {
                            let dy = arg(args, "deltaY").and_then(Value::as_f64).unwrap_or(600.0);
                            p.mouse_wheel(dy).await.map_err(|e| said(e.into()))?;
                        }
                        "click_xy" => {
                            let x = arg(args, "x").and_then(Value::as_f64).unwrap_or(f64::NAN);
                            let y = arg(args, "y").and_then(Value::as_f64).unwrap_or(f64::NAN);
                            click_at(&p, x, y).await.map_err(|e| said(e.into()))?;
                        }
                        _ => return Err(Failed::Settled(EngineError("Unsupported action".to_owned()))),
                    }
                    Ok::<(), Failed>(())
                }
            })
            .await;
        // The action may have put the new password somewhere else (a copy, a reveal): swept again first,
        // so a page that leaked it is ended whatever the action answered.
        self.sweep_sign_up(&r).await?;
        if let Err(e) = acted {
            return Err(self.explain(&r, e).await);
        }
        Ok(Value::Object(self.looked(&r, Self::describe_reporting(&r)).await))
    }

    fn handoff(r: &Rec, handoff: &str, exact: bool) -> Value {
        let mut d = Self::describe(r);
        d.insert("handoff".into(), Value::String(handoff.to_owned()));
        if exact {
            d.insert("exactPage".into(), Value::Bool(true));
        }
        Value::Object(d)
    }

    /// `show(owner, {pageId})`.
    pub(crate) async fn show(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&Self::page_id(args), owner, false)?;
        if arg(args, "verification").is_some_and(truthy) {
            return self.show_check(&r).await;
        }
        let release = arg(args, "release").is_some_and(truthy);
        if release {
            self.may_release(&r)?;
        }
        // Paused already, so shown already, unless a hand-back's failed keep left its window hidden: that one
        // is shown again, as the owner asked. The record already holds its site, being paused. A live check
        // Phantab started and has not popped up yet is paused with its window hidden on purpose (its grace):
        // it answers as shown, as before, and makes no window call, since a check that ends there gives the
        // page back unhidden. Both under one guard: a check ends by unpausing before it reports its outcome,
        // so "paused, and the check that paused it has ended" is never seen.
        let (again, grace) = {
            let s = r.lock();
            (s.paused, s.verification.as_ref().is_some_and(|v| v.current().live() && !v.shown))
        };
        if again && !release && (grace || !self.reads_hidden(&r).await) {
            let mut out = Self::handoff(&r, "already-shown", false);
            if let (Value::Object(m), Some(v)) = (&mut out, self.verification_field(&r)) {
                m.insert("verification".into(), v);
            }
            return Ok(out);
        }
        // A page given away for good takes no hold on its site: it is about to hold none.
        if !again && !release {
            self.lock_site(&r, None)?;
        }
        let (workspace, handback) = {
            let mut s = r.lock();
            s.paused = true;
            let handback = std::mem::take(&mut s.handback);
            (s.workspace, handback)
        };
        match self.show_inner(&r, workspace).await {
            Ok(_) if release => Ok(self.let_go(&r)),
            Ok(v) => Ok(v),
            Err(e) => {
                let window_id = {
                    let mut s = r.lock();
                    // A record shown again goes back to where it was: still paused, not the agent's.
                    if again {
                        s.handback = handback;
                    } else {
                        s.paused = false;
                    }
                    s.window_id.clone()
                };
                if workspace && (!again || self.reads_hidden(&r).await) {
                    let _ = self
                        .bridge()
                        .op_in(&r.profile, "markShown", json!({ "windowId": window_id, "shown": false }))
                        .await;
                }
                Err(e)
            }
        }
    }

    /// Whether `browser_show` may give this page to the owner for good (`release: true`). A page in
    /// phantab's own isolated browser has no tab of the owner's to become, and a check phantab is handing
    /// to the owner ends by itself first (SR-69).
    fn may_release(&self, r: &Arc<Rec>) -> EngineResult<()> {
        if r.lock().isolated.is_some() {
            return Err(EngineError(
                "release: an isolated page lives in phantab's own browser, not yours, so it cannot become your tab. Use browser_show without release."
                    .to_owned(),
            ));
        }
        match self.verification_refusal(r) {
            Some(refusal) => Err(refusal),
            None => Ok(()),
        }
    }

    /// The end of `show` with `release: true`, once the page is on the owner's screen: the agent's record
    /// of it ends (its debugger is detached, its site hold dropped) and the tab stays open as the owner's
    /// ordinary tab. A workspace window was marked shown before the reveal, so the extension already treats
    /// it as the owner's: it never closes it, mutes it or answers its dialogs.
    fn let_go(&self, r: &Arc<Rec>) -> Value {
        let mut out = Self::describe(r);
        out.remove("paused");
        out.insert("handoff".into(), Value::String("released".to_owned()));
        self.forget(&r.id);
        Value::Object(out)
    }

    pub(crate) async fn show_inner(&self, r: &Arc<Rec>, workspace: bool) -> EngineResult {
        let (tab, window_id, mode) = {
            let s = r.lock();
            (s.tab_id, s.window_id.clone(), s.mode.clone())
        };
        if workspace {
            // A re-attach still running would put the fixed size back after the clear below.
            Self::settle_recovery(r).await;
            r.lock().shown_once = true;
            // Marked shown first, so a bridge drop mid-takeover leaves the owner's window open.
            self.bridge()
                .op_in(&r.profile, "markShown", json!({ "windowId": window_id, "shown": true }))
                .await?;
            // Left on, Chrome paints the fixed viewport as a box in the corner of the owner's window, gray
            // around it. Not a reload, so unsaved input stays. Chrome already cleared a detached page's.
            // Started before the reveal so the owner never sees the box; a busy page's slow answer doesn't
            // hold the window back.
            let (page, detached) = {
                let s = r.lock();
                (s.page.clone(), s.detached.is_some())
            };
            let mut fit = Box::pin(async move {
                if !detached {
                    let _ = page.set_viewport(None).await;
                }
            });
            let fitted = matches!(futures_util::poll!(fit.as_mut()), Poll::Ready(()));
            self.visibility(r, true).await?;
            self.bridge().op_in(&r.profile, "focus", json!({ "tabId": tab })).await?;
            if !fitted {
                fit.await;
            }
            return Ok(Self::handoff(r, "actual-tab", true));
        }
        if mode == "existing-tab" || mode == "visible" {
            self.bridge().op_in(&r.profile, "focus", json!({ "tabId": tab })).await?;
            return Ok(Self::handoff(r, "actual-tab", false));
        }
        let existing = r.lock().viewer_token.clone();
        let token = if let Some(t) = existing {
            t
        } else {
            let t = random_hex(24).map_err(|e| EngineError(e.to_string()))?;
            r.lock().viewer_token = Some(t.clone());
            self.st().viewers.push(super::Viewer { token: t.clone(), page: r.id.clone(), remote: false });
            t
        };
        let viewer_url = format!("http://127.0.0.1:{}/view#{token}", self.setup.port);
        // The token stays local and is never returned through MCP or command-line arguments.
        self.require_browser(&r.profile).await?;
        let viewer_tab = r.lock().viewer_tab;
        let focused = match viewer_tab {
            Some(t) => self.bridge().op_in(&r.profile, "focus", json!({ "tabId": t })).await.is_ok(),
            None => false,
        };
        if !focused {
            let created = self.bridge().op_in(&r.profile, "createTab", json!({ "url": viewer_url })).await?;
            r.lock().viewer_tab = created.get("tabId").and_then(Value::as_i64);
        }
        Ok(Self::handoff(r, "interactive-live-view", true))
    }

    /// `resume(owner, {pageId, ownerConfirmed})`.
    pub(crate) async fn resume(&self, owner: &str, args: &Value) -> EngineResult {
        let id = Self::page_id(args);
        let confirmed = arg(args, "ownerConfirmed").is_some_and(truthy);
        let orphaned = self.find(&id).is_some_and(|r| r.lock().orphaned);
        let r = if orphaned { self.adopt(&id, owner, confirmed)? } else { self.get(&id, owner, false)? };
        // A check Phantab is handing to the owner ends by itself; the agent waits for it, it does not
        // resume it (SR-69).
        if let Some(refusal) = self.verification_refusal(&r) {
            return Err(refusal);
        }
        let (paused, handback) = {
            let mut s = r.lock();
            if confirmed && s.isolated.is_none() {
                s.handback = true;
            }
            (s.paused, s.handback)
        };
        // Without `guardrails: full` the agent's own word that the owner is done is enough
        // (`docs/GUARDRAILS.md`).
        if paused && !handback && self.guardrails().full() {
            return Err(EngineError(
                "Wait for owner handback: Return to agent in the isolated live view, or ownerConfirmed after explicit handback for shared tabs."
                    .to_owned(),
            ));
        }
        self.hand_back(&r, false).await?;
        // A check that came up while the owner already held the page ends with his handback.
        self.drop_check(&r);
        Ok(Value::Object(Self::describe(&r)))
    }

    /// The handback half of `resume`, shared with the end of a verification check: hides a workspace
    /// window again, ends the live view, unpauses. `close_viewer` also closes the local viewer tab, which
    /// a verification opened and so takes away again; `resume` leaves it.
    pub(crate) async fn hand_back(&self, r: &Arc<Rec>, close_viewer: bool) -> EngineResult<()> {
        let (workspace, window_id) = {
            let s = r.lock();
            (s.workspace, s.window_id.clone())
        };
        if workspace {
            if let Err(e) = self.visibility(r, false).await {
                // A keep that failed still hides the window (`visibility`). The extension then hears it is
                // hidden, so it mutes it, answers its dialogs for the agent and may close it, as for every
                // hidden agent window. The record stays paused: the agent hears the error and waits for a
                // resume that works, and `show` shows the window again. A window still shown keeps its mark.
                if self.reads_hidden(r).await {
                    let _ = self
                        .bridge()
                        .op_in(&r.profile, "markShown", json!({ "windowId": window_id, "shown": false }))
                        .await;
                }
                return Err(e);
            }
            self.bridge()
                .op_in(&r.profile, "markShown", json!({ "windowId": window_id, "shown": false }))
                .await?;
        }
        let (token, tab, detached, page, viewer_tab) = {
            let mut s = r.lock();
            s.paused = false;
            s.handback = false;
            let viewer_tab = if close_viewer { s.viewer_tab.take() } else { None };
            (s.viewer_token.take(), s.tab_id, s.detached.is_some(), s.page.clone(), viewer_tab)
        };
        if let Some(token) = token {
            self.st().viewers.retain(|v| v.token != token);
        }
        if let Some(t) = viewer_tab {
            let _ = self.bridge().op_in(&r.profile, "closeTab", json!({ "tabId": t })).await;
        }
        // A page still detached gets both from recover at its next call. A re-attach during the takeover
        // ended the screencast. The handback has already happened, so a page too busy to answer, or a
        // detach not yet reported, is not its failure.
        if workspace && !detached {
            let _ = self.bridge().op_in(&r.profile, "keepRendering", json!({ "tabId": tab })).await;
            let _ = Self::prepare(&page).await;
        }
        Ok(())
    }

    /// `close(owner, {pageId})`. Closing an agent's own tab takes the field with it; an owner's tab stays
    /// open, so it waits for the blank.
    pub(crate) async fn close(&self, owner: &str, args: &Value) -> EngineResult {
        let id = Self::page_id(args);
        self.close_page(owner, &id).await
    }

    async fn close_page(&self, owner: &str, id: &str) -> EngineResult {
        if let Some(r) = self.find(id).filter(|r| r.lock().owner == owner) {
            self.end_with_page(&r);
        }
        let held = self.find(id).filter(|h| {
            let s = h.lock();
            s.owner == owner && s.owned && s.sign_in == Some(Phase::Unblanked) && !s.paused
        });
        let r = match held {
            Some(r) => r,
            None => self.get(id, owner, true)?,
        };
        let (viewer_tab, isolated, owns_tab) = {
            let s = r.lock();
            (s.viewer_tab, s.isolated.clone(), s.owned)
        };
        if let Some(t) = viewer_tab {
            let _ = self.bridge().op_in(&r.profile, "closeTab", json!({ "tabId": t })).await;
        }
        if let Some(b) = isolated {
            b.close().await?;
        } else if owns_tab && self.keep_spare(&r).await {
            // Kept for this client's next open; it closes by itself if none comes (`window::Spare`).
        } else if owns_tab {
            self.close_tab(&r).await?;
        }
        self.forget(id);
        Ok(json!({ "released": true, "closedOwnedTab": owns_tab }))
    }

    /// `release(owner)`: a page mid-handoff or mid-sign-in is orphaned instead of closed.
    pub(crate) async fn release_all(&self, owner: &str) -> EngineResult {
        let records = self.st().records.clone();
        for r in records {
            let mine = r.lock().owner == owner;
            if !mine {
                continue;
            }
            // Nobody is left to carry on after a check Phantab started, so its page closes like any other.
            self.end_with_page(&r);
            let busy = {
                let s = r.lock();
                s.paused || s.sign_in.is_some()
            };
            if busy {
                r.lock().orphaned = true;
            } else {
                self.close_page(owner, &r.id).await?;
            }
        }
        // A client that releases opens nothing more.
        self.release_spare(owner).await;
        Ok(json!({ "released": true }))
    }

    /// The page whose hand-off `token` views, among the tokens of the listener it came in on (`remote`).
    /// Every key is compared, in constant time, with no early exit (SR-8).
    pub(crate) fn viewer_page(&self, token: &str, remote: bool) -> Option<String> {
        let st = self.st();
        let mut found = None;
        for v in &st.viewers {
            if same_secret(v.token.as_bytes(), token.as_bytes()) && v.remote == remote {
                found = Some(v.page.clone());
            }
        }
        found
    }

    /// `viewer(token, action, args)`. The token is compared in constant time (SR-8), and only against
    /// the tokens of the listener it came in on.
    pub(crate) async fn viewer_call(
        &self,
        token: &str,
        action: Option<&str>,
        args: &Value,
        remote: bool,
    ) -> EngineResult {
        let ended = || EngineError("This handoff has ended.".to_owned());
        let id = self.viewer_page(token, remote);
        let r = id.and_then(|id| self.find(&id)).filter(|r| r.lock().paused).ok_or_else(ended)?;
        let page: Page = r.page();
        let (checking, passkey) = {
            let s = r.lock();
            let live = s.verification.as_ref().filter(|v| v.current().live());
            (live.is_some(), live.is_some_and(|v| v.kind == super::record::CheckKind::Passkey))
        };
        match action {
            Some("frame") => return viewer_frame(&page, checking, passkey, args).await,
            Some("handback") => {
                r.lock().handback = true;
                return Ok(json!({ "ready": true }));
            }
            Some("done") => return self.owner_done(&r).await,
            Some("decline") => return Ok(Self::owner_declined(&r)),
            _ => {}
        }
        {
            let mut s = r.lock();
            if s.handback {
                return Err(EngineError("Control has been returned to the agent.".to_owned()));
            }
            let pointer_move = action == Some("pointer") && args.get("type") == Some(&json!("move"));
            if pointer_move {
                spend(&mut s.viewer_moves, VIEWER_MOVES_PER_SECOND, "pointer moves")?;
            } else if matches!(action, Some("click" | "type" | "press" | "scroll" | "pointer")) {
                spend(&mut s.viewer_actions, VIEWER_ACTIONS_PER_SECOND, "viewer actions")?;
            }
        }
        let num = |k: &str| args.get(k).and_then(Value::as_f64).unwrap_or(f64::NAN);
        match action {
            Some("click") => page.mouse_click(num("x"), num("y")).await?,
            Some("type") => page.type_text(&js_string(args.get("text"))).await?,
            Some("press") => page.key_press(&js_string(args.get("key"))).await?,
            Some("scroll") => page.mouse_wheel(num("deltaY")).await?,
            // A press-and-hold or a slider is the owner's own pointer, relayed as he moves it.
            // Where it is held is kept, so a release that never arrives can be sent when the check ends.
            Some("pointer") => {
                let (x, y) = (num("x"), num("y"));
                match args.get("type").and_then(Value::as_str) {
                    Some("down") => {
                        page.mouse_down(x, y).await?;
                        r.lock().pointer_held = Some((x, y));
                    }
                    Some("move") => {
                        page.mouse_move(x, y).await?;
                        if let Some(held) = r.lock().pointer_held.as_mut() {
                            *held = (x, y);
                        }
                    }
                    Some("up") => {
                        r.lock().pointer_held = None;
                        page.mouse_up(x, y).await?;
                    }
                    _ => return Err(EngineError("pointer type is down, move or up.".to_owned())),
                }
            }
            _ => return Err(EngineError("Unsupported viewer action".to_owned())),
        }
        Ok(json!({ "ok": true }))
    }

    /// Ends a live check Phantab started on a page that is about to close or be released.
    fn end_with_page(&self, r: &Arc<Rec>) {
        let ours = r.lock().verification.as_ref().is_some_and(|v| v.current().live() && !v.prior_paused);
        if ours {
            self.drop_check(r);
        }
    }

    /// `dispose()`: refuses while the owner holds a page.
    pub(crate) async fn dispose_all(&self) -> EngineResult<()> {
        let records = self.st().records.clone();
        if records.iter().any(|r| r.lock().paused) {
            return Err(EngineError(
                "Owner takeover is active; return control before stopping the service.".to_owned(),
            ));
        }
        for r in records {
            let (isolated, owned) = {
                let s = r.lock();
                (s.isolated.clone(), s.owned)
            };
            if let Some(b) = isolated {
                b.close().await?;
            } else if owned {
                self.close_tab(&r).await?;
            }
            self.forget(&r.id);
        }
        Ok(())
    }
}

/// The option value a select of `want` picks, from `options` (`select_options.js`'s `[value, label]`
/// list): the option whose value is `want`, else the one whose label is (trimmed, case aside), so the
/// label a snapshot shows works as well as the value behind it. Anything but a list (not a `<select>`)
/// leaves `want` as it is, for the select itself to refuse. No match is an error naming the options: a
/// select that matched nothing used to succeed with nothing chosen.
fn pick_option(options: &Value, want: &str) -> Result<String, String> {
    let Some(list) = options.as_array() else { return Ok(want.to_owned()) };
    let pairs: Vec<(&str, &str)> =
        list.iter().filter_map(|o| Some((o.get(0)?.as_str()?, o.get(1)?.as_str()?))).collect();
    if pairs.iter().any(|(value, _)| *value == want) {
        return Ok(want.to_owned());
    }
    let folded = want.trim().to_lowercase();
    if let Some((value, _)) = pairs.iter().find(|(_, label)| label.trim().to_lowercase() == folded) {
        return Ok((*value).to_owned());
    }
    let named: Vec<String> = pairs
        .iter()
        .map(
            |(value, label)| {
                if value == label { format!("{value:?}") } else { format!("{label:?} (value {value:?})") }
            },
        )
        .collect();
    Err(format!(
        "no option has the value or label {:?}; the options are {}",
        cut(want, PAGE_TEXT_LIMIT),
        cut(&named.join(", "), PAGE_TEXT_LIMIT)
    ))
}

#[allow(clippy::cast_possible_truncation, reason = "a tab id far outside i64 is not a tab id anyway")]
fn js_int(f: f64) -> i64 {
    f as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_covered_click_is_not_called_unconfirmed() {
        let timeout = EngineError("Waiting timed out after 10000ms".to_owned());
        assert!(unconfirmed(timeout, "click").0.starts_with("click: the page did not confirm in time"));
        // The page chose the covering element's id; nothing was sent, so the error stays as it is.
        let covered = format!("{}<div#timed out>, so the click was not sent.", phantab_cdp::COVERED_PREFIX);
        assert_eq!(unconfirmed(EngineError(covered.clone()), "click").0, covered);
    }

    #[test]
    fn a_select_matches_a_value_then_a_label() {
        let options = json!([["", "Month"], ["1", "January"], ["3", "March"], ["May", "May"]]);
        assert_eq!(pick_option(&options, "3").unwrap(), "3");
        assert_eq!(pick_option(&options, "March").unwrap(), "3");
        assert_eq!(pick_option(&options, " march ").unwrap(), "3");
        assert_eq!(pick_option(&options, "May").unwrap(), "May");
        // A value wins over another option's label.
        let tricky = json!([["March", "Third"], ["3", "March"]]);
        assert_eq!(pick_option(&tricky, "March").unwrap(), "March");
        let none = pick_option(&options, "Marzo").unwrap_err();
        assert!(
            none.starts_with(
                "no option has the value or label \"Marzo\"; the options are \"Month\" (value \"\")"
            ),
            "{none}"
        );
        assert!(none.contains("\"March\" (value \"3\")") && none.contains("\"May\""), "{none}");
        // Not a <select>: left to the select itself.
        assert_eq!(pick_option(&Value::Null, "x").unwrap(), "x");
    }
}
