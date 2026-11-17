//! The measuring tools (THREAT-MODEL SR-91): `emulate` and `trace`, developer tools refused unless
//! `config.json` sets `"devTools": true`, as SR-90's are.
//!
//! `emulate` is a write on one page: it takes the site's lease, a page handed to the owner refuses it,
//! and it lasts until a clear call, the page's close or its release to the owner (`show` with
//! `release`). The page list says which pages have it on. It sets what the page is told (a slower CPU
//! or network, a position, a user agent, a colour scheme), never a permission: a site not allowed to
//! read the location still cannot.
//!
//! `trace` records one page at a time with Chrome's tracing, into the file the agent names, in the
//! Trace Event Format the Performance panel loads. It has a time limit and a size limit, and reaching
//! either ends it. Its categories leave out screenshots and the network log, and the saved file has no
//! `Cookie`, `Set-Cookie`, `Authorization` or `Proxy-Authorization` header and no Chrome command line,
//! and is redacted as every answer is (SR-45). Its numbers come from the page's own performance
//! entries, read in a world of their own ([`phantab_cdp::MEASURE_WORLD`]); a number the page did not
//! report is missing with a reason, never 0.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use phantab_cdp::{CdpError, Page, TRACE_FULL, TraceData};
use serde_json::{Map, Value, json};

use super::Engine;
use super::files::Target;
use super::record::Rec;
use super::recover::Failed;
use crate::engine_api::{EngineError, EngineResult, page_id};
use crate::util::truthy;

/// A trace's time limit, unless `seconds` asks a shorter or longer one, and the most it may ask.
const TRACE_SECONDS: f64 = 30.0;
const TRACE_MOST_SECONDS: f64 = 120.0;
/// Chrome's trace buffer: once it is full the trace ends (the size limit).
const TRACE_BUFFER_KB: u64 = 20 * 1024;
/// The most a saved trace may be; Chrome's JSON is larger than its buffer.
const TRACE_MOST_BYTES: usize = 128 << 20;
/// How long a stop waits for Chrome to finish writing the trace.
const TRACE_END_WAIT: Duration = Duration::from_secs(30);
/// How often a running trace is checked against its limits.
const TRACE_TICK: Duration = Duration::from_millis(500);

/// What a trace records: the Performance panel's own tracks (tasks, loading, paints, layout shifts,
/// script, user timings, input latency, the CPU profile). No screenshot and no network-log category, so
/// no frame of the page and no request header.
const TRACE_CATEGORIES: &[&str] = &[
    "devtools.timeline",
    "disabled-by-default-devtools.timeline",
    "disabled-by-default-devtools.timeline.frame",
    "disabled-by-default-devtools.timeline.stack",
    "toplevel",
    "v8.execute",
    "blink.console",
    "blink.user_timing",
    "latencyInfo",
    "loading",
    "disabled-by-default-v8.cpu_profiler",
];

/// The headers no saved trace holds, whatever their case, as `phantab_cdp::clean_headers`.
const SECRET_HEADERS: [&str; 4] = ["cookie", "set-cookie", "authorization", "proxy-authorization"];

/// What every stop's numbers come with.
const NUMBERS_NOTE: &str = "Measured in phantab's hidden window: compare runs with each other, and do not publish these as the site's speed. There is no insight analysis or Lighthouse score; open the saved trace in Chrome's Performance panel for the detail.";

/// Run in the measuring world of every new document from its start (and in the current one): keeps
/// the page's largest paint, layout shifts and long tasks as the page reports them. Once per document.
const MEASURE_JS: &str = r##"if (!globalThis.__phantabMeasure) {
  const m = globalThis.__phantabMeasure = { paint: null, shifts: [], tasks: 0, taskMs: 0, observed: [] };
  const watch = (type, take) => {
    try {
      new PerformanceObserver((list) => list.getEntries().forEach(take)).observe({ type, buffered: true });
      m.observed.push(type);
    } catch (e) {}
  };
  watch("largest-contentful-paint", (e) => {
    const el = e.element;
    const name = el ? el.tagName.toLowerCase() + (el.id ? "#" + el.id : "") : null;
    m.paint = { ms: e.startTime, size: e.size, url: e.url || null, element: name };
  });
  watch("layout-shift", (e) => { if (!e.hadRecentInput) m.shifts.push([e.startTime, e.value]); });
  watch("longtask", (e) => { m.tasks += 1; m.taskMs += e.duration; });
}"##;

/// Reads what [`MEASURE_JS`] kept, and the page's own timings, as the stop's `numbers`.
const READ_JS: &str = r#"() => {
  const m = globalThis.__phantabMeasure;
  const missing = (why) => ({ missing: why });
  const round = (ms) => Math.round(ms * 10) / 10;
  const nav = performance.getEntriesByType("navigation")[0];
  const out = {};
  out.load = !nav ? missing("the page has no navigation timing")
    : nav.loadEventEnd > 0 ? { ms: round(nav.loadEventEnd) }
    : missing("the page had not finished loading when the trace ended");
  if (!m) {
    const why = missing("the measuring script did not run in this document");
    return Object.assign(out, { largestPaint: why, layoutShift: why, longTasks: why, slowestRequests: why });
  }
  out.largestPaint = !m.observed.includes("largest-contentful-paint")
    ? missing("this browser does not report the largest paint")
    : m.paint ? Object.assign({ ms: round(m.paint.ms), size: m.paint.size },
        m.paint.element ? { element: m.paint.element } : {}, m.paint.url ? { url: m.paint.url } : {})
    : missing("the page reported no largest paint: it painted nothing large, or not while it was visible");
  if (!m.observed.includes("layout-shift")) {
    out.layoutShift = missing("this browser does not report layout shifts");
  } else {
    let best = 0, cur = 0, first = -1, last = -1;
    for (const [t, v] of m.shifts) {
      if (first >= 0 && t - last < 1000 && t - first < 5000) { cur += v; } else { cur = v; first = t; }
      last = t;
      best = Math.max(best, cur);
    }
    out.layoutShift = { score: Math.round(best * 10000) / 10000, shifts: m.shifts.length };
  }
  out.longTasks = !m.observed.includes("longtask") ? missing("this browser does not report long tasks")
    : { count: m.tasks, totalMs: round(m.taskMs) };
  // A request lasts until its response ends: a navigation's own duration runs on to the page's load.
  const entries = [...performance.getEntriesByType("navigation"), ...performance.getEntriesByType("resource")]
    .map((e) => ({ e, ms: (e.responseEnd || e.startTime + e.duration) - e.startTime }));
  out.slowestRequests = entries.length === 0 ? missing("the page reported no requests")
    : entries.sort((a, b) => b.ms - a.ms).slice(0, 10).map(({ e, ms }) => Object.assign(
        { url: e.name, ms: round(ms), type: e.entryType === "navigation" ? "navigation" : e.initiatorType },
        e.transferSize > 0 ? { bytes: e.transferSize } : {}));
  return out;
}"#;

/// The engine's one trace (`State::trace`).
pub(crate) struct Tracing {
    serial: u64,
    page_id: String,
    page: Page,
    seconds: f64,
    script: String,
    target: Option<Target>,
    phase: Phase,
}

impl std::fmt::Debug for Tracing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tracing")
            .field("page_id", &self.page_id)
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}

enum Phase {
    /// Being started: its slot is taken, nothing is recorded yet.
    Starting,
    Running,
    /// Its end is being read from Chrome.
    Finishing,
    /// Ended, by a stop or a limit (`ended` says which), and waiting for its stop.
    Done {
        ended: String,
        result: Result<(TraceData, Value), String>,
    },
}

static SERIAL: AtomicU64 = AtomicU64::new(1);

/// What `emulate` sets, as the page list names each.
const KEYS: [&str; 5] = ["cpu", "network", "location", "userAgent", "colorScheme"];

/// `name` given as JSON and not `null`; `null` clears just this one, as absent leaves it.
fn given<'a>(args: &'a Value, name: &str) -> Option<&'a Value> {
    args.get(name).filter(|v| !v.is_null())
}

fn number(v: &Value, name: &str, low: f64, high: f64, unit: &str) -> EngineResult<f64> {
    match v.as_f64() {
        Some(n) if (low..=high).contains(&n) => Ok(n),
        _ => Err(EngineError(format!("{name}: give a number from {low} to {high}{unit}."))),
    }
}

/// One emulation asked for: its key in the page's list, the commands that set it, and the value listed.
#[derive(Debug, PartialEq)]
struct Setting {
    key: &'static str,
    /// `None` clears it.
    value: Option<Value>,
}

/// `emulate`'s arguments, checked before anything is sent: each setting given, `clear` alone, or an
/// error naming the argument.
fn settings(args: &Value) -> EngineResult<Option<Vec<Setting>>> {
    let clear = args.get("clear").is_some_and(truthy);
    let asked: Vec<&str> = KEYS.into_iter().filter(|k| args.get(*k).is_some()).collect();
    if clear {
        if let Some(first) = asked.first() {
            return Err(EngineError(format!(
                "clear ends every emulation on the page, so give it alone; {first} was given too. To end only one, give it as null."
            )));
        }
        return Ok(None);
    }
    if asked.is_empty() {
        return Err(EngineError(
            "emulate: give at least one of cpu, network, location, userAgent or colorScheme, or clear true."
                .to_owned(),
        ));
    }
    let mut out = Vec::new();
    for key in asked {
        let value = match given(args, key) {
            None => None,
            Some(v) => Some(setting(key, v)?),
        };
        out.push(Setting { key, value });
    }
    Ok(Some(out))
}

/// One setting's value checked, as the page list will show it.
fn setting(key: &str, v: &Value) -> EngineResult<Value> {
    match key {
        "cpu" => number(v, "cpu", 1.0, 20.0, " (how many times slower; 1 is no slowdown)").map(|_| v.clone()),
        "network" => network(v),
        "location" => location(v),
        "userAgent" => match v.as_str() {
            Some(s) if !s.trim().is_empty() && s.len() <= 1000 => Ok(v.clone()),
            _ => Err(EngineError(
                "userAgent: give it as a non-empty string of at most 1000 characters.".to_owned(),
            )),
        },
        _ => match v.as_str() {
            Some("light" | "dark") => Ok(v.clone()),
            _ => Err(EngineError("colorScheme: give \"light\" or \"dark\".".to_owned())),
        },
    }
}

fn network(v: &Value) -> EngineResult<Value> {
    let Some(given) = v.as_object() else {
        return Err(EngineError(
            "network: give an object of offline, latencyMs, downloadKbps and uploadKbps.".to_owned(),
        ));
    };
    let mut out = Map::new();
    for (k, x) in given {
        let ok = match k.as_str() {
            "offline" => x.is_boolean(),
            "latencyMs" => number(x, "network.latencyMs", 0.0, 60_000.0, " ms").is_ok(),
            "downloadKbps" | "uploadKbps" => x.as_f64().is_some_and(|n| n > 0.0 && n <= 10_000_000.0),
            _ => {
                return Err(EngineError(format!(
                    "network: {k} is not a setting; give offline, latencyMs, downloadKbps or uploadKbps."
                )));
            }
        };
        if !ok {
            return Err(EngineError(format!(
                "network.{k}: give offline as true or false, latencyMs from 0 to 60000, and each Kbps above 0."
            )));
        }
        out.insert(k.clone(), x.clone());
    }
    if out.is_empty() {
        return Err(EngineError(
            "network: give at least one of offline, latencyMs, downloadKbps or uploadKbps.".to_owned(),
        ));
    }
    Ok(Value::Object(out))
}

fn location(v: &Value) -> EngineResult<Value> {
    let (Some(lat), Some(long)) = (v.get("latitude"), v.get("longitude")) else {
        return Err(EngineError(
            "location: give an object with latitude and longitude, and accuracy in metres if you want one."
                .to_owned(),
        ));
    };
    number(lat, "location.latitude", -90.0, 90.0, "")?;
    number(long, "location.longitude", -180.0, 180.0, "")?;
    let mut out = json!({ "latitude": lat, "longitude": long });
    if let Some(a) = v.get("accuracy").filter(|a| !a.is_null()) {
        number(a, "location.accuracy", 0.0, 1_000_000.0, " metres")?;
        out["accuracy"] = a.clone();
    }
    Ok(out)
}

/// Sets, or with `None` clears, one emulation on the page's own target.
async fn apply(p: &Page, key: &str, value: Option<&Value>) -> Result<(), CdpError> {
    match (key, value) {
        ("cpu", v) => {
            let rate = v.and_then(Value::as_f64).unwrap_or(1.0);
            p.send("Emulation.setCPUThrottlingRate", json!({ "rate": rate })).await?;
        }
        ("network", v) => {
            // Kilobits a second, as Chrome's own throttling presets, into bytes a second; -1 is no limit.
            let kbps = |k: &str| v.and_then(|v| v.get(k)).and_then(Value::as_f64).map_or(-1.0, |n| n * 125.0);
            let params = json!({
                "offline": v.and_then(|v| v.get("offline")).and_then(Value::as_bool).unwrap_or(false),
                "latency": v.and_then(|v| v.get("latencyMs")).and_then(Value::as_f64).unwrap_or(0.0),
                "downloadThroughput": kbps("downloadKbps"),
                "uploadThroughput": kbps("uploadKbps"),
            });
            // Chrome applies the conditions only to a page whose Network domain is on, so they start the
            // page's network recording too, as browser_network would.
            if v.is_some() {
                p.record_network().await?;
            }
            p.send("Network.emulateNetworkConditions", params).await?;
        }
        ("location", Some(v)) => {
            let accuracy = v.get("accuracy").and_then(Value::as_f64).unwrap_or(100.0);
            let params =
                json!({ "latitude": v["latitude"], "longitude": v["longitude"], "accuracy": accuracy });
            p.send("Emulation.setGeolocationOverride", params).await?;
        }
        ("location", None) => {
            p.send("Emulation.clearGeolocationOverride", json!({})).await?;
        }
        ("userAgent", v) => {
            let agent = v.and_then(Value::as_str).unwrap_or("");
            p.send("Emulation.setUserAgentOverride", json!({ "userAgent": agent })).await?;
        }
        (_, v) => {
            let features =
                v.map_or_else(Vec::new, |v| vec![json!({ "name": "prefers-color-scheme", "value": v })]);
            p.send("Emulation.setEmulatedMedia", json!({ "features": features })).await?;
        }
    }
    Ok(())
}

/// A number as JSON, whole numbers without a fraction.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::float_cmp)]
fn num(n: f64) -> Value {
    if n.fract() == 0.0 && (0.0..1e15).contains(&n) { json!(n as u64) } else { json!(n) }
}

/// Takes every secret header out of a saved trace, at any depth, as a `Headers` object or a list of
/// `{name, value}`, and Chrome's command line, which names the profile's folder.
fn scrub(v: &mut Value) {
    let secret = |name: &str| SECRET_HEADERS.iter().any(|s| name.trim().eq_ignore_ascii_case(s));
    match v {
        Value::Object(m) => {
            m.retain(|k, _| !secret(k) && k != "command_line");
            for x in m.values_mut() {
                scrub(x);
            }
        }
        Value::Array(a) => {
            a.retain(|x| {
                !x.get("name").and_then(Value::as_str).is_some_and(|n| secret(n) && x.get("value").is_some())
            });
            for x in a {
                scrub(x);
            }
        }
        _ => {}
    }
}

/// Reads the numbers, ends the trace and stops the measuring script: what a stop saves and answers.
async fn finish(page: &Page, script: &str) -> Result<(TraceData, Value), String> {
    let numbers = match page.evaluate_measure(READ_JS).await {
        Ok(v) if v.is_object() => v,
        _ => {
            let why =
                json!({ "missing": "the page's numbers could not be read: it was navigating or had closed" });
            json!({ "load": why, "largestPaint": why, "layoutShift": why, "longTasks": why, "slowestRequests": why })
        }
    };
    let data = page.trace_end(TRACE_END_WAIT, TRACE_MOST_BYTES).await;
    let _ = page.remove_measure_script(script).await;
    match data {
        Ok(data) => Ok((data, numbers)),
        Err(CdpError::Closed(_)) => {
            Err("the page closed or was re-attached while it ran, which ends a trace".to_owned())
        }
        Err(e) => Err(e.to_string()),
    }
}

impl Engine {
    /// `emulate(owner, {pageId, cpu, network, location, userAgent, colorScheme, clear})`.
    pub(crate) async fn emulate(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&page_id(args), owner, true)?;
        let asked = settings(args)?;
        self.lock_site(&r, None)?;
        self.sweep_sign_up(&r).await?;
        let asked = asked.unwrap_or_else(|| {
            let s = r.lock();
            KEYS.into_iter()
                .filter(|k| s.emulation.contains_key(*k))
                .map(|key| Setting { key, value: None })
                .collect()
        });
        let asked = Arc::new(asked);
        self.cdp(&r, None, |p, _| {
            let (asked, r) = (Arc::clone(&asked), Arc::clone(&r));
            async move {
                for s in asked.iter() {
                    apply(&p, s.key, s.value.as_ref()).await.map_err(Failed::from)?;
                    let mut st = r.lock();
                    match &s.value {
                        Some(v) => st.emulation.insert(s.key.to_owned(), v.clone()),
                        None => st.emulation.remove(s.key),
                    };
                }
                Ok::<_, Failed>(())
            }
        })
        .await?;
        let emulation = r.lock().emulation.clone();
        Ok(json!({ "pageId": r.id, "emulation": emulation }))
    }

    /// Ends every emulation on the page, as its close or release does; a failure leaves it to the end of
    /// the page's debugging, which ends it too.
    pub(crate) async fn end_emulation(&self, r: &Arc<Rec>) {
        let on = std::mem::take(&mut r.lock().emulation);
        if on.is_empty() {
            return;
        }
        let page = r.lock().page.clone();
        for key in on.keys() {
            let _ = apply(&page, key, None).await;
        }
    }

    /// `trace(owner, {pageId, action, reload, path, overwrite, seconds})`.
    pub(crate) async fn trace(&self, owner: &str, args: &Value) -> EngineResult {
        match args.get("action").and_then(Value::as_str) {
            Some("start") => self.trace_start(owner, args).await,
            Some("stop") => self.trace_stop(owner, args).await,
            _ => Err(EngineError("action: give \"start\" or \"stop\".".to_owned())),
        }
    }

    async fn trace_start(&self, owner: &str, args: &Value) -> EngineResult {
        let reload = args.get("reload").is_some_and(truthy);
        // A trace with a reload is a write: the reload is.
        let r = self.get(&page_id(args), owner, reload)?;
        let seconds = match given(args, "seconds") {
            None => TRACE_SECONDS,
            Some(v) => number(v, "seconds", 1.0, TRACE_MOST_SECONDS, " (the trace's time limit)")?,
        };
        let Some(target) = Target::of(args)? else {
            return Err(EngineError(
                "path: give the whole path of the file to save the trace in, from its drive or root; Chrome's Performance panel opens it.".to_owned(),
            ));
        };
        if reload {
            self.confirm_first(&r, args, "reload").await?;
            self.lock_site(&r, None)?;
        }
        self.sweep_sign_up(&r).await?;
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = target.path().display().to_string();
        {
            let mut st = self.st();
            if let Some(t) = &st.trace {
                return Err(EngineError(format!(
                    "One trace at a time: page {}'s trace is running. Stop it first with action stop.",
                    t.page_id
                )));
            }
            let page = r.lock().page.clone();
            let (page_id, script, target) = (r.id.clone(), String::new(), Some(target));
            st.trace =
                Some(Tracing { serial, page_id, page, seconds, script, target, phase: Phase::Starting });
        }
        let action = reload.then_some("trace");
        let started = self
            .cdp(&r, action, |p, _| async move {
                let script = p.add_measure_script(MEASURE_JS).await?;
                p.trace_start(TRACE_CATEGORIES, TRACE_BUFFER_KB).await?;
                if reload {
                    p.reload(super::ops::NAVIGATE_TIMEOUT).await?;
                }
                Ok::<_, CdpError>((p, script))
            })
            .await;
        // The slot is still this trace's unless its page closed meanwhile (`drop_trace`).
        let running = {
            let mut st = self.st();
            let slot = st.trace.as_mut().filter(|t| t.serial == serial);
            match (&started, slot) {
                (Ok((page, script)), Some(t)) => {
                    (t.page, t.script, t.phase) = (page.clone(), script.clone(), Phase::Running);
                    true
                }
                (_, Some(_)) => {
                    st.trace = None;
                    false
                }
                (_, None) => false,
            }
        };
        if !running {
            if let Ok((p, script)) = &started {
                let _ = tokio::time::timeout(Duration::from_secs(5), p.trace_discard(Duration::from_secs(4)))
                    .await;
                let _ = p.remove_measure_script(script).await;
            }
            return Err(started
                .err()
                .unwrap_or_else(|| EngineError("The page closed as its trace started.".to_owned())));
        }
        self.watch_trace(serial, seconds);
        Ok(json!({ "pageId": r.id, "tracing": true, "seconds": num(seconds), "path": path }))
    }

    /// Ends trace `serial` at its time limit, or once Chrome's buffer is full.
    fn watch_trace(&self, serial: u64, seconds: f64) {
        let engine = self.me.clone();
        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(seconds);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TRACE_TICK).await;
                let Some(engine) = engine.upgrade() else { return };
                let reason = {
                    let st = engine.st();
                    let Some(t) =
                        st.trace.as_ref().filter(|t| t.serial == serial && matches!(t.phase, Phase::Running))
                    else {
                        return;
                    };
                    if tokio::time::Instant::now() >= deadline {
                        Some(format!("time limit of {} s reached", num(t.seconds)))
                    } else if t.page.trace_fill().is_some_and(|f| f >= TRACE_FULL) {
                        Some(format!("size limit of {} MB reached", TRACE_BUFFER_KB / 1024))
                    } else {
                        None
                    }
                };
                if let Some(reason) = reason {
                    engine.end_trace(serial, reason).await;
                    return;
                }
            }
        });
    }

    /// Ends trace `serial` if it is running, keeping what it recorded for its stop.
    async fn end_trace(&self, serial: u64, ended: String) {
        let (page, script) = {
            let mut st = self.st();
            let Some(t) =
                st.trace.as_mut().filter(|t| t.serial == serial && matches!(t.phase, Phase::Running))
            else {
                return;
            };
            t.phase = Phase::Finishing;
            (t.page.clone(), t.script.clone())
        };
        let result = finish(&page, &script).await;
        if let Some(t) = self.st().trace.as_mut().filter(|t| t.serial == serial) {
            t.phase = Phase::Done { ended, result };
        }
    }

    async fn trace_stop(&self, owner: &str, args: &Value) -> EngineResult {
        let r = self.get(&page_id(args), owner, false)?;
        let serial = self.st().trace.as_ref().filter(|t| t.page_id == r.id).map(|t| t.serial);
        let Some(serial) = serial else {
            return Err(EngineError(
                "No trace is running on this page. Start one with action start, and a path to save it in."
                    .to_owned(),
            ));
        };
        self.end_trace(serial, "stopped".to_owned()).await;
        // A limit may have ended it just before: its end is being read.
        let give_up = tokio::time::Instant::now() + TRACE_END_WAIT + Duration::from_secs(5);
        let (ended, result, target) = loop {
            {
                let mut st = self.st();
                let done = st
                    .trace
                    .as_ref()
                    .filter(|t| t.serial == serial)
                    .map(|t| matches!(t.phase, Phase::Done { .. }));
                match done {
                    None => return Err(EngineError("The trace ended with its page, unsaved.".to_owned())),
                    Some(true) => {
                        if let Some(Tracing { phase: Phase::Done { ended, result }, target, .. }) =
                            st.trace.take()
                        {
                            break (ended, result, target);
                        }
                    }
                    Some(false) if tokio::time::Instant::now() >= give_up => {
                        st.trace = None;
                        return Err(EngineError(
                            "Chrome did not finish writing the trace in time; it was dropped.".to_owned(),
                        ));
                    }
                    Some(false) => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let (data, numbers) =
            result.map_err(|e| EngineError(format!("The trace could not be saved: {e}.")))?;
        let ended = if data.full && ended == "stopped" {
            format!("size limit of {} MB reached", TRACE_BUFFER_KB / 1024)
        } else {
            ended
        };
        let mut trace: Value = serde_json::from_slice(&data.bytes).map_err(|e| {
            EngineError(format!("The trace Chrome wrote is not JSON ({e}); nothing was saved."))
        })?;
        scrub(&mut trace);
        let bytes = serde_json::to_vec(&self.redacted(trace, false))
            .map_err(|e| EngineError(format!("saving the trace: {e}")))?;
        let Some(target) = target else {
            return Err(EngineError("The trace had nowhere to be saved.".to_owned()));
        };
        let mut out = target.write(bytes).await?;
        out.insert("pageId".into(), json!(r.id));
        out.insert("ended".into(), json!(ended));
        if data.data_lost {
            out.insert(
                "dataLost".into(),
                json!("Chrome reported that some events were lost; the trace has gaps."),
            );
        }
        out.insert("numbers".into(), numbers);
        out.insert("note".into(), json!(NUMBERS_NOTE));
        Ok(Value::Object(out))
    }

    /// The trace of page `id` taken from its slot, if it has one.
    fn take_trace(&self, id: &str) -> Option<Tracing> {
        let mut st = self.st();
        if st.trace.as_ref().is_some_and(|t| t.page_id == id) { st.trace.take() } else { None }
    }

    /// Ends page `id`'s trace before its page closes or is kept as a spare, unsaved: Chrome traces one
    /// client at a time, so a trace left running would refuse the next one.
    pub(crate) async fn stop_trace_of(&self, id: &str) {
        if let Some(t) = self.take_trace(id) {
            discard(t).await;
        }
    }

    /// The trace of page `id`, ended with it (`forget`): nothing is saved, and Chrome is asked to stop.
    pub(crate) fn drop_trace(&self, id: &str) {
        let Some(t) = self.take_trace(id) else { return };
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(discard(t));
        }
    }
}

/// Ends a trace nobody will save, best-effort and within a few seconds (SR-91).
async fn discard(t: Tracing) {
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        // A trace still starting or finishing is ended by whoever is doing that.
        if matches!(t.phase, Phase::Running) {
            let _ = t.page.trace_discard(Duration::from_secs(4)).await;
        }
        let _ = t.page.remove_measure_script(&t.script).await;
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emulation_is_checked_before_anything_is_sent() {
        let s = settings(&json!({ "cpu": 4, "colorScheme": "dark", "userAgent": null })).unwrap().unwrap();
        assert_eq!(
            s,
            vec![
                Setting { key: "cpu", value: Some(json!(4)) },
                Setting { key: "userAgent", value: None },
                Setting { key: "colorScheme", value: Some(json!("dark")) },
            ]
        );
        assert_eq!(settings(&json!({ "clear": true })).unwrap(), None);
        let net = settings(&json!({ "network": { "offline": true, "latencyMs": 40, "downloadKbps": 1600 } }));
        assert_eq!(net.unwrap().unwrap()[0].value.as_ref().unwrap()["downloadKbps"], json!(1600));
        let loc = settings(&json!({ "location": { "latitude": 51.5, "longitude": -0.12, "accuracy": 20 } }));
        assert_eq!(loc.unwrap().unwrap()[0].value.as_ref().unwrap()["accuracy"], json!(20));
        for (bad, starts) in [
            (json!({}), "emulate:"),
            (json!({ "cpu": 0.5 }), "cpu:"),
            (json!({ "cpu": 21 }), "cpu:"),
            (json!({ "cpu": "4" }), "cpu:"),
            (json!({ "clear": true, "cpu": 2 }), "clear"),
            (json!({ "network": {} }), "network:"),
            (json!({ "network": { "speed": 3 } }), "network:"),
            (json!({ "network": { "latencyMs": -1 } }), "network.latencyMs"),
            (json!({ "network": { "offline": "yes" } }), "network.offline"),
            (json!({ "network": { "uploadKbps": 0 } }), "network.uploadKbps"),
            (json!({ "location": { "latitude": 91, "longitude": 0 } }), "location.latitude"),
            (json!({ "location": { "latitude": 1 } }), "location:"),
            (json!({ "userAgent": "" }), "userAgent:"),
            (json!({ "colorScheme": "blue" }), "colorScheme:"),
        ] {
            let e = settings(&bad).unwrap_err().0;
            assert!(e.starts_with(starts), "{bad}: {e}");
        }
    }

    #[test]
    fn a_saved_trace_holds_no_secret_header_and_no_command_line() {
        let mut t = json!({
            "traceEvents": [
                { "name": "ResourceReceiveResponse", "args": { "data": { "headers": [
                    { "name": "Set-Cookie", "value": "a=1" },
                    { "name": "content-type", "value": "text/html" },
                    { "name": " authorization ", "value": "Bearer x" },
                ] } } },
                { "name": "ResourceSendRequest", "args": { "data": { "headers": { "Cookie": "a=1", "Accept": "*/*" } } } },
            ],
            "metadata": { "command_line": "chrome --user-data-dir=/home/x", "cpu-brand": "cpu" },
        });
        scrub(&mut t);
        let text = t.to_string();
        assert!(
            !text.contains("a=1") && !text.contains("Bearer") && !text.contains("user-data-dir"),
            "{text}"
        );
        assert!(text.contains("text/html") && text.contains("*/*") && text.contains("cpu-brand"), "{text}");
        // Only a header list loses its entries: an event called "cookie" with no value stays.
        let mut events = json!([{ "name": "Cookie" }]);
        scrub(&mut events);
        assert_eq!(events.as_array().unwrap().len(), 1);
    }

    #[test]
    fn whole_numbers_read_as_whole_numbers() {
        assert_eq!(num(1.0), json!(1));
        assert_eq!(num(2.5), json!(2.5));
        assert_eq!(num(-1.0), json!(-1.0));
    }

    #[test]
    fn the_trace_records_no_screenshot_and_no_network_log() {
        assert!(TRACE_CATEGORIES.iter().all(|c| !c.contains("screenshot") && !c.contains("netlog")));
        assert!(!TRACE_CATEGORIES.contains(&"*"));
    }
}
