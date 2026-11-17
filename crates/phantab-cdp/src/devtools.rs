//! The developer tools' recordings (THREAT-MODEL SR-90): one page's console errors, warnings and
//! exceptions, and its requests, kept from the call that starts them (`Page::record_console`,
//! `Page::record_network`) until the page closes, and cleared at each new main document.
//!
//! Only what is listed here is kept, never an event as it came: a request's headers pass
//! [`clean_headers`] before they are stored, and no request body is read (`Network.enable` runs with
//! `maxPostDataSize: 0`). Only the header maps are read, never `headersText`, `requestHeaders` or
//! `requestHeadersText`, and no `...ExtraInfo` event reaches this module (`crate::DEVTOOLS_EVENTS`).
//!
//! A trace (SR-91) is followed here only by its fill and its end; the trace itself is read from the
//! stream Chrome gives (`Page::trace_end`).

use std::collections::VecDeque;
use std::fmt::Write as _;

use serde_json::{Map, Value, json};

/// The console messages kept per page; the oldest go first, counted.
pub const CONSOLE_KEPT: usize = 200;
/// Each console message's text is cut to this many characters.
pub const CONSOLE_TEXT: usize = 2000;
/// The requests kept per page; the oldest go first, counted.
pub const REQUESTS_KEPT: usize = 500;

/// The headers removed from every request, response and redirect, in any case: they carry the owner's
/// sessions (SR-90).
const SECRET_HEADERS: [&str; 4] = ["cookie", "set-cookie", "authorization", "proxy-authorization"];

/// A CDP `Headers` object without [`SECRET_HEADERS`], whatever their case or surrounding spaces. Values
/// stay as Chrome gave them; a value that is not a string is kept as its JSON text.
#[must_use]
pub fn clean_headers(headers: Option<&Value>) -> Map<String, Value> {
    let Some(Value::Object(headers)) = headers else { return Map::new() };
    headers
        .iter()
        .filter(|(name, _)| !SECRET_HEADERS.iter().any(|s| name.trim().eq_ignore_ascii_case(s)))
        .map(|(name, v)| {
            let v = match v {
                Value::String(_) => v.clone(),
                other => Value::String(other.to_string()),
            };
            (name.clone(), v)
        })
        .collect()
}

/// One console error, warning or exception.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsoleMessage {
    /// `error`, `warning` or `exception`.
    pub level: &'static str,
    /// Cut to [`CONSOLE_TEXT`] characters.
    pub text: String,
    /// The script or resource it names, when Chrome gave one.
    pub url: String,
    /// One-based, when Chrome gave one.
    pub line: Option<u64>,
}

impl ConsoleMessage {
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut m = json!({ "level": self.level, "text": self.text });
        if !self.url.is_empty() {
            m["url"] = json!(self.url);
        }
        if let Some(line) = self.line {
            m["line"] = json!(line);
        }
        m
    }
}

/// What [`crate::Page::console`] answers: the kept messages, oldest first, and how many were dropped
/// for room since the last navigation.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsoleRead {
    pub messages: Vec<ConsoleMessage>,
    pub dropped: u64,
}

/// One redirect a request took: where it was, and the response that sent it on.
#[derive(Debug, Clone, PartialEq)]
pub struct Redirect {
    pub url: String,
    pub status: Option<u64>,
    pub headers: Map<String, Value>,
}

/// One request the page made.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Chrome's request id, which `Page::response_body` takes.
    pub id: String,
    pub method: String,
    /// The whole URL, query included.
    pub url: String,
    /// Chrome's resource type: `Document`, `Script`, `Fetch`, ...
    pub kind: String,
    pub status: Option<u64>,
    pub mime: String,
    /// Bytes received, once loaded.
    pub size: Option<u64>,
    /// Milliseconds from start to its end, once ended.
    pub time_ms: Option<u64>,
    /// Chrome's error text, for a request that failed (`net::ERR_...`), with `canceled` or the blocked
    /// reason when Chrome gave one.
    pub failed: Option<String>,
    /// Whether it sent a body; the body itself is never read.
    pub has_body: bool,
    pub request_headers: Map<String, Value>,
    pub response_headers: Map<String, Value>,
    pub redirects: Vec<Redirect>,
    /// The document it belongs to (Chrome's loader id).
    pub loader: String,
    started: f64,
}

impl Request {
    /// A failure, or an HTTP error status.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.failed.is_some() || self.status.is_some_and(|s| s >= 400)
    }

    /// The list line: id, method, URL, status, type, size and time.
    #[must_use]
    pub fn summary(&self) -> Value {
        let mut m = json!({ "id": self.id, "method": self.method, "url": self.url, "type": self.kind });
        if let Some(s) = self.status {
            m["status"] = json!(s);
        }
        if let Some(f) = &self.failed {
            m["failed"] = json!(f);
        }
        if let Some(s) = self.size {
            m["size"] = json!(s);
        }
        if let Some(t) = self.time_ms {
            m["ms"] = json!(t);
        }
        m
    }

    /// Everything kept about it: the summary, the MIME type, both header maps (cleaned) and its
    /// redirects.
    #[must_use]
    pub fn detail(&self) -> Value {
        let mut m = self.summary();
        if !self.mime.is_empty() {
            m["mimeType"] = json!(self.mime);
        }
        m["requestHeaders"] = Value::Object(self.request_headers.clone());
        m["responseHeaders"] = Value::Object(self.response_headers.clone());
        if self.has_body {
            m["sentBody"] = json!(true);
        }
        if !self.redirects.is_empty() {
            m["redirects"] = Value::Array(
                self.redirects
                    .iter()
                    .map(|r| json!({ "url": r.url, "status": r.status, "headers": r.headers }))
                    .collect(),
            );
        }
        m
    }
}

/// What [`crate::Page::network`] answers: the kept requests in the order they started, and how many
/// were dropped for room since the last navigation.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkRead {
    pub requests: Vec<Request>,
    pub dropped: u64,
}

/// What `Page::evaluate_script` answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Evaluated {
    /// The script's result by value, and its JavaScript type (`string`, `object`, `undefined`, ...).
    Value { value: Value, kind: String },
    /// It did not finish in time. `stopped`: it was still running, so `Runtime.terminateExecution`
    /// ended it; otherwise it was waiting (a promise that never settled), and is left waiting.
    TimedOut { stopped: bool },
}

#[derive(Debug)]
pub(crate) struct ConsoleLog {
    /// When recording started (ms since the epoch): `Log.enable` replays the entries Chrome already
    /// had, and those are from before.
    since_ms: f64,
    messages: VecDeque<ConsoleMessage>,
    dropped: u64,
}

#[derive(Debug, Default)]
pub(crate) struct NetworkLog {
    requests: VecDeque<Request>,
    dropped: u64,
}

/// A page's recordings; `None` while not recording.
#[derive(Debug, Default)]
pub(crate) struct Recording {
    pub(crate) console: Option<ConsoleLog>,
    pub(crate) network: Option<NetworkLog>,
    /// A running trace (THREAT-MODEL SR-91), from `Page::trace_start` until `Page::trace_end` reads it.
    pub(crate) trace: Option<TraceLog>,
}

/// A trace's progress as Chrome reports it: how full its buffer is, and once ended, the stream that
/// holds it. Nothing of the trace itself passes through here; it is read from the stream.
#[derive(Debug, Default)]
pub(crate) struct TraceLog {
    /// The buffer's last reported fill, 0 to 1 (`Tracing.bufferUsage`).
    pub(crate) full: f64,
    /// `Tracing.tracingComplete`: whether Chrome lost data, and the stream handle it gave.
    pub(crate) complete: Option<(bool, Option<String>)>,
}

impl TraceLog {
    fn on_event(&mut self, method: &str, params: &Value) {
        match method {
            "Tracing.bufferUsage" => {
                if let Some(full) = params.get("percentFull").and_then(Value::as_f64) {
                    self.full = full;
                }
            }
            "Tracing.tracingComplete" => {
                let lost = params.get("dataLossOccurred").and_then(Value::as_bool) == Some(true);
                let stream = params.get("stream").and_then(Value::as_str).map(str::to_owned);
                self.complete = Some((lost, stream));
            }
            _ => {}
        }
    }
}

/// A finished trace, as [`crate::Page::trace_end`] read it from Chrome's stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceData {
    /// The trace JSON, as Chrome wrote it.
    pub bytes: Vec<u8>,
    /// Chrome said it lost events.
    pub data_lost: bool,
    /// The buffer was full ([`TRACE_FULL`]): Chrome stopped recording there.
    pub full: bool,
}

/// The buffer fill at which a trace counts as full: Chrome keeps no more events from there.
pub const TRACE_FULL: f64 = 0.99;

fn cut(text: &str) -> String {
    match text.char_indices().nth(CONSOLE_TEXT) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn line(v: &Value) -> Option<u64> {
    v.get("lineNumber").and_then(Value::as_u64).map(|l| l + 1)
}

/// One console argument as text: a string as it is, anything else as Chrome describes it.
fn arg_text(a: &Value) -> String {
    if a.get("type").and_then(Value::as_str) == Some("string") {
        return s(a, "value").to_owned();
    }
    if let Some(u) = a.get("unserializableValue").and_then(Value::as_str) {
        return u.to_owned();
    }
    if let Some(d) = a.get("description").and_then(Value::as_str) {
        return d.to_owned();
    }
    match a.get("value") {
        Some(v) => v.to_string(),
        None => s(a, "type").to_owned(),
    }
}

/// The first stack frame's URL and line.
fn top_frame(stack: Option<&Value>) -> (String, Option<u64>) {
    let top = stack.and_then(|s| s.pointer("/callFrames/0"));
    top.map_or((String::new(), None), |f| (s(f, "url").to_owned(), line(f)))
}

impl ConsoleLog {
    pub(crate) fn new(since_ms: f64) -> Self {
        Self { since_ms, messages: VecDeque::new(), dropped: 0 }
    }

    fn push(&mut self, m: ConsoleMessage) {
        self.messages.push_back(m);
        while self.messages.len() > CONSOLE_KEPT {
            self.messages.pop_front();
            self.dropped += 1;
        }
    }

    fn on_event(&mut self, method: &str, params: &Value) {
        let message = match method {
            "Runtime.consoleAPICalled" => {
                let level = match s(params, "type") {
                    "error" | "assert" => "error",
                    "warning" => "warning",
                    _ => return,
                };
                let args = params.get("args").and_then(Value::as_array);
                let mut text =
                    args.map(|a| a.iter().map(arg_text).collect::<Vec<_>>().join(" ")).unwrap_or_default();
                if s(params, "type") == "assert" {
                    text = format!("Assertion failed: {text}");
                }
                let (url, line) = top_frame(params.get("stackTrace"));
                ConsoleMessage { level, text: cut(&text), url, line }
            }
            "Runtime.exceptionThrown" => {
                let Some(d) = params.get("exceptionDetails") else { return };
                let said = s(d, "text");
                let described = d.pointer("/exception/description").and_then(Value::as_str).unwrap_or("");
                let text = match (said, described) {
                    ("", d) => d.to_owned(),
                    (t, "") => t.to_owned(),
                    (t, d) => format!("{t} {d}"),
                };
                let (mut url, mut at) = (s(d, "url").to_owned(), line(d));
                if url.is_empty() {
                    (url, at) = top_frame(d.get("stackTrace"));
                }
                ConsoleMessage { level: "exception", text: cut(&text), url, line: at }
            }
            "Log.entryAdded" => {
                let Some(e) = params.get("entry") else { return };
                let level = match s(e, "level") {
                    "error" => "error",
                    "warning" => "warning",
                    _ => return,
                };
                if e.get("timestamp").and_then(Value::as_f64).is_some_and(|t| t < self.since_ms) {
                    return;
                }
                ConsoleMessage { level, text: cut(s(e, "text")), url: s(e, "url").to_owned(), line: line(e) }
            }
            _ => return,
        };
        self.push(message);
    }

    pub(crate) fn read(&self) -> ConsoleRead {
        ConsoleRead { messages: self.messages.iter().cloned().collect(), dropped: self.dropped }
    }
}

impl NetworkLog {
    fn find(&mut self, id: &str) -> Option<&mut Request> {
        self.requests.iter_mut().rev().find(|r| r.id == id)
    }

    fn ended(r: &mut Request, params: &Value) {
        if let Some(t) = params.get("timestamp").and_then(Value::as_f64) {
            let ms = ((t - r.started) * 1000.0).max(0.0).round();
            // Whole milliseconds of a page's request: far below u64's range.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let ms = ms as u64;
            r.time_ms = Some(ms);
        }
    }

    fn on_event(&mut self, method: &str, params: &Value) {
        let id = s(params, "requestId");
        match method {
            "Network.requestWillBeSent" => {
                let req = params.get("request").unwrap_or(&Value::Null);
                if let (Some(hop), Some(r)) = (params.get("redirectResponse"), self.find(id)) {
                    let from = std::mem::replace(&mut r.url, s(req, "url").to_owned());
                    r.redirects.push(Redirect {
                        url: from,
                        status: hop.get("status").and_then(Value::as_u64),
                        headers: clean_headers(hop.get("headers")),
                    });
                    s(req, "method").clone_into(&mut r.method);
                    r.request_headers = clean_headers(req.get("headers"));
                    return;
                }
                self.requests.push_back(Request {
                    id: id.to_owned(),
                    method: s(req, "method").to_owned(),
                    url: s(req, "url").to_owned(),
                    kind: s(params, "type").to_owned(),
                    status: None,
                    mime: String::new(),
                    size: None,
                    time_ms: None,
                    failed: None,
                    has_body: req.get("hasPostData").and_then(Value::as_bool).unwrap_or(false),
                    request_headers: clean_headers(req.get("headers")),
                    response_headers: Map::new(),
                    redirects: Vec::new(),
                    loader: s(params, "loaderId").to_owned(),
                    started: params.get("timestamp").and_then(Value::as_f64).unwrap_or(0.0),
                });
                while self.requests.len() > REQUESTS_KEPT {
                    self.requests.pop_front();
                    self.dropped += 1;
                }
            }
            "Network.responseReceived" => {
                let Some(r) = self.find(id) else { return };
                let res = params.get("response").unwrap_or(&Value::Null);
                r.status = res.get("status").and_then(Value::as_u64);
                res.get("mimeType").and_then(Value::as_str).unwrap_or("").clone_into(&mut r.mime);
                r.response_headers = clean_headers(res.get("headers"));
                if let Some(kind) = params.get("type").and_then(Value::as_str) {
                    kind.clone_into(&mut r.kind);
                }
            }
            "Network.loadingFinished" => {
                let Some(r) = self.find(id) else { return };
                r.size = params.get("encodedDataLength").and_then(Value::as_f64).map(|n| {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let n = n.max(0.0) as u64;
                    n
                });
                Self::ended(r, params);
            }
            "Network.loadingFailed" => {
                let Some(r) = self.find(id) else { return };
                let mut why = s(params, "errorText").to_owned();
                if params.get("canceled").and_then(Value::as_bool) == Some(true) {
                    why.push_str(" (canceled)");
                }
                if let Some(b) = params.get("blockedReason").and_then(Value::as_str) {
                    let _ = write!(why, " (blocked: {b})");
                }
                r.failed = Some(why);
                Self::ended(r, params);
            }
            _ => {}
        }
    }

    pub(crate) fn read(&self) -> NetworkRead {
        NetworkRead { requests: self.requests.iter().cloned().collect(), dropped: self.dropped }
    }
}

impl Recording {
    /// One developer tools event of the page's own target.
    /// Each log reads only its own events by their full names and passes over the rest.
    pub(crate) fn on_event(&mut self, method: &str, params: &Value) {
        if let Some(n) = &mut self.network {
            n.on_event(method, params);
        }
        if let Some(c) = &mut self.console {
            c.on_event(method, params);
        }
        if let Some(t) = &mut self.trace {
            t.on_event(method, params);
        }
    }

    /// The main frame has a new document (`loader`): what the old one logged goes, and so do its
    /// requests, but not the new document's own (its request came before the commit).
    pub(crate) fn on_main_document(&mut self, loader: &str) {
        if let Some(c) = &mut self.console {
            c.messages.clear();
            c.dropped = 0;
        }
        if let Some(n) = &mut self.network {
            n.requests.retain(|r| !loader.is_empty() && r.loader == loader);
            n.dropped = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_headers_go_in_any_case() {
        let h = json!({
            "Cookie": "a=1", "set-cookie": "b=2", "AUTHORIZATION": "Bearer x", "Proxy-Authorization": "Basic y",
            " cookie ": "c=3", "Accept": "*/*", "X-Count": 3
        });
        let clean = clean_headers(Some(&h));
        assert_eq!(Value::Object(clean), json!({ "Accept": "*/*", "X-Count": "3" }));
        assert!(clean_headers(None).is_empty());
        assert!(clean_headers(Some(&json!("Cookie: a=1"))).is_empty());
    }

    fn recording() -> Recording {
        Recording {
            console: Some(ConsoleLog::new(1000.0)),
            network: Some(NetworkLog::default()),
            trace: None,
        }
    }

    #[test]
    fn console_keeps_errors_warnings_and_exceptions_cut_and_bounded() {
        let mut r = recording();
        let call = |kind: &str, text: &str| {
            json!({ "type": kind, "args": [{ "type": "string", "value": text }, { "type": "number", "value": 7, "description": "7" }],
                    "stackTrace": { "callFrames": [{ "url": "http://h/a.js", "lineNumber": 4 }] } })
        };
        r.on_event("Runtime.consoleAPICalled", &call("log", "plain"));
        r.on_event("Runtime.consoleAPICalled", &call("error", "bad"));
        r.on_event("Runtime.consoleAPICalled", &call("warning", "careful"));
        r.on_event(
            "Runtime.exceptionThrown",
            &json!({ "exceptionDetails": { "text": "Uncaught", "url": "http://h/b.js", "lineNumber": 0,
                     "exception": { "description": "Error: boom\n    at x" } } }),
        );
        // Replayed by Log.enable from before recording started, then one after.
        r.on_event(
            "Log.entryAdded",
            &json!({ "entry": { "level": "error", "text": "old", "timestamp": 999.0 } }),
        );
        r.on_event(
            "Log.entryAdded",
            &json!({ "entry": { "level": "error", "text": "new", "timestamp": 1001.0 } }),
        );
        r.on_event(
            "Log.entryAdded",
            &json!({ "entry": { "level": "info", "text": "fine", "timestamp": 1002.0 } }),
        );
        let read = r.console.as_ref().unwrap().read();
        let said: Vec<(&str, &str)> = read.messages.iter().map(|m| (m.level, m.text.as_str())).collect();
        assert_eq!(
            said,
            [
                ("error", "bad 7"),
                ("warning", "careful 7"),
                ("exception", "Uncaught Error: boom\n    at x"),
                ("error", "new")
            ]
        );
        assert_eq!((read.messages[0].url.as_str(), read.messages[0].line), ("http://h/a.js", Some(5)));
        assert_eq!(read.messages[2].line, Some(1));

        let long = "x".repeat(CONSOLE_TEXT + 50);
        for _ in 0..CONSOLE_KEPT + 3 {
            r.on_event("Runtime.consoleAPICalled", &call("error", &long));
        }
        let read = r.console.as_ref().unwrap().read();
        assert_eq!((read.messages.len(), read.dropped), (CONSOLE_KEPT, 7));
        assert_eq!(read.messages[0].text.chars().count(), CONSOLE_TEXT + 1);
        r.on_main_document("L2");
        let read = r.console.as_ref().unwrap().read();
        assert_eq!((read.messages.len(), read.dropped), (0, 0));
    }

    #[test]
    fn network_keeps_cleaned_requests_redirects_and_failures_until_the_next_document() {
        let mut r = recording();
        let sent = |id: &str, url: &str, loader: &str| {
            json!({ "requestId": id, "loaderId": loader, "type": "Fetch", "timestamp": 10.0,
                    "request": { "url": url, "method": "GET", "headers": { "Authorization": "Bearer t", "Accept": "x" } } })
        };
        r.on_event("Network.requestWillBeSent", &sent("1", "http://h/a", "L1"));
        let mut hop = sent("1", "http://h/b", "L1");
        hop["redirectResponse"] =
            json!({ "status": 302, "headers": { "Set-Cookie": "s=1", "Location": "/b" } });
        r.on_event("Network.requestWillBeSent", &hop);
        r.on_event(
            "Network.responseReceived",
            &json!({ "requestId": "1", "type": "Fetch", "response": { "status": 200, "mimeType": "text/plain",
                     "headers": { "set-cookie": "s=2", "Content-Type": "text/plain" },
                     "requestHeaders": { "Cookie": "s=1" }, "headersText": "Set-Cookie: s=2" } }),
        );
        r.on_event(
            "Network.loadingFinished",
            &json!({ "requestId": "1", "timestamp": 10.25, "encodedDataLength": 42.0 }),
        );
        r.on_event("Network.requestWillBeSent", &sent("2", "http://127.0.0.1:1/", "L1"));
        r.on_event(
            "Network.loadingFailed",
            &json!({ "requestId": "2", "timestamp": 10.5, "errorText": "net::ERR_UNSAFE_PORT", "canceled": false }),
        );
        let read = r.network.as_ref().unwrap().read();
        let first = &read.requests[0];
        assert_eq!(first.url, "http://h/b");
        assert_eq!((first.status, first.size, first.time_ms), (Some(200), Some(42), Some(250)));
        let all = first.detail().to_string();
        assert!(!all.contains("s=1") && !all.contains("s=2") && !all.contains("Bearer"), "{all}");
        assert_eq!(first.redirects[0].url, "http://h/a");
        assert_eq!(first.redirects[0].headers.get("Location"), Some(&json!("/b")));
        assert!(!first.is_failed() && read.requests[1].is_failed());
        assert_eq!(read.requests[1].failed.as_deref(), Some("net::ERR_UNSAFE_PORT"));

        for i in 0..REQUESTS_KEPT {
            r.on_event("Network.requestWillBeSent", &sent(&format!("n{i}"), "http://h/n", "L1"));
        }
        assert_eq!(r.network.as_ref().unwrap().read().dropped, 2);
        r.on_event("Network.requestWillBeSent", &sent("doc", "http://h/next", "L2"));
        r.on_main_document("L2");
        let read = r.network.as_ref().unwrap().read();
        assert_eq!(read.dropped, 0);
        assert_eq!(read.requests.iter().map(|q| q.id.as_str()).collect::<Vec<_>>(), ["doc"]);
    }

    /// SR-90's header removal: whole events as Chrome sends them, with the secret in every header
    /// field Chrome has (its maps in any case, the raw `headersText` and `requestHeadersText`, the
    /// `requestHeaders` a response carries, an `...ExtraInfo` event's), and in no answer.
    #[test]
    fn cookie_and_authorization_headers_never_leave_the_service() {
        let secret = "SENTINEL-c00k1e";
        let mut r = recording();
        let headers = json!({
            "Cookie": format!("sid={secret}"), "AUTHORIZATION": format!("Bearer {secret}"),
            "proxy-authorization": format!("Basic {secret}"), " cookie ": secret, "Accept": "*/*"
        });
        r.on_event(
            "Network.requestWillBeSent",
            &json!({ "requestId": "1", "loaderId": "L1", "type": "Fetch", "timestamp": 1.0,
                     "request": { "url": "http://h/a", "method": "POST", "headers": headers, "hasPostData": true,
                                  "postData": secret, "postDataEntries": [{ "bytes": secret }] } }),
        );
        let mut hop = json!({ "requestId": "1", "loaderId": "L1", "type": "Fetch", "timestamp": 1.1,
                              "request": { "url": "http://h/b", "method": "GET", "headers": headers } });
        hop["redirectResponse"] = json!({ "status": 302, "headers": { "SET-COOKIE": secret, "Location": "/b" },
                                          "headersText": secret, "requestHeaders": headers, "requestHeadersText": secret });
        r.on_event("Network.requestWillBeSent", &hop);
        r.on_event(
            "Network.responseReceived",
            &json!({ "requestId": "1", "type": "Fetch", "response": { "status": 200, "mimeType": "text/plain",
                     "headers": { "Set-Cookie": format!("sid={secret}; HttpOnly"), "Content-Type": "text/plain" },
                     "headersText": secret, "requestHeaders": headers, "requestHeadersText": secret } }),
        );
        for extra in ["Network.requestWillBeSentExtraInfo", "Network.responseReceivedExtraInfo"] {
            r.on_event(
                extra,
                &json!({ "requestId": "1", "headers": headers, "headersText": secret,
                                       "associatedCookies": [{ "cookie": { "value": secret } }] }),
            );
        }
        r.on_event(
            "Network.loadingFinished",
            &json!({ "requestId": "1", "timestamp": 1.2, "encodedDataLength": 3.0 }),
        );
        let read = r.network.as_ref().unwrap().read();
        assert_eq!(read.requests.len(), 1);
        let q = &read.requests[0];
        let said = format!("{} {} {:?}", q.detail(), q.summary(), q);
        assert!(!said.contains(secret), "{said}");
        assert_eq!(Value::Object(q.request_headers.clone()), json!({ "Accept": "*/*" }));
        assert_eq!(Value::Object(q.response_headers.clone()), json!({ "Content-Type": "text/plain" }));
        assert!(q.has_body && q.detail()["sentBody"] == json!(true));
    }

    #[test]
    fn nothing_is_kept_while_not_recording() {
        let mut r = Recording::default();
        r.on_event("Runtime.consoleAPICalled", &json!({ "type": "error", "args": [] }));
        r.on_event("Network.requestWillBeSent", &json!({ "requestId": "1", "request": {} }));
        assert!(r.console.is_none() && r.network.is_none());
    }
}
