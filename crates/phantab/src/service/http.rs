//! The service's HTTP surface: `/health`, `/view`, `/viewer`, `/rpc` and the `/bridge` upgrade; and the
//! remote view's listener, which answers only `/view` and `/viewer`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method as HttpMethod, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Map, Value, json};

use super::{Method, RemoteState, Service};
use crate::paths::{BRIDGE_UPGRADE, SERVICE_NAME, SERVICE_PROTOCOL};
use crate::util::{json_error, same_secret};

/// The live view of an isolated page during an owner handoff. Embedded, never read from disk
/// (THREAT-MODEL SR-7).
const VIEWER: &[u8] = include_bytes!("../../assets/viewer.html");
const VIEWER_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-ancestors 'none'";
const BODY_LIMIT: usize = 65_536;
/// How long a request the service reads may take to deliver its body, on either listener (R14). hyper
/// bounds only the headers; without this a caller could hold a connection and its task open by sending
/// its body a byte at a time. The body is read before the call reaches the serializer, so the slot is
/// never held. A real client sends a body this small at once, on loopback or through the remote route.
pub(super) const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a rejected request's unread body may take to arrive before the connection closes anyway.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

type Res = Response<Full<Bytes>>;

/// `authed` is this connection's flag: set once a request on it carries the token, which lets the
/// connection wait longer for its next request (`super::KEPT_IDLE`, THREAT-MODEL R14).
pub(super) async fn handle(svc: Arc<Service>, req: Request<Incoming>, authed: &AtomicBool) -> Res {
    if is_upgrade(req.headers()) {
        return upgrade(&svc, req).await;
    }
    let (parts, body) = req.into_parts();
    let mut body = Some(body);
    let mut res = route(&svc, &parts, &mut body, authed).await;
    if let Some(unread) = body {
        drain(unread).await;
    }
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
}

fn finish(status: StatusCode, value: &Value) -> Res {
    let mut res = Response::new(Full::new(Bytes::from(serde_json::to_vec(value).unwrap_or_default())));
    *res.status_mut() = status;
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    res
}

fn error(status: StatusCode, message: &str) -> Res {
    finish(status, &json!({ "error": message }))
}

fn text<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Node routes a request to its upgrade handler when it asks to upgrade at all, whatever its method
/// or path; the handler then decides.
fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
}

impl Service {
    fn host_ok(&self, headers: &HeaderMap) -> bool {
        text(headers, &header::HOST) == Some(self.host.as_str())
    }

    fn bearer_ok(&self, headers: &HeaderMap) -> bool {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.as_bytes().strip_prefix(b"Bearer "))
            .is_some_and(|t| same_secret(t, self.token.as_bytes()))
    }
}

// The bridge extension's native host (`host.rs`) joins over an HTTP upgrade on this server,
// authenticated like /rpc. Pages cannot send a custom Upgrade.
async fn upgrade(svc: &Arc<Service>, mut req: Request<Incoming>) -> Res {
    let h = req.headers();
    let origin = h.get(header::ORIGIN).is_some_and(|o| !o.is_empty());
    let allowed = text(h, &header::UPGRADE) == Some(BRIDGE_UPGRADE)
        && svc.host_ok(h)
        && !origin
        && req.uri() == "/bridge"
        && svc.bearer_ok(h)
        && !svc.stopping.load(Ordering::SeqCst);
    if !allowed {
        drain(req.into_body()).await;
        let mut res = Response::new(Full::new(Bytes::new()));
        *res.status_mut() = StatusCode::FORBIDDEN;
        res.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
        res.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return res;
    }
    let bridge = Arc::clone(&svc.bridge);
    tokio::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(&mut req).await {
            bridge.accept(TokioIo::new(upgraded));
        }
    });
    let mut res = Response::new(Full::new(Bytes::new()));
    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    res.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    res.headers_mut().insert(header::UPGRADE, HeaderValue::from_static(BRIDGE_UPGRADE));
    res
}

/// Reads what is left of a request the service answers without its body (a 403, a 404), up to the
/// [`BODY_LIMIT`] and [`DRAIN_TIMEOUT`], without keeping it. Closing a socket that still holds unread
/// bytes makes the OS send RST instead of FIN, and on Windows an RST can discard the reply the client
/// had already received, so the caller would see `ConnectionAborted` instead of the 403. Past the cap the
/// connection just closes: SR-6 buffers nothing beyond it.
async fn drain(mut body: Incoming) {
    let read = async {
        let mut seen = 0usize;
        while let Some(Ok(frame)) = body.frame().await {
            seen += frame.data_ref().map_or(0, Bytes::len);
            if seen > BODY_LIMIT {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, read).await;
}

async fn body(body: Incoming) -> Result<Value, String> {
    let Ok(collected) = tokio::time::timeout(BODY_TIMEOUT, Limited::new(body, BODY_LIMIT).collect()).await
    else {
        return Err("Request body timed out".to_owned());
    };
    let bytes = match collected {
        Ok(c) => c.to_bytes(),
        Err(e) if e.is::<http_body_util::LengthLimitError>() => return Err("Request too large".to_owned()),
        Err(e) => return Err(e.to_string()),
    };
    serde_json::from_slice(&bytes).map_err(|e| json_error(&bytes, &e))
}

/// `const {a, b} = value`: fields of an object, nothing of a primitive, a `TypeError` for null.
fn destructure(value: Value, first: &str) -> Result<Map<String, Value>, String> {
    match value {
        Value::Object(m) => Ok(m),
        Value::Null => {
            Err(format!("Cannot destructure property '{first}' of '(intermediate value)' as it is null."))
        }
        _ => Ok(Map::new()),
    }
}

/// Takes `body` only on the routes that read it; the caller drains what is left.
async fn route(svc: &Arc<Service>, req: &Parts, body: &mut Option<Incoming>, authed: &AtomicBool) -> Res {
    let h = &req.headers;
    if !svc.host_ok(h) {
        return error(StatusCode::FORBIDDEN, "Invalid host");
    }
    if let Some(origin) = h.get(header::ORIGIN).filter(|o| !o.is_empty())
        && origin.as_bytes() != format!("http://{}", svc.host).as_bytes()
    {
        return error(StatusCode::FORBIDDEN, "Invalid origin");
    }
    // Node's `req.url`: the request target as sent, query and all.
    let url = req.uri.to_string();
    let method = req.method.clone();
    if method == HttpMethod::GET && url == "/health" {
        return finish(
            StatusCode::OK,
            &json!({ "service": SERVICE_NAME, "version": env!("CARGO_PKG_VERSION"), "protocol": SERVICE_PROTOCOL }),
        );
    }
    // SR-13: unauthenticated by design; the answer proves this listener holds the token without
    // revealing it.
    if method == HttpMethod::GET && (url == "/hello" || url.starts_with("/hello?")) {
        return match crate::hello::nonce_of(&url).and_then(|n| crate::hello::proof(&svc.token, &n)) {
            // `keep` tells a client it may reuse the connection once its token is accepted.
            Some(proof) => finish(
                StatusCode::OK,
                &json!({ "proof": proof, crate::hello::KEEP: super::KEPT_IDLE.as_secs() }),
            ),
            None => error(StatusCode::BAD_REQUEST, "Invalid nonce"),
        };
    }
    if method == HttpMethod::GET && url == "/view" {
        return viewer_page();
    }
    if method != HttpMethod::POST {
        return error(StatusCode::NOT_FOUND, "Not found");
    }
    if url == "/viewer" {
        return viewer_post(svc, h, body, false).await;
    }
    if url != "/rpc" || !svc.bearer_ok(h) {
        return error(StatusCode::FORBIDDEN, "Unauthorized");
    }
    authed.store(true, Ordering::Relaxed);
    let Some(b) = body.take() else { return error(StatusCode::BAD_REQUEST, "Request body missing") };
    match rpc(svc, b).await {
        Ok(result) => finish(StatusCode::OK, &json!({ "result": result })),
        Err(e) => error(StatusCode::BAD_REQUEST, &e),
    }
}

fn viewer_page() -> Res {
    let mut res = Response::new(Full::new(Bytes::from_static(VIEWER)));
    res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(VIEWER_CSP));
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    res
}

async fn viewer_post(svc: &Arc<Service>, h: &HeaderMap, body: &mut Option<Incoming>, remote: bool) -> Res {
    let auth = h
        .get(header::AUTHORIZATION)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    let key = auth.strip_prefix("Bearer ").unwrap_or(&auth).to_owned();
    // SR-8: a key that views no hand-off on this listener gets the answer an ended one gets, before its
    // body is read, as /rpc checks its bearer first.
    if !svc.engine.viewer_known(&key, remote) {
        return error(StatusCode::BAD_REQUEST, "This handoff has ended.");
    }
    let Some(b) = body.take() else { return error(StatusCode::BAD_REQUEST, "Request body missing") };
    match viewer(svc, key, b, remote).await {
        Ok(result) => finish(StatusCode::OK, &json!({ "result": result })),
        Err(e) => error(viewer_status(&e), &e),
    }
}

/// The remote view's listener (THREAT-MODEL SR-70). It answers the live view and nothing
/// else: no `/rpc`, `/bridge`, `/health` or `/hello`, so reaching it gives no handle on the service, and
/// its `/viewer` takes only the tokens of links (`remote` viewers), never a local hand-off's.
pub(super) async fn handle_remote(svc: Arc<Service>, req: Request<Incoming>) -> Res {
    let (parts, body) = req.into_parts();
    let mut body = Some(body);
    let mut res = remote_route(&svc, &parts, &mut body).await;
    if let Some(unread) = body {
        drain(unread).await;
    }
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
}

async fn remote_route(svc: &Arc<Service>, req: &Parts, body: &mut Option<Incoming>) -> Res {
    let RemoteState::Listening(remote) = &svc.remote else {
        return error(StatusCode::NOT_FOUND, "Not found");
    };
    let h = &req.headers;
    // Exact Host, as on the local listener (DNS rebinding). Tailscale Serve passes the Host the owner's
    // device sent through unchanged (`mypc:8490`; the MagicDNS name `mypc.<tailnet>.ts.net:8490`
    // is a different Host and is refused), so publicBaseUrl must be the address he opens.
    if text(h, &header::HOST) != Some(remote.host.as_str()) {
        return error(StatusCode::FORBIDDEN, "Invalid host");
    }
    if let Some(origin) = h.get(header::ORIGIN).filter(|o| !o.is_empty())
        && origin.as_bytes() != remote.origin.as_bytes()
    {
        return error(StatusCode::FORBIDDEN, "Invalid origin");
    }
    if let Some((name, equals)) = &remote.identity {
        let who = h.get(name.as_str()).map_or(&b""[..], HeaderValue::as_bytes);
        if !same_secret(who, equals.as_bytes()) {
            return error(StatusCode::FORBIDDEN, "Not allowed");
        }
    }
    let url = req.uri.to_string();
    if req.method == HttpMethod::GET && url == "/view" {
        return viewer_page();
    }
    if req.method == HttpMethod::POST && url == "/viewer" {
        return viewer_post(svc, h, body, true).await;
    }
    error(StatusCode::NOT_FOUND, "Not found")
}

/// The engine's SR-8 refusals (too many viewer actions or pointer moves a second), which the engine
/// reports as text: its `spend` words every one "Too many {what}: …".
const VIEWER_RATE_LIMITED: &str = "Too many ";

/// SR-8: a viewer over its action limit gets 429; any other refusal, 400.
fn viewer_status(error: &str) -> StatusCode {
    if error.starts_with(VIEWER_RATE_LIMITED) {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::BAD_REQUEST
    }
}

async fn viewer(svc: &Arc<Service>, key: String, req: Incoming, remote: bool) -> Result<Value, String> {
    let mut m = destructure(body(req).await?, "action")?;
    let action = m.get("action").and_then(Value::as_str).map(str::to_owned);
    let args = m.remove("args").unwrap_or_else(|| json!({}));
    let (engine, serializer) = (Arc::clone(&svc.engine), svc.serializer.clone());
    let task =
        tokio::spawn(
            async move { serializer.run(engine.viewer(&key, action.as_deref(), args, remote)).await },
        );
    match task.await {
        Ok(r) => r.map_err(|e| e.0),
        Err(e) => Err(format!("Browser service call failed: {e}")),
    }
}

async fn rpc(svc: &Arc<Service>, req: Incoming) -> Result<Value, String> {
    let mut m = destructure(body(req).await?, "method")?;
    let client = m.get("client").and_then(Value::as_str).map(str::to_owned);
    let method = m.get("method").and_then(Value::as_str).and_then(Method::from_name);
    // `args = {}` replaces only an absent value; an explicit null stays null.
    let args = m.remove("args").unwrap_or_else(|| json!({}));
    // 1 to 150 in UTF-16 units, as JavaScript counts a string's length (SR-26).
    let (Some(client), Some(method)) = (client.filter(|c| crate::util::client_id_ok(c)), method) else {
        return Err("Invalid method or client".to_owned());
    };
    if svc.stopping.load(Ordering::SeqCst) && method != Method::Status {
        return Err("Browser service maintenance in progress. Retry after restart.".to_owned());
    }
    svc.touch(&client);
    svc.dispatch(method, args, client).await.map_err(|e| e.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_detection_follows_node() {
        let mut h = HeaderMap::new();
        h.insert(header::UPGRADE, HeaderValue::from_static("phantab-bridge"));
        assert!(!is_upgrade(&h));
        h.insert(header::CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        assert!(is_upgrade(&h));
    }

    /// SR-8, L1: the engine's rate-limit refusal is 429, everything else stays 400.
    #[test]
    fn a_viewer_over_its_limit_gets_429() {
        assert_eq!(
            viewer_status("Too many viewer actions: at most 20 a second."),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            viewer_status("Too many pointer moves: at most 30 a second."),
            StatusCode::TOO_MANY_REQUESTS
        );
        for other in ["Control has been returned to the agent.", "Unknown viewer action.", ""] {
            assert_eq!(viewer_status(other), StatusCode::BAD_REQUEST, "{other}");
        }
        // The engine still words its refusal this way (engine/ops.rs), or the 429 silently stops.
        let ops = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/ops.rs")).unwrap();
        assert!(ops.contains(&format!("\"{VIEWER_RATE_LIMITED}{{what}}: at most {{limit}} a second.\"")));
    }

    #[test]
    fn viewer_is_the_bundled_page() {
        let page = std::str::from_utf8(VIEWER).unwrap();
        assert!(page.contains("Return to agent"));
        assert!(page.contains("fetch('/viewer'"));
    }
}
