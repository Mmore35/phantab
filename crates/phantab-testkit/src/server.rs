//! `FixtureServer`: the fixture pages on two loopback origins, recording every request.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener as StdListener};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;

use crate::http::{self, ReadError, Response};
use crate::pages::PAGES;

/// What `/post/ok` (and every POST without its own answer) returns.
pub const LANDED: &str = "<title>Landed</title><p>Welcome back</p>";
/// The longest `/slow?ms=` delay honoured.
pub const SLOW_CAP_MS: u64 = 120_000;
/// How long a connection may take to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Which listener took a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// `http://127.0.0.1:<port>`.
    Primary,
    /// `http://localhost:<twin_port>`: another site to Chrome, for cross-site frames.
    Twin,
}

/// One request as the server saw it.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub listener: Listener,
    pub method: String,
    /// Percent-decoded path, such as `/post/ok`.
    pub path: String,
    /// The raw query without `?`; empty when there was none.
    pub query: String,
    /// Header names lower-cased.
    pub headers: Vec<(String, String)>,
    /// The body as text (lossy UTF-8).
    pub body: String,
    /// The full URL on the listener's origin, such as `http://127.0.0.1:5123/post/ok?x=1`.
    pub url: String,
}

impl RecordedRequest {
    /// A field of a form-encoded body, decoded (`URLSearchParams` rules).
    pub fn form(&self, name: &str) -> Option<String> {
        http::form_pairs(&self.body).into_iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Every field of a form-encoded body, decoded, in order.
    pub fn form_pairs(&self) -> Vec<(String, String)> {
        http::form_pairs(&self.body)
    }

    /// A query parameter, decoded.
    pub fn query_param(&self, name: &str) -> Option<String> {
        http::form_pairs(&self.query).into_iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// A header value; `name` is matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Whether `needle` appears in the path, query, body or a header value, as sent
    /// or decoded. Use it to prove a value was never sent.
    pub fn contains(&self, needle: &str) -> bool {
        let decoded = [http::percent_decode(&self.query, true), http::percent_decode(&self.body, true)];
        [&self.path, &self.query, &self.body, &self.url]
            .into_iter()
            .chain(decoded.iter())
            .chain(self.headers.iter().map(|(_, v)| v))
            .any(|text| text.contains(needle))
    }
}

struct GateState {
    open: watch::Sender<bool>,
    arrivals: watch::Sender<usize>,
}

struct State {
    primary_origin: String,
    twin_origin: String,
    requests: Mutex<Vec<RecordedRequest>>,
    /// Bumped on every recorded request, so waiters wake.
    recorded: watch::Sender<usize>,
    gates: Mutex<HashMap<String, GateState>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The fixture pages over HTTP/1.1 on two loopback origins.
///
/// - Primary: `http://127.0.0.1:<port>`.
/// - Twin: `http://localhost:<twin_port>`, a different site to Chrome, so a primary
///   page that frames a twin URL gets a cross-site (out-of-process) frame. The twin
///   listens on 127.0.0.1 and, when the machine has IPv6, on `[::1]` at the same port.
///
/// It runs on its own thread with its own runtime, so it works from plain `#[test]`s
/// and from `#[tokio::test]`s alike. Dropping it stops both listeners.
///
/// Routes (both origins serve the same set):
///
/// | Path | Answer |
/// |---|---|
/// | `/` | An index linking every fixture page. |
/// | `/<key>` or `/<key>.html` | The fixture page `fixtures/<key>.html`, templated. |
/// | `/slow?ms=N[&then=/path]` | Waits `N` ms (cap 120000), then serves `then` (or a small page). |
/// | `/redirect?to=URL[&status=301\|302\|303\|307\|308]` | A redirect, 302 by default. |
/// | `/status?code=N` | An empty page with that status. |
/// | `/hook/<name>` | `ok`, after any [`Gate`] for `<name>` is released. |
/// | `POST /post/<name>` | The page that form's site would show next (see below). |
/// | `GET /post/<name>` | [`LANDED`]. |
/// | `/captcha-frame/...[?fixture=KEY]` | A stub page (or the fixture page `KEY`), so a frame URL can look like a captcha provider's. |
/// | anything else | 404 `none`. |
///
/// POST answers: `/post/ok` gives [`LANDED`]; `/post/userstep`
/// gives `sign-in/passstep`; `/post/tocode` gives `sign-in/code`; `/post/tokey` (phantab's own)
/// gives `sign-in/securitykey`; `/post/wrong` gives
/// `sign-in/wrong`; `/post/echo` gives `You typed <pass>` (escaped);
/// `/post/thendetach` gives [`LANDED`] plus a script that POSTs
/// `/hook/detach-me` after 500 ms; any other POST gives [`LANDED`].
///
/// Templating: `{{PRIMARY}}` and `{{TWIN}}` are the two origins, `{{SELF}}` the origin
/// that served the page, and `{{query:NAME}}` the HTML-escaped query parameter.
///
/// Every response is `Connection: close` with `Cache-Control: no-store`.
#[derive(Debug)]
pub struct FixtureServer {
    port: u16,
    twin_port: u16,
    twin_ipv6: bool,
    state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("primary_origin", &self.primary_origin)
            .field("twin_origin", &self.twin_origin)
            .finish_non_exhaustive()
    }
}

impl FixtureServer {
    /// Binds both listeners on free ports and starts serving.
    pub fn start() -> io::Result<Self> {
        let primary = StdListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (twin, twin6) = bind_twin()?;
        let port = primary.local_addr()?.port();
        let twin_port = twin.local_addr()?.port();
        let twin_ipv6 = twin6.is_some();
        let state = Arc::new(State {
            primary_origin: format!("http://127.0.0.1:{port}"),
            twin_origin: format!("http://localhost:{twin_port}"),
            requests: Mutex::new(Vec::new()),
            recorded: watch::Sender::new(0),
            gates: Mutex::new(HashMap::new()),
        });
        let mut listeners = vec![(primary, Listener::Primary), (twin, Listener::Twin)];
        if let Some(twin6) = twin6 {
            listeners.push((twin6, Listener::Twin));
        }
        for (listener, _) in &listeners {
            listener.set_nonblocking(true)?;
        }
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (stop, stopped) = oneshot::channel();
        let serving = Arc::clone(&state);
        let thread = std::thread::Builder::new()
            .name(format!("fixture-server-{port}"))
            .spawn(move || runtime.block_on(serve(listeners, serving, stopped)))?;
        Ok(Self { port, twin_port, twin_ipv6, state, shutdown: Some(stop), thread: Some(thread) })
    }

    /// `http://127.0.0.1:<port>` + `path`. `path` should start with `/`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.state.primary_origin)
    }

    /// `http://localhost:<twin_port>` + `path`: the same pages on another site.
    pub fn twin_url(&self, path: &str) -> String {
        format!("{}{path}", self.state.twin_origin)
    }

    pub fn origin(&self) -> &str {
        &self.state.primary_origin
    }

    pub fn twin_origin(&self) -> &str {
        &self.state.twin_origin
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn twin_port(&self) -> u16 {
        self.twin_port
    }

    /// Whether the twin also listens on `[::1]` (false when the machine has no IPv6).
    pub fn twin_has_ipv6(&self) -> bool {
        self.twin_ipv6
    }

    /// Every request so far, oldest first, from both origins.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        lock(&self.state.requests).clone()
    }

    /// What the tests call posts: every POST, and every request to `/post/...`
    /// (a GET form's submission lands there too).
    pub fn posts(&self) -> Vec<RecordedRequest> {
        lock(&self.state.requests)
            .iter()
            .filter(|r| r.method == "POST" || r.path.starts_with("/post/"))
            .cloned()
            .collect()
    }

    /// Forgets recorded requests (gates stay).
    pub fn clear_requests(&self) {
        lock(&self.state.requests).clear();
    }

    /// Whether any recorded request contains `needle` (see [`RecordedRequest::contains`]).
    pub fn saw(&self, needle: &str) -> bool {
        lock(&self.state.requests).iter().any(|r| r.contains(needle))
    }

    /// Waits until a recorded request (already seen or new) matches `pred`, or `timeout` passes.
    pub async fn wait_for_request(
        &self,
        pred: impl Fn(&RecordedRequest) -> bool,
        timeout: Duration,
    ) -> Option<RecordedRequest> {
        let mut changes = self.state.recorded.subscribe();
        tokio::time::timeout(timeout, async {
            loop {
                changes.borrow_and_update();
                if let Some(found) = lock(&self.state.requests).iter().find(|r| pred(r)) {
                    return Some(found.clone());
                }
                if changes.changed().await.is_err() {
                    return None;
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// Holds requests to `/hook/<name>` until the returned gate is released or dropped.
    /// The page that made the request waits for its answer meanwhile, which lets a test
    /// act (detach the tab, kill the bridge) at that exact point.
    pub fn gate(&self, name: &str) -> Gate {
        lock(&self.state.gates).insert(
            name.to_owned(),
            GateState { open: watch::Sender::new(false), arrivals: watch::Sender::new(0) },
        );
        Gate { name: name.to_owned(), state: Arc::clone(&self.state) }
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A held `/hook/<name>` route; see [`FixtureServer::gate`]. Released on drop.
#[derive(Debug)]
pub struct Gate {
    name: String,
    state: Arc<State>,
}

impl Gate {
    /// How many requests have reached the gate so far.
    pub fn arrivals(&self) -> usize {
        lock(&self.state.gates).get(&self.name).map_or(0, |g| *g.arrivals.borrow())
    }

    /// Waits until a request reaches the gate. False if `timeout` passed first.
    pub async fn arrived(&self, timeout: Duration) -> bool {
        let Some(mut arrivals) = lock(&self.state.gates).get(&self.name).map(|g| g.arrivals.subscribe())
        else {
            return false;
        };
        tokio::time::timeout(timeout, arrivals.wait_for(|n| *n > 0)).await.is_ok_and(|r| r.is_ok())
    }

    /// Lets held and later requests through.
    pub fn release(&self) {
        if let Some(g) = lock(&self.state.gates).get(&self.name) {
            g.open.send_replace(true);
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        if let Some(g) = lock(&self.state.gates).remove(&self.name) {
            g.open.send_replace(true);
        }
    }
}

/// Binds the twin on 127.0.0.1 and, if the machine has IPv6, on `[::1]` at the same
/// port: Chrome may try either address for `localhost`, and a stranger on the other
/// one would answer in our place.
fn bind_twin() -> io::Result<(StdListener, Option<StdListener>)> {
    for _ in 0..20 {
        let v4 = StdListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = v4.local_addr()?.port();
        match StdListener::bind((Ipv6Addr::LOCALHOST, port)) {
            Ok(v6) => return Ok((v4, Some(v6))),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {}
            // No IPv6 loopback here, so Chrome cannot reach [::1] either.
            Err(_) => return Ok((v4, None)),
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, "no port free on both 127.0.0.1 and [::1] after 20 tries"))
}

async fn serve(listeners: Vec<(StdListener, Listener)>, state: Arc<State>, stopped: oneshot::Receiver<()>) {
    let mut accepts = JoinSet::new();
    for (listener, which) in listeners {
        let Ok(listener) = TcpListener::from_std(listener) else { continue };
        let state = Arc::clone(&state);
        accepts.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            connections.spawn(handle(stream, which, Arc::clone(&state)));
                        }
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
    }
    let _ = stopped.await;
    // Dropping the sets aborts every accept loop and every open connection.
    accepts.abort_all();
}

async fn handle(mut stream: TcpStream, which: Listener, state: Arc<State>) {
    let request = match tokio::time::timeout(READ_TIMEOUT, http::read_request(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(ReadError::Reject(status, why))) => {
            let _ = Response::text(status, why).write(&mut stream, false).await;
            return;
        }
        Ok(Err(ReadError::Closed | ReadError::Io)) | Err(_) => return,
    };
    let self_origin = match which {
        Listener::Primary => state.primary_origin.clone(),
        Listener::Twin => state.twin_origin.clone(),
    };
    let path = http::percent_decode(&request.path, false);
    let recorded = RecordedRequest {
        listener: which,
        method: request.method.clone(),
        url: format!(
            "{self_origin}{}{}{}",
            request.path,
            if request.query.is_empty() { "" } else { "?" },
            request.query
        ),
        path: path.clone(),
        query: request.query.clone(),
        headers: request.headers.clone(),
        body: String::from_utf8_lossy(&request.body).into_owned(),
    };
    let body = recorded.body.clone();
    lock(&state.requests).push(recorded);
    state.recorded.send_modify(|n| *n += 1);

    let ctx = Ctx { state: &state, self_origin: &self_origin, query: &request.query };
    let response = route(&ctx, &request.method, &path, &body).await;
    let _ = response.write(&mut stream, request.method == "HEAD").await;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
}

struct Ctx<'a> {
    state: &'a State,
    self_origin: &'a str,
    query: &'a str,
}

impl Ctx<'_> {
    fn param(&self, name: &str) -> Option<String> {
        http::form_pairs(self.query).into_iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    fn render(&self, source: &str) -> String {
        render(source, &self.state.primary_origin, &self.state.twin_origin, self.self_origin, self.query)
    }

    fn page(&self, key: &str) -> Option<String> {
        PAGES.iter().find(|(k, _)| *k == key).map(|(_, source)| self.render(source))
    }
}

async fn route(ctx: &Ctx<'_>, method: &str, path: &str, body: &str) -> Response {
    if let Some(name) = path.strip_prefix("/hook/") {
        hook(ctx.state, name).await;
        return Response::text(200, "ok");
    }
    if let Some(rest) = path.strip_prefix("/post/") {
        if let Some(step) = rest.strip_prefix("parity-") {
            // The parity benchmark's account site: the server checks the sign-in (`parity.rs`).
            let step = if method == "POST" { step } else { "" };
            return Response::html(200, crate::parity::answer(step, body));
        }
        if method != "POST" {
            return Response::html(200, LANDED);
        }
        let page = |key| ctx.page(key).unwrap_or_else(|| LANDED.to_owned());
        return Response::html(
            200,
            match rest {
                "userstep" => page("sign-in/passstep"),
                "tocode" => page("sign-in/code"),
                "tokey" => page("sign-in/securitykey"),
                "wrong" => page("sign-in/wrong"),
                "echo" => {
                    let typed = http::form_pairs(body)
                        .into_iter()
                        .find(|(n, _)| n == "pass")
                        .map(|(_, v)| v)
                        .unwrap_or_default();
                    format!("<title>Oops</title><p>You typed {}</p>", http::html_escape(&typed))
                }
                "thendetach" => format!(
                    "{LANDED}<script>setTimeout(()=>fetch('/hook/detach-me',{{method:'POST'}}),500);</script>"
                ),
                _ => LANDED.to_owned(),
            },
        );
    }
    match path {
        "/" => return Response::html(200, index()),
        "/slow" => {
            let ms = ctx.param("ms").and_then(|v| v.parse::<u64>().ok()).unwrap_or(1000).min(SLOW_CAP_MS);
            tokio::time::sleep(Duration::from_millis(ms)).await;
            let then = ctx.param("then").and_then(|to| ctx.page(page_key(&to)));
            return Response::html(
                200,
                then.unwrap_or_else(|| format!("<title>Slow</title><p>Waited {ms} ms</p>")),
            );
        }
        "/redirect" => {
            let to = ctx.param("to").unwrap_or_else(|| "/engine/basic".to_owned());
            let status = match ctx.param("status").as_deref() {
                Some("301") => 301,
                Some("303") => 303,
                Some("307") => 307,
                Some("308") => 308,
                _ => 302,
            };
            return Response::redirect(status, &to);
        }
        "/status" => {
            let code =
                ctx.param("code").and_then(|v| v.parse::<u16>().ok()).filter(|c| (200..600).contains(c));
            let code = code.unwrap_or(500);
            return Response::html(code, format!("<title>Status {code}</title>"));
        }
        _ => {}
    }
    if path.starts_with("/captcha-frame/") {
        // `?fixture=<key>` puts a fixture page at the provider-looking URL: a stand-in check with something
        // to press (`verify/box`).
        if let Some(page) = ctx.param("fixture").and_then(|key| ctx.page(&key)) {
            return Response::html(200, page);
        }
        return Response::html(200, "<title>Captcha stub</title><p>stub</p>");
    }
    match ctx.page(page_key(path)) {
        Some(page) => Response::html(200, page),
        None => Response::html(404, "none"),
    }
}

/// `/sign-in/one.html?x` or `/sign-in/one` to `sign-in/one`.
fn page_key(path: &str) -> &str {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let path = path.trim_start_matches('/');
    path.strip_suffix(".html").unwrap_or(path)
}

async fn hook(state: &State, name: &str) {
    let open = {
        let gates = lock(&state.gates);
        let Some(gate) = gates.get(name) else { return };
        gate.arrivals.send_modify(|n| *n += 1);
        gate.open.subscribe()
    };
    let mut open = open;
    // A dropped gate (sender gone) counts as released.
    let _ = open.wait_for(|released| *released).await;
}

fn index() -> String {
    let mut out = String::from("<title>Fixtures</title><ul>");
    for (key, _) in PAGES {
        let _ = write!(out, "<li><a href=\"/{key}\">{key}</a></li>");
    }
    out.push_str("</ul>");
    out
}

/// Replaces `{{PRIMARY}}`, `{{TWIN}}`, `{{SELF}}` and `{{query:NAME}}`. Anything else
/// between braces is left as written.
pub(crate) fn render(source: &str, primary: &str, twin: &str, self_origin: &str, query: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let token = &after[..end];
        match token {
            "PRIMARY" => out.push_str(primary),
            "TWIN" => out.push_str(twin),
            "SELF" => out.push_str(self_origin),
            _ => {
                if let Some(name) = token.strip_prefix("query:") {
                    let value = http::form_pairs(query).into_iter().find(|(n, _)| n == name).map(|(_, v)| v);
                    out.push_str(&http::html_escape(&value.unwrap_or_default()));
                } else {
                    out.push_str("{{");
                    out.push_str(token);
                    out.push_str("}}");
                }
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_tokens() {
        let out = render(
            "{{PRIMARY}}|{{TWIN}}|{{SELF}}|{{query:n}}|{{query:none}}|{{other}}|{{",
            "http://127.0.0.1:1",
            "http://localhost:2",
            "http://localhost:2",
            "n=%3Cb%3E&x=1",
        );
        assert_eq!(out, "http://127.0.0.1:1|http://localhost:2|http://localhost:2|&lt;b&gt;||{{other}}|{{");
    }

    #[test]
    fn keys() {
        assert_eq!(page_key("/sign-in/one.html"), "sign-in/one");
        assert_eq!(page_key("/sign-in/one?x=1"), "sign-in/one");
        assert_eq!(page_key("changes"), "changes");
    }
}
