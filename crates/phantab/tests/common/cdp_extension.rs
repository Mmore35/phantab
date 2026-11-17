//! A fake bridge extension backed by a real headless Chrome over CDP (lane 3, docs/TESTING.md): every
//! bridge op the extension's `background.ts` offers, done with the browser's own protocol instead of
//! `chrome.debugger`, `chrome.tabs` and `chrome.windows`.
//!
//! - `createWindow`/`createTab` open a new target (`Target.createTarget`); a tab id is a counter mapped
//!   to its target id.
//! - `attach` is `Target.attachToTarget{flatten}`; `send` goes to that session, or to a child session
//!   the page attached beneath it (`sessionId`, as `chrome.debugger` passes it). Events come back as
//!   `{event:'cdp',tabId,sessionId?,method,params}`; a detach Chrome made posts `{event:'detach'}` after
//!   200 ms with `tabOpen`, as the extension does; a closed tab posts `{event:'removed'}`.
//! - `keepRendering` is a no-op (headless always renders); `markShown`, `windowState` and
//!   `clearForeignFrames` keep the extension's agent-window bookkeeping and refusals.
//! - A dialog in a hidden agent window is answered here, as the extension's `answerHiddenDialog` does:
//!   leave and alert accepted, confirm and prompt dismissed, unless `answerNextDialog` set the next answer.
//!
//! Only the Chrome this test launched, with a temporary profile. Window strategy `None`
//! (`PHANTAB_TEST_WINDOWS=none`) goes with it: these windows are headless and never on screen.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::future::Future;
use std::net::TcpStream as StdTcpStream;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use phantab_cdp::{Browser, CdpError, LaunchOptions, SessionId, Transport as _, TransportEvent};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Default)]
struct State {
    next_tab: i64,
    /// tabId → targetId.
    tabs: HashMap<i64, String>,
    /// tabId → its debugger session and event forwarder.
    attached: HashMap<i64, (SessionId, JoinHandle<()>)>,
    /// Agent windows this extension created: windowId → shown.
    agent_windows: HashMap<i64, bool>,
    /// Every `createTab` URL, in order (the viewer's URL carries its token).
    created_tabs: Vec<String>,
    /// The tab of every `createWindow`, in order.
    window_tabs: Vec<i64>,
    /// Every op the service sent, in order.
    ops: Vec<String>,
    /// Every op and CDP command, timed: `send <tabId> <method>`, `markShown <shown>`, else the op's name.
    timeline: Vec<(Instant, String)>,
    /// The agent's answer for a tab's next dialog (`answerNextDialog`): accept, and a prompt's text.
    next_answers: HashMap<i64, (bool, Option<String>)>,
}

/// The fake extension; dropping it hangs up.
pub struct CdpExtension {
    pub browser: Arc<Browser>,
    state: Arc<Mutex<State>>,
    out: mpsc::UnboundedSender<Value>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for CdpExtension {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for (_, (_, t)) in self.state.lock().unwrap().attached.drain() {
            t.abort();
        }
    }
}

/// A headless Chrome on a temporary profile (removed by `Browser::close`).
pub async fn launch_chrome(executable: &Path) -> Arc<Browser> {
    let options = LaunchOptions {
        executable: executable.to_path_buf(),
        headless: true,
        user_data_dir: None,
        args: vec!["--no-first-run".to_owned()],
    };
    Arc::new(Browser::launch(options).await.expect("headless Chrome starts"))
}

fn lock(s: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    s.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What `chrome.debugger.sendCommand` reports: a protocol error as its JSON, anything else as text.
fn relay_error(e: &CdpError) -> String {
    match e {
        CdpError::Protocol { code, message, data, .. } => {
            let mut v = json!({ "code": code, "message": message });
            if let Some(d) = data {
                v["data"] = json!(d);
            }
            v.to_string()
        }
        other => other.to_string(),
    }
}

impl CdpExtension {
    /// Says hello on an upgraded bridge socket, then serves the bridge ops from `browser`.
    pub fn connect(mut stream: StdTcpStream, instance: &str, browser: Arc<Browser>) -> Self {
        stream.set_read_timeout(None).unwrap();
        crate::common::hello(&mut stream, instance);
        stream.set_nonblocking(true).unwrap();
        let stream = tokio::net::TcpStream::from_std(stream).unwrap();
        let (mut read, mut write) = stream.into_split();
        let (out, mut rx) = mpsc::unbounded_channel::<Value>();
        let writer = tokio::spawn(async move {
            while let Some(v) = rx.recv().await {
                if write.write_all(&crate::common::frame(&v)).await.is_err() {
                    break;
                }
            }
        });
        let state = Arc::new(Mutex::new(State { next_tab: 100, ..State::default() }));
        let ext = Ext { browser: Arc::clone(&browser), state: Arc::clone(&state), out: out.clone() };
        let reader = tokio::spawn(async move {
            let mut replies: HashMap<i64, mpsc::UnboundedSender<(Value, Answer)>> = HashMap::new();
            loop {
                let mut len = [0u8; 4];
                if read.read_exact(&mut len).await.is_err() {
                    break;
                }
                let mut body = vec![0u8; usize::try_from(u32::from_le_bytes(len)).unwrap()];
                if read.read_exact(&mut body).await.is_err() {
                    break;
                }
                let Ok(m) = serde_json::from_slice::<Value>(&body) else { continue };
                if m["op"] == "send" {
                    // chrome.debugger answers one tab's commands in the order they were sent, and the page
                    // relies on that (its input state settles in answer order). So a send is written to
                    // Chrome here, in arrival order, and its tab's answers go back in that order.
                    let args = m.get("args").cloned().unwrap_or_else(|| json!({}));
                    {
                        let mut s = lock(&ext.state);
                        s.ops.push("send".to_owned());
                        let entry =
                            format!("send {} {}", args["tabId"], args["method"].as_str().unwrap_or_default());
                        s.timeline.push((Instant::now(), entry));
                    }
                    let mut fut = ext.start_send(&args);
                    let first = futures_util::poll!(fut.as_mut());
                    let tab = args["tabId"].as_i64().unwrap_or(-1);
                    let queue = replies.entry(tab).or_insert_with(|| {
                        let (tx, mut rx) = mpsc::unbounded_channel::<(Value, Answer)>();
                        let out = ext.out.clone();
                        tokio::spawn(async move {
                            while let Some((id, answer)) = rx.recv().await {
                                let r = match answer {
                                    Answer::Ready(r) => r,
                                    Answer::Pending(f) => f.await,
                                };
                                let reply = match r {
                                    Ok(result) => json!({ "id": id, "result": result }),
                                    Err(error) => json!({ "id": id, "error": error }),
                                };
                                let _ = out.send(reply);
                            }
                        });
                        tx
                    });
                    let answer = match first {
                        std::task::Poll::Ready(r) => Answer::Ready(r),
                        std::task::Poll::Pending => Answer::Pending(fut),
                    };
                    let _ = queue.send((m["id"].clone(), answer));
                    continue;
                }
                let ext = ext.clone();
                // The extension answers ops concurrently, each as its promise settles.
                tokio::spawn(async move {
                    let op = m["op"].as_str().unwrap_or_default().to_owned();
                    let args = m.get("args").cloned().unwrap_or_else(|| json!({}));
                    {
                        let mut s = lock(&ext.state);
                        s.ops.push(op.clone());
                        let entry = if op == "markShown" {
                            format!("markShown {}", args["shown"])
                        } else {
                            op.clone()
                        };
                        s.timeline.push((Instant::now(), entry));
                    }
                    let reply = match ext.run(&op, &args).await {
                        Ok(result) => json!({ "id": m["id"], "result": result }),
                        Err(error) => json!({ "id": m["id"], "error": error }),
                    };
                    let _ = ext.out.send(reply);
                });
            }
        });
        Self { browser, state, out, tasks: vec![writer, reader] }
    }

    /// Hangs up, as a stopped extension or a dropped native host does.
    pub fn hang_up(&mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
        }
    }

    pub fn created_tabs(&self) -> Vec<String> {
        lock(&self.state).created_tabs.clone()
    }

    /// The tab of the last agent window the service created.
    pub fn last_window_tab(&self) -> i64 {
        *lock(&self.state).window_tabs.last().expect("an agent window")
    }

    pub fn ops(&self) -> Vec<String> {
        lock(&self.state).ops.clone()
    }

    /// Every op and CDP command so far, timed (see `State::timeline`).
    pub fn timeline(&self) -> Vec<(Instant, String)> {
        lock(&self.state).timeline.clone()
    }

    /// The viewer token of the last live view the service opened (the `#` part of its URL).
    pub fn viewer_token(&self) -> Option<String> {
        self.created_tabs().iter().rev().find_map(|u| u.split_once("/view#").map(|(_, t)| t.to_owned()))
    }

    /// The owner opening a tab of their own. It returns before the tab has loaded `url`: an attach made
    /// at once records an empty URL, and a sign-in on it then answers `Invalid URL`. Wait for the tab's
    /// `location.href` (through [`Self::eval`]) before attaching.
    pub async fn open_owner_tab(&self, url: &str) -> i64 {
        let ext =
            Ext { browser: Arc::clone(&self.browser), state: Arc::clone(&self.state), out: self.out.clone() };
        ext.create(url, None).await.unwrap()["tabId"].as_i64().unwrap()
    }

    /// The owner closing a tab by hand.
    pub async fn close_tab_by_hand(&self, tab: i64) {
        let ext =
            Ext { browser: Arc::clone(&self.browser), state: Arc::clone(&self.state), out: self.out.clone() };
        ext.close_tab(tab).await.unwrap();
    }

    /// Whether Chrome still has the tab.
    pub async fn tab_open(&self, tab: i64) -> bool {
        let ext =
            Ext { browser: Arc::clone(&self.browser), state: Arc::clone(&self.state), out: self.out.clone() };
        ext.target_info(tab).await.is_ok()
    }

    /// Runs a function in a tab's page through a separate session, as a test reads the page's own state.
    pub async fn eval(&self, tab: i64, expression: &str) -> Value {
        let ext =
            Ext { browser: Arc::clone(&self.browser), state: Arc::clone(&self.state), out: self.out.clone() };
        let target = ext.target(tab).unwrap();
        let conn = self.browser.connection();
        let s = conn
            .send(None, "Target.attachToTarget", json!({ "targetId": target, "flatten": true }))
            .await
            .unwrap();
        let sid = SessionId::new(s["sessionId"].as_str().unwrap());
        let _events = conn.take_events(&sid);
        let r = conn
            .send(
                Some(&sid),
                "Runtime.evaluate",
                json!({ "expression": expression, "returnByValue": true, "awaitPromise": true }),
            )
            .await
            .unwrap();
        let _ = conn.send(None, "Target.detachFromTarget", json!({ "sessionId": sid.as_str() })).await;
        r["result"]["value"].clone()
    }
}

type SendFuture = Pin<Box<dyn Future<Output = Result<Value, String>> + Send>>;

enum Answer {
    Ready(Result<Value, String>),
    Pending(SendFuture),
}

#[derive(Clone)]
struct Ext {
    browser: Arc<Browser>,
    state: Arc<Mutex<State>>,
    out: mpsc::UnboundedSender<Value>,
}

impl Ext {
    async fn cdp(&self, session: Option<&SessionId>, method: &str, params: Value) -> Result<Value, String> {
        self.browser.connection().send(session, method, params).await.map_err(|e| relay_error(&e))
    }

    fn target(&self, tab: i64) -> Result<String, String> {
        lock(&self.state).tabs.get(&tab).cloned().ok_or_else(|| format!("No tab with id: {tab}."))
    }

    fn tab_of(&self, target: &str) -> i64 {
        let mut s = lock(&self.state);
        if let Some((t, _)) = s.tabs.iter().find(|(_, id)| *id == target) {
            return *t;
        }
        s.next_tab += 1;
        let t = s.next_tab;
        s.tabs.insert(t, target.to_owned());
        t
    }

    async fn window_of(&self, target: &str) -> i64 {
        self.cdp(None, "Browser.getWindowForTarget", json!({ "targetId": target }))
            .await
            .ok()
            .and_then(|w| w["windowId"].as_i64())
            .unwrap_or(-1)
    }

    async fn target_info(&self, tab: i64) -> Result<Value, String> {
        let target = self.target(tab)?;
        let all = self.cdp(None, "Target.getTargets", json!({})).await?;
        all["targetInfos"]
            .as_array()
            .and_then(|a| a.iter().find(|t| t["targetId"] == json!(target)).cloned())
            .ok_or_else(|| format!("No tab with id: {tab}."))
    }

    async fn tab_info(&self, info: &Value) -> Value {
        let target = info["targetId"].as_str().unwrap_or_default();
        let tab = self.tab_of(target);
        json!({ "tabId": tab, "windowId": self.window_of(target).await, "title": info["title"], "url": info["url"] })
    }

    async fn create(&self, url: &str, new_window: Option<&Value>) -> Result<Value, String> {
        let mut params = json!({ "url": url });
        if let Some(bounds) = new_window {
            params["newWindow"] = json!(true);
            for k in ["left", "top", "width", "height"] {
                if let Some(v) = bounds.get(k).filter(|v| !v.is_null()) {
                    params[k] = v.clone();
                }
            }
        }
        let created = self.cdp(None, "Target.createTarget", params).await?;
        let target =
            created["targetId"].as_str().ok_or("createTarget answered without a targetId")?.to_owned();
        let tab = self.tab_of(&target);
        let window = self.window_of(&target).await;
        Ok(json!({ "windowId": window, "tabId": tab }))
    }

    async fn close_tab(&self, tab: i64) -> Result<Value, String> {
        let target = self.target(tab)?;
        self.cdp(None, "Target.closeTarget", json!({ "targetId": target })).await?;
        lock(&self.state).tabs.remove(&tab);
        let _ = self.out.send(json!({ "event": "removed", "tabId": tab }));
        Ok(json!({}))
    }

    async fn attach(&self, tab: i64) -> Result<Value, String> {
        let target = self.target(tab)?;
        if lock(&self.state).attached.contains_key(&tab) {
            return Err("Another debugger is already attached to the tab with id: ".to_owned()
                + &tab.to_string()
                + ".");
        }
        let a =
            self.cdp(None, "Target.attachToTarget", json!({ "targetId": target, "flatten": true })).await?;
        let root = SessionId::new(a["sessionId"].as_str().ok_or("attach answered without a sessionId")?);
        let mut events = self.browser.connection().take_events(&root);
        let me = self.clone();
        let root2 = root.clone();
        let forward = tokio::spawn(async move {
            while let Some(e) = events.recv().await {
                match e {
                    TransportEvent::Event { session: None, method, params } => {
                        if method == "Target.detachedFromTarget"
                            && params["sessionId"] == json!(root2.as_str())
                        {
                            me.detached_by_chrome(tab).await;
                            return;
                        }
                    }
                    TransportEvent::Event { session: Some(s), method, params } => {
                        if method == "Page.javascriptDialogOpening" {
                            let (me, s, kind) =
                                (me.clone(), s.clone(), params["type"].as_str().unwrap_or("").to_owned());
                            tokio::spawn(async move { me.answer_hidden_dialog(tab, &s, &kind).await });
                        }
                        let mut ev =
                            json!({ "event": "cdp", "tabId": tab, "method": method, "params": params });
                        if s != root2 {
                            ev["sessionId"] = json!(s.as_str());
                        }
                        let _ = me.out.send(ev);
                    }
                    TransportEvent::Closed(_) => return,
                }
            }
        });
        lock(&self.state).attached.insert(tab, (root, forward));
        Ok(json!({}))
    }

    /// A `send`: checked and handed to Chrome before this returns (the first poll writes it).
    fn start_send(&self, a: &Value) -> SendFuture {
        let tab = a["tabId"].as_i64().unwrap_or(-1);
        let method = a["method"].as_str().unwrap_or_default().to_owned();
        if !phantab::cdp_methods::allowed(&method) {
            return Box::pin(std::future::ready(Err(format!("CDP method not allowed: {method}"))));
        }
        let session = {
            let s = lock(&self.state);
            let Some((root, _)) = s.attached.get(&tab) else {
                let e = format!("Debugger is not attached to the tab with id: {tab}.");
                return Box::pin(std::future::ready(Err(e)));
            };
            a["sessionId"].as_str().map_or_else(|| root.clone(), SessionId::new)
        };
        let params = a.get("params").cloned().filter(|p| !p.is_null()).unwrap_or_else(|| json!({}));
        let browser = Arc::clone(&self.browser);
        Box::pin(async move {
            browser.connection().send(Some(&session), &method, params).await.map_err(|e| relay_error(&e))
        })
    }

    /// Whether the tab is in an agent window not shown to the owner.
    async fn in_hidden_window(&self, tab: i64) -> bool {
        let Ok(target) = self.target(tab) else { return false };
        let window = self.window_of(&target).await;
        lock(&self.state).agent_windows.get(&window) == Some(&false)
    }

    async fn answer_hidden_dialog(&self, tab: i64, session: &SessionId, kind: &str) {
        if !self.in_hidden_window(tab).await {
            return;
        }
        let next = lock(&self.state).next_answers.remove(&tab);
        let (accept, text) = next.unwrap_or((kind == "beforeunload" || kind == "alert", None));
        let mut params = json!({ "accept": accept });
        if let Some(t) = text {
            params["promptText"] = json!(t);
        }
        let _ = self.cdp(Some(session), "Page.handleJavaScriptDialog", params).await;
    }

    async fn detached_by_chrome(&self, tab: i64) {
        lock(&self.state).attached.remove(&tab);
        lock(&self.state).next_answers.remove(&tab);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let open = self.target_info(tab).await.is_ok();
        let _ = self.out.send(json!({ "event": "detach", "tabId": tab, "reason": "target_closed", "tabOpen": open, "foreign": null }));
    }

    async fn mark_shown(&self, a: &Value) -> Result<Value, String> {
        let window = a["windowId"].as_i64().unwrap_or(-1);
        let shown = a["shown"].as_bool().unwrap_or(false);
        if shown {
            // Shown, the window's dialogs are the owner's: the agent's answers are dropped.
            let tabs: Vec<i64> = lock(&self.state).next_answers.keys().copied().collect();
            for t in tabs {
                if let Ok(target) = self.target(t)
                    && self.window_of(&target).await == window
                {
                    lock(&self.state).next_answers.remove(&t);
                }
            }
        }
        if let Some(w) = lock(&self.state).agent_windows.get_mut(&window) {
            *w = shown;
        }
        Ok(json!({}))
    }

    async fn set_next_answer(&self, tab: i64, a: &Value) -> Result<Value, String> {
        if !self.in_hidden_window(tab).await {
            return Err(format!(
                "Tab {tab} is not in a hidden agent window; its dialogs are the owner's to answer."
            ));
        }
        let text = a["promptText"].as_str().map(str::to_owned);
        lock(&self.state).next_answers.insert(tab, (a["accept"].as_bool().unwrap_or(false), text));
        Ok(json!({}))
    }

    async fn run(&self, op: &str, a: &Value) -> Result<Value, String> {
        let tab = a["tabId"].as_i64().unwrap_or(-1);
        match op {
            "ping" | "keepRendering" => Ok(json!({})),
            "attach" => self.attach(tab).await,
            "detach" => {
                // An extension's own detach fires no onDetach.
                let entry = lock(&self.state).attached.remove(&tab);
                if let Some((sid, forward)) = entry {
                    forward.abort();
                    self.cdp(None, "Target.detachFromTarget", json!({ "sessionId": sid.as_str() })).await?;
                }
                Ok(json!({}))
            }
            "createWindow" => {
                if let Some(state) = a.get("state").filter(|s| !s.is_null())
                    && state != "minimized"
                {
                    return Err(format!("createWindow takes no state {state}; only 'minimized'."));
                }
                let url = a["url"].as_str().unwrap_or("about:blank");
                let w = self.create(url, Some(a)).await?;
                let mut s = lock(&self.state);
                s.agent_windows.insert(w["windowId"].as_i64().unwrap_or(-1), false);
                s.window_tabs.push(w["tabId"].as_i64().unwrap_or(-1));
                drop(s);
                Ok(w)
            }
            "createTab" => {
                let url = a["url"].as_str().unwrap_or("about:blank").to_owned();
                lock(&self.state).created_tabs.push(url.clone());
                self.create(&url, None).await
            }
            "tabs" => {
                let all = self.cdp(None, "Target.getTargets", json!({})).await?;
                let mut tabs = Vec::new();
                for t in all["targetInfos"].as_array().into_iter().flatten().filter(|t| t["type"] == "page") {
                    tabs.push(self.tab_info(t).await);
                }
                Ok(Value::Array(tabs))
            }
            "tab" => {
                let info = self.target_info(tab).await?;
                Ok(self.tab_info(&info).await)
            }
            "closeTab" => self.close_tab(tab).await,
            "focus" => {
                let target = self.target(tab)?;
                self.cdp(None, "Target.activateTarget", json!({ "targetId": target })).await?;
                Ok(json!({}))
            }
            "windowState" => {
                let window = a["windowId"].as_i64().unwrap_or(-1);
                let state = a["state"].as_str().unwrap_or_default();
                if !["normal", "minimized", "maximized", "fullscreen"].contains(&state) {
                    return Err(format!("Unknown window state: {state}"));
                }
                if !lock(&self.state).agent_windows.contains_key(&window) {
                    return Err(format!("Window {window} is not an agent window; its state is left alone."));
                }
                Ok(json!({ "state": state }))
            }
            "markShown" => self.mark_shown(a).await,
            "answerNextDialog" => self.set_next_answer(tab, a).await,
            "clearForeignFrames" => {
                let info = self.target_info(tab).await?;
                let window = self.window_of(info["targetId"].as_str().unwrap_or_default()).await;
                if lock(&self.state).agent_windows.get(&window) != Some(&false) {
                    return Err(format!(
                        "Tab {tab} is not in a hidden agent window; its frames are left alone."
                    ));
                }
                Ok(json!({ "removed": [], "errors": [] }))
            }
            other => Err(format!("Unknown bridge operation: {other}")),
        }
    }
}
