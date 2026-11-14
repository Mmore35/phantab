//! A browser-level CDP connection with flat sessions, demultiplexed per page. The wire under it is a
//! WebSocket ([`crate::ws`]) or Chrome's debugging pipe ([`crate::pipe`]); both feed this one core, so
//! routing, timeouts and `Closed` behave the same on either.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{CdpError, SessionId, Transport, TransportEvent};

/// The largest message either wire accepts. Puppeteer's `NodeWebSocketTransport` allows 256 MiB
/// payloads; full-page screenshots need it.
pub(crate) const MAX_MESSAGE: usize = 256 << 20;

/// What the connection hands its wire's writer.
#[derive(Debug)]
pub(crate) enum Outgoing {
    /// One CDP command, serialized JSON.
    Text(String),
    /// Close the wire after what is queued.
    Close,
}

type Reply = oneshot::Sender<Result<Value, CdpError>>;

/// Which page channel each session's events go to. A page's root session and every session that
/// attaches beneath it share one channel, so a page sees its OOPIFs without knowing about the socket.
#[derive(Default)]
struct Routes {
    by_session: HashMap<SessionId, mpsc::UnboundedSender<TransportEvent>>,
    roots: HashSet<SessionId>,
    /// Root channels created when Chrome announced the attach, waiting for [`Connection::take_events`].
    /// Chrome sends `Target.attachedToTarget` before the `attachToTarget` answer, and the session's
    /// first events can follow before the caller has the id, so they are buffered here.
    unclaimed: HashMap<SessionId, mpsc::UnboundedReceiver<TransportEvent>>,
}

impl Routes {
    /// Drops every route feeding the same channel as `root`.
    fn remove_page(&mut self, root: &SessionId) -> Option<mpsc::UnboundedSender<TransportEvent>> {
        let tx = self.by_session.get(root).cloned()?;
        self.by_session.retain(|_, t| !t.same_channel(&tx));
        self.roots.remove(root);
        self.unclaimed.remove(root);
        Some(tx)
    }
}

struct Inner {
    /// The WebSocket URL; `None` on a pipe.
    url: Option<String>,
    out: mpsc::UnboundedSender<Outgoing>,
    pending: Mutex<HashMap<u64, (String, Reply)>>,
    next_id: AtomicU64,
    routes: Mutex<Routes>,
    closed: watch::Sender<Option<String>>,
}

impl Inner {
    fn dispatch(&self, text: &str) {
        // A message that is not an object has no id or method, so it is dropped either way.
        let mut msg = match serde_json::from_str(text) {
            Ok(Value::Object(m)) => m,
            Ok(_) => return,
            Err(e) => {
                tracing::debug!(error = %e, "unparseable CDP message");
                return;
            }
        };
        if let Some(id) = msg.get("id").and_then(Value::as_u64) {
            let entry = self.pending.lock().remove(&id);
            if let Some((method, tx)) = entry {
                let r = match msg.get("error") {
                    Some(e) => Err(CdpError::protocol(&method, e)),
                    // Moved out, not copied: a reply can be a screenshot's few hundred kilobytes.
                    None => Ok(msg.remove("result").unwrap_or_else(|| json!({}))),
                };
                let _ = tx.send(r);
            }
            return;
        }
        let params = msg.remove("params").unwrap_or_else(|| json!({}));
        let Some(method) = msg.get("method").and_then(Value::as_str) else { return };
        let session = msg.get("sessionId").and_then(Value::as_str).map(SessionId::from);
        let child = params.get("sessionId").and_then(Value::as_str).map(SessionId::from);
        let mut routes = self.routes.lock();
        let tx = match &session {
            Some(s) => {
                let Some(tx) = routes.by_session.get(s).cloned() else { return };
                // Routes change here, on the reader, so a child's first event can never beat its route.
                match (method, &child) {
                    ("Target.attachedToTarget", Some(c)) => {
                        routes.by_session.insert(c.clone(), tx.clone());
                    }
                    ("Target.detachedFromTarget", Some(c)) => {
                        routes.by_session.remove(c);
                    }
                    _ => {}
                }
                tx
            }
            None => match (method, child) {
                ("Target.attachedToTarget", Some(c)) => {
                    let (tx, rx) = mpsc::unbounded_channel();
                    routes.by_session.insert(c.clone(), tx);
                    routes.roots.insert(c.clone());
                    routes.unclaimed.insert(c, rx);
                    return;
                }
                // The page learns its own end from the browser-level event, as it would on a relay.
                ("Target.detachedFromTarget", Some(c)) if routes.roots.contains(&c) => {
                    let Some(tx) = routes.remove_page(&c) else { return };
                    tx
                }
                _ => return,
            },
        };
        drop(routes);
        let ev = TransportEvent::Event { session, method: method.to_owned(), params };
        if tx.send(ev).is_err() {
            // The page is gone; stop routing its sessions.
            let mut routes = self.routes.lock();
            let dead: Vec<SessionId> = routes
                .roots
                .iter()
                .filter(|r| routes.by_session.get(*r).is_some_and(|t| t.same_channel(&tx)))
                .cloned()
                .collect();
            for r in dead {
                routes.remove_page(&r);
            }
            routes.by_session.retain(|_, t| !t.same_channel(&tx));
        }
    }

    /// Fails everything in flight and tells every page. Idempotent.
    fn shutdown(&self, reason: &str) {
        let pending = {
            let mut pending = self.pending.lock();
            // Set under the pending lock so no send can slip in after the drain and wait forever.
            let first = self.closed.send_if_modified(|c| {
                if c.is_some() {
                    return false;
                }
                *c = Some(reason.to_owned());
                true
            });
            if !first {
                return;
            }
            std::mem::take(&mut *pending)
        };
        for (_, (_, tx)) in pending {
            let _ = tx.send(Err(CdpError::Closed(reason.to_owned())));
        }
        let routes = std::mem::take(&mut *self.routes.lock());
        let mut told: Vec<mpsc::UnboundedSender<TransportEvent>> = Vec::new();
        for tx in routes.by_session.into_values() {
            if !told.iter().any(|t| t.same_channel(&tx)) {
                let _ = tx.send(TransportEvent::Closed(reason.to_owned()));
                told.push(tx);
            }
        }
    }

    fn closed_reason(&self) -> Option<String> {
        self.closed.borrow().clone()
    }
}

/// Removes a pending entry whose caller stopped waiting (timeout or drop).
struct PendingGuard<'a> {
    inner: &'a Inner,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.inner.pending.lock().remove(&self.id);
    }
}

/// The wire's handle on its connection: the reader delivers each message and reports the end. Holds
/// the connection weakly, so a wire never keeps a dropped connection alive.
#[derive(Clone)]
pub(crate) struct Feed(Weak<Inner>);

impl Feed {
    /// Routes one received message. `false` once the connection is gone, so the reader can stop.
    pub(crate) fn deliver(&self, text: &str) -> bool {
        let Some(inner) = self.0.upgrade() else { return false };
        inner.dispatch(text);
        true
    }

    /// The wire ended: fails everything in flight and tells every page.
    pub(crate) fn end(&self, reason: &str) {
        if let Some(inner) = self.0.upgrade() {
            inner.shutdown(reason);
        }
    }
}

/// A browser-level CDP connection over a WebSocket ([`Connection::connect`]) or a debugging pipe
/// ([`Connection::pipe`]). Cheap to clone; clones share the wire. Implements [`Transport`] for every
/// session on it (`None` is the browser session).
#[derive(Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("url", &self.inner.url)
            .field("closed", &self.inner.closed_reason())
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// A connection with no wire yet: the wire's writer drains the receiver, its reader uses the
    /// [`Feed`].
    pub(crate) fn new(url: Option<String>) -> (Connection, mpsc::UnboundedReceiver<Outgoing>, Feed) {
        let (out, out_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            url,
            out,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            routes: Mutex::new(Routes::default()),
            closed: watch::Sender::new(None),
        });
        let feed = Feed(Arc::downgrade(&inner));
        (Connection { inner }, out_rx, feed)
    }

    /// The WebSocket URL this connection was opened with; `None` on a pipe.
    pub fn url(&self) -> Option<&str> {
        self.inner.url.as_deref()
    }

    /// Takes the event channel of a page session attached with `Target.attachToTarget{flatten:true}`:
    /// its own events, those of sessions attached beneath it, and its browser-level
    /// `Target.detachedFromTarget` (with `session: None`). Hand it to [`crate::Page::attach`].
    pub fn take_events(&self, session: &SessionId) -> mpsc::UnboundedReceiver<TransportEvent> {
        let mut routes = self.inner.routes.lock();
        if let Some(rx) = routes.unclaimed.remove(session) {
            return rx;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        if let Some(reason) = self.inner.closed_reason() {
            let _ = tx.send(TransportEvent::Closed(reason));
            return rx;
        }
        routes.by_session.insert(session.clone(), tx);
        routes.roots.insert(session.clone());
        rx
    }

    /// Closes the wire. Pending commands fail with [`CdpError::Closed`]. On a pipe, Chrome takes the
    /// closed pipe as its signal to exit.
    pub fn close(&self) {
        let _ = self.inner.out.send(Outgoing::Close);
        self.inner.shutdown("Connection closed");
    }

    /// `Some(reason)` once the wire is closed.
    pub fn closed(&self) -> watch::Receiver<Option<String>> {
        self.inner.closed.subscribe()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed_reason().is_some()
    }
}

#[async_trait]
impl Transport for Connection {
    async fn send(
        &self,
        session: Option<&SessionId>,
        method: &str,
        params: Value,
    ) -> Result<Value, CdpError> {
        // Everything up to the await runs on the first poll, which queues the request in call order.
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending.lock();
            if let Some(r) = self.inner.closed_reason() {
                return Err(CdpError::Closed(r));
            }
            pending.insert(id, (method.to_owned(), tx));
        }
        let _guard = PendingGuard { inner: &self.inner, id };
        let mut msg = Map::new();
        msg.insert("id".into(), id.into());
        msg.insert("method".into(), method.into());
        msg.insert("params".into(), params);
        if let Some(s) = session {
            msg.insert("sessionId".into(), s.as_str().into());
        }
        // serde_json escapes control characters, so the text never holds the pipe's NUL terminator.
        let text = Value::Object(msg).to_string();
        if self.inner.out.send(Outgoing::Text(text)).is_err() {
            return Err(CdpError::Closed(
                self.inner.closed_reason().unwrap_or_else(|| "Connection closed".into()),
            ));
        }
        match rx.await {
            Ok(r) => r,
            Err(_) => Err(CdpError::Closed(
                self.inner.closed_reason().unwrap_or_else(|| "Connection closed".into()),
            )),
        }
    }
}
