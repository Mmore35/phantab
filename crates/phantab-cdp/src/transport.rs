//! The seam between a [`crate::Page`] and whatever carries CDP: the extension relay or a browser
//! [`crate::Connection`] (debugging pipe or WebSocket).

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;
use serde_json::Value;

use crate::CdpError;

/// A flat CDP session id. The page's own root session may be `None` (the relay addresses the tab
/// itself); OOPIF and worker sessions always have one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new(id: impl Into<String>) -> Self {
        SessionId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for SessionId {
    fn from(s: &str) -> Self {
        SessionId(s.to_owned())
    }
}

impl From<String> for SessionId {
    fn from(s: String) -> Self {
        SessionId(s)
    }
}

/// What a transport delivers to a page, in arrival order.
#[derive(Debug, Clone, PartialEq)]
pub enum TransportEvent {
    /// A CDP event. `session` is the flat session it arrived on (`None` for the relay's tab, or for
    /// browser-level events on a browser connection).
    Event { session: Option<SessionId>, method: String, params: Value },
    /// The transport is gone for good; the page fails everything pending with this reason.
    Closed(String),
}

/// Carries CDP commands for one page.
///
/// Ordering contract: the request must be queued (written, or handed to the relay) during the first poll
/// of the returned future, before it first awaits. The page relies on that to keep input events in the
/// order they were issued while several are in flight, as puppeteer does.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    async fn send(&self, session: Option<&SessionId>, method: &str, params: Value)
    -> Result<Value, CdpError>;
}

/// The future a relay send closure returns: the CDP result, or the bridge's error message.
pub type RelayFuture = Pin<Box<dyn Future<Output = Result<Value, String>> + Send>>;

/// The relay send closure: `(session, method, params)`. It must hand the request to the bridge when
/// called and only wait for the answer in the future it returns (see [`Transport`]'s ordering contract).
pub type RelaySendFn = Box<dyn Fn(Option<SessionId>, String, Value) -> RelayFuture + Send + Sync>;

/// A [`Transport`] over the extension relay (`chrome.debugger` in the extension, reached through the
/// bridge). Events are not its business: the owner feeds bridge `cdp` events, and `Closed` when the tab
/// ends or the bridge drops, into the channel given to [`crate::Page::attach`].
pub struct RelayTransport {
    send: RelaySendFn,
}

impl RelayTransport {
    pub fn new(send: RelaySendFn) -> Self {
        RelayTransport { send }
    }

    /// Convenience over [`RelayTransport::new`] for a plain async closure.
    pub fn from_fn<F, Fut>(f: F) -> Self
    where
        F: Fn(Option<SessionId>, String, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, String>> + Send + 'static,
    {
        RelayTransport { send: Box::new(move |s, m, p| Box::pin(f(s, m, p))) }
    }
}

impl fmt::Debug for RelayTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayTransport").finish_non_exhaustive()
    }
}

#[async_trait]
impl Transport for RelayTransport {
    async fn send(
        &self,
        session: Option<&SessionId>,
        method: &str,
        params: Value,
    ) -> Result<Value, CdpError> {
        (self.send)(session.cloned(), method.to_owned(), params)
            .await
            .map_err(|m| CdpError::from_relay_message(method, &m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn relay_passes_session_and_maps_errors() {
        let t = RelayTransport::from_fn(|s: Option<SessionId>, m: String, _p: Value| async move {
            match m.as_str() {
                "ok" => Ok(json!({"session": s.map(|s| s.0)})),
                _ => Err(r#"{"code":-32000,"message":"No frame"}"#.to_owned()),
            }
        });
        let v = t.send(Some(&SessionId::from("S1")), "ok", json!({})).await.unwrap();
        assert_eq!(v, json!({"session": "S1"}));
        let v = t.send(None, "ok", json!({})).await.unwrap();
        assert_eq!(v, json!({"session": null}));
        let e = t.send(None, "Page.navigate", json!({})).await.unwrap_err();
        assert_eq!(e.to_string(), "Protocol error (Page.navigate): No frame");
    }
}
