//! Shared pages over the bridge's CDP relay.
//!
//! Each relay page is a [`Page`] over a [`RelayTransport`] whose send is the bridge's `send` op. Its
//! events come from one dispatcher (the engine's bridge subscription), which hands each tab's `Cdp`
//! events to that tab's [`Route`] (one task for every page, not one per page). The
//! bridge refuses a method off the SR-20 list before it leaves the process (`crate::cdp_methods`).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use phantab_cdp::{Page, PageOptions, RelayTransport, SessionId, TransportEvent};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::Engine;
use crate::bridge::{BridgeError, CdpEvent, Profile, SEND_OP_TIMEOUT, TabId};
use crate::engine_api::{EngineError, EngineResult};
use crate::util::lock;

/// Network and Audits events are most of a heavy page's traffic through the extension, and nothing here
/// enables or reads them. puppeteer's `protocolTimeout: 15000`.
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(15);

static NEXT_ROUTE: AtomicU64 = AtomicU64::new(1);

/// How the extension's `send` refuses a method off its list (`extension/src/background.ts`).
const EXTENSION_REFUSED: &str = "CDP method not allowed: ";

/// The service and the extension read one allow-list, so the extension refusing a method this service
/// sends means the loaded extension is older than the service (a list that grew in an update).
fn remote_error(m: String) -> String {
    if m.starts_with(EXTENSION_REFUSED) {
        return format!(
            "{m}. The phantab bridge extension is older than this phantab: reload it at chrome://extensions."
        );
    }
    m
}

/// Where one relay page's events go.
#[derive(Debug)]
pub(crate) struct Route {
    pub id: u64,
    tx: mpsc::UnboundedSender<TransportEvent>,
}

/// A relay page's hold on its tab: closing it ends the page and detaches the debugger. The tab is
/// `profile`'s, and only that profile's link speaks for it (SR-76).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    pub profile: Profile,
    pub tab: TabId,
    pub route: u64,
}

/// A page attached to a tab.
#[derive(Debug)]
pub(crate) struct Linked {
    pub page: Page,
    pub link: Link,
}

/// Starts `f` now, so whatever it sends goes out before anything sent after this returns (an
/// un-awaited bridge call), and finishes it in the background.
pub(crate) fn fire<F>(f: F)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let mut f = Box::pin(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    if f.as_mut().poll(&mut cx).is_pending() {
        tokio::spawn(f);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendArgs<'a> {
    tab_id: TabId,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
    method: &'a str,
    params: &'a Value,
}

impl Engine {
    /// Hands a tab's CDP event to its page, if one is attached.
    pub(crate) fn route_event(&self, e: &CdpEvent) {
        // Parsed before the routes lock, which every tab's events and every attach share. The send
        // stays under it, so it is still ordered against `close_route`.
        let params =
            e.params.as_ref().and_then(|p| serde_json::from_str(p.get()).ok()).unwrap_or_else(|| json!({}));
        let session = e.session_id.clone().map(SessionId::new);
        let routes = lock(&self.routes);
        let Some(route) = routes.get(&(e.profile.clone(), e.tab_id)) else { return };
        // A page already gone has dropped its receiver; nothing to tell it.
        let _ = route.tx.send(TransportEvent::Event { session, method: e.method.clone(), params });
    }

    /// Ends the page on `route` if it is still the tab's (`transport.onclose`), and with `detach` also
    /// detaches the debugger (`transport.close`), as puppeteer's `disconnect` does.
    pub(crate) fn close_route(&self, profile: &Profile, tab: TabId, route: u64, detach: bool) {
        let key = (profile.clone(), tab);
        let removed = {
            let mut routes = lock(&self.routes);
            if routes.get(&key).is_some_and(|r| r.id == route) { routes.remove(&key) } else { None }
        };
        let Some(removed) = removed else { return };
        let _ = removed.tx.send(TransportEvent::Closed("Target closed".to_owned()));
        if detach {
            let bridge = Arc::clone(self.bridge());
            let profile = profile.clone();
            fire(async move {
                let _ = bridge.op_in(&profile, "detach", json!({ "tabId": tab })).await;
            });
        }
    }

    /// `browser.disconnect()` on a relay page.
    pub(crate) fn close_link(&self, link: &Link) {
        self.close_route(&link.profile, link.tab, link.route, true);
    }

    fn relay(&self, profile: &Profile, tab: TabId) -> RelayTransport {
        let bridge = Arc::clone(self.bridge());
        let profile = profile.clone();
        RelayTransport::from_fn(move |session: Option<SessionId>, method: String, params: Value| {
            let bridge = Arc::clone(&bridge);
            let profile = profile.clone();
            async move {
                let args = SendArgs {
                    tab_id: tab,
                    session_id: session.as_ref().map(SessionId::as_str),
                    method: &method,
                    params: &params,
                };
                match bridge.op_raw_in(&profile, "send", &args, SEND_OP_TIMEOUT).await {
                    Ok(Some(raw)) => serde_json::from_str(raw.get()).map_err(|e| e.to_string()),
                    Ok(None) => Ok(json!({})),
                    Err(BridgeError::Remote(m)) => Err(remote_error(m)),
                    Err(e) => Err(e.to_string()),
                }
            }
        })
    }

    /// `pageFor(tabId)`: attaches the debugger to the tab and opens a page on it. A failed connect does
    /// not leave the debugger attached, or the next attach is refused. `workspace`: the tab is in an agent
    /// window, whose popups open as its tabs (`PageOptions::popups_as_tabs`); an owner's tab keeps its own.
    /// The tab is `profile`'s, attached and driven through that profile's link.
    pub(crate) async fn page_for(
        &self,
        profile: &Profile,
        tab: TabId,
        workspace: bool,
    ) -> EngineResult<Linked> {
        let (tx, rx) = mpsc::unbounded_channel();
        let link = Link { profile: profile.clone(), tab, route: NEXT_ROUTE.fetch_add(1, Ordering::Relaxed) };
        // Before the attach, so no event of the new session is missed.
        lock(&self.routes).insert((profile.clone(), tab), Route { id: link.route, tx });
        if let Err(e) = self.bridge().op_in(profile, "attach", json!({ "tabId": tab })).await {
            self.close_route(profile, tab, link.route, false);
            return Err(e.into());
        }
        let options = PageOptions {
            protocol_timeout: PROTOCOL_TIMEOUT,
            popups_as_tabs: workspace,
            // An agent's page: a passkey request there is the owner's to answer.
            watch_passkeys: workspace,
            ..PageOptions::default()
        };
        match Page::attach(Arc::new(self.relay(profile, tab)), None, rx, options).await {
            Ok(page) if page.main_frame().is_ok() => Ok(Linked { page, link }),
            Ok(_) => {
                self.close_link(&link);
                Err(EngineError("Chrome did not expose the tab as a page.".to_owned()))
            }
            Err(e) => {
                self.close_link(&link);
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_older_extension_refusing_a_method_says_to_reload_it() {
        assert_eq!(
            remote_error("CDP method not allowed: Page.createIsolatedWorld".into()),
            "CDP method not allowed: Page.createIsolatedWorld. The phantab bridge extension is older than this phantab: reload it at chrome://extensions."
        );
        assert_eq!(
            remote_error("Debugger is not attached to the tab with id: 4.".into()),
            "Debugger is not attached to the tab with id: 4."
        );
    }
}
