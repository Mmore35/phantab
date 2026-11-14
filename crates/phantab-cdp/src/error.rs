//! One error type for every CDP failure, and the single place that classifies them.

use serde_json::Value;

/// Phrases (lower case) that mean "the page navigated under this call". The engine retries on these, so
/// they mirror its `NAVIGATING` pattern; keep classification here and nowhere else.
/// phantab: `uniquecontextid not found` is what V8 says for a call by unique id whose context went.
const NAVIGATING: [&str; 5] = [
    "context was destroyed",
    "cannot find context",
    "detached frame",
    "inspected target navigated",
    "uniquecontextid not found",
];

/// Everything that can go wrong talking to a page.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CdpError {
    /// The browser answered a command with an error.
    #[error("Protocol error ({method}): {message}{}", data.as_ref().map(|d| format!(" {d}")).unwrap_or_default())]
    Protocol { method: String, code: Option<i64>, message: String, data: Option<String> },
    /// No answer within the protocol timeout. Puppeteer appends advice about `protocolTimeout`; the
    /// engine only matches "timed out", so the advice is dropped.
    #[error("{method} timed out.")]
    Timeout { method: String },
    /// `goto` did not reach `DOMContentLoaded` (or a same-document navigation) in time.
    #[error("Navigation timeout of {0} ms exceeded")]
    NavigationTimeout(u64),
    /// A waiting helper (execution context, locator) ran out of time. `last` is the error from the final
    /// attempt, kept because puppeteer attaches it as the `cause`.
    #[error("Timed out after waiting {ms}ms")]
    WaitTimeout { ms: u64, last: Option<String> },
    /// `goto` failed with the browser's `errorText`, e.g. `net::ERR_NAME_NOT_RESOLVED at http://x/`,
    /// or the navigating frame went away.
    #[error("{0}")]
    Navigation(String),
    /// The page function threw. `value` is set when it threw a non-Error value (puppeteer rethrows the
    /// value itself; here it is kept alongside its JSON text).
    #[error("{message}")]
    Evaluation { name: Option<String>, message: String, value: Option<Value> },
    /// The execution context went away mid-call, almost always because the frame navigated.
    #[error("Execution context was destroyed, most likely because of a navigation.")]
    ContextDestroyed,
    /// The frame is gone (`Attempted to use detached Frame '<id>'.` and friends).
    #[error("{0}")]
    DetachedFrame(String),
    /// A selector click found another element on top of its target at the click point, so it sent
    /// nothing; the string says what covers it and what to do.
    #[error("{0}")]
    Covered(String),
    /// The page or its transport closed; the string is the reason.
    #[error("{0}")]
    Closed(String),
    /// Starting Chrome or reaching its devtools endpoint failed.
    #[error("{0}")]
    Launch(String),
    /// Anything else, with puppeteer's message where one exists.
    #[error("{0}")]
    Other(String),
}

impl CdpError {
    /// Builds a protocol error from a CDP `error` object (`{code, message, data}`).
    pub fn protocol(method: &str, error: &Value) -> Self {
        let message = error.get("message").and_then(Value::as_str).unwrap_or("Unknown error").to_owned();
        let data = error.get("data").map(|d| d.as_str().map_or_else(|| d.to_string(), str::to_owned));
        CdpError::Protocol {
            method: method.to_owned(),
            code: error.get("code").and_then(Value::as_i64),
            message,
            data,
        }
    }

    /// Maps a relay error string. `chrome.debugger.sendCommand` reports protocol errors as their JSON
    /// (`{"code":-32000,"message":"..."}`) and its own failures as plain text, so both land here.
    pub fn from_relay_message(method: &str, message: &str) -> Self {
        if let Ok(v @ Value::Object(_)) = serde_json::from_str::<Value>(message)
            && v.get("message").is_some_and(Value::is_string)
        {
            return Self::protocol(method, &v);
        }
        CdpError::Protocol { method: method.to_owned(), code: None, message: message.to_owned(), data: None }
    }

    /// True for every kind of timeout: a command, a navigation, or a wait.
    pub fn is_timeout(&self) -> bool {
        match self {
            CdpError::Timeout { .. } | CdpError::NavigationTimeout(_) | CdpError::WaitTimeout { .. } => true,
            CdpError::Other(m) => m.to_ascii_lowercase().contains("timed out"),
            _ => false,
        }
    }

    /// True when the call failed because the page navigated (or the frame detached) under it, so the
    /// caller should re-read the page rather than report a failure.
    pub fn is_navigating(&self) -> bool {
        match self {
            CdpError::ContextDestroyed | CdpError::DetachedFrame(_) => true,
            // `Evaluation` falls through to false: page-thrown errors are the page's own words, and a
            // script throwing "Cannot find context" did not navigate. The engine's regex would match them
            // anyway; this is a deliberate narrowing.
            CdpError::Protocol { message, .. } | CdpError::Other(message) | CdpError::Navigation(message) => {
                is_navigating_message(message)
            }
            _ => false,
        }
    }

    /// True when the page or transport closed.
    pub fn is_closed(&self) -> bool {
        matches!(self, CdpError::Closed(_))
    }

    /// Puppeteer's `rewriteError` for evaluation calls: these protocol messages mean the context is gone,
    /// and are reported as [`CdpError::ContextDestroyed`]. phantab adds V8's answer to a call by
    /// `uniqueContextId` (the id puppeteer does not use) whose context is gone.
    pub(crate) fn rewrite_for_evaluation(self) -> Self {
        if let CdpError::Protocol { message, .. } = &self
            && (message.ends_with("Cannot find context with specified id")
                || message.ends_with("Inspected target navigated or closed")
                || message.ends_with("uniqueContextId not found"))
        {
            return CdpError::ContextDestroyed;
        }
        self
    }

    /// Puppeteer turns these into `undefined` instead of failing (the result simply could not be
    /// serialized).
    pub(crate) fn is_unreturnable_value(&self) -> bool {
        matches!(self, CdpError::Protocol { message, .. }
            if message.contains("Object reference chain is too long")
                || message.contains("Object couldn't be returned by value"))
    }
}

fn is_navigating_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    NAVIGATING.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn protocol_display_matches_puppeteer() {
        let e = CdpError::protocol("Runtime.evaluate", &json!({"code": -32000, "message": "boom"}));
        assert_eq!(e.to_string(), "Protocol error (Runtime.evaluate): boom");
        let e = CdpError::protocol("X.y", &json!({"code": -32602, "message": "Invalid", "data": "why"}));
        assert_eq!(e.to_string(), "Protocol error (X.y): Invalid why");
    }

    #[test]
    fn relay_messages_parse_json_or_keep_text() {
        let e = CdpError::from_relay_message(
            "Runtime.callFunctionOn",
            r#"{"code":-32000,"message":"Cannot find context with specified id"}"#,
        );
        assert!(matches!(&e, CdpError::Protocol { code: Some(-32000), .. }));
        assert!(e.is_navigating());
        assert_eq!(e.clone().rewrite_for_evaluation(), CdpError::ContextDestroyed);
        // A call by unique id whose context is gone (V8's InvalidParams).
        let e = CdpError::from_relay_message(
            "Runtime.callFunctionOn",
            r#"{"code":-32602,"message":"uniqueContextId not found"}"#,
        );
        assert!(e.is_navigating());
        assert_eq!(e.rewrite_for_evaluation(), CdpError::ContextDestroyed);

        let e =
            CdpError::from_relay_message("Page.navigate", "Debugger is not attached to the tab with id: 4.");
        assert_eq!(
            e.to_string(),
            "Protocol error (Page.navigate): Debugger is not attached to the tab with id: 4."
        );
        assert!(!e.is_navigating());
    }

    #[test]
    fn navigating_classification() {
        for m in [
            "Execution context was destroyed, most likely because of a navigation.",
            "Cannot find context with specified id",
            "Attempted to use detached Frame 'ABC'.",
            "Inspected target navigated or closed",
            "uniqueContextId not found",
        ] {
            assert!(CdpError::Other(m.into()).is_navigating(), "{m}");
            assert!(
                CdpError::Protocol { method: "M".into(), code: None, message: m.into(), data: None }
                    .is_navigating(),
                "{m}"
            );
        }
        assert!(CdpError::ContextDestroyed.is_navigating());
        assert!(CdpError::ContextDestroyed.to_string().contains("context was destroyed"));
        assert!(CdpError::DetachedFrame("x".into()).is_navigating());
        assert!(
            !CdpError::Evaluation { name: None, message: "Cannot find context".into(), value: None }
                .is_navigating()
        );
        assert!(!CdpError::Closed("Target closed".into()).is_navigating());
        assert!(!CdpError::Other("Node is detached from document".into()).is_navigating());
    }

    #[test]
    fn timeout_classification() {
        let e = CdpError::Timeout { method: "Page.navigate".into() };
        assert_eq!(e.to_string(), "Page.navigate timed out.");
        assert!(e.is_timeout());
        assert!(CdpError::NavigationTimeout(30_000).is_timeout());
        assert_eq!(
            CdpError::NavigationTimeout(30_000).to_string(),
            "Navigation timeout of 30000 ms exceeded"
        );
        assert!(CdpError::WaitTimeout { ms: 10, last: None }.is_timeout());
        assert!(!CdpError::Closed("x".into()).is_timeout());
        assert!(!CdpError::Closed("x".into()).is_navigating());
        assert!(CdpError::Closed("x".into()).is_closed());
    }

    #[test]
    fn unreturnable_values() {
        let e = CdpError::Protocol {
            method: "Runtime.callFunctionOn".into(),
            code: Some(-32000),
            message: "Object reference chain is too long".into(),
            data: None,
        };
        assert!(e.is_unreturnable_value());
        assert!(!CdpError::ContextDestroyed.is_unreturnable_value());
    }
}
