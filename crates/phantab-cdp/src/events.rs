//! The CDP events phantab reads: the one list of them (perf-data-3).
//!
//! Chrome sends many more on an attached tab, `Runtime.consoleAPICalled` and `Runtime.exceptionThrown`
//! most of all (thousands on a page that logs in a loop, each with its arguments and stack). Nothing
//! here reads those, so they need not cross native messaging, the host and the bridge only to be
//! dropped by [`crate::Page`]. The service names this list in its bridge welcome and the extension
//! forwards only these (`extension/src/background.ts`, `forwarded`); the bridge drops any other one an
//! older extension still sends. A test in `crates/phantab/src/cdp_methods.rs` fails when the code
//! matches an event this list lacks, so add a new one here when you read it.

/// Every CDP event method phantab-cdp or the engine matches, sorted. Anything else is dropped.
pub const EVENTS: &[&str] = &[
    "Inspector.detached",
    "Page.frameAttached",
    "Page.frameDetached",
    "Page.frameNavigated",
    "Page.frameStartedLoading",
    "Page.frameStoppedLoading",
    "Page.javascriptDialogClosed",
    "Page.javascriptDialogOpening",
    "Page.lifecycleEvent",
    "Page.navigatedWithinDocument",
    "Runtime.executionContextCreated",
    "Runtime.executionContextDestroyed",
    "Runtime.executionContextsCleared",
    "Target.attachedToTarget",
    "Target.detachedFromTarget",
    "Target.targetDestroyed",
];

/// Whether phantab reads the CDP event `method` ([`EVENTS`]).
#[must_use]
pub fn reads_event(method: &str) -> bool {
    EVENTS.binary_search(&method).is_ok()
}

/// The developer tools' events (THREAT-MODEL SR-90, SR-91), sorted: read only for a page whose console,
/// network or trace the service is recording, on a connection whose welcome declared `devTools`. The extension
/// forwards them only from such a tab's own target (`extension/src/cdp-methods.ts`, `DEVTOOLS_EVENTS`,
/// which a test keeps equal to this list), so a page that never asks sends what it sent before. No
/// `...ExtraInfo` event is here, or ever forwarded: those carry the raw headers, cookies included.
pub const DEVTOOLS_EVENTS: &[&str] = &[
    "Log.entryAdded",
    "Network.loadingFailed",
    "Network.loadingFinished",
    "Network.requestWillBeSent",
    "Network.responseReceived",
    "Runtime.consoleAPICalled",
    "Runtime.exceptionThrown",
    "Tracing.bufferUsage",
    "Tracing.tracingComplete",
];

/// Whether `method` is one of [`DEVTOOLS_EVENTS`].
#[must_use]
pub fn reads_devtools_event(method: &str) -> bool {
    DEVTOOLS_EVENTS.binary_search(&method).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_sorted_unique_and_searchable() {
        assert!(EVENTS.windows(2).all(|w| w[0] < w[1]), "keep EVENTS sorted and unique: {EVENTS:?}");
        for m in EVENTS {
            assert!(reads_event(m), "{m}");
        }
        assert!(!reads_event("Runtime.consoleAPICalled"));
        assert!(!reads_event("Runtime.exceptionThrown"));
        assert!(!reads_event("Page.screencastFrame"));
        assert!(!reads_event(""));
    }

    #[test]
    fn the_developer_tools_events_are_sorted_apart_and_never_extra_info() {
        let sorted = DEVTOOLS_EVENTS.windows(2).all(|w| w[0] < w[1]);
        assert!(sorted, "keep DEVTOOLS_EVENTS sorted and unique: {DEVTOOLS_EVENTS:?}");
        for m in DEVTOOLS_EVENTS {
            assert!(reads_devtools_event(m) && !reads_event(m), "{m}");
            assert!(!m.contains("ExtraInfo") && !m.contains("ookie"), "{m}");
        }
        assert!(!reads_devtools_event("Network.requestWillBeSentExtraInfo"));
        assert!(!reads_devtools_event("Network.responseReceivedExtraInfo"));
        assert!(!reads_devtools_event("Page.frameNavigated"));
    }
}
