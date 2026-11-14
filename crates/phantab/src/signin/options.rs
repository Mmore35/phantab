//! The call's time budgets and the two test-only switches (THREAT-MODEL SR-30, SR-45).
//! A normal build has only [`Options::default`]: the setters exist with the `test-seams` feature alone,
//! which the crate's own dev-dependency turns on, so a release binary cannot loosen a guard.

use std::time::Duration;

use tracing::level_filters::LevelFilter;

/// The call's time budgets. A client gives up on a call at 90 s while the service carries on, so
/// nothing may send late enough for that to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Times {
    pub call_ms: u64,
    pub fill_by_ms: u64,
    pub provider_ms: u64,
    pub observe_ms: u64,
    pub settle_ms: u64,
    pub find_ms: u64,
}

impl Default for Times {
    fn default() -> Self {
        Times {
            call_ms: 80_000,
            fill_by_ms: 60_000,
            provider_ms: 45_000,
            observe_ms: 15_000,
            settle_ms: 4_000,
            find_ms: 4_000,
        }
    }
}

/// What a sign-in may be told by its engine.
#[derive(Debug, Clone, Default)]
pub struct Options {
    times: Times,
    allow_loopback: bool,
    ignore_debug_logging: bool,
}

impl Options {
    #[must_use]
    pub fn times(&self) -> Times {
        self.times
    }

    /// `engine.options.allowLoopback===true`: `http://127.0.0.1` and `http://localhost` count as secure.
    #[must_use]
    pub fn allow_loopback(&self) -> bool {
        self.allow_loopback
    }

    #[must_use]
    pub fn ignore_debug_logging(&self) -> bool {
        self.ignore_debug_logging
    }
}

#[cfg(feature = "test-seams")]
impl Options {
    /// Test builds only: `{...defaults, ...engine.options.times}`.
    #[must_use]
    pub fn with_times(mut self, change: impl FnOnce(&mut Times)) -> Self {
        change(&mut self.times);
        self
    }

    /// Test builds only: sets `allowLoopback`.
    #[must_use]
    pub fn with_loopback(mut self, on: bool) -> Self {
        self.allow_loopback = on;
        self
    }

    /// Test builds only: lets the TRACE sentinel test run a sign-in, to show nothing leaks even then.
    #[must_use]
    pub fn with_debug_logging_ignored(mut self, on: bool) -> Self {
        self.ignore_debug_logging = on;
        self
    }
}

pub(crate) fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Sign-in is refused while message bodies could be logged (THREAT-MODEL
/// SR-42): any tracing subscriber in the process that would take
/// events above `info`. [`LevelFilter::current`] is the most verbose level any registered subscriber
/// (global or scoped) has asked for, so it covers every phantab target at once; a capped third-party
/// target (SR-42) does not raise it, since the service folds those caps into its own directives.
#[must_use]
pub fn debug_logging_on() -> bool {
    too_verbose(LevelFilter::current())
}

pub(crate) fn too_verbose(level: LevelFilter) -> bool {
    level > LevelFilter::INFO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_are_the_documented_ones() {
        let t = Options::default().times();
        assert_eq!(
            [t.call_ms, t.fill_by_ms, t.provider_ms, t.observe_ms, t.settle_ms, t.find_ms],
            [80_000, 60_000, 45_000, 15_000, 4_000, 4_000]
        );
        assert!(!Options::default().allow_loopback());
        assert!(!Options::default().ignore_debug_logging());
    }

    #[test]
    fn levels_above_info_refuse() {
        for (level, refuse) in [
            (LevelFilter::OFF, false),
            (LevelFilter::ERROR, false),
            (LevelFilter::WARN, false),
            (LevelFilter::INFO, false),
            (LevelFilter::DEBUG, true),
            (LevelFilter::TRACE, true),
        ] {
            assert_eq!(too_verbose(level), refuse, "{level}");
        }
    }
}
