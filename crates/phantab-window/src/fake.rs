//! Window control without an OS: [`Noop`] for headless lanes, [`Recording`] for engine unit tests.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::{
    ArmGuard, HideStrategy, NativeHandle, QuietState, Result, Snapshot, WindowControl, WindowError,
    WindowSpec,
};

/// Does nothing and succeeds, so the engine's window steps pass through a headless lane: arm catches
/// nothing, `find` answers handle 0, show and hide succeed, `snapshot` is empty and `quiet` finds no entry
/// and no running browser. Tokens are still checked, so a lane catches a malformed one.
#[derive(Debug, Clone, Copy, Default)]
pub struct Noop;

#[async_trait::async_trait]
impl WindowControl for Noop {
    fn strategy(&self) -> HideStrategy {
        HideStrategy::None
    }
    async fn arm_hide_within(&self, spec: &WindowSpec, _timeout: Duration) -> Result<ArmGuard> {
        crate::check_token(&spec.token)?;
        Ok(ArmGuard::settled(None))
    }
    async fn find(&self, token: &str) -> Result<NativeHandle> {
        crate::check_token(token)?;
        Ok(NativeHandle(0))
    }
    async fn hide(&self, _handle: NativeHandle) -> Result<()> {
        Ok(())
    }
    async fn show(&self, _handle: NativeHandle, _maximize: bool) -> Result<()> {
        Ok(())
    }
    async fn is_visible(&self, _handle: NativeHandle) -> Result<bool> {
        Ok(false)
    }
    async fn snapshot(&self) -> Result<Snapshot> {
        Ok(Snapshot::default())
    }
    async fn quiet(&self, _mode_on: bool, _chrome_path: &str, _run_key: Option<&str>) -> Result<QuietState> {
        Ok(QuietState::default())
    }
}

/// One call a [`Recording`] saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Arm(WindowSpec),
    Find(String),
    Hide(NativeHandle),
    Show { handle: NativeHandle, maximize: bool },
    KeepHidden { handle: NativeHandle, on: bool },
    IsVisible(NativeHandle),
    Snapshot,
    Quiet { mode_on: bool, chrome_path: String, run_key: Option<String> },
}

/// Records every call and answers with what the test set up. It keeps a visible/hidden state per handle,
/// so show and hide are observable through `is_visible`.
#[derive(Debug, Default)]
pub struct Recording {
    inner: Mutex<RecordingState>,
}

#[derive(Debug, Default)]
struct RecordingState {
    calls: Vec<Call>,
    arm_answer: Option<NativeHandle>,
    windows: Vec<(String, NativeHandle)>,
    visible: Vec<NativeHandle>,
    snapshot: Snapshot,
    quiet: QuietState,
    /// `None` reads as [`HideStrategy::OsHook`], the strategy whose calls the engine makes most.
    strategy: Option<HideStrategy>,
    /// `keep_hidden(_, true)` fails, as a keeper that timed out or could not hook would.
    keeps_fail: bool,
    /// `hide` fails, leaving the window as it was.
    hides_fail: bool,
    /// `show` fails, leaving the window as it was.
    shows_fail: bool,
}

impl Recording {
    pub fn new() -> Self {
        Self::default()
    }

    /// What `settle` gives for every armed hide (default `None`, the find-by-title path).
    #[must_use]
    pub fn with_arm_answer(self, handle: Option<NativeHandle>) -> Self {
        self.state().arm_answer = handle;
        self
    }

    /// A window with this title, for `find`; show and hide accept its handle.
    #[must_use]
    pub fn with_window(self, title: impl Into<String>, handle: NativeHandle) -> Self {
        self.state().windows.push((title.into(), handle));
        self
    }

    /// What `strategy` answers (default [`HideStrategy::OsHook`]). Not recorded as a call.
    #[must_use]
    pub fn with_strategy(self, strategy: HideStrategy) -> Self {
        self.state().strategy = Some(strategy);
        self
    }

    #[must_use]
    pub fn with_snapshot(self, snapshot: Snapshot) -> Self {
        self.state().snapshot = snapshot;
        self
    }

    #[must_use]
    pub fn with_quiet(self, quiet: QuietState) -> Self {
        self.state().quiet = quiet;
        self
    }

    /// From now on, `keep_hidden(_, true)` fails (still recorded), as a keeper that timed out or could not
    /// hook the window's process would; `false` ends that.
    pub fn fail_keeps(&self, on: bool) {
        self.state().keeps_fail = on;
    }

    /// From now on, `hide` fails (still recorded) and leaves the window as it was; `false` ends that.
    pub fn fail_hides(&self, on: bool) {
        self.state().hides_fail = on;
    }

    /// From now on, `show` fails (still recorded) and leaves the window as it was; `false` ends that.
    pub fn fail_shows(&self, on: bool) {
        self.state().shows_fail = on;
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.state().calls.clone()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, RecordingState> {
        // A test that panicked mid-call still leaves a readable record.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, call: Call) -> std::sync::MutexGuard<'_, RecordingState> {
        let mut state = self.state();
        state.calls.push(call);
        state
    }

    fn known(state: &RecordingState, handle: NativeHandle) -> Result<()> {
        let known = state.windows.iter().any(|(_, h)| *h == handle) || state.arm_answer == Some(handle);
        if known { Ok(()) } else { Err(WindowError::InvalidHandle) }
    }
}

#[async_trait::async_trait]
impl WindowControl for Recording {
    fn strategy(&self) -> HideStrategy {
        self.state().strategy.unwrap_or(HideStrategy::OsHook)
    }
    async fn arm_hide_within(&self, spec: &WindowSpec, _timeout: Duration) -> Result<ArmGuard> {
        let mut state = self.record(Call::Arm(spec.clone()));
        crate::check_token(&spec.token)?;
        let answer = state.arm_answer;
        if let Some(handle) = answer {
            state.visible.retain(|h| *h != handle);
        }
        Ok(ArmGuard::settled(answer))
    }

    async fn find(&self, token: &str) -> Result<NativeHandle> {
        let state = self.record(Call::Find(token.to_owned()));
        crate::check_token(token)?;
        let found: Vec<NativeHandle> =
            state.windows.iter().filter(|(title, _)| title.contains(token)).map(|(_, h)| *h).collect();
        match found.as_slice() {
            [one] => Ok(*one),
            _ => Err(WindowError::NotExactlyOne { found: found.len() }),
        }
    }

    async fn hide(&self, handle: NativeHandle) -> Result<()> {
        let mut state = self.record(Call::Hide(handle));
        Self::known(&state, handle)?;
        if state.hides_fail {
            return Err(WindowError::Os {
                context: "hide the window",
                message: "the test failed this hide".into(),
            });
        }
        state.visible.retain(|h| *h != handle);
        Ok(())
    }

    async fn show(&self, handle: NativeHandle, maximize: bool) -> Result<()> {
        let mut state = self.record(Call::Show { handle, maximize });
        Self::known(&state, handle)?;
        if state.shows_fail {
            return Err(WindowError::Os {
                context: "show the window",
                message: "the test failed this show".into(),
            });
        }
        if !state.visible.contains(&handle) {
            state.visible.push(handle);
        }
        Ok(())
    }

    async fn keep_hidden(&self, handle: NativeHandle, on: bool) -> Result<()> {
        let state = self.record(Call::KeepHidden { handle, on });
        if on && state.keeps_fail {
            return Err(WindowError::Os {
                context: "keep agent windows hidden",
                message: "the test failed this keep".into(),
            });
        }
        if on { Self::known(&state, handle) } else { Ok(()) }
    }

    async fn is_visible(&self, handle: NativeHandle) -> Result<bool> {
        let state = self.record(Call::IsVisible(handle));
        Self::known(&state, handle)?;
        Ok(state.visible.contains(&handle))
    }

    async fn snapshot(&self) -> Result<Snapshot> {
        Ok(self.record(Call::Snapshot).snapshot.clone())
    }

    async fn quiet(&self, mode_on: bool, chrome_path: &str, run_key: Option<&str>) -> Result<QuietState> {
        let state = self.record(Call::Quiet {
            mode_on,
            chrome_path: chrome_path.to_owned(),
            run_key: run_key.map(str::to_owned),
        });
        Ok(state.quiet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "PHANTAB-1234";

    #[tokio::test]
    async fn noop_passes_the_engine_flow_through() {
        let w = Noop;
        assert_eq!(w.strategy(), HideStrategy::None);
        let mut guard = w.arm_hide(&WindowSpec::workspace(TOKEN)).await.unwrap();
        assert_eq!(guard.settle().await, None);
        let h = w.find(TOKEN).await.unwrap();
        w.hide(h).await.unwrap();
        w.show(h, true).await.unwrap();
        assert_eq!(w.snapshot().await.unwrap(), Snapshot::default());
        assert_eq!(w.quiet(true, "chrome.exe", None).await.unwrap(), QuietState::default());
        assert!(matches!(w.find("other").await, Err(WindowError::InvalidToken)));
    }

    #[tokio::test]
    async fn recording_records_calls_in_order() {
        let w = Recording::new().with_window(TOKEN, NativeHandle(5));
        let spec = WindowSpec::workspace(TOKEN);
        let mut guard = w.arm_hide(&spec).await.unwrap();
        assert_eq!(guard.settle().await, None);
        let h = w.find(TOKEN).await.unwrap();
        assert_eq!(h, NativeHandle(5));
        w.hide(h).await.unwrap();
        assert!(!w.is_visible(h).await.unwrap());
        w.show(h, true).await.unwrap();
        assert!(w.is_visible(h).await.unwrap());
        w.quiet(false, "c.exe", Some(r"HKCU\Software\x")).await.unwrap();
        assert_eq!(
            w.calls(),
            vec![
                Call::Arm(spec),
                Call::Find(TOKEN.into()),
                Call::Hide(h),
                Call::IsVisible(h),
                Call::Show { handle: h, maximize: true },
                Call::IsVisible(h),
                Call::Quiet {
                    mode_on: false,
                    chrome_path: "c.exe".into(),
                    run_key: Some(r"HKCU\Software\x".into())
                },
            ]
        );
    }

    #[tokio::test]
    async fn recording_answers_what_it_was_given() {
        let w = Recording::new()
            .with_arm_answer(Some(NativeHandle(9)))
            .with_quiet(QuietState { run_value: Some(true), running: Some(false) });
        let mut guard = w.arm_hide(&WindowSpec::workspace(TOKEN)).await.unwrap();
        assert_eq!(guard.settle().await, Some(NativeHandle(9)));
        assert_eq!(guard.settle().await, Some(NativeHandle(9)));
        assert!(!w.is_visible(NativeHandle(9)).await.unwrap());
        assert!(matches!(w.find(TOKEN).await, Err(WindowError::NotExactlyOne { found: 0 })));
        assert!(matches!(w.hide(NativeHandle(1)).await, Err(WindowError::InvalidHandle)));
        assert_eq!(w.strategy(), HideStrategy::OsHook);
        let mac = Recording::new().with_strategy(HideStrategy::ExtensionMinimize);
        assert_eq!(mac.strategy(), HideStrategy::ExtensionMinimize);
        assert!(mac.calls().is_empty(), "strategy is not a call");
        assert_eq!(
            w.quiet(true, "c.exe", None).await.unwrap(),
            QuietState { run_value: Some(true), running: Some(false) }
        );
    }
}
