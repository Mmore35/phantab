//! macOS: no OS window work (docs/MAC.md § Recommendation). Agent windows are created minimized by the
//! extension and kept rendering by CDP focus emulation, so there is nothing to arm, find, hide or show here,
//! and no title token. What is left is the read-only half of `quiet`.
//!
//! Compiled on every OS (it uses only `ps` through tokio), so its logic is built and linted on Windows too;
//! `platform()` picks it on macOS.

use std::time::Duration;

use crate::matching::{browser_args_lines, running_state};
use crate::{
    ArmGuard, HideStrategy, NativeHandle, QuietState, Result, Snapshot, WindowControl, WindowError,
    WindowSpec,
};

const PLATFORM: &str = "macOS";
/// macOS ships `ps` here, on the sealed system volume.
const PS: &str = "/bin/ps";

/// The macOS window control: strategy [`HideStrategy::ExtensionMinimize`]; window calls are
/// [`WindowError::Unsupported`]; `quiet` reports the running browser's flag and writes nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacWindowControl;

#[async_trait::async_trait]
impl WindowControl for MacWindowControl {
    fn strategy(&self) -> HideStrategy {
        HideStrategy::ExtensionMinimize
    }
    async fn arm_hide_within(&self, _spec: &WindowSpec, _timeout: Duration) -> Result<ArmGuard> {
        Err(WindowError::Unsupported(PLATFORM))
    }
    async fn find(&self, _token: &str) -> Result<NativeHandle> {
        Err(WindowError::Unsupported(PLATFORM))
    }
    async fn hide(&self, _handle: NativeHandle) -> Result<()> {
        Err(WindowError::Unsupported(PLATFORM))
    }
    async fn show(&self, _handle: NativeHandle, _maximize: bool) -> Result<()> {
        Err(WindowError::Unsupported(PLATFORM))
    }
    async fn is_visible(&self, _handle: NativeHandle) -> Result<bool> {
        Err(WindowError::Unsupported(PLATFORM))
    }
    async fn snapshot(&self) -> Result<Snapshot> {
        Err(WindowError::Unsupported(PLATFORM))
    }

    async fn quiet(&self, _mode_on: bool, chrome_path: &str, _run_key: Option<&str>) -> Result<QuietState> {
        if chrome_path.is_empty() {
            return Err(WindowError::InvalidArgument(
                "Quiet debugging needs the configured Chrome path".into(),
            ));
        }
        // `ps` rather than sysinfo: one short-lived read of every process's argv, with no extra dependency
        // and no unsafe. `-ww` stops it truncating long command lines. By absolute path: a bare `ps` is
        // looked up on the PATH this process inherited, where an earlier folder could hold another one.
        // The C locale: the service now passes `LANG` on (for `bw`), and this parse should not depend on
        // the owner's locale.
        let out = tokio::process::Command::new(PS)
            .args(["-axww", "-o", "args="])
            .env("LC_ALL", "C")
            .output()
            .await
            .map_err(|e| WindowError::Os { context: "list processes", message: e.to_string() })?;
        if !out.status.success() {
            return Err(WindowError::Os {
                context: "list processes",
                message: format!("ps exited with {}", out.status),
            });
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(QuietState { run_value: None, running: running_state(browser_args_lines(&text, chrome_path)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn window_calls_are_unsupported_and_quiet_writes_nothing() {
        let w = MacWindowControl;
        assert_eq!(w.strategy(), HideStrategy::ExtensionMinimize);
        assert!(matches!(w.find("PHANTAB-1").await, Err(WindowError::Unsupported("macOS"))));
        assert!(matches!(
            w.arm_hide(&WindowSpec::workspace("PHANTAB-1")).await,
            Err(WindowError::Unsupported(_))
        ));
        assert!(matches!(w.show(NativeHandle(1), true).await, Err(WindowError::Unsupported(_))));
        assert!(w.quiet(true, "", None).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn quiet_reports_no_run_value() {
        // No process runs from this path, so nothing is running either.
        let state =
            MacWindowControl.quiet(true, "/nonexistent/phantab-test/Google Chrome", None).await.unwrap();
        assert_eq!(state, QuietState { run_value: None, running: None });
    }

    /// The process list comes from the system's `ps`, never one found on the inherited PATH.
    #[cfg(target_os = "macos")]
    #[test]
    fn ps_is_the_systems_by_absolute_path() {
        let ps = std::path::Path::new(PS);
        assert!(ps.is_absolute() && ps.is_file(), "{PS}");
    }
}
