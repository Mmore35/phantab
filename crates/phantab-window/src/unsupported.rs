//! The placeholder for platforms phantab does not target (neither Windows nor macOS): every call fails,
//! naming the platform, and the strategy is [`HideStrategy::None`].

use std::time::Duration;

use crate::{
    ArmGuard, Browser, HideStrategy, NativeHandle, QuietRequest, QuietState, Quit, Result, Snapshot,
    WindowControl, WindowError, WindowSpec,
};

/// Fails every call with [`WindowError::Unsupported`], naming the platform.
#[derive(Debug, Clone, Copy)]
pub struct Unsupported {
    platform: &'static str,
}

impl Unsupported {
    pub fn new(platform: &'static str) -> Self {
        Self { platform }
    }

    fn fail<T>(self) -> Result<T> {
        Err(WindowError::Unsupported(self.platform))
    }
}

#[async_trait::async_trait]
impl WindowControl for Unsupported {
    fn strategy(&self) -> HideStrategy {
        HideStrategy::None
    }
    async fn arm_hide_within(&self, _spec: &WindowSpec, _timeout: Duration) -> Result<ArmGuard> {
        self.fail()
    }
    async fn find(&self, _token: &str) -> Result<NativeHandle> {
        self.fail()
    }
    async fn hide(&self, _handle: NativeHandle) -> Result<()> {
        self.fail()
    }
    async fn show(&self, _handle: NativeHandle, _maximize: bool) -> Result<()> {
        self.fail()
    }
    async fn is_visible(&self, _handle: NativeHandle) -> Result<bool> {
        self.fail()
    }
    async fn snapshot(&self) -> Result<Snapshot> {
        self.fail()
    }
    async fn quiet(&self, _request: &QuietRequest) -> Result<QuietState> {
        self.fail()
    }
    async fn quit_browser(&self, _browser: &Browser) -> Result<Option<Quit>> {
        self.fail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_call_names_the_platform() {
        let w = Unsupported::new("linux");
        assert_eq!(w.strategy(), HideStrategy::None);
        let err = w.find("PHANTAB-1").await.unwrap_err();
        assert!(matches!(err, WindowError::Unsupported("linux")));
        assert_eq!(err.to_string(), "OS window control is not supported on linux");
        assert!(w.arm_hide(&WindowSpec::workspace("PHANTAB-1")).await.is_err());
        assert!(w.quiet(&QuietRequest::default()).await.is_err());
        assert!(w.quit_browser(&Browser::default()).await.is_err());
    }
}
