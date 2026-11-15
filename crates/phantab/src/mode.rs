//! Which mode a process runs in, and the tokio runtime each mode gets.
//!
//! Only the service serves many clients at once, so only it gets worker threads. The other modes
//! each serve one caller and run on the calling thread: a multi-thread runtime would start one
//! idle worker per CPU in every MCP session and every native host (`docs/ARCHITECTURE.md`
//! § Processes and threads). Blocking work still goes to tokio's blocking pool in every mode.

use tokio::runtime::{Builder, Runtime};

/// The service's worker threads. More than one, so a call that keeps a worker busy for a while
/// (parsing a large frame, writing a log, a sign-in scan) never stops the bridge or the other
/// clients' calls; two is enough because the work is waiting on Chrome, not computing.
pub const SERVICE_WORKERS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `install` / `uninstall`: synchronous, no runtime.
    Install,
    /// Chrome started us as the extension's native host.
    Host,
    Mcp,
    Serve,
    Bitwarden,
    /// `phantab vaults status`: the configured sign-in providers (docs/VAULTS.md).
    Vaults,
    /// Any other first argument: one CLI command.
    Cli,
}

impl Mode {
    #[must_use]
    pub fn of(args: &[String]) -> Self {
        match args.first().map(String::as_str) {
            Some("install" | "uninstall") => Self::Install,
            // Chrome starts a native host with the caller's origin first (and, on Windows, a window handle).
            Some(origin) if crate::host::is_host_invocation(origin) => Self::Host,
            Some("mcp") => Self::Mcp,
            Some("serve") => Self::Serve,
            Some("bitwarden") => Self::Bitwarden,
            Some("vaults") => Self::Vaults,
            _ => Self::Cli,
        }
    }

    /// The runtime this mode runs on.
    ///
    /// # Errors
    /// The OS refused a thread or an I/O driver.
    pub fn runtime(self) -> std::io::Result<Runtime> {
        let mut builder = if self == Self::Serve {
            let mut b = Builder::new_multi_thread();
            b.worker_threads(SERVICE_WORKERS);
            b
        } else {
            Builder::new_current_thread()
        };
        builder.enable_all().build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn each_invocation_maps_to_its_mode() {
        assert_eq!(Mode::of(&args(&["install"])), Mode::Install);
        assert_eq!(Mode::of(&args(&["uninstall", "--yes"])), Mode::Install);
        assert_eq!(Mode::of(&args(&["chrome-extension://abc/", "--parent-window=0"])), Mode::Host);
        assert_eq!(Mode::of(&args(&["mcp", "--name", "x"])), Mode::Mcp);
        assert_eq!(Mode::of(&args(&["serve"])), Mode::Serve);
        assert_eq!(Mode::of(&args(&["bitwarden", "status"])), Mode::Bitwarden);
        assert_eq!(Mode::of(&args(&["vaults", "status"])), Mode::Vaults);
        assert_eq!(Mode::of(&args(&["status"])), Mode::Cli);
        assert_eq!(Mode::of(&args(&[])), Mode::Cli);
    }

    /// perf-idle-2: only the service has worker threads; every other mode runs on its own thread.
    #[test]
    fn only_the_service_has_worker_threads() {
        for (mode, workers) in [
            (Mode::Host, 1),
            (Mode::Mcp, 1),
            (Mode::Bitwarden, 1),
            (Mode::Vaults, 1),
            (Mode::Cli, 1),
            (Mode::Serve, SERVICE_WORKERS),
        ] {
            let runtime = mode.runtime().expect("runtime");
            assert_eq!(runtime.metrics().num_workers(), workers, "{mode:?}");
            let flavor = if mode == Mode::Serve {
                tokio::runtime::RuntimeFlavor::MultiThread
            } else {
                tokio::runtime::RuntimeFlavor::CurrentThread
            };
            assert_eq!(runtime.handle().runtime_flavor(), flavor, "{mode:?}");
        }
    }
}
