//! macOS: no OS window work (docs/MAC.md § Recommendation). Agent windows are created minimized by the
//! extension and kept rendering by CDP focus emulation, so there is nothing to arm, find, hide or show here,
//! and no title token. What is left is quiet debugging: phantab's `LaunchAgent` that starts Chrome with the
//! flag at login (docs/MAC.md Q4), the running browser's flag, and the clean quit for a restart with it.
//!
//! Compiled on every OS (it uses only `ps`, `kill` and files, through tokio and std), so its logic is built
//! and linted on Windows too; `platform()` picks it on macOS.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::matching::{
    LAUNCH_AGENT_LABEL, app_bundle, browser_args_lines, is_browser_process, is_our_launch_agent,
    launch_agent_plist, on_user_data_dir, ps_processes, ps_switches, running_state,
};
use crate::{
    ArmGuard, Browser, HideStrategy, NativeHandle, QUIT_WAIT, QuietRequest, QuietState, Quit, Result,
    Snapshot, WindowControl, WindowError, WindowSpec,
};

const PLATFORM: &str = "macOS";
/// macOS ships `ps` here, on the sealed system volume.
const PS: &str = "/bin/ps";
/// And `kill`, which signals the one browser process by pid.
const KILL: &str = "/bin/kill";

/// The macOS window control: strategy [`HideStrategy::ExtensionMinimize`]; window calls are
/// [`WindowError::Unsupported`]; `quiet` writes or removes phantab's `LaunchAgent` and reports the running
/// browser's flag; `quit_browser` asks that one browser to quit.
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

    async fn quiet(&self, request: &QuietRequest) -> Result<QuietState> {
        let browser = &request.browser;
        if browser.chrome_path.is_empty() {
            return Err(WindowError::InvalidArgument(
                "Quiet debugging needs the configured Chrome path".into(),
            ));
        }
        let launch_agent = match launch_agents_dir(request) {
            Some(dir) => Some(set_launch_agent(&dir, request.mode_on, browser)?),
            None => None,
        };
        let text = ps().await?;
        let running = running_state(browsers(&text, browser).into_iter().map(|(_, args)| args));
        Ok(QuietState { running, launch_agent, ..QuietState::default() })
    }

    async fn quit_browser(&self, browser: &Browser) -> Result<Option<Quit>> {
        if browser.chrome_path.is_empty() {
            return Err(WindowError::InvalidArgument(
                "Quitting Chrome needs the configured Chrome path".into(),
            ));
        }
        let deadline = tokio::time::Instant::now() + QUIT_WAIT;
        let text = ps().await?;
        let Some((pid, args)) = only_browser(&text, browser)? else { return Ok(None) };
        let args = args.to_owned();
        // Read again just before the signal: the pid must still be that browser, with those arguments, so a
        // pid reused since the first read is never signalled.
        let again = ps().await?;
        if only_browser(&again, browser)? != Some((pid, args.as_str())) {
            return Err(WindowError::Os {
                context: "quit the browser",
                message: "the browser process changed while phantab read it; nothing was closed".into(),
            });
        }
        // SIGTERM is Chrome's own clean exit on macOS: it closes every window as Quit from the menu does
        // and keeps the session for `--restore-last-session`. By pid, never by process name.
        let pid_arg = pid.to_string();
        if !kill(&["-TERM", &pid_arg]).await? {
            return Ok(None);
        }
        let quit = Quit { pid, args: ps_switches(&args, &browser.chrome_path) };
        while tokio::time::Instant::now() < deadline {
            if !kill(&["-0", &pid_arg]).await? {
                return Ok(Some(quit));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Err(WindowError::Os {
            context: "quit the browser",
            message: format!("Chrome (pid {pid}) was asked to quit but still runs after {QUIT_WAIT:?}"),
        })
    }
}

/// Every process's pid and argv. `ps` rather than sysinfo: one short-lived read with no extra dependency and
/// no unsafe. `-ww` stops it truncating long command lines. By absolute path: a bare `ps` is looked up on
/// the PATH this process inherited, where an earlier folder could hold another one. The C locale: the
/// service passes `LANG` on (for `bw`), and this parse should not depend on the owner's locale.
async fn ps() -> Result<String> {
    let out = tokio::process::Command::new(PS)
        .args(["-axww", "-o", "pid=,args="])
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
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `/bin/kill` with these arguments; `false` when the process is gone (or never was).
async fn kill(args: &[&str]) -> Result<bool> {
    let status = tokio::process::Command::new(KILL)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(|e| WindowError::Os { context: "signal the browser", message: e.to_string() })?;
    Ok(status.success())
}

/// From `ps -o pid=,args=` output, the browser processes (not helpers) started as the configured Chrome on
/// its user-data dir. A Chrome on another dir is another browser.
pub(crate) fn browsers<'a>(ps_output: &'a str, browser: &Browser) -> Vec<(u32, &'a str)> {
    ps_processes(ps_output)
        .into_iter()
        .filter(|(_, args)| {
            !browser_args_lines(args, &browser.chrome_path).is_empty()
                && is_browser_process(args)
                && on_user_data_dir(args, &browser.user_data_dir, browser.default_dir, false)
        })
        .collect()
}

/// The one browser process [`browsers`] finds, `None` for none; more than one is an error, as which to quit
/// would be a guess.
fn only_browser<'a>(ps_output: &'a str, browser: &Browser) -> Result<Option<(u32, &'a str)>> {
    match browsers(ps_output, browser).as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(*one)),
        more => Err(WindowError::Os {
            context: "quit the browser",
            message: format!("{} browser processes run on that user-data dir", more.len()),
        }),
    }
}

/// Where phantab's `LaunchAgent` goes: the request's folder, or `~/Library/LaunchAgents` in a real macOS
/// build. A test build never names the real one.
fn launch_agents_dir(request: &QuietRequest) -> Option<PathBuf> {
    if let Some(dir) = &request.launch_agents_dir {
        return Some(dir.clone());
    }
    if cfg!(all(target_os = "macos", not(feature = "test-seams"))) {
        return std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library").join("LaunchAgents"));
    }
    None
}

fn io_error(context: &'static str) -> impl Fn(std::io::Error) -> WindowError {
    move |e| WindowError::Os { context, message: e.to_string() }
}

/// Writes (`on`) or removes phantab's `LaunchAgent` in `dir`, and says whether it is there now. A file at
/// that path that is not phantab's (no label) is never overwritten or removed.
pub(crate) fn set_launch_agent(dir: &Path, on: bool, browser: &Browser) -> Result<bool> {
    let path = dir.join(format!("{LAUNCH_AGENT_LABEL}.plist"));
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(io_error("read the LaunchAgent")(e)),
    };
    if existing.as_deref().is_some_and(|text| !is_our_launch_agent(text)) {
        return Err(WindowError::InvalidArgument(format!(
            "{} is not phantab's LaunchAgent, so it was left alone",
            path.display()
        )));
    }
    if !on {
        if existing.is_some() {
            std::fs::remove_file(&path).map_err(io_error("remove the LaunchAgent"))?;
        }
        return Ok(false);
    }
    let bundle = app_bundle(&browser.chrome_path).ok_or_else(|| {
        WindowError::InvalidArgument(format!("{} is not inside an .app bundle", browser.chrome_path))
    })?;
    let dir_arg =
        (!browser.default_dir && !browser.user_data_dir.is_empty()).then_some(&*browser.user_data_dir);
    let text = launch_agent_plist(bundle, dir_arg);
    if existing.as_deref() == Some(text.as_str()) {
        return Ok(true);
    }
    std::fs::create_dir_all(dir).map_err(io_error("make the LaunchAgents folder"))?;
    // Written beside it and renamed over, so launchd never reads half a file.
    let partial = dir.join(format!(".{LAUNCH_AGENT_LABEL}.plist.partial"));
    std::fs::write(&partial, text).map_err(io_error("write the LaunchAgent"))?;
    std::fs::rename(&partial, &path).map_err(io_error("write the LaunchAgent"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("phantab-mac-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn window_calls_are_unsupported_and_quiet_needs_a_chrome() {
        let w = MacWindowControl;
        assert_eq!(w.strategy(), HideStrategy::ExtensionMinimize);
        assert!(matches!(w.find("PHANTAB-1").await, Err(WindowError::Unsupported("macOS"))));
        assert!(matches!(
            w.arm_hide(&WindowSpec::workspace("PHANTAB-1")).await,
            Err(WindowError::Unsupported(_))
        ));
        assert!(matches!(w.show(NativeHandle(1), true).await, Err(WindowError::Unsupported(_))));
        assert!(w.quiet(&QuietRequest::default()).await.is_err());
        assert!(w.quit_browser(&Browser::default()).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn quiet_in_a_test_build_writes_no_launch_agent_of_its_own() {
        // No process runs from this path, so nothing is running either, and with no folder named a test
        // build writes nowhere.
        let browser =
            Browser { chrome_path: "/nonexistent/phantab-test/Google Chrome".into(), ..Browser::default() };
        let state = MacWindowControl.quiet(&QuietRequest::new(true, browser.clone())).await.unwrap();
        assert_eq!(state, QuietState::default());
        assert_eq!(MacWindowControl.quit_browser(&browser).await.unwrap(), None);
    }

    #[test]
    fn browsers_are_the_configured_chrome_on_its_own_dir() {
        let helper = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/\
                      Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper --type=renderer";
        let ps = format!(
            "  101 {CHROME}\n  102 {helper}\n  103 {CHROME} --user-data-dir=/Users/a/scratch --no-first-run\n\
             104 /Applications/Other.app/Contents/MacOS/Other\n"
        );
        let default = Browser {
            chrome_path: CHROME.into(),
            user_data_dir: "/Users/a/Chrome".into(),
            default_dir: true,
        };
        assert_eq!(browsers(&ps, &default), vec![(101, CHROME)]);
        let scratch =
            Browser { user_data_dir: "/Users/a/scratch/".into(), default_dir: false, ..default.clone() };
        assert_eq!(browsers(&ps, &scratch).iter().map(|(pid, _)| *pid).collect::<Vec<_>>(), vec![103]);
        let other = Browser { user_data_dir: "/Users/a/elsewhere".into(), default_dir: false, ..default };
        assert!(browsers(&ps, &other).is_empty(), "another dir's Chrome is another browser");
    }

    #[test]
    fn the_launch_agent_round_trips_and_leaves_a_stranger_alone() {
        let dir = scratch("agent");
        let browser = Browser {
            chrome_path: CHROME.into(),
            user_data_dir: "/Users/a/scratch".into(),
            default_dir: false,
        };
        let path = dir.join("dev.phantab.chrome.plist");
        assert!(set_launch_agent(&dir, true, &browser).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("<string>/Applications/Google Chrome.app</string>"), "{text}");
        assert!(text.contains("<string>--user-data-dir=/Users/a/scratch</string>"), "{text}");
        assert!(set_launch_agent(&dir, true, &browser).unwrap(), "again is a no-op");
        assert!(!set_launch_agent(&dir, false, &browser).unwrap());
        assert!(!path.exists());
        assert!(!set_launch_agent(&dir, false, &browser).unwrap(), "off with none there is fine");

        let default = Browser { default_dir: true, ..browser.clone() };
        set_launch_agent(&dir, true, &default).unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("--user-data-dir"));

        std::fs::write(&path, "<plist>someone else's</plist>").unwrap();
        assert!(set_launch_agent(&dir, true, &browser).is_err());
        assert!(set_launch_agent(&dir, false, &browser).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "<plist>someone else's</plist>");

        std::fs::remove_file(&path).unwrap();
        let not_a_bundle = Browser { chrome_path: "/opt/chrome/chrome".into(), ..browser };
        assert!(set_launch_agent(&dir, true, &not_a_bundle).is_err());
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn quiet_writes_the_launch_agent_in_the_folder_it_is_given() {
        let dir = scratch("quiet");
        let browser = Browser { chrome_path: CHROME.into(), default_dir: true, ..Browser::default() };
        let request =
            QuietRequest { launch_agents_dir: Some(dir.clone()), ..QuietRequest::new(true, browser) };
        if cfg!(unix) {
            assert_eq!(MacWindowControl.quiet(&request).await.unwrap().launch_agent, Some(true));
            let off = QuietRequest { mode_on: false, ..request };
            assert_eq!(MacWindowControl.quiet(&off).await.unwrap().launch_agent, Some(false));
        } else {
            // No `/bin/ps` here: the agent is written, then the process list fails.
            assert!(MacWindowControl.quiet(&request).await.is_err());
            assert!(dir.join("dev.phantab.chrome.plist").is_file());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The process list and the signal come from the system's tools, never ones found on the inherited PATH.
    #[cfg(target_os = "macos")]
    #[test]
    fn ps_and_kill_are_the_systems_by_absolute_path() {
        for tool in [PS, KILL] {
            let path = Path::new(tool);
            assert!(path.is_absolute() && path.is_file(), "{tool}");
        }
    }
}
