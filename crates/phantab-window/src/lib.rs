//! phantab-window: OS window control. See docs/ARCHITECTURE.md § Window control.
//!
//! The engine opens each agent page in a real browser window that the OS hides at its first appearance, so
//! it keeps rendering and can later be shown intact. This crate is that OS half: arm a hide before the window
//! exists, find it by the token in its title, show and hide it, and quiet debugging (the Run-key, shortcut
//! and `LaunchAgent` edits, and the clean quit of the browser for a restart with the flag).
// SR-58: every `unsafe` block, here only, says why it is sound; clippy fails the build otherwise.
#![deny(clippy::undocumented_unsafe_blocks)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

pub mod console;
#[cfg(any(windows, unix))]
mod console_keys;
#[cfg(unix)]
mod console_unix;
mod fake;
pub mod file_identity;
#[cfg(windows)]
mod file_win32;
mod mac;
mod matching;
pub mod process;
#[cfg(windows)]
mod quiet_win32;
#[cfg(target_os = "macos")]
mod secret_mac;
pub mod secret_store;
#[cfg(windows)]
mod secret_win32;
pub mod secure_dir;
#[cfg(unix)]
mod secure_unix;
#[cfg(windows)]
mod secure_win32;
pub mod streams;
#[cfg(target_os = "macos")]
mod streams_mac;
#[cfg(unix)]
mod streams_unix;
#[cfg(windows)]
mod streams_win32;
mod unsupported;
#[cfg(windows)]
mod win32;
#[cfg(all(windows, feature = "test-seams"))]
pub use win32::seams;

pub use fake::{Call, Noop, Recording};
pub use mac::MacWindowControl;
pub use matching::{
    LAUNCH_AGENT_LABEL, QUIET_FLAG, ScreenRect, app_bundle, browser_args_lines, check_token, expand_env,
    is_browser_process, is_our_launch_agent, launch_agent_plist, on_user_data_dir, ps_processes, ps_switches,
    rect_matches, rewrite_run_value, rewrite_shortcut_args, running_state, user_data_dir_of, windows_args,
};
pub use unsupported::Unsupported;

/// Every window token starts with this; `arm_hide` and `find` refuse anything else.
pub const TOKEN_PREFIX: &str = "PHANTAB-";
/// How long an armed hook waits for its window and the token: it must outlast the
/// engine's 10 s wait for the page title.
pub const ARM_TIMEOUT: Duration = Duration::from_secs(15);
/// The HKCU key `quiet` edits when the caller names none.
pub const DEFAULT_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// Where the new window will appear, in DIPs (the units `chrome.windows.create` takes), and the token its
/// page title will carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSpec {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
    pub token: String,
}

impl WindowSpec {
    /// The engine's workspace rect: a size the agent's fixed pages fit.
    pub fn workspace(token: impl Into<String>) -> Self {
        Self { left: 20, top: 20, width: 1287, height: 903, token: token.into() }
    }
}

/// How agent windows are kept out of the owner's sight on this platform. The engine branches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HideStrategy {
    /// Windows: the OS hides the window at its first SHOW (`arm_hide`), then `find`/`hide`/`show` by handle.
    OsHook,
    /// macOS (docs/MAC.md): the extension creates the window minimized and shows it by restoring it; CDP
    /// focus emulation keeps it rendering. This crate does no window work: arm/find/hide/show are
    /// [`WindowError::Unsupported`].
    ExtensionMinimize,
    /// No window to hide (headless lanes, [`Noop`]).
    None,
}

/// An OS window handle (an `HWND` on Windows), carried as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NativeHandle(pub i64);

/// The foreground window and every visible chrome.exe top-level window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub foreground: Option<NativeHandle>,
    pub chrome_windows: Vec<NativeHandle>,
}

/// What `quiet` found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QuietState {
    /// Windows: the mode now written to the browser's Run entry, `None` when no entry starts with the
    /// Chrome path. Always `None` on macOS.
    pub run_value: Option<bool>,
    /// Whether the running browser (the one on the configured user-data dir) has the flag, `None` when
    /// none runs.
    pub running: Option<bool>,
    /// Windows: this user's own shortcuts that start the browser, now in the asked mode.
    pub shortcuts: usize,
    /// Windows: how many of those this call rewrote; the rest were in the asked mode already.
    pub changed: usize,
    /// Windows: this user's shortcuts that start the browser but could not be rewritten (read-only, say),
    /// by path. They still start Chrome as they did.
    pub unwritable: Vec<String>,
    /// Windows: all users' shortcuts (the `ProgramData` Start menu, the Public Desktop) that start the
    /// browser and are not in the asked mode, by path. Reported, never written: another account's Chrome
    /// starts from them too.
    pub shared_shortcuts: Vec<String>,
    /// Windows: shortcuts on a `OneDrive` Desktop that start the browser and are not in the asked mode, by
    /// path. Reported, never written: a change there syncs to the owner's other PCs.
    pub synced_shortcuts: Vec<String>,
    /// macOS: whether phantab's `LaunchAgent` is in place now. `None` on Windows.
    pub launch_agent: Option<bool>,
}

/// The browser `quiet` and `quit_browser` act on: the configured Chrome, on the configured user-data dir.
/// Chrome processes on any other user-data dir are another browser and are never counted or touched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Browser {
    /// The configured Chrome executable.
    pub chrome_path: String,
    /// The configured user-data dir (empty when not known).
    pub user_data_dir: String,
    /// `user_data_dir` is Chrome's default, so a browser started with no `--user-data-dir` is on it.
    pub default_dir: bool,
}

/// A folder whose `.lnk` shortcuts `quiet` rewrites or reports (Windows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortcutDir {
    pub path: std::path::PathBuf,
    /// Into its subfolders too (the Start menu's), or only the folder itself (a Desktop).
    pub recurse: bool,
    pub kind: ShortcutKind,
}

impl ShortcutDir {
    /// One of this user's own folders, whose shortcuts `quiet` rewrites.
    #[must_use]
    pub fn own(path: impl Into<std::path::PathBuf>, recurse: bool) -> Self {
        Self { path: path.into(), recurse, kind: ShortcutKind::Own }
    }
}

/// Whose a shortcut folder is, which decides whether `quiet` may write its shortcuts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ShortcutKind {
    /// This user's own: rewritten.
    #[default]
    Own,
    /// All users' (the `ProgramData` Start menu, the Public Desktop): another account's Chrome starts from
    /// it too, so it is only reported ([`QuietState::shared_shortcuts`]).
    Shared,
    /// Under `OneDrive`: a change there syncs to the owner's other PCs, so it is only reported
    /// ([`QuietState::synced_shortcuts`]).
    Synced,
}

/// The browser `quit_browser` closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Quit {
    pub pid: u32,
    /// Its arguments after the program, as its command line gave them, so a restart keeps the owner's own
    /// switches (`--proxy-server=…`, say). On macOS `ps` joins argv without quoting, so an argument starts at
    /// each ` -` ([`ps_switches`]).
    pub args: Vec<String>,
}

/// What `quiet` is asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuietRequest {
    /// Add the flag (`true`) or take it away.
    pub mode_on: bool,
    pub browser: Browser,
    /// Windows: the HKCU key holding Chrome's sign-in entry; `None` is [`DEFAULT_RUN_KEY`].
    pub run_key: Option<String>,
    /// Windows: the folders whose shortcuts are rewritten or reported. `None` is the real ones: this
    /// user's Start menu, Quick Launch (with the pinned taskbar and Start items under it) and Desktop,
    /// rewritten; all users' Start menu and the Public Desktop ([`ShortcutKind::Shared`]) and the `OneDrive`
    /// Desktops ([`ShortcutKind::Synced`]), only reported. A test build never uses the real ones: there
    /// `None` rewrites no shortcut.
    pub shortcut_dirs: Option<Vec<ShortcutDir>>,
    /// macOS: the folder for phantab's `LaunchAgent`. `None` is `~/Library/LaunchAgents`; a test build
    /// never uses that: there `None` writes no `LaunchAgent`.
    pub launch_agents_dir: Option<std::path::PathBuf>,
}

impl QuietRequest {
    #[must_use]
    pub fn new(mode_on: bool, browser: Browser) -> Self {
        Self { mode_on, browser, ..Self::default() }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WindowError {
    #[error("OS window control is not supported on {0}")]
    Unsupported(&'static str),
    #[error("A phantab window token is required")]
    InvalidToken,
    #[error("Expected exactly one owned browser window")]
    NotExactlyOne { found: usize },
    #[error("Browser window is no longer valid")]
    InvalidHandle,
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{context}: {message}")]
    Os { context: &'static str, message: String },
}

pub type Result<T> = std::result::Result<T, WindowError>;

/// OS window control. Every implementation is cheap to share (`Arc<dyn WindowControl>`).
#[async_trait::async_trait]
pub trait WindowControl: Send + Sync + std::fmt::Debug {
    /// Which hiding path the engine takes with this implementation.
    fn strategy(&self) -> HideStrategy;

    /// Arms a hide for the next window that appears at `spec`'s rect, and returns once the hook is
    /// listening, so the caller creates the window only after this. See [`ArmGuard`].
    async fn arm_hide(&self, spec: &WindowSpec) -> Result<ArmGuard> {
        self.arm_hide_within(spec, ARM_TIMEOUT).await
    }

    /// `arm_hide` with an explicit wait for the window and its token.
    async fn arm_hide_within(&self, spec: &WindowSpec, timeout: Duration) -> Result<ArmGuard>;

    /// The one top-level window whose title contains `token`, hidden or not.
    async fn find(&self, token: &str) -> Result<NativeHandle>;

    /// Hides the window. It must still be a chrome window.
    async fn hide(&self, handle: NativeHandle) -> Result<()>;

    /// Shows the window maximized or restored, and brings it to the front. It must still be a chrome window.
    async fn show(&self, handle: NativeHandle, maximize: bool) -> Result<()>;

    /// While `on`, keeps the window hidden: anything that shows it again is undone at once, and a destroyed
    /// window is forgotten. Chrome shows a browser window whenever a page in it opens a popup or a tab
    /// (`window.open`), which would otherwise leave a hidden agent window on the owner's screen. `on` needs a
    /// live chrome window; `false` never fails. The default does nothing, for strategies without a handle.
    async fn keep_hidden(&self, _handle: NativeHandle, _on: bool) -> Result<()> {
        Ok(())
    }

    /// Whether the window is visible now (`IsWindowVisible`).
    async fn is_visible(&self, handle: NativeHandle) -> Result<bool>;

    async fn snapshot(&self) -> Result<Snapshot>;

    /// Windows: adds (`mode_on`) or removes [`QUIET_FLAG`] on each Run entry and each of this user's own
    /// shortcuts that starts the browser at `chrome_path`, touching no other argument and nothing else,
    /// reports the all users' and `OneDrive` ones it leaves alone, and reports whether the running browser
    /// has it. The Run key must be under HKCU.
    ///
    /// macOS: writes (`mode_on`) or removes phantab's own `LaunchAgent`, which starts Chrome with the flag
    /// at login (docs/MAC.md Q4), and reports the running browser as above. Never a file it did not write.
    async fn quiet(&self, request: &QuietRequest) -> Result<QuietState>;

    /// Quits the running browser on `browser`'s user-data dir the way a system restart does, so Chrome
    /// saves the whole session as it closes, and waits for it to exit, all within [`QUIT_WAIT`]. `Ok(None)`
    /// when none runs. It acts on that one process, found by its path and user-data dir, never on a process
    /// name. The default refuses: only Windows and macOS have one.
    async fn quit_browser(&self, _browser: &Browser) -> Result<Option<Quit>> {
        Err(WindowError::Unsupported(std::env::consts::OS))
    }
}

/// How long `quit_browser` takes at most, from its ask to Chrome's exit: Chrome saves its session and exits.
pub const QUIT_WAIT: Duration = Duration::from_secs(45);

/// Stops this process's stdin, stdout and stderr from being inherited by the children it starts later
/// (Windows; a no-op elsewhere, where Rust's `Command` never leaks them). Call it first in `main`.
pub fn disable_std_handle_inheritance() {
    #[cfg(windows)]
    win32::disable_std_handle_inheritance();
}

/// Windows: from here on a DLL this process loads by name at run time (a library a dependency or the OS
/// pulls in late) comes from System32 only, never from the binary's folder, the working folder or
/// `PATH`, where a planted copy would run as phantab. DLLs in the import table are loaded before `main`
/// and are not covered: they are system DLLs, but four are not in the `KnownDLLs` list and are found in
/// the binary's folder first. The DLLs those four delay-load come later, so from System32
/// (THREAT-MODEL SR-58). Call it first in `main`.
/// A refusal (Windows older than 8 without KB2533623) leaves the usual order. A no-op elsewhere.
pub fn restrict_dll_search() {
    #[cfg(windows)]
    let _ = win32::restrict_dll_search();
}

/// Sets (`true`) or clears `HANDLE_FLAG_INHERIT` on `handle` (Windows). phantab-cdp marks Chrome's two
/// debugging-pipe ends inheritable for the one spawn that hands them over (THREAT-MODEL R13); std has no
/// safe call for it.
#[cfg(windows)]
pub fn set_handle_inheritable(
    handle: std::os::windows::io::BorrowedHandle<'_>,
    inheritable: bool,
) -> std::io::Result<()> {
    win32::set_handle_inheritable(handle, inheritable)
}

/// The platform's window control: Win32 on Windows, [`MacWindowControl`] on macOS (docs/MAC.md), and
/// [`Unsupported`] elsewhere.
pub fn platform() -> Arc<dyn WindowControl> {
    #[cfg(windows)]
    {
        Arc::new(win32::Win32)
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacWindowControl)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Arc::new(Unsupported::new(std::env::consts::OS))
    }
}

/// An armed hide. [`settle`](Self::settle), called once the page title shows the window exists, gives the
/// confirmed handle, or `None` when the hook caught nothing (the caller then finds and hides it by title).
/// `None` only means the slower path, never an error.
///
/// Settling twice returns the first answer. Dropping the guard unsettled stops the hook; a window it hid
/// but never confirmed is shown again, without activation.
#[derive(Debug)]
pub struct ArmGuard {
    state: GuardState,
}

#[derive(Debug)]
enum GuardState {
    Settled(Option<NativeHandle>),
    #[cfg_attr(not(windows), allow(dead_code, reason = "only the Win32 hook arms a pending guard"))]
    Pending(ArmLink),
}

impl ArmGuard {
    /// A guard whose answer is already known (fakes, and platforms with nothing to arm).
    pub fn settled(handle: Option<NativeHandle>) -> Self {
        Self { state: GuardState::Settled(handle) }
    }

    #[cfg_attr(not(windows), allow(dead_code, reason = "only the Win32 hook arms a pending guard"))]
    pub(crate) fn pending(link: ArmLink) -> Self {
        Self { state: GuardState::Pending(link) }
    }

    /// Whether the hook has hidden a window at the rect (not yet confirmed by its title).
    pub fn caught(&self) -> bool {
        match &self.state {
            GuardState::Settled(handle) => handle.is_some(),
            GuardState::Pending(link) => link.flags.caught.load(Ordering::Acquire),
        }
    }

    /// The confirmed handle, or `None`. When nothing was caught it returns at once, stopping the hook; when
    /// a window was hidden it waits for the token in its title, up to the arm timeout. Cancel-safe.
    pub async fn settle(&mut self) -> Option<NativeHandle> {
        let value = match &mut self.state {
            GuardState::Settled(handle) => return *handle,
            GuardState::Pending(link) => {
                if !link.flags.caught.load(Ordering::Acquire) {
                    link.stop();
                }
                // A closed channel means the hook thread is gone: nothing confirmed.
                (&mut link.result).await.unwrap_or(None)
            }
        };
        self.state = GuardState::Settled(value);
        value
    }
}

/// Flags shared between a guard and the thread that runs its hook.
#[derive(Debug, Default)]
pub(crate) struct ArmFlags {
    pub(crate) caught: AtomicBool,
    pub(crate) stop: AtomicBool,
}

/// The guard's end of a running hook.
pub(crate) struct ArmLink {
    pub(crate) flags: Arc<ArmFlags>,
    pub(crate) result: oneshot::Receiver<Option<NativeHandle>>,
    /// Wakes the hook thread so it sees `stop` without waiting out its sleep.
    pub(crate) wake: Box<dyn Fn() + Send + Sync>,
}

impl ArmLink {
    fn stop(&self) {
        self.flags.stop.store(true, Ordering::Release);
        (self.wake)();
    }
}

impl Drop for ArmLink {
    fn drop(&mut self) {
        self.stop();
    }
}

impl std::fmt::Debug for ArmLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArmLink").field("flags", &self.flags).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SR-58: the OS takes the System32-only search order (every Windows phantab supports has it), and
    /// this process still starts children and loads system DLLs afterwards.
    #[cfg(windows)]
    #[test]
    fn dll_search_is_restricted_to_system32() {
        win32::restrict_dll_search().unwrap();
        let system32 = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
        let status = std::process::Command::new(system32.join("cmd.exe"))
            .args(["/C", "exit", "0"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[tokio::test]
    async fn settle_twice_returns_the_first_answer() {
        let mut guard = ArmGuard::settled(Some(NativeHandle(7)));
        assert_eq!(guard.settle().await, Some(NativeHandle(7)));
        assert_eq!(guard.settle().await, Some(NativeHandle(7)));
    }

    #[tokio::test]
    async fn uncaught_settle_stops_the_hook_and_drop_is_safe() {
        let flags = Arc::new(ArmFlags::default());
        let (tx, rx) = oneshot::channel();
        let seen = Arc::clone(&flags);
        // Stands in for the hook thread: answers once it is told to stop.
        let thread = std::thread::spawn(move || {
            while !seen.stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            let _ = tx.send(None);
        });
        let mut guard =
            ArmGuard::pending(ArmLink { flags: Arc::clone(&flags), result: rx, wake: Box::new(|| {}) });
        assert!(!guard.caught());
        assert_eq!(guard.settle().await, None);
        assert_eq!(guard.settle().await, None);
        drop(guard);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn caught_settle_waits_for_the_confirmation() {
        let flags = Arc::new(ArmFlags::default());
        flags.caught.store(true, Ordering::Release);
        let (tx, rx) = oneshot::channel();
        let mut guard =
            ArmGuard::pending(ArmLink { flags: Arc::clone(&flags), result: rx, wake: Box::new(|| {}) });
        assert!(guard.caught());
        tx.send(Some(NativeHandle(42))).unwrap();
        assert_eq!(guard.settle().await, Some(NativeHandle(42)));
        assert_eq!(guard.settle().await, Some(NativeHandle(42)));
    }

    #[test]
    fn dropping_an_unsettled_guard_stops_the_hook() {
        let flags = Arc::new(ArmFlags::default());
        let (_tx, rx) = oneshot::channel();
        drop(ArmGuard::pending(ArmLink { flags: Arc::clone(&flags), result: rx, wake: Box::new(|| {}) }));
        assert!(flags.stop.load(Ordering::Acquire));
    }

    #[test]
    fn serde_shapes_are_the_wire_shapes() {
        let snap = Snapshot { foreground: Some(NativeHandle(1)), chrome_windows: vec![NativeHandle(2)] };
        assert_eq!(serde_json::to_string(&snap).unwrap(), r#"{"foreground":1,"chromeWindows":[2]}"#);
        let quiet = QuietState { run_value: Some(true), shortcuts: 2, ..QuietState::default() };
        assert_eq!(
            serde_json::to_string(&quiet).unwrap(),
            r#"{"runValue":true,"running":null,"shortcuts":2,"changed":0,"unwritable":[],"sharedShortcuts":[],"syncedShortcuts":[],"launchAgent":null}"#
        );
        let old: QuietState = serde_json::from_str(r#"{"runValue":true,"running":false}"#).unwrap();
        assert_eq!(old, QuietState { run_value: Some(true), running: Some(false), ..QuietState::default() });
    }
}
