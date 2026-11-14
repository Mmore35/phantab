//! Windows: a direct port of `windows.ps1`, calling Win32 instead of starting PowerShell per operation.
//!
//! Handles cross this module as `isize` (an `HWND`'s value), never as a pointer: an `HWND` is an opaque
//! number owned by the window manager, so a stale one is only an invalid window, never a dangling access.
#![allow(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, HANDLE, HWND, LPARAM, RECT, UNICODE_STRING, WAIT_OBJECT_0, WPARAM,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentThreadId, INFINITE, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
};
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent};
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForWindow, SetThreadDpiAwarenessContext,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CHILDID_SELF, DispatchMessageW, EVENT_OBJECT_DESTROY, EVENT_OBJECT_SHOW, EnumWindows, GA_ROOT,
    GetAncestor, GetForegroundWindow, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId, IsWindow,
    IsWindowVisible, MSG, MWMO_INPUTAVAILABLE, MsgWaitForMultipleObjects, MsgWaitForMultipleObjectsEx,
    OBJID_WINDOW, PM_NOREMOVE, PM_REMOVE, PeekMessageW, PostThreadMessageW, QS_ALLINPUT, SW_HIDE,
    SW_MAXIMIZE, SW_RESTORE, SW_SHOWNOACTIVATE, SetForegroundWindow, ShowWindow, WINEVENT_OUTOFCONTEXT,
    WM_APP, WM_NULL, WM_QUIT,
};
use windows::core::{BOOL, PWSTR};
use windows_registry::{CURRENT_USER, Type};

use crate::matching::{ScreenRect, check_token, hkcu_subkey, rect_matches, rewrite_run_value, running_state};
use crate::{
    ArmFlags, ArmGuard, ArmLink, DEFAULT_RUN_KEY, HideStrategy, NativeHandle, QuietState, Result, Snapshot,
    WindowControl, WindowError, WindowSpec,
};

const CHROME_EXE: &str = "chrome.exe";

/// The Win32 implementation. Stateless: every armed hook owns its own thread.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Win32;

#[async_trait::async_trait]
impl WindowControl for Win32 {
    fn strategy(&self) -> HideStrategy {
        HideStrategy::OsHook
    }
    async fn arm_hide_within(&self, spec: &WindowSpec, timeout: Duration) -> Result<ArmGuard> {
        check_token(&spec.token)?;
        let flags = Arc::new(ArmFlags::default());
        let (ready_tx, ready_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        let thread_flags = Arc::clone(&flags);
        let spec = spec.clone();
        std::thread::Builder::new()
            .name("phantab-arm-hide".into())
            .spawn(move || run_hook(spec, timeout, &thread_flags, ready_tx, result_tx))
            .map_err(|e| WindowError::Os { context: "start the arm thread", message: e.to_string() })?;
        let thread_id = ready_rx.await.map_err(|_| WindowError::Os {
            context: "arm the window hook",
            message: "the hook thread ended before it was listening".into(),
        })??;
        let wake = Box::new(move || {
            // SAFETY: posting WM_NULL carries no pointers; a thread that already ended makes this fail
            // harmlessly, which is ignored because the thread then needs no waking.
            let _ = unsafe { PostThreadMessageW(thread_id, WM_NULL, WPARAM(0), LPARAM(0)) };
        });
        Ok(ArmGuard::pending(ArmLink { flags, result: result_rx, wake }))
    }

    async fn find(&self, token: &str) -> Result<NativeHandle> {
        check_token(token)?;
        let found: Vec<isize> =
            top_level_windows().into_iter().filter(|&h| window_title(h).contains(token)).collect();
        match found.as_slice() {
            [one] => Ok(NativeHandle(handle_value(*one))),
            _ => Err(WindowError::NotExactlyOne { found: found.len() }),
        }
    }

    async fn hide(&self, handle: NativeHandle) -> Result<()> {
        off_workers("hide the window", move || {
            let h = chrome_window(handle)?;
            // SAFETY: `h` was just validated as a live top-level window; ShowWindow takes it by value.
            let _ = unsafe { ShowWindow(hwnd(h), SW_HIDE) };
            Ok(())
        })
        .await
    }

    async fn show(&self, handle: NativeHandle, maximize: bool) -> Result<()> {
        off_workers("show the window", move || {
            let h = chrome_window(handle)?;
            let cmd = if maximize { SW_MAXIMIZE } else { SW_RESTORE };
            // SAFETY: `h` was just validated as a live top-level window; both calls take it by value. Their
            // return values are previous state and foreground-lock refusals, neither of which matters here.
            unsafe {
                let _ = ShowWindow(hwnd(h), cmd);
                let _ = SetForegroundWindow(hwnd(h));
            }
            Ok(())
        })
        .await
    }

    async fn keep_hidden(&self, handle: NativeHandle, on: bool) -> Result<()> {
        if !on {
            let h = handle_isize(handle)?;
            // The caller shows the window next. A keeper hide of it already under way finishes first, so it
            // cannot land after that show; off the workers, as the hide waits on the window's own thread.
            if forget(h) {
                let _ = off_workers("let the window go", move || {
                    wait_hidden(h);
                    Ok(())
                })
                .await;
            }
            return Ok(());
        }
        let h = chrome_window(handle)?;
        keep(h, window_pid(h)).await
    }

    async fn is_visible(&self, handle: NativeHandle) -> Result<bool> {
        let h = live_window(handle)?;
        // SAFETY: by-value handle query, no memory is passed.
        Ok(unsafe { IsWindowVisible(hwnd(h)) }.as_bool())
    }

    async fn snapshot(&self) -> Result<Snapshot> {
        let chrome = chrome_pids()?;
        // SAFETY: no arguments; returns a handle value or null.
        let foreground = unsafe { GetForegroundWindow() }.0 as isize;
        let chrome_windows = top_level_windows()
            .into_iter()
            // SAFETY: by-value handle query on a handle EnumWindows just gave.
            .filter(|&h| unsafe { IsWindowVisible(hwnd(h)) }.as_bool() && chrome.contains(&window_pid(h)))
            .map(|h| NativeHandle(handle_value(h)))
            .collect();
        Ok(Snapshot {
            foreground: (foreground != 0).then(|| NativeHandle(handle_value(foreground))),
            chrome_windows,
        })
    }

    async fn quiet(&self, mode_on: bool, chrome_path: &str, run_key: Option<&str>) -> Result<QuietState> {
        let chrome_path = chrome_path.to_owned();
        let run_key = run_key.unwrap_or(DEFAULT_RUN_KEY).to_owned();
        off_workers("quiet debugging", move || quiet(mode_on, &chrome_path, &run_key)).await
    }
}

/// Runs `call` on tokio's blocking pool. A show or hide of another thread's window waits until that thread
/// takes the message, which a hung Chrome never does; on a runtime worker that would stall every other task
/// the worker runs (the service has two). The pool grows a thread per such call instead.
async fn off_workers<T: Send + 'static>(
    context: &'static str,
    call: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|e| WindowError::Os { context, message: e.to_string() })?
}

// ---- arm --------------------------------------------------------------------------------------------------
//
// Started before the window exists, so it is hidden at its first SHOW, one frame after it appears. The title is
// still "Untitled" then, so position and size pick it out, and the token confirms it afterwards. Out-of-context
// WinEvents are delivered on the thread that set the hook, while it pumps messages, so the callback's state is
// thread-local to that thread. One hook per thread; the engine arms one at a time.

thread_local! {
    static ARM_SPEC: RefCell<Option<WindowSpec>> = const { RefCell::new(None) };
    /// The window the hook hid, 0 for none. Set before ShowWindow: hiding another process's window can
    /// dispatch further events into this callback re-entrantly, and they must see it already taken.
    static ARM_HIDDEN: Cell<isize> = const { Cell::new(0) };
}

fn run_hook(
    spec: WindowSpec,
    timeout: Duration,
    flags: &ArmFlags,
    ready: oneshot::Sender<Result<u32>>,
    result: oneshot::Sender<Option<NativeHandle>>,
) {
    // SAFETY: changes only this thread's DPI awareness, so GetWindowRect in the callback reports physical
    // pixels on every monitor; the previous context it returns is not needed on a thread of our own.
    let _ = unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    let mut msg = MSG::default();
    // SAFETY: `msg` is a valid, writable MSG for the call. A peek creates this thread's message queue, so the
    // guard's wake (PostThreadMessage) cannot fail for want of one.
    let _ = unsafe { PeekMessageW(&raw mut msg, None, 0, 0, PM_NOREMOVE) };
    let token = spec.token.clone();
    ARM_SPEC.with_borrow_mut(|s| *s = Some(spec));
    ARM_HIDDEN.set(0);
    // SAFETY: `on_show` matches WINEVENTPROC and lives for the program; no module handle is needed for an
    // out-of-context hook. The hook is removed below on every path that installed it.
    let hook = unsafe {
        SetWinEventHook(
            EVENT_OBJECT_SHOW,
            EVENT_OBJECT_SHOW,
            None,
            Some(on_show),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };
    if hook.is_invalid() {
        let _ = ready.send(Err(WindowError::Os {
            context: "arm the window hook",
            message: windows::core::Error::from_thread().message(),
        }));
        return;
    }
    // SAFETY: no arguments.
    let thread_id = unsafe { GetCurrentThreadId() };
    let handle = if ready.send(Ok(thread_id)).is_ok() { pump(&token, timeout, flags, &result) } else { None };
    unhook(hook);
    let _ = result.send(handle);
}

fn unhook(hook: HWINEVENTHOOK) {
    // SAFETY: `hook` came from SetWinEventHook on this thread and is removed once.
    let _ = unsafe { UnhookWinEvent(hook) };
}

/// Pumps the hook's events until its window is confirmed by the token, it is told to stop, or the timeout.
fn pump(
    token: &str,
    timeout: Duration,
    flags: &ArmFlags,
    result: &oneshot::Sender<Option<NativeHandle>>,
) -> Option<NativeHandle> {
    let deadline = Instant::now() + timeout;
    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is a valid MSG; DispatchMessage gets back exactly what PeekMessage filled in.
        while unsafe { PeekMessageW(&raw mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
            // SAFETY: `msg` is the MSG PeekMessageW just filled in, passed back unchanged.
            let _ = unsafe { DispatchMessageW(&raw const msg) };
        }
        let hidden = ARM_HIDDEN.get();
        if hidden != 0 {
            flags.caught.store(true, Ordering::Release);
            // SAFETY: by-value handle query.
            if !unsafe { IsWindow(Some(hwnd(hidden))) }.as_bool() {
                return None;
            }
            if window_title(hidden).contains(token) {
                return Some(NativeHandle(handle_value(hidden)));
            }
        }
        let now = Instant::now();
        // A closed result channel means the guard (or the arm call) is gone: nobody will settle.
        if now >= deadline || flags.stop.load(Ordering::Acquire) || result.is_closed() {
            if hidden != 0 {
                // Never left hidden on a guess: not the token's window, so it goes back as it was, unactivated.
                // SAFETY: by-value call on a handle that was a live window a moment ago; a stale one fails.
                let _ = unsafe { ShowWindow(hwnd(hidden), SW_SHOWNOACTIVATE) };
            }
            return None;
        }
        // Waits for the next message (WinEvents and the guard's wake both arrive as one), or until the next title
        // poll once a window is hidden. Capped so `stop` is seen even if a wake were lost.
        let slice = if hidden == 0 {
            (deadline - now).min(Duration::from_millis(50))
        } else {
            Duration::from_millis(2)
        };
        let ms = u32::try_from(slice.as_millis()).unwrap_or(50).max(1);
        // SAFETY: no handles are passed; the call only waits on this thread's queue.
        let _ = unsafe { MsgWaitForMultipleObjects(None, false, ms, QS_ALLINPUT) };
    }
}

/// The `EVENT_OBJECT_SHOW` callback: hides the first chrome top-level window that appears at the armed rect.
unsafe extern "system" fn on_show(
    _hook: HWINEVENTHOOK,
    _event: u32,
    window: HWND,
    id_object: i32,
    id_child: i32,
    _thread: u32,
    _time: u32,
) {
    if ARM_HIDDEN.get() != 0
        || id_object != OBJID_WINDOW.0
        || id_child != CHILDID_SELF.cast_signed()
        || window.is_invalid()
    {
        return;
    }
    let h = window.0 as isize;
    // SAFETY: by-value handle query; a window gone since the event just yields null.
    if unsafe { GetAncestor(window, GA_ROOT) }.0 as isize != h {
        return;
    }
    let mut rect = RECT::default();
    // SAFETY: `rect` is a valid, writable RECT for the call.
    if unsafe { GetWindowRect(window, &raw mut rect) }.is_err() {
        return;
    }
    // SAFETY: by-value handle query; 0 on failure, which then matches nothing.
    let dpi = unsafe { GetDpiForWindow(window) };
    let at = ScreenRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
    let matches = ARM_SPEC.with_borrow(|spec| spec.as_ref().is_some_and(|spec| rect_matches(at, dpi, spec)));
    if !matches || !is_chrome_pid(window_pid(h)) {
        return;
    }
    ARM_HIDDEN.set(h);
    // SAFETY: by-value call on the window the event named.
    let _ = unsafe { ShowWindow(window, SW_HIDE) };
}

// ---- keeping windows hidden --------------------------------------------------------------------------------
//
// Chrome shows a browser window again whenever a page in it opens a popup or a tab (`window.open` ends in
// Navigate's SHOW_WINDOW), which undid an agent window's hide and left it on the owner's screen until the page
// closed. A keeper thread watches SHOW and DESTROY with one hook per process that owns a kept window: a kept
// window is hidden again at its show, and forgotten at its destroy, so a later window given the same handle
// value is never hidden. Windows reports a window's SHOW and DESTROY as events of the process that owns the
// window, whichever process asked for them, so a hook scoped to that process sees every show of it. A hook
// goes when its process has no kept window left, and the thread goes with the last hook, so a session with
// no kept window is never woken by the rest of the desktop.
//
// The keeper also holds each hooked process open (SYNCHRONIZE only) and waits on it with its queue. A process
// that ends, killed or crashed, takes its kept windows and its hook with it at once, whether or not a DESTROY
// came for each window; and while the keeper holds it, Windows gives its id to no other process, so a hook
// is never left over for a new process that reuses the number.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeeperThread {
    Stopped,
    /// Spawned, its id not yet published; its first pass is still to come, so it needs no wake.
    Starting,
    Running(u32),
}

type Settled = oneshot::Sender<std::result::Result<(), String>>;

struct Keeper {
    /// The windows kept hidden, with the process that owns each, as handle values. Few at a time, so a list.
    kept: Vec<(isize, u32)>,
    /// One hook per owning process, as handle values. Only the keeper thread installs and removes them.
    hooked: Vec<(u32, isize)>,
    /// `keep` calls waiting for the hook that watches their window.
    waiting: Vec<(u32, Settled)>,
    thread: KeeperThread,
    /// The keeper thread is changing hooks outside the lock, so `hooked` may be about to change.
    busy: bool,
    /// Kept windows the keeper thread is hiding now, marked under the same lock that found them kept.
    hiding: Vec<isize>,
}

static KEEPER: Mutex<Keeper> = Mutex::new(Keeper {
    kept: Vec::new(),
    hooked: Vec::new(),
    waiting: Vec::new(),
    thread: KeeperThread::Stopped,
    busy: false,
    hiding: Vec::new(),
});

/// Signalled each time a keeper hide ends (`hiding`).
static KEEPER_HID: Condvar = Condvar::new();

/// The keeper thread's wake: bring the hooks in line with the kept windows.
const KEEPER_WAKE: u32 = WM_APP;

/// How long `keep` waits for its hook. The keeper thread hides a kept window with a call that waits for the
/// window's own thread, so a hung Chrome can hold it up; the caller then hears so instead of waiting on it,
/// and the window stays kept for the keeper to hook once it answers. Shorter in tests, which wait it out, but
/// long enough there for a keeper slowed by a loaded machine.
const KEEP_DEADLINE: Duration = if cfg!(test) { Duration::from_secs(2) } else { Duration::from_secs(5) };

/// Processes watched at once: `MsgWaitForMultipleObjectsEx` takes at most 63 handles beside the queue.
const MAX_WATCHED: usize = 63;

fn keeper() -> std::sync::MutexGuard<'static, Keeper> {
    KEEPER.lock().unwrap_or_else(PoisonError::into_inner)
}

fn keep_error(message: String) -> WindowError {
    WindowError::Os { context: "keep agent windows hidden", message }
}

/// Keeps `h`, a window of process `pid`, hidden from now on; returns once the hook that watches it is in place.
async fn keep(h: isize, pid: u32) -> Result<()> {
    // 0 would hook every process on the desktop.
    if pid == 0 {
        return Err(WindowError::InvalidHandle);
    }
    let settled = {
        let mut k = keeper();
        k.kept.retain(|&(w, _)| w != h);
        k.kept.push((h, pid));
        // A hooked process is held open, so it is still the process that owns `h`.
        if !k.busy && k.hooked.iter().any(|&(p, _)| p == pid) {
            return Ok(());
        }
        let (tx, rx) = oneshot::channel();
        k.waiting.push((pid, tx));
        if let Err(message) = wake(&mut k) {
            k.waiting.pop();
            k.kept.retain(|&(w, _)| w != h);
            return Err(keep_error(message));
        }
        rx
    };
    match tokio::time::timeout(KEEP_DEADLINE, settled).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(message))) => Err(keep_error(message)),
        Ok(Err(_)) => Err(keep_error("the keeper thread ended before its hook was in place".into())),
        // Still kept, so the keeper hooks it, and hides it again if shown, once it answers; forgetting it here
        // could also undo another call's keep of the same window. The caller hears why, and hides the window
        // itself either way (the engine's `window.rs`).
        Err(_) => Err(keep_error("the keeper thread did not answer in time".into())),
    }
}

/// Stops keeping `h`. Its process's hook goes once that process has no kept window left. True if the keeper
/// thread is hiding `h` at this moment: it found `h` kept before this, so the hide goes ahead, and a show
/// meant to follow the release waits for it (`wait_hidden`).
fn forget(h: isize) -> bool {
    let mut k = keeper();
    let before = k.kept.len();
    k.kept.retain(|&(w, _)| w != h);
    if k.kept.len() != before {
        // Best effort: a wake that fails leaves the hook until the next keep or forget, never a window shown.
        let _ = wake(&mut k);
    }
    k.hiding.contains(&h)
}

/// Waits until the keeper thread is not hiding `h`, at most `KEEP_DEADLINE`. Past that a hung Chrome holds
/// the hide, and a show of the window, which waits on the same thread, goes ahead as on main. Never on the
/// keeper thread, whose own hide this would wait for.
fn wait_hidden(h: isize) {
    let k = keeper();
    let waited = KEEPER_HID.wait_timeout_while(k, KEEP_DEADLINE, |k| k.hiding.contains(&h));
    drop(waited.unwrap_or_else(PoisonError::into_inner));
}

/// Marks a keeper hide of `h` under way if `h` is still kept (as `pid`'s window, when given), in one lock with
/// the check, so a `forget` either comes first and the hide is skipped, or sees the mark and waits.
fn start_hide(h: isize, pid: Option<u32>) -> bool {
    let mut k = keeper();
    let kept = k.kept.iter().any(|&(w, p)| w == h && pid.is_none_or(|pid| p == pid));
    if kept {
        k.hiding.push(h);
    }
    kept
}

fn end_hide(h: isize) {
    let mut k = keeper();
    if let Some(i) = k.hiding.iter().position(|&w| w == h) {
        k.hiding.swap_remove(i);
    }
    drop(k);
    KEEPER_HID.notify_all();
}

/// Has the keeper thread bring its hooks in line with `kept`, starting it if it has stopped.
fn wake(k: &mut Keeper) -> std::result::Result<(), String> {
    match k.thread {
        KeeperThread::Starting => Ok(()),
        // The thread marks itself stopped under this lock before it ends, so it is still there to read this.
        KeeperThread::Running(id) => {
            // SAFETY: posts a message carrying no pointers to a thread id; a thread without a queue makes it fail.
            unsafe { PostThreadMessageW(id, KEEPER_WAKE, WPARAM(0), LPARAM(0)) }.map_err(|e| e.message())
        }
        KeeperThread::Stopped => {
            std::thread::Builder::new()
                .name("phantab-keep-hidden".into())
                .spawn(run_keeper)
                .map_err(|e| e.to_string())?;
            k.thread = KeeperThread::Starting;
            Ok(())
        }
    }
}

/// A hooked process, held open so the keeper sees it end. Only the keeper thread has these.
type Watched = Vec<(u32, Owned)>;

fn run_keeper() {
    let mut msg = MSG::default();
    // SAFETY: `msg` is a valid, writable MSG for the call. The peek creates this thread's message queue before
    // its id is published, so a wake posted to it cannot fail for want of one.
    let _ = unsafe { PeekMessageW(&raw mut msg, None, 0, 0, PM_NOREMOVE) };
    // SAFETY: no arguments.
    let id = unsafe { GetCurrentThreadId() };
    keeper().thread = KeeperThread::Running(id);
    let mut watched: Watched = Vec::new();
    while reconcile(&mut watched) {
        match next_wake(&watched) {
            Woke::Queue => {
                if !pump_keeper() {
                    abandon(watched, true);
                    return;
                }
            }
            // Its windows go now; the next pass removes its hook, then lets go of the process.
            Woke::Exited(pid) => keeper().kept.retain(|&(_, p)| p != pid),
            // Not restarted: a wait that failed on handles this thread owns would fail again at once.
            Woke::Failed => {
                abandon(watched, false);
                return;
            }
        }
    }
}

enum Woke {
    /// Messages, or the hooks' events, are waiting in the queue.
    Queue,
    /// A hooked process ended.
    Exited(u32),
    Failed,
}

/// Waits, without a timeout, for the queue or for a watched process to end.
fn next_wake(watched: &Watched) -> Woke {
    let handles: Vec<HANDLE> = watched.iter().map(|(_, process)| process.0).collect();
    // SAFETY: `handles` are process handles this thread holds open for the whole call, at most MAX_WATCHED of
    // them (`reconcile` refuses more). MWMO_INPUTAVAILABLE returns at once for input already queued, so no
    // event waits behind one a peek has already seen.
    let woke =
        unsafe { MsgWaitForMultipleObjectsEx(Some(&handles), INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE) };
    #[cfg(test)]
    if tests::wait_fails() {
        return Woke::Failed;
    }
    let index = usize::try_from(woke.0.wrapping_sub(WAIT_OBJECT_0.0)).unwrap_or(usize::MAX);
    match watched.get(index) {
        Some(&(pid, _)) => Woke::Exited(pid),
        None if index == watched.len() => Woke::Queue,
        None => Woke::Failed,
    }
}

/// Dispatches everything queued; the hooks' callbacks run inside these peeks. False at a `WM_QUIT`.
fn pump_keeper() -> bool {
    let mut msg = MSG::default();
    // SAFETY: `msg` is a valid, writable MSG.
    while unsafe { PeekMessageW(&raw mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
        if msg.message == WM_QUIT {
            return false;
        }
        // SAFETY: `msg` is the MSG PeekMessageW just filled in, passed back unchanged.
        let _ = unsafe { DispatchMessageW(&raw const msg) };
    }
    true
}

/// Brings the hooks in line with the kept windows, then settles the waiting calls. False once nothing is kept:
/// no hook is left, and the thread has marked itself stopped, so the next `keep` starts a fresh one.
fn reconcile(watched: &mut Watched) -> bool {
    loop {
        let (add, remove) = {
            let mut k = keeper();
            // A window that went before its process's hook was in place never sent its DESTROY here.
            // SAFETY: by-value handle query.
            k.kept.retain(|&(h, _)| unsafe { IsWindow(Some(hwnd(h))) }.as_bool());
            let mut add: Vec<u32> = Vec::new();
            for &(_, pid) in &k.kept {
                if !add.contains(&pid) && !k.hooked.iter().any(|&(p, _)| p == pid) {
                    add.push(pid);
                }
            }
            let remove: Vec<(u32, isize)> =
                k.hooked.iter().copied().filter(|&(p, _)| !k.kept.iter().any(|&(_, q)| q == p)).collect();
            if add.is_empty() && remove.is_empty() {
                settle(&mut k);
                if k.kept.is_empty() {
                    k.thread = KeeperThread::Stopped;
                    return false;
                }
                return true;
            }
            k.busy = true;
            (add, remove)
        };
        // Unhooked before the process is let go: until then its id cannot name another process.
        for &(pid, hook) in &remove {
            unhook(HWINEVENTHOOK(hook as *mut c_void));
            watched.retain(|&(p, _)| p != pid);
        }
        let mut added: Vec<(u32, std::result::Result<isize, String>)> = Vec::new();
        for &pid in &add {
            let hooked = if watched.len() < MAX_WATCHED {
                hook_process(pid).map(|(hook, process)| {
                    watched.push((pid, process));
                    hook
                })
            } else {
                Err(format!("already watching {MAX_WATCHED} processes"))
            };
            added.push((pid, hooked));
        }
        // A window whose hook failed is hidden if shown before it is let go, while it is still kept (a window
        // no longer kept is skipped), so none is left shown unwatched.
        let failed: Vec<u32> =
            added.iter().filter(|(_, hooked)| hooked.is_err()).map(|&(pid, _)| pid).collect();
        for (h, pid) in kept_of(&failed) {
            hide_if_kept(h, pid);
        }
        let mut k = keeper();
        k.busy = false;
        k.hooked.retain(|entry| !remove.contains(entry));
        let mut hooked_now: Vec<u32> = Vec::new();
        for (pid, hook) in added {
            match hook {
                Ok(hook) => {
                    k.hooked.push((pid, hook));
                    hooked_now.push(pid);
                }
                Err(message) => {
                    // Not kept at all, rather than kept unwatched; hidden above. The calls waiting on this
                    // process hear why now, from this attempt: a later keep for it starts afresh and cannot
                    // answer for them. A window whose call was answered before (a restarted keeper) has no call
                    // left to tell; the engine keeps it again at its next hide.
                    k.kept.retain(|&(_, p)| p != pid);
                    let (failed, rest): (Vec<_>, Vec<_>) =
                        std::mem::take(&mut k.waiting).into_iter().partition(|&(p, _)| p == pid);
                    k.waiting = rest;
                    for (_, settled) in failed {
                        let _ = settled.send(Err(message.clone()));
                    }
                }
            }
        }
        // Answered before the hides below, as on main, where a keep never waited on Chrome: a hide waits on
        // the window's own thread, which a busy Chrome is slow to take. The hook already undoes every later
        // show, and the engine hides a newly kept window itself once its keep answers.
        settle_hooked(&mut k);
        drop(k);
        // A show while a process had no hook raised no event here: a restarted keeper's gap, or the time
        // before a first hook. Its kept windows are hidden again now.
        for (h, pid) in kept_of(&hooked_now) {
            hide_if_kept(h, pid);
        }
        #[cfg(test)]
        tests::between_passes();
    }
}

/// Whether a kept window of `pid` is still `pid`'s.
fn owns_a_kept_window(pid: u32) -> bool {
    keeper().kept.iter().any(|&(h, p)| p == pid && window_pid(h) == pid)
}

/// The kept windows of `pids`.
fn kept_of(pids: &[u32]) -> Vec<(isize, u32)> {
    keeper().kept.iter().copied().filter(|(_, p)| pids.contains(p)).collect()
}

/// Hides `h` if it is shown and still kept as `pid`'s window, as the callback does at a SHOW. Synchronous for
/// the same reason (`on_kept_event`).
fn hide_if_kept(h: isize, pid: u32) {
    #[cfg(test)]
    tests::before_check();
    if !start_hide(h, Some(pid)) {
        return;
    }
    #[cfg(test)]
    tests::after_check();
    // SAFETY: by-value query on a kept window; a window gone since makes it fail.
    if window_pid(h) == pid && unsafe { IsWindowVisible(hwnd(h)) }.as_bool() {
        // SAFETY: by-value call on the same window.
        let _ = unsafe { ShowWindow(hwnd(h), SW_HIDE) };
    }
    end_hide(h);
}

/// Settles the calls waiting on a process that is hooked now.
fn settle_hooked(k: &mut Keeper) {
    let (ready, rest): (Vec<_>, Vec<_>) =
        std::mem::take(&mut k.waiting).into_iter().partition(|&(p, _)| k.hooked.iter().any(|&(q, _)| q == p));
    k.waiting = rest;
    for (_, settled) in ready {
        let _ = settled.send(Ok(()));
    }
}

/// Settles every call still waiting: its window's process is hooked. A window let go meanwhile (closed,
/// shown, or its process ended) settles fine, as nothing is left to keep.
fn settle(k: &mut Keeper) {
    for (_, settled) in std::mem::take(&mut k.waiting) {
        let _ = settled.send(Ok(()));
    }
}

/// The keeper thread is ending early: its hooks and processes go with it. After a `WM_QUIT` (`restart`), a
/// new thread takes over the kept windows and the waiting calls at once, and hides any shown meanwhile;
/// otherwise the kept windows are hidden if shown, the calls hear why, and the next `keep` or `forget`
/// starts a thread.
fn abandon(watched: Watched, restart: bool) {
    let (hooks, unwatched) = {
        let mut k = keeper();
        k.thread = KeeperThread::Stopped;
        let hooks = std::mem::take(&mut k.hooked);
        let restarted = restart && !k.kept.is_empty() && wake(&mut k).is_ok();
        let mut unwatched = Vec::new();
        if !restarted {
            for (_, settled) in std::mem::take(&mut k.waiting) {
                let _ = settled.send(Err("the keeper thread's message queue failed".into()));
            }
            unwatched.clone_from(&k.kept);
        }
        (hooks, unwatched)
    };
    for (h, pid) in unwatched {
        hide_if_kept(h, pid);
    }
    for (_, hook) in hooks {
        unhook(HWINEVENTHOOK(hook as *mut c_void));
    }
    drop(watched);
}

/// Hooks SHOW and DESTROY of the windows `pid` owns, on this (the keeper's) thread, and opens the process so
/// its end is seen.
fn hook_process(pid: u32) -> std::result::Result<(isize, Owned), String> {
    // SAFETY: plain by-value call; the returned handle is owned by `Owned`. SYNCHRONIZE is all a wait needs.
    let process =
        unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.map(Owned).map_err(|e| e.message())?;
    #[cfg(test)]
    tests::before_hook();
    #[cfg(test)]
    if tests::FAIL_NEXT_HOOK.swap(false, Ordering::SeqCst) {
        return Err("the test failed this hook".into());
    }
    // Held open from here, so `pid` names this process until it is let go; checked before the hook, which
    // then goes to no other. The window was matched to `pid` before anything held it: a process that ended
    // and gave its id to another meanwhile owns no kept window, and its successor gets no hook.
    if !owns_a_kept_window(pid) {
        return Err(format!("process {pid} no longer owns the window to keep"));
    }
    // SAFETY: `on_kept_event` matches WINEVENTPROC and lives for the program; no module handle is needed for
    // an out-of-context hook. DESTROY and SHOW are adjacent event ids, so one range covers both. `pid` is never
    // 0 (`keep`), so only that process's events come. `reconcile` removes the hook on this thread once `pid`
    // has no kept window.
    let hook = unsafe {
        SetWinEventHook(
            EVENT_OBJECT_DESTROY,
            EVENT_OBJECT_SHOW,
            None,
            Some(on_kept_event),
            pid,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };
    if hook.is_invalid() {
        Err(windows::core::Error::from_thread().message())
    } else {
        Ok((hook.0 as isize, process))
    }
}

/// The keeper's callback, on the keeper thread. The lock is released before `ShowWindow`, which can dispatch
/// events back into this callback re-entrantly; the hide is marked under way (`start_hide`) meanwhile, so a
/// release of the window waits for it rather than being undone by it.
///
/// The hide is synchronous, as on main, though a hung Chrome then holds the keeper up (`KEEP_DEADLINE`).
/// `ShowWindowAsync` posts it, and a window's thread takes sent messages before posted ones: a show the
/// engine makes right after letting the window go (`ShowWindow` from another thread is sent) could then be
/// undone by a hide posted before it, leaving hidden a window the owner asked to see.
unsafe extern "system" fn on_kept_event(
    _hook: HWINEVENTHOOK,
    event: u32,
    window: HWND,
    id_object: i32,
    id_child: i32,
    _thread: u32,
    _time: u32,
) {
    if id_object != OBJID_WINDOW.0 || id_child != CHILDID_SELF.cast_signed() || window.is_invalid() {
        return;
    }
    let h = window.0 as isize;
    #[cfg(test)]
    tests::saw(event, h);
    if event == EVENT_OBJECT_DESTROY {
        // The hook comes off on the wake this posts, not inside its own callback.
        forget(h);
        return;
    }
    if event == EVENT_OBJECT_SHOW && start_hide(h, None) {
        // SAFETY: by-value call on the window the event named; a window gone since then makes it fail.
        let _ = unsafe { ShowWindow(window, SW_HIDE) };
        end_hide(h);
        #[cfg(test)]
        tests::REHIDDEN.fetch_add(1, Ordering::SeqCst);
    }
}

// ---- windows ----------------------------------------------------------------------------------------------

fn hwnd(h: isize) -> HWND {
    HWND(h as *mut c_void)
}

fn handle_value(h: isize) -> i64 {
    h as i64
}

fn handle_isize(handle: NativeHandle) -> Result<isize> {
    isize::try_from(handle.0).map_err(|_| WindowError::InvalidHandle)
}

/// `handle` if it is still a window at all.
fn live_window(handle: NativeHandle) -> Result<isize> {
    let h = handle_isize(handle)?;
    // SAFETY: by-value handle query.
    if h != 0 && unsafe { IsWindow(Some(hwnd(h))) }.as_bool() {
        Ok(h)
    } else {
        Err(WindowError::InvalidHandle)
    }
}

/// `handle` if it is still a top-level window of a chrome.exe process, the only windows show and hide touch.
fn chrome_window(handle: NativeHandle) -> Result<isize> {
    let h = live_window(handle)?;
    // SAFETY: by-value handle query.
    let top_level = unsafe { GetAncestor(hwnd(h), GA_ROOT) }.0 as isize == h;
    #[cfg(test)]
    if top_level && tests::taken_for_chrome(h) {
        return Ok(h);
    }
    if top_level && is_chrome_pid(window_pid(h)) { Ok(h) } else { Err(WindowError::InvalidHandle) }
}

unsafe extern "system" fn collect_window(window: HWND, list: LPARAM) -> BOOL {
    // SAFETY: `list` is the `&mut Vec<isize>` top_level_windows passes, alive and unaliased for the whole
    // EnumWindows call, which invokes this callback synchronously on the same thread.
    let list = unsafe { &mut *(list.0 as *mut Vec<isize>) };
    list.push(window.0 as isize);
    BOOL(1)
}

fn top_level_windows() -> Vec<isize> {
    let mut list: Vec<isize> = Vec::new();
    // SAFETY: the LPARAM points at `list`, which outlives the call; see collect_window. A failure leaves
    // whatever was collected.
    let _ = unsafe { EnumWindows(Some(collect_window), LPARAM(&raw mut list as isize)) };
    list
}

fn window_title(h: isize) -> String {
    let mut buf = [0u16; 2048];
    // SAFETY: GetWindowTextW writes at most `buf.len()` u16s into the slice it is given. For another
    // process's window it reads the stored caption without sending a message, so it cannot hang.
    let len = unsafe { GetWindowTextW(hwnd(h), &mut buf) };
    let len = usize::try_from(len).unwrap_or(0).min(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn window_pid(h: isize) -> u32 {
    let mut pid = 0u32;
    // SAFETY: `pid` is a valid, writable u32 for the call.
    let _ = unsafe { GetWindowThreadProcessId(hwnd(h), Some(&raw mut pid)) };
    pid
}

// ---- processes --------------------------------------------------------------------------------------------

/// A process or snapshot handle, closed on drop.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module, is owned only here, and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn open_process(pid: u32) -> Option<Owned> {
    // SAFETY: plain by-value call; the returned handle is owned by `Owned`. Limited information is enough for
    // the image path and the command line, and is granted for other users' processes too.
    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok().map(Owned)
}

fn image_path(process: &Owned) -> Option<String> {
    let mut buf = vec![0u16; 4096];
    let mut len = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `buf` holds `len` writable u16s and `len` is a valid in/out u32, as the call requires.
    unsafe {
        QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &raw mut len)
    }
    .ok()?;
    let len = usize::try_from(len).ok()?.min(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn is_chrome_pid(pid: u32) -> bool {
    pid != 0
        && open_process(pid)
            .and_then(|p| image_path(&p))
            .is_some_and(|path| file_name(&path).eq_ignore_ascii_case(CHROME_EXE))
}

/// Every chrome.exe process id, from a `ToolHelp` snapshot (names only; no process is opened).
fn chrome_pids() -> Result<Vec<u32>> {
    // SAFETY: plain call; the snapshot handle is owned by `Owned`.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map(Owned)
        .map_err(|e| WindowError::Os { context: "list processes", message: e.message() })?;
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..Default::default()
    };
    let mut pids = Vec::new();
    // SAFETY: `entry` is a valid PROCESSENTRY32W with dwSize set, as both calls require.
    let mut more = unsafe { Process32FirstW(snap.0, &raw mut entry) }.is_ok();
    while more {
        let name = &entry.szExeFile;
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        if String::from_utf16_lossy(&name[..len]).eq_ignore_ascii_case(CHROME_EXE) {
            pids.push(entry.th32ProcessID);
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap.0, &raw mut entry) }.is_ok();
    }
    Ok(pids)
}

/// A process's command line through `ProcessCommandLineInformation` (Windows 8.1+). It needs only limited
/// query access, unlike reading the PEB from the process's memory, which needs VM read.
fn command_line(process: &Owned) -> Option<String> {
    let mut needed = 0u32;
    // SAFETY: a zero-length query with a null buffer only reports the size needed into `needed`.
    let _ = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    let bytes = usize::try_from(needed).ok().filter(|&n| n >= size_of::<UNICODE_STRING>())?;
    // u64 words, so the UNICODE_STRING header at the start is aligned.
    let mut buf = vec![0u64; bytes.div_ceil(8)];
    let size = u32::try_from(buf.len() * 8).ok()?;
    // SAFETY: `buf` is `size` writable bytes, 8-aligned.
    let status = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessCommandLineInformation,
            buf.as_mut_ptr().cast(),
            size,
            &raw mut needed,
        )
    };
    if status.is_err() {
        return None;
    }
    // SAFETY: on success the buffer starts with a UNICODE_STRING (it is at least that long, checked above,
    // and 8-aligned).
    let header = unsafe { buf.as_ptr().cast::<UNICODE_STRING>().read() };
    let start = header.Buffer.0.cast_const();
    let len = usize::from(header.Length / 2);
    let (lo, hi) = (buf.as_ptr().addr(), buf.as_ptr().addr() + buf.len() * 8);
    if len == 0 || start.addr() < lo || start.addr() + len * 2 > hi || start.addr() % 2 != 0 {
        return None;
    }
    // SAFETY: the string lies inside `buf` (checked just above), is u16-aligned, and `buf` outlives the slice.
    let text = unsafe { std::slice::from_raw_parts(start, len) };
    Some(String::from_utf16_lossy(text))
}

/// Command lines of the chrome.exe processes whose image is `chrome_path`. Processes this user cannot query
/// are skipped, as if they had no command line.
fn browser_command_lines(chrome_path: &str) -> Result<Vec<String>> {
    let want = chrome_path.to_lowercase();
    Ok(chrome_pids()?
        .into_iter()
        .filter_map(open_process)
        .filter(|p| image_path(p).is_some_and(|path| path.to_lowercase() == want))
        .filter_map(|p| command_line(&p))
        .collect())
}

// ---- quiet ------------------------------------------------------------------------------------------------
//
// Chrome reads --silent-debugger-extension-api only from the command line that starts its browser process:
// here, its sign-in (Run) entry. The registry goes through windows-registry, the windows-rs safe wrapper.

fn quiet(mode_on: bool, chrome_path: &str, run_key: &str) -> Result<QuietState> {
    if chrome_path.is_empty() {
        return Err(WindowError::InvalidArgument("Quiet debugging needs the configured Chrome path".into()));
    }
    let subkey = hkcu_subkey(run_key)?;
    let registry = |context: &'static str| {
        move |e: windows::core::Error| WindowError::Os { context, message: e.message() }
    };
    let mut run_value = None;
    match CURRENT_USER.options().read().write().open(subkey) {
        Ok(key) => {
            // Collected first so the writes below do not shift the enumeration.
            let values: Vec<_> = key.values().map_err(registry("read the Run key"))?.collect();
            for (name, value) in values {
                let ty = value.ty();
                if !matches!(ty, Type::String | Type::ExpandString) {
                    continue;
                }
                let Ok(text) = String::try_from(value) else { continue };
                let Some(new) = rewrite_run_value(&text, chrome_path, mode_on) else { continue };
                if new != text {
                    // Kept as the type it was: an expandable entry stays expandable.
                    let written = if ty == Type::ExpandString {
                        key.set_expand_string(&name, &new)
                    } else {
                        key.set_string(&name, &new)
                    };
                    written.map_err(registry("write the Run key"))?;
                }
                run_value = Some(mode_on);
            }
        }
        Err(e) if e.code() == ERROR_FILE_NOT_FOUND.to_hresult() => {}
        Err(e) => return Err(registry("open the Run key")(e)),
    }
    let lines = browser_command_lines(chrome_path)?;
    Ok(QuietState { run_value, running: running_state(lines.iter().map(String::as_str)) })
}

/// Clears `HANDLE_FLAG_INHERIT` on this process's stdin, stdout and stderr, so a child started later
/// (Chrome for an isolated page, the sign-in provider) does not hold them open. A stdio client then sees
/// EOF when this process ends, not when its last child does.
pub(crate) fn disable_std_handle_inheritance() {
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation};

    let raws = [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ];
    for raw in raws {
        if raw.is_null() {
            continue;
        }
        // SAFETY: `raw` is this process's own standard handle, alive for the process; SetHandleInformation
        // only changes its inherit flag and reads no memory through it. A console or invalid handle makes
        // it fail, which changes nothing.
        let _ = unsafe { SetHandleInformation(HANDLE(raw), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) };
    }
}

/// See [`crate::restrict_dll_search`].
pub(crate) fn restrict_dll_search() -> std::io::Result<()> {
    use windows::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};

    // SAFETY: SetDefaultDllDirectories takes one flag value and no pointer; it changes only this
    // process's search order for later loads by name, and a flag it does not take makes it fail.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) }.map_err(std::io::Error::from)
}

/// See [`crate::set_handle_inheritable`].
pub(crate) fn set_handle_inheritable(
    handle: std::os::windows::io::BorrowedHandle<'_>,
    inheritable: bool,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation};

    let flags = if inheritable { HANDLE_FLAG_INHERIT } else { HANDLE_FLAGS(0) };
    // SAFETY: the handle is borrowed, so it stays open for this call; SetHandleInformation only changes
    // its inherit flag and reads no memory through it.
    unsafe { SetHandleInformation(HANDLE(handle.as_raw_handle()), HANDLE_FLAG_INHERIT.0, flags) }
        .map_err(std::io::Error::from)
}

/// The window lane's view (`tests/window_lane.rs`, test builds only): the processes the keeper hooks, and the
/// top-level windows its own Chrome shows. It reads windows and process ids only, and changes nothing.
#[cfg(feature = "test-seams")]
pub mod seams {
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Instant;

    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{GetCurrentThreadId, GetProcessTimes};
    use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook};
    use windows::Win32::UI::WindowsAndMessaging::{
        CHILDID_SELF, DispatchMessageW, EVENT_OBJECT_SHOW, GA_ROOT, GetAncestor, GetClassNameW, GetMessageW,
        MSG, OBJID_WINDOW, PM_NOREMOVE, PeekMessageW, PostThreadMessageW, WINEVENT_OUTOFCONTEXT, WM_QUIT,
    };

    use crate::NativeHandle;

    /// The processes the keeper has a hook for now.
    #[must_use]
    pub fn kept_processes() -> Vec<u32> {
        super::keeper().hooked.iter().map(|&(pid, _)| pid).collect()
    }

    /// The process that owns `handle`, 0 for none.
    #[must_use]
    pub fn window_pid(handle: NativeHandle) -> u32 {
        isize::try_from(handle.0).map_or(0, super::window_pid)
    }

    /// The window class of `handle`, empty for none.
    #[must_use]
    pub fn window_class(handle: NativeHandle) -> String {
        let mut buf = [0u16; 256];
        let h = isize::try_from(handle.0).unwrap_or(0);
        // SAFETY: GetClassNameW writes at most `buf.len()` u16s into the slice it is given; no message is sent.
        let len = unsafe { GetClassNameW(super::hwnd(h), &mut buf) };
        String::from_utf16_lossy(&buf[..usize::try_from(len).unwrap_or(0).min(buf.len())])
    }

    /// When `pid` was created, in FILETIME units; `None` if it cannot be read.
    fn created(pid: u32) -> Option<u64> {
        let process = super::open_process(pid)?;
        let (mut created, mut exited, mut kernel, mut user) =
            (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        // SAFETY: four valid, writable FILETIMEs and a process handle held open for the call.
        unsafe {
            GetProcessTimes(process.0, &raw mut created, &raw mut exited, &raw mut kernel, &raw mut user)
        }
        .ok()?;
        Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    /// `root` and every process descended from it, from a `ToolHelp` snapshot. `ToolHelp` keeps a parent's
    /// id after the parent ends, and ids are reused, so a process counts as a child only if it was created no
    /// earlier than the process now holding its parent's id; one whose time cannot be read still counts.
    #[must_use]
    pub fn process_tree(root: u32) -> Vec<u32> {
        // SAFETY: plain call; the snapshot handle is owned by `Owned`.
        let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }).map(super::Owned) else {
            return vec![root];
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(0),
            ..Default::default()
        };
        let mut parents = Vec::new();
        // SAFETY: `entry` is a valid PROCESSENTRY32W with dwSize set, as both calls require.
        let mut more = unsafe { Process32FirstW(snap.0, &raw mut entry) }.is_ok();
        while more {
            parents.push((entry.th32ProcessID, entry.th32ParentProcessID));
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap.0, &raw mut entry) }.is_ok();
        }
        let mut tree = vec![(root, created(root))];
        let mut grew = true;
        while grew {
            grew = false;
            for &(pid, parent) in &parents {
                if pid == 0 || tree.iter().any(|&(p, _)| p == pid) {
                    continue;
                }
                let Some(&(_, parent_created)) = tree.iter().find(|&&(p, _)| p == parent) else {
                    continue;
                };
                let child_created = created(pid);
                if let (Some(child), Some(parent)) = (child_created, parent_created)
                    && child < parent
                {
                    continue;
                }
                tree.push((pid, child_created));
                grew = true;
            }
        }
        tree.into_iter().map(|(pid, _)| pid).collect()
    }

    /// One SHOW of a top-level window owned by a process of the recorded tree.
    #[derive(Debug, Clone)]
    pub struct Shown {
        pub handle: NativeHandle,
        pub pid: u32,
        pub class: String,
        pub at: Instant,
    }

    /// Records, until dropped, every SHOW of a top-level window owned by `root` or a process descended from
    /// it. The hook is desktop-wide, as only that sees a show attributed to any process; every other
    /// process's window is passed over on its id alone.
    #[derive(Debug)]
    pub struct ShowLog {
        thread: u32,
        shown: Arc<Mutex<Vec<Shown>>>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl ShowLog {
        #[must_use]
        pub fn shown(&self) -> Vec<Shown> {
            self.shown.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }
    }

    impl Drop for ShowLog {
        fn drop(&mut self) {
            // SAFETY: a message with no pointers to the recording thread, which ends at it.
            let _ = unsafe { PostThreadMessageW(self.thread, WM_QUIT, WPARAM(0), LPARAM(0)) };
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    /// The tree's root process, and where its shows go.
    type Recording = Option<(u32, Arc<Mutex<Vec<Shown>>>)>;

    thread_local! {
        static LOG: std::cell::RefCell<Recording> = const { std::cell::RefCell::new(None) };
    }

    /// Starts a [`ShowLog`] for `root`'s process tree; `None` if its thread or hook cannot start.
    #[must_use]
    pub fn record_shows(root: u32) -> Option<ShowLog> {
        let shown = Arc::new(Mutex::new(Vec::new()));
        let theirs = Arc::clone(&shown);
        let (tx, rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            LOG.with_borrow_mut(|log| *log = Some((root, theirs)));
            let mut msg = MSG::default();
            // SAFETY: `msg` is a valid, writable MSG; the peek creates this thread's queue.
            let _ = unsafe { PeekMessageW(&raw mut msg, None, 0, 0, PM_NOREMOVE) };
            // SAFETY: `on_show` matches WINEVENTPROC and lives for the program; out of context, no module.
            let hook = unsafe {
                SetWinEventHook(
                    EVENT_OBJECT_SHOW,
                    EVENT_OBJECT_SHOW,
                    None,
                    Some(on_show),
                    0,
                    0,
                    WINEVENT_OUTOFCONTEXT,
                )
            };
            if hook.is_invalid() {
                return;
            }
            // SAFETY: no arguments.
            let _ = tx.send(unsafe { GetCurrentThreadId() });
            // SAFETY: `msg` is a valid MSG; DispatchMessage gets back what GetMessage filled in.
            while unsafe { GetMessageW(&raw mut msg, None, 0, 0) }.0 > 0 {
                // SAFETY: as above.
                let _ = unsafe { DispatchMessageW(&raw const msg) };
            }
            super::unhook(hook);
        });
        let thread = rx.recv().ok()?;
        Some(ShowLog { thread, shown, join: Some(join) })
    }

    unsafe extern "system" fn on_show(
        _hook: HWINEVENTHOOK,
        _event: u32,
        window: HWND,
        id_object: i32,
        id_child: i32,
        _thread: u32,
        _time: u32,
    ) {
        if id_object != OBJID_WINDOW.0 || id_child != CHILDID_SELF.cast_signed() || window.is_invalid() {
            return;
        }
        let h = window.0 as isize;
        // SAFETY: by-value handle query.
        if unsafe { GetAncestor(window, GA_ROOT) }.0 as isize != h {
            return;
        }
        let pid = super::window_pid(h);
        let at = Instant::now();
        LOG.with_borrow(|log| {
            if let Some((root, shown)) = log
                && process_tree(*root).contains(&pid)
            {
                let handle = NativeHandle(super::handle_value(h));
                let class = window_class(handle);
                shown.lock().unwrap_or_else(PoisonError::into_inner).push(Shown { handle, pid, class, at });
            }
        });
    }
}

#[cfg(test)]
#[allow(clippy::print_stdout, reason = "the other processes answer on stdout, and a result is printed")]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::mpsc;

    use windows::Win32::Foundation::{LRESULT, POINT, RECT};
    use windows::Win32::UI::WindowsAndMessaging::{
        CallWindowProcW, CreateWindowExW, DestroyWindow, GWLP_WNDPROC, GetMessageW, GetWindowRect,
        MINMAXINFO, SW_MINIMIZE, SW_SHOW, SW_SHOWMAXIMIZED, SW_SHOWNORMAL, SWP_ASYNCWINDOWPOS,
        SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, SetWindowLongPtrW,
        SetWindowPos, ShowWindowAsync, WINDOW_EX_STYLE, WM_GETMINMAXINFO, WNDPROC, WS_EX_NOACTIVATE,
        WS_EX_TOOLWINDOW, WS_POPUP,
    };
    use windows::core::w;

    use super::*;

    /// Kept windows the keeper hid again.
    pub(super) static REHIDDEN: AtomicUsize = AtomicUsize::new(0);
    /// SHOW events the keeper received for a window of another process: none, with its hooks scoped.
    static FOREIGN: AtomicUsize = AtomicUsize::new(0);
    /// Windows whose DESTROY the keeper received.
    static DESTROYED: Mutex<Vec<isize>> = Mutex::new(Vec::new());
    /// Fails the next `hook_process` after it opens the process.
    pub(super) static FAIL_NEXT_HOOK: AtomicBool = AtomicBool::new(false);
    /// A window whose being shown makes the keeper's next wait fail, as `MsgWaitForMultipleObjectsEx` failing
    /// would. Only once it is shown, so a wake from another test's window before then passes.
    static FAIL_WAIT_ONCE_SHOWN: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
    /// Run once on the keeper thread just before its next `SetWinEventHook`, while that process has no hook.
    static BEFORE_HOOK: Mutex<Option<Between>> = Mutex::new(None);
    /// Run once on the keeper thread after a pass that changed hooks, before the next pass.
    type Between = Box<dyn FnOnce() + Send>;
    static BETWEEN: Mutex<Option<Between>> = Mutex::new(None);
    /// Run once on the keeper thread at its next `hide_if_kept`, before it checks the window is still kept.
    static BEFORE_CHECK: Mutex<Option<Between>> = Mutex::new(None);
    /// Run once on the keeper thread at its next `hide_if_kept` that found the window kept, before the hide.
    static AFTER_CHECK: Mutex<Option<Between>> = Mutex::new(None);
    /// Test windows `chrome_window` accepts as Chrome's.
    static TAKEN_FOR_CHROME: Mutex<Vec<isize>> = Mutex::new(Vec::new());
    /// The keeper is one per process, so the tests that use it take turns.
    static SERIAL: Mutex<()> = Mutex::new(());

    pub(super) fn saw(event: u32, h: isize) {
        let pid = window_pid(h);
        if event == EVENT_OBJECT_SHOW && pid != 0 && pid != std::process::id() {
            FOREIGN.fetch_add(1, Ordering::SeqCst);
        }
        if event == EVENT_OBJECT_DESTROY {
            DESTROYED.lock().unwrap_or_else(PoisonError::into_inner).push(h);
        }
    }

    /// A seam that panicked on the keeper thread (`run_seam`).
    static SEAM_PANICKED: AtomicBool = AtomicBool::new(false);

    /// Runs a seam on the keeper thread. A panic there would end the thread with no pass to mark it stopped,
    /// leaving `Running` with a dead id, and every later test's `keep` failing with "Invalid thread
    /// identifier". Nothing on the keeper's own path panics (no unwrap, assert, indexing or unchecked sum),
    /// and release builds abort at any panic, so only a seam can get there. The panic is caught instead, and
    /// the test that armed the seam fails at its end (`Serial`).
    fn run_seam(seam: &Mutex<Option<Between>>) {
        let seam = seam.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(seam) = seam
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(seam)).is_err()
        {
            SEAM_PANICKED.store(true, Ordering::SeqCst);
        }
    }

    pub(super) fn between_passes() {
        run_seam(&BETWEEN);
    }

    pub(super) fn before_check() {
        run_seam(&BEFORE_CHECK);
    }

    pub(super) fn after_check() {
        run_seam(&AFTER_CHECK);
    }

    pub(super) fn wait_fails() -> bool {
        let h = FAIL_WAIT_ONCE_SHOWN.load(Ordering::SeqCst);
        h != 0 && visible(h) && FAIL_WAIT_ONCE_SHOWN.swap(0, Ordering::SeqCst) == h
    }

    pub(super) fn before_hook() {
        run_seam(&BEFORE_HOOK);
    }

    pub(super) fn taken_for_chrome(h: isize) -> bool {
        TAKEN_FOR_CHROME.lock().unwrap_or_else(PoisonError::into_inner).contains(&h)
    }

    fn serial() -> Serial {
        Serial { _turn: SERIAL.lock().unwrap_or_else(PoisonError::into_inner) }
    }

    /// A keeper test's turn. A test that fails leaves its seams armed and its windows kept; they are cleared
    /// as it ends, and the keeper is given 10 s to stop, so the next test starts from a stopped keeper and
    /// only the test at fault fails.
    struct Serial {
        _turn: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for Serial {
        fn drop(&mut self) {
            if !std::thread::panicking() && !SEAM_PANICKED.load(Ordering::SeqCst) {
                return;
            }
            for seam in [&BETWEEN, &BEFORE_HOOK, &BEFORE_CHECK, &AFTER_CHECK] {
                seam.lock().unwrap_or_else(PoisonError::into_inner).take();
            }
            FAIL_NEXT_HOOK.store(false, Ordering::SeqCst);
            FAIL_WAIT_ONCE_SHOWN.store(0, Ordering::SeqCst);
            {
                let mut k = keeper();
                k.kept.clear();
                if wake(&mut k).is_err() {
                    // A thread that ended without marking itself stopped: its hooks went with it. Its waiting
                    // calls hear that it ended, and the next keep starts a new one.
                    k.thread = KeeperThread::Stopped;
                    k.hooked.clear();
                    k.waiting.clear();
                    k.busy = false;
                    k.hiding.clear();
                }
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stopped() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !stopped() {
                eprintln!("keeper test cleanup: the keeper did not stop within 10 s");
            }
            // Read after the wait: a seam still running as its test failed may panic during it.
            let seam_panicked = SEAM_PANICKED.swap(false, Ordering::SeqCst);
            // Not while the test is already failing: a second panic aborts the run.
            assert!(std::thread::panicking() || !seam_panicked, "a seam panicked on the keeper thread");
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    /// Tells the other process `keeper_scope_and_lifetime` starts which window to show.
    const CHILD_ENV: &str = "PHANTAB_TEST_KEEPER_SHOWS";
    /// Tells the other process `an_ended_process_takes_its_windows_and_hook` starts to run.
    const EXIT_ENV: &str = "PHANTAB_TEST_KEEPER_EXITS";
    /// Asks the window thread to destroy the window in WPARAM.
    const DESTROY: u32 = WM_APP + 1;

    /// Every way another process can show a window: the cases a hook scoped to the window's owner must see.
    const SHOWS: [&str; 10] = [
        "ShowWindow(SW_SHOWNOACTIVATE)",
        "ShowWindow(SW_SHOW)",
        "ShowWindow(SW_SHOWNORMAL)",
        "SetWindowPos(SWP_SHOWWINDOW)",
        "SetWindowPos(SWP_SHOWWINDOW | SWP_ASYNCWINDOWPOS)",
        "ShowWindowAsync(SW_SHOWNOACTIVATE)",
        "ShowWindow(SW_SHOWMAXIMIZED)",
        "ShowWindow(SW_RESTORE), from maximized",
        "ShowWindow(SW_MINIMIZE)",
        "ShowWindow(SW_RESTORE), from minimized",
    ];

    /// Shows `h` the way `SHOWS[i]` names.
    fn show_by(i: usize, h: isize) {
        let window = hwnd(h);
        let flags = SWP_SHOWWINDOW | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE;
        // SAFETY: by-value calls on a test window of the other process, whose thread pumps, so a synchronous
        // show returns. The results are previous state, not needed here.
        unsafe {
            match i {
                3 => SetWindowPos(window, None, 0, 0, 0, 0, flags).unwrap(),
                4 => SetWindowPos(window, None, 0, 0, 0, 0, flags | SWP_ASYNCWINDOWPOS).unwrap(),
                5 => {
                    let _ = ShowWindowAsync(window, SW_SHOWNOACTIVATE);
                }
                _ => {
                    let cmd = match i {
                        0 => SW_SHOWNOACTIVATE,
                        1 => SW_SHOW,
                        2 => SW_SHOWNORMAL,
                        6 => SW_SHOWMAXIMIZED,
                        8 => SW_MINIMIZE,
                        _ => SW_RESTORE,
                    };
                    let _ = ShowWindow(window, cmd);
                }
            }
        }
    }

    /// Keeps a test window 1x1 and far off screen even maximized, so `SW_SHOWMAXIMIZED` puts nothing on the
    /// owner's screen: a maximized window takes its size and place from this answer.
    unsafe extern "system" fn test_window_proc(window: HWND, message: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        // SAFETY: STATIC_PROC holds the procedure SetWindowLongPtrW returned for a STATIC window before this one
        // was set: a window procedure, or 0 (None) if that call failed.
        let static_proc: WNDPROC =
            unsafe { std::mem::transmute::<isize, WNDPROC>(STATIC_PROC.load(Ordering::SeqCst)) };
        if message == WM_GETMINMAXINFO {
            // SAFETY: for WM_GETMINMAXINFO, LPARAM points to a writable MINMAXINFO for the call.
            let info = unsafe { &mut *(l.0 as *mut MINMAXINFO) };
            info.ptMaxSize = POINT { x: 1, y: 1 };
            info.ptMaxPosition = POINT { x: -32000, y: -32000 };
            info.ptMaxTrackSize = POINT { x: 1, y: 1 };
            return LRESULT(0);
        }
        // SAFETY: the STATIC class's own procedure, with the arguments this one was called with.
        unsafe { CallWindowProcW(static_proc, window, message, w, l) }
    }

    /// The STATIC class's window procedure, which `test_window_proc` passes all else on to.
    static STATIC_PROC: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

    /// A 1x1 hidden tool window far off screen, owned by the calling thread.
    fn test_window() -> isize {
        // SAFETY: a system class and literal strings; no parent, menu, instance or create parameter.
        let window = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(WS_EX_TOOLWINDOW.0 | WS_EX_NOACTIVATE.0),
                w!("STATIC"),
                w!("phantab keeper test"),
                WS_POPUP,
                -32000,
                -32000,
                1,
                1,
                None,
                None,
                None,
                None,
            )
        };
        let window = window.expect("test window");
        // SAFETY: this thread's own new window, given a procedure that lives for the program. Every STATIC
        // window has the same class procedure, so the one returned is the same each time.
        let previous =
            unsafe { SetWindowLongPtrW(window, GWLP_WNDPROC, test_window_proc as *const () as isize) };
        assert_ne!(previous, 0, "test window procedure");
        STATIC_PROC.store(previous, Ordering::SeqCst);
        window.0 as isize
    }

    fn visible(h: isize) -> bool {
        // SAFETY: by-value handle query.
        unsafe { IsWindowVisible(hwnd(h)) }.as_bool()
    }

    fn show(h: isize) {
        // SAFETY: by-value call on a test window whose thread pumps, so a show from another thread returns.
        let _ = unsafe { ShowWindow(hwnd(h), SW_SHOWNOACTIVATE) };
    }

    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting until {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn hooked_pids() -> Vec<u32> {
        keeper().hooked.iter().map(|&(p, _)| p).collect()
    }

    fn stopped() -> bool {
        let k = keeper();
        k.thread == KeeperThread::Stopped && k.hooked.is_empty() && k.kept.is_empty()
    }

    /// Message loop for a test window thread: destroys the window a `DESTROY` names, ends at `WM_QUIT`.
    fn pump_test_windows() {
        let mut msg = MSG::default();
        // SAFETY: `msg` is a valid MSG; DispatchMessage gets back what GetMessage filled in.
        while unsafe { GetMessageW(&raw mut msg, None, 0, 0) }.0 > 0 {
            if msg.message == DESTROY {
                // SAFETY: the window in WPARAM was created on this thread.
                let _ = unsafe { DestroyWindow(hwnd(msg.wParam.0.cast_signed())) };
            }
            // SAFETY: as above.
            let _ = unsafe { DispatchMessageW(&raw const msg) };
        }
    }

    fn thread_queue() -> u32 {
        let mut msg = MSG::default();
        // SAFETY: `msg` is a valid, writable MSG; the peek creates this thread's queue.
        let _ = unsafe { PeekMessageW(&raw mut msg, None, 0, 0, PM_NOREMOVE) };
        // SAFETY: no arguments.
        unsafe { GetCurrentThreadId() }
    }

    /// Two test windows on a thread of their own, which pumps until it is told to quit.
    fn window_thread() -> (u32, isize, isize) {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let id = thread_queue();
            tx.send((id, test_window(), test_window())).unwrap();
            pump_test_windows();
        });
        rx.recv().unwrap()
    }

    fn post(thread: u32, message: u32, w: isize) {
        // SAFETY: a message with no pointers, to the test's window thread.
        unsafe { PostThreadMessageW(thread, message, WPARAM(w.cast_unsigned()), LPARAM(0)) }.unwrap();
    }

    /// The test binary again, running only `test` with `env` set.
    fn other_process(test: &str, env: (&str, String)) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env(env.0, env.1)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// What follows `prefix` in the next line the other process printed with it.
    fn line_from(lines: &mut impl Iterator<Item = std::io::Result<String>>, prefix: &str) -> String {
        loop {
            let line = lines.next().unwrap_or_else(|| panic!("the other process ended before \"{prefix}\""));
            // libtest starts the line with the test name ahead of what the test prints.
            if let Some((_, rest)) = line.unwrap().split_once(prefix) {
                return rest.to_owned();
            }
        }
    }

    /// perf-idle-3: the keeper hooks only the processes that own a kept window, only while one is kept, and
    /// still hides a kept window again whichever process shows it, by any of the ways to show one.
    #[test]
    fn keeper_scope_and_lifetime() {
        let _serial = serial();
        let runtime = runtime();
        let own = std::process::id();
        let (thread, a, b) = window_thread();
        assert!(runtime.block_on(keep(a, 0)).is_err(), "pid 0 would hook the whole desktop");
        assert!(stopped());

        runtime.block_on(keep(a, own)).unwrap();
        runtime.block_on(keep(b, own)).unwrap();
        assert_eq!(hooked_pids(), vec![own], "one hook, for the owning process");

        // Shown from this process: hidden again.
        show(a);
        wait_until("this process's show of a kept window is undone", || {
            REHIDDEN.load(Ordering::SeqCst) >= 1 && !visible(a)
        });

        // Shown from another process, which also shows a window of its own, one way after another: each is
        // hidden again, and the other process's window never reaches the keeper. A desktop-wide hook, as on
        // main, hides the same set (docs/TESTING.md).
        let mut other = other_process("win32::tests::keeper_child", (CHILD_ENV, a.to_string()));
        let mut to = other.stdin.take().unwrap();
        let mut from = BufReader::new(other.stdout.take().unwrap()).lines();
        line_from(&mut from, "ready");
        for (i, name) in SHOWS.iter().enumerate() {
            let before = REHIDDEN.load(Ordering::SeqCst);
            writeln!(to, "{i}").unwrap();
            to.flush().unwrap();
            line_from(&mut from, &format!("shown {i}"));
            wait_until(&format!("{name} from another process is undone"), || {
                REHIDDEN.load(Ordering::SeqCst) > before && !visible(a)
            });
        }
        drop(to);
        let status = other.wait().unwrap();
        assert!(status.success(), "the other process failed: {status}");
        assert_eq!(FOREIGN.load(Ordering::SeqCst), 0, "the keeper saw another process's window");

        // A window let go is not hidden again; the hook stays while another window is kept.
        forget(a);
        show(a);
        std::thread::sleep(Duration::from_millis(200));
        assert!(visible(a), "a window let go was hidden again");
        assert_eq!(hooked_pids(), vec![own]);

        // The last kept window's DESTROY takes the hook and the thread with it.
        post(thread, DESTROY, b);
        wait_until("the hook and its thread are gone", stopped);

        // The next keep starts them again.
        runtime.block_on(keep(a, own)).unwrap();
        assert_eq!(hooked_pids(), vec![own]);
        forget(a);
        wait_until("the hook and its thread are gone again", stopped);
        post(thread, WM_QUIT, 0);
    }

    /// The other process of `keeper_scope_and_lifetime`; does nothing in a normal run. Shows its own window,
    /// then the target once per line it reads, the way `SHOWS` names.
    #[test]
    fn keeper_child() {
        let Some(target) = std::env::var(CHILD_ENV).ok().and_then(|v| v.parse::<isize>().ok()) else {
            return;
        };
        let own = test_window();
        // Its own window first, shown long enough for a desktop-wide hook to see it.
        show(own);
        std::thread::sleep(Duration::from_millis(300));
        println!("ready");
        for line in std::io::stdin().lock().lines() {
            let i: usize = line.unwrap().trim().parse().unwrap();
            show_by(i, target);
            println!("shown {i}");
            std::io::stdout().flush().unwrap();
        }
        // SAFETY: this thread created `own`.
        unsafe { DestroyWindow(hwnd(own)) }.unwrap();
    }

    /// A hook that fails answers the calls waiting on it with its error, even when a later call for the same
    /// process is hooked fine before they are answered.
    #[test]
    fn a_failed_hook_fails_its_own_calls() {
        let _serial = serial();
        let own = std::process::id();
        let (thread, a, c) = window_thread();
        let second: Arc<Mutex<Option<std::thread::JoinHandle<Result<()>>>>> = Arc::default();
        let slot = Arc::clone(&second);
        FAIL_NEXT_HOOK.store(true, Ordering::SeqCst);
        // After the failed pass: a second call for the same process, which the next pass hooks.
        *BETWEEN.lock().unwrap() = Some(Box::new(move || {
            let call = std::thread::spawn(move || runtime().block_on(keep(c, own)));
            *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(call);
            wait_until("the second call is waiting", || keeper().kept.iter().any(|&(w, _)| w == c));
        }));
        let first = runtime().block_on(keep(a, own));
        // The failed hook answers `first` within its pass, before the seam that follows the pass has run.
        wait_until("the second call was made", || second.lock().unwrap().is_some());
        let second = second.lock().unwrap().take().unwrap().join().unwrap();
        assert!(first.is_err(), "the call whose hook failed was answered {first:?}");
        assert!(!keeper().kept.iter().any(|&(w, _)| w == a), "a window whose hook failed is still kept");
        assert!(second.is_ok(), "the later call was answered {second:?}");
        assert_eq!(hooked_pids(), vec![own]);
        forget(c);
        wait_until("the hook and its thread are gone", stopped);
        post(thread, WM_QUIT, 0);
    }

    /// A process that ends, killed or crashed, without destroying its windows: its kept windows and its hook
    /// go with it, so its id, free for reuse once the keeper lets go, never inherits a hook.
    #[test]
    fn an_ended_process_takes_its_windows_and_hook() {
        let _serial = serial();
        let (thread, a, _) = window_thread();
        let mut other = other_process("win32::tests::exiting_child", (EXIT_ENV, "1".into()));
        let pid = other.id();
        let mut from = BufReader::new(other.stdout.take().unwrap()).lines();
        let theirs: isize = line_from(&mut from, "window ").parse().unwrap();
        let runtime = runtime();
        runtime.block_on(keep(theirs, pid)).unwrap();
        // One of this process's windows, kept under the other process's id: no DESTROY of it comes from
        // there, so only the process's end lets go of it.
        runtime.block_on(keep(a, pid)).unwrap();
        assert_eq!(hooked_pids(), vec![pid]);
        drop(other.stdin.take());
        let status = other.wait().unwrap();
        assert!(status.success(), "the other process failed: {status}");
        wait_until("the ended process's windows and hook are gone", stopped);
        let destroyed = DESTROYED.lock().unwrap().contains(&theirs);
        println!("keeper: the ended process's window sent its DESTROY: {destroyed}");
        post(thread, WM_QUIT, 0);
    }

    /// The other process of `an_ended_process_takes_its_windows_and_hook`; does nothing in a normal run.
    #[test]
    fn exiting_child() {
        if std::env::var_os(EXIT_ENV).is_none() {
            return;
        }
        let own = test_window();
        println!("window {own}");
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read_line(&mut String::new());
        // Ends with its window still there, as a killed Chrome does.
        std::process::exit(0);
    }

    /// A keeper thread held up (as by a callback's hide of a hung Chrome's window) answers no call: `keep`
    /// gives up at its deadline, and the window stays kept, so the keeper hooks it and hides it again once it
    /// is free.
    #[test]
    fn a_held_up_keeper_fails_the_call_but_keeps_the_window() {
        let _serial = serial();
        let own = std::process::id();
        let (thread, a, _) = window_thread();
        let (release, released) = mpsc::channel::<()>();
        *BEFORE_HOOK.lock().unwrap() = Some(Box::new(move || {
            let _ = released.recv_timeout(Duration::from_secs(10));
        }));
        let t = Instant::now();
        let kept = runtime().block_on(keep(a, own));
        let waited = t.elapsed();
        release.send(()).unwrap();
        assert!(kept.is_err(), "a call the keeper never answered returned {kept:?} after {waited:?}");
        assert!(waited < KEEP_DEADLINE * 4, "it waited {waited:?}");
        wait_until("the freed keeper hooks the window it was too late to answer for", || {
            keeper().kept.contains(&(a, own)) && hooked_pids() == vec![own]
        });
        let before = REHIDDEN.load(Ordering::SeqCst);
        show(a);
        wait_until("the window is hidden again", || REHIDDEN.load(Ordering::SeqCst) > before && !visible(a));
        forget(a);
        wait_until("the hook and its thread are gone", stopped);
        post(thread, WM_QUIT, 0);
    }

    /// A `WM_QUIT` (any process of this user can post one to the thread) ends the keeper thread; a new one takes
    /// over the kept windows at once, so they are never left unwatched until the next call.
    #[test]
    fn a_quit_keeper_thread_is_replaced() {
        let _serial = serial();
        let own = std::process::id();
        let (thread, a, _) = window_thread();
        runtime().block_on(keep(a, own)).unwrap();
        let KeeperThread::Running(first) = keeper().thread else {
            panic!("the keeper thread is not running")
        };
        // Shown in the gap, while no thread has a hook for it: no event comes of it.
        let rehidden = REHIDDEN.load(Ordering::SeqCst);
        *BEFORE_HOOK.lock().unwrap() = Some(Box::new(move || show(a)));
        post(first, WM_QUIT, 0);
        wait_until("a new keeper thread hooks the kept window", || {
            let k = keeper();
            matches!(k.thread, KeeperThread::Running(id) if id != first) && k.hooked.len() == 1
        });
        wait_until("the window shown in the gap is hidden again", || !visible(a));
        assert_eq!(REHIDDEN.load(Ordering::SeqCst), rehidden, "the gap's show raised no event");
        let before = REHIDDEN.load(Ordering::SeqCst);
        show(a);
        wait_until("the new thread hides the kept window again", || {
            REHIDDEN.load(Ordering::SeqCst) > before && !visible(a)
        });
        forget(a);
        wait_until("the hook and its thread are gone", stopped);
        post(thread, WM_QUIT, 0);
    }

    /// A restarted keeper whose hook then fails: the windows it took over, answered long ago, are hidden if
    /// shown before they are let go, never left shown unwatched.
    #[test]
    fn a_hook_failed_after_a_restart_hides_its_windows() {
        let _serial = serial();
        let own = std::process::id();
        let (thread, a, _) = window_thread();
        runtime().block_on(keep(a, own)).unwrap();
        let KeeperThread::Running(first) = keeper().thread else {
            panic!("the keeper thread is not running")
        };
        *BEFORE_HOOK.lock().unwrap() = Some(Box::new(move || show(a)));
        FAIL_NEXT_HOOK.store(true, Ordering::SeqCst);
        post(first, WM_QUIT, 0);
        wait_until("the window is let go, and the hook and thread with it", stopped);
        assert!(!visible(a), "a window whose hook failed after a restart was left shown");
        post(thread, WM_QUIT, 0);
    }

    /// A keeper thread whose wait fails ends without a restart (it would fail again at once); its kept windows
    /// are hidden first, as no hook watches them until the next call.
    #[test]
    fn a_failed_wait_hides_the_kept_windows() {
        let _serial = serial();
        let own = std::process::id();
        let (thread, a, _) = window_thread();
        let (passed, pass_ended) = mpsc::channel();
        *BETWEEN.lock().unwrap() = Some(Box::new(move || {
            let _ = passed.send(());
        }));
        runtime().block_on(keep(a, own)).unwrap();
        // `keep` is answered before its pass hides the kept windows: a show ahead of that hide is undone by
        // it, and the wait below then finds the window hidden and does not fail.
        pass_ended.recv_timeout(Duration::from_secs(10)).unwrap();
        let rehidden = REHIDDEN.load(Ordering::SeqCst);
        FAIL_WAIT_ONCE_SHOWN.store(a, Ordering::SeqCst);
        // Wakes the keeper, whose wait then fails before it dispatches this show's event.
        show(a);
        wait_until("the keeper thread has ended", || keeper().thread == KeeperThread::Stopped);
        wait_until("the kept window is hidden", || !visible(a));
        assert_eq!(
            REHIDDEN.load(Ordering::SeqCst),
            rehidden,
            "hidden by the ending thread, not at the event"
        );
        forget(a);
        wait_until("the next thread finds nothing kept", stopped);
        post(thread, WM_QUIT, 0);
    }

    /// The hook goes only to a process that, once held open, still owns a kept window: a process given the
    /// id of one that ended gets none. Here the window is this process's, kept under another's id.
    #[test]
    fn a_hook_is_set_only_for_the_process_that_owns_the_window() {
        let _serial = serial();
        let (thread, a, _) = window_thread();
        let mut other = other_process("win32::tests::exiting_child", (EXIT_ENV, "1".into()));
        let mut from = BufReader::new(other.stdout.take().unwrap()).lines();
        line_from(&mut from, "window ");
        let kept = runtime().block_on(keep(a, other.id()));
        assert!(kept.is_err(), "a hook for a process that does not own the window was set: {kept:?}");
        wait_until("nothing is kept or hooked", stopped);
        drop(other.stdin.take());
        let _ = other.wait();
        post(thread, WM_QUIT, 0);
    }

    /// A first keep of a shown window whose thread is busy (as a Chrome page can hold its UI thread) is
    /// answered once the hook is in place, not after the hide, which waits on that thread; the window is
    /// hidden once the thread is free. The probe of review round 3, which timed out at e26ab0d.
    #[test]
    fn a_busy_window_at_its_first_keep_is_answered_before_its_hide() {
        let _serial = serial();
        let own = std::process::id();
        let (tx, rx) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let id = thread_queue();
            let a = test_window();
            show(a);
            tx.send((id, a)).unwrap();
            // Busy: no message is taken until released.
            let _ = released.recv();
            pump_test_windows();
        });
        let (thread, a) = rx.recv().unwrap();
        assert!(visible(a));
        let t = Instant::now();
        let kept = runtime().block_on(keep(a, own));
        let waited = t.elapsed();
        release.send(()).unwrap();
        assert!(kept.is_ok(), "a busy window's first keep was answered {kept:?} after {waited:?}");
        assert!(waited < KEEP_DEADLINE, "it waited {waited:?}");
        wait_until("the window is hidden once its thread is free", || !visible(a));
        forget(a);
        wait_until("the hook and its thread are gone", stopped);
        post(thread, WM_QUIT, 0);
    }

    /// A window let go and shown (the engine's show for the owner, from another thread) after the keeper
    /// listed it to hide, but before its hide: the hide finds it no longer kept and leaves it shown.
    #[test]
    fn a_window_let_go_before_the_keepers_hide_stays_shown() {
        let _serial = serial();
        let own = std::process::id();
        let (thread, a, _) = window_thread();
        show(a);
        *BEFORE_CHECK.lock().unwrap() = Some(Box::new(move || {
            std::thread::spawn(move || {
                let _ = forget(a);
                show(a);
            })
            .join()
            .unwrap();
        }));
        runtime().block_on(keep(a, own)).unwrap();
        wait_until("the hook and its thread are gone", stopped);
        assert!(visible(a), "the keeper hid a window let go before its hide");
        post(thread, WM_QUIT, 0);
    }

    /// A window let go while the keeper is hiding it: the release waits for that hide (`keep_hidden(false)`
    /// does), so the show that follows lands after it and the window ends shown.
    #[test]
    fn a_window_let_go_during_the_keepers_hide_is_shown_after_it() {
        let _serial = serial();
        let own = std::process::id();
        let (thread, a, _) = window_thread();
        show(a);
        let (done, shown) = mpsc::channel();
        *AFTER_CHECK.lock().unwrap() = Some(Box::new(move || {
            std::thread::spawn(move || {
                // Through the trait, as the engine releases a window, so the wait in it is what is tested.
                runtime().block_on(Win32.keep_hidden(NativeHandle(handle_value(a)), false)).unwrap();
                show(a);
                let _ = done.send(());
            });
            // Gives the release, and its show, every chance to land before this hide.
            wait_until("the window is let go", || !keeper().kept.iter().any(|&(w, _)| w == a));
            std::thread::sleep(Duration::from_millis(50));
        }));
        runtime().block_on(keep(a, own)).unwrap();
        shown.recv_timeout(Duration::from_secs(10)).unwrap();
        wait_until("the hook and its thread are gone", stopped);
        assert!(visible(a), "the keeper's hide landed after the release's show");
        post(thread, WM_QUIT, 0);
    }

    /// A test window maximized stays 1x1 and off screen, so `keeper_scope_and_lifetime`'s
    /// `SW_SHOWMAXIMIZED` puts nothing on the owner's screen.
    #[test]
    fn a_maximized_test_window_stays_off_screen() {
        let h = test_window();
        // SAFETY: by-value call on this thread's own test window.
        let _ = unsafe { ShowWindow(hwnd(h), SW_SHOWMAXIMIZED) };
        let mut rect = RECT::default();
        // SAFETY: `rect` is a valid, writable RECT for the call.
        unsafe { GetWindowRect(hwnd(h), &raw mut rect) }.unwrap();
        // SAFETY: this thread's own window.
        unsafe { DestroyWindow(hwnd(h)) }.unwrap();
        assert!(rect.right <= -31000 && rect.bottom <= -31000, "maximized at {rect:?}");
    }

    /// Show and hide wait on the window's thread; one that takes no messages, as a hung Chrome's, holds them
    /// up, but not the runtime's workers: here the service's two, with more calls held up than workers.
    #[test]
    fn window_calls_leave_the_runtime_workers_free() {
        const CALLS: usize = 4;
        let (tx, rx) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let id = thread_queue();
            let windows: Vec<isize> = (0..CALLS).map(|_| test_window()).collect();
            for &h in &windows {
                show(h);
            }
            tx.send((id, windows)).unwrap();
            // Hung: no message is taken until released.
            let _ = released.recv();
            pump_test_windows();
        });
        let (thread, windows) = rx.recv().unwrap();
        TAKEN_FOR_CHROME.lock().unwrap().extend(&windows);
        let runtime =
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let calls: Vec<_> = windows
            .iter()
            .map(|&h| runtime.spawn(async move { Win32.hide(NativeHandle(handle_value(h))).await }))
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        let (answer, answered) = mpsc::channel();
        runtime.spawn(async move {
            let _ = answer.send(());
        });
        let free = answered.recv_timeout(Duration::from_secs(2)).is_ok();
        release.send(()).unwrap();
        for call in calls {
            runtime.block_on(call).unwrap().unwrap();
        }
        assert!(
            windows.iter().all(|&h| !visible(h)),
            "every window was hidden once its thread took messages"
        );
        post(thread, WM_QUIT, 0);
        TAKEN_FOR_CHROME.lock().unwrap().retain(|h| !windows.contains(h));
        assert!(free, "{CALLS} window calls into a hung thread held up both runtime workers");
    }
}
