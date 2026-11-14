//! Windows quiet debugging. Chrome reads `--silent-debugger-extension-api` only from the command line that
//! starts its browser process, so the flag goes where Windows starts Chrome from: its sign-in (Run) entry
//! and the shortcuts that start it (Start menu, taskbar, Desktop). Only that flag is added or removed, and
//! only on entries and shortcuts whose target is the configured Chrome. The running browser is found by
//! its image path and user-data dir; `quit_browser` asks that one process to close the way a system restart
//! does, so Chrome saves the whole session first.
//!
//! The Restart Manager (`rstrtmgr.dll`) and COM (`ole32.dll`) are loaded at first use from System32 by full
//! search flag rather than imported, so the binary's import table, loaded before `main` and before
//! `restrict_dll_search` (THREAT-MODEL SR-58), stays as it was. The registry goes through windows-registry,
//! the windows-rs safe wrapper.
#![allow(unsafe_code)]

use std::collections::HashSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, FILETIME, HMODULE, WAIT_OBJECT_0};
use windows::Win32::System::Com::{IPersistFile, STGM_READ};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
use windows::core::{GUID, HRESULT, Interface, PCSTR, PCWSTR, s, w};
use windows_registry::{CURRENT_USER, Type};

use crate::matching::{
    expand_env, hkcu_subkey, is_browser_process, on_user_data_dir, rewrite_run_value, rewrite_shortcut_args,
    running_state,
};
use crate::win32::{Owned, chrome_pids, command_line, image_path};
use crate::{
    Browser, DEFAULT_RUN_KEY, QUIT_WAIT, QuietRequest, QuietState, Result, ShortcutDir, WindowError,
};

/// How deep the Start menu and Quick Launch trees are walked, and how many shortcuts at most are read in all:
/// far more than a real Start menu holds, so a folder loop or a huge tree cannot keep a connect busy.
const MAX_DEPTH: usize = 6;
const MAX_SHORTCUTS: usize = 5000;
/// The longest target path and argument string read from a shortcut, in UTF-16 units. One that fills it may
/// have been cut short, so it is left alone.
const LONGEST: usize = 32_768;

pub(crate) fn quiet(request: &QuietRequest) -> Result<QuietState> {
    let browser = &request.browser;
    if browser.chrome_path.is_empty() {
        return Err(WindowError::InvalidArgument("Quiet debugging needs the configured Chrome path".into()));
    }
    let run_key = request.run_key.as_deref().unwrap_or(DEFAULT_RUN_KEY);
    let run_value = run_entries(request.mode_on, &browser.chrome_path, run_key)?;
    let dirs = shortcut_dirs(request);
    let (shortcuts, unwritable) =
        if dirs.is_empty() { (0, Vec::new()) } else { shortcuts(&dirs, request.mode_on, browser)? };
    let running = browsers(browser)?;
    Ok(QuietState {
        run_value,
        running: running_state(running.iter().map(|(_, _, line)| line.as_str())),
        shortcuts,
        unwritable,
        launch_agent: None,
    })
}

// ---- Run entry --------------------------------------------------------------------------------------------

/// Rewrites each Run entry that starts `chrome_path`; `None` when there is none.
fn run_entries(mode_on: bool, chrome_path: &str, run_key: &str) -> Result<Option<bool>> {
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
    Ok(run_value)
}

// ---- the running browser ----------------------------------------------------------------------------------

/// The browser processes (no `--type=`) whose image is the configured Chrome and that run on its user-data
/// dir, each with a handle that can wait for its exit, and its command line. Processes this user cannot
/// open are skipped: they are not this user's browser.
fn browsers(browser: &Browser) -> Result<Vec<(u32, Owned, String)>> {
    let want = normalize(&browser.chrome_path);
    Ok(chrome_pids()?
        .into_iter()
        .filter_map(|pid| {
            // SAFETY: plain by-value call; the returned handle is owned by `Owned`. Limited information is
            // enough for the image path and the command line, and synchronize for the wait on its exit.
            let process =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) }
                    .ok()
                    .map(Owned)?;
            if normalize(&image_path(&process)?) != want {
                return None;
            }
            let line = command_line(&process)?;
            let ours = is_browser_process(&line)
                && on_user_data_dir(&line, &browser.user_data_dir, browser.default_dir, true);
            ours.then_some((pid, process, line))
        })
        .collect())
}

/// A Windows path for comparing: case and the separator's direction do not matter.
fn normalize(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

pub(crate) fn quit_browser(browser: &Browser) -> Result<Option<u32>> {
    if browser.chrome_path.is_empty() {
        return Err(WindowError::InvalidArgument("Quitting Chrome needs the configured Chrome path".into()));
    }
    let mut found = browsers(browser)?;
    let (pid, process, _) = match found.len() {
        0 => return Ok(None),
        1 => found.remove(0),
        n => {
            return Err(WindowError::Os {
                context: "quit the browser",
                message: format!("{n} browser processes run on that user-data dir"),
            });
        }
    };
    let rm = restart_manager()?;
    let created = created(&process)?;
    rm.shut_down(pid, created)?;
    let wait = u32::try_from(QUIT_WAIT.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: `process` is a handle this module opened with synchronize access and still owns.
    if unsafe { WaitForSingleObject(process.0, wait) } == WAIT_OBJECT_0 {
        return Ok(Some(pid));
    }
    Err(WindowError::Os {
        context: "quit the browser",
        message: format!("Chrome (pid {pid}) was asked to close but still runs after {QUIT_WAIT:?}"),
    })
}

/// When the process was created: with the pid, the Restart Manager's name for exactly this process, so a
/// pid reused since it was read is never the one shut down.
fn created(process: &Owned) -> Result<FILETIME> {
    let (mut created, mut exited, mut kernel, mut user) =
        (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: four valid, writable FILETIMEs and a process handle held open for the call.
    unsafe { GetProcessTimes(process.0, &raw mut created, &raw mut exited, &raw mut kernel, &raw mut user) }
        .map_err(|e| WindowError::Os { context: "read when Chrome started", message: e.message() })?;
    Ok(created)
}

// ---- System32 DLLs loaded at first use ---------------------------------------------------------------------

/// Loads a System32 DLL and keeps it loaded for the life of the process: the functions found in it are kept
/// in statics, so it is never freed.
fn system_dll(name: PCWSTR) -> Option<HMODULE> {
    // SAFETY: a NUL-terminated literal name, no file handle, and a flag that limits the search to System32.
    unsafe { LoadLibraryExW(name, None, LOAD_LIBRARY_SEARCH_SYSTEM32) }.ok()
}

/// The export `name` of `dll` as the function pointer type `T`.
///
/// # Safety
/// `T` must be an `unsafe extern "system" fn` type with the export's prototype, and `dll` must stay loaded
/// while the pointer is used (`system_dll` never frees one).
unsafe fn export<T: Copy>(dll: HMODULE, name: PCSTR) -> Option<T> {
    const { assert!(size_of::<T>() == size_of::<unsafe extern "system" fn() -> isize>()) };
    // SAFETY: `dll` is a loaded module's handle and `name` a NUL-terminated literal.
    let found = unsafe { GetProcAddress(dll, name) }?;
    // SAFETY: the caller promises `T` is this export's function pointer type; both are one pointer wide
    // (checked above).
    Some(unsafe { std::mem::transmute_copy::<unsafe extern "system" fn() -> isize, T>(&found) })
}

/// `RM_UNIQUE_PROCESS` (restartmanager.h).
#[repr(C)]
struct RmUniqueProcess {
    pid: u32,
    created: FILETIME,
}

type RmStartSession = unsafe extern "system" fn(session: *mut u32, flags: u32, key: *mut u16) -> u32;
type RmRegisterResources = unsafe extern "system" fn(
    session: u32,
    files: u32,
    file_names: *const PCWSTR,
    processes: u32,
    process_list: *const RmUniqueProcess,
    services: u32,
    service_names: *const PCWSTR,
) -> u32;
type RmShutdown = unsafe extern "system" fn(session: u32, flags: u32, progress: *const c_void) -> u32;
type RmEndSession = unsafe extern "system" fn(session: u32) -> u32;

/// `CCH_RM_SESSION_KEY + 1`: the session key the Restart Manager writes, with its NUL.
const RM_SESSION_KEY_LEN: usize = 33;

struct RestartManager {
    start: RmStartSession,
    register: RmRegisterResources,
    shutdown: RmShutdown,
    end: RmEndSession,
}

fn restart_manager() -> Result<&'static RestartManager> {
    static RM: OnceLock<Option<RestartManager>> = OnceLock::new();
    RM.get_or_init(|| {
        let dll = system_dll(w!("rstrtmgr.dll"))?;
        // SAFETY: each type is that export's prototype in restartmanager.h, in the system ABI, and
        // `system_dll` keeps the DLL loaded.
        unsafe {
            Some(RestartManager {
                start: export(dll, s!("RmStartSession"))?,
                register: export(dll, s!("RmRegisterResources"))?,
                shutdown: export(dll, s!("RmShutdown"))?,
                end: export(dll, s!("RmEndSession"))?,
            })
        }
    })
    .as_ref()
    .ok_or_else(|| WindowError::Os {
        context: "load the Restart Manager",
        message: "rstrtmgr.dll or one of its calls is missing".into(),
    })
}

impl RestartManager {
    /// Shuts `pid` (created at `created`) down as Windows does for a restart: it is told the session ends
    /// and closes itself, with no force, so Chrome saves its session as it goes.
    fn shut_down(&self, pid: u32, created: FILETIME) -> Result<()> {
        let fail = |step: &str, code: u32| WindowError::Os {
            context: "quit the browser",
            message: format!("the Restart Manager's {step} failed with error {code}"),
        };
        let mut session = 0u32;
        let mut key = [0u16; RM_SESSION_KEY_LEN];
        // SAFETY: a writable session id and a key buffer of the size the call writes.
        let started = unsafe { (self.start)(&raw mut session, 0, key.as_mut_ptr()) };
        if started != 0 {
            return Err(fail("RmStartSession", started));
        }
        let process = RmUniqueProcess { pid, created };
        // SAFETY: one valid RM_UNIQUE_PROCESS and no files or services, in the session just started.
        let mut result = match unsafe {
            (self.register)(session, 0, std::ptr::null(), 1, &raw const process, 0, std::ptr::null())
        } {
            0 => Ok(()),
            code => Err(fail("RmRegisterResources", code)),
        };
        if result.is_ok() {
            // SAFETY: the session started above; flags 0 ask without forcing; no progress callback.
            let code = unsafe { (self.shutdown)(session, 0, std::ptr::null()) };
            if code != 0 {
                result = Err(fail("RmShutdown", code));
            }
        }
        // SAFETY: ends the session started above, once.
        let _ = unsafe { (self.end)(session) };
        result
    }
}

// ---- shortcuts ---------------------------------------------------------------------------------------------

/// The folders to rewrite: the request's own, else the real ones in a real build. A test build never names
/// the real ones.
fn shortcut_dirs(request: &QuietRequest) -> Vec<ShortcutDir> {
    if let Some(dirs) = &request.shortcut_dirs {
        return dirs.clone();
    }
    if cfg!(feature = "test-seams") {
        return Vec::new();
    }
    real_shortcut_dirs(|name| std::env::var(name).ok(), registry_desktop())
}

/// Where Windows starts Chrome from by a shortcut: both Start menus, Quick Launch (its `User Pinned` folder
/// holds the taskbar's and Start's pinned items), and each Desktop. `var` reads the environment;
/// `registry_desktop` is the Desktop the shell uses (moved to `OneDrive`, say).
fn real_shortcut_dirs(
    var: impl Fn(&str) -> Option<String>,
    registry_desktop: Option<PathBuf>,
) -> Vec<ShortcutDir> {
    let base = |name: &str| var(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let mut dirs = Vec::new();
    let mut tree = |root: Option<PathBuf>, rel: &str, recurse: bool| {
        if let Some(root) = root {
            dirs.push(ShortcutDir { path: root.join(rel), recurse });
        }
    };
    tree(base("APPDATA"), r"Microsoft\Windows\Start Menu", true);
    tree(base("ProgramData"), r"Microsoft\Windows\Start Menu", true);
    tree(base("APPDATA"), r"Microsoft\Internet Explorer\Quick Launch", true);
    tree(base("USERPROFILE"), "Desktop", false);
    tree(registry_desktop, "", false);
    for one_drive in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
        tree(base(one_drive), "Desktop", false);
    }
    tree(base("PUBLIC"), "Desktop", false);
    dirs
}

/// The shell's Desktop folder from `User Shell Folders` (a `REG_EXPAND_SZ`, expanded here).
fn registry_desktop() -> Option<PathBuf> {
    let key =
        CURRENT_USER.open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders").ok()?;
    let text = String::try_from(key.get_value("Desktop").ok()?).ok()?;
    let path = expand_env(&text, |name| std::env::var(name).ok());
    (!path.contains('%')).then(|| PathBuf::from(path))
}

/// Every `.lnk` file in `dirs` (into subfolders for a `recurse` one), once each, never through a link or a
/// junction, at most [`MAX_SHORTCUTS`].
fn shortcut_files(dirs: &[ShortcutDir]) -> Vec<PathBuf> {
    fn walk(dir: &Path, depth: usize, seen: &mut HashSet<String>, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            if out.len() >= MAX_SHORTCUTS {
                return;
            }
            // Not followed: a directory entry's type is the link's own, and a junction reads as one.
            let Ok(ty) = entry.file_type() else { continue };
            let path = entry.path();
            if ty.is_symlink() {
                continue;
            }
            if ty.is_dir() {
                if depth > 0 {
                    walk(&path, depth - 1, seen, out);
                }
            } else if ty.is_file()
                && path.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
                && seen.insert(normalize(&path.to_string_lossy()))
            {
                out.push(path);
            }
        }
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for dir in dirs {
        walk(&dir.path, if dir.recurse { MAX_DEPTH } else { 0 }, &mut seen, &mut out);
    }
    out
}

/// What happened to one shortcut.
#[derive(Debug, PartialEq, Eq)]
enum Edit {
    /// It does not start the configured Chrome (or could not be read): left alone.
    Other,
    /// It starts the browser and is in the asked mode now.
    Done,
    /// It starts the browser but saving it failed (no write access, say): left as it was.
    Unwritable,
}

/// Rewrites every shortcut in `dirs` that starts the browser, on a thread of its own with its own COM
/// apartment. Returns how many start it and the ones that could not be saved.
fn shortcuts(dirs: &[ShortcutDir], on: bool, browser: &Browser) -> Result<(usize, Vec<String>)> {
    let files = shortcut_files(dirs);
    if files.is_empty() {
        return Ok((0, Vec::new()));
    }
    let browser = browser.clone();
    let thread = std::thread::Builder::new()
        .name("phantab-shortcuts".into())
        .spawn(move || {
            in_apartment(|com| {
                let mut done = 0;
                let mut unwritable = Vec::new();
                for file in &files {
                    match edit_shortcut(com, file, on, &browser)? {
                        Edit::Other => {}
                        Edit::Done => done += 1,
                        Edit::Unwritable => unwritable.push(file.display().to_string()),
                    }
                }
                Ok((done, unwritable))
            })
        })
        .map_err(|e| WindowError::Os { context: "start the shortcut thread", message: e.to_string() })?;
    thread.join().map_err(|_| WindowError::Os {
        context: "rewrite the shortcuts",
        message: "the shortcut thread panicked".into(),
    })?
}

type CoInitializeEx = unsafe extern "system" fn(reserved: *const c_void, flags: u32) -> HRESULT;
type CoUninitialize = unsafe extern "system" fn();
type CoCreateInstance = unsafe extern "system" fn(
    class: *const GUID,
    outer: *mut c_void,
    context: u32,
    interface: *const GUID,
    object: *mut *mut c_void,
) -> HRESULT;

/// objbase.h and combaseapi.h.
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const COINIT_DISABLE_OLE1DDE: u32 = 0x4;
const CLSCTX_INPROC_SERVER: u32 = 0x1;

struct Com {
    init: CoInitializeEx,
    uninit: CoUninitialize,
    create: CoCreateInstance,
}

fn com() -> Result<&'static Com> {
    static COM: OnceLock<Option<Com>> = OnceLock::new();
    COM.get_or_init(|| {
        let dll = system_dll(w!("ole32.dll"))?;
        // SAFETY: each type is that export's prototype in combaseapi.h, in the system ABI, and `system_dll`
        // keeps the DLL loaded.
        unsafe {
            Some(Com {
                init: export(dll, s!("CoInitializeEx"))?,
                uninit: export(dll, s!("CoUninitialize"))?,
                create: export(dll, s!("CoCreateInstance"))?,
            })
        }
    })
    .as_ref()
    .ok_or_else(|| WindowError::Os {
        context: "load COM",
        message: "ole32.dll or one of its calls is missing".into(),
    })
}

/// Runs `work` in a single-threaded COM apartment on this thread, which must be one of this module's own:
/// the apartment ends when `work` returns, after every interface it made was dropped.
fn in_apartment<T>(work: impl FnOnce(&Com) -> Result<T>) -> Result<T> {
    let com = com()?;
    // SAFETY: a null reserved pointer and valid flags; a success is paired with the CoUninitialize below on
    // this same thread.
    let hr = unsafe { (com.init)(std::ptr::null(), COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    if hr.is_err() {
        return Err(WindowError::Os {
            context: "start COM",
            message: windows::core::Error::from(hr).message(),
        });
    }
    let result = work(com);
    // SAFETY: matches the successful CoInitializeEx above, on the same thread; `work` has returned, so every
    // interface it made is dropped.
    unsafe { (com.uninit)() };
    result
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> Option<String> {
    let len = buf.iter().position(|&c| c == 0)?;
    // Filled to the end: it may have been cut short.
    (len + 1 < buf.len()).then(|| String::from_utf16_lossy(&buf[..len]))
}

/// Reads one shortcut and, when it starts the browser, puts it in the asked mode. Turning on touches only
/// shortcuts on the configured user-data dir (another dir is another browser); turning off takes the flag
/// from every shortcut that starts the configured Chrome, so nothing phantab added is left behind.
fn edit_shortcut(com: &Com, path: &Path, on: bool, browser: &Browser) -> Result<Edit> {
    let mut raw: *mut c_void = std::ptr::null_mut();
    // SAFETY: valid GUIDs that outlive the call, no outer object, and a writable out pointer.
    let hr = unsafe {
        (com.create)(&ShellLink, std::ptr::null_mut(), CLSCTX_INPROC_SERVER, &IShellLinkW::IID, &raw mut raw)
    };
    if hr.is_err() || raw.is_null() {
        return Err(WindowError::Os {
            context: "read the shortcuts",
            message: windows::core::Error::from(hr).message(),
        });
    }
    // SAFETY: CoCreateInstance succeeded for IShellLinkW's IID, so `raw` is an IShellLinkW reference that
    // this now owns (released on drop).
    let link = unsafe { IShellLinkW::from_raw(raw) };
    let file: IPersistFile =
        link.cast().map_err(|e| WindowError::Os { context: "read the shortcuts", message: e.message() })?;
    let name = wide(&path.to_string_lossy());
    // SAFETY: a NUL-terminated path that outlives the call.
    if unsafe { file.Load(PCWSTR(name.as_ptr()), STGM_READ) }.is_err() {
        return Ok(Edit::Other);
    }
    let mut buf = vec![0u16; LONGEST];
    // SAFETY: a writable buffer of its own length; no find data is asked for; flags 0 give the full path.
    if unsafe { link.GetPath(&mut buf, std::ptr::null_mut(), 0) }.is_err() {
        return Ok(Edit::Other);
    }
    let Some(target) = from_wide(&buf) else { return Ok(Edit::Other) };
    if target.is_empty() || normalize(&target) != normalize(&browser.chrome_path) {
        return Ok(Edit::Other);
    }
    buf.fill(0);
    // SAFETY: as above.
    if unsafe { link.GetArguments(&mut buf) }.is_err() {
        return Ok(Edit::Other);
    }
    let Some(args) = from_wide(&buf) else { return Ok(Edit::Other) };
    let command_line = format!("\"{target}\" {args}");
    if on && !on_user_data_dir(&command_line, &browser.user_data_dir, browser.default_dir, true) {
        return Ok(Edit::Other);
    }
    let new = rewrite_shortcut_args(&args, on);
    if new == args {
        return Ok(Edit::Done);
    }
    let new = wide(&new);
    // SAFETY: a NUL-terminated string that outlives the call. Save with no name writes back the file loaded.
    let saved =
        unsafe { link.SetArguments(PCWSTR(new.as_ptr())).and_then(|()| file.Save(PCWSTR::null(), true)) };
    Ok(if saved.is_ok() { Edit::Done } else { Edit::Unwritable })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("phantab-quiet-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A shortcut at `path` to `target` with `args`, made through the same COM calls.
    fn make_shortcut(path: &Path, target: &str, args: &str) {
        in_apartment(|com| {
            let mut raw: *mut c_void = std::ptr::null_mut();
            // SAFETY: as in `edit_shortcut`.
            let hr = unsafe {
                (com.create)(
                    &ShellLink,
                    std::ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IShellLinkW::IID,
                    &raw mut raw,
                )
            };
            assert!(hr.is_ok() && !raw.is_null());
            // SAFETY: as in `edit_shortcut`.
            let link = unsafe { IShellLinkW::from_raw(raw) };
            let file: IPersistFile = link.cast().unwrap();
            let (target, args, name) = (wide(target), wide(args), wide(&path.to_string_lossy()));
            // SAFETY: NUL-terminated strings that outlive the calls.
            unsafe {
                link.SetPath(PCWSTR(target.as_ptr())).unwrap();
                link.SetArguments(PCWSTR(args.as_ptr())).unwrap();
                file.Save(PCWSTR(name.as_ptr()), true).unwrap();
            }
            Ok(())
        })
        .unwrap();
    }

    fn arguments(path: &Path) -> String {
        in_apartment(|com| {
            let mut raw: *mut c_void = std::ptr::null_mut();
            // SAFETY: as in `edit_shortcut`.
            let _ = unsafe {
                (com.create)(
                    &ShellLink,
                    std::ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IShellLinkW::IID,
                    &raw mut raw,
                )
            };
            // SAFETY: as in `edit_shortcut`.
            let link = unsafe { IShellLinkW::from_raw(raw) };
            let file: IPersistFile = link.cast().unwrap();
            let name = wide(&path.to_string_lossy());
            let mut buf = vec![0u16; LONGEST];
            // SAFETY: as in `edit_shortcut`.
            unsafe {
                file.Load(PCWSTR(name.as_ptr()), STGM_READ).unwrap();
                link.GetArguments(&mut buf).unwrap();
            }
            Ok(from_wide(&buf).unwrap())
        })
        .unwrap()
    }

    /// The scratch "Chrome": any existing exe will do, as a shortcut's target must exist to keep its path.
    fn fake_chrome() -> String {
        let root = std::env::var("SystemRoot").unwrap();
        format!(r"{root}\System32\cmd.exe")
    }

    #[test]
    fn shortcuts_to_the_browser_round_trip_and_others_are_left_alone() {
        let dir = scratch("lnk");
        let nested = dir.join(r"Programs\Google");
        std::fs::create_dir_all(&nested).unwrap();
        let chrome = fake_chrome();
        let other = format!(r"{}\System32\notepad.exe", std::env::var("SystemRoot").unwrap());
        let plain = nested.join("Chrome.lnk");
        let profile = dir.join("Chrome profile.lnk");
        let elsewhere = dir.join("Chrome scratch.lnk");
        let notepad = dir.join("Notepad.lnk");
        make_shortcut(&plain, &chrome, "");
        make_shortcut(&profile, &chrome, r#"--profile-directory="Profile 1""#);
        make_shortcut(&elsewhere, &chrome, r#"--user-data-dir="C:\scratch" --no-first-run"#);
        make_shortcut(&notepad, &other, "--silent-debugger-extension-api-not");
        let before: Vec<String> =
            [&plain, &profile, &elsewhere, &notepad].iter().map(|p| arguments(p)).collect();

        let browser = Browser {
            chrome_path: chrome.to_uppercase().replace('\\', "/"),
            default_dir: true,
            ..Browser::default()
        };
        let tree = vec![ShortcutDir { path: dir.clone(), recurse: true }];
        let (count, unwritable) = shortcuts(&tree, true, &browser).unwrap();
        assert_eq!((count, unwritable.len()), (2, 0), "the default-dir ones start this browser");
        assert_eq!(arguments(&plain), "--silent-debugger-extension-api");
        assert_eq!(arguments(&profile), r#"--silent-debugger-extension-api --profile-directory="Profile 1""#);
        assert_eq!(arguments(&elsewhere), before[2], "another user-data dir is another browser");
        assert_eq!(arguments(&notepad), before[3]);
        assert_eq!(shortcuts(&tree, true, &browser).unwrap().0, 2, "again changes nothing");
        assert_eq!(arguments(&plain), "--silent-debugger-extension-api");

        let top_only = vec![ShortcutDir { path: dir.clone(), recurse: false }];
        assert_eq!(shortcuts(&top_only, false, &browser).unwrap().0, 2, "off: every one that starts Chrome");
        assert_eq!(arguments(&plain), "--silent-debugger-extension-api", "not into subfolders");
        shortcuts(&tree, false, &browser).unwrap();
        let after: Vec<String> =
            [&plain, &profile, &elsewhere, &notepad].iter().map(|p| arguments(p)).collect();
        assert_eq!(after, before, "a clean round trip");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_read_only_shortcut_is_reported_and_left_as_it_was() {
        let dir = scratch("ro");
        let chrome = fake_chrome();
        let path = dir.join("Chrome.lnk");
        make_shortcut(&path, &chrome, "--no-first-run");
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms.clone()).unwrap();
        let browser = Browser { chrome_path: chrome, default_dir: true, ..Browser::default() };
        let (count, unwritable) =
            shortcuts(&[ShortcutDir { path: dir.clone(), recurse: false }], true, &browser).unwrap();
        assert_eq!((count, unwritable), (0, vec![path.display().to_string()]));
        assert_eq!(arguments(&path), "--no-first-run");
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_walk_takes_lnk_files_once_and_no_deeper_than_asked() {
        let dir = scratch("walk");
        let deep = (0..=MAX_DEPTH + 1).fold(dir.clone(), |p, i| p.join(format!("d{i}")));
        std::fs::create_dir_all(&deep).unwrap();
        for p in
            [dir.join("a.LNK"), dir.join("b.txt"), dir.join("d0").join("c.lnk"), deep.join("too-deep.lnk")]
        {
            std::fs::write(p, b"").unwrap();
        }
        let both = [
            ShortcutDir { path: dir.clone(), recurse: true },
            ShortcutDir { path: dir.clone(), recurse: false },
        ];
        let mut names: Vec<String> = shortcut_files(&both)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["a.LNK", "c.lnk"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_real_folders_are_the_start_menus_quick_launch_and_the_desktops() {
        let env = |name: &str| match name {
            "APPDATA" => Some(r"C:\Users\a\AppData\Roaming".to_owned()),
            "ProgramData" => Some(r"C:\ProgramData".to_owned()),
            "USERPROFILE" => Some(r"C:\Users\a".to_owned()),
            "OneDrive" => Some(r"C:\Users\a\OneDrive".to_owned()),
            "OneDriveConsumer" => Some(String::new()),
            "PUBLIC" => Some(r"C:\Users\Public".to_owned()),
            _ => None,
        };
        let dirs = real_shortcut_dirs(env, Some(PathBuf::from(r"D:\Desk")));
        let shown: Vec<(String, bool)> =
            dirs.iter().map(|d| (d.path.display().to_string(), d.recurse)).collect();
        assert_eq!(
            shown,
            [
                (r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu".to_owned(), true),
                (r"C:\ProgramData\Microsoft\Windows\Start Menu".to_owned(), true),
                (r"C:\Users\a\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch".to_owned(), true),
                (r"C:\Users\a\Desktop".to_owned(), false),
                (r"D:\Desk\".to_owned(), false),
                (r"C:\Users\a\OneDrive\Desktop".to_owned(), false),
                (r"C:\Users\Public\Desktop".to_owned(), false),
            ]
        );
    }

    #[test]
    fn a_test_build_rewrites_no_real_shortcut() {
        assert_eq!(shortcut_dirs(&QuietRequest::default()), Vec::<ShortcutDir>::new());
        let mine = vec![ShortcutDir { path: PathBuf::from(r"C:\scratch"), recurse: false }];
        assert_eq!(
            shortcut_dirs(&QuietRequest { shortcut_dirs: Some(mine.clone()), ..QuietRequest::default() }),
            mine
        );
    }

    #[test]
    fn quitting_a_browser_that_does_not_run_is_nothing_to_do() {
        let browser = Browser {
            chrome_path: r"C:\nonexistent\phantab-test\chrome.exe".into(),
            user_data_dir: r"C:\nonexistent\phantab-test\data".into(),
            default_dir: false,
        };
        assert_eq!(quit_browser(&browser).unwrap(), None);
        assert!(restart_manager().is_ok(), "rstrtmgr.dll loads from System32");
    }
}
