//! Names and locations every subcommand agrees on. Kept in one module so the service, the host, the
//! CLI and the installer can never disagree about where the runtime lives.

use std::path::{Path, PathBuf};

/// Native messaging host name registered with Chrome.
pub const HOST_NAME: &str = "dev.phantab.bridge";
/// Environment variable that overrides the runtime directory.
pub const RUNTIME_ENV: &str = "PHANTAB_RUNTIME";
/// Client id environment variable (the MCP server sets it for the CLI and child calls).
pub const CLIENT_ENV: &str = "PHANTAB_CLIENT";

/// The runtime directory: `PHANTAB_RUNTIME`; else the runtime this binary is installed in (see
/// [`installed_runtime`]); else the per-user platform default.
#[must_use]
pub fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(RUNTIME_ENV).filter(|v| !v.is_empty()) {
        return PathBuf::from(dir);
    }
    if let Some(dir) = std::env::current_exe().ok().as_deref().and_then(installed_runtime) {
        return dir;
    }
    default_runtime_dir()
}

/// The runtime that `exe` is installed in: `<runtime>/bin/<exe>` with the installer's `<runtime>/config.json`
/// beside `bin`. Chrome starts the native host without our environment (from Explorer, Finder or the Dock), so
/// the installed binary finds its runtime from its own location.
/// Both conditions are required so a binary that merely sits in some `bin` (`~/.cargo/bin`, `/usr/local/bin`)
/// never adopts that folder's parent as a runtime.
#[must_use]
pub fn installed_runtime(exe: &Path) -> Option<PathBuf> {
    let bin = exe.parent()?;
    if bin.file_name()? != "bin" {
        return None;
    }
    let runtime = bin.parent()?;
    runtime.join("config.json").is_file().then(|| runtime.to_path_buf())
}

#[cfg(windows)]
fn default_runtime_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map_or_else(|| home().join("AppData").join("Local"), PathBuf::from)
        .join("phantab")
}

#[cfg(target_os = "macos")]
fn default_runtime_dir() -> PathBuf {
    home().join("Library").join("Application Support").join("phantab")
}

#[cfg(not(any(windows, target_os = "macos")))]
fn default_runtime_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map_or_else(|| home().join(".local").join("state"), PathBuf::from)
        .join("phantab")
}

#[must_use]
pub fn home() -> PathBuf {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

#[must_use]
pub fn config_path() -> PathBuf {
    runtime_dir().join("config.json")
}

#[must_use]
pub fn endpoint_path() -> PathBuf {
    runtime_dir().join("endpoint.json")
}

/// The service's `/health` name.
pub const SERVICE_NAME: &str = "phantab";
/// The service protocol in `/health` and `endpoint.json`. A client refuses a service speaking another,
/// so a stale service is never mistaken for the new one.
pub const SERVICE_PROTOCOL: u64 = 1;
/// The bridge protocol the extension's hello must name.
pub const BRIDGE_PROTOCOL: u64 = 1;
/// The HTTP `Upgrade` token the native host uses to join `/bridge`. Pages cannot send a custom one.
pub const BRIDGE_UPGRADE: &str = "phantab-bridge";

/// The service's single-instance lock: an OS file lock held while the service lives, so a crash
/// never leaves a stale one (THREAT-MODEL SR-12). The file also records the pid, for operators.
#[must_use]
pub fn lock_path() -> PathBuf {
    runtime_dir().join("service.lock")
}

/// The unpacked extension folder the installer copies, named in the not-connected error.
#[must_use]
pub fn extension_dir() -> PathBuf {
    runtime_dir().join("extension")
}

/// The copy of the extension for one of `otherProfiles` (`dir`, a [`valid_profile_dir`] name): the
/// installed extension plus a `profile.json` naming `dir`, which the bridge's hello carries (SR-76). It is
/// `extension-profiles/<dir>/extension`, so its SR-74 record sits beside it in a folder of its own.
#[must_use]
pub fn profile_extension_dir(dir: &str) -> PathBuf {
    profile_extension_dir_in(&runtime_dir(), dir)
}

/// [`profile_extension_dir`] in the runtime `runtime`.
#[must_use]
pub fn profile_extension_dir_in(runtime: &Path, dir: &str) -> PathBuf {
    runtime.join("extension-profiles").join(dir).join("extension")
}

/// Whether `dir` can name a Chrome profile folder: `Default`, or `Profile <n>` (Chrome names every other
/// profile so), and nothing that could be a path, a flag or a second argument once it reaches a folder
/// name or `--profile-directory=`.
#[must_use]
pub fn valid_profile_dir(dir: &str) -> bool {
    dir == "Default"
        || dir
            .strip_prefix("Profile ")
            .is_some_and(|n| !n.is_empty() && n.len() <= 6 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Present while the owner has quiet debugging on.
#[must_use]
pub fn quiet_marker_path() -> PathBuf {
    runtime_dir().join("quiet-debugging.on")
}

/// Sign-in send counts and stops. No secret in it.
#[must_use]
pub fn sign_in_guard_path() -> PathBuf {
    runtime_dir().join("sign-in-guard.json")
}
