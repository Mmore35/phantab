//! Chrome profiles other than the usual one (THREAT-MODEL SR-76). The installer allows each by its folder
//! (`config.json` `otherProfiles`) and puts a copy of the bridge for it at
//! `runtime/extension-profiles/<folder>/extension`; a call names one with `profile` (its folder, or Chrome's name for
//! it). Every page lives in one profile for life, and everything about a page goes over that profile's link.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::{Check, Engine};
use crate::bridge::{self, Allowed, Profile, ProfileCheck, USUAL};
use crate::engine_api::{EngineError, EngineResult, NOT_CONNECTED};
use crate::paths;
use crate::util::node_fs_error;

/// How long a started profile has to bring its copy of the bridge up: Chrome's start, the extension's
/// worker and the native host's launch.
const START_WAIT: Duration = Duration::from_secs(15);
/// How long `guardrails: full` waits for the owner to open a window in a closed profile.
const OPEN_WAIT: Duration = Duration::from_secs(10);

/// The profile a call names, as its pages record it.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    /// [`USUAL`], or the folder of one of `otherProfiles`.
    pub profile: Profile,
    /// Chrome's name for it (its folder when Chrome gives none); `None` for the usual profile.
    pub name: Option<String>,
}

impl Target {
    fn usual() -> Self {
        Self { profile: Arc::from(USUAL), name: None }
    }
}

impl Engine {
    fn usual_folder(&self) -> &str {
        self.setup.config.profile_directory.as_deref().unwrap_or("")
    }

    /// The folder `profile` stands for.
    pub(crate) fn folder<'a>(&'a self, profile: &'a str) -> &'a str {
        if profile == USUAL { self.usual_folder() } else { profile }
    }

    fn profile_names(&self) -> Vec<(String, String)> {
        self.setup.config.user_data_dir.as_deref().map(bridge::profile_names).unwrap_or_default()
    }

    /// `Work (Profile 1)`, or the folder when Chrome gives it no name.
    pub(crate) fn profile_label(&self, profile: &str) -> String {
        let folder = self.folder(profile);
        match self.profile_names().into_iter().find(|(f, _)| f == folder) {
            Some((_, name)) => format!("{name} ({folder})"),
            None => folder.to_owned(),
        }
    }

    /// The profile `args.profile` names: absent or null is the usual profile, as is its own folder or name.
    pub(crate) fn target(&self, args: &Value) -> EngineResult<Target> {
        let arg = match args.get("profile") {
            None | Some(Value::Null) => return Ok(Target::usual()),
            Some(Value::String(s)) => s,
            Some(_) => return Err(EngineError("profile must be a string.".to_owned())),
        };
        let others = self.setup.config.allowed_other_profiles();
        let usual = self.usual_folder();
        let allowed: Vec<&str> = std::iter::once(usual).chain(others.iter().map(String::as_str)).collect();
        let names = self.profile_names();
        let folder = bridge::resolve_profile(&names, &allowed, arg).map_err(EngineError)?;
        if folder == usual {
            return Ok(Target::usual());
        }
        let name = names.into_iter().find(|(f, _)| *f == folder).map_or_else(|| folder.clone(), |(_, n)| n);
        Ok(Target { profile: Arc::from(folder), name: Some(name) })
    }

    /// [`Engine::target`] for `open`: an isolated-headless page runs in no Chrome profile.
    pub(crate) fn open_target(&self, args: &Value, mode: &str) -> EngineResult<Target> {
        if mode == "isolated-headless" {
            if args.get("profile").is_some_and(|p| !p.is_null()) {
                return Err(EngineError(
                    "An isolated-headless page runs in no Chrome profile; leave profile out.".to_owned(),
                ));
            }
            return Ok(Target::usual());
        }
        self.target(args)
    }

    /// The check before `profile`'s link is used (SR-19, SR-76, SR-74), as a call that owns its inputs, so
    /// it can run off the runtime's workers. It checks every allowed profile, so a copy in the wrong one is
    /// found whichever profile is asked for.
    pub(crate) fn profile_check(&self, profile: &str) -> impl FnOnce() -> ProfileCheck + Send + 'static {
        let config = &self.setup.config;
        let dir = config.user_data_dir.clone();
        let usual = self.usual_folder().to_owned();
        let which = self.folder(profile).to_owned();
        let mut dirs = vec![(usual, self.setup.extension_path.clone())];
        dirs.extend(config.allowed_other_profiles().into_iter().map(|o| {
            let p = paths::profile_extension_dir_in(&self.setup.runtime, &o);
            (o, p)
        }));
        let recorded = config.extension_files_recorded == Some(true);
        move || match &dir {
            Some(dir) => {
                let allowed: Vec<Allowed<'_>> =
                    dirs.iter().map(|(folder, path)| Allowed { folder, extension_dir: path }).collect();
                bridge::profiles_check(dir, &allowed, &which, &bridge::EXTENSION_ID, recorded).unwrap_or_else(
                    |e| ProfileCheck::Failed {
                        final_: true,
                        error: format!("Chrome profile check failed: {}", node_fs_error(&e, "scandir", dir)),
                    },
                )
            }
            None => ProfileCheck::Failed {
                final_: true,
                error: "Chrome profile check failed: config.json names no userDataDir".to_owned(),
            },
        }
    }

    /// `profile`'s check state, made on first use.
    pub(crate) fn check_mut<'a>(st: &'a mut super::State, profile: &Profile) -> &'a mut Check {
        st.checks.entry(profile.clone()).or_default()
    }

    /// Waits for `profile`'s link. The usual profile's comes by itself once Chrome runs. A closed allowed
    /// profile is started without a window (no window, as hidden pages open none), unless guardrails are
    /// `full`, which leave opening it to the owner.
    pub(crate) async fn link_up(&self, profile: &Profile) -> EngineResult<()> {
        let bridge = self.bridge();
        if **profile == *USUAL {
            if bridge.wait_connected_in(USUAL, Duration::from_secs(10)).await {
                return Ok(());
            }
            return Err(EngineError(format!(
                "{NOT_CONNECTED}{} (once). Headless tools do not inherit this login.",
                self.setup.extension_path.display()
            )));
        }
        if bridge.connected_in(profile) {
            return Ok(());
        }
        let label = self.profile_label(profile);
        if self.guardrails().full() {
            if bridge.wait_connected_in(profile, OPEN_WAIT).await {
                return Ok(());
            }
            return Err(EngineError(format!(
                "Chrome profile {label} is not open. Open a Chrome window in {label}, or set guardrails to light or parity so phantab starts it without a window."
            )));
        }
        let Some(chrome) = self.setup.config.chrome_executable.clone() else {
            return Err(EngineError(format!(
                "Chrome profile {label} is not open, and config.json names no chromeExecutable to start it with. Open a Chrome window in {label}."
            )));
        };
        let args =
            start_args(self.start_user_data_dir().as_deref(), profile, self.setup.quiet_marker.is_file())
                .map_err(|e| EngineError(format!("Could not start Chrome profile {label}: {e}")))?;
        (self.setup.start_profile.0)(&chrome, &args)
            .map_err(|e| EngineError(format!("Could not start Chrome profile {label}: {e}")))?;
        if bridge.wait_connected_in(profile, START_WAIT).await {
            return Ok(());
        }
        Err(EngineError(format!(
            "The phantab bridge copy for Chrome profile {label} has not connected. In that profile open chrome://extensions, turn on Developer mode and Load unpacked {} (once).",
            paths::profile_extension_dir_in(&self.setup.runtime, profile).display()
        )))
    }

    /// `--user-data-dir` for a start, only when `config.json`'s differs from Chrome's own: Chrome on Windows
    /// finds its running browser by that exact string, so naming the default one could miss it and fail.
    pub(crate) fn start_user_data_dir(&self) -> Option<PathBuf> {
        let dir = self.setup.config.user_data_dir.clone()?;
        (!crate::install::discover::is_default_user_data_dir(&dir)).then_some(dir)
    }
}

/// The arguments that start Chrome profile `folder` without a window: when Chrome runs, it hands them to
/// the running browser, which opens the profile and nothing else. With quiet debugging on, a Chrome this
/// starts gets [`phantab_window::QUIET_FLAG`] too, as its sign-in entry would give it. No shell, no other
/// flag: never a debugging port.
///
/// # Errors
/// `folder` is not a profile folder name ([`paths::valid_profile_dir`]).
pub(crate) fn start_args(
    user_data_dir: Option<&Path>,
    folder: &str,
    quiet: bool,
) -> io::Result<Vec<OsString>> {
    if !paths::valid_profile_dir(folder) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a Chrome profile folder"));
    }
    let mut args = Vec::new();
    if let Some(dir) = user_data_dir {
        let mut a = OsString::from("--user-data-dir=");
        a.push(dir);
        args.push(a);
    }
    args.push(format!("--profile-directory={folder}").into());
    args.push("--no-startup-window".into());
    if quiet {
        args.push(phantab_window::QUIET_FLAG.into());
    }
    Ok(args)
}

/// Starts `chrome` with `args` and leaves it running; a thread reaps it when it exits (at once, when it
/// handed them to a running Chrome).
///
/// The owner's Chrome lives for hours, so it is the one child that must never be started while a
/// headless launch has its pipe ends open to inheritance (`phantab_cdp::spawn_guard`, threat model R13):
/// it would hold that pipe open and hide a headless crash for as long as it ran.
///
/// # Errors
/// Chrome could not be started.
pub(crate) fn start_chrome(chrome: &Path, args: &[OsString]) -> io::Result<()> {
    let _no_pipe_ends = phantab_cdp::spawn_guard();
    let mut child = Command::new(chrome)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::start_args;
    use std::path::Path;

    /// R13: this file starts one process, the owner's Chrome, and takes the spawn guard first.
    #[test]
    fn the_owners_chrome_is_started_under_the_spawn_guard() {
        let source = include_str!("profiles.rs");
        let code = source.split("mod tests {").next().unwrap_or(source);
        assert_eq!(code.matches("Command::new(").count(), 1, "a second process is started here");
        let guard = code.find("phantab_cdp::spawn_guard();").expect("the guard is taken");
        let spawn = code.find("Command::new(").expect("Chrome is started");
        let body = code.find("fn start_chrome(").expect("start_chrome");
        assert!(body < guard && guard < spawn, "the guard is taken inside start_chrome, before the spawn");
    }

    #[test]
    fn start_args_name_the_profile_and_no_window() {
        let a = start_args(None, "Profile 1", false).unwrap();
        assert_eq!(a, ["--profile-directory=Profile 1", "--no-startup-window"]);
        let a = start_args(Some(Path::new("/x/y")), "Default", true).unwrap();
        assert_eq!(
            a,
            [
                "--user-data-dir=/x/y",
                "--profile-directory=Default",
                "--no-startup-window",
                phantab_window::QUIET_FLAG
            ]
        );
    }

    #[test]
    fn start_args_refuse_a_folder_that_is_not_a_profile() {
        for bad in
            ["", "..", "Profile 1 --remote-debugging-port=9222", "System Profile", "Profile x", "../Default"]
        {
            assert!(start_args(None, bad, false).is_err(), "{bad}");
        }
    }
}
