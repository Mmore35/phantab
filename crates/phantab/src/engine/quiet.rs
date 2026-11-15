//! Quiet debugging: Chrome's debugging bar gone from agent pages ([`phantab_window::QUIET_FLAG`] on the
//! owner's Chrome), and `restart_quiet`, the owner's way to give the Chrome now running the flag.
//!
//! The flag counts only on the command line that starts the browser process. So it goes on everything
//! that starts the owner's Chrome (the Windows sign-in entry and shortcuts, the macOS `LaunchAgent`),
//! again at each connect, as Chrome may rewrite its own entry when it starts. A Chrome that already runs
//! without it keeps the bar until it restarts: status says so, and `restart_quiet` restarts it on the
//! owner's word, never by itself (THREAT-MODEL SR-49).

use std::ffi::OsString;
use std::time::Duration;

use phantab_window::{Browser, QUIET_FLAG, QUIT_WAIT, QuietRequest, QuietState};
use serde_json::{Map, Value, json};

use super::Engine;
use crate::bridge::USUAL;
use crate::engine_api::{EngineError, EngineResult};

/// The note status adds while the running Chrome lacks the flag.
pub(crate) const QUIET_PENDING: &str = "Chrome's debugging bar still shows on agent pages: the Chrome now running started without the flag, and the bar's X or Cancel ends an agent page. A new window doesn't change that, as hidden agent windows keep the same Chrome running. To fix it now, the owner runs `phantab chrome restart-quiet`: Chrome closes, saving every window and tab, and reopens them with the flag. Otherwise the next Chrome start picks the flag up.";
/// Added to the note when some shortcut could not be changed.
const UNWRITABLE: &str = "Some shortcuts that start Chrome could not be changed (`unwritable`): a Chrome started from one of them shows the bar again.";
/// How long a restarted Chrome has to reconnect the bridge before the answer reports what it found.
const RECONNECT_WAIT: Duration = Duration::from_secs(20);
/// All of `restart_quiet`, from its first check to its answer: the quit (at most [`QUIT_WAIT`]), the start,
/// and the reconnect wait, which gets what is left, up to [`RECONNECT_WAIT`]. Inside the CLI's call, so the
/// owner always gets the answer rather than a timeout while Chrome is half restarted.
const RESTART_BUDGET: Duration = Duration::from_secs(80);
const _: () = assert!(
    QUIT_WAIT.as_secs() + RECONNECT_WAIT.as_secs() + 10 <= RESTART_BUDGET.as_secs()
        && RESTART_BUDGET.as_secs() + 5 <= crate::runtime::RPC_TIMEOUT.as_secs()
);
/// Chrome's markers around the `chrome://flags` switches it adds to its own command line at each start: a
/// restart leaves them, and what is between, to Chrome, which adds them again.
const FLAGS_BEGIN: &str = "--flag-switches-begin";
const FLAGS_END: &str = "--flag-switches-end";
/// Switches of a start at sign-in that would keep a restarted Chrome from opening its windows.
const SIGN_IN_ONLY: [&str; 2] = ["--no-startup-window", "--win-session-start"];
const RESTORE: &str = "--restore-last-session";

impl Engine {
    /// The browser quiet acts on: `chromeExecutable` on `userDataDir` (Chrome's own default when the config
    /// names none). Only that one browser is ever counted, quit or started.
    pub(crate) fn quiet_browser(&self) -> Browser {
        let config = &self.setup.config;
        let start_dir = self.start_user_data_dir();
        let user_data_dir = config.user_data_dir.clone().or_else(crate::install::discover::user_data_dir);
        Browser {
            chrome_path: config
                .chrome_executable
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            user_data_dir: user_data_dir.map(|d| d.display().to_string()).unwrap_or_default(),
            default_dir: start_dir.is_none(),
        }
    }

    async fn quiet_now(&self) -> Result<QuietState, EngineError> {
        let request = QuietRequest::new(true, self.quiet_browser());
        let state = self.windows.quiet(&request).await.map_err(EngineError::from)?;
        self.st().quiet = Some(serde_json::to_value(&state).unwrap_or(Value::Null));
        Ok(state)
    }

    /// Puts the flag back on while the owner has quiet debugging on: Chrome may rewrite its own sign-in
    /// entry when it starts, so this runs at each connect of the usual profile.
    pub(crate) fn apply_quiet(&self) {
        if !self.setup.quiet_marker.is_file() {
            self.st().quiet = None;
            return;
        }
        let Some(me) = self.arc() else { return };
        tokio::spawn(async move {
            if let Err(e) = me.quiet_now().await {
                me.st().quiet = Some(json!({ "error": e.0 }));
            }
        });
    }

    /// `quietDebugging` in status: what the last apply found, with a note when the bar still shows.
    pub(crate) fn quiet_status(q: &Map<String, Value>) -> Map<String, Value> {
        let mut q = q.clone();
        let mut note = Vec::new();
        if q.get("running") == Some(&Value::Bool(false)) {
            note.push(QUIET_PENDING);
        }
        if q.get("unwritable").and_then(Value::as_array).is_some_and(|u| !u.is_empty()) {
            note.push(UNWRITABLE);
        }
        if !note.is_empty() {
            q.insert("note".into(), Value::String(note.join(" ")));
        }
        q
    }

    /// `restart_quiet`: the owner's Chrome, running without the flag, closes the way a system restart
    /// closes it (saving every window and tab) and starts again with the flag and `--restore-last-session`.
    /// Only the configured Chrome on the configured user-data dir, found by its path and that dir; never
    /// another Chrome, never by a process name. It refuses while agent pages are open, as they would end.
    /// Exclusive in the queue, so no page opens meanwhile.
    pub(crate) async fn restart_quiet(&self) -> EngineResult {
        let deadline = tokio::time::Instant::now() + RESTART_BUDGET;
        if !self.setup.quiet_marker.is_file() {
            return Err(EngineError(
                "Quiet debugging is off, so a restart would not hide the bar. Turn it on first: phantab install --quiet-debugging on".to_owned(),
            ));
        }
        let Some(chrome) = self.setup.config.chrome_executable.clone() else {
            return Err(EngineError(
                "config.json names no chromeExecutable, so phantab cannot restart Chrome. Close Chrome and open it again yourself.".to_owned(),
            ));
        };
        {
            let st = self.st();
            if !st.records.is_empty() || !st.creating.is_empty() {
                return Err(EngineError(
                    "Agent pages are open, and restarting Chrome would end them. Close them (and finish any owner hand-off) first.".to_owned(),
                ));
            }
        }
        // A kept hidden window would come back as a visible blank window.
        self.close_spare(|_| true).await;
        let before = self.quiet_now().await?;
        match before.running {
            Some(true) => {
                return Ok(
                    json!({ "restarted": false, "running": true, "reason": "The Chrome running already has the flag." }),
                );
            }
            None => {
                return Ok(
                    json!({ "restarted": false, "running": null, "reason": "No Chrome runs on the configured profile now; the next start picks the flag up." }),
                );
            }
            Some(false) => {}
        }
        let browser = self.quiet_browser();
        // The link up now is the Chrome about to close: only a link after it is the restarted one.
        let old_link = self.bridge().link_id_in(USUAL);
        let quit = self
            .windows
            .quit_browser(&browser)
            .await
            .map_err(|e| EngineError(format!("Chrome did not close, so nothing was restarted: {e}")))?;
        let running_args = quit.as_ref().map(|q| q.args.as_slice()).unwrap_or_default();
        let args = restart_args(self.start_user_data_dir().as_deref(), running_args);
        (self.setup.start_profile.0)(&chrome, &args).map_err(|e| {
            EngineError(format!("Chrome closed but could not be started again: {e}. Open Chrome yourself; it offers to restore its windows."))
        })?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let reconnected = self.bridge().wait_new_link_in(USUAL, old_link, RECONNECT_WAIT.min(left)).await;
        let after = self.quiet_now().await?;
        Ok(json!({
            "restarted": true,
            "quitPid": quit.map(|q| q.pid),
            "reconnected": reconnected,
            "running": after.running,
        }))
    }
}

/// The arguments that start the owner's Chrome again: the switches it ran with (`running`, so the owner's
/// own, `--proxy-server=…` say, are kept), less Chrome's `chrome://flags` block, the sign-in start's
/// `--no-startup-window` and anything that is not a switch (a URL it opened); then `--user-data-dir` when
/// those name none and it is not Chrome's default (as [`super::profiles::start_args`]), the flag, and the
/// session Chrome saved as it closed.
pub(crate) fn restart_args(user_data_dir: Option<&std::path::Path>, running: &[String]) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    let mut in_flags = false;
    let mut names_dir = false;
    for arg in running {
        // What follows is the command line's positional part (URLs and files).
        if arg == "--" || arg == "--single-argument" {
            break;
        }
        if in_flags {
            in_flags = arg != FLAGS_END;
            continue;
        }
        if arg == FLAGS_BEGIN {
            in_flags = true;
            continue;
        }
        if !arg.starts_with('-')
            || SIGN_IN_ONLY.contains(&arg.as_str())
            || arg == QUIET_FLAG
            || arg == RESTORE
        {
            continue;
        }
        names_dir |= arg.to_ascii_lowercase().starts_with("--user-data-dir=");
        args.push(arg.into());
    }
    if let Some(dir) = user_data_dir.filter(|_| !names_dir) {
        let mut a = OsString::from("--user-data-dir=");
        a.push(dir);
        args.insert(0, a);
    }
    args.push(QUIET_FLAG.into());
    args.push(RESTORE.into());
    args
}
