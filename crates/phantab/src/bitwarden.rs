//! `phantab bitwarden connect | status | disconnect` (docs/BITWARDEN.md § Connecting; THREAT-MODEL
//! SR-62, SR-63): the owner's own steps for the built-in Bitwarden source. They read `config.json`'s
//! `signInProvider.bitwarden` block and need no service.
//!
//! - `connect`, run by the owner in a terminal window: logs the CLI in when it is logged out (its own
//!   prompts, on the owner's terminal), else asks for the master password with echo off and runs
//!   `bw unlock --passwordenv`, the password only in that child's environment. Only the session key it
//!   prints is kept, protected by the OS ([`crate::signin::bitwarden::vault`]), pinned to the `bw` that
//!   made it: the configured command and the SHA-256 of its files ([`crate::signin::bitwarden::pin`]).
//!   Before any `bw` runs it shows the files it will pin, resolved, with their SHA-256, and goes on only
//!   when `yes` is typed at the terminal: running `connect` again pins the key to the `bw` configured now,
//!   so a `bw` a `config.json` edit planted shows there. A pipe cannot answer; a same-user process driving
//!   a pseudo-terminal or sending keys to the console can, but it still has no master password.
//! - `status`: whether a session is stored and what `bw status` says, as JSON. No email, no server. A
//!   stored key made with another `bw` (or by an earlier phantab) is `stale`: no `bw` gets it, and the
//!   owner is told to connect again.
//! - `disconnect`: removes the stored session and locks the CLI.

use std::io::IsTerminal as _;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::paths;
use crate::signin::bitwarden::cli::{self, Call, Ran};
use crate::signin::bitwarden::config::Config;
use crate::signin::bitwarden::pin::{self, Pin};
use crate::signin::bitwarden::vault::{OsVault, SessionKey, SessionVault};
use crate::signin::bitwarden::{VaultState, status};
use crate::signin::source::bitwarden_config;

/// The child-only variable `bw unlock --passwordenv` reads the master password from.
const PASSWORD_ENV: &str = "PHANTAB_BW_MASTER";
/// The exit code when the owner presses Ctrl+C at the password prompt: what a shell reports for a command
/// ended by SIGINT (128 + 2). The prompt has already restored echo and ended the line.
const CANCELLED_EXIT: i32 = 130;
/// How long a non-interactive `bw` step may take.
const STEP: Duration = Duration::from_secs(120);
/// How long the owner has for `bw login`'s prompts (email, password, two-step code).
const LOGIN: Duration = Duration::from_secs(600);

const USAGE: &str = "Usage: phantab bitwarden connect | status | disconnect";

/// What `connect` says when the `bw` it pinned changed before it was given the master password.
const CHANGED: &str = "The bw program changed while connecting, so it was not given your master password: \
                       run `phantab bitwarden connect` again.";

/// What `connect` says when the owner does not confirm the `bw` it shows.
const NOT_CONFIRMED: &str = "Not connected: you did not confirm that bw. If it is not the Bitwarden CLI you \
                             installed, check signInProvider.bitwarden.bw in config.json.";

/// What `connect` shows the owner before any `bw` runs: the files it pins, as they will run.
fn to_confirm(held: &pin::Held) -> String {
    format!(
        "phantab will connect this bw and give it your master password; it runs these files:\n{}",
        held.describe()
    )
}

/// What `connect` says when the configured `bw` cannot be pinned.
fn pin_error(config: &Config, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::InvalidInput {
        format!("phantab cannot pin the bw program, so it could not tell which bw has the session: {e}.")
    } else {
        format!("Could not read the bw program {} to pin it: {e}", pin::escaped(&config.program))
    }
}

/// The pin is still `pin`: checked again just before `bw` is given the master password or the owner's
/// typing, since its files may have changed after the pin was taken (on unix; on Windows `connect`
/// holds them shut). Answers the files this check opened, held: that `bw` is started by them, as every
/// run that carries a key is started by the files its own check held, so on unix a link repointed during
/// the prompt cannot send the password to a file the check did not hash.
async fn unchanged(config: &Config, pin: &Pin) -> Result<pin::Held, String> {
    match Pin::current(config).await {
        Ok((now, held)) if &now == pin => Ok(held),
        _ => Err(CHANGED.to_owned()),
    }
}

/// What `status` says to the owner when the stored key was made with another `bw`.
const RECONNECT: &str = "The stored Bitwarden session was made with another bw (signInProvider.bitwarden.bw \
                         changed, or the program was updated or replaced), so phantab no longer uses it: run \
                         `phantab bitwarden connect` again.";

fn state_word(state: VaultState) -> &'static str {
    match state {
        VaultState::Unlocked => "unlocked",
        VaultState::Locked => "locked",
        VaultState::Unauthenticated => "unauthenticated",
    }
}

/// Makes `<runtime>/bitwarden` and the CLI's data folder owner-only before the CLI writes there.
fn prepare(config: &Config, dir: &Path) -> Result<(), String> {
    phantab_window::secure_dir::lock_down(dir)
        .map_err(|e| format!("Could not prepare {}: {e}", dir.display()))?;
    phantab_window::secure_dir::lock_down(&config.data_dir)
        .map_err(|e| format!("Could not prepare {}: {e}", config.data_dir.display()))
}

/// `connect`, with the session store and the owner's answers given. `confirm` is shown what will be
/// pinned and says whether the owner confirmed it; `read_password` is only called when the CLI is logged
/// in and locked.
async fn connect_with(
    config: &Config,
    dir: &Path,
    vault: &dyn SessionVault,
    confirm: &mut dyn FnMut(&str) -> std::io::Result<bool>,
    read_password: &mut dyn FnMut() -> std::io::Result<Zeroizing<String>>,
) -> Result<(), String> {
    prepare(config, dir)?;
    // Pinned before any `bw` runs: the key goes only to the program hashed here (sec-creds-2). Its files
    // stay held to the end, so on Windows they cannot change while `connect` runs, and every `bw` below
    // is started by their resolved paths.
    let (pin, held) = Pin::current(config).await.map_err(|e| pin_error(config, &e))?;
    // What is pinned is shown before anything runs: a `bw` that a `config.json` edit planted shows here.
    // A terminal check cannot prove a person typed `yes` (a pseudo-terminal or sent keys can), so this
    // shows the owner what he is about to give his master password to; the password is the boundary.
    match confirm(&to_confirm(&held)) {
        Ok(true) => {}
        Ok(false) => return Err(NOT_CONFIRMED.to_owned()),
        Err(e) => return Err(format!("Could not read your answer: {e}")),
    }
    let held = Some(&held);
    let (state, _) = status(config, None, held, Instant::now() + STEP)
        .await
        .map_err(|_| "Could not run bw status: check signInProvider.bitwarden.bw.".to_owned())?;
    let printed = if state == VaultState::Unauthenticated {
        if let Some(server) = &config.server {
            let args = ["config", "server", server.as_str()];
            let call = Call { held, ..Call::new(&args, None) };
            if !matches!(cli::run(config, &call, Instant::now() + STEP).await, Ran::Out(_)) {
                return Err("bw config server failed.".into());
            }
        }
        let checked = unchanged(config, &pin).await?;
        eprintln!("The Bitwarden CLI is logged out: log in with its own prompts below.");
        let login = Call { interactive: true, held: Some(&checked), ..Call::new(&["login", "--raw"], None) };
        match cli::run(config, &login, Instant::now() + LOGIN).await {
            Ran::Out(out) => out,
            _ => return Err("bw login did not finish.".into()),
        }
    } else {
        let password = read_password().map_err(|e| format!("Could not read the master password: {e}"))?;
        if password.is_empty() {
            return Err("No master password given.".into());
        }
        let checked = unchanged(config, &pin).await?;
        let unlock = Call {
            args: &["unlock", "--passwordenv", PASSWORD_ENV, "--raw"],
            session: None,
            extra_env: &[(PASSWORD_ENV, password.as_str())],
            interactive: false,
            held: Some(&checked),
        };
        match cli::run(config, &unlock, Instant::now() + STEP).await {
            Ran::Out(out) => out,
            _ => return Err("Bitwarden did not unlock (a wrong master password?).".into()),
        }
    };
    let key = SessionKey::parse(&printed).ok_or("bw did not print a session key.")?.pinned(pin);
    match status(config, Some(&key), None, Instant::now() + STEP).await {
        Ok((VaultState::Unlocked, _)) => {}
        _ => return Err("The new session does not unlock the vault.".into()),
    }
    vault.store(&key).map_err(|e| format!("Could not store the session: {e}"))
}

/// `status`, as the JSON it prints.
async fn status_with(config: &Config, vault: &dyn SessionVault) -> Value {
    let (session, key) = match vault.load() {
        Ok(Some(key)) if pin::holds(config, &key).await => ("stored", Some(key)),
        // Made with another `bw`: `bw status` runs without it, and `run` tells the owner to connect again.
        Ok(Some(_)) => ("stale", None),
        Ok(None) => ("none", None),
        Err(_) => ("unreadable", None),
    };
    let state = match status(config, key.as_ref(), None, Instant::now() + STEP).await {
        Ok((state, _)) => state_word(state),
        Err(_) => "unknown",
    };
    json!({"source": "bitwarden", "protection": vault.protection(), "session": session, "vault": state})
}

/// `disconnect`, as the JSON it prints.
/// `config` is `None` when the config no longer names a usable bitwarden source: the stored session is
/// still removed (it and the CLI's data together decrypt the vault, THREAT-MODEL A9), and only the lock,
/// which needs the CLI's path, is skipped.
async fn disconnect_with(config: Option<&Config>, vault: &dyn SessionVault) -> Result<Value, String> {
    let key = vault.load().ok().flatten();
    let removed = vault.clear().map_err(|e| format!("Could not remove the stored session: {e}"))?;
    let session = if removed { "removed" } else { "none" };
    let Some(config) = config else {
        return Ok(
            json!({"session": session, "locked": false, "lock": "skipped: the config names no bitwarden CLI"}),
        );
    };
    // Locking also forgets the key in the CLI's own data, so a copy of the session is no use either. A key
    // made with another `bw` is not handed to this one: it locks without it.
    let key = match key {
        Some(key) if pin::holds(config, &key).await => Some(key),
        _ => None,
    };
    let locked = matches!(
        cli::run(config, &Call::new(&["lock"], key.as_ref()), Instant::now() + STEP).await,
        Ran::Out(_)
    );
    Ok(json!({"session": session, "locked": locked}))
}

/// Shows the owner what `connect` will pin and reads his answer from the terminal: only `yes` goes on.
fn ask_to_confirm(shown: &str) -> std::io::Result<bool> {
    eprint!("{shown}Is this the Bitwarden CLI you installed? Type yes to connect it: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().eq_ignore_ascii_case("yes"))
}

fn prompt_password() -> std::io::Result<Zeroizing<String>> {
    eprint!("Bitwarden master password (typing is hidden): ");
    let line = phantab_window::console::read_hidden_line();
    eprintln!();
    line
}

/// Runs `phantab bitwarden <args>`. Returns the exit code.
#[allow(clippy::print_stdout)] // stdout is the result
pub async fn run(args: &[String]) -> i32 {
    // SR-59, as the service does at start: no core file of this process, which holds the master password
    // (`connect`) or the session key (every verb). Before anything is read, so a crash at any later point
    // writes none (macOS `RLIMIT_CORE = 0`; Windows writes none unless WER LocalDumps is set, R11). The
    // `bw` children inherit the limit. Lowering a limit is always allowed, so it cannot fail in practice;
    // like the service, a refusal does not stop the command.
    let _ = phantab_window::process::disable_core_dumps();
    let verb = args.first().map(String::as_str);
    if !matches!(verb, Some("connect" | "status" | "disconnect")) || args.len() > 1 {
        eprintln!("{USAGE}");
        return 2;
    }
    let dir = paths::runtime_dir().join("bitwarden");
    let vault = OsVault::new(&dir);
    let config = crate::runtime::read_config().map_err(|e| format!("phantab: {e:#}")).and_then(|c| {
        bitwarden_config(c.sign_in_provider.as_ref(), &dir)
            .map_err(|e| format!("{}: {e}", paths::config_path().display()))
    });
    // disconnect removes the stored session even when the config no longer names the source.
    if verb == Some("disconnect") {
        if let Err(e) = &config {
            eprintln!("{e}");
        }
        return match disconnect_with(config.as_ref().ok(), &vault).await {
            Ok(v) => {
                println!("{v}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        };
    }
    let config = match config {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if verb != Some("connect") {
        let shown = status_with(&config, &vault).await;
        println!("{shown}");
        if shown["session"] == "stale" {
            eprintln!("{RECONNECT}");
        }
        return 0;
    }
    // Its questions (is this your bw, the master password) are asked only at a terminal: a pipe or an
    // agent's plain shell cannot answer them. A same-user process driving a pseudo-terminal (`script` on
    // macOS) or sending keys to a console on Windows can answer `yes`, but not with the master password.
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "connect asks you to confirm the bw program and reads your master password from the terminal: \
             run it yourself in a terminal window."
        );
        return 1;
    }
    let mut cancelled = false;
    let mut read = || prompt_password().inspect_err(|e| cancelled = phantab_window::console::is_cancelled(e));
    match connect_with(&config, &dir, &vault, &mut ask_to_confirm, &mut read).await {
        Ok(()) => {
            println!("{}", json!({"connected": true, "protection": vault.protection()}));
            0
        }
        Err(_) if cancelled => {
            eprintln!("Cancelled.");
            CANCELLED_EXIT
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// Test builds only: the three verbs over an in-memory session store holding the record `stored` (as an
/// OS store would: [`pinned`] makes one; a bare key is what an earlier phantab stored), with `password`
/// as what the owner types. Answers each verb's result and the record the store holds after it.
#[cfg(feature = "test-seams")]
pub mod test_seams {
    use super::{
        Config, Path, Pin, SessionKey, Value, Zeroizing, bitwarden_config, connect_with, disconnect_with,
        status_with,
    };
    use crate::signin::bitwarden::vault::MemoryVault;

    fn config(provider: &Value, dir: &Path) -> Result<Config, String> {
        bitwarden_config(Some(provider), dir).map_err(|e| e.to_string())
    }

    /// The record `connect` stores for `key` with the `bw` that `provider` names, as its files are now.
    ///
    /// # Errors
    /// A config that does not parse, a `bw` that cannot be read, or a key `bw` would not print.
    pub fn pinned(provider: &Value, dir: &Path, key: &str) -> Result<String, String> {
        let (pin, _) = Pin::open(&config(provider, dir)?).map_err(|e| e.to_string())?;
        let key = SessionKey::parse(key.as_bytes()).ok_or("not a session key")?.pinned(pin);
        let record = key.record().map_err(|e| e.to_string())?;
        std::str::from_utf8(&record).map(str::to_owned).map_err(|e| e.to_string())
    }

    /// `connect`, the owner confirming the `bw` it shows. `password` is `None` when the prompt must not be
    /// reached.
    ///
    /// # Errors
    /// What `connect` would print, or a config that does not parse.
    pub async fn connect(
        provider: &Value,
        dir: &Path,
        stored: Option<&str>,
        password: Option<&str>,
    ) -> (Result<(), String>, Option<String>) {
        let (out, stored, _) = connect_answering(provider, dir, stored, password, true).await;
        (out, stored)
    }

    /// `connect`, the owner answering `confirmed` to the `bw` it shows. Also answers what it showed, if
    /// it got that far.
    ///
    /// # Errors
    /// What `connect` would print, or a config that does not parse.
    pub async fn connect_answering(
        provider: &Value,
        dir: &Path,
        stored: Option<&str>,
        password: Option<&str>,
        confirmed: bool,
    ) -> (Result<(), String>, Option<String>, Option<String>) {
        let vault = MemoryVault::holding(stored);
        let mut shown = None;
        let mut confirm = |text: &str| {
            shown = Some(text.to_owned());
            Ok(confirmed)
        };
        let mut read = || {
            password
                .map(|p| Zeroizing::new(p.to_owned()))
                .ok_or_else(|| std::io::Error::other("the prompt was reached"))
        };
        let out = match config(provider, dir) {
            Ok(c) => connect_with(&c, dir, &vault, &mut confirm, &mut read).await,
            Err(e) => Err(e),
        };
        (out, vault.stored(), shown)
    }

    /// `connect` given `password`, with `typing` run while the owner would be typing it: after the pin
    /// was taken and before `bw` is given the password.
    ///
    /// # Errors
    /// What `connect` would print, or a config that does not parse.
    pub async fn connect_while_typing(
        provider: &Value,
        dir: &Path,
        password: &str,
        typing: &mut dyn FnMut(),
    ) -> (Result<(), String>, Option<String>) {
        let vault = MemoryVault::holding(None);
        let mut read = || {
            typing();
            Ok(Zeroizing::new(password.to_owned()))
        };
        let out = match config(provider, dir) {
            Ok(c) => connect_with(&c, dir, &vault, &mut |_| Ok(true), &mut read).await,
            Err(e) => Err(e),
        };
        (out, vault.stored())
    }

    /// `status`.
    ///
    /// # Errors
    /// A config that does not parse.
    pub async fn status(provider: &Value, dir: &Path, stored: Option<&str>) -> Result<Value, String> {
        Ok(status_with(&config(provider, dir)?, &MemoryVault::holding(stored)).await)
    }

    /// `disconnect`.
    ///
    /// # Errors
    /// What `disconnect` would print, or a config that does not parse.
    pub async fn disconnect(
        provider: &Value,
        dir: &Path,
        stored: Option<&str>,
    ) -> (Result<Value, String>, Option<String>) {
        let vault = MemoryVault::holding(stored);
        let out = disconnect_with(config(provider, dir).ok().as_ref(), &vault).await;
        (out, vault.stored())
    }
}
