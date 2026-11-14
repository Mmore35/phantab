//! `phantab <method> ['<json>']` (cli.mjs): one service call from a shell, its result on stdout.
//! `doctor` is `status`; `sign-in-clear <host|all>` edits the guard file without the service;
//! `check-wait <token>` is a verification hand-off's wake command.

use std::time::Duration;

use serde_json::{Value, json};

use crate::paths;
use crate::runtime::rpc;
use crate::sign_in_guard::{GuardError, clear_guard};

/// Methods that act on no page, so they need no stable client id.
const CLIENTLESS: &[&str] = &["doctor", "status", "connect", "tabs", "shutdown"];

/// The task id a CLI caller works under: ours, then the agent session's own.
fn client_id() -> Option<String> {
    [paths::CLIENT_ENV, "CODEX_THREAD_ID", "CODEX_SESSION_ID", "CLAUDE_SESSION_ID"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// Whether stdin is a terminal. A test build (`test-seams`) also takes `PHANTAB_TEST_TERMINAL=1`, so the
/// CLI tests can run `sign-in-clear` from a pipe.
fn at_terminal() -> bool {
    #[cfg(feature = "test-seams")]
    if std::env::var("PHANTAB_TEST_TERMINAL").as_deref() == Ok("1") {
        return true;
    }
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// The longest a wake waits: a check's 15-minute expiry plus a minute. Its end has come by then.
pub(crate) const WAKE_LIMIT: Duration = Duration::from_mins(16);
/// Service calls a wake may lose in a row (a busy machine) before it counts the service as gone.
const WAKE_RETRIES: u32 = 3;

/// `phantab check-wait <token>`: the `wake` command a verification hand-off gives its agent. It
/// returns the moment the check ends, prints one line, and exits 0 whatever the end, since
/// the agent's harness wakes the agent on any exit. A service that is down counts as `gone`.
#[allow(clippy::print_stdout)] // stdout is the result
async fn check_wait(watch: &str) -> i32 {
    if watch.len() != 48 || !watch.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!("check-wait takes the token from a verification's wake command.");
        return 1;
    }
    let deadline = tokio::time::Instant::now() + WAKE_LIMIT;
    let mut lost = 0;
    let line = loop {
        match rpc("check_wait", json!({ "watch": watch }), "operator", false).await {
            Ok(v) => {
                lost = 0;
                let state = v.get("state").and_then(Value::as_str).unwrap_or("gone");
                let live = matches!(state, "checking" | "with-owner");
                if !live || tokio::time::Instant::now() >= deadline {
                    break match v.get("pageId").and_then(Value::as_str) {
                        Some(page) => format!("verification {state} on page {page}"),
                        None => format!("verification {state}"),
                    };
                }
            }
            Err(_) if lost + 1 < WAKE_RETRIES => {
                lost += 1;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(_) => break "verification gone: the browser service is not running".to_owned(),
        }
    };
    println!("{line}");
    0
}

/// Exit code for Ctrl+C at the prompt, as `bitwarden connect` and a shell use.
const CANCELLED_EXIT: i32 = 130;

/// What the owner types at the console, echo off, read as `bitwarden connect` reads the master password
/// (it refuses a stdin that is not a console). A test build (`test-seams`) takes `PHANTAB_TEST_TYPED` as
/// the line.
fn typed_line() -> std::io::Result<zeroize::Zeroizing<String>> {
    #[cfg(feature = "test-seams")]
    if let Ok(line) = std::env::var("PHANTAB_TEST_TYPED") {
        return Ok(zeroize::Zeroizing::new(line));
    }
    phantab_window::console::read_hidden_line()
}

/// The owner types the host (or `all`) being cleared, exactly. `Err` is the exit code when they did not.
fn owner_confirms(target: &str) -> Result<(), i32> {
    eprint!("To lift the stop, type {target} and press Enter (typing is hidden): ");
    let typed = typed_line();
    eprintln!();
    match typed {
        Ok(line) if line.trim() == target => Ok(()),
        Ok(_) => {
            eprintln!("That was not {target}: nothing was cleared.");
            Err(1)
        }
        Err(e) if phantab_window::console::is_cancelled(&e) => {
            eprintln!("Cancelled.");
            Err(CANCELLED_EXIT)
        }
        Err(e) => {
            eprintln!("Could not read what you typed ({e}): nothing was cleared.");
            Err(1)
        }
    }
}

/// Runs the CLI with the arguments after the program name. Returns the exit code.
#[allow(clippy::print_stdout)] // stdout is the result
pub async fn run(args: &[String]) -> i32 {
    let method = args.first().map_or("doctor", String::as_str);
    let json = args.get(1).map_or("{}", String::as_str);
    // A plain host or `all`, not JSON. Reads no service: a damaged guard file is one reason to run it.
    // Only on the owner's word.
    if method == "sign-in-clear" {
        if json == "{}" {
            eprintln!("Name a host, or all.");
            return 1;
        }
        // THREAT-MODEL SR-46: lifting a stop is the owner's. The terminal and the typed-back target stop a
        // plain non-interactive shell and a clear run by mistake. A determined process running as the owner
        // can still answer them (a pseudo-terminal, sent keys) or delete the guard file (R20): guard state
        // held in the service is a follow-up.
        if !at_terminal() {
            eprintln!(
                "sign-in-clear lifts a sign-in stop, which is yours to do: run it yourself in a terminal window."
            );
            return 1;
        }
        if let Err(code) = owner_confirms(json) {
            return code;
        }
        return match clear_guard(&paths::sign_in_guard_path(), json).await {
            Ok(v) => {
                println!("{v}");
                0
            }
            Err(GuardError::Damaged) => {
                eprintln!("The guard file is damaged: run sign-in-clear all.");
                1
            }
            Err(GuardError::Io(_)) => {
                eprintln!("Could not write the guard file.");
                1
            }
            Err(e @ GuardError::Invalid(_)) => {
                eprintln!("{e}");
                1
            }
        };
    }
    // A plain token, not JSON; acts on no page, so it needs no client id.
    if method == "check-wait" {
        return check_wait(args.get(1).map_or("", String::as_str)).await;
    }
    let client = client_id();
    if client.is_none() && !CLIENTLESS.contains(&method) {
        eprintln!("Set PHANTAB_CLIENT to a unique stable task ID for CLI page operations.");
        return 1;
    }
    let args: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", crate::util::json_error(json.as_bytes(), &e));
            return 1;
        }
    };
    if method == "doctor" {
        // SR-53: drift since install, beside the service's status; stdout stays the service's answer.
        match crate::install::drift(&paths::runtime_dir()) {
            Ok(found) => found.iter().for_each(|line| eprintln!("Drift: {line}")),
            Err(e) => eprintln!("Could not check the install for drift: {e:#}"),
        }
    }
    let method = if method == "doctor" { "status" } else { method };
    let client = client.map_or_else(|| "operator".to_owned(), |c| format!("cli:{c}"));
    if !crate::util::client_id_ok(&client) {
        // SR-26: the service would refuse it; say why before any call.
        eprintln!(
            "The client ID must be at most {} characters with its cli: prefix.",
            crate::util::CLIENT_ID_MAX
        );
        return 1;
    }
    match rpc(method, args, &client, true).await {
        Ok(result) => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}
