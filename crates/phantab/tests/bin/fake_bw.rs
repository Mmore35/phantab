//! A stand-in for the Bitwarden CLI, for the built-in Bitwarden source's tests (docs/BITWARDEN.md §
//! Testing). It never touches a real vault: it answers from `fake-bw.json` in the folder
//! `BITWARDENCLI_APPDATA_DIR` names, and appends one JSON line per run to `fake-bw.log` there. The log
//! holds the arguments, the environment's variable *names*, whether the session and the master password
//! matched, the core-file limit it inherited (unix), and the path it was started by (`exe`: on Windows
//! the one its parent named, links and junctions unresolved); never a value.
//!
//! Control fields: `status` (`unlocked`, `locked`, `unauthenticated`), `session` (the key `unlock` and
//! `login` print, and the one the other commands need in `BW_SESSION`), `masterPassword`, `lastSync`,
//! `items` (what `list items` prints, whatever the URL: the real CLI matches more widely than phantab),
//! `totp` (`{id: code}`), `readBack` (`wrong`: `get item` prints another password than the one saved),
//! and per command name (`status`, `sync`, `list`, `get`, `create`, `edit`, `unlock`, `login`, `lock`,
//! `config`): `delayMs.<name>`, `huge` (a list of names that print 5 MiB), `malformed` (names that print
//! text that is not JSON), `fail` (names that exit 1). A successful `unlock` or `login` writes
//! `status: unlocked` back to the control file and `lock` writes `locked`, as the real CLI keeps its state.
//!
//! `create item` and `edit item <id>` read the encoded login from stdin, as the real CLI does when no
//! argument carries it, and write it into `items` (a new one gets the id `created-<n>`); the log says only
//! how many bytes came in (`stdinBytes`). `get item <id>` prints one item, `get totp <id>` its code.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn listed(control: &Value, field: &str, name: &str) -> bool {
    control.get(field).and_then(Value::as_array).is_some_and(|a| a.iter().any(|v| v.as_str() == Some(name)))
}

/// Writes `status` back to the control file, for the next run.
fn keep(dir: &std::path::Path, control: &Value, status: &str) -> Result<()> {
    let mut next = control.clone();
    next["status"] = json!(status);
    std::fs::write(dir.join("fake-bw.json"), next.to_string())?;
    Ok(())
}

fn main() -> Result<()> {
    let dir =
        PathBuf::from(std::env::var_os("BITWARDENCLI_APPDATA_DIR").ok_or("no BITWARDENCLI_APPDATA_DIR")?);
    let control: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("fake-bw.json"))?)?;
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let name = argv.first().cloned().unwrap_or_default();
    let want_session = control.get("session").and_then(Value::as_str).unwrap_or_default();
    let session = match std::env::var("BW_SESSION") {
        Ok(s) if s == want_session && !s.is_empty() => "match",
        Ok(_) => "wrong",
        Err(_) => "absent",
    };
    let password_env = argv.iter().position(|a| a == "--passwordenv").and_then(|i| argv.get(i + 1));
    let password = match password_env.map(std::env::var) {
        Some(Ok(p)) if Some(p.as_str()) == control.get("masterPassword").and_then(Value::as_str) => "match",
        Some(Ok(_)) => "wrong",
        _ => "absent",
    };
    let mut env: Vec<String> = std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
    env.sort();
    let core = core_limit();
    let exe = std::env::current_exe().map_or(Value::Null, |p| json!(p));
    // Only the writes read stdin; phantab gives every other command none.
    let mut input = Vec::new();
    if name == "create" || name == "edit" {
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut input)?;
    }
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("fake-bw.log"))?;
    log.write_all(
        format!(
            "{}\n",
            json!({
                "argv": argv, "env": env, "session": session, "password": password, "core": core, "exe": exe,
                "stdinBytes": input.len(),
            })
        )
        .as_bytes(),
    )?;
    drop(log);

    let interactive = name == "login";
    if !interactive && !argv.iter().any(|a| a == "--nointeraction") {
        std::process::exit(9);
    }
    if let Some(ms) = control.pointer(&format!("/delayMs/{name}")).and_then(Value::as_u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
    if listed(&control, "fail", &name) {
        eprintln!("fake failure for {name}");
        std::process::exit(1);
    }
    let mut out = std::io::stdout().lock();
    if listed(&control, "huge", &name) {
        let block = vec![b' '; 1 << 16];
        for _ in 0..80 {
            out.write_all(&block)?;
        }
        out.flush()?;
        return Ok(());
    }
    if listed(&control, "malformed", &name) {
        out.write_all(b"{not json")?;
        return Ok(());
    }
    if name == "create" || name == "edit" {
        if session != "match"
            || control.get("status").and_then(Value::as_str).unwrap_or("unlocked") != "unlocked"
        {
            eprintln!("Vault is locked.");
            std::process::exit(1);
        }
        write_item(&dir, &control, &argv, &input, &mut out)?;
        out.flush()?;
        return Ok(());
    }
    answer(&dir, &control, &argv, session == "match", password == "match", &mut out)?;
    out.flush()?;
    Ok(())
}

/// `create item` / `edit item <id>`: the decoded login into `items`, written back, and printed.
fn write_item(
    dir: &std::path::Path,
    control: &Value,
    argv: &[String],
    input: &[u8],
    out: &mut impl Write,
) -> Result<()> {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.decode(input.trim_ascii())?;
    let mut item: Value = serde_json::from_slice(&text)?;
    let mut next = control.clone();
    let items = next.get_mut("items").and_then(Value::as_array_mut);
    let mut fresh = Vec::new();
    let items = match items {
        Some(items) => items,
        None => &mut fresh,
    };
    if argv.first().map(String::as_str) == Some("edit") {
        let id = argv.get(2).cloned().unwrap_or_default();
        let Some(at) = items.iter().position(|i| i.get("id").and_then(Value::as_str) == Some(id.as_str()))
        else {
            eprintln!("Not found.");
            std::process::exit(1);
        };
        item["id"] = json!(id);
        items[at] = item.clone();
    } else {
        item["id"] = json!(format!("created-{}", items.len() + 1));
        items.push(item.clone());
    }
    let items = items.clone();
    next["items"] = Value::Array(items);
    std::fs::write(dir.join("fake-bw.json"), next.to_string())?;
    writeln!(out, "{item}")?;
    Ok(())
}

/// The core-file limit this run inherited, as `ulimit -c` prints it (`0`, `unlimited`), so a test sees
/// whether its parent turned core dumps off. Unix only: Windows has no such limit.
fn core_limit() -> Value {
    #[cfg(unix)]
    {
        std::process::Command::new("/bin/sh")
            .args(["-c", "ulimit -c"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map_or(Value::Null, |s| json!(s.trim()))
    }
    #[cfg(not(unix))]
    {
        Value::Null
    }
}

/// What one command prints, on an unlocked or locked vault.
fn answer(
    dir: &std::path::Path,
    control: &Value,
    argv: &[String],
    session_matches: bool,
    password_matches: bool,
    out: &mut impl Write,
) -> Result<()> {
    let name = argv.first().map(String::as_str).unwrap_or_default();
    let want_session = control.get("session").and_then(Value::as_str).unwrap_or_default();
    let status = control.get("status").and_then(Value::as_str).unwrap_or("unlocked");
    let unlocked = status == "unlocked" && session_matches;
    let locked = || -> Result<()> {
        eprintln!("Vault is locked.");
        std::process::exit(1);
    };
    match name {
        "status" => {
            let shown = if status == "unlocked" && !unlocked { "locked" } else { status };
            let line = json!({
                "serverUrl": null,
                "lastSync": control.get("lastSync").cloned().unwrap_or(Value::Null),
                "userEmail": "fixture-owner@example.test",
                "userId": "00000000-0000-4000-8000-000000000000",
                "status": shown,
            });
            writeln!(out, "{line}")?;
        }
        "sync" => {
            if !unlocked {
                return locked();
            }
            writeln!(out, "Syncing complete.")?;
        }
        "list" => {
            if !unlocked {
                return locked();
            }
            writeln!(out, "{}", control.get("items").cloned().unwrap_or(json!([])))?;
        }
        "get" => {
            if !unlocked {
                return locked();
            }
            let id = argv.get(2).map(String::as_str).unwrap_or_default();
            if argv.get(1).map(String::as_str) == Some("item") {
                let found = control.get("items").and_then(Value::as_array).and_then(|items| {
                    items.iter().find(|i| i.get("id").and_then(Value::as_str) == Some(id)).cloned()
                });
                let Some(mut item) = found else {
                    eprintln!("Not found.");
                    std::process::exit(1);
                };
                if control.get("readBack").and_then(Value::as_str) == Some("wrong")
                    && let Some(Value::String(p)) = item.pointer_mut("/login/password")
                {
                    p.push('x');
                }
                writeln!(out, "{item}")?;
                return Ok(());
            }
            let Some(code) = control.pointer(&format!("/totp/{id}")).and_then(Value::as_str) else {
                eprintln!("No TOTP available for this login.");
                std::process::exit(1);
            };
            write!(out, "{code}")?;
        }
        "unlock" => {
            if !password_matches {
                eprintln!("Invalid master password.");
                std::process::exit(1);
            }
            keep(dir, control, "unlocked")?;
            write!(out, "{want_session}")?;
        }
        "login" => {
            keep(dir, control, "unlocked")?;
            write!(out, "{want_session}")?;
        }
        "lock" => {
            keep(dir, control, "locked")?;
            writeln!(out, "Your vault is locked.")?;
        }
        "config" => writeln!(out, "Saved setting `config`.")?,
        _ => std::process::exit(2),
    }
    Ok(())
}
