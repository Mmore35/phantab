//! A saved-login provider for tests: the control file says what
//! to answer. Its log holds what was asked, never a value.
//!
//! `phantab-fake-provider <control.json> <public key>`. Control fields: `log` (a
//! JSON-lines file each request is appended to), `values`, `answer` (a string is printed as is, anything
//! else as JSON), `delayMs`, `noise` (written to stderr), `wallIfUrl`, `badDigest`, `accountKey`. Two
//! more for phantab's own tests: `grandchild` (a heartbeat file: a child of this process writes to it every
//! 50 ms, to show a timeout kills the whole tree) and `envOut` (a file this process writes the names of
//! its environment variables to).
//!
//! `phantab-fake-provider --sleeper <heartbeat>`: the grandchild.

use std::io::{Read as _, Write as _};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--sleeper") {
        return sleeper(args.get(2).ok_or("no heartbeat file")?);
    }
    let control: Value =
        serde_json::from_str(&std::fs::read_to_string(args.get(1).ok_or("no control file")?)?)?;
    let public_key = args.last().ok_or("no public key")?;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: Value = serde_json::from_str(&input)?;
    if let Some(log) = control.get("log").and_then(Value::as_str) {
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
        file.write_all(format!("{request}\n").as_bytes())?;
    }
    if let Some(out) = control.get("envOut").and_then(Value::as_str) {
        let names: Vec<String> = std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
        std::fs::write(out, serde_json::to_string(&names)?)?;
    }
    if let Some(beat) = control.get("grandchild").and_then(Value::as_str) {
        std::process::Command::new(std::env::current_exe()?)
            .args(["--sleeper", beat])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
    }
    if let Some(ms) = control.get("delayMs").and_then(Value::as_u64).filter(|ms| *ms > 0) {
        std::thread::sleep(Duration::from_millis(ms));
    }
    if let Some(noise) = control.get("noise").and_then(Value::as_str) {
        eprintln!("{noise}");
    }
    let walled =
        control.get("wallIfUrl").and_then(Value::as_str).filter(|w| !w.is_empty()).is_some_and(|w| {
            request
                .get("urls")
                .and_then(Value::as_array)
                .is_some_and(|urls| urls.iter().any(|u| u.as_str().is_some_and(|u| u.contains(w))))
        });
    let answer = if walled {
        Some(json!({"status": "wall", "reason": "form-posts-elsewhere"}))
    } else {
        control.get("answer").cloned()
    };
    let line = match answer {
        // `if(answer)`: an empty string, null, false and 0 are no answer.
        Some(Value::String(raw)) if !raw.is_empty() => raw,
        Some(answer)
            if !answer.is_null() && answer != json!(false) && answer != json!(0) && !answer.is_string() =>
        {
            answer.to_string()
        }
        _ => {
            let digest = if control.get("badDigest").is_some_and(|b| b.as_bool() == Some(true)) {
                "0".repeat(64)
            } else {
                phantab::signin::request_digest(&request)
            };
            let account_key = control
                .get("accountKey")
                .and_then(Value::as_str)
                .filter(|k| !k.is_empty())
                .unwrap_or("account-one");
            let values = control.get("values").cloned().unwrap_or(Value::Null);
            let sealed = phantab::signin::seal(
                public_key,
                &json!({"digest": digest, "accountKey": account_key, "values": values}),
            )?;
            json!({"status": "ok", "sealed": sealed}).to_string()
        }
    };
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(line.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

/// Writes the time to `beat` every 50 ms for up to two minutes.
fn sleeper(beat: &str) -> Result<()> {
    let end = SystemTime::now() + Duration::from_secs(120);
    while SystemTime::now() < end {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        std::fs::write(beat, now.to_string())?;
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
