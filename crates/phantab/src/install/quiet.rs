//! `--quiet-debugging on|off`: the marker the service reads, and the Run-key edit through phantab-window.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use phantab_window::QuietState;

use super::{CONFIG, QUIET_MARKER};

pub(crate) fn set(runtime: &Path, on: bool, run_key: Option<&str>, out: &mut dyn Write) -> Result<()> {
    if !cfg!(windows) {
        bail!("--quiet-debugging is Windows-only: it edits the browser's Windows sign-in (Run key) entry.");
    }
    let chrome = chrome_of(runtime)?;
    let marker = runtime.join(QUIET_MARKER);
    if on {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&marker)
            .with_context(|| format!("Could not write {}", marker.display()))?;
    } else {
        remove_marker(runtime)?;
    }
    let state = apply(on, &chrome, run_key)?;
    writeln!(
        out,
        "Quiet debugging {}: takes effect at the next Windows sign-in (sign out and in, or restart); reopening \
         Chrome from the taskbar does not carry it. Browser not restarted.",
        if on { "on" } else { "off" }
    )?;
    if state.run_value.is_none() {
        writeln!(
            out,
            "Chrome has no sign-in entry in the Run key yet, so nothing changed there. Chrome adds one while it \
             may run in the background (Settings > System); the service re-checks each time the bridge connects."
        )?;
    }
    Ok(())
}

/// The runtime's `chromeExecutable`: the browser whose Run entry quiet mode edits.
pub(crate) fn chrome_of(runtime: &Path) -> Result<String> {
    let path = runtime.join(CONFIG);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!("Quiet debugging needs an installed runtime: {} is missing", path.display())
    })?;
    let config: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("Could not read {}", path.display()))?;
    config
        .get("chromeExecutable")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("{} names no chromeExecutable", path.display()))
}

pub(crate) fn remove_marker(runtime: &Path) -> Result<()> {
    let marker = runtime.join(QUIET_MARKER);
    match std::fs::remove_file(&marker) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("Could not remove {}", marker.display()))
        }
        _ => Ok(()),
    }
}

/// Runs the async `quiet` on a runtime of its own, on its own thread, so it works from any caller,
/// including one already inside a tokio runtime.
pub(crate) fn apply(on: bool, chrome: &str, run_key: Option<&str>) -> Result<QuietState> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<QuietState> {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                Ok(runtime.block_on(phantab_window::platform().quiet(on, chrome, run_key))?)
            })
            .join()
            .map_err(|_| anyhow!("the quiet-debugging change stopped unexpectedly"))?
    })
}
