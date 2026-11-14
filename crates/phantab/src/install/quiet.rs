//! Quiet debugging at install: the question, `--quiet-debugging on|off`, the markers the service reads,
//! and the edits through phantab-window: Chrome's Windows sign-in (Run key) entry and the shortcuts that
//! start it, or phantab's macOS `LaunchAgent` (THREAT-MODEL SR-49).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use phantab_window::{Browser, QuietRequest, QuietState, ShortcutDir};

use super::{CONFIG, QUIET_MARKER, QUIET_OFF_MARKER};

/// What install asks once, at a terminal, when the owner has not answered yet. Enter is yes.
pub(crate) const QUESTION: &str = "Hide Chrome's debugging bar? Then every extension that uses Chrome's debugger attaches silently, not only phantab's bridge. [Y/n] ";

/// Where the edits go. All `None` is the real places; tests name scratch ones (`--run-key`,
/// `--shortcut-dir`, `--launch-agents-dir`, which the usage text leaves out).
#[derive(Debug, Default, Clone)]
pub(crate) struct Places {
    pub run_key: Option<String>,
    pub shortcut_dirs: Option<Vec<ShortcutDir>>,
    pub launch_agents_dir: Option<PathBuf>,
}

/// The owner's answer so far: `Some(true)` on, `Some(false)` said no, `None` never asked.
pub(crate) fn answered(runtime: &Path) -> Option<bool> {
    if runtime.join(QUIET_MARKER).is_file() {
        Some(true)
    } else if runtime.join(QUIET_OFF_MARKER).is_file() {
        Some(false)
    } else {
        None
    }
}

/// Asks [`QUESTION`] until the answer is yes or no; Enter is yes, the end of input no.
pub(crate) fn ask(terminal: &mut dyn BufRead, out: &mut dyn Write) -> Result<bool> {
    loop {
        write!(out, "{QUESTION}")?;
        out.flush()?;
        let mut line = String::new();
        if terminal.read_line(&mut line)? == 0 {
            writeln!(out)?;
            return Ok(false);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(out, "Answer y or n.")?,
        }
    }
}

/// Turns quiet debugging on or off: the answer's marker, then the edits, then what they found.
pub(crate) fn set(runtime: &Path, on: bool, places: &Places, out: &mut dyn Write) -> Result<()> {
    let browser = browser_of(runtime)?;
    let (keep, drop) = if on { (QUIET_MARKER, QUIET_OFF_MARKER) } else { (QUIET_OFF_MARKER, QUIET_MARKER) };
    remove(runtime, drop)?;
    let marker = runtime.join(keep);
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&marker)
        .with_context(|| format!("Could not write {}", marker.display()))?;
    let state = apply(on, browser, places)?;
    report(on, &state, out)
}

fn report(on: bool, state: &QuietState, out: &mut dyn Write) -> Result<()> {
    let mode = if on { "on" } else { "off" };
    if cfg!(windows) {
        let entry = match state.run_value {
            Some(_) => "Chrome's sign-in entry",
            None => "no sign-in entry (Chrome has none in the Run key yet)",
        };
        let what = if on { "now start Chrome with the flag" } else { "no longer carry the flag" };
        let n = state.shortcuts;
        let shortcuts = if n == 1 { "1 shortcut".to_owned() } else { format!("{n} shortcuts") };
        writeln!(out, "Quiet debugging {mode}: {entry} and {shortcuts} {what}. Browser not restarted.")?;
        for path in &state.unwritable {
            writeln!(
                out,
                "Could not change the shortcut {path} (it needs administrator rights): Chrome started from it {}.",
                if on { "still shows the bar" } else { "keeps the flag" }
            )?;
        }
    } else {
        let agent = if on {
            "phantab's LaunchAgent starts Chrome with the flag at each login. Turn off Chrome's own open at login \
             (System Settings > General > Login Items), or it may start first, without the flag"
        } else {
            "phantab's LaunchAgent is gone"
        };
        writeln!(out, "Quiet debugging {mode}: {agent}. Browser not restarted.")?;
    }
    match (on, state.running) {
        (true, Some(false)) => writeln!(
            out,
            "The Chrome running now started without the flag, so the bar shows until it restarts. To restart it \
             now, run phantab chrome restart-quiet: Chrome closes, saving every window and tab, and reopens them \
             with the flag."
        )?,
        (true, Some(true)) => writeln!(out, "The Chrome running now already has the flag.")?,
        (false, Some(true)) => writeln!(out, "The Chrome running now keeps the flag until it restarts.")?,
        (_, None) | (false, Some(false)) => {}
    }
    Ok(())
}

/// The runtime's browser: `chromeExecutable` on `userDataDir` (Chrome's own default when it names none).
pub(crate) fn browser_of(runtime: &Path) -> Result<Browser> {
    let path = runtime.join(CONFIG);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!("Quiet debugging needs an installed runtime: {} is missing", path.display())
    })?;
    let config: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("Could not read {}", path.display()))?;
    let field = |name: &str| config.get(name).and_then(serde_json::Value::as_str).map(str::to_owned);
    let chrome_path =
        field("chromeExecutable").with_context(|| format!("{} names no chromeExecutable", path.display()))?;
    let user_data_dir = field("userDataDir").map(PathBuf::from).or_else(super::discover::user_data_dir);
    Ok(Browser {
        chrome_path,
        default_dir: user_data_dir.as_deref().is_none_or(super::discover::is_default_user_data_dir),
        user_data_dir: user_data_dir.map(|d| d.display().to_string()).unwrap_or_default(),
    })
}

/// Removes both answers: uninstall forgets the question, so a later install asks it again.
pub(crate) fn remove_markers(runtime: &Path) -> Result<()> {
    remove(runtime, QUIET_MARKER)?;
    remove(runtime, QUIET_OFF_MARKER)
}

fn remove(runtime: &Path, name: &str) -> Result<()> {
    let marker = runtime.join(name);
    match std::fs::remove_file(&marker) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("Could not remove {}", marker.display()))
        }
        _ => Ok(()),
    }
}

/// Runs the async `quiet` on a runtime of its own, on its own thread, so it works from any caller,
/// including one already inside a tokio runtime.
pub(crate) fn apply(on: bool, browser: Browser, places: &Places) -> Result<QuietState> {
    let request = QuietRequest {
        run_key: places.run_key.clone(),
        shortcut_dirs: places.shortcut_dirs.clone(),
        launch_agents_dir: places.launch_agents_dir.clone(),
        ..QuietRequest::new(on, browser)
    };
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<QuietState> {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                Ok(runtime.block_on(phantab_window::platform().quiet(&request))?)
            })
            .join()
            .map_err(|_| anyhow!("the quiet-debugging change stopped unexpectedly"))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asked(typed: &str) -> (bool, String) {
        let mut out = Vec::new();
        let yes = ask(&mut typed.as_bytes(), &mut out).unwrap();
        (yes, String::from_utf8(out).unwrap())
    }

    #[test]
    fn the_question_defaults_to_yes_and_asks_again_on_anything_else() {
        assert!(asked("\n").0, "Enter is yes");
        assert!(asked("Y\r\n").0);
        assert!(asked(" yes \n").0);
        assert!(!asked("n\n").0);
        assert!(!asked("No\n").0);
        assert!(!asked("").0, "the end of input is no");
        let (yes, said) = asked("maybe\nn\n");
        assert!(!yes);
        assert_eq!(said.matches(QUESTION).count(), 2, "{said}");
        assert!(said.contains("Answer y or n."));
        assert!(QUESTION.contains("every extension that uses Chrome's debugger attaches silently"));
    }

    #[test]
    fn the_answer_is_one_marker_or_the_other() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(answered(dir.path()), None);
        std::fs::write(dir.path().join(QUIET_OFF_MARKER), "").unwrap();
        assert_eq!(answered(dir.path()), Some(false));
        std::fs::write(dir.path().join(QUIET_MARKER), "").unwrap();
        assert_eq!(answered(dir.path()), Some(true));
        remove_markers(dir.path()).unwrap();
        assert_eq!(answered(dir.path()), None);
        remove_markers(dir.path()).unwrap();
    }

    #[test]
    fn the_browser_is_the_configs_chrome_on_its_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(browser_of(dir.path()).is_err(), "no runtime");
        let other = dir.path().join("Chrome Data");
        let config = serde_json::json!({ "chromeExecutable": "C:/c/chrome.exe", "userDataDir": other });
        std::fs::write(dir.path().join(CONFIG), config.to_string()).unwrap();
        let b = browser_of(dir.path()).unwrap();
        assert_eq!(
            b,
            Browser {
                chrome_path: "C:/c/chrome.exe".into(),
                user_data_dir: other.display().to_string(),
                default_dir: false
            }
        );
        std::fs::write(dir.path().join(CONFIG), "{}").unwrap();
        assert!(browser_of(dir.path()).is_err(), "no chromeExecutable");
    }
}
