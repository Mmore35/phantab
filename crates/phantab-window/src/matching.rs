//! The decisions behind window control, kept free of OS calls so they are unit-tested on every OS.

use crate::{Result, TOKEN_PREFIX, WindowError, WindowSpec};

/// The flag Chrome reads only from the command line that starts its browser process.
pub const QUIET_FLAG: &str = "--silent-debugger-extension-api";

/// A window rect in physical pixels, as `GetWindowRect` gives it to a per-monitor-v2 aware thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Whether a window at `rect` on a monitor of `dpi` is the one `spec` asked for: each edge and size within
/// 2 px of the DIP value scaled by `dpi / 96`. The tolerance absorbs rounding at fractional scales.
pub fn rect_matches(rect: ScreenRect, dpi: u32, spec: &WindowSpec) -> bool {
    let scale = f64::from(dpi) / 96.0;
    let near = |actual: i32, dip: i32| (f64::from(actual) - f64::from(dip) * scale).abs() <= 2.0;
    near(rect.left, spec.left)
        && near(rect.top, spec.top)
        && near(rect.right - rect.left, spec.width)
        && near(rect.bottom - rect.top, spec.height)
}

/// Refuses a token that is not phantab's, so a caller cannot hide or find an arbitrary window by title.
pub fn check_token(token: &str) -> Result<()> {
    if token.len() > TOKEN_PREFIX.len() && token.starts_with(TOKEN_PREFIX) {
        Ok(())
    } else {
        Err(WindowError::InvalidToken)
    }
}

/// The Run-entry rewrite: for a value that starts with `"<chrome_path>"` (case-insensitive, quotes
/// included), the value with [`QUIET_FLAG`] right after the path (`on`) or with every ` <flag>` removed
/// (`!on`). `None` for a value that does not start the browser. Idempotent; the rest of the value is kept.
pub fn rewrite_run_value(value: &str, chrome_path: &str, on: bool) -> Option<String> {
    let start = format!("\"{chrome_path}\"");
    let split = prefix_len_ignore_case(value, &start)?;
    let (head, rest) = value.split_at(split);
    let rest = rest.replace(&format!(" {QUIET_FLAG}"), "");
    Some(if on { format!("{head} {QUIET_FLAG}{rest}") } else { format!("{head}{rest}") })
}

/// `running` in [`crate::QuietState`], from the command lines of the chrome.exe processes at the configured
/// path: those without `--type=` are the browser process. `None` when no browser process runs.
pub fn running_state<'a>(command_lines: impl IntoIterator<Item = &'a str>) -> Option<bool> {
    let mut browsers = command_lines.into_iter().filter(|line| !line.contains("--type=")).peekable();
    browsers.peek()?;
    Some(browsers.any(|line| line.contains(QUIET_FLAG)))
}

/// macOS: from `ps -axww -o args=` output (one process's argv per line), the lines of processes started
/// as `chrome_path`, i.e. whose `argv[0]` is that path (followed by an argument or nothing). Paths with
/// spaces (`…/Google Chrome.app/Contents/MacOS/Google Chrome`) work because the path is matched whole.
pub fn browser_args_lines<'a>(ps_output: &'a str, chrome_path: &str) -> Vec<&'a str> {
    ps_output
        .lines()
        .map(str::trim_start)
        .filter(|line| {
            line.strip_prefix(chrome_path).is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
        })
        .collect()
}

/// The byte length of `value`'s prefix that equals `prefix` ignoring case (per char, like .NET's
/// `OrdinalIgnoreCase`), or `None`.
fn prefix_len_ignore_case(value: &str, prefix: &str) -> Option<usize> {
    let mut chars = value.char_indices();
    for want in prefix.chars() {
        let (_, have) = chars.next()?;
        if !have.to_lowercase().eq(want.to_lowercase()) {
            return None;
        }
    }
    Some(chars.next().map_or(value.len(), |(at, _)| at))
}

/// The subkey path under HKCU for a key written `HKCU\…`, `HKCU:\…` or `HKEY_CURRENT_USER\…`.
#[cfg_attr(not(windows), allow(dead_code, reason = "the Run key exists on Windows only"))]
pub(crate) fn hkcu_subkey(key: &str) -> Result<&str> {
    for root in ["HKCU:\\", "HKCU\\", "HKEY_CURRENT_USER\\"] {
        if let Some(at) = prefix_len_ignore_case(key, root) {
            let rest = key[at..].trim_matches('\\');
            if !rest.is_empty() {
                return Ok(rest);
            }
        }
    }
    Err(WindowError::InvalidArgument(format!("The Run key must be under HKCU: {key}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";

    fn spec() -> WindowSpec {
        WindowSpec::workspace("PHANTAB-x")
    }

    #[test]
    fn rect_matches_at_100_percent() {
        let r = ScreenRect { left: 20, top: 20, right: 1307, bottom: 923 };
        assert!(rect_matches(r, 96, &spec()));
        let off = ScreenRect { left: 23, ..r };
        assert!(!rect_matches(off, 96, &spec()), "3 px off the left edge");
        let narrow = ScreenRect { right: 1304, ..r };
        assert!(!rect_matches(narrow, 96, &spec()), "3 px narrower");
    }

    #[test]
    fn rect_matches_scales_by_dpi_with_two_pixels_of_slack() {
        // 150 %: 20 -> 30, 1287 -> 1930.5, 903 -> 1354.5.
        let r = ScreenRect { left: 30, top: 30, right: 30 + 1931, bottom: 30 + 1354 };
        assert!(rect_matches(r, 144, &spec()));
        assert!(!rect_matches(r, 96, &spec()), "the unscaled rect is not the scaled one");
        let edge = ScreenRect { left: 32, top: 28, right: 32 + 1932, bottom: 28 + 1356 };
        assert!(rect_matches(edge, 144, &spec()));
        let past = ScreenRect { left: 33, ..r };
        assert!(!rect_matches(past, 144, &spec()));
    }

    #[test]
    fn rect_matches_at_125_percent() {
        // 20 -> 25, 1287 -> 1608.75, 903 -> 1128.75.
        let r = ScreenRect { left: 25, top: 25, right: 25 + 1609, bottom: 25 + 1129 };
        assert!(rect_matches(r, 120, &spec()));
    }

    #[test]
    fn tokens_must_be_phantab_tokens() {
        assert!(check_token("PHANTAB-1b4e28ba-2fa1-11d2-883f-0016d3cca427").is_ok());
        assert!(matches!(check_token("PHANTAB-"), Err(WindowError::InvalidToken)));
        assert!(matches!(check_token("UA-BROWSER-1"), Err(WindowError::InvalidToken)));
        assert!(matches!(check_token(""), Err(WindowError::InvalidToken)));
    }

    #[test]
    fn run_value_gets_the_flag_after_the_path() {
        let value = format!("\"{CHROME}\" --profile-directory=Default --no-startup-window");
        let on = rewrite_run_value(&value, CHROME, true).unwrap();
        assert_eq!(on, format!("\"{CHROME}\" {QUIET_FLAG} --profile-directory=Default --no-startup-window"));
        assert_eq!(rewrite_run_value(&on, CHROME, true).unwrap(), on, "on is idempotent");
        let off = rewrite_run_value(&on, CHROME, false).unwrap();
        assert_eq!(off, value);
        assert_eq!(rewrite_run_value(&off, CHROME, false).unwrap(), value, "off is idempotent");
    }

    #[test]
    fn run_value_with_nothing_after_the_path() {
        let value = format!("\"{CHROME}\"");
        assert_eq!(rewrite_run_value(&value, CHROME, true).unwrap(), format!("\"{CHROME}\" {QUIET_FLAG}"));
        assert_eq!(rewrite_run_value(&value, CHROME, false).unwrap(), value);
    }

    #[test]
    fn run_value_path_match_ignores_case_and_keeps_the_original_spelling() {
        let value = format!("\"{}\" --x", CHROME.to_uppercase());
        let on = rewrite_run_value(&value, CHROME, true).unwrap();
        assert_eq!(on, format!("\"{}\" {QUIET_FLAG} --x", CHROME.to_uppercase()));
    }

    #[test]
    fn run_value_collapses_a_doubled_flag() {
        let value = format!("\"{CHROME}\" {QUIET_FLAG} --x {QUIET_FLAG}");
        assert_eq!(
            rewrite_run_value(&value, CHROME, true).unwrap(),
            format!("\"{CHROME}\" {QUIET_FLAG} --x")
        );
        assert_eq!(rewrite_run_value(&value, CHROME, false).unwrap(), format!("\"{CHROME}\" --x"));
    }

    #[test]
    fn other_run_values_are_untouched() {
        assert_eq!(rewrite_run_value(r#""C:\Other\app.exe" --x"#, CHROME, true), None);
        // Unquoted, so not the entry Chrome writes for itself.
        assert_eq!(rewrite_run_value(&format!("{CHROME} --x"), CHROME, true), None);
        // Another program under the same folder.
        assert_eq!(rewrite_run_value(&format!("\"{CHROME}x\" --x"), CHROME, true), None);
        assert_eq!(rewrite_run_value("", CHROME, true), None);
    }

    #[test]
    fn running_state_reads_only_the_browser_process() {
        assert_eq!(running_state([]), None);
        assert_eq!(running_state(["chrome.exe --type=renderer --silent-debugger-extension-api"]), None);
        assert_eq!(
            running_state(["chrome.exe --type=gpu-process", "chrome.exe --no-startup-window"]),
            Some(false)
        );
        assert_eq!(running_state(["chrome.exe", "chrome.exe --silent-debugger-extension-api"]), Some(true));
    }

    #[test]
    fn mac_browser_lines_match_the_whole_path() {
        let chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
        let helper = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/\
                      Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper --type=renderer";
        let ps = format!(
            "/sbin/launchd\n  {chrome} --silent-debugger-extension-api\n{chrome}\n{helper}\n{chrome}X --y\n"
        );
        let lines = browser_args_lines(&ps, chrome);
        let flagged = format!("{chrome} --silent-debugger-extension-api");
        assert_eq!(lines, vec![flagged.as_str(), chrome]);
        assert_eq!(running_state(lines), Some(true));
        assert_eq!(running_state(browser_args_lines("/sbin/launchd\n", chrome)), None);
    }

    #[test]
    fn run_key_must_be_under_hkcu() {
        assert_eq!(hkcu_subkey(r"HKCU\Software\X").unwrap(), r"Software\X");
        assert_eq!(hkcu_subkey(r"HKCU:\Software\X").unwrap(), r"Software\X");
        assert_eq!(hkcu_subkey(r"hkey_current_user\Software\X\").unwrap(), r"Software\X");
        assert!(hkcu_subkey(r"HKLM\Software\X").is_err());
        assert!(hkcu_subkey(r"HKCU\").is_err());
        assert!(hkcu_subkey(r"Software\X").is_err());
    }
}
