//! The decisions behind window control, kept free of OS calls so they are unit-tested on every OS.

use std::fmt::Write as _;

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

/// A shortcut's arguments with [`QUIET_FLAG`] first (`on`), or with every whole-word copy of it taken out
/// (`!on`), and nothing else changed: off after on gives back the original exactly. Idempotent; a flag
/// already there stays where it is. A copy inside quotes is part of another argument and is left alone.
pub fn rewrite_shortcut_args(args: &str, on: bool) -> String {
    let found = flag_spans(args);
    if on {
        return match (found.is_empty(), args.is_empty()) {
            (false, _) => args.to_owned(),
            (true, true) => QUIET_FLAG.to_owned(),
            (true, false) => format!("{QUIET_FLAG} {args}"),
        };
    }
    let mut out = String::with_capacity(args.len());
    let mut at = 0;
    for (start, end) in found {
        // The space after the flag goes with it, or, for one at the end, the space before it.
        let (cut_start, cut_end) = if args[end..].starts_with(' ') {
            (start, end + 1)
        } else if start > at && args[..start].ends_with(' ') {
            (start - 1, end)
        } else {
            (start, end)
        };
        out.push_str(&args[at..cut_start]);
        at = cut_end;
    }
    out.push_str(&args[at..]);
    out
}

/// The byte spans of [`QUIET_FLAG`] as a whole argument of `args`, outside quotes.
fn flag_spans(args: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut quoted = false;
    let mut word_start = None;
    for (i, c) in args.char_indices().chain(std::iter::once((args.len(), ' '))) {
        if c == '"' {
            quoted = !quoted;
        }
        if (c.is_whitespace() && !quoted) || i == args.len() {
            if let Some(start) = word_start.take()
                && &args[start..i] == QUIET_FLAG
            {
                spans.push((start, i));
            }
        } else if word_start.is_none() {
            word_start = Some(i);
        }
    }
    spans
}

/// The arguments of a Windows command line, split as `CommandLineToArgvW` does: whitespace outside quotes
/// separates them, quotes group, and backslashes are literal except before a quote (2n of them and a quote:
/// n backslashes and the quote groups; 2n+1: n backslashes and a literal quote).
pub fn windows_args(command_line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_arg = false;
    let mut quoted = false;
    let mut chars = command_line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut n = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    n += 1;
                }
                in_arg = true;
                if chars.peek() == Some(&'"') {
                    current.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        chars.next();
                        current.push('"');
                    }
                } else {
                    current.extend(std::iter::repeat_n('\\', n));
                }
            }
            '"' => {
                in_arg = true;
                // Two quotes inside a quoted part are one literal quote, as the C runtime reads them.
                if quoted && chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    quoted = !quoted;
                }
            }
            c if c.is_whitespace() && !quoted => {
                if in_arg {
                    args.push(std::mem::take(&mut current));
                    in_arg = false;
                }
            }
            c => {
                in_arg = true;
                current.push(c);
            }
        }
    }
    if in_arg {
        args.push(current);
    }
    args
}

/// The `--user-data-dir` a browser command line names (the last one, as Chrome takes the last), or `None`.
/// `windows`: the line is a Windows command line, split by [`windows_args`], where Chrome takes the switch
/// after `--`, `-` or `/` in any case. Otherwise it is `ps -o args=` output, the argv joined by single
/// spaces with no quoting, so the value runs to the next ` -` that starts another switch, or the end.
pub fn user_data_dir_of(command_line: &str, windows: bool) -> Option<String> {
    const NAME: &str = "user-data-dir=";
    if windows {
        return windows_args(command_line).into_iter().skip(1).rev().find_map(|arg| {
            let body = arg.strip_prefix("--").or_else(|| arg.strip_prefix(['-', '/']))?;
            let at = prefix_len_ignore_case(body, NAME)?;
            Some(body[at..].to_owned())
        });
    }
    let switch = " --user-data-dir=";
    let start = command_line.rfind(switch)? + switch.len();
    let rest = &command_line[start..];
    let end = rest.find(" -").unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

/// Whether a browser command line runs on the configured user-data dir. One that names none runs on
/// Chrome's default, so it matches only when `default_dir`; one that names a dir matches when it is
/// `user_data_dir` (ignoring case and the separator's direction on Windows, and a trailing separator).
pub fn on_user_data_dir(command_line: &str, user_data_dir: &str, default_dir: bool, windows: bool) -> bool {
    match user_data_dir_of(command_line, windows) {
        None => default_dir,
        Some(named) => same_dir(&named, user_data_dir, windows),
    }
}

fn same_dir(a: &str, b: &str, windows: bool) -> bool {
    let trim = |s: &str| s.trim_end_matches(['/', '\\']).to_owned();
    let (a, b) = (trim(a), trim(b));
    if a.is_empty() {
        return false;
    }
    if windows { a.replace('/', "\\").to_lowercase() == b.replace('/', "\\").to_lowercase() } else { a == b }
}

/// Whether a command line is a browser process, not one of its helpers (`--type=renderer` and the rest).
pub fn is_browser_process(command_line: &str) -> bool {
    !command_line.contains("--type=")
}

/// macOS: `ps -axww -o pid=,args=` output as `(pid, args)` per process.
pub fn ps_processes(ps_output: &str) -> Vec<(u32, &str)> {
    ps_output
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, args) = line.split_once(' ').unwrap_or((line, ""));
            Some((pid.parse().ok()?, args.trim_start()))
        })
        .collect()
}

/// macOS: the `.app` bundle that holds `chrome_path` (`/Applications/Google Chrome.app`), which `open -a`
/// starts.
pub fn app_bundle(chrome_path: &str) -> Option<&str> {
    let at = chrome_path.find(".app/Contents/MacOS/")?;
    Some(&chrome_path[..at + ".app".len()])
}

/// macOS: the label of phantab's `LaunchAgent`, and its file's name (`.plist` added) in
/// `~/Library/LaunchAgents`.
pub const LAUNCH_AGENT_LABEL: &str = "dev.phantab.chrome";

/// macOS: the `LaunchAgent` that starts Chrome with [`QUIET_FLAG`] at login (docs/MAC.md Q4):
/// `/usr/bin/open -a <bundle> --args <flag> [--user-data-dir=<dir>]`, run once at load. `open --args`
/// reaches Chrome only when it is not yet running, so it never restarts one.
pub fn launch_agent_plist(bundle: &str, user_data_dir: Option<&str>) -> String {
    let escape = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let mut args = vec!["/usr/bin/open".to_owned(), "-a".to_owned(), bundle.to_owned(), "--args".to_owned()];
    args.push(QUIET_FLAG.to_owned());
    if let Some(dir) = user_data_dir {
        args.push(format!("--user-data-dir={dir}"));
    }
    let strings = args.iter().fold(String::new(), |mut all, a| {
        let _ = writeln!(all, "\t\t<string>{}</string>", escape(a));
        all
    });
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{LAUNCH_AGENT_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         {strings}\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// Whether the file at phantab's `LaunchAgent` path is phantab's own: it carries the label. Anything else
/// there is left alone.
pub fn is_our_launch_agent(text: &str) -> bool {
    text.contains(&format!("<string>{LAUNCH_AGENT_LABEL}</string>"))
}

/// Expands `%NAME%` in a registry path (a `REG_EXPAND_SZ` value) from `var`; an unknown name stays as it
/// was, as `ExpandEnvironmentStrings` leaves it.
pub fn expand_env(value: &str, var: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(open) = rest.find('%') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let known =
            after.find('%').filter(|&close| close > 0).and_then(|close| Some((close, var(&after[..close])?)));
        if let Some((close, v)) = known {
            out.push_str(&v);
            rest = &after[close + 1..];
        } else {
            out.push('%');
            rest = after;
        }
    }
    out.push_str(rest);
    out
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

    #[test]
    fn shortcut_args_round_trip_exactly() {
        for original in [
            "",
            "--profile-directory=Default",
            "--profile-directory=\"Profile 1\"  --new-window",
            " leading and trailing ",
            "https://example.com/?q=--silent-debugger-extension-api",
        ] {
            let on = rewrite_shortcut_args(original, true);
            assert!(on.starts_with(QUIET_FLAG), "{on:?}");
            assert_eq!(rewrite_shortcut_args(&on, true), on, "on is idempotent: {original:?}");
            assert_eq!(rewrite_shortcut_args(&on, false), original, "off undoes on: {original:?}");
            assert_eq!(rewrite_shortcut_args(original, false), original, "off is idempotent");
        }
        assert_eq!(rewrite_shortcut_args("", true), QUIET_FLAG);
        assert_eq!(rewrite_shortcut_args("--x", true), format!("{QUIET_FLAG} --x"));
    }

    #[test]
    fn shortcut_args_off_takes_every_whole_word_copy_only() {
        let args = format!("--a {QUIET_FLAG} --b {QUIET_FLAG}");
        assert_eq!(rewrite_shortcut_args(&args, false), "--a --b");
        assert_eq!(rewrite_shortcut_args(&args, true), args, "a flag already there stays where it is");
        let longer = format!("{QUIET_FLAG}x --y");
        assert_eq!(rewrite_shortcut_args(&longer, false), longer, "another switch that starts the same");
        let quoted = format!("\"{QUIET_FLAG}\" \"a {QUIET_FLAG} b\"");
        assert_eq!(rewrite_shortcut_args(&quoted, false), quoted, "quoted copies belong to other arguments");
        assert_eq!(rewrite_shortcut_args(QUIET_FLAG, false), "");
    }

    #[test]
    fn windows_args_split_as_command_line_to_argv() {
        assert_eq!(windows_args(r#""C:\a b\c.exe" --x="y z" w"#), [r"C:\a b\c.exe", "--x=y z", "w"]);
        assert_eq!(windows_args(r#"a\\"b c" d"#), [r"a\b c", "d"]);
        assert_eq!(windows_args(r#"a\"b c"#), [r#"a"b"#, "c"]);
        assert_eq!(windows_args(r"a\b\\ c"), [r"a\b\\", "c"]);
        assert_eq!(windows_args(r#""" x"#), ["", "x"]);
        assert_eq!(windows_args("   "), Vec::<String>::new());
    }

    #[test]
    fn user_data_dir_from_a_windows_command_line() {
        let line = format!(r#""{CHROME}" --user-data-dir="C:\Data\Chrome Two" --flag"#);
        assert_eq!(user_data_dir_of(&line, true).as_deref(), Some(r"C:\Data\Chrome Two"));
        let last = format!(r"{CHROME} --user-data-dir=C:\a /User-Data-Dir=C:\b");
        assert_eq!(user_data_dir_of(&last, true).as_deref(), Some(r"C:\b"), "the last one, in any case");
        assert_eq!(user_data_dir_of(&format!(r#""{CHROME}" --no-startup-window"#), true), None);
        // argv[0] is the program, never a switch.
        assert_eq!(user_data_dir_of(r"--user-data-dir=C:\x", true), None);
    }

    #[test]
    fn user_data_dir_from_ps_output() {
        let chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
        let line = format!("{chrome} --user-data-dir=/Users/a/Library/Application Support/X Y --flag");
        assert_eq!(
            user_data_dir_of(&line, false).as_deref(),
            Some("/Users/a/Library/Application Support/X Y")
        );
        assert_eq!(user_data_dir_of(&format!("{chrome} --user-data-dir=/d"), false).as_deref(), Some("/d"));
        assert_eq!(user_data_dir_of(chrome, false), None);
    }

    #[test]
    fn only_the_configured_user_data_dir_matches() {
        let default = format!(r#""{CHROME}" --no-startup-window"#);
        let named =
            format!(r#""{CHROME}" --user-data-dir="C:/Users/A/AppData/Local/Google/Chrome/User Data""#);
        let other = format!(r#""{CHROME}" --user-data-dir=C:\Temp\scratch"#);
        let dir = r"c:/users/a/appdata/local/google/chrome/user data";
        assert!(on_user_data_dir(&default, dir, true, true));
        assert!(!on_user_data_dir(&default, r"C:\Temp\scratch", false, true));
        assert!(on_user_data_dir(&named, dir, true, true), "case and the separators' direction are ignored");
        assert!(!on_user_data_dir(&other, dir, true, true));
        assert!(on_user_data_dir(&other, r"C:\Temp\scratch\", false, true));
        assert!(!on_user_data_dir(&format!("{CHROME} --user-data-dir="), "", false, true), "an empty dir");
        assert!(!on_user_data_dir("/c --user-data-dir=/A", "/a", false, false), "macOS keeps case");
        assert!(on_user_data_dir("/c --user-data-dir=/a/", "/a", false, false));
    }

    #[test]
    fn browser_processes_are_the_ones_without_a_type() {
        assert!(is_browser_process(r#""chrome.exe" --no-startup-window"#));
        assert!(!is_browser_process(r#""chrome.exe" --type=renderer"#));
    }

    #[test]
    fn ps_output_gives_pids_and_args() {
        let ps = "    1 /sbin/launchd\n  412 /Applications/A B.app/Contents/MacOS/A B --x\nbad line\n 7\n";
        assert_eq!(
            ps_processes(ps),
            [(1, "/sbin/launchd"), (412, "/Applications/A B.app/Contents/MacOS/A B --x"), (7, "")]
        );
    }

    #[test]
    fn launch_agent_starts_the_bundle_with_the_flag() {
        let chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
        assert_eq!(app_bundle(chrome), Some("/Applications/Google Chrome.app"));
        assert_eq!(app_bundle("/usr/bin/chrome"), None);
        let plist = launch_agent_plist("/Applications/Google Chrome.app", None);
        assert!(plist.contains("<string>dev.phantab.chrome</string>"), "{plist}");
        assert!(
            plist.contains(
                "<string>/usr/bin/open</string>\n\t\t<string>-a</string>\n\t\t<string>/Applications/Google \
                 Chrome.app</string>\n\t\t<string>--args</string>\n\t\t<string>--silent-debugger-extension-api\
                 </string>\n\t</array>"
            ),
            "{plist}"
        );
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"), "{plist}");
        assert!(is_our_launch_agent(&plist));
        assert!(!is_our_launch_agent("<string>com.example.other</string>"));
        let named = launch_agent_plist("/A&B.app", Some("/Users/a/<dir>"));
        assert!(named.contains("<string>/A&amp;B.app</string>"), "{named}");
        assert!(named.contains("<string>--user-data-dir=/Users/a/&lt;dir&gt;</string>"), "{named}");
    }

    #[test]
    fn registry_paths_expand_known_names_only() {
        let var = |name: &str| (name == "USERPROFILE").then(|| r"C:\Users\a".to_owned());
        assert_eq!(expand_env(r"%USERPROFILE%\Desktop", var), r"C:\Users\a\Desktop");
        assert_eq!(expand_env(r"%NOPE%\x", var), r"%NOPE%\x");
        assert_eq!(expand_env(r"%NOPE%%USERPROFILE%", var), r"%NOPE%C:\Users\a");
        assert_eq!(expand_env("50% done %%", var), "50% done %%");
        assert_eq!(expand_env(r"D:\plain", var), r"D:\plain");
    }
}
