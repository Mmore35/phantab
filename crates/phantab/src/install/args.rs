//! The installer's flags.

use std::path::PathBuf;

pub(crate) const USAGE: &str = "\
Usage: phantab install [flags]      register phantab in the selected MCP clients
       phantab uninstall [flags]    restore what install replaced (same as install --uninstall)

Clients (at least one; only these files are changed):
  --codex-config <config.toml>      a Codex config; repeatable
  --claude-config <.claude.json>    a Claude Code config; repeatable
Browser binding (first install needs all three; later installs keep them):
  --profile <dir name>              the Chrome profile folder inside the user-data dir (\"Default\", \"Profile 1\")
  --user-data-dir <dir>             Chrome's user-data dir (default: Chrome's own, when it exists)
  --chrome <exe>                    the Chrome executable (default: the installed Google Chrome)
Other Chrome profiles agents may use too (kept by later installs; each needs its copy of the bridge
loaded once, by hand, at chrome://extensions in that profile):
  --all-profiles on|off             on (the default): every profile in the user-data dir but the usual one
                                    and those left out, a new one joining at the next install; off: only
                                    those named with --add-profile
  --add-profile <name or dir>       on: take one back off the leave-out list; off: allow it. By Chrome's
                                    name for it (\"Work\") or its folder (\"Profile 1\"); repeatable
  --remove-profile <name or dir>    on: leave one out; off: stop allowing it. Its copy is removed;
                                    repeatable
Other:
  --runtime <dir>                   runtime dir (default: PHANTAB_RUNTIME, else the per-user default)
  --server-name <name>              the MCP entry's name in both clients (default: phantab)
  --sign-in-provider <json array>   the command browser_sign_in runs for a saved login; [] removes it.
                                    With a provider list, it sets (or [] removes) the list's \"default\"
  --add-sign-in-provider <json object>
                                    adds one password manager to the list, or replaces the one of its
                                    name (docs/VAULTS.md); repeatable
  --remove-sign-in-provider <name>  removes one from the list; repeatable
  --sign-in-save-to <name>          the provider browser_sign_up saves new logins to; \"\" removes it
  --quiet-debugging on|off          on hides Chrome's debugging bar, off brings it back; every extension
                                    that uses Chrome's debugger then attaches silently. Answers the
                                    question an install at a terminal asks once; with no client flag it
                                    changes only that
  --dev-tools                       writes \"devTools\": true to config.json, which turns the
                                    developer tools on (docs/GUARDRAILS.md). Later installs keep it,
                                    with or without the flag
  --extension-dir <dir>             the built extension (default: extension/ beside the binary, else in
                                    a debug build the source tree's extension/dist)
  --uninstall                       uninstall instead
";

#[derive(Debug, Default)]
pub(crate) struct Args {
    pub runtime: Option<PathBuf>,
    pub codex_configs: Vec<PathBuf>,
    pub claude_configs: Vec<PathBuf>,
    pub profile: Option<String>,
    pub user_data_dir: Option<PathBuf>,
    pub chrome: Option<PathBuf>,
    pub uninstall: bool,
    /// `--dev-tools`: write `devTools` on (THREAT-MODEL SR-90). Without it nothing is removed.
    pub dev_tools: bool,
    pub sign_in_provider: Option<String>,
    pub add_sign_in_providers: Vec<String>,
    pub remove_sign_in_providers: Vec<String>,
    pub sign_in_save_to: Option<String>,
    pub quiet_debugging: Option<bool>,
    /// Tests only: a scratch key instead of the real Run key (`--run-key`, not in the usage text).
    pub run_key: Option<String>,
    /// Tests only: scratch folders instead of the real shortcut folders (`--shortcut-dir`, repeatable).
    pub shortcut_dirs: Option<Vec<PathBuf>>,
    /// Tests only: a scratch folder instead of `~/Library/LaunchAgents` (`--launch-agents-dir`).
    pub launch_agents_dir: Option<PathBuf>,
    pub server_name: Option<String>,
    pub extension_dir: Option<PathBuf>,
    pub add_profiles: Vec<String>,
    pub remove_profiles: Vec<String>,
    pub all_profiles: Option<bool>,
    /// Tests only (Windows): the HKCU key that registers the native host, instead of Chrome's.
    pub native_host_key: Option<String>,
    pub help: bool,
}

impl Args {
    /// Where the quiet-debugging edits go: the real places, unless a test named scratch ones.
    pub(crate) fn quiet_places(&self) -> super::quiet::Places {
        super::quiet::Places {
            run_key: self.run_key.clone(),
            shortcut_dirs: self.shortcut_dirs.as_ref().map(|dirs| {
                dirs.iter().map(|path| phantab_window::ShortcutDir::own(path.clone(), true)).collect()
            }),
            launch_agents_dir: self.launch_agents_dir.clone(),
        }
    }
}

/// Parses `words` (everything after `install` / `uninstall`). `Err` is a usage message.
pub(crate) fn parse(words: &[String]) -> Result<Args, String> {
    let mut args = Args::default();
    let mut rest = words.iter().peekable();
    while let Some(arg) = rest.next() {
        let Some(flag) = arg.strip_prefix("--") else {
            return Err(format!("unrecognized argument: {arg}"));
        };
        let (name, inline) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (flag, None),
        };
        // A flag's value is the inline `=value` or the next argument, unless that is another flag.
        let mut value = |what: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            match rest.next_if(|next| !next.starts_with("--")) {
                Some(v) => Ok(v.clone()),
                None => Err(format!("--{what} needs a value")),
            }
        };
        match name {
            "runtime" => args.runtime = Some(value(name)?.into()),
            "codex-config" => args.codex_configs.push(value(name)?.into()),
            "claude-config" => args.claude_configs.push(value(name)?.into()),
            "profile" => args.profile = Some(value(name)?),
            "user-data-dir" => args.user_data_dir = Some(value(name)?.into()),
            "chrome" => args.chrome = Some(value(name)?.into()),
            "sign-in-provider" => args.sign_in_provider = Some(value(name)?),
            "add-sign-in-provider" => args.add_sign_in_providers.push(value(name)?),
            "remove-sign-in-provider" => args.remove_sign_in_providers.push(value(name)?),
            "sign-in-save-to" => args.sign_in_save_to = Some(value(name)?),
            "quiet-debugging" => {
                args.quiet_debugging = Some(match value(name)?.as_str() {
                    "on" => true,
                    "off" => false,
                    other => return Err(format!("--quiet-debugging takes on or off, not {other:?}")),
                });
            }
            "all-profiles" => {
                args.all_profiles = Some(match value(name)?.as_str() {
                    "on" => true,
                    "off" => false,
                    other => return Err(format!("--all-profiles takes on or off, not {other:?}")),
                });
            }
            "run-key" => args.run_key = Some(value(name)?),
            "shortcut-dir" => args.shortcut_dirs.get_or_insert_with(Vec::new).push(value(name)?.into()),
            "launch-agents-dir" => args.launch_agents_dir = Some(value(name)?.into()),
            "server-name" => args.server_name = Some(value(name)?),
            "extension-dir" => args.extension_dir = Some(value(name)?.into()),
            "add-profile" => args.add_profiles.push(value(name)?),
            "remove-profile" => args.remove_profiles.push(value(name)?),
            "native-host-key" => args.native_host_key = Some(value(name)?),
            "uninstall" | "dev-tools" | "help" if inline.is_some() => {
                return Err(format!("--{name} takes no value"));
            }
            "uninstall" => args.uninstall = true,
            "dev-tools" => args.dev_tools = true,
            "help" => args.help = true,
            _ => return Err(format!("unrecognized flag: --{name}")),
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn values_inline_or_next_and_repeatable_configs() {
        let a = parse(&strings(&[
            "--codex-config",
            "a.toml",
            "--codex-config=b.toml",
            "--claude-config",
            "c.json",
            "--profile",
            "Work Profile",
            "--sign-in-provider",
            "[]",
            "--quiet-debugging=on",
            "--add-profile",
            "Work",
            "--add-profile=Profile 5",
            "--remove-profile",
            "Other",
            "--all-profiles=off",
            "--uninstall",
            "--dev-tools",
        ]))
        .unwrap();
        assert_eq!(a.add_profiles, ["Work", "Profile 5"]);
        assert_eq!(a.remove_profiles, ["Other"]);
        assert_eq!(a.all_profiles, Some(false));
        assert_eq!(parse(&strings(&["--all-profiles", "on"])).unwrap().all_profiles, Some(true));
        assert_eq!(parse(&[]).unwrap().all_profiles, None, "absent: config.json decides");
        assert_eq!(a.codex_configs, [PathBuf::from("a.toml"), PathBuf::from("b.toml")]);
        assert_eq!(a.claude_configs, [PathBuf::from("c.json")]);
        assert_eq!(a.profile.as_deref(), Some("Work Profile"));
        assert_eq!(a.sign_in_provider.as_deref(), Some("[]"));
        assert_eq!(a.quiet_debugging, Some(true));
        assert!(a.uninstall);
        assert!(a.dev_tools);
        assert!(!parse(&[]).unwrap().dev_tools, "absent: config.json keeps what it has");
    }

    #[test]
    fn refuses_unknown_missing_and_bad_values() {
        assert!(parse(&strings(&["--bogus"])).is_err());
        assert!(parse(&strings(&["positional"])).is_err());
        assert!(parse(&strings(&["--profile"])).is_err());
        assert!(parse(&strings(&["--profile", "--chrome", "x"])).is_err());
        assert!(parse(&strings(&["--quiet-debugging", "maybe"])).is_err());
        let error = parse(&strings(&["--all-profiles", "maybe"])).unwrap_err();
        assert_eq!(error, r#"--all-profiles takes on or off, not "maybe""#);
        assert!(parse(&strings(&["--all-profiles"])).is_err());
        assert!(parse(&strings(&["--uninstall=yes"])).is_err());
        assert_eq!(parse(&strings(&["--dev-tools=yes"])).unwrap_err(), "--dev-tools takes no value");
        assert!(parse(&strings(&["--migrate-from"])).is_err());
        assert!(parse(&strings(&["--instance-root", "x"])).is_err());
    }
}
