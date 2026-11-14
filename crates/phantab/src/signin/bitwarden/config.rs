//! The `signInProvider.bitwarden` block of `config.json` (docs/BITWARDEN.md § Config):
//!
//! ```json
//! "signInProvider": {
//!   "source": "bitwarden",
//!   "bitwarden": {
//!     "bw": "C:\\Tools\\bw.exe",
//!     "dataDir": "...", "askFirst": ["bank.example"], "policyFile": "...",
//!     "syncAfterSeconds": 300, "server": "https://vault.bitwarden.eu"
//!   }
//! }
//! ```
//!
//! Only `bw` is required. A block that does not parse makes every sign-in answer `provider-failed`
//! (fail closed); `phantab bitwarden status` says why.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

/// How long a local vault copy is trusted before a call runs `bw sync` first. Five minutes matches
/// Bitwarden's own clients, which sync on unlock and then periodically (docs/BITWARDEN.md § Design
/// decisions, 2).
const DEFAULT_SYNC_AFTER: Duration = Duration::from_secs(300);

/// The parsed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    /// The `bw` program: an absolute path, never looked up on `PATH`.
    pub(crate) program: PathBuf,
    /// Arguments before every `bw` command (`["C:\\node.exe", "C:\\...\\bw.js"]` gives one).
    pub(crate) prefix: Vec<String>,
    /// `BITWARDENCLI_APPDATA_DIR`: phantab's own CLI state, never the owner's other `bw` data.
    pub(crate) data_dir: PathBuf,
    /// Base domains that answer `ask-first` (as `sign-in-policy.json`'s `askFirst`).
    pub(crate) ask_first: Vec<String>,
    /// A `sign-in-policy.json`-shaped file read on every call, for sites and approvals the owner edits.
    pub(crate) policy_file: Option<PathBuf>,
    pub(crate) sync_after: Duration,
    /// The server `connect` points a logged-out CLI at. Not used by sign-in calls.
    pub(crate) server: Option<String>,
    /// The proxy every `bw` phantab runs goes through, given as its `http_proxy` and `https_proxy` in
    /// place of any proxy variable the service has (THREAT-MODEL SR-14). So the proxy does not depend on
    /// which client started the service. An `http://` or `https://` URL with no user name or password,
    /// which would otherwise sit in this file and in `bw`'s environment.
    pub(crate) proxy: Option<String>,
}

/// The keys a block may have.
const KNOWN: &[&str] = &["bw", "dataDir", "askFirst", "policyFile", "syncAfterSeconds", "server", "proxy"];

/// Why a block does not parse. The text is for the owner's `status`, and names no value from the vault.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub(crate) struct ConfigError(pub(crate) String);

/// A proxy URL `bw` can use: http or https, a host, and no credentials. No control characters either:
/// the URL parser drops a tab or newline, but the text given is what `bw` gets.
fn valid_proxy(s: &str) -> bool {
    !s.chars().any(char::is_control)
        && url::Url::parse(s).is_ok_and(|u| {
            matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some_and(|h| !h.is_empty())
                && u.username().is_empty()
                && u.password().is_none()
        })
}

fn bad(text: &str) -> ConfigError {
    ConfigError(text.to_owned())
}

/// A site in an ask-first list: a lower-case host or base domain, as the policy checks it.
pub(crate) fn valid_site(site: &str) -> bool {
    !site.is_empty()
        && site.len() <= 253
        && site.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !site.starts_with('.')
        && !site.ends_with('.')
}

fn absolute(v: &Value, what: &str) -> Result<PathBuf, ConfigError> {
    let text =
        v.as_str().filter(|s| !s.is_empty()).ok_or_else(|| ConfigError(format!("{what} must be a path")))?;
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        return Err(ConfigError(format!("{what} must be an absolute path")));
    }
    Ok(path)
}

/// A batch file runs through `cmd.exe`, a shell, so it is refused (THREAT-MODEL SR-64). Windows drops
/// trailing dots and spaces from a file name, so `bw.cmd ` is `bw.cmd` and is refused too; so is a name
/// with a `:` (an alternate data stream) or one that is not Unicode, which could not be checked.
fn is_batch(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return true };
    let name = name.trim_end_matches(['.', ' ']);
    name.contains(':')
        || Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"))
}

/// On Windows the program must name a `.exe` exactly. For any other name Rust's `Command` first tries the
/// name with `.exe` added and runs that if it exists, so `C:\Tools\bw` would pin `bw` (the pin,
/// `super::pin`, hashes the name as configured) and run a `bw.exe` planted beside it. A trailing dot or
/// space, which Windows drops, is not `.exe`.
pub(crate) fn is_exe(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.len().checked_sub(4).and_then(|at| n.get(at..)))
        .is_some_and(|ext| ext.eq_ignore_ascii_case(".exe"))
}

impl Config {
    /// Parses the block. `bitwarden_dir` is `<runtime>/bitwarden`, the home of the default `dataDir`.
    ///
    /// # Errors
    /// What is wrong, for the owner.
    pub(crate) fn parse(block: Option<&Value>, bitwarden_dir: &Path) -> Result<Self, ConfigError> {
        let block = block
            .and_then(Value::as_object)
            .ok_or_else(|| bad("signInProvider.bitwarden must be an object"))?;
        if let Some(k) = block.keys().find(|k| !KNOWN.contains(&k.as_str())) {
            return Err(ConfigError(format!("signInProvider.bitwarden has an unknown key {k:?}")));
        }
        let (program, prefix) = match block.get("bw") {
            Some(Value::Array(parts)) => {
                let parts: Vec<&str> = parts
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<_>>()
                    .ok_or_else(|| bad("bw must be a path or an array of strings"))?;
                let (first, rest) = parts.split_first().ok_or_else(|| bad("bw must not be empty"))?;
                (absolute(&Value::from(*first), "bw")?, rest.iter().map(|s| (*s).to_owned()).collect())
            }
            Some(v) => (absolute(v, "bw")?, Vec::new()),
            None => {
                return Err(bad(
                    "signInProvider.bitwarden.bw is required: the absolute path of the bw program",
                ));
            }
        };
        // npm's launchers (`bw.cmd`, `bw.ps1`, `bw`) sit beside its package: the owner is told the exact
        // `bw` to set instead (the same text a launcher gets from the pin on macOS).
        let set = || super::pin::install_hint(&program).map_or_else(String::new, |set| format!(": {set}"));
        if is_batch(&program) {
            return Err(ConfigError(format!(
                "bw must be a program, not a .cmd or .bat file (those run through a shell){}",
                set()
            )));
        }
        if cfg!(windows) && !is_exe(&program) {
            return Err(ConfigError(format!(
                "bw must name a .exe program: the standalone bw.exe, or [\"<absolute path of node.exe>\", \
                 \"<absolute path of @bitwarden/cli/build/bw.js>\"]{}",
                set()
            )));
        }
        let data_dir = match block.get("dataDir") {
            Some(v) => absolute(v, "dataDir")?,
            None => bitwarden_dir.join("cli"),
        };
        let ask_first = match block.get("askFirst") {
            None => Vec::new(),
            Some(Value::Array(sites)) => sites
                .iter()
                .map(|s| s.as_str().filter(|s| valid_site(s)).map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or_else(|| {
                    bad("askFirst must list lower-case hosts or base domains, like \"bank.example\"")
                })?,
            Some(_) => return Err(bad("askFirst must be an array")),
        };
        let policy_file = block.get("policyFile").map(|v| absolute(v, "policyFile")).transpose()?;
        let sync_after = match block.get("syncAfterSeconds") {
            None => DEFAULT_SYNC_AFTER,
            Some(v) => {
                Duration::from_secs(v.as_u64().ok_or_else(|| bad("syncAfterSeconds must be a whole number"))?)
            }
        };
        let server = match block.get("server") {
            None => None,
            Some(Value::String(s)) if s.starts_with("https://") && url::Url::parse(s).is_ok() => {
                Some(s.clone())
            }
            Some(_) => return Err(bad("server must be an https:// URL")),
        };
        let proxy = match block.get("proxy") {
            None => None,
            Some(Value::String(s)) if valid_proxy(s) => Some(s.clone()),
            Some(_) => {
                return Err(bad("proxy must be an http:// or https:// URL with no user name or password"));
            }
        };
        Ok(Config { program, prefix, data_dir, ask_first, policy_file, sync_after, server, proxy })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn abs(p: &str) -> String {
        if cfg!(windows) { format!("C:\\{p}") } else { format!("/{p}") }
    }

    #[test]
    fn a_minimal_block() {
        let dir = PathBuf::from(abs("rt")).join("bitwarden");
        let c = Config::parse(Some(&json!({"bw": abs("bw.exe")})), &dir).unwrap();
        assert_eq!(c.program, PathBuf::from(abs("bw.exe")));
        assert_eq!(c.prefix, Vec::<String>::new());
        assert_eq!(c.data_dir, dir.join("cli"));
        assert_eq!(c.sync_after, DEFAULT_SYNC_AFTER);
        assert!(c.ask_first.is_empty() && c.policy_file.is_none() && c.server.is_none() && c.proxy.is_none());
        let c = Config::parse(
            Some(&json!({"bw": [abs("node.exe"), "bw.js"], "askFirst": ["bank.example"], "syncAfterSeconds": 0, "server": "https://vault.bitwarden.eu", "proxy": "http://10.0.0.1:3128"})),
            &dir,
        )
        .unwrap();
        assert_eq!(c.prefix, ["bw.js"]);
        assert_eq!(c.ask_first, ["bank.example"]);
        assert_eq!(c.sync_after, Duration::ZERO);
        assert_eq!(c.proxy.as_deref(), Some("http://10.0.0.1:3128"));
    }

    #[test]
    fn a_bad_block_is_refused() {
        let dir = PathBuf::from(abs("rt"));
        for block in [
            json!(null),
            json!("bw"),
            json!({}),
            json!({"bw": "bw"}),
            json!({"bw": "bw.exe"}),
            json!({"bw": []}),
            json!({"bw": [5]}),
            json!({"bw": abs("bw.cmd")}),
            json!({"bw": abs("BW.BAT")}),
            json!({"bw": abs("bw.cmd ")}),
            json!({"bw": abs("bw.cmd. .")}),
            json!({"bw": abs("bw.bat::$DATA")}),
            json!({"bw": [abs("bw.CMD "), "x"]}),
            json!({"bw": abs("bw.exe"), "askFirst": ["Bank.example"]}),
            json!({"bw": abs("bw.exe"), "askFirst": ["*.bank.example"]}),
            json!({"bw": abs("bw.exe"), "askFirst": "bank.example"}),
            json!({"bw": abs("bw.exe"), "dataDir": "relative"}),
            json!({"bw": abs("bw.exe"), "syncAfterSeconds": -1}),
            json!({"bw": abs("bw.exe"), "server": "http://vault.test"}),
            json!({"bw": abs("bw.exe"), "proxy": "socks5://10.0.0.1:1080"}),
            json!({"bw": abs("bw.exe"), "proxy": "http://user:pw@10.0.0.1:3128"}),
            json!({"bw": abs("bw.exe"), "proxy": "http://user@10.0.0.1:3128"}),
            json!({"bw": abs("bw.exe"), "proxy": "10.0.0.1:3128"}),
            json!({"bw": abs("bw.exe"), "proxy": 3128}),
            json!({"bw": abs("bw.exe"), "proxy": "http://10.0.0.1:3128\n"}),
            json!({"bw": abs("bw.exe"), "typo": 1}),
        ] {
            assert!(Config::parse(Some(&block), &dir).is_err(), "{block}");
        }
        assert!(Config::parse(None, &dir).is_err());
    }

    #[test]
    #[cfg(windows)]
    fn on_windows_the_program_is_a_named_exe() {
        let dir = PathBuf::from(abs("rt"));
        for ok in ["bw.exe", "BW.EXE", "node.Exe"] {
            assert!(Config::parse(Some(&json!({"bw": abs(ok)})), &dir).is_ok(), "{ok}");
        }
        // Windows would run `bw.exe` for `bw` (or `bw.com`, `bw.exe.`); `bw.ps1` and `bw.js` are no program.
        for refused in ["bw", "bw.com", "bw.exe.", "bw.exe ", "bw.ps1", "bw.js", "exe"] {
            let e = Config::parse(Some(&json!({"bw": abs(refused)})), &dir).unwrap_err();
            assert!(e.0.contains("bw.js"), "{refused}: {e}");
        }
        let e = Config::parse(Some(&json!({"bw": [abs("tools\\node"), abs("bw.js")]})), &dir).unwrap_err();
        assert!(e.0.contains(".exe"), "{e}");
    }
}
