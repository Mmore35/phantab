//! Where a sign-in's saved login comes from (docs/BITWARDEN.md § Sources). The config's
//! `signInProvider` picks one [`CredentialSource`]:
//!
//! - `{"command": [...]}` (no `source`, or `"source": "command"`): the external provider command and its
//!   sealed protocol ([`super::provider`]), unchanged.
//! - `{"source": "bitwarden", "bitwarden": {...}}`: the built-in Bitwarden source ([`super::bitwarden`]).
//!
//! Any other `source`, or a `bitwarden` source that also names a `command`, answers `provider-failed` on
//! every call: a config that says it wants a source must never quietly get another (fail closed). No
//! `signInProvider` at all is `no-provider`, as before.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use super::Outcome;
use super::bitwarden::BitwardenSource;
use super::bitwarden::config::{Config, ConfigError};
use super::bitwarden::vault::{OsVault, SessionVault};
use super::generate::Rules;
use super::provider::{Answer, ask_provider, has_provider};
use super::seal::Request;
use super::secret::Secret;

/// One way to answer "which saved login, and its values" for a sign-in.
#[async_trait]
pub(crate) trait CredentialSource: Send + Sync {
    /// The values `request.want` names for one login, with its account key; or the label that says why
    /// not. `budget` is all the time it may take.
    async fn ask(&self, request: &Request, budget: Duration) -> Answer;

    /// `browser_sign_up`: the password for `request.username` at `request.origin`, saved and
    /// read back before it is answered. A new one under `request.rules`, or the one already saved for that
    /// exact origin and username (unless `request.regenerate`, which replaces it). Only the built-in
    /// Bitwarden source makes one: any other answers `no-provider-create` and starts nothing.
    async fn create(&self, _request: &CreateRequest, _budget: Duration) -> Created {
        Created::Not(Outcome::of("no-provider-create"))
    }
}

/// What a sign-up asks its source: where, for whom, the item's name, and the password's rules.
#[derive(Debug, Clone)]
pub(crate) struct CreateRequest {
    /// The page's origin (`https://host[:port]`): the only one the login is saved for and found by.
    pub(crate) origin: String,
    pub(crate) username: String,
    /// `<host> (sign-up <YYYY-MM-DD>)`, or the agent's own name for it.
    pub(crate) name: String,
    pub(crate) rules: Rules,
    /// Replace the saved login's password with a new one.
    pub(crate) regenerate: bool,
}

/// Which login a sign-up's password is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Saved {
    /// A new login, saved and read back.
    New,
    /// The login already saved for this origin and username.
    Existing,
    /// The saved login, its password replaced and read back.
    Replaced,
}

/// A source's answer to [`CredentialSource::create`].
#[derive(Debug)]
pub(crate) enum Created {
    Ok { password: Secret, saved: Saved },
    Not(Outcome),
}

/// The external provider command.
pub(crate) struct CommandSource(Value);

#[async_trait]
impl CredentialSource for CommandSource {
    async fn ask(&self, request: &Request, budget: Duration) -> Answer {
        ask_provider(&self.0, request, budget).await
    }
}

/// A config that names a source phantab cannot use.
struct Misconfigured;

#[async_trait]
impl CredentialSource for Misconfigured {
    async fn ask(&self, _request: &Request, _budget: Duration) -> Answer {
        Answer::Not(Outcome::of("provider-failed"))
    }

    async fn create(&self, _request: &CreateRequest, _budget: Duration) -> Created {
        Created::Not(Outcome::of("provider-failed"))
    }
}

/// Which source a `signInProvider` value names.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Named {
    /// None configured: `no-provider`.
    Nothing,
    Command,
    Bitwarden,
    /// A source the config names but phantab cannot use, with why.
    Wrong(String),
}

/// Reads `signInProvider` without starting anything.
pub(crate) fn named(config: Option<&Value>) -> Named {
    let Some(config) = config else { return Named::Nothing };
    match config.get("source") {
        None if has_provider(Some(config)) => Named::Command,
        None => Named::Nothing,
        Some(Value::String(s)) if s == "command" => {
            if has_provider(Some(config)) {
                Named::Command
            } else {
                Named::Wrong("source command has no command".into())
            }
        }
        Some(Value::String(s)) if s == "bitwarden" => {
            if config.get("command").is_some() {
                Named::Wrong("source bitwarden must not also name a command".into())
            } else {
                Named::Bitwarden
            }
        }
        Some(other) => Named::Wrong(format!("unknown sign-in source {other}")),
    }
}

/// Whether a sign-in has any source to ask (else it answers `no-provider`).
pub(crate) fn has_source(config: Option<&Value>) -> bool {
    named(config) != Named::Nothing
}

/// The `bitwarden` block, parsed, when the config names the Bitwarden source.
///
/// # Errors
/// The config names another source (`None` inside), or the block does not parse.
pub(crate) fn bitwarden_config(config: Option<&Value>, bitwarden_dir: &Path) -> Result<Config, ConfigError> {
    match named(config) {
        Named::Bitwarden => Config::parse(config.and_then(|c| c.get("bitwarden")), bitwarden_dir),
        Named::Wrong(why) => Err(ConfigError(why)),
        Named::Nothing | Named::Command => Err(ConfigError(
            "signInProvider does not name the bitwarden source (\"source\": \"bitwarden\")".into(),
        )),
    }
}

/// The source `signInProvider` names. `bitwarden_dir` is `<runtime>/bitwarden`: the Bitwarden source's
/// session store and default CLI data folder.
pub(crate) fn open(config: Option<&Value>, bitwarden_dir: &Path) -> Box<dyn CredentialSource> {
    open_with(config, bitwarden_dir, Box::new(OsVault::new(bitwarden_dir)))
}

/// [`open`] with the session store given (the tests' in-memory one).
pub(crate) fn open_with(
    config: Option<&Value>,
    bitwarden_dir: &Path,
    vault: Box<dyn SessionVault>,
) -> Box<dyn CredentialSource> {
    match named(config) {
        Named::Command => {
            Box::new(CommandSource(config.and_then(|c| c.get("command")).cloned().unwrap_or(Value::Null)))
        }
        Named::Bitwarden => match bitwarden_config(config, bitwarden_dir) {
            Ok(c) => Box::new(BitwardenSource::new(c, vault)),
            Err(_) => Box::new(Misconfigured),
        },
        Named::Nothing | Named::Wrong(_) => Box::new(Misconfigured),
    }
}

/// Test builds only: one Bitwarden source round trip as a sign-in makes it, with the session store held
/// in memory (`session`). Answers the label, and for a login its account key and values.
#[cfg(feature = "test-seams")]
#[allow(clippy::too_many_arguments)] // The request's fields, spelled out for the tests.
pub async fn bitwarden_ask_for_test(
    provider: &Value,
    bitwarden_dir: &Path,
    session: Option<&str>,
    urls: Vec<String>,
    account: Option<String>,
    account_key: Option<String>,
    want: Vec<&'static str>,
    ms: u64,
) -> (Value, Option<(String, Vec<(String, String)>)>) {
    let vault = Box::new(super::bitwarden::vault::MemoryVault::holding(session));
    let source = open_with(Some(provider), bitwarden_dir, vault);
    let request = Request { urls, account, account_key, want };
    match source.ask(&request, Duration::from_millis(ms)).await {
        Answer::Not(outcome) => (super::label::label(&outcome), None),
        Answer::Ok { values, account_key } => {
            let pairs =
                [("username", &values.username), ("password", &values.password), ("code", &values.code)]
                    .into_iter()
                    .filter_map(|(n, v)| v.as_ref().map(|v| (n.to_owned(), v.expose().to_owned())))
                    .collect();
            (serde_json::json!({"status": "ok"}), Some((account_key, pairs)))
        }
    }
}

/// Test builds only: one sign-up create through the configured source, with the session key held in
/// memory (`session`) and the default password rules. Answers the label, and for a password which login
/// it is (`new`, `existing`, `replaced`) and the password, for the test to compare inside itself.
#[cfg(feature = "test-seams")]
#[allow(clippy::too_many_arguments)] // The request's fields, spelled out for the tests.
pub async fn bitwarden_create_for_test(
    provider: &Value,
    bitwarden_dir: &Path,
    session: Option<&str>,
    origin: &str,
    username: &str,
    name: &str,
    regenerate: bool,
    ms: u64,
) -> (Value, Option<(&'static str, String)>) {
    let vault = Box::new(super::bitwarden::vault::MemoryVault::holding(session));
    let source = open_with(Some(provider), bitwarden_dir, vault);
    let Ok(rules) = super::generate::rules(None, None, None) else {
        return (super::label::label_sign_up(&Outcome::FAILED), None);
    };
    let request = CreateRequest {
        origin: origin.to_owned(),
        username: username.to_owned(),
        name: name.to_owned(),
        rules,
        regenerate,
    };
    match source.create(&request, Duration::from_millis(ms)).await {
        Created::Not(outcome) => (super::label::label_sign_up(&outcome), None),
        Created::Ok { password, saved } => {
            let which = match saved {
                Saved::New => "new",
                Saved::Existing => "existing",
                Saved::Replaced => "replaced",
            };
            (serde_json::json!({"status": "ok"}), Some((which, password.expose().to_owned())))
        }
    }
}

/// Test builds only: a sign-up source held in memory, for the fake-page and Chrome tests (never a real
/// vault). It answers only counts and yes or no about what it saved, so a test compares a value inside
/// itself and never prints one.
#[cfg(feature = "test-seams")]
pub struct MemorySource {
    entries: std::sync::Mutex<Vec<(String, String, String, Secret)>>,
    refuse: Option<&'static str>,
    creates: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "test-seams")]
impl std::fmt::Debug for MemorySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemorySource([redacted])")
    }
}

#[cfg(feature = "test-seams")]
impl Default for MemorySource {
    fn default() -> Self {
        MemorySource { entries: std::sync::Mutex::default(), refuse: None, creates: 0.into() }
    }
}

#[cfg(feature = "test-seams")]
impl MemorySource {
    /// A source whose every create answers `status` (`locked`, `ask-first`, ...).
    #[must_use]
    pub fn refusing(status: &'static str) -> Self {
        MemorySource { refuse: Some(status), ..MemorySource::default() }
    }

    /// Saves a login first, as the owner's vault already holding one.
    #[must_use]
    pub fn holding(self, origin: &str, username: &str, password: &str) -> Self {
        crate::util::lock(&self.entries).push((
            origin.to_owned(),
            username.to_owned(),
            format!("{origin} (saved)"),
            Secret::new(password.to_owned()),
        ));
        self
    }

    /// Whether the login saved for `origin` and `username` has `value` as its password.
    pub fn saved_matches(&self, origin: &str, username: &str, value: &str) -> bool {
        crate::util::lock(&self.entries)
            .iter()
            .any(|(o, u, _, p)| o == origin && u == username && p.matches(value))
    }

    /// Whether any saved password, in any form the sweep looks for, is in `text`.
    pub fn found_in(&self, text: &str) -> bool {
        crate::util::lock(&self.entries)
            .iter()
            .flat_map(|(_, _, _, p)| super::web::sweep_forms(Some(p)))
            .any(|f| text.contains(f.expose()))
    }

    /// How many logins it holds.
    pub fn count(&self) -> usize {
        crate::util::lock(&self.entries).len()
    }

    /// The names of the logins it holds.
    pub fn names(&self) -> Vec<String> {
        crate::util::lock(&self.entries).iter().map(|(_, _, n, _)| n.clone()).collect()
    }

    /// How many creates it was asked.
    pub fn creates(&self) -> usize {
        self.creates.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(feature = "test-seams")]
#[async_trait]
impl CredentialSource for MemorySource {
    async fn ask(&self, _request: &Request, _budget: Duration) -> Answer {
        Answer::Not(Outcome::of("none"))
    }

    async fn create(&self, request: &CreateRequest, _budget: Duration) -> Created {
        self.creates.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(status) = self.refuse {
            return Created::Not(Outcome::of(status));
        }
        let mut entries = crate::util::lock(&self.entries);
        let at = entries.iter().position(|(o, u, _, _)| *o == request.origin && *u == request.username);
        match at {
            Some(i) if !request.regenerate => Created::Ok {
                password: Secret::new(entries[i].3.expose().to_owned()),
                saved: Saved::Existing,
            },
            found => {
                let Some(password) = super::generate::password(&request.rules) else {
                    return Created::Not(Outcome::of("provider-failed"));
                };
                let copy = Secret::new(password.expose().to_owned());
                let saved = if let Some(i) = found {
                    entries[i].3 = copy;
                    Saved::Replaced
                } else {
                    entries.push((
                        request.origin.clone(),
                        request.username.clone(),
                        request.name.clone(),
                        copy,
                    ));
                    Saved::New
                };
                Created::Ok { password, saved }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_config_names_the_source() {
        assert_eq!(named(None), Named::Nothing);
        assert_eq!(named(Some(&json!({}))), Named::Nothing);
        assert_eq!(named(Some(&json!({"command": []}))), Named::Nothing);
        assert_eq!(named(Some(&json!({"command": ["p"]}))), Named::Command);
        assert_eq!(named(Some(&json!({"command": "p"}))), Named::Command);
        assert_eq!(named(Some(&json!({"source": "command", "command": ["p"]}))), Named::Command);
        assert_eq!(named(Some(&json!({"source": "bitwarden", "bitwarden": {}}))), Named::Bitwarden);
        assert!(matches!(named(Some(&json!({"source": "command"}))), Named::Wrong(_)));
        assert!(matches!(named(Some(&json!({"source": "bitwarden", "command": ["p"]}))), Named::Wrong(_)));
        assert!(matches!(named(Some(&json!({"source": "1password"}))), Named::Wrong(_)));
        assert!(matches!(named(Some(&json!({"source": 5}))), Named::Wrong(_)));
        assert!(!has_source(None));
        assert!(
            has_source(Some(&json!({"source": "nope"}))),
            "a wrong source is configured: provider-failed"
        );
    }

    #[tokio::test]
    async fn only_bitwarden_creates() {
        let dir = tempfile::tempdir().unwrap();
        let request = CreateRequest {
            origin: "https://a.test".into(),
            username: "u@a.test".into(),
            name: "a.test (sign-up 2026-11-10)".into(),
            rules: super::super::generate::rules(None, None, None).unwrap(),
            regenerate: false,
        };
        // The command source spawns nothing: its program would fail the test's way if it ran.
        let command = json!({"command": [dir.path().join("never-run").to_string_lossy()]});
        let answer = open(Some(&command), dir.path()).create(&request, Duration::from_secs(5)).await;
        assert!(matches!(answer, Created::Not(o) if o == Outcome::of("no-provider-create")));
        let wrong = json!({"source": "nope"});
        let answer = open(Some(&wrong), dir.path()).create(&request, Duration::from_secs(5)).await;
        assert!(matches!(answer, Created::Not(o) if o == Outcome::of("provider-failed")));
    }

    #[tokio::test]
    async fn a_wrong_source_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let request = Request {
            urls: vec!["https://a.test/".into()],
            account: None,
            account_key: None,
            want: vec!["password"],
        };
        for config in [
            json!({"source": "nope"}),
            json!({"source": "bitwarden"}),
            json!({"source": "bitwarden", "bitwarden": {"bw": "relative-bw"}}),
            json!({"source": "bitwarden", "command": ["x"], "bitwarden": {"bw": "/bw"}}),
        ] {
            let answer = open(Some(&config), dir.path()).ask(&request, Duration::from_secs(5)).await;
            assert!(matches!(answer, Answer::Not(o) if o == Outcome::of("provider-failed")), "{config}");
        }
    }
}
