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
use super::provider::{Answer, ask_provider, has_provider};
use super::seal::Request;

/// One way to answer "which saved login, and its values" for a sign-in.
#[async_trait]
pub(crate) trait CredentialSource: Send + Sync {
    /// The values `request.want` names for one login, with its account key; or the label that says why
    /// not. `budget` is all the time it may take.
    async fn ask(&self, request: &Request, budget: Duration) -> Answer;
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
