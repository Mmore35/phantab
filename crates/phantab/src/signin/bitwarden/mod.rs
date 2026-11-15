//! The built-in Bitwarden source (docs/BITWARDEN.md; THREAT-MODEL SR-62 to SR-67): saved logins from the
//! owner's vault through the official `bw` CLI, without a provider command in between. The answer is
//! the same [`Answer`] the command provider gives, so the pipeline's checks after it (the held account,
//! the guard file, the leak sweep) are unchanged.
//!
//! One call: every URL `https` → ask-first sites → the stored session ([`vault`]), used only with the
//! `bw` it was made with ([`pin`]; else `locked`) → `bw status` →
//! `bw sync` when the local copy is old → one `bw list items --url <page>` → one login by each entry's
//! match setting, as Bitwarden's clients ([`matching`]) → its username and password → `bw get totp <id>`
//! only when the page asks for a code.

pub(crate) mod cli;
pub(crate) mod config;
mod create;
pub(crate) mod matching;
pub(crate) mod pin;
pub(crate) mod policy;
pub(crate) mod vault;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::time::Instant;

use self::cli::{Call, Ran};
use self::config::Config;
use self::vault::{SessionKey, SessionVault};
use super::Outcome;
use super::provider::Answer;
use super::seal::Request;
use super::secret::{Scrubbed, Secret, Values};
use super::source::{CreateRequest, Created, CredentialSource};

/// The least time left in which a call still runs `bw sync` before it lists: the list after it must fit.
const SYNC_NEEDS: Duration = Duration::from_secs(20);

/// What `bw status` says, without the email or server it also prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultState {
    Unlocked,
    Locked,
    Unauthenticated,
}

/// The vault's state and when it last synced (milliseconds since 1970), from `bw status --raw`. `held`:
/// the pinned files `connect` holds, so `bw` is started by their resolved paths.
pub(crate) async fn status(
    config: &Config,
    session: Option<&SessionKey>,
    held: Option<&pin::Held>,
    deadline: Instant,
) -> Result<(VaultState, Option<i64>), Outcome> {
    let call = Call { held, ..Call::new(&["status", "--raw"], session) };
    let out = match cli::run(config, &call, deadline).await {
        Ran::Out(out) => out,
        Ran::TimedOut => return Err(Outcome::of("busy")),
        // The stored key was made with another `bw`: the owner connects again.
        Ran::Unpinned => return Err(Outcome::of("locked")),
        Ran::Failed | Ran::TooBig => return Err(Outcome::of("provider-failed")),
    };
    let v = Scrubbed(serde_json::from_slice(&out).map_err(|_| Outcome::of("provider-failed"))?);
    let state = match v.0.get("status").and_then(Value::as_str) {
        Some("unlocked") => VaultState::Unlocked,
        Some("locked") => VaultState::Locked,
        Some("unauthenticated") => VaultState::Unauthenticated,
        _ => return Err(Outcome::of("provider-failed")),
    };
    Ok((state, v.0.get("lastSync").and_then(Value::as_str).and_then(policy::parse_time)))
}

fn now_millis() -> i64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
}

/// The built-in source over one config and one session store.
pub(crate) struct BitwardenSource {
    config: Config,
    vault: Arc<dyn SessionVault>,
}

impl BitwardenSource {
    /// Lookup, one-time codes and sign-up saves. Passkey release is not answered until passkey sign-in is
    /// built (docs/VAULTS.md § Capabilities).
    pub(crate) const CAPS: super::caps::Caps =
        super::caps::Caps::LOOKUP.with(super::caps::Caps::TOTP).with(super::caps::Caps::CREATE);

    pub(crate) fn new(config: Config, vault: Box<dyn SessionVault>) -> Self {
        BitwardenSource { config, vault: Arc::from(vault) }
    }

    async fn decide(&self, request: &Request, deadline: Instant) -> Result<Answer, Outcome> {
        let c = &self.config;
        let mut hosts = Vec::new();
        for url in &request.urls {
            hosts.push(matching::page_origin(url).ok_or(Outcome::of("refused"))?);
        }
        if hosts.is_empty() {
            return Err(Outcome::of("refused"));
        }
        let sites = policy::sites(&c.ask_first, c.policy_file.as_deref(), now_millis())
            .map_err(|()| Outcome::of("refused"))?;
        if hosts.iter().any(|o| sites.iter().any(|s| policy::host_on(o.host(), s))) {
            return Err(Outcome::of("ask-first"));
        }
        let session = self.open_vault(deadline).await?;
        let page = request.urls[0].as_str();
        let raw = match cli::run(
            c,
            &Call::new(&["list", "items", "--url", page, "--raw"], Some(&session)),
            deadline,
        )
        .await
        {
            Ran::Out(out) => out,
            Ran::TimedOut => return Err(Outcome::of("busy")),
            Ran::Unpinned => return Err(Outcome::of("locked")),
            Ran::Failed | Ran::TooBig => return Err(Outcome::of("provider-failed")),
        };
        // Every candidate's whole item is in here: it is scrubbed when this call ends.
        let parsed = serde_json::from_slice::<Value>(&raw);
        drop(raw);
        let mut list = Scrubbed(parsed.map_err(|_| Outcome::of("provider-failed"))?);
        let Some(items) = list.0.as_array_mut() else { return Err(Outcome::of("provider-failed")) };
        let chosen = matching::choose(
            items,
            &request.urls,
            request.account.as_deref(),
            request.account_key.as_deref(),
        )?;
        let item = &mut items[chosen];
        if !no_reprompt(item.get("reprompt")) {
            // The owner asked Bitwarden to ask for the master password before this login is used.
            return Err(Outcome::of("refused"));
        }
        if matching::entries(item).iter().any(|(uri, _)| sites.iter().any(|s| policy::uri_names(uri, s))) {
            return Err(Outcome::of("ask-first"));
        }
        let id = item.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
        let has_totp = item.pointer("/login/totp").and_then(Value::as_str).is_some_and(|t| !t.is_empty());
        // A login saved with a passkey and no password: the owner signs in with the passkey, which only
        // he can give. Only whether the list is empty is read, never what is in it.
        let has_passkey =
            item.pointer("/login/fido2Credentials").and_then(Value::as_array).is_some_and(|c| !c.is_empty());
        let mut values = Values::default();
        for name in &request.want {
            match *name {
                "username" => {
                    values.username = Some(take(item, "/login/username").ok_or(Outcome::of("none"))?);
                }
                "password" => {
                    let none =
                        if has_passkey { Outcome::with("wall", "passkey") } else { Outcome::of("none") };
                    values.password = Some(take(item, "/login/password").ok_or(none)?);
                }
                _ => {}
            }
        }
        drop(list);
        if request.want.contains(&"code") {
            if !has_totp {
                return Err(Outcome::with("wall", "code-not-saved"));
            }
            values.code = Some(self.code(&id, &session, deadline).await?);
        }
        Ok(Answer::Ok { values, account_key: matching::account_key(&id) })
    }

    /// The stored session, used only on an unlocked vault, after a `bw sync` when the local copy is old.
    async fn open_vault(&self, deadline: Instant) -> Result<SessionKey, Outcome> {
        let c = &self.config;
        // The load can wait on the owner: macOS may ask once for Keychain access after a binary update. It
        // runs off the runtime's threads and within the call's deadline; one that runs out answers
        // provider-failed while the prompt stays up for the owner, and a later call finds the key.
        let vault = Arc::clone(&self.vault);
        let load = tokio::task::spawn_blocking(move || vault.load());
        let session = match tokio::time::timeout_at(deadline, load).await {
            Ok(Ok(Ok(Some(key)))) => key,
            Ok(Ok(Ok(None))) => return Err(Outcome::of("locked")),
            _ => return Err(Outcome::of("provider-failed")),
        };
        let (state, last_sync) = status(c, Some(&session), None, deadline).await?;
        if state != VaultState::Unlocked {
            return Err(Outcome::of("locked"));
        }
        let old_copy = last_sync.is_none_or(|at| {
            now_millis().saturating_sub(at) >= i64::try_from(c.sync_after.as_millis()).unwrap_or(i64::MAX)
        });
        if old_copy && deadline.saturating_duration_since(Instant::now()) > SYNC_NEEDS {
            // Offline or refused, the local copy still answers; a sync that runs out the clock is `busy`.
            match cli::run(c, &Call::new(&["sync"], Some(&session)), deadline).await {
                Ran::TimedOut => return Err(Outcome::of("busy")),
                Ran::Unpinned => return Err(Outcome::of("locked")),
                Ran::Out(_) | Ran::Failed | Ran::TooBig => {}
            }
        }
        Ok(session)
    }

    async fn code(&self, id: &str, session: &SessionKey, deadline: Instant) -> Result<Secret, Outcome> {
        let out =
            match cli::run(&self.config, &Call::new(&["get", "totp", id], Some(session)), deadline).await {
                Ran::Out(out) => out,
                Ran::TimedOut => return Err(Outcome::of("busy")),
                Ran::Unpinned => return Err(Outcome::of("locked")),
                Ran::Failed | Ran::TooBig => return Err(Outcome::with("wall", "code-not-saved")),
            };
        let code = std::str::from_utf8(&out).map(str::trim).unwrap_or_default();
        if code.len() < 4 || code.len() > 10 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Outcome::with("wall", "code-not-saved"));
        }
        Ok(Secret::new(code.to_owned()))
    }
}

/// Whether an item's `reprompt` lets it be used without the master password: only when it is missing,
/// `null` or the integer `0` (`CipherRepromptType.None`). Anything else refuses, so a value a later
/// Bitwarden writes another way (`1.0`, `"1"`, `true`, a new type) never reads as "no reprompt".
fn no_reprompt(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        // `as_u64` is `None` for a float, so `0.0` refuses too.
        Some(Value::Number(n)) => n.as_u64() == Some(0),
        Some(_) => false,
    }
}

/// Moves one non-empty string out of the item into a [`Secret`], leaving an empty string behind.
fn take(item: &mut Value, pointer: &str) -> Option<Secret> {
    match item.pointer_mut(pointer) {
        Some(Value::String(s)) if !s.is_empty() => Some(Secret::new(std::mem::take(s))),
        _ => None,
    }
}

#[async_trait]
impl CredentialSource for BitwardenSource {
    fn caps(&self) -> super::caps::Caps {
        Self::CAPS
    }

    async fn ask(&self, request: &Request, budget: Duration) -> Answer {
        self.decide(request, Instant::now() + budget).await.unwrap_or_else(Answer::Not)
    }

    async fn create(&self, request: &CreateRequest, budget: Duration) -> Created {
        match self.make(request, Instant::now() + budget).await {
            Ok((password, saved)) => Created::Ok { password, saved },
            Err(why) => Created::Not(why),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::no_reprompt;

    #[test]
    fn only_a_missing_null_or_integer_zero_reprompt_passes() {
        assert!(no_reprompt(None));
        for ok in [json!(null), json!(0)] {
            assert!(no_reprompt(Some(&ok)), "{ok}");
        }
        for refused in [
            json!(1),
            json!(2),
            json!(-1),
            json!(1.0),
            json!(0.0),
            json!(0.5),
            json!("0"),
            json!("1"),
            json!(true),
            json!(false),
            json!({}),
            json!([]),
        ] {
            assert!(!no_reprompt(Some(&refused)), "{refused}");
        }
    }
}
