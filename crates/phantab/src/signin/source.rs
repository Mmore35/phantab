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
use super::caps::Caps;
use super::chain::{Chain, Entry, origin_of};
use super::generate::Rules;
use super::provider::{Answer, ask_command, command_parts, create_command, has_provider};
use super::runner::{PinList, parse_pin};
use super::seal::Request;
use super::secret::Secret;

/// One way to answer "which saved login, and its values" for a sign-in.
#[async_trait]
pub(crate) trait CredentialSource: Send + Sync {
    /// What the source can do ([`Caps`]); the chain asks it for nothing else.
    fn caps(&self) -> Caps {
        Caps::LOOKUP
    }

    /// The values `request.want` names for one login, with its account key; or the label that says why
    /// not. `budget` is all the time it may take.
    async fn ask(&self, request: &Request, budget: Duration) -> Answer;

    /// `browser_sign_up`: the password for `request.username` at `request.origin`, saved and
    /// read back before it is answered. A new one under `request.rules`, or the one already saved for that
    /// exact origin and username (unless `request.regenerate`, which replaces it). The built-in Bitwarden
    /// source and a v2 command provider that declared `create` make one: any other answers
    /// `no-provider-create` and starts nothing.
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

/// The external provider command: protocol v1 when its config declares no `caps` (the command alone, as
/// before), else v2 with its declared caps and its `pin` (docs/VAULTS.md § Protocol).
pub(crate) struct CommandSource {
    command: Value,
    /// `None`: v1, which answers sign-ins (lookup and totp) and nothing else.
    caps: Option<Caps>,
    pin: Option<PinList>,
}

impl CommandSource {
    fn v1(command: Value) -> CommandSource {
        CommandSource { command, caps: None, pin: None }
    }
}

#[async_trait]
impl CredentialSource for CommandSource {
    fn caps(&self) -> Caps {
        self.caps.unwrap_or(Caps::LOOKUP.with(Caps::TOTP))
    }

    async fn ask(&self, request: &Request, budget: Duration) -> Answer {
        if !self.caps().has(Caps::LOOKUP) {
            return Answer::Not(Outcome::of("none"));
        }
        ask_command(&self.command, self.pin.as_deref(), self.caps.is_some(), request, budget).await
    }

    async fn create(&self, request: &CreateRequest, budget: Duration) -> Created {
        if self.caps.is_none_or(|c| !c.has(Caps::CREATE)) {
            return Created::Not(Outcome::of("no-provider-create"));
        }
        create_command(&self.command, self.pin.as_deref(), request, budget).await
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
    /// A `signInProviders` list ([`provider_config`]) with at least one entry.
    List,
    /// A source the config names but phantab cannot use, with why.
    Wrong(String),
}

/// The key [`provider_config`] puts the list under, which no single `signInProvider` has.
pub(crate) const LIST: &str = "signInProviders";
/// The key of the list's sign-up target.
pub(crate) const SAVE_TO: &str = "signInSaveTo";
/// The legacy single provider's key, beside the list.
pub(crate) const LEGACY: &str = "signInProvider";

/// What the sign-in calls read as their provider config: the single `signInProvider` as it is, when no
/// `signInProviders` list or `signInSaveTo` is set (so a config from before the list is read exactly as
/// before); else the three together, for [`named`] and [`open_for`] to check.
pub(crate) fn provider_config(config: &crate::runtime::Config) -> Option<Value> {
    if config.sign_in_providers.is_none() && config.sign_in_save_to.is_none() {
        return config.sign_in_provider.clone();
    }
    Some(serde_json::json!({
        LIST: config.sign_in_providers.clone().unwrap_or(Value::Null),
        SAVE_TO: config.sign_in_save_to.clone().unwrap_or(Value::Null),
        LEGACY: config.sign_in_provider.clone().unwrap_or(Value::Null),
    }))
}

/// Reads `signInProvider` (or the list) without starting anything.
pub(crate) fn named(config: Option<&Value>) -> Named {
    let Some(config) = config else { return Named::Nothing };
    if config.get(LIST).is_some() {
        return match entries(config) {
            Ok(list) if list.entries.is_empty() => Named::Nothing,
            Ok(_) => Named::List,
            Err(why) => Named::Wrong(why),
        };
    }
    named_one(config)
}

/// One provider's value, as `signInProvider` was always read: unknown keys are ignored.
fn named_one(config: &Value) -> Named {
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

/// The agent's `vault` argument: a provider name, never a secret. `None` when it is absent or null.
///
/// # Errors
/// Given, but not a provider name ([`valid_name`]): the call's error text.
pub(crate) fn vault_arg(args: &Value) -> Result<Option<&str>, String> {
    match args.get("vault") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) if valid_name(v) => Ok(Some(v.as_str())),
        Some(_) => Err("vault, when given, must be the name of a configured sign-in provider (lower-case \
                        letters, digits and -)."
            .into()),
    }
}

/// Whether a sign-in has any source to ask (else it answers `no-provider`).
pub(crate) fn has_source(config: Option<&Value>) -> bool {
    named(config) != Named::Nothing
}

/// The keys a `signInProviders` entry may have.
const ENTRY_KEYS: &[&str] = &["name", "source", "command", "caps", "pin", "sites", "bitwarden"];

/// The name every config written before the list has as its one source, and the bare one in a list.
pub(crate) const DEFAULT_NAME: &str = "default";

/// One checked entry of the list, before anything is started.
#[derive(Debug, Clone)]
pub(crate) struct EntryConfig {
    pub(crate) name: String,
    pub(crate) kind: Kind,
    pub(crate) sites: Vec<String>,
    /// Its account keys go out as they are ([`super::chain`]).
    pub(crate) bare: bool,
}

/// What an entry starts.
#[derive(Debug, Clone)]
pub(crate) enum Kind {
    Command {
        command: Value,
        caps: Option<Caps>,
        pin: Option<PinList>,
    },
    /// The entry's whole value, for [`Config::parse`] of its `bitwarden` block.
    Bitwarden(Value),
}

/// The checked list and its sign-up target.
#[derive(Debug, Clone)]
pub(crate) struct List {
    pub(crate) entries: Vec<EntryConfig>,
    pub(crate) save_to: Option<String>,
}

/// Whether a provider name is one the config may give: lower-case letters, digits and `-`, starting with
/// a letter or digit, at most 32 characters. No `:`, so a prefixed account key splits one way only.
pub(crate) fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name.len() <= 32
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// One list entry, checked. Unlike the single `signInProvider`, an unknown key is refused: the list is
/// new, so no config written before it has one.
///
/// # Errors
/// Why the entry cannot be used, for the owner.
pub(crate) fn entry(value: &Value) -> Result<EntryConfig, String> {
    let map = value.as_object().ok_or("each signInProviders entry must be an object")?;
    if let Some(k) = map.keys().find(|k| !ENTRY_KEYS.contains(&k.as_str())) {
        return Err(format!("signInProviders entry has an unknown key {k:?}"));
    }
    let name = map.get("name").and_then(Value::as_str).ok_or("each signInProviders entry needs a name")?;
    if !valid_name(name) {
        return Err(format!(
            "provider name {name:?} must be 1 to 32 lower-case letters, digits or -, starting with a letter \
             or digit"
        ));
    }
    let sites = match map.get("sites") {
        None => Vec::new(),
        Some(Value::Array(sites)) => sites
            .iter()
            .map(|s| {
                let s = s.as_str().ok_or_else(|| format!("{name}: sites must be origins"))?;
                match origin_of(s) {
                    Some(o) if o == s && s.starts_with("https://") => Ok(o),
                    _ => {
                        Err(format!("{name}: site {s:?} must be an https origin such as https://example.com"))
                    }
                }
            })
            .collect::<Result<_, String>>()?,
        Some(_) => return Err(format!("{name}: sites must be an array of origins")),
    };
    let kind = match map.get("source") {
        None => command_kind(name, map)?,
        Some(Value::String(s)) if s == "command" => command_kind(name, map)?,
        Some(Value::String(s)) if s == "bitwarden" => {
            if let Some(k) = ["command", "caps", "pin"].into_iter().find(|k| map.contains_key(*k)) {
                return Err(format!("{name}: a bitwarden source has no {k} (its bw is pinned by connect)"));
            }
            Kind::Bitwarden(value.clone())
        }
        Some(other) => return Err(format!("{name}: unknown sign-in source {other}")),
    };
    if map.contains_key("bitwarden") && !matches!(kind, Kind::Bitwarden(_)) {
        return Err(format!("{name}: only a bitwarden source has a bitwarden block"));
    }
    Ok(EntryConfig { name: name.to_owned(), kind, sites, bare: false })
}

fn command_kind(name: &str, map: &serde_json::Map<String, Value>) -> Result<Kind, String> {
    let command = map.get("command").cloned().unwrap_or(Value::Null);
    let Some((program, args)) = command_parts(&command) else {
        return Err(format!(
            "{name}: command must be a JSON array whose first part is the program's absolute path"
        ));
    };
    let caps = map.get("caps").map(|c| Caps::parse(c, Caps::COMMAND_V2).map_err(|e| format!("{name}: {e}")));
    let caps = caps.transpose()?;
    let pin = map.get("pin").map(|p| parse_pin(p, &program, &args).map_err(|e| format!("{name}: {e}")));
    let pin = pin.transpose()?;
    if caps.is_some() && pin.is_none() {
        // A v2 provider can be sent a sign-up's password: it gets the bar `bw` has (SR-85).
        return Err(format!("{name}: a provider that declares caps must be pinned (pin)"));
    }
    Ok(Kind::Command { command, caps, pin })
}

/// The list [`provider_config`] made: each entry checked, names unique, one Bitwarden source at most,
/// `saveTo` a source that creates, and the bare source marked (`default`, else the Bitwarden one). With
/// no list, the legacy `signInProvider` is the one entry, named `default`.
///
/// # Errors
/// Why the list cannot be used: every call then answers `provider-failed`.
pub(crate) fn entries(config: &Value) -> Result<List, String> {
    let legacy = config.get(LEGACY).filter(|v| !v.is_null());
    let mut out: Vec<EntryConfig> = match config.get(LIST) {
        Some(Value::Array(list)) => {
            if legacy.is_some_and(|l| named_one(l) != Named::Nothing) {
                return Err("set signInProviders or signInProvider, not both".into());
            }
            list.iter().map(entry).collect::<Result<_, _>>()?
        }
        None | Some(Value::Null) => match legacy.map(named_one) {
            None | Some(Named::Nothing) => Vec::new(),
            Some(Named::Wrong(why)) => return Err(why),
            Some(Named::Bitwarden) => vec![EntryConfig {
                name: DEFAULT_NAME.into(),
                kind: Kind::Bitwarden(legacy.cloned().unwrap_or(Value::Null)),
                sites: Vec::new(),
                bare: false,
            }],
            Some(Named::Command | Named::List) => vec![EntryConfig {
                name: DEFAULT_NAME.into(),
                kind: Kind::Command {
                    command: legacy.and_then(|l| l.get("command")).cloned().unwrap_or(Value::Null),
                    caps: None,
                    pin: None,
                },
                sites: Vec::new(),
                bare: false,
            }],
        },
        Some(_) => return Err("signInProviders must be an array".into()),
    };
    for (i, e) in out.iter().enumerate() {
        if out[..i].iter().any(|o| o.name == e.name) {
            return Err(format!("provider name {:?} is used twice", e.name));
        }
    }
    if out.iter().filter(|e| matches!(e.kind, Kind::Bitwarden(_))).count() > 1 {
        return Err("only one bitwarden source can be configured (its session store is one)".into());
    }
    let bare = out
        .iter()
        .position(|e| e.name == DEFAULT_NAME)
        .or_else(|| out.iter().position(|e| matches!(e.kind, Kind::Bitwarden(_))));
    if let Some(i) = bare {
        out[i].bare = true;
    }
    let save_to = match config.get(SAVE_TO) {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) => {
            let Some(e) = out.iter().find(|e| e.name == *name) else {
                return Err(format!("signInSaveTo names no configured provider ({name:?})"));
            };
            if !entry_caps(e).has(Caps::CREATE) {
                return Err(format!("signInSaveTo: provider {name:?} does not declare create"));
            }
            Some(name.clone())
        }
        Some(_) => return Err("signInSaveTo must be a provider name".into()),
    };
    Ok(List { entries: out, save_to })
}

/// What an entry's source will declare, without starting it.
pub(crate) fn entry_caps(e: &EntryConfig) -> Caps {
    match &e.kind {
        Kind::Command { caps, .. } => caps.unwrap_or(Caps::LOOKUP.with(Caps::TOTP)),
        Kind::Bitwarden(_) => BitwardenSource::CAPS,
    }
}

/// The `bitwarden` block, parsed, when the config names the Bitwarden source (alone, or as the one
/// Bitwarden entry of the list).
///
/// # Errors
/// The config names another source (`None` inside), or the block does not parse.
pub(crate) fn bitwarden_config(config: Option<&Value>, bitwarden_dir: &Path) -> Result<Config, ConfigError> {
    match named(config) {
        Named::Bitwarden => Config::parse(config.and_then(|c| c.get("bitwarden")), bitwarden_dir),
        Named::List => {
            let list = config.map(entries).and_then(Result::ok).map(|l| l.entries).unwrap_or_default();
            match list.iter().find_map(|e| match &e.kind {
                Kind::Bitwarden(v) => Some(v),
                Kind::Command { .. } => None,
            }) {
                Some(v) => Config::parse(v.get("bitwarden"), bitwarden_dir),
                None => Err(ConfigError("no signInProviders entry is the bitwarden source".into())),
            }
        }
        Named::Wrong(why) => Err(ConfigError(why)),
        Named::Nothing | Named::Command => Err(ConfigError(
            "signInProvider does not name the bitwarden source (\"source\": \"bitwarden\")".into(),
        )),
    }
}

/// The source `signInProvider` names. `bitwarden_dir` is `<runtime>/bitwarden`: the Bitwarden source's
/// session store and default CLI data folder. Calls use [`open_for`]; the tests open this way.
#[cfg(test)]
pub(crate) fn open(config: Option<&Value>, bitwarden_dir: &Path) -> Box<dyn CredentialSource> {
    open_for(config, bitwarden_dir, None)
}

/// [`open`] for a call that may name a `vault` (the agent's argument: a provider name, never a secret).
pub(crate) fn open_for(
    config: Option<&Value>,
    bitwarden_dir: &Path,
    vault: Option<&str>,
) -> Box<dyn CredentialSource> {
    open_with(config, bitwarden_dir, vault, Box::new(OsVault::new(bitwarden_dir)))
}

/// [`open_for`] with the session store given (the tests' in-memory one).
pub(crate) fn open_with(
    config: Option<&Value>,
    bitwarden_dir: &Path,
    vault: Option<&str>,
    store: Box<dyn SessionVault>,
) -> Box<dyn CredentialSource> {
    let Some(config) = config else { return Box::new(Misconfigured) };
    // A config from before the list, and no vault named: the one source, exactly as before.
    if config.get(LIST).is_none() && vault.is_none() {
        return match named_one(config) {
            Named::Command => {
                Box::new(CommandSource::v1(config.get("command").cloned().unwrap_or(Value::Null)))
            }
            Named::Bitwarden => match Config::parse(config.get("bitwarden"), bitwarden_dir) {
                Ok(c) => Box::new(BitwardenSource::new(c, store)),
                Err(_) => Box::new(Misconfigured),
            },
            Named::Nothing | Named::List | Named::Wrong(_) => Box::new(Misconfigured),
        };
    }
    let wrapped;
    let config = if config.get(LIST).is_some() {
        config
    } else {
        wrapped = serde_json::json!({ LEGACY: config });
        &wrapped
    };
    let Ok(list) = entries(config) else { return Box::new(Misconfigured) };
    if list.entries.is_empty() {
        return Box::new(Misconfigured);
    }
    let mut store = Some(store);
    let mut chain = Chain { entries: Vec::new(), save_to: list.save_to, vault: vault.map(str::to_owned) };
    for e in list.entries {
        let source: Box<dyn CredentialSource> = match e.kind {
            Kind::Command { command, caps, pin } => Box::new(CommandSource { command, caps, pin }),
            Kind::Bitwarden(v) => match (Config::parse(v.get("bitwarden"), bitwarden_dir), store.take()) {
                (Ok(c), Some(store)) => Box::new(BitwardenSource::new(c, store)),
                _ => Box::new(Misconfigured),
            },
        };
        chain.entries.push(Entry { name: e.name, bare: e.bare, sites: e.sites, source });
    }
    Box::new(chain)
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
    let call = ProvidersCall { config: provider, bitwarden_dir, vault: None, session, ms };
    providers_ask_for_test(&call, urls, account, account_key, want).await
}

/// Test builds only: what a sign-in or sign-up through the configured providers is opened with. `config`
/// is what [`provider_config`] reads (a legacy `signInProvider` value, or the list's three keys), `vault`
/// the agent's argument, `session` the Bitwarden session record held in memory.
#[cfg(feature = "test-seams")]
#[derive(Debug, Clone, Copy)]
pub struct ProvidersCall<'a> {
    pub config: &'a Value,
    pub bitwarden_dir: &'a Path,
    pub vault: Option<&'a str>,
    pub session: Option<&'a str>,
    pub ms: u64,
}

/// Test builds only: one sign-in through the providers `call` names (one source, or the chain), as the
/// call makes it. Answers the label, and for a login its account key and values.
#[cfg(feature = "test-seams")]
pub async fn providers_ask_for_test(
    call: &ProvidersCall<'_>,
    urls: Vec<String>,
    account: Option<String>,
    account_key: Option<String>,
    want: Vec<&'static str>,
) -> (Value, Option<(String, Vec<(String, String)>)>) {
    let ProvidersCall { config, bitwarden_dir, vault, session, ms } = *call;
    let store = Box::new(super::bitwarden::vault::MemoryVault::holding(session));
    let source = open_with(Some(config), bitwarden_dir, vault, store);
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
    let call = ProvidersCall { config: provider, bitwarden_dir, vault: None, session, ms };
    providers_create_for_test(&call, origin, username, name, regenerate).await
}

/// Test builds only: one sign-up save through the providers `call` names, with the default password
/// rules. Answers the label, and for a password which login it is and the password, for the test to
/// compare inside itself.
#[cfg(feature = "test-seams")]
pub async fn providers_create_for_test(
    call: &ProvidersCall<'_>,
    origin: &str,
    username: &str,
    name: &str,
    regenerate: bool,
) -> (Value, Option<(&'static str, String)>) {
    let ProvidersCall { config, bitwarden_dir, vault, session, ms } = *call;
    let store = Box::new(super::bitwarden::vault::MemoryVault::holding(session));
    let source = open_with(Some(config), bitwarden_dir, vault, store);
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
