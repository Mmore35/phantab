//! The built-in Bitwarden source against the fake `bw` binary, without Chrome or a real vault
//! (docs/BITWARDEN.md § Testing; THREAT-MODEL SR-62 to SR-67): exact-origin matching, ambiguity, locked
//! and logged-out vaults, ask-first, the output cap and the deadline, the child's environment, and that
//! no value reaches a label, an error or the fake's log. Then `phantab bitwarden connect`, `status` and
//! `disconnect` over an in-memory session store, and that a stored key goes only to the `bw` it was made
//! with.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use phantab::bitwarden::test_seams;
use phantab::signin::{bitwarden_ask_for_test, bitwarden_create_for_test};
use phantab_testkit::sign_in::{CODE, PASSWORD, USERNAME};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const FAKE: &str = env!("CARGO_BIN_EXE_phantab-fake-bw");
const SESSION: &str = "ZmFrZS1zZXNzaW9uLWtleS1mb3ItdGVzdHM=";
const MASTER: &str = "M4ster pw sentinel!";
const ID1: &str = "6c1f2a3b-0001-4d5e-8f90-a1b2c3d4e5f6";
const ID2: &str = "6c1f2a3b-0002-4d5e-8f90-a1b2c3d4e5f6";
const PAGE: &str = "https://login.site.test/signin";
/// The name the pin starts a program by with no script: any other program alone would be given `bw`'s
/// arguments, which an interpreter runs as code.
const BW: &str = if cfg!(windows) { "bw.exe" } else { "bw" };

/// The fake, copied to a file named [`BW`] in this build's test scratch folder. The folder is named by
/// the fake's SHA-256, so each build of it is copied once and every test (and test process) shares it.
fn fake() -> &'static Path {
    static COPY: OnceLock<PathBuf> = OnceLock::new();
    COPY.get_or_init(|| {
        let bytes = std::fs::read(FAKE).unwrap();
        let named = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fake-bw").join(&sha256_hex(&bytes)[..16]);
        let copy = named.join(BW);
        if std::fs::read(&copy).ok().as_deref() != Some(bytes.as_slice()) {
            std::fs::create_dir_all(&named).unwrap();
            let part = named.join(format!("{BW}.{}.part", std::process::id()));
            std::fs::copy(FAKE, &part).unwrap();
            // Another test process may have put it there first, and be running it.
            if std::fs::rename(&part, &copy).is_err() {
                let _ = std::fs::remove_file(&part);
            }
            assert_eq!(std::fs::read(&copy).unwrap(), bytes, "{}", copy.display());
        }
        copy
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().fold(String::new(), |mut hex, b| {
        write!(hex, "{b:02x}").unwrap();
        hex
    })
}

/// `signInProvider` naming the fake, with `extra` keys in its `bitwarden` block.
fn provider(extra: &Value) -> Value {
    provider_for(fake(), extra)
}

/// `signInProvider` naming the `bw` at `bw`, with `extra` keys in its `bitwarden` block.
fn provider_for(bw: &Path, extra: &Value) -> Value {
    let mut block = json!({"bw": bw});
    for (k, v) in extra.as_object().unwrap() {
        block[k] = v.clone();
    }
    json!({"source": "bitwarden", "bitwarden": block})
}

/// The record `connect` would store for `key` with the `bw` that `provider` names.
fn pinned(provider: &Value, dir: &Path, key: &str) -> String {
    test_seams::pinned(provider, dir, key).unwrap()
}

/// The key in a stored record, after its header and pin lines.
fn key_in(record: Option<&str>) -> Option<&str> {
    let record = record?;
    assert!(record.starts_with("phantab-bw-session-2\n"), "a pinned record: {record}");
    record.rsplit('\n').next()
}

struct Fake {
    dir: tempfile::TempDir,
}

fn login(id: &str, name: &str, uris: &Value) -> Value {
    json!({
        "object": "item", "id": id, "type": 1, "name": name, "reprompt": 0, "deletedDate": null,
        "login": {"username": USERNAME, "password": PASSWORD, "totp": null, "uris": uris},
    })
}

fn one_login() -> Value {
    login(ID1, "Site", &json!([{"match": null, "uri": "https://login.site.test"}]))
}

#[allow(clippy::many_single_char_names)] // the algorithm's own names
fn recent() -> String {
    // Any time inside the last five minutes: phantab only compares it with its sync threshold.
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let days = secs / 86_400;
    let (h, m, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
    // civil_from_days (Howard Hinnant), for the test's own clock text.
    let z = i64::try_from(days).unwrap() + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.000Z")
}

/// macOS: a scratch keychain, named to the phantab binary `cmd` runs (`PHANTAB_TEST_KEYCHAIN`, honoured
/// only in a `test-seams` build), so its Keychain calls use it: a test build never opens the owner's
/// login keychain. Deleted when the result drops, also while a panic unwinds.
#[cfg(target_os = "macos")]
fn scratch_keychain(
    cmd: &mut std::process::Command,
) -> phantab_window::secret_store::test_keychain::TestKeychain {
    let keychain = phantab_window::secret_store::test_keychain::TestKeychain::create().unwrap();
    cmd.env("PHANTAB_TEST_KEYCHAIN", keychain.path())
        .env("PHANTAB_TEST_KEYCHAIN_PASSWORD", keychain.password());
    keychain
}

/// `phantab bitwarden status` over the scratch runtime `f`, with no test keychain named unless `cmd`'s
/// caller adds one.
fn status_command(f: &Fake) -> std::process::Command {
    std::fs::write(
        f.dir.path().join("config.json"),
        json!({"signInProvider": provider(&json!({}))}).to_string(),
    )
    .unwrap();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_phantab"));
    cmd.args(["bitwarden", "status"])
        .env("PHANTAB_RUNTIME", f.dir.path())
        .env_remove("PHANTAB_TEST_KEYCHAIN")
        .env_remove("PHANTAB_TEST_KEYCHAIN_PASSWORD");
    cmd
}

/// The session `status` reports.
fn session_shown(out: &std::process::Output) -> Value {
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let shown: Value = serde_json::from_slice(&out.stdout).unwrap();
    shown["session"].clone()
}

impl Fake {
    fn new() -> Self {
        Fake { dir: tempfile::Builder::new().prefix("phantab-signin-bitwarden-").tempdir().unwrap() }
    }

    /// `<runtime>/bitwarden`, as the source sees it.
    fn bitwarden_dir(&self) -> PathBuf {
        self.dir.path().join("bitwarden")
    }

    /// The CLI's data folder: the default, `<runtime>/bitwarden/cli`.
    fn data(&self) -> PathBuf {
        self.bitwarden_dir().join("cli")
    }

    /// The fake's control file: an unlocked vault holding [`one_login`], synced just now, then `fields`.
    fn control(&self, fields: &Value) {
        let mut c = json!({
            "status": "unlocked", "session": SESSION, "masterPassword": MASTER, "lastSync": recent(),
            "items": [one_login()], "totp": {},
        });
        for (k, v) in fields.as_object().unwrap() {
            c[k] = v.clone();
        }
        std::fs::create_dir_all(self.data()).unwrap();
        std::fs::write(self.data().join("fake-bw.json"), c.to_string()).unwrap();
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(self.data().join("fake-bw.log")).unwrap_or_default()
    }

    fn runs(&self) -> Vec<Value> {
        self.log_text().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    /// The command names the fake ran, in order.
    fn commands(&self) -> Vec<String> {
        self.runs().iter().map(|r| r["argv"][0].as_str().unwrap_or_default().to_owned()).collect()
    }

    async fn ask_with(
        &self,
        extra: &Value,
        urls: &[&str],
        account: Option<&str>,
        held: Option<String>,
        want: Vec<&'static str>,
        ms: u64,
    ) -> (Value, Option<(String, Vec<(String, String)>)>) {
        bitwarden_ask_for_test(
            &provider(extra),
            &self.bitwarden_dir(),
            Some(&pinned(&provider(extra), &self.bitwarden_dir(), SESSION)),
            urls.iter().map(|u| (*u).to_owned()).collect(),
            account.map(str::to_owned),
            held,
            want,
            ms,
        )
        .await
    }

    async fn ask(&self, want: Vec<&'static str>) -> Value {
        self.ask_with(&json!({}), &[PAGE], None, None, want, 20_000).await.0
    }
}

fn key_of(id: &str) -> String {
    let digest = Sha256::digest(format!("phantab-sign-in:{id}").as_bytes());
    let mut hex = String::new();
    for b in digest {
        write!(hex, "{b:02x}").unwrap();
    }
    hex[..32].to_owned()
}

/// No value of the fixture login, nor the master password, in `text`.
fn assert_no_value(text: &str) {
    for value in [PASSWORD, USERNAME, CODE, MASTER, "S3ntinel", "M4ster"] {
        assert!(!text.contains(value), "a value leaked: {value} in {text}");
    }
}

#[tokio::test]
async fn one_exact_login_answers_its_values_and_key() {
    let f = Fake::new();
    f.control(&json!({}));
    let (label, opened) =
        f.ask_with(&json!({}), &[PAGE], None, None, vec!["username", "password"], 20_000).await;
    assert_eq!(label, json!({"status": "ok"}));
    let (key, values) = opened.unwrap();
    assert_eq!(key, key_of(ID1), "the per-item account key, so guard stops keep meaning this login");
    assert_eq!(
        values,
        [("username".to_owned(), USERNAME.to_owned()), ("password".to_owned(), PASSWORD.to_owned())]
    );
    // status, then one list by the page URL; no sync (fresh), no second fetch, no TOTP (not wanted).
    assert_eq!(f.commands(), ["status", "list"]);
    let runs = f.runs();
    assert_eq!(runs[1]["argv"], json!(["list", "items", "--url", PAGE, "--raw", "--nointeraction"]));
    for run in &runs {
        assert_eq!(run["session"], "match", "the session reaches the child in BW_SESSION");
        let argv = run["argv"].to_string();
        assert!(!argv.contains(SESSION), "never on the command line: {argv}");
    }
    assert_no_value(&f.log_text());
}

/// The variables a `bw` child may see (THREAT-MODEL SR-65).
const ALLOWED: &[&str] = &[
    "SystemRoot",
    "windir",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "BITWARDENCLI_APPDATA_DIR",
    "BW_NOINTERACTION",
    "BW_SESSION",
];

#[tokio::test]
async fn the_child_gets_a_small_environment() {
    let f = Fake::new();
    f.control(&json!({}));
    assert_eq!(f.ask(vec!["password"]).await, json!({"status": "ok"}));
    for run in f.runs() {
        for name in run["env"].as_array().unwrap() {
            let name = name.as_str().unwrap();
            // Windows may add its own per-process variables (`=C:` and the like) to every child.
            if name.starts_with('=') {
                continue;
            }
            assert!(ALLOWED.iter().any(|a| a.eq_ignore_ascii_case(name)), "{name} reached bw");
        }
    }
}

#[tokio::test]
async fn each_entry_is_matched_by_its_own_setting() {
    let f = Fake::new();
    // What `bw list --url` may return for the page: a base-domain login for the parent domain (the
    // default, which fits a subdomain), a host-only one for a sibling, http, a pattern and a never.
    f.control(&json!({"items": [
        login(ID1, "Parent", &json!([{"uri": "https://site.test"}])),
        login(ID2, "Sibling", &json!([{"uri": "https://www.site.test", "match": 1}])),
        login("6c1f2a3b-0003-4d5e-8f90-a1b2c3d4e5f6", "Plain", &json!([{"uri": "http://login.site.test"}])),
        login("6c1f2a3b-0004-4d5e-8f90-a1b2c3d4e5f6", "Pattern", &json!([{"uri": ".*site\\.test", "match": 4}])),
        login("6c1f2a3b-0005-4d5e-8f90-a1b2c3d4e5f6", "Never", &json!([{"uri": "https://login.site.test", "match": 5}])),
    ]}));
    let (label, opened) = f.ask_with(&json!({}), &[PAGE], None, None, vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "ok"}));
    assert_eq!(opened.unwrap().0, key_of(ID1), "only the base-domain login fits");
    // Base domain on both: the parent and a sibling subdomain each fit, so the agent must name one.
    f.control(&json!({"items": [
        login(ID1, "Parent", &json!([{"uri": "https://site.test"}])),
        login(ID2, "Sibling", &json!([{"uri": "https://www.site.test", "match": 0}])),
    ]}));
    assert_eq!(f.ask(vec!["password"]).await, json!({"status": "ambiguous", "count": 2}));
    // Neither another site nor a shared suffix's other tenant.
    f.control(&json!({"items": [
        login(ID1, "Other", &json!([{"uri": "https://othersite.test"}])),
        login(ID2, "Lookalike", &json!([{"uri": "https://login.site.test.evil.test"}])),
    ]}));
    assert_eq!(f.ask(vec!["password"]).await, json!({"status": "none"}));
}

#[tokio::test]
async fn two_fits_are_ambiguous_until_the_agent_names_one() {
    let f = Fake::new();
    f.control(&json!({"items": [
        login(ID1, "Work", &json!([{"uri": "https://login.site.test"}])),
        login(ID2, "Home", &json!([{"uri": "login.site.test"}])),
    ]}));
    assert_eq!(f.ask(vec!["password"]).await, json!({"status": "ambiguous", "count": 2}));
    let (label, opened) = f.ask_with(&json!({}), &[PAGE], Some("Home"), None, vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "ok"}));
    assert_eq!(opened.unwrap().0, key_of(ID2));
    // A page that already used a login keeps it; another key is refused.
    let (label, _) = f.ask_with(&json!({}), &[PAGE], None, Some(key_of(ID1)), vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "ok"}));
    let (label, _) =
        f.ask_with(&json!({}), &[PAGE], None, Some("f".repeat(32)), vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "refused"}));
}

#[tokio::test]
async fn a_form_that_posts_elsewhere_needs_its_own_entry() {
    let f = Fake::new();
    f.control(&json!({}));
    let urls = [PAGE, "https://sso.other.test/form"];
    let (label, _) = f.ask_with(&json!({}), &urls, None, None, vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "wall", "reason": "form-posts-elsewhere"}));
}

#[tokio::test]
async fn a_code_is_fetched_only_when_the_page_asks() {
    let f = Fake::new();
    let mut item = one_login();
    item["login"]["totp"] = json!("otpauth://totp/fixture?secret=JBSWY3DPEHPK3PXP");
    f.control(&json!({"items": [item], "totp": {ID1: CODE}}));
    let (label, opened) = f.ask_with(&json!({}), &[PAGE], None, None, vec!["code"], 20_000).await;
    assert_eq!(label, json!({"status": "ok"}));
    assert_eq!(opened.unwrap().1, [("code".to_owned(), CODE.to_owned())]);
    assert_eq!(f.commands(), ["status", "list", "get"]);
    assert_eq!(f.runs()[2]["argv"], json!(["get", "totp", ID1, "--nointeraction"]));
    // No authenticator key saved: a wall, and no `get totp`.
    let g = Fake::new();
    g.control(&json!({}));
    assert_eq!(g.ask(vec!["code"]).await, json!({"status": "wall", "reason": "code-not-saved"}));
    assert_eq!(g.commands(), ["status", "list"]);
    // `get totp` fails: the same wall.
    let h = Fake::new();
    let mut item = one_login();
    item["login"]["totp"] = json!("JBSWY3DPEHPK3PXP");
    h.control(&json!({"items": [item], "fail": ["get"]}));
    assert_eq!(h.ask(vec!["code"]).await, json!({"status": "wall", "reason": "code-not-saved"}));
}

#[tokio::test]
async fn a_locked_or_logged_out_vault_is_locked() {
    let f = Fake::new();
    f.control(&json!({}));
    // No stored session: `bw` is not even started.
    let (label, _) = bitwarden_ask_for_test(
        &provider(&json!({})),
        &f.bitwarden_dir(),
        None,
        vec![PAGE.into()],
        None,
        None,
        vec!["password"],
        20_000,
    )
    .await;
    assert_eq!(label, json!({"status": "locked"}));
    assert_eq!(f.commands(), Vec::<String>::new());
    // A stored session the CLI no longer takes.
    let (label, _) = bitwarden_ask_for_test(
        &provider(&json!({})),
        &f.bitwarden_dir(),
        Some(&pinned(&provider(&json!({})), &f.bitwarden_dir(), "c3RhbGU=")),
        vec![PAGE.into()],
        None,
        None,
        vec!["password"],
        20_000,
    )
    .await;
    assert_eq!(label, json!({"status": "locked"}));
    assert_eq!(f.commands(), ["status"]);
    for status in ["locked", "unauthenticated"] {
        let g = Fake::new();
        g.control(&json!({"status": status}));
        assert_eq!(g.ask(vec!["password"]).await, json!({"status": "locked"}), "{status}");
        assert_eq!(g.commands(), ["status"]);
    }
}

#[tokio::test]
async fn ask_first_sites_stop_before_the_vault() {
    let f = Fake::new();
    f.control(&json!({}));
    let (label, _) =
        f.ask_with(&json!({"askFirst": ["site.test"]}), &[PAGE], None, None, vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "ask-first"}));
    assert_eq!(f.commands(), Vec::<String>::new(), "not one bw run for an ask-first page");
    // A login saved for an ask-first site too, used on another page, also asks.
    let g = Fake::new();
    g.control(&json!({"items": [login(ID1, "Bank", &json!([{"uri": "https://login.site.test"}, {"uri": "https://bank.test"}]))]}));
    let (label, _) =
        g.ask_with(&json!({"askFirst": ["bank.test"]}), &[PAGE], None, None, vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "ask-first"}));
    // The policy file: its own sites, an approval that has run out, and a broken file refuses. (An approval
    // that lifts a site is the policy unit test's.)
    let policy = f.dir.path().join("sign-in-policy.json");
    std::fs::write(&policy, json!({"askFirst": ["site.test"]}).to_string()).unwrap();
    let with_policy = json!({"policyFile": policy});
    let (label, _) = f.ask_with(&with_policy, &[PAGE], None, None, vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "ask-first"}));
    let now = recent();
    let approval =
        json!({"site": "site.test", "at": now, "until": "2999-01-01T00:00:00Z", "words": "too long"});
    std::fs::write(&policy, json!({"askFirst": ["site.test"], "approvals": [approval]}).to_string()).unwrap();
    let (label, _) = f.ask_with(&with_policy, &[PAGE], None, None, vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "ask-first"}), "an approval longer than an hour counts for nothing");
    std::fs::write(&policy, "{broken").unwrap();
    let (label, _) = f.ask_with(&with_policy, &[PAGE], None, None, vec!["password"], 20_000).await;
    assert_eq!(label, json!({"status": "refused"}));
    assert_eq!(f.commands(), Vec::<String>::new());
}

#[tokio::test]
async fn refusals_before_and_after_the_list() {
    let f = Fake::new();
    f.control(&json!({}));
    let (label, _) = f
        .ask_with(&json!({}), &["http://login.site.test/signin"], None, None, vec!["password"], 20_000)
        .await;
    assert_eq!(label, json!({"status": "refused"}), "https only");
    assert_eq!(f.commands(), Vec::<String>::new());
    let g = Fake::new();
    let mut item = one_login();
    item["reprompt"] = json!(1);
    g.control(&json!({"items": [item]}));
    assert_eq!(
        g.ask(vec!["password"]).await,
        json!({"status": "refused"}),
        "a master-password reprompt item"
    );
    // Only a missing, null or integer-zero reprompt lets the login through (sec-creds-5).
    for (reprompt, want) in [
        (Some(json!(1.0)), "refused"),
        (Some(json!("1")), "refused"),
        (Some(json!("0")), "refused"),
        (Some(json!(0.0)), "refused"),
        (Some(json!(true)), "refused"),
        (Some(json!(2)), "refused"),
        (Some(json!(-1)), "refused"),
        (Some(json!({})), "refused"),
        (Some(json!(0)), "ok"),
        (Some(Value::Null), "ok"),
        (None, "ok"),
    ] {
        let r = Fake::new();
        let mut item = one_login();
        match &reprompt {
            Some(v) => item["reprompt"] = v.clone(),
            None => {
                item.as_object_mut().unwrap().remove("reprompt");
            }
        }
        r.control(&json!({"items": [item]}));
        assert_eq!(r.ask(vec!["password"]).await["status"], json!(want), "reprompt {reprompt:?}");
    }
    let h = Fake::new();
    let mut item = one_login();
    item["login"]["password"] = Value::Null;
    h.control(&json!({"items": [item]}));
    assert_eq!(h.ask(vec!["password"]).await, json!({"status": "none"}), "no saved password");
}

/// A login saved with a passkey and no password is the owner's to sign in with: `wall` / `passkey`,
/// not `none`. A password next to a passkey is used as before, and an empty list is no passkey.
#[tokio::test]
async fn a_passkey_with_no_password_is_a_passkey_wall() {
    let passkey = json!([{"credentialId": "c", "rpId": "example.test", "keyValue": "k"}]);
    for (password, credentials, want) in [
        (Value::Null, passkey.clone(), json!({"status": "wall", "reason": "passkey"})),
        (json!(""), passkey.clone(), json!({"status": "wall", "reason": "passkey"})),
        (Value::Null, json!([]), json!({"status": "none"})),
        (Value::Null, Value::Null, json!({"status": "none"})),
    ] {
        let f = Fake::new();
        let mut item = one_login();
        item["login"]["password"] = password.clone();
        item["login"]["fido2Credentials"] = credentials.clone();
        f.control(&json!({"items": [item]}));
        assert_eq!(f.ask(vec!["password"]).await, want, "{password} {credentials}");
    }
    let f = Fake::new();
    let mut item = one_login();
    item["login"]["fido2Credentials"] = passkey;
    f.control(&json!({"items": [item]}));
    assert_eq!(f.ask(vec!["password"]).await["status"], "ok", "a saved password still signs in");
}

#[tokio::test]
async fn bad_output_fails_and_a_slow_cli_is_busy() {
    for (fields, want) in [
        (json!({"huge": ["list"]}), json!({"status": "provider-failed"})),
        (json!({"malformed": ["list"]}), json!({"status": "provider-failed"})),
        (json!({"malformed": ["status"]}), json!({"status": "provider-failed"})),
        (json!({"fail": ["list"]}), json!({"status": "provider-failed"})),
        (json!({"items": {"not": "a list"}}), json!({"status": "provider-failed"})),
    ] {
        let f = Fake::new();
        f.control(&fields);
        assert_eq!(f.ask(vec!["password"]).await, want, "{fields}");
    }
    let f = Fake::new();
    f.control(&json!({"delayMs": {"list": 30_000}}));
    let started = Instant::now();
    let (label, _) = f.ask_with(&json!({}), &[PAGE], None, None, vec!["password"], 3000).await;
    assert_eq!(label, json!({"status": "busy"}));
    assert!(started.elapsed().as_secs() < 15, "the deadline ends the call: {:?}", started.elapsed());
}

#[tokio::test]
async fn an_old_copy_syncs_first_and_a_failed_sync_still_answers() {
    // A sync only starts with more than 20 s left, so these calls have the default 45 s.
    let ms = 45_000;
    let f = Fake::new();
    f.control(&json!({"lastSync": "2020-01-01T00:00:00.000Z"}));
    let (label, _) = f.ask_with(&json!({}), &[PAGE], None, None, vec!["password"], ms).await;
    assert_eq!(label, json!({"status": "ok"}));
    assert_eq!(f.commands(), ["status", "sync", "list"]);
    let g = Fake::new();
    g.control(&json!({"lastSync": null, "fail": ["sync"]}));
    let (label, _) = g.ask_with(&json!({}), &[PAGE], None, None, vec!["password"], ms).await;
    assert_eq!(label, json!({"status": "ok"}), "offline: the local copy answers");
    assert_eq!(g.commands(), ["status", "sync", "list"]);
    // With 20 s or less left, the local copy answers without a sync.
    let h = Fake::new();
    h.control(&json!({"lastSync": null}));
    assert_eq!(h.ask(vec!["password"]).await, json!({"status": "ok"}));
    assert_eq!(h.commands(), ["status", "list"]);
}

#[tokio::test]
async fn connect_unlocks_with_a_hidden_password_and_keeps_only_the_session() {
    let f = Fake::new();
    f.control(&json!({"status": "locked"}));
    let config = provider(&json!({}));
    let (out, stored) = test_seams::connect(&config, &f.bitwarden_dir(), None, Some(MASTER)).await;
    assert_eq!(out, Ok(()));
    assert_eq!(key_in(stored.as_deref()), Some(SESSION));
    assert_eq!(stored, Some(pinned(&config, &f.bitwarden_dir(), SESSION)), "pinned to the fake as it is");
    let runs = f.runs();
    let unlock = runs.iter().find(|r| r["argv"][0] == "unlock").unwrap();
    assert_eq!(
        unlock["argv"],
        json!(["unlock", "--passwordenv", "PHANTAB_BW_MASTER", "--raw", "--nointeraction"])
    );
    assert_eq!(unlock["password"], "match");
    for run in runs.iter().filter(|r| r["argv"][0] != "unlock") {
        assert!(
            !run["env"].as_array().unwrap().iter().any(|n| n == "PHANTAB_BW_MASTER"),
            "the password went only to unlock"
        );
    }
    assert_no_value(&f.log_text());
    // A wrong password stores nothing, and the error does not repeat it.
    let g = Fake::new();
    g.control(&json!({"status": "locked"}));
    let (out, stored) =
        test_seams::connect(&provider(&json!({})), &g.bitwarden_dir(), None, Some("wrong pw sentinel")).await;
    let err = out.unwrap_err();
    assert!(!err.contains("wrong pw sentinel"), "{err}");
    assert_eq!(stored, None);
}

#[tokio::test]
async fn connect_logs_a_logged_out_cli_in_without_the_password_prompt() {
    let f = Fake::new();
    f.control(&json!({"status": "unauthenticated"}));
    let config = provider(&json!({"server": "https://vault.example.test"}));
    // `None`: reaching the master-password prompt would be an error. Login's own prompts are the CLI's.
    let (out, stored) = test_seams::connect(&config, &f.bitwarden_dir(), None, None).await;
    assert_eq!(out, Ok(()));
    assert_eq!(key_in(stored.as_deref()), Some(SESSION));
    assert_eq!(f.commands(), ["status", "config", "login", "status"]);
    assert_eq!(
        f.runs()[1]["argv"],
        json!(["config", "server", "https://vault.example.test", "--nointeraction"])
    );
    assert_eq!(f.runs()[2]["argv"], json!(["login", "--raw"]), "login is interactive: no --nointeraction");
}

#[tokio::test]
async fn status_and_disconnect() {
    let f = Fake::new();
    f.control(&json!({}));
    let config = provider(&json!({}));
    let dir = f.bitwarden_dir();
    let record = pinned(&config, &dir, SESSION);
    let shown = test_seams::status(&config, &dir, Some(&record)).await.unwrap();
    assert_eq!(
        shown,
        json!({"source": "bitwarden", "protection": "memory", "session": "stored", "vault": "unlocked"})
    );
    assert!(!shown.to_string().contains("fixture-owner@example.test"), "no email in status");
    let shown = test_seams::status(&config, &dir, None).await.unwrap();
    assert_eq!(shown["session"], "none");
    assert_eq!(shown["vault"], "locked");
    let (out, stored) = test_seams::disconnect(&config, &dir, Some(&record)).await;
    assert_eq!(out.unwrap(), json!({"session": "removed", "locked": true}));
    assert_eq!(stored, None);
    assert_eq!(f.commands().last().map(String::as_str), Some("lock"));
    // Not the bitwarden source: refused with the reason.
    let err = test_seams::status(&json!({"command": ["x"]}), &dir, None).await.unwrap_err();
    assert!(err.contains("bitwarden"), "{err}");
    // Back on the command provider, disconnect still removes a session left behind; only the lock is skipped.
    let runs = f.commands().len();
    let (out, stored) = test_seams::disconnect(&json!({"command": ["x"]}), &dir, Some(&record)).await;
    let out = out.unwrap();
    assert_eq!((&out["session"], &out["locked"]), (&json!("removed"), &json!(false)), "{out}");
    assert_eq!(stored, None);
    assert_eq!(f.commands().len(), runs, "no bw run without a configured CLI");
}

/// A copy of the fake under another path, as another `bw` program.
fn copy_of_fake(dir: &Path) -> PathBuf {
    let copy = dir.join("other").join(BW);
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::copy(fake(), &copy).unwrap();
    copy
}

#[tokio::test]
async fn a_session_goes_only_to_the_bw_it_was_made_with() {
    let f = Fake::new();
    f.control(&json!({}));
    let dir = f.bitwarden_dir();
    let copy = copy_of_fake(f.dir.path());
    let fake = provider(&json!({}));
    let other = provider_for(&copy, &json!({}));
    let ask = |provider: Value, record: Option<String>| {
        let dir = dir.clone();
        async move {
            bitwarden_ask_for_test(
                &provider,
                &dir,
                record.as_deref(),
                vec![PAGE.into()],
                None,
                None,
                vec!["password"],
                20_000,
            )
            .await
            .0
        }
    };
    let for_fake = pinned(&fake, &dir, SESSION);
    assert_eq!(ask(fake.clone(), Some(for_fake.clone())).await, json!({"status": "ok"}));
    let ran = f.commands().len();
    // config.json now names another program (the same bytes, elsewhere): it never gets the key.
    assert_eq!(ask(other.clone(), Some(for_fake.clone())).await, json!({"status": "locked"}));
    // An earlier phantab's store, the bare key with no pin: locked until connect runs again.
    assert_eq!(ask(fake.clone(), Some(SESSION.to_owned())).await, json!({"status": "locked"}));
    // The program pinned, then replaced in place.
    let for_copy = pinned(&other, &dir, SESSION);
    assert_eq!(ask(other.clone(), Some(for_copy.clone())).await, json!({"status": "ok"}));
    let ran_copy = f.commands().len();
    let mut bytes = std::fs::read(&copy).unwrap();
    bytes.push(0);
    std::fs::write(&copy, &bytes).unwrap();
    assert_eq!(ask(other.clone(), Some(for_copy)).await, json!({"status": "locked"}));
    assert_eq!(f.commands().len(), ran_copy, "no bw started for a key it was not pinned to");
    // Back to the fake's own bytes, so it runs again below as itself.
    bytes.pop();
    std::fs::write(&copy, &bytes).unwrap();
    assert!(f.runs()[ran..].iter().all(|r| r["session"] == "match"), "only pinned runs got the key");
    // status names it, runs bw without the key, and says nothing of the key; disconnect locks without it.
    let shown = test_seams::status(&fake, &dir, Some(SESSION)).await.unwrap();
    assert_eq!(shown["session"], "stale", "{shown}");
    assert_eq!(f.runs().last().unwrap()["session"], "absent", "status ran without the key");
    let (out, stored) = test_seams::disconnect(&fake, &dir, Some(&pinned(&other, &dir, SESSION))).await;
    assert_eq!(out.unwrap()["session"], "removed");
    assert_eq!(stored, None);
    let lock = f.runs().last().unwrap().clone();
    assert_eq!((&lock["argv"][0], &lock["session"]), (&json!("lock"), &json!("absent")));
    // Connecting again, with config.json naming the other program, pins the key to it.
    let g = Fake::new();
    g.control(&json!({"status": "locked"}));
    let gdir = g.bitwarden_dir();
    let (out, stored) = test_seams::connect(&other, &gdir, Some(&for_fake), Some(MASTER)).await;
    assert_eq!(out, Ok(()));
    let stored = stored.unwrap();
    assert_eq!(stored, pinned(&other, &gdir, SESSION));
    g.control(&json!({}));
    let asked = bitwarden_ask_for_test(
        &other,
        &gdir,
        Some(&stored),
        vec![PAGE.into()],
        None,
        None,
        vec!["password"],
        20_000,
    )
    .await;
    assert_eq!(asked.0, json!({"status": "ok"}));
}

#[tokio::test]
async fn connect_gives_the_password_only_to_the_bw_it_pinned() {
    // The owner types the master password after the pin was taken: a `bw` changed meanwhile is not given
    // it. On Windows `connect` holds the pinned files shut, so the change itself fails.
    let f = Fake::new();
    f.control(&json!({"status": "locked"}));
    let copy = copy_of_fake(f.dir.path());
    let mut changed = None;
    let mut typing = || {
        let mut bytes = std::fs::read(&copy).unwrap();
        bytes.push(0);
        changed = Some(std::fs::write(&copy, &bytes).is_ok());
    };
    let (out, stored) = test_seams::connect_while_typing(
        &provider_for(&copy, &json!({})),
        &f.bitwarden_dir(),
        MASTER,
        &mut typing,
    )
    .await;
    if cfg!(windows) {
        assert_eq!(changed, Some(false), "the pinned bw could be rewritten while connect held it");
        assert_eq!(out, Ok(()));
        assert_eq!(key_in(stored.as_deref()), Some(SESSION));
        assert!(std::fs::write(&copy, b"x").is_ok(), "connect let go when it finished");
    } else {
        assert_eq!(changed, Some(true));
        let err = out.unwrap_err();
        assert!(err.contains("changed while connecting"), "{err}");
        assert_eq!(stored, None);
        assert_eq!(f.commands(), ["status"], "no unlock ran");
    }
}

#[tokio::test]
async fn connect_refuses_a_bw_it_cannot_pin() {
    let f = Fake::new();
    f.control(&json!({"status": "locked"}));
    let gone = f.dir.path().join(if cfg!(windows) { "gone.exe" } else { "gone" });
    let (out, stored) =
        test_seams::connect(&provider_for(&gone, &json!({})), &f.bitwarden_dir(), None, Some(MASTER)).await;
    assert!(out.unwrap_err().contains("to pin it"));
    assert_eq!(stored, None);
    assert_eq!(f.commands(), Vec::<String>::new(), "no bw ran");
}

#[tokio::test]
async fn connect_shows_the_bw_it_pins_and_goes_on_only_when_confirmed() {
    let f = Fake::new();
    f.control(&json!({"status": "locked"}));
    let config = provider(&json!({}));
    // Not confirmed: nothing stored, and no bw ran.
    let (out, stored, shown) =
        test_seams::connect_answering(&config, &f.bitwarden_dir(), None, Some(MASTER), false).await;
    let err = out.unwrap_err();
    assert!(err.contains("did not confirm"), "{err}");
    assert_eq!(stored, None);
    assert_eq!(f.commands(), Vec::<String>::new(), "no bw ran before the owner confirmed");
    // What was shown: the program as it runs, with its SHA-256.
    let shown = shown.unwrap();
    let sha256 = sha256_hex(&std::fs::read(fake()).unwrap());
    assert!(shown.contains(&sha256), "{shown}");
    let real = std::fs::canonicalize(fake()).unwrap();
    let real = real.to_string_lossy();
    assert!(shown.contains(real.strip_prefix(r"\\?\").unwrap_or(&real)), "{shown}");
    // Confirmed: it connects.
    let (out, stored, _) =
        test_seams::connect_answering(&config, &f.bitwarden_dir(), None, Some(MASTER), true).await;
    assert_eq!(out, Ok(()));
    assert_eq!(key_in(stored.as_deref()), Some(SESSION));
}

#[test]
fn connect_refuses_to_run_without_a_terminal() {
    // The real binary, over a scratch runtime (never the owner's), with stdin not a terminal: it stops
    // before it pins, asks or runs anything.
    let f = Fake::new();
    f.control(&json!({"status": "locked"}));
    std::fs::write(
        f.dir.path().join("config.json"),
        json!({"signInProvider": provider(&json!({}))}).to_string(),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_phantab"))
        .args(["bitwarden", "connect"])
        .env("PHANTAB_RUNTIME", f.dir.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("terminal window"), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert_eq!(f.commands(), Vec::<String>::new(), "no bw ran");
}

/// A link on the configured path (a junction on Windows, as Scoop's `current` is; a symbolic link on
/// unix) is repointed to an identical copy while the owner types, and the file it led to is rewritten in
/// place: the master password goes to the files the check after the prompt opened and hashed, started by
/// their resolved path, never to the path resolved before the prompt.
#[tokio::test]
async fn connect_gives_the_password_to_the_files_checked_after_the_prompt() {
    let f = Fake::new();
    f.control(&json!({"status": "locked"}));
    let copy = copy_of_fake(f.dir.path());
    let real = copy.parent().unwrap().to_path_buf();
    let planted = f.dir.path().join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::copy(fake(), planted.join(BW)).unwrap();
    let link = f.dir.path().join("current");
    let point = |to: &Path| {
        #[cfg(windows)]
        {
            let made = std::process::Command::new("cmd")
                .arg("/c")
                .arg("mklink")
                .arg("/J")
                .arg(&link)
                .arg(to)
                .output()
                .unwrap();
            assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(to, &link).unwrap();
    };
    let unlink = || {
        #[cfg(windows)]
        std::fs::remove_dir(&link).unwrap();
        #[cfg(unix)]
        std::fs::remove_file(&link).unwrap();
    };
    point(&real);
    let config = provider_for(&link.join(BW), &json!({}));
    let mut rewritten = None;
    let mut typing = || {
        unlink();
        point(&planted);
        // The file the link led to before the prompt, rewritten with its inode kept.
        let append =
            std::fs::OpenOptions::new().append(true).open(&copy).and_then(|mut file| file.write_all(&[0]));
        rewritten = Some(append.is_ok());
    };
    let (out, stored) =
        test_seams::connect_while_typing(&config, &f.bitwarden_dir(), MASTER, &mut typing).await;
    assert_eq!(rewritten, Some(cfg!(unix)), "on Windows connect holds the files it pinned shut");
    assert_eq!(out, Ok(()));
    assert_eq!(key_in(stored.as_deref()), Some(SESSION));
    // `status` ran from the file held before the prompt; `unlock`, and the new key's own check, from the
    // planted copy that the check after the prompt found (the same bytes, so the pin holds for them).
    let runs = f.runs();
    let unlock = runs.iter().position(|r| r["argv"][0] == "unlock").expect("unlock ran");
    assert!(unlock > 0 && runs.len() > unlock + 1, "{runs:?}");
    for (i, run) in runs.iter().enumerate() {
        let exe = run["exe"].as_str().unwrap();
        let from = if i < unlock { "other" } else { "planted" };
        assert!(exe.contains(from) && !exe.contains("current"), "{i} {}: {exe}", run["argv"]);
    }
    unlink();
}

#[test]
fn the_fake_never_names_a_real_cli() {
    // The tests run only the fake: this build's own test binary, and its copy named `bw` in this build's
    // test scratch folder.
    assert!(Path::new(FAKE).is_absolute());
    assert!(Path::new(FAKE).file_stem().is_some_and(|s| s == "phantab-fake-bw"));
    assert!(fake().starts_with(env!("CARGO_TARGET_TMPDIR")), "{}", fake().display());
    assert_eq!(std::fs::read(fake()).unwrap(), std::fs::read(FAKE).unwrap());
}

#[test]
#[cfg_attr(
    windows,
    ignore = "Windows has no core limit to lower; crash dumps there are WER's (THREAT-MODEL R11)"
)]
fn the_bitwarden_verbs_turn_core_dumps_off_first() {
    // macOS starts processes with a soft core limit of 0 already, so on unix phantab starts under the
    // shell with the soft limit raised to the hard one: the 0 the fake sees is then phantab's own doing.
    const RAISE: &str = r#"ulimit -S -c "$(ulimit -H -c)""#;
    // The real binary, over a scratch runtime (never the owner's): `status` runs `bw status`, and the fake
    // logs the core-file limit it inherited. `connect` takes the same path before it reads the password.
    let f = Fake::new();
    f.control(&json!({}));
    std::fs::write(
        f.dir.path().join("config.json"),
        json!({"signInProvider": provider(&json!({}))}).to_string(),
    )
    .unwrap();
    let mut cmd = if cfg!(unix) {
        let raised =
            std::process::Command::new("/bin/sh").args(["-c", &format!("{RAISE}; ulimit -c")]).output();
        let raised = String::from_utf8(raised.unwrap().stdout).unwrap();
        assert_ne!(raised.trim(), "0", "this machine's hard core limit is 0: the test would prove nothing");
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", &format!(r#"{RAISE}; exec "$0" bitwarden status"#), env!("CARGO_BIN_EXE_phantab")]);
        c
    } else {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_phantab"));
        c.args(["bitwarden", "status"]);
        c
    };
    cmd.env("PHANTAB_RUNTIME", f.dir.path());
    #[cfg(target_os = "macos")]
    let _keychain = scratch_keychain(&mut cmd);
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let shown: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(shown["session"], "none", "{shown}");
    let runs = f.runs();
    assert_eq!(f.commands(), vec!["status"]);
    assert_eq!(runs[0]["core"], "0", "bw inherited a core limit: {}", runs[0]);
}

#[test]
fn the_binary_never_opens_the_owners_session_store() {
    // `bitwarden status` over a scratch runtime with no test keychain named. A test build never opens the
    // login keychain, so on macOS the session is unreadable, never read from the owner's keychain (and
    // elsewhere but Windows nothing can store one).
    let f = Fake::new();
    f.control(&json!({}));
    let out = status_command(&f).output().unwrap();
    assert_eq!(session_shown(&out), if cfg!(windows) { "none" } else { "unreadable" });
    #[cfg(windows)]
    {
        // On Windows the session is a DPAPI file in the runtime folder, and a test build uses a file name
        // (and an entropy) of its own: a blob under the owner's name is never opened, even in the folder
        // the test build reads, while one under the test name is.
        let bitwarden = f.dir.path().join("bitwarden");
        std::fs::create_dir_all(&bitwarden).unwrap();
        std::fs::write(bitwarden.join("session.dpapi"), b"the owner's blob").unwrap();
        assert_eq!(session_shown(&status_command(&f).output().unwrap()), "none");
        std::fs::write(bitwarden.join("session.test.dpapi"), b"a damaged test blob").unwrap();
        assert_eq!(session_shown(&status_command(&f).output().unwrap()), "unreadable");
        assert_eq!(std::fs::read(bitwarden.join("session.dpapi")).unwrap(), b"the owner's blob");
    }
    #[cfg(target_os = "macos")]
    {
        // With a scratch keychain named, the same call reads it, and it holds nothing.
        let mut cmd = status_command(&f);
        let _keychain = scratch_keychain(&mut cmd);
        assert_eq!(session_shown(&cmd.output().unwrap()), "none");
        // The owner's keychains named are refused before anything opens them.
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        for owners in [
            home.join("Library/Keychains/login.keychain-db"),
            home.join("Library/Keychains/other.keychain-db"),
        ] {
            let out = status_command(&f)
                .env("PHANTAB_TEST_KEYCHAIN", &owners)
                .env("PHANTAB_TEST_KEYCHAIN_PASSWORD", "x")
                .output()
                .unwrap();
            assert_eq!(session_shown(&out), "unreadable", "{}", owners.display());
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(err.contains("a test never uses it"), "{err}");
        }
    }
}

// --- browser_sign_up's save (THREAT-MODEL SR-78 to SR-83) ---

const ORIGIN: &str = "https://login.site.test";
const NEW_USER: &str = "new-owner@example.test";
const ITEM_NAME: &str = "login.site.test (sign-up 2026-11-10)";

impl Fake {
    async fn create_with(
        &self,
        extra: &Value,
        username: &str,
        regenerate: bool,
    ) -> (Value, Option<(&'static str, String)>) {
        bitwarden_create_for_test(
            &provider(extra),
            &self.bitwarden_dir(),
            Some(&pinned(&provider(extra), &self.bitwarden_dir(), SESSION)),
            ORIGIN,
            username,
            ITEM_NAME,
            regenerate,
            20_000,
        )
        .await
    }

    async fn create(&self, username: &str, regenerate: bool) -> (Value, Option<(&'static str, String)>) {
        self.create_with(&json!({}), username, regenerate).await
    }

    /// The fake's items now: what a create or an edit wrote back.
    fn items(&self) -> Vec<Value> {
        let control: Value =
            serde_json::from_str(&std::fs::read_to_string(self.data().join("fake-bw.json")).unwrap())
                .unwrap();
        control["items"].as_array().cloned().unwrap_or_default()
    }
}

/// Neither `password` nor the master password in the fake's log, and no write's login on a command line.
fn assert_not_logged(f: &Fake, password: &str) {
    let log = f.log_text();
    assert!(!password.is_empty() && !log.contains(password), "the new password reached the log");
    assert!(!log.contains(MASTER));
    for run in f.runs() {
        let argv = run["argv"].as_array().unwrap();
        assert!(argv.len() <= 6, "nothing but the command, the id and the flags: {argv:?}");
    }
}

/// The new or replaced password, compared inside the test and never printed.
fn same(a: &str, b: &str) -> bool {
    a == b
}

#[tokio::test]
async fn a_new_login_is_saved_read_back_and_synced() {
    let f = Fake::new();
    f.control(&json!({}));
    let (label, made) = f.create(NEW_USER, false).await;
    assert_eq!(label, json!({"status": "ok"}));
    let (which, password) = made.unwrap();
    assert_eq!(which, "new");
    assert_eq!(password.len(), 20);
    assert_eq!(f.commands(), ["status", "list", "create", "get", "sync"]);
    let runs = f.runs();
    assert_eq!(runs[1]["argv"], json!(["list", "items", "--url", ORIGIN, "--raw", "--nointeraction"]));
    assert_eq!(runs[2]["argv"], json!(["create", "item", "--nointeraction"]));
    assert!(runs[2]["stdinBytes"].as_u64().unwrap() > 0, "the login came on stdin");
    assert_eq!(runs[3]["argv"], json!(["get", "item", "created-2", "--nointeraction"]));
    for run in &runs {
        assert_eq!(run["session"], "match");
    }
    let items = f.items();
    let saved = items.iter().find(|i| i["id"] == "created-2").unwrap();
    assert_eq!(saved["name"], ITEM_NAME);
    assert_eq!(saved["type"], 1);
    assert_eq!(saved["login"]["username"], NEW_USER);
    assert_eq!(saved["login"]["uris"], json!([{"match": null, "uri": ORIGIN}]));
    assert!(same(saved["login"]["password"].as_str().unwrap(), &password), "the vault holds what is filled");
    assert_eq!(saved["reprompt"], 0);
    assert_not_logged(&f, &password);
}

#[tokio::test]
async fn the_saved_login_for_this_origin_and_username_answers_existing() {
    let f = Fake::new();
    f.control(&json!({}));
    let (label, made) = f.create(USERNAME, false).await;
    assert_eq!(label, json!({"status": "ok"}));
    let (which, password) = made.unwrap();
    assert_eq!(which, "existing");
    assert!(same(&password, PASSWORD), "the saved password");
    assert_eq!(f.commands(), ["status", "list"], "no write");
    // A login for the parent domain is not this origin's: a new one is made.
    let g = Fake::new();
    g.control(&json!({"items": [login(ID1, "Parent", &json!([{"uri": "https://site.test"}]))]}));
    assert_eq!(g.create(USERNAME, false).await.1.unwrap().0, "new");
    // Nor is one for another username.
    let h = Fake::new();
    h.control(&json!({}));
    assert_eq!(h.create(NEW_USER, false).await.1.unwrap().0, "new");
}

#[tokio::test]
async fn regenerate_edits_the_saved_login() {
    let f = Fake::new();
    f.control(&json!({}));
    let (label, made) = f.create(USERNAME, true).await;
    assert_eq!(label, json!({"status": "ok"}));
    let (which, password) = made.unwrap();
    assert_eq!(which, "replaced");
    assert!(!same(&password, PASSWORD));
    assert_eq!(f.commands(), ["status", "list", "edit", "get", "sync"]);
    assert_eq!(f.runs()[2]["argv"], json!(["edit", "item", ID1, "--nointeraction"]));
    let items = f.items();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "Site", "the rest of the login is kept");
    assert!(same(items[0]["login"]["password"].as_str().unwrap(), &password));
    assert_not_logged(&f, &password);
}

#[tokio::test]
async fn the_vaults_refusals_write_nothing() {
    let two = json!({"items": [
        one_login(),
        login(ID2, "Again", &json!([{"uri": "https://login.site.test/other"}])),
    ]});
    let mut reprompt = one_login();
    reprompt["reprompt"] = json!(1);
    let cases = [
        (json!({}), two, json!({"status": "ambiguous", "count": 2})),
        (json!({}), json!({"items": [reprompt]}), json!({"status": "refused"})),
        (json!({"askFirst": ["site.test"]}), json!({}), json!({"status": "ask-first"})),
        (json!({}), json!({"status": "locked"}), json!({"status": "locked"})),
        (json!({}), json!({"fail": ["list"]}), json!({"status": "provider-failed"})),
    ];
    for (extra, control, want) in cases {
        let f = Fake::new();
        f.control(&control);
        let (label, made) = f.create_with(&extra, USERNAME, true).await;
        assert_eq!(label, want, "{control}");
        assert!(made.is_none());
        let commands = f.commands();
        assert!(!commands.iter().any(|c| c == "create" || c == "edit"), "{commands:?}");
    }
}

#[tokio::test]
async fn ask_first_starts_no_bw_at_all() {
    let f = Fake::new();
    f.control(&json!({}));
    let (label, _) = f.create_with(&json!({"askFirst": ["site.test"]}), NEW_USER, false).await;
    assert_eq!(label, json!({"status": "ask-first"}));
    assert!(f.commands().is_empty(), "{:?}", f.commands());
}

#[tokio::test]
async fn a_failed_write_or_a_wrong_read_back_answers_nothing() {
    let f = Fake::new();
    f.control(&json!({"fail": ["create"]}));
    let (label, made) = f.create(NEW_USER, false).await;
    assert_eq!(label, json!({"status": "provider-failed"}));
    assert!(made.is_none());
    assert_eq!(f.commands(), ["status", "list", "create"]);
    let g = Fake::new();
    g.control(&json!({"readBack": "wrong"}));
    let (label, made) = g.create(NEW_USER, false).await;
    assert_eq!(label, json!({"status": "provider-failed"}));
    assert!(made.is_none());
    assert_eq!(g.commands(), ["status", "list", "create", "get"], "no sync after a read-back that differs");
    let h = Fake::new();
    h.control(&json!({"malformed": ["create"]}));
    let (label, made) = h.create(NEW_USER, false).await;
    assert_eq!(label, json!({"status": "provider-failed"}));
    assert!(made.is_none());
    // A sync that fails after the write still answers: the login is saved on the server.
    let k = Fake::new();
    k.control(&json!({"fail": ["sync"]}));
    assert_eq!(k.create(NEW_USER, false).await.1.unwrap().0, "new");
}

#[tokio::test]
async fn a_non_https_origin_is_refused_before_bw() {
    let f = Fake::new();
    f.control(&json!({}));
    let out = bitwarden_create_for_test(
        &provider(&json!({})),
        &f.bitwarden_dir(),
        Some(&pinned(&provider(&json!({})), &f.bitwarden_dir(), SESSION)),
        "http://login.site.test",
        NEW_USER,
        ITEM_NAME,
        false,
        20_000,
    )
    .await;
    assert_eq!(out.0, json!({"status": "refused"}));
    assert!(out.1.is_none());
    assert!(f.commands().is_empty());
}
