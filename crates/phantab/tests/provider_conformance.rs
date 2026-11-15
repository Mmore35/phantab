//! The provider conformance kit (docs/VAULTS.md § Conformance kit; THREAT-MODEL SR-84 to SR-87), run
//! against the fixture provider, a stand-in password manager over a vault file of made-up logins. A
//! third-party command provider passes it by being driven the same way. Never a real vault.
//!
//! What a provider must do: answer sealed, bound to the digest of the request it was sent; name only the
//! fields the protocol names; and be cut off, never waited on, when it is slow, crashes, floods its
//! output or answers garbage. And the leak test: a canary password goes through every outcome and is
//! never in the fixture's log, a temp file phantab leaves, the command line, a label or the status output.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use phantab::signin::{ProvidersCall, providers_ask_for_test, providers_create_for_test};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const FIXTURE: &str = env!("CARGO_BIN_EXE_phantab-fixture-provider");
/// The canary: a made-up password the leak test looks for everywhere it must not be.
const CANARY: &str = "CANARY-pw-5e1d0c7b";
const CANARY_CODE: &str = "731905";

struct Kit {
    dir: tempfile::TempDir,
}

impl Kit {
    fn new() -> Self {
        Kit { dir: tempfile::Builder::new().prefix("phantab-conformance-").tempdir().unwrap() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The vault file: two logins on one site, one on another, and `behave`.
    fn vault(&self, behave: &str) {
        let vault = json!({
            "logins": [
                {"id": "a1", "origin": "https://site.test", "username": "ann@example.test", "password": CANARY,
                 "totp": CANARY_CODE},
                {"id": "b2", "origin": "https://site.test", "username": "bob@example.test", "password": CANARY},
                {"id": "c3", "origin": "https://other.test", "username": "cy@example.test", "password": CANARY},
            ],
            "log": self.path("asked.jsonl"),
            "behave": behave,
        });
        std::fs::write(self.path("vault.json"), vault.to_string()).unwrap();
    }

    fn vault_file(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.path("vault.json")).unwrap()).unwrap()
    }

    /// The fixture as a pinned v2 provider (`caps` given) or a v1 one (`caps` null), named `name`.
    fn entry(&self, name: &str, caps: &Value) -> Value {
        let vault = self.path("vault.json").to_string_lossy().into_owned();
        let mut e = json!({"name": name, "command": [FIXTURE, vault]});
        if !caps.is_null() {
            e["caps"] = caps.clone();
            e["pin"] = json!({FIXTURE: sha256_of(Path::new(FIXTURE))});
        }
        e
    }

    /// The fixture as the one legacy `signInProvider`: protocol v1, as configs before the list are.
    fn v1(&self) -> Value {
        json!({"command": self.entry("x", &Value::Null)["command"]})
    }

    fn v2(&self) -> Value {
        json!({"signInProviders": [self.entry("default", &json!(["lookup", "totp", "create"]))],
               "signInSaveTo": null, "signInProvider": null})
    }

    async fn ask(
        &self,
        config: &Value,
        account: Option<&str>,
        key: Option<&str>,
        want: Vec<&'static str>,
        ms: u64,
    ) -> (Value, Option<(String, Vec<(String, String)>)>) {
        let call = ProvidersCall { config, bitwarden_dir: &self.path("bw"), vault: None, session: None, ms };
        providers_ask_for_test(
            &call,
            vec!["https://site.test/login".into()],
            account.map(str::to_owned),
            key.map(str::to_owned),
            want,
        )
        .await
    }

    async fn create(
        &self,
        config: &Value,
        username: &str,
        regenerate: bool,
    ) -> (Value, Option<(&'static str, String)>) {
        let call =
            ProvidersCall { config, bitwarden_dir: &self.path("bw"), vault: None, session: None, ms: 10_000 };
        providers_create_for_test(&call, "https://site.test", username, "site.test", regenerate).await
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path("asked.jsonl")).unwrap_or_default()
    }
}

fn sha256_of(path: &Path) -> String {
    phantab::util::hex(&Sha256::digest(std::fs::read(path).unwrap()))
}

fn status(label: &Value) -> &str {
    label["status"].as_str().unwrap_or("")
}

#[tokio::test]
async fn a_sealed_answer_bound_to_the_request_is_taken_in_both_protocols() {
    let kit = Kit::new();
    kit.vault("");
    for config in [kit.v2(), kit.v1()] {
        let (label, got) = kit
            .ask(&config, Some("ann@example.test"), None, vec!["username", "password", "code"], 10_000)
            .await;
        assert_eq!(status(&label), "ok", "{label}");
        let (key, values) = got.unwrap();
        assert_eq!(key, "a1", "the one source's keys go out bare");
        assert!(values.contains(&("password".into(), CANARY.into())));
        assert!(values.contains(&("code".into(), CANARY_CODE.into())));
    }
    // Two logins on the site: ambiguous with the count; a held key picks one; none elsewhere.
    let (label, _) = kit.ask(&kit.v2(), None, None, vec!["username", "password"], 10_000).await;
    assert_eq!((status(&label), &label["count"]), ("ambiguous", &json!(2)), "{label}");
    let (label, got) = kit.ask(&kit.v2(), None, Some("b2"), vec!["password"], 10_000).await;
    assert_eq!(status(&label), "ok", "{label}");
    assert_eq!(got.unwrap().0, "b2");
    let (label, _) = kit.ask(&kit.v2(), Some("nobody@example.test"), None, vec!["password"], 10_000).await;
    assert_eq!(status(&label), "none", "{label}");
    // A code the login has no seed for is a wall, never a guess.
    let (label, _) = kit.ask(&kit.v2(), None, Some("b2"), vec!["password", "code"], 10_000).await;
    assert_eq!((status(&label), &label["reason"]), ("wall", &json!("code-not-saved")), "{label}");
    // The v2 request names its version and operation; the v1 one is v1's four fields.
    let lines: Vec<Value> = kit.log().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines[0]["fields"], json!(["v", "operation", "urls", "account", "accountKey", "want"]));
    assert_eq!(lines[1]["fields"], json!(["urls", "account", "accountKey", "want"]));
}

#[tokio::test]
async fn a_provider_that_breaks_the_protocol_is_cut_off() {
    let kit = Kit::new();
    // Each misbehaviour, and the answer phantab gives instead of anything the provider said.
    let cases = [
        ("bad-digest", "refused"),
        ("unsealed", "refused"),
        ("extra-field", "provider-failed"),
        ("extra-plain", "provider-failed"),
        ("garbage", "provider-failed"),
        ("huge", "provider-failed"),
        ("crash", "provider-failed"),
        ("locked", "locked"),
    ];
    for (behave, want) in cases {
        kit.vault(behave);
        let (label, got) = kit.ask(&kit.v2(), Some("ann@example.test"), None, vec!["password"], 10_000).await;
        assert_eq!(status(&label), want, "{behave}: {label}");
        assert!(got.is_none(), "{behave}: nothing reaches the page");
    }
    // Slow: the call's deadline answers busy and kills the provider; it is not waited on.
    kit.vault("slow");
    let started = std::time::Instant::now();
    let (label, _) = kit.ask(&kit.v2(), Some("ann@example.test"), None, vec!["password"], 1_500).await;
    assert_eq!(status(&label), "busy", "{label}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10), "slow provider waited on");
    // An unknown field is only an error in v2: a v1 provider was written against a reader that ignored it.
    kit.vault("extra-field");
    let v1 = kit.v1();
    let (label, _) = kit.ask(&v1, Some("ann@example.test"), None, vec!["password"], 10_000).await;
    assert_eq!(status(&label), "ok", "{label}");
}

#[tokio::test]
async fn a_pinned_provider_that_changed_or_went_missing_is_never_started() {
    let kit = Kit::new();
    kit.vault("");
    let mut config = kit.v2();
    config["signInProviders"][0]["pin"] = json!({FIXTURE: "0".repeat(64)});
    let (label, _) = kit.ask(&config, Some("ann@example.test"), None, vec!["password"], 10_000).await;
    assert_eq!(status(&label), "provider-failed", "{label}");
    assert!(kit.log().is_empty(), "a changed provider ran");
    let gone = kit.path("gone.exe").to_string_lossy().into_owned();
    config["signInProviders"][0]["command"] = json!([gone, kit.path("vault.json")]);
    config["signInProviders"][0]["pin"] = json!({&gone: sha256_of(Path::new(FIXTURE))});
    let (label, _) = kit.ask(&config, Some("ann@example.test"), None, vec!["password"], 10_000).await;
    assert_eq!(status(&label), "provider-failed", "{label}");
    // A provider that declares caps without a pin is refused at config, and every call fails closed.
    let mut unpinned = kit.v2();
    unpinned["signInProviders"][0].as_object_mut().unwrap().remove("pin");
    let (label, _) = kit.ask(&unpinned, Some("ann@example.test"), None, vec!["password"], 10_000).await;
    assert_eq!(status(&label), "provider-failed", "{label}");
    assert!(kit.log().is_empty(), "an unpinned v2 provider ran");
}

#[tokio::test]
async fn a_sign_up_saves_reads_back_and_never_overwrites_unasked() {
    let kit = Kit::new();
    kit.vault("");
    let (label, got) = kit.create(&kit.v2(), "new@example.test", false).await;
    assert_eq!(status(&label), "ok", "{label}");
    let (saved, password) = got.unwrap();
    assert_eq!(saved, "new");
    let vault = kit.vault_file();
    let held =
        vault["logins"].as_array().unwrap().iter().find(|l| l["username"] == "new@example.test").unwrap();
    assert!(held["password"] == password.as_str(), "the vault holds what phantab made");
    // The login is there now: kept as it is, unless a regenerate was asked.
    let (_, got) = kit.create(&kit.v2(), "new@example.test", false).await;
    let (saved, again) = got.unwrap();
    assert_eq!(saved, "existing");
    assert!(again == password, "existing answers the saved password");
    let (_, got) = kit.create(&kit.v2(), "new@example.test", true).await;
    let (saved, fresh) = got.unwrap();
    assert_eq!(saved, "replaced");
    assert!(fresh != password, "a regenerate makes a new password");
    // A v1 provider (no caps) is never sent a password: it cannot create.
    let v1 = kit.v1();
    let before = kit.log().lines().count();
    let (label, got) = kit.create(&v1, "other@example.test", false).await;
    assert!(got.is_none(), "{label}");
    assert_eq!(kit.log().lines().count(), before, "a v1 provider was sent a create");
    // A create answer with a field the protocol does not name is refused, and nothing reaches the page.
    kit.vault("extra-field");
    let (label, got) = kit.create(&kit.v2(), "x@example.test", false).await;
    assert!(got.is_none(), "{label}");
}

/// Every file under `dir` written since `since` and under 4 MiB, read as text, skipping the kit's own
/// directories (each holds a vault file of made-up logins, the canary among them).
fn every_file(dir: &Path, since: std::time::SystemTime, out: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            // A directory a new file went into was modified since; the rest of a big temp tree is skipped.
            if !entry.file_name().to_string_lossy().starts_with("phantab-conformance-")
                && meta.modified().is_ok_and(|m| m >= since)
            {
                every_file(&path, since, out);
            }
        } else if meta.len() < 4 << 20
            && meta.modified().is_ok_and(|m| m >= since)
            && let Ok(bytes) = std::fs::read(&path)
        {
            out.push((path, String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
}

#[tokio::test]
async fn the_canary_is_never_written_logged_or_shown() {
    let since = std::time::SystemTime::now() - std::time::Duration::from_secs(2);
    let kit = Kit::new();
    let mut shown = String::new();
    for behave in ["", "bad-digest", "unsealed", "extra-field", "garbage", "crash", "locked"] {
        kit.vault(behave);
        for (account, key, want) in [
            (Some("ann@example.test"), None, vec!["username", "password", "code"]),
            (None, None, vec!["password"]),
            (None, Some("b2"), vec!["password", "code"]),
        ] {
            let (label, _) = kit.ask(&kit.v2(), account, key, want, 10_000).await;
            shown.push_str(&label.to_string());
        }
    }
    kit.vault("");
    let (label, _) = kit.create(&kit.v2(), "new@example.test", false).await;
    shown.push_str(&label.to_string());
    // The status the owner reads, from the real binary.
    let runtime = kit.path("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::write(runtime.join("config.json"), kit.v2().to_string()).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_phantab"))
        .args(["vaults", "status"])
        .env("PHANTAB_RUNTIME", &runtime)
        .output()
        .unwrap();
    assert!(out.status.success(), "vaults status: {}", String::from_utf8_lossy(&out.stderr));
    let listed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(listed["providers"][0]["pin"], "ok", "{listed}");
    shown.push_str(&String::from_utf8_lossy(&out.stdout));
    shown.push_str(&String::from_utf8_lossy(&out.stderr));
    assert!(!shown.contains(CANARY) && !shown.contains(CANARY_CODE), "a value in a label or the status");
    // The fixture's log holds field names only; no file but the vault itself holds the canary.
    assert!(!kit.log().contains(CANARY), "a value in the provider's log");
    for entry in std::fs::read_dir(kit.dir.path()).unwrap().flatten() {
        let path = entry.path();
        if path.ends_with("vault.json") || path.is_dir() {
            continue;
        }
        let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        assert!(!text.contains(CANARY) && !text.contains(CANARY_CODE), "a value in {}", path.display());
    }
    let mut written = Vec::new();
    every_file(&kit.path("runtime"), since, &mut written);
    every_file(&std::env::temp_dir(), since, &mut written);
    for (path, text) in &written {
        assert!(!text.contains(CANARY), "a value in {}", path.display());
    }
    // A provider's argv is its config: the canary is never put on a command line.
    assert!(!kit.v2().to_string().contains(CANARY));
}
