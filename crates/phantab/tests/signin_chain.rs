//! Several sign-in providers at once, end to end through the fixture provider (docs/VAULTS.md § Order of
//! choice; THREAT-MODEL SR-84, SR-86), and the golden check that one provider answers as it always did: a
//! legacy `signInProvider` and the same command as the list's one `default` entry give the same answers
//! and the same account keys. Never a real vault.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use phantab::signin::{ProvidersCall, providers_ask_for_test, providers_create_for_test};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const FIXTURE: &str = env!("CARGO_BIN_EXE_phantab-fixture-provider");
const PASSWORD: &str = "made-up-pw-2c91";

struct World {
    dir: tempfile::TempDir,
}

type Asked = (Value, Option<(String, Vec<(String, String)>)>);

impl World {
    fn new() -> Self {
        World { dir: tempfile::Builder::new().prefix("phantab-signin-chain-").tempdir().unwrap() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// `<name>.json`: the vault `logins` (`(id, origin, username)`), logging to `<name>.jsonl`.
    fn vault(&self, name: &str, logins: &[(&str, &str, &str)], behave: &str) {
        let logins: Vec<Value> = logins
            .iter()
            .map(|(id, origin, user)| json!({"id": id, "origin": origin, "username": user, "password": PASSWORD}))
            .collect();
        let vault = json!({"logins": logins, "log": self.path(&format!("{name}.jsonl")), "behave": behave});
        std::fs::write(self.path(&format!("{name}.json")), vault.to_string()).unwrap();
    }

    fn asked(&self, name: &str) -> usize {
        std::fs::read_to_string(self.path(&format!("{name}.jsonl"))).unwrap_or_default().lines().count()
    }

    fn command(&self, name: &str) -> Value {
        json!([FIXTURE, self.path(&format!("{name}.json"))])
    }

    /// A pinned v2 entry over `<name>.json`.
    fn entry(&self, name: &str, sites: &[&str]) -> Value {
        json!({"name": name, "command": self.command(name), "caps": ["lookup", "totp", "create"],
               "pin": {FIXTURE: sha256_of(Path::new(FIXTURE))}, "sites": sites})
    }

    fn list(entries: &[Value], save_to: Option<&str>) -> Value {
        json!({"signInProviders": entries, "signInSaveTo": save_to, "signInProvider": null})
    }

    async fn ask(&self, config: &Value, vault: Option<&str>, url: &str, key: Option<&str>) -> Asked {
        let call =
            ProvidersCall { config, bitwarden_dir: &self.path("bw"), vault, session: None, ms: 10_000 };
        providers_ask_for_test(
            &call,
            vec![url.into()],
            None,
            key.map(str::to_owned),
            vec!["username", "password"],
        )
        .await
    }

    async fn create(&self, config: &Value, vault: Option<&str>, user: &str) -> Value {
        let call =
            ProvidersCall { config, bitwarden_dir: &self.path("bw"), vault, session: None, ms: 10_000 };
        let (label, got) =
            providers_create_for_test(&call, "https://site.test", user, "site.test", false).await;
        match got {
            Some((saved, _)) => json!({"status": label["status"], "saved": saved}),
            None => label,
        }
    }

    fn holds(&self, name: &str, user: &str) -> bool {
        let vault: Value =
            serde_json::from_str(&std::fs::read_to_string(self.path(&format!("{name}.json"))).unwrap())
                .unwrap();
        vault["logins"].as_array().unwrap().iter().any(|l| l["username"] == user)
    }
}

fn sha256_of(path: &Path) -> String {
    phantab::util::hex(&Sha256::digest(std::fs::read(path).unwrap()))
}

fn key(asked: &Asked) -> Option<&str> {
    asked.1.as_ref().map(|(k, _)| k.as_str())
}

fn status(asked: &Asked) -> &str {
    asked.0["status"].as_str().unwrap_or("")
}

#[tokio::test]
async fn one_provider_answers_as_it_always_did() {
    let w = World::new();
    w.vault(
        "one",
        &[
            ("k1", "https://site.test", "ann"),
            ("k2", "https://site.test", "bob"),
            ("k3", "https://b.test", "cy"),
        ],
        "",
    );
    let legacy = json!({"command": w.command("one")});
    let listed = World::list(&[json!({"name": "default", "command": w.command("one")})], None);
    let cases: [(&str, Option<&str>); 4] = [
        ("https://site.test/login", None),
        ("https://site.test/login", Some("k2")),
        ("https://b.test/", None),
        ("https://none.test/", None),
    ];
    for (url, held) in cases {
        let before = w.ask(&legacy, None, url, held).await;
        let after = w.ask(&listed, None, url, held).await;
        let named = w.ask(&listed, Some("default"), url, held).await;
        assert_eq!(before, after, "{url} {held:?}: the list's one default entry answers as the legacy one");
        assert_eq!(before, named, "{url} {held:?}: naming the default vault changes nothing");
    }
    // The bare keys stay bare, so held accounts and ask-first files from before the list keep working.
    assert_eq!(key(&w.ask(&listed, None, "https://b.test/", None).await), Some("k3"));
    // And the v1 request is byte for byte what it was: four fields, no version, no operation.
    let first: Value =
        serde_json::from_str(std::fs::read_to_string(w.path("one.jsonl")).unwrap().lines().next().unwrap())
            .unwrap();
    assert_eq!(first["fields"], json!(["urls", "account", "accountKey", "want"]));
}

#[tokio::test]
async fn the_chain_asks_in_order_and_routes_keys_back_to_their_issuer() {
    let w = World::new();
    w.vault("work", &[("w1", "https://site.test", "ann")], "");
    w.vault("home", &[("h1", "https://site.test", "ann"), ("h2", "https://other.test", "ann")], "");
    let config = World::list(&[w.entry("work", &[]), w.entry("home", &[])], None);
    // The first provider that has the login answers; its key comes back with its name.
    let got = w.ask(&config, None, "https://site.test/login", None).await;
    assert_eq!((status(&got), key(&got)), ("ok", Some("work:w1")), "{got:?}");
    assert_eq!(w.asked("home"), 0, "a second vault asked after the first answered");
    // Not in the first: the next is asked.
    let got = w.ask(&config, None, "https://other.test/", None).await;
    assert_eq!(key(&got), Some("home:h2"));
    // A held key goes to its issuer only, with its own key.
    let work_before = w.asked("work");
    let got = w.ask(&config, None, "https://site.test/login", Some("home:h1")).await;
    assert_eq!(key(&got), Some("home:h1"));
    assert_eq!(w.asked("work"), work_before, "a held key was sent to another vault");
    // A bare key has no bare source to go to here: none, and nobody is asked.
    let got = w.ask(&config, None, "https://site.test/login", Some("h1")).await;
    assert_eq!(status(&got), "none", "{got:?}");
    // The agent's vault, and an unknown one.
    assert_eq!(key(&w.ask(&config, Some("home"), "https://site.test/login", None).await), Some("home:h1"));
    assert_eq!(
        status(&w.ask(&config, Some("nope"), "https://site.test/login", None).await),
        "provider-failed"
    );
    // An owner's site pin narrows the chain to the pinned vault.
    let pinned = World::list(&[w.entry("work", &[]), w.entry("home", &["https://site.test"])], None);
    assert_eq!(key(&w.ask(&pinned, None, "https://site.test/login", None).await), Some("home:h1"));
}

#[tokio::test]
async fn a_failing_vault_falls_through_and_an_owner_s_no_stops_the_chain() {
    let w = World::new();
    w.vault("home", &[("h1", "https://site.test", "ann")], "");
    let config = World::list(&[w.entry("work", &[]), w.entry("home", &[])], None);
    for behave in ["locked", "crash", "garbage", "extra-plain"] {
        w.vault("work", &[("w1", "https://site.test", "ann")], behave);
        let got = w.ask(&config, None, "https://site.test/login", None).await;
        assert_eq!(key(&got), Some("home:h1"), "{behave}: {got:?}");
    }
    // Two logins in the first vault: ambiguous stops the chain; the second is never asked.
    w.vault("work", &[("w1", "https://site.test", "ann"), ("w2", "https://site.test", "bob")], "");
    let home_before = w.asked("home");
    let got = w.ask(&config, None, "https://site.test/login", None).await;
    assert_eq!(status(&got), "ambiguous", "{got:?}");
    assert_eq!(w.asked("home"), home_before);
    // A sealed answer that fails its digest is refused, and refused is never overruled by the next vault.
    w.vault("work", &[("w1", "https://site.test", "ann")], "bad-digest");
    let got = w.ask(&config, None, "https://site.test/login", None).await;
    assert_eq!(status(&got), "refused", "{got:?}");
    assert_eq!(w.asked("home"), home_before);
    // Every vault fell through: the most telling answer.
    w.vault("home", &[], "locked");
    w.vault("work", &[], "");
    assert_eq!(status(&w.ask(&config, None, "https://site.test/login", None).await), "locked");
}

#[tokio::test]
async fn a_sign_up_password_goes_to_exactly_one_vault() {
    let w = World::new();
    w.vault("work", &[], "");
    w.vault("home", &[], "");
    let config = World::list(&[w.entry("work", &[]), w.entry("home", &[])], Some("home"));
    assert_eq!(w.create(&config, None, "u1").await["saved"], "new");
    assert!(w.holds("home", "u1") && !w.holds("work", "u1"), "saveTo picks the vault");
    assert_eq!(w.create(&config, Some("work"), "u2").await["saved"], "new");
    assert!(w.holds("work", "u2") && !w.holds("home", "u2"), "the agent's vault picks it");
    let pinned = World::list(&[w.entry("work", &["https://site.test"]), w.entry("home", &[])], Some("home"));
    assert_eq!(w.create(&pinned, None, "u3").await["saved"], "new");
    assert!(w.holds("work", "u3") && !w.holds("home", "u3"), "a site pin beats saveTo");
    // A vault that fails the save is the answer: the password is never tried in a second vault.
    w.vault("home", &[], "crash");
    let failed = w.create(&config, None, "u4").await;
    assert_ne!(failed["status"], "ok", "{failed}");
    assert!(!w.holds("work", "u4"));
}
