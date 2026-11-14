//! The provider protocol against the fake provider binary, without Chrome: the seal round trip, the
//! answer labels, the stdout cap, the environment allow-list and the tree kill on a timeout (SR-43, SR-44).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use phantab::signin::ask_for_test;
use phantab_testkit::sign_in::{CODE, PASSWORD, USERNAME};
use serde_json::{Value, json};

const FAKE: &str = env!("CARGO_BIN_EXE_phantab-fake-provider");

struct Fake {
    dir: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        Fake { dir: tempfile::Builder::new().prefix("phantab-signin-provider-").tempdir().unwrap() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The control file: the log, the fixture values, then `fields`.
    fn control(&self, fields: &Value) {
        let mut c = json!({
            "log": self.path("asked.jsonl"),
            "values": {"username": USERNAME, "password": PASSWORD, "code": CODE},
        });
        for (k, v) in fields.as_object().unwrap() {
            c[k] = v.clone();
        }
        std::fs::write(self.path("provider.json"), c.to_string()).unwrap();
    }

    fn command(&self) -> Value {
        json!([FAKE, self.path("provider.json")])
    }

    fn requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.path("asked.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    async fn ask(
        &self,
        want: Vec<&'static str>,
        ms: u64,
    ) -> (Value, Option<(String, Vec<(String, String)>)>) {
        ask_for_test(&self.command(), vec!["https://site.test/login".into()], None, want, ms).await
    }
}

#[tokio::test]
async fn a_sealed_answer_opens_to_the_wanted_values_only() {
    let f = Fake::new();
    f.control(&json!({}));
    let (label, opened) = f.ask(vec!["username", "password"], 20_000).await;
    assert_eq!(label, json!({"status": "ok"}));
    let (key, values) = opened.unwrap();
    assert_eq!(key, "account-one");
    assert_eq!(
        values,
        [("username".to_owned(), USERNAME.to_owned()), ("password".to_owned(), PASSWORD.to_owned())],
        "the code was not asked for, so it is not kept"
    );
    // The provider saw `JSON.stringify(request)` on stdin.
    let asked = f.requests();
    assert_eq!(
        asked,
        [
            json!({"urls": ["https://site.test/login"], "account": null, "accountKey": null, "want": ["username", "password"]})
        ]
    );

    f.control(&json!({"accountKey": "account-two"}));
    let (_, opened) = f.ask(vec!["code"], 20_000).await;
    let (key, values) = opened.unwrap();
    assert_eq!((key.as_str(), values), ("account-two", vec![("code".to_owned(), CODE.to_owned())]));
}

#[tokio::test]
async fn provider_answers_reach_the_agent_as_literal_labels() {
    let f = Fake::new();
    let cases = [
        (json!({"status": "none"}), json!({"status": "none"})),
        (
            json!({"status": "ambiguous", "count": 3, "extra": "dropped"}),
            json!({"status": "ambiguous", "count": 3}),
        ),
        (json!({"status": "ambiguous", "count": 2.5}), json!({"status": "ambiguous"})),
        (json!({"status": "refused", "why": "stack trace"}), json!({"status": "refused"})),
        (json!({"status": "ask-first"}), json!({"status": "ask-first"})),
        (json!({"status": "locked"}), json!({"status": "locked"})),
        (json!({"status": "provider-failed"}), json!({"status": "provider-failed"})),
        (json!({"status": "busy"}), json!({"status": "busy"})),
        (
            json!({"status": "wall", "reason": "code-not-saved"}),
            json!({"status": "wall", "reason": "code-not-saved"}),
        ),
        (
            json!({"status": "wall", "reason": "free text from a provider"}),
            json!({"status": "wall", "reason": "no-clear-submit"}),
        ),
        (json!({"status": "made-up-status"}), json!({"status": "provider-failed"})),
        (json!("not json"), json!({"status": "provider-failed"})),
        (json!({"status": "ok"}), json!({"status": "refused"})),
        (json!({"status": "ok", "sealed": "x"}), json!({"status": "refused"})),
    ];
    for (answer, want) in cases {
        f.control(&json!({"answer": answer}));
        assert_eq!(f.ask(vec!["username", "password"], 20_000).await.0, want, "{answer}");
    }
    f.control(&json!({"badDigest": true}));
    assert_eq!(
        f.ask(vec!["password"], 20_000).await.0,
        json!({"status": "refused"}),
        "a digest that differs"
    );
    f.control(&json!({"values": {"username": USERNAME}}));
    assert_eq!(
        f.ask(vec!["password"], 20_000).await.0,
        json!({"status": "provider-failed"}),
        "a missing value"
    );
    f.control(&json!({"values": {"password": ""}}));
    assert_eq!(
        f.ask(vec!["password"], 20_000).await.0,
        json!({"status": "provider-failed"}),
        "an empty value"
    );
    f.control(&json!({"values": [PASSWORD]}));
    assert_eq!(
        f.ask(vec!["password"], 20_000).await.0,
        json!({"status": "provider-failed"}),
        "values as an array"
    );
    f.control(&json!({"values": PASSWORD}));
    assert_eq!(f.ask(vec!["password"], 20_000).await.0, json!({"status": "refused"}), "values as a string");
    f.control(&json!({"wallIfUrl": "site.test"}));
    assert_eq!(
        f.ask(vec!["password"], 20_000).await.0,
        json!({"status": "wall", "reason": "form-posts-elsewhere"})
    );
    // stderr goes nowhere, and does not spoil the answer.
    f.control(&json!({"noise": format!("PROVIDER-NOISE {PASSWORD}")}));
    assert_eq!(f.ask(vec!["password"], 20_000).await.0, json!({"status": "ok"}));
}

#[tokio::test]
async fn only_the_first_line_counts_and_output_is_capped() {
    let f = Fake::new();
    f.control(&json!({"answer": "{\"status\":\"locked\"}\n{\"status\":\"none\"}"}));
    assert_eq!(f.ask(vec!["password"], 20_000).await.0, json!({"status": "locked"}));
    // A first line over 262144 bytes is a failure, however it ends.
    let long = format!("{{\"status\":\"none\",\"pad\":\"{}\"}}", "x".repeat(262_144));
    f.control(&json!({"answer": long}));
    assert_eq!(f.ask(vec!["password"], 20_000).await.0, json!({"status": "provider-failed"}));
    let fits = format!("{{\"status\":\"none\",\"pad\":\"{}\"}}", "x".repeat(200_000));
    f.control(&json!({"answer": fits}));
    assert_eq!(f.ask(vec!["password"], 20_000).await.0, json!({"status": "none"}));
}

#[tokio::test]
async fn a_command_that_cannot_run_is_provider_failed() {
    for command in [json!(["phantab-no-such-provider-anywhere"]), json!([]), json!(""), json!([5])] {
        let (label, _) = ask_for_test(&command, vec![], None, vec!["password"], 5_000).await;
        assert_eq!(label, json!({"status": "provider-failed"}), "{command}");
    }
    // No shell: a command line with shell syntax is one program name that does not exist.
    let (label, _) =
        ask_for_test(&json!(format!("{FAKE} x & echo hi")), vec![], None, vec!["password"], 5_000).await;
    assert_eq!(label, json!({"status": "provider-failed"}));
}

#[tokio::test]
async fn a_bare_program_name_is_never_looked_up_on_path() {
    // The system shell prints a file holding an answer. Named by its absolute path it runs, and its answer
    // comes back. Named bare it would be found on PATH: refused before anything starts. The public key
    // phantab adds as the last argument is base64, often with a `/` that cmd's own verbs read as a switch,
    // so the shell is told to ignore it (`rem` on Windows; on unix it is `$1`, unused).
    let scratch = tempfile::tempdir().unwrap();
    let answer = scratch.path().join("answer.json");
    std::fs::write(&answer, "{\"status\":\"none\"}\n").unwrap();
    let answer = answer.display().to_string();
    let (bare, absolute) = if cfg!(windows) {
        let system = std::env::var("SystemRoot").unwrap();
        (
            json!(["cmd", "/c", "type", answer, "&", "rem"]),
            json!([format!(r"{system}\System32\cmd.exe"), "/c", "type", answer, "&", "rem"]),
        )
    } else {
        (json!(["sh", "-c", r#"cat "$0""#, answer]), json!(["/bin/sh", "-c", r#"cat "$0""#, answer]))
    };
    let (label, _) = ask_for_test(&absolute, vec![], None, vec!["password"], 10_000).await;
    assert_eq!(label, json!({"status": "none"}), "the absolute form runs");
    let (label, _) = ask_for_test(&bare, vec![], None, vec!["password"], 10_000).await;
    assert_eq!(label, json!({"status": "provider-failed"}), "the bare name never starts");
}

/// Last change time of the heartbeat, as written by the grandchild.
fn beat(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

// The timeout is 5 s, not less: with 1.5 s it was flaky under heavy load (several builds at once on
// Windows), where the fake provider or its grandchild did not start in time and this failed with "the
// grandchild never ran". Seen 2026-11-06; run alone it passed 3 of 3.
#[tokio::test]
async fn a_timeout_is_busy_and_kills_the_whole_tree() {
    let f = Fake::new();
    let heartbeat = f.path("beat.txt");
    f.control(&json!({"delayMs": 30_000, "grandchild": heartbeat}));
    let began = Instant::now();
    let (label, _) = f.ask(vec!["password"], 5_000).await;
    assert_eq!(label, json!({"status": "busy"}));
    // 15 s: the 5 s timeout plus 10 s of room for the kill and the return on a loaded machine.
    assert!(began.elapsed() < Duration::from_secs(15), "the call did not wait for the provider");
    // The grandchild had started (it beats every 50 ms) and is gone with its parent.
    assert!(beat(&heartbeat).is_some(), "the grandchild never ran");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let then = beat(&heartbeat);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(beat(&heartbeat), then, "the provider's child outlived the timeout");
}

const CHILD: &str = "PHANTAB_SIGNIN_ENV_CHILD";

/// The allow-list (`ENV_ALLOWED`) and phantab's runtime variable.
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
    "LOCALAPPDATA",
    "APPDATA",
    "ProgramData",
    "ComSpec",
    "PHANTAB_RUNTIME",
];

/// Runs itself again with variables set (the test process may not set its own: `set_var` is unsafe), and
/// the child checks what the provider saw.
#[tokio::test]
async fn the_provider_sees_only_the_allowed_environment() {
    if std::env::var_os(CHILD).is_some() {
        let f = Fake::new();
        let out = f.path("env.json");
        f.control(&json!({"envOut": out}));
        assert_eq!(f.ask(vec!["password"], 20_000).await.0, json!({"status": "ok"}));
        let names: Vec<String> = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        for name in &names {
            // macOS: the fake links the phantab lib, so CoreFoundation (the Keychain session store's) loads in
            // it and sets this in the fake's own environment at start. The parent cleared the environment, so
            // it cannot have passed it.
            if cfg!(target_os = "macos") && name == "__CF_USER_TEXT_ENCODING" {
                continue;
            }
            assert!(ALLOWED.iter().any(|a| a.eq_ignore_ascii_case(name)), "the provider saw {name}");
        }
        for name in ["PHANTAB_RUNTIME", "PATH"] {
            assert!(names.iter().any(|n| n.eq_ignore_ascii_case(name)), "the provider did not see {name}");
        }
        return;
    }
    let runtime = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "the_provider_sees_only_the_allowed_environment", "--test-threads=1"])
        .env(CHILD, "1")
        .env("PHANTAB_RUNTIME", runtime.path())
        .env("PHANTAB_SIGNIN_CANARY", "must not reach the provider")
        .env("RUST_LOG", "trace")
        .status()
        .unwrap();
    assert!(status.success(), "the child check failed");
}
