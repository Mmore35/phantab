//! Asking the saved-login provider (THREAT-MODEL SR-39, SR-43,
//! SR-44). The provider is the configured command with the service's one-call public key as its last
//! argument, no shell and a small environment. It reads the request on stdin and answers one JSON line
//! on stdout; stderr goes nowhere. Whatever it says, the agent hears only a literal label.

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::Outcome;
use super::seal::{KeyPair, Request, digest};
use super::secret::{Secret, Values};

/// The most stdout the service reads before it gives up on the provider, in bytes, so a provider that
/// answers in multi-byte text is cut off at fewer characters.
pub(crate) const OUTPUT_CAP: usize = 262_144;

/// The variables a provider may see (`ENV_ALLOWED`), plus phantab's runtime variable. On Windows the
/// lookup is case-insensitive, as `process.env` is, and the child gets the name spelled as here.
pub(crate) const ENV_ALLOWED: &[&str] = &[
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
    crate::paths::RUNTIME_ENV,
];

const PROVIDER_STATUS: &[&str] =
    &["none", "ambiguous", "refused", "ask-first", "locked", "provider-failed", "busy", "wall"];

/// The wall reasons a provider (or the page) may name; anything else becomes `no-clear-submit`.
pub(crate) const WALL_REASONS: &[&str] = &[
    "passkey",
    "captcha",
    "code-not-saved",
    "code-boxes",
    "not-taken",
    "no-clear-submit",
    "form-posts-elsewhere",
    "form-posts-in-the-clear",
    "field-not-editable",
];

pub(crate) fn literal(set: &'static [&'static str], value: Option<&str>) -> Option<&'static str> {
    value.and_then(|v| set.iter().copied().find(|s| *s == v))
}

/// The environment the provider starts with: each allowed variable that is set, and nothing else.
pub(crate) fn provider_env() -> Vec<(&'static str, std::ffi::OsString)> {
    ENV_ALLOWED.iter().filter_map(|name| std::env::var_os(name).map(|v| (*name, v))).collect()
}

/// Whether a provider's program is an absolute path. A bare name (`node`) or a relative one would be
/// looked up on `PATH` or in the current folder, where another program can be planted ahead of the real
/// one; so it is refused, as the Bitwarden source's `bw` is (THREAT-MODEL SR-44, SR-64).
pub(crate) fn program_is_absolute(program: &str) -> bool {
    std::path::Path::new(program).is_absolute()
}

/// The configured command as program and arguments, or `None` when it is not an array of strings
/// (Node's `spawn` throws on those: `provider-failed`) or its program is not an absolute path
/// ([`program_is_absolute`]): nothing is started.
pub(crate) fn command_parts(command: &Value) -> Option<(String, Vec<String>)> {
    let parts: Vec<String> =
        command.as_array()?.iter().map(|v| v.as_str().map(str::to_owned)).collect::<Option<_>>()?;
    let (program, args) = parts.split_first()?;
    if !program_is_absolute(program) {
        return None;
    }
    Some((program.clone(), args.to_vec()))
}

/// `engine.config.signInProvider?.command?.length`: whether a provider is configured at all.
pub(crate) fn has_provider(config: Option<&Value>) -> bool {
    match config.and_then(|c| c.get("command")) {
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::String(s)) => !s.is_empty(),
        _ => false,
    }
}

fn failed() -> Value {
    serde_json::json!({ "status": "provider-failed" })
}

fn busy() -> Value {
    serde_json::json!({ "status": "busy" })
}

/// `JSON.parse(line)`, or the provider-failed answer.
fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|_| failed())
}

fn spawn(
    program: &str,
    args: &[String],
    public_key: &str,
) -> std::io::Result<Box<dyn process_wrap::tokio::ChildWrapper>> {
    use process_wrap::tokio::{CommandWrap, KillOnDrop};
    let mut cmd = CommandWrap::with_new(program, |c| {
        c.args(args)
            .arg(public_key)
            .env_clear()
            .envs(provider_env())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
    });
    // The whole tree goes with the provider: a job object on Windows, a process group elsewhere.
    #[cfg(windows)]
    {
        use process_wrap::tokio::{CreationFlags, JobObject};
        use windows::Win32::System::Threading::CREATE_NO_WINDOW;
        cmd.wrap(CreationFlags(CREATE_NO_WINDOW)).wrap(JobObject);
    }
    #[cfg(unix)]
    cmd.wrap(process_wrap::tokio::ProcessGroup::leader());
    cmd.wrap(KillOnDrop);
    // Not while a Chrome launch has its pipe ends open to inheritance (`phantab_cdp::spawn_guard`).
    let _no_pipe_ends = phantab_cdp::spawn_guard();
    cmd.spawn()
}

/// `runProvider`: the provider's first stdout line as JSON, or a stand-in answer. A timer of `ms` answers
/// `busy`. The provider's whole tree is killed at every finish.
pub(crate) async fn run_provider(command: &Value, public_key: &str, input: &str, ms: Duration) -> Value {
    let Some((program, args)) = command_parts(command) else { return failed() };
    let Ok(mut child) = spawn(&program, &args, public_key) else { return failed() };
    let answer = tokio::time::timeout(ms, talk(child.as_mut(), input)).await.unwrap_or_else(|_| busy());
    let _ = child.start_kill();
    // Reap it, briefly: the kill has been sent, and a tree that will not die must not hold the call.
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    answer
}

/// How stdout ended: a first line, or the whole of it at end of file.
enum Read {
    Line(Value),
    Ended(Vec<u8>),
}

async fn read_line(mut stdout: impl tokio::io::AsyncRead + Unpin) -> Read {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stdout.read(&mut chunk).await {
            Ok(0) | Err(_) => return Read::Ended(out),
            Ok(n) => n,
        };
        let seen = out.len();
        out.extend_from_slice(&chunk[..n]);
        if out.len() > OUTPUT_CAP {
            return Read::Line(failed());
        }
        if let Some(end) = out[seen..].iter().position(|b| *b == b'\n') {
            return Read::Line(parse(&out[..seen + end]));
        }
    }
}

async fn talk(child: &mut dyn process_wrap::tokio::ChildWrapper, input: &str) -> Value {
    let (Some(mut stdin), Some(stdout)) = (child.stdin().take(), child.stdout().take()) else {
        return failed();
    };
    // The request goes in while stdout is read, as Node's `stdin.end(input)` does: a provider that answers
    // before reading (or never reads) must not hold the write. A write error is not one either.
    let input = input.as_bytes().to_vec();
    let writer = async move {
        let _ = stdin.write_all(&input).await;
        let _ = stdin.shutdown().await;
    };
    tokio::pin!(writer);
    let reader = read_line(stdout);
    tokio::pin!(reader);
    let mut written = false;
    let read = loop {
        tokio::select! {
            () = &mut writer, if !written => written = true,
            read = &mut reader => break read,
        }
    };
    match read {
        Read::Line(v) => v,
        // `close`: stdout ended and the process is gone.
        Read::Ended(out) => {
            let _ = child.wait().await;
            if out.is_empty() { failed() } else { parse(&out) }
        }
    }
}

/// What the provider said, reduced to what the call may use.
#[derive(Debug)]
pub(crate) enum Answer {
    Ok { values: Values, account_key: String },
    Not(Outcome),
}

/// Integers that JSON can carry exactly. `Number.isInteger` also passes `3.0` and `1e300`; phantab keeps
/// the first kind and drops a count too large for an i64.
fn integer(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    v.as_i64().or_else(|| {
        let f = v.as_f64()?;
        // The cast is exact: f is a whole number inside i64's range.
        #[allow(clippy::cast_possible_truncation)]
        (f.fract() == 0.0 && f.abs() < 9.2e18).then_some(f as i64)
    })
}

/// The answer to a plain status, reduced to an outcome.
pub(crate) fn plain_answer(answer: &Value) -> Outcome {
    let Some(status) = literal(PROVIDER_STATUS, answer.get("status").and_then(Value::as_str)) else {
        return Outcome::of("provider-failed");
    };
    match status {
        "wall" => {
            let reason = literal(WALL_REASONS, answer.get("reason").and_then(Value::as_str))
                .unwrap_or("no-clear-submit");
            Outcome::with(status, reason)
        }
        "ambiguous" => Outcome { count: integer(answer.get("count")), ..Outcome::of(status) },
        _ => Outcome::of(status),
    }
}

/// Opens a sealed answer and keeps only what was asked for, in `want` order.
pub(crate) fn open_answer(
    pair: &KeyPair,
    request_json: &str,
    want: &[&'static str],
    answer: &Value,
) -> Answer {
    let refused = || Answer::Not(Outcome::of("refused"));
    let Some(mut opened) = answer.get("sealed").and_then(|s| pair.unseal(s)) else { return refused() };
    let opened = &mut opened.0;
    if opened.get("digest").and_then(Value::as_str) != Some(digest(request_json).as_str()) {
        return refused();
    }
    let Some(account_key) =
        opened.get("accountKey").and_then(Value::as_str).filter(|k| !k.is_empty()).map(str::to_owned)
    else {
        return refused();
    };
    let values = match opened.get_mut("values") {
        Some(Value::Object(map)) => map,
        // An array is not a map of named values.
        Some(Value::Array(_)) => return Answer::Not(Outcome::of("provider-failed")),
        _ => return refused(),
    };
    let mut out = Values::default();
    for name in want {
        let Some(Value::String(v)) =
            values.get_mut(*name).filter(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        else {
            return Answer::Not(Outcome::of("provider-failed"));
        };
        let secret = Some(Secret::new(std::mem::take(v)));
        match *name {
            "username" => out.username = secret,
            "password" => out.password = secret,
            _ => out.code = secret,
        }
    }
    Answer::Ok { values: out, account_key }
}

/// `askProvider`: one key pair for this call, the request on stdin, and the answer reduced.
pub(crate) async fn ask_provider(command: &Value, request: &Request, ms: Duration) -> Answer {
    let Ok(pair) = KeyPair::generate() else { return Answer::Not(Outcome::of("provider-failed")) };
    let json = request.to_json();
    let answer = run_provider(command, pair.public(), &json, ms).await;
    if answer.get("status").and_then(Value::as_str) != Some("ok") {
        return Answer::Not(plain_answer(&answer));
    }
    open_answer(&pair, &json, &request.want, &answer)
}

/// Test builds only: one provider round trip as the call makes it, for the provider tests (tree kill,
/// environment, answers). Answers the label, and for a sealed answer the account key and the values.
#[cfg(feature = "test-seams")]
pub async fn ask_for_test(
    command: &Value,
    urls: Vec<String>,
    account_key: Option<String>,
    want: Vec<&'static str>,
    ms: u64,
) -> (Value, Option<(String, Vec<(String, String)>)>) {
    let request = Request { urls, account: None, account_key, want };
    match ask_provider(command, &request, Duration::from_millis(ms)).await {
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
    use crate::signin::seal::seal;

    fn request() -> Request {
        Request {
            urls: vec!["https://a.test/".into()],
            account: None,
            account_key: None,
            want: vec!["username", "password"],
        }
    }

    #[test]
    fn plain_answers_become_labels() {
        for (answer, want) in [
            (json!({"status": "none"}), Outcome::of("none")),
            (
                json!({"status": "ambiguous", "count": 3, "extra": "dropped"}),
                Outcome { count: Some(3), ..Outcome::of("ambiguous") },
            ),
            (
                json!({"status": "ambiguous", "count": 3.0}),
                Outcome { count: Some(3), ..Outcome::of("ambiguous") },
            ),
            (json!({"status": "ambiguous", "count": 2.5}), Outcome::of("ambiguous")),
            (json!({"status": "ambiguous", "count": "3"}), Outcome::of("ambiguous")),
            (json!({"status": "refused", "why": "stack trace"}), Outcome::of("refused")),
            (json!({"status": "ask-first"}), Outcome::of("ask-first")),
            (json!({"status": "locked"}), Outcome::of("locked")),
            (json!({"status": "provider-failed"}), Outcome::of("provider-failed")),
            (json!({"status": "busy"}), Outcome::of("busy")),
            (json!({"status": "wall", "reason": "code-not-saved"}), Outcome::with("wall", "code-not-saved")),
            (
                json!({"status": "wall", "reason": "free text from a provider"}),
                Outcome::with("wall", "no-clear-submit"),
            ),
            (json!({"status": "wall"}), Outcome::with("wall", "no-clear-submit")),
            (json!({"status": "made-up-status"}), Outcome::of("provider-failed")),
            (json!({"status": "submitted"}), Outcome::of("provider-failed")),
            (json!("not json"), Outcome::of("provider-failed")),
            (json!(null), Outcome::of("provider-failed")),
            (json!([1]), Outcome::of("provider-failed")),
        ] {
            assert_eq!(plain_answer(&answer), want, "{answer}");
        }
    }

    #[test]
    fn sealed_answers_are_checked() {
        let pair = KeyPair::generate().unwrap();
        let r = request();
        let j = r.to_json();
        let good = |values: Value| json!({"status": "ok", "sealed": seal(pair.public(), &json!({"digest": digest(&j), "accountKey": "k1", "values": values})).unwrap()});
        let Answer::Ok { values, account_key } =
            open_answer(&pair, &j, &r.want, &good(json!({"code": "1", "password": "p", "username": "u"})))
        else {
            panic!("refused a good answer")
        };
        assert_eq!(account_key, "k1");
        assert_eq!(values.username.as_ref().map(Secret::expose), Some("u"));
        assert_eq!(values.password.as_ref().map(Secret::expose), Some("p"));
        assert!(values.code.is_none(), "only what was asked");
        let outcome = |a: &Value| match open_answer(&pair, &j, &r.want, a) {
            Answer::Ok { .. } => "ok",
            Answer::Not(o) => o.status,
        };
        assert_eq!(outcome(&good(json!({"username": "u"}))), "provider-failed");
        assert_eq!(outcome(&good(json!({"username": "u", "password": ""}))), "provider-failed");
        assert_eq!(outcome(&good(json!({"username": "u", "password": 5}))), "provider-failed");
        assert_eq!(outcome(&good(json!(["u", "p"]))), "provider-failed");
        assert_eq!(outcome(&good(json!(null))), "refused");
        assert_eq!(outcome(&good(json!("up"))), "refused");
        let sealed =
            |payload: Value| json!({"status": "ok", "sealed": seal(pair.public(), &payload).unwrap()});
        let values = json!({"username": "u", "password": "p"});
        assert_eq!(
            outcome(&sealed(json!({"digest": "0".repeat(64), "accountKey": "k", "values": values}))),
            "refused"
        );
        assert_eq!(
            outcome(&sealed(json!({"digest": digest(&j), "accountKey": "", "values": values}))),
            "refused"
        );
        assert_eq!(
            outcome(&sealed(json!({"digest": digest(&j), "accountKey": 7, "values": values}))),
            "refused"
        );
        assert_eq!(outcome(&sealed(json!({"digest": digest(&j), "values": values}))), "refused");
        assert_eq!(outcome(&sealed(json!(null))), "refused");
        assert_eq!(outcome(&json!({"status": "ok"})), "refused");
        assert_eq!(outcome(&json!({"status": "ok", "sealed": "x"})), "refused");
        // Sealed to another key.
        let other = KeyPair::generate().unwrap();
        let theirs = json!({"status": "ok", "sealed": seal(other.public(), &json!({"digest": digest(&j), "accountKey": "k", "values": values})).unwrap()});
        assert_eq!(outcome(&theirs), "refused");
    }

    #[test]
    fn commands_and_env() {
        let node = if cfg!(windows) { r"C:\tools\node.exe" } else { "/opt/tools/node" };
        assert_eq!(command_parts(&json!([node, "x.mjs"])), Some((node.into(), vec!["x.mjs".into()])));
        assert_eq!(command_parts(&json!([node])), Some((node.into(), vec![])));
        assert_eq!(command_parts(&json!([])), None);
        assert_eq!(command_parts(&json!("node x.mjs")), None);
        assert_eq!(command_parts(&json!([node, 5])), None);
        // Never a name looked up on PATH or in the current folder (sec-creds-8).
        for relative in ["node", "only", "node.exe", "./node", "bin/node", r"..\node.exe", ""] {
            assert_eq!(command_parts(&json!([relative, "x.mjs"])), None, "{relative:?}");
        }
        // Windows: a path from the current drive's root, or relative to a drive's current folder.
        #[cfg(windows)]
        for not_absolute in [r"\tools\node.exe", r"C:node.exe", "/opt/tools/node"] {
            assert_eq!(command_parts(&json!([not_absolute])), None, "{not_absolute}");
        }
        assert!(has_provider(Some(&json!({"command": ["a"]}))));
        assert!(has_provider(Some(&json!({"command": "a"}))));
        assert!(!has_provider(Some(&json!({"command": []}))));
        assert!(!has_provider(Some(&json!({"command": ""}))));
        assert!(!has_provider(Some(&json!({}))));
        assert!(!has_provider(None));
        // Only allowed names, each at most once, spelled as in the list.
        let env = provider_env();
        assert!(env.iter().all(|(n, _)| ENV_ALLOWED.contains(n)));
        assert!(ENV_ALLOWED.contains(&"PHANTAB_RUNTIME"));
        assert!(
            !env.iter().any(
                |(n, _)| n.eq_ignore_ascii_case("PHANTAB_TEST_CHROME") || n.eq_ignore_ascii_case("CARGO")
            )
        );
        #[cfg(windows)]
        assert!(env.iter().any(|(n, _)| *n == "PATH"), "Path is found case-insensitively and passed as PATH");
    }

    #[tokio::test]
    async fn a_command_that_cannot_start_is_provider_failed() {
        let pk = KeyPair::generate().unwrap();
        let out = run_provider(
            &json!(["phantab-no-such-program-anywhere"]),
            pk.public(),
            "{}",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out, failed());
        assert_eq!(run_provider(&json!("x"), pk.public(), "{}", Duration::from_secs(5)).await, failed());
        assert_eq!(
            run_provider(&json!(["bad\0name"]), pk.public(), "{}", Duration::from_secs(5)).await,
            failed()
        );
    }
}
