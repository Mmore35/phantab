//! Running the official Bitwarden CLI (docs/BITWARDEN.md § Running bw; THREAT-MODEL SR-64, SR-65): the
//! configured program, never a shell and never a `PATH` lookup, with a small environment of its own. The
//! session key goes only into that child's `BW_SESSION`, only for the commands that need it, and never on
//! its command line (another process can read a command line). stdout is read into a zeroized buffer up
//! to [`OUTPUT_CAP`]; stderr goes nowhere (it can echo the vault's own error text). Every finish kills
//! the whole tree, as the command provider's does. A command that carries the session key starts only
//! while the key's pin holds: the same configured command, and its files unchanged since `connect`
//! ([`super::pin`]), held open (on Windows, shut against writes) until the child has exited, and the
//! child started by the held files' resolved paths rather than the configured ones.

use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::config::Config;
use super::pin::Held;
use super::vault::SessionKey;

/// The most stdout read from one `bw` command. `bw list items --url` prints each candidate's whole item;
/// a few megabytes is hundreds of logins on one site. The buffer is allocated once at this size, so it
/// never grows and leaves a copy behind.
pub(crate) const OUTPUT_CAP: usize = 4 << 20;

/// The variables `bw` may see from phantab's own environment: what Windows and Node need to start, a
/// home and temp folder, and the standard proxy variables (so `bw` reaches the server on a network that
/// needs a proxy, as it does when the owner runs it). Not `APPDATA` or `XDG_CONFIG_HOME` (so the CLI can
/// never fall back to the owner's other `bw` data), and none of `NODE_OPTIONS` (code injection),
/// `NODE_EXTRA_CA_CERTS` (trusts another certificate authority) or `NODE_TLS_REJECT_UNAUTHORIZED` (turns
/// certificate checks off): docs/BITWARDEN.md § Running bw.
///
/// Proxies, checked in bitwarden/clients `cli-v2026.10.1` (`apps/cli/src/platform/services/
/// node-api.service.ts`): `bw` reads `http_proxy`, else `https_proxy`, lower case, and sends every request
/// through it. Windows looks variable names up regardless of case, so there `HTTP_PROXY` works too. It
/// reads neither `NO_PROXY` nor `ALL_PROXY`; they pass because they are harmless and a later `bw` may.
pub(crate) const BW_ENV_ALLOWED: &[&str] = &[
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
];

/// Where the CLI keeps its state: phantab's own folder for it.
pub(crate) const DATA_DIR_ENV: &str = "BITWARDENCLI_APPDATA_DIR";
pub(crate) const SESSION_ENV: &str = "BW_SESSION";
pub(crate) const NO_INTERACTION_ENV: &str = "BW_NOINTERACTION";

/// One `bw` command.
pub(crate) struct Call<'a> {
    pub(crate) args: &'a [&'a str],
    pub(crate) session: Option<&'a SessionKey>,
    /// More variables for this child only (the master password for `unlock --passwordenv`).
    pub(crate) extra_env: &'a [(&'static str, &'a str)],
    /// `connect`'s `bw login`: the owner's terminal is its stdin and stderr, and it may prompt.
    pub(crate) interactive: bool,
    /// The pinned files `connect` holds: the child is started by their resolved paths. A call with a
    /// session holds its own.
    pub(crate) held: Option<&'a Held>,
}

impl<'a> Call<'a> {
    pub(crate) fn new(args: &'a [&'a str], session: Option<&'a SessionKey>) -> Self {
        Call { args, session, extra_env: &[], interactive: false, held: None }
    }
}

/// How a command ended. Its `Debug` prints the size of the output, never the bytes: `bw list items`
/// prints every candidate's password, and a `{:?}` in a log or a test failure must not carry them.
pub(crate) enum Ran {
    /// Exit status 0, and its stdout.
    Out(Zeroizing<Vec<u8>>),
    /// It could not start, exited non-zero, or was killed.
    Failed,
    /// It printed more than [`OUTPUT_CAP`].
    TooBig,
    /// The deadline came first.
    TimedOut,
    /// It carried the session key, and the key was not made with this `bw` (another command, a file that
    /// changed, or a key stored before pins): nothing was started. Callers answer `locked`.
    Unpinned,
}

impl std::fmt::Debug for Ran {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ran::Out(out) => write!(f, "Out(<{} bytes>)", out.len()),
            Ran::Failed => f.write_str("Failed"),
            Ran::TooBig => f.write_str("TooBig"),
            Ran::TimedOut => f.write_str("TimedOut"),
            Ran::Unpinned => f.write_str("Unpinned"),
        }
    }
}

/// The environment of one `bw` child without its secrets: each allowed variable that is set, then
/// phantab's own. On Windows, where `http_proxy` and `HTTP_PROXY` are one variable, a name is taken once.
/// A `proxy` in the config replaces every proxy variable the service has.
pub(crate) fn bw_env(config: &Config, call: &Call<'_>) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    bw_env_from(config, call, |name| std::env::var_os(name))
}

/// [`bw_env`], with the service's environment read through `var`.
fn bw_env_from(
    config: &Config,
    call: &Call<'_>,
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut env: Vec<(std::ffi::OsString, std::ffi::OsString)> = Vec::new();
    for (n, name) in BW_ENV_ALLOWED.iter().enumerate() {
        if cfg!(windows) && BW_ENV_ALLOWED[..n].iter().any(|seen| seen.eq_ignore_ascii_case(name)) {
            continue;
        }
        if config.proxy.is_some() && name.to_ascii_lowercase().ends_with("_proxy") {
            continue;
        }
        if let Some(value) = var(name) {
            env.push(((*name).into(), value));
        }
    }
    if let Some(proxy) = &config.proxy {
        env.push(("http_proxy".into(), proxy.into()));
        env.push(("https_proxy".into(), proxy.into()));
    }
    env.push((DATA_DIR_ENV.into(), config.data_dir.clone().into_os_string()));
    if !call.interactive {
        env.push((NO_INTERACTION_ENV.into(), "true".into()));
    }
    env
}

/// The secret variables of one `bw` child, borrowed from their zeroized owners: the session key, and the
/// master password for `unlock --passwordenv`. `spawn` hands them straight to the command, so phantab
/// makes no copy of its own (THREAT-MODEL R17, R18).
pub(crate) fn secret_env<'a>(call: &Call<'a>) -> Vec<(&'static str, &'a str)> {
    let mut env: Vec<(&'static str, &'a str)> = Vec::new();
    if let Some(key) = call.session {
        env.push((SESSION_ENV, key.expose()));
    }
    env.extend_from_slice(call.extra_env);
    env
}

/// Starts `call`: by `held`'s resolved paths when the files are held, else as configured.
fn spawn(
    config: &Config,
    held: Option<&Held>,
    call: &Call<'_>,
) -> std::io::Result<Box<dyn process_wrap::tokio::ChildWrapper>> {
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::Stdio;

    use process_wrap::tokio::{CommandWrap, KillOnDrop};
    let (program, mut args): (&OsStr, Vec<&OsStr>) = match held {
        Some(held) => (held.program().as_os_str(), held.script().map(Path::as_os_str).into_iter().collect()),
        None => (config.program.as_os_str(), config.prefix.iter().map(OsStr::new).collect()),
    };
    args.extend(call.args.iter().map(OsStr::new));
    if !call.interactive {
        args.push(OsStr::new("--nointeraction"));
    }
    let interactive = call.interactive;
    let env = bw_env(config, call);
    let secrets = secret_env(call);
    let mut cmd = CommandWrap::with_new(program, |c| {
        c.args(&args).env_clear().envs(env);
        for (name, value) in &secrets {
            c.env(name, value);
        }
        c.stdin(if interactive { Stdio::inherit() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(if interactive { Stdio::inherit() } else { Stdio::null() });
    });
    #[cfg(windows)]
    {
        use process_wrap::tokio::{CreationFlags, JobObject};
        use windows::Win32::System::Threading::CREATE_NO_WINDOW;
        // An interactive `bw login` needs the owner's console, so only the others run windowless.
        if !interactive {
            cmd.wrap(CreationFlags(CREATE_NO_WINDOW));
        }
        cmd.wrap(JobObject);
    }
    #[cfg(unix)]
    if !interactive {
        // A process group of its own, so a timeout kills the whole tree. An interactive one stays in the
        // terminal's foreground group so it can read the owner's typing.
        cmd.wrap(process_wrap::tokio::ProcessGroup::leader());
    }
    cmd.wrap(KillOnDrop);
    let _no_pipe_ends = phantab_cdp::spawn_guard();
    cmd.spawn()
}

async fn read_capped(mut stdout: impl tokio::io::AsyncRead + Unpin) -> Result<Zeroizing<Vec<u8>>, Ran> {
    let mut out = Zeroizing::new(Vec::with_capacity(OUTPUT_CAP));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = match stdout.read(&mut chunk[..]).await {
            Ok(0) => return Ok(out),
            Ok(n) => n,
            Err(_) => return Err(Ran::Failed),
        };
        if out.len() + n > OUTPUT_CAP {
            return Err(Ran::TooBig);
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

async fn finish(child: &mut dyn process_wrap::tokio::ChildWrapper) -> Ran {
    let Some(stdout) = child.stdout().take() else { return Ran::Failed };
    let out = match read_capped(stdout).await {
        Ok(out) => out,
        Err(ran) => return ran,
    };
    match child.wait().await {
        Ok(status) if status.success() => Ran::Out(out),
        _ => Ran::Failed,
    }
}

/// Runs one `bw` command until `deadline`. One that carries the session key runs only while the key's
/// pin holds for `config` (checked here, the one place every `bw` starts, so no caller can skip it), and
/// the pinned files stay held until the child is gone; it is started by their resolved paths.
pub(crate) async fn run(config: &Config, call: &Call<'_>, deadline: Instant) -> Ran {
    if Instant::now() >= deadline {
        return Ran::TimedOut;
    }
    let held = match call.session {
        None => None,
        Some(key) => match tokio::time::timeout_at(deadline, super::pin::hold(config, key)).await {
            Ok(Some(held)) => Some(held),
            Ok(None) => return Ran::Unpinned,
            Err(_) => return Ran::TimedOut,
        },
    };
    let Ok(mut child) = spawn(config, held.as_ref().or(call.held), call) else { return Ran::Failed };
    let ran = tokio::time::timeout_at(deadline, finish(child.as_mut())).await.unwrap_or(Ran::TimedOut);
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    ran
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn config() -> Config {
        Config {
            program: PathBuf::from(if cfg!(windows) {
                "C:\\phantab-no-such\\bw.exe"
            } else {
                "/phantab-no-such/bw"
            }),
            prefix: vec![],
            data_dir: PathBuf::from("data"),
            ask_first: vec![],
            policy_file: None,
            sync_after: Duration::ZERO,
            server: None,
            proxy: None,
        }
    }

    /// SR-14, L1: a configured proxy is the only one `bw` gets, whatever the service was started with;
    /// without one, `bw` gets the service's.
    #[test]
    fn a_configured_proxy_replaces_the_services() {
        let service = |name: &str| -> Option<std::ffi::OsString> {
            ["HTTPS_PROXY", "https_proxy", "http_proxy", "no_proxy", "NO_PROXY", "ALL_PROXY", "PATH"]
                .contains(&name)
                .then(|| format!("service-{name}").into())
        };
        let proxies = |c: &Config| -> Vec<(String, String)> {
            bw_env_from(c, &Call::new(&["sync"], None), service)
                .iter()
                .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
                .filter(|(k, _)| k.to_ascii_lowercase().ends_with("_proxy") || k == "PATH")
                .collect()
        };
        let c = Config { proxy: Some("http://10.0.0.1:3128".to_owned()), ..config() };
        let want = "http://10.0.0.1:3128".to_owned();
        assert_eq!(
            proxies(&c),
            [
                ("PATH".to_owned(), "service-PATH".to_owned()),
                ("http_proxy".to_owned(), want.clone()),
                ("https_proxy".to_owned(), want)
            ]
        );
        // Without `proxy`, the service's own pass (on Windows, where case does not matter, each once).
        let given = proxies(&config());
        assert!(given.contains(&("http_proxy".to_owned(), "service-http_proxy".to_owned())), "{given:?}");
        assert!(given.contains(&("no_proxy".to_owned(), "service-no_proxy".to_owned())), "{given:?}");
        assert_eq!(given.iter().any(|(k, _)| k == "HTTPS_PROXY"), !cfg!(windows), "{given:?}");
    }

    #[test]
    fn the_session_goes_only_where_asked() {
        let c = config();
        let names = |call: &Call<'_>| -> Vec<String> {
            bw_env(&c, call).into_iter().map(|(k, _)| k.to_string_lossy().into_owned()).collect()
        };
        let plain = names(&Call::new(&["status"], None));
        assert!(plain.contains(&DATA_DIR_ENV.to_owned()) && plain.contains(&NO_INTERACTION_ENV.to_owned()));
        assert!(!plain.contains(&SESSION_ENV.to_owned()));
        assert_eq!(secret_env(&Call::new(&["status"], None)), vec![]);
        let key = SessionKey::parse(b"S2V5").unwrap();
        let list = Call::new(&["list"], Some(&key));
        assert_eq!(secret_env(&list), vec![(SESSION_ENV, "S2V5")]);
        let all = names(&list);
        assert!(!all.contains(&SESSION_ENV.to_owned()), "secrets are set apart, never copied");
        for name in &all {
            assert!(
                BW_ENV_ALLOWED.contains(&name.as_str())
                    || [DATA_DIR_ENV, NO_INTERACTION_ENV].contains(&name.as_str()),
                "{name}"
            );
        }
        for never in
            ["APPDATA", "LOCALAPPDATA", "NODE_OPTIONS", "PHANTAB_RUNTIME", "CARGO", "XDG_CONFIG_HOME"]
        {
            assert!(!all.iter().any(|n| n.eq_ignore_ascii_case(never)), "{never}");
        }
        let unlock = Call {
            args: &["unlock", "--passwordenv", "PHANTAB_BW_MASTER"],
            session: None,
            extra_env: &[("PHANTAB_BW_MASTER", "pw")],
            interactive: false,
            held: None,
        };
        assert_eq!(secret_env(&unlock), vec![("PHANTAB_BW_MASTER", "pw")]);
        assert!(!names(&unlock).contains(&"PHANTAB_BW_MASTER".to_owned()));
        let login = Call { args: &["login"], interactive: true, ..Call::new(&[], None) };
        let login = names(&login);
        assert!(!login.contains(&NO_INTERACTION_ENV.to_owned()));
    }

    #[test]
    fn proxies_pass_and_tls_overrides_do_not() {
        for proxy in ["http_proxy", "https_proxy", "no_proxy", "all_proxy"] {
            assert!(BW_ENV_ALLOWED.contains(&proxy), "{proxy}");
            assert!(BW_ENV_ALLOWED.contains(&proxy.to_ascii_uppercase().as_str()), "{proxy}");
        }
        for never in ["NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "APPDATA"] {
            assert!(!BW_ENV_ALLOWED.iter().any(|n| n.eq_ignore_ascii_case(never)), "{never}");
        }
        assert!(BW_ENV_ALLOWED.iter().all(|n| !n.to_ascii_uppercase().starts_with("NODE_")));
    }

    #[test]
    fn debug_shows_the_size_and_never_the_output() {
        let ran = Ran::Out(Zeroizing::new(br#"{"password":"hunter2-sentinel"}"#.to_vec()));
        let shown = format!("{ran:?} {ran:#?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(!shown.contains("104"), "no byte values either: {shown}");
        assert_eq!(format!("{ran:?}"), "Out(<31 bytes>)");
        assert_eq!(format!("{:?}", Ran::TimedOut), "TimedOut");
    }

    #[tokio::test]
    async fn a_program_that_cannot_start_fails() {
        let c = config();
        let far = Instant::now() + Duration::from_secs(5);
        assert!(matches!(run(&c, &Call::new(&["status"], None), far).await, Ran::Failed));
        assert!(matches!(run(&c, &Call::new(&["status"], None), Instant::now()).await, Ran::TimedOut));
    }

    #[tokio::test]
    async fn a_key_without_a_pin_for_this_bw_starts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config();
        c.program = dir.path().join(if cfg!(windows) { "bw.exe" } else { "bw" });
        std::fs::write(&c.program, [super::super::pin::NATIVE[0], b"not a program"].concat()).unwrap();
        let far = Instant::now() + Duration::from_secs(5);
        let bare = SessionKey::parse(b"S2V5").unwrap();
        assert!(matches!(run(&c, &Call::new(&["status"], Some(&bare)), far).await, Ran::Unpinned));
        let pinned = SessionKey::parse(b"S2V5").unwrap().pinned(super::super::pin::Pin::of(&c).unwrap());
        // The pin holds, so it is started (and fails: the file is no program).
        assert!(matches!(run(&c, &Call::new(&["status"], Some(&pinned)), far).await, Ran::Failed));
        std::fs::write(&c.program, b"another file").unwrap();
        assert!(matches!(run(&c, &Call::new(&["status"], Some(&pinned)), far).await, Ran::Unpinned));
        assert_eq!(format!("{:?}", Ran::Unpinned), "Unpinned");
    }
}
