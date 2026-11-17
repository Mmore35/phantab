//! `phantab install` / `uninstall`. Everything lives
//! in temp dirs; the native host and Run keys are scratch keys under `HKCU\Software\phantab-test-<pid>`,
//! removed afterwards. No test reads or writes the owner's client configs, runtimes or real registry keys.

// Test helpers fail by panicking, like the tests themselves (clippy.toml allows it only inside #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

const FAKE_EXE: &[u8] = b"fake phantab binary";
/// A sign-in provider's program: an absolute path, as phantab requires (a bare name is refused). Never run.
const NODE: &str = if cfg!(windows) { r"C:\tools\node.exe" } else { "/opt/tools/node" };

/// One test's world: a Chrome profile, a fake browser and binary, a built extension, a client config.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    runtime: PathBuf,
    browser: PathBuf,
    chrome: PathBuf,
    exe: PathBuf,
    extension: PathBuf,
    target: PathBuf,
    #[cfg(windows)]
    keys: reg::Scratch,
}

impl Fixture {
    #[cfg_attr(
        not(windows),
        allow(unused_variables, reason = "names the scratch registry keys, Windows only")
    )]
    fn new(test: &str) -> Self {
        let dir = tempfile::Builder::new().prefix("phantab install ").tempdir().unwrap();
        let root = plain(&std::fs::canonicalize(dir.path()).unwrap());
        let browser = root.join("browser");
        std::fs::create_dir_all(browser.join("Default")).unwrap();
        std::fs::write(browser.join("Default").join("Preferences"), "{}").unwrap();
        let chrome = root.join("chrome.exe");
        std::fs::write(&chrome, b"fixture").unwrap();
        let exe = root.join("source").join("phantab.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, FAKE_EXE).unwrap();
        let extension = root.join("extension-dist");
        std::fs::create_dir_all(extension.join("icons")).unwrap();
        std::fs::copy(repo().join("extension").join("manifest.json"), extension.join("manifest.json"))
            .unwrap();
        std::fs::write(extension.join("icons").join("icon.txt"), "icon").unwrap();
        let target = root.join("client.toml");
        std::fs::write(&target, "model=\"unchanged\"\n").unwrap();
        Self {
            runtime: root.join("state"),
            _dir: dir,
            root,
            browser,
            chrome,
            exe,
            extension,
            target,
            #[cfg(windows)]
            keys: reg::Scratch::new(test),
        }
    }

    /// A runtime that already has its binding, plus `"retained": <extra>`.
    fn with_runtime(self, extra: &str) -> Self {
        std::fs::create_dir_all(&self.runtime).unwrap();
        let config = json!({
            "profileDirectory": "Default",
            "userDataDir": self.browser,
            "chromeExecutable": self.chrome,
        })
        .to_string();
        let text = format!("{},\"retained\":{extra}}}", &config[..config.len() - 1]);
        std::fs::write(self.runtime.join("config.json"), text).unwrap();
        self
    }

    /// The flags every run gets: this runtime, this extension, the scratch keys.
    fn base(&self) -> Vec<String> {
        #[cfg_attr(not(windows), allow(unused_mut, reason = "only Windows adds the scratch keys"))]
        let mut words = vec![
            "--runtime".to_owned(),
            self.runtime.display().to_string(),
            "--extension-dir".to_owned(),
            self.extension.display().to_string(),
        ];
        #[cfg(windows)]
        words.extend([
            "--native-host-key".to_owned(),
            self.keys.host(),
            "--run-key".to_owned(),
            self.keys.run(),
        ]);
        words
    }

    /// `base` and `--codex-config <target>`, then `extra`.
    fn argv(&self, extra: &[&str]) -> Vec<String> {
        let mut words = self.base();
        words.extend(["--codex-config".to_owned(), self.target.display().to_string()]);
        words.extend(extra.iter().map(|s| (*s).to_owned()));
        words
    }

    fn run(&self, words: &[String]) -> anyhow::Result<String> {
        self.run_as(words, false)
    }

    fn run_as(&self, words: &[String], uninstall: bool) -> anyhow::Result<String> {
        let mut out = Vec::new();
        let code = phantab::install::run_with(words, uninstall, &self.exe, &mut out)?;
        assert_eq!(code, 0, "{words:?}");
        Ok(String::from_utf8(out).unwrap())
    }

    fn config(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.runtime.join("config.json")).unwrap()).unwrap()
    }

    /// Chrome profile `folder` lists the bridge, loaded from `copy`, as Chrome writes it once the owner
    /// loads it at `chrome://extensions`.
    fn loads_bridge(&self, folder: &str, copy: &Path) {
        let id = phantab::bridge::EXTENSION_ID.as_str();
        let prefs = json!({ "extensions": { "settings": { id: { "path": copy, "location": 4 } } } });
        std::fs::write(self.browser.join(folder).join("Secure Preferences"), prefs.to_string()).unwrap();
    }

    fn record(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.runtime.join("registration-v2.json")).unwrap()).unwrap()
    }

    fn binary(&self) -> PathBuf {
        self.runtime.join("bin").join(format!("phantab{}", std::env::consts::EXE_SUFFIX))
    }

    /// Every file under the fixture, for "nothing changed" checks.
    fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        files(&self.root)
    }
}

fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.insert(path.strip_prefix(root).unwrap().to_path_buf(), std::fs::read(&path).unwrap());
            }
        }
    }
    found
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn plain(path: &Path) -> PathBuf {
    PathBuf::from(path.to_string_lossy().trim_start_matches(r"\\?\"))
}

fn toml_of(path: &Path) -> toml::Table {
    std::fs::read_to_string(path).unwrap().parse().unwrap()
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

#[cfg(windows)]
mod reg {
    //! Scratch HKCU keys: each test gets `Software\phantab-test-<pid>\<test>`, deleted when it ends; the
    //! `<pid>` key goes once no test is left under it.
    use std::sync::Mutex;

    use windows_registry::CURRENT_USER;

    static LOCK: Mutex<()> = Mutex::new(());

    fn base() -> String {
        format!(r"Software\phantab-test-{}", std::process::id())
    }

    #[derive(Debug)]
    pub struct Scratch {
        sub: String,
    }

    impl Scratch {
        pub fn new(test: &str) -> Self {
            let sub = format!(r"{}\{test}", base());
            let _held = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = CURRENT_USER.remove_tree(&sub);
            // The test's own key holds the <pid> key open for it until it ends.
            CURRENT_USER.create(&sub).unwrap();
            Self { sub }
        }

        pub fn host(&self) -> String {
            format!(r"HKCU\{}\NativeHost", self.sub)
        }

        /// In the `HKCU:\` form (PowerShell's), which install also takes.
        pub fn run(&self) -> String {
            format!(r"HKCU:\{}\Run", self.sub)
        }

        pub fn host_value(&self) -> Option<String> {
            CURRENT_USER.open(format!(r"{}\NativeHost", self.sub)).ok()?.get_string("").ok()
        }

        pub fn host_key_exists(&self) -> bool {
            CURRENT_USER.open(format!(r"{}\NativeHost", self.sub)).is_ok()
        }

        pub fn set_host(&self, value: &str) {
            CURRENT_USER.create(format!(r"{}\NativeHost", self.sub)).unwrap().set_string("", value).unwrap();
        }

        pub fn set_run(&self, name: &str, value: &str) {
            CURRENT_USER.create(format!(r"{}\Run", self.sub)).unwrap().set_string(name, value).unwrap();
        }

        pub fn run_value(&self, name: &str) -> String {
            CURRENT_USER.open(format!(r"{}\Run", self.sub)).unwrap().get_string(name).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _held = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = CURRENT_USER.remove_tree(&self.sub);
            let empty = CURRENT_USER.open(base()).is_ok_and(|key| {
                key.keys().is_ok_and(|mut k| k.next().is_none())
                    && key.values().is_ok_and(|mut v| v.next().is_none())
            });
            if empty {
                let _ = CURRENT_USER.remove_tree(base());
            }
        }
    }
}

#[test]
fn nonfinite_runtime_refuses_before_any_registration_mutation() {
    for extra in ["NaN", "Infinity", "-Infinity", "1e400", "-1e400", r#"{"nested":[0,NaN]}"#] {
        let world = Fixture::new("nonfinite").with_runtime(extra);
        let before = world.files();
        let error = world.run(&world.argv(&[])).unwrap_err();
        assert!(format!("{error:#}").contains("config.json"), "{extra}: {error:#}");
        assert_eq!(world.files(), before, "{extra}");
        assert!(!world.runtime.join("registration-v2.json").exists());
        #[cfg(windows)]
        assert!(!world.keys.host_key_exists(), "{extra}");
    }
}

#[test]
fn finite_runtime_preserves_unknown_fields_and_token_strings() {
    let extra = r#"{"":null,"A":1,"a":2,"values":[1e300,-2.5,true,"NaN Infinity"]}"#;
    let world = Fixture::new("finite").with_runtime(extra);
    world.run(&world.argv(&[])).unwrap();
    let once = std::fs::read(world.runtime.join("config.json")).unwrap();
    world.run(&world.argv(&[])).unwrap();
    let text = String::from_utf8(once.clone()).unwrap();
    assert!(!text.contains("NaN,") && !text.contains("Infinity,"), "{text}");
    let output: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(output["retained"], serde_json::from_str::<Value>(extra).unwrap());
    assert_eq!(std::fs::read(world.runtime.join("config.json")).unwrap(), once);
    assert_eq!(toml_of(&world.target)["model"].as_str(), Some("unchanged"));
}

#[test]
fn uninstall_does_not_rewrite_nonfinite_runtime() {
    let world = Fixture::new("uninstall-nonfinite").with_runtime("1");
    let original = toml_of(&world.target);
    world.run(&world.argv(&[])).unwrap();
    let text = std::fs::read_to_string(world.runtime.join("config.json")).unwrap();
    let bad = text.replace("\"retained\": 1", "\"retained\": NaN");
    assert_ne!(bad, text);
    std::fs::write(world.runtime.join("config.json"), &bad).unwrap();
    world.run(&world.argv(&["--uninstall"])).unwrap();
    assert_eq!(std::fs::read_to_string(world.runtime.join("config.json")).unwrap(), bad);
    assert_eq!(toml_of(&world.target), original);
}

#[cfg(windows)]
#[test]
fn quiet_debugging_round_trip_on_a_scratch_key() {
    let world = Fixture::new("quiet");
    let chrome = r"C:\Fixture Browser\chrome.exe";
    let browser = format!(r#""{chrome}" --no-startup-window /prefetch:5"#);
    let other = r#""C:\Other\app.exe" --keep"#;
    world.keys.set_run("Browser", &browser);
    world.keys.set_run("Other", other);
    let flagged = format!(r#""{chrome}" --silent-debugger-extension-api --no-startup-window /prefetch:5"#);
    std::fs::create_dir_all(&world.runtime).unwrap();
    std::fs::write(world.runtime.join("config.json"), json!({ "chromeExecutable": chrome }).to_string())
        .unwrap();
    let argv = |mode: &str| {
        let mut words = world.base();
        words.extend(["--quiet-debugging".to_owned(), mode.to_owned()]);
        words
    };
    // No client config is needed to change it, unlike an install.
    world.run(&argv("on")).unwrap();
    assert_eq!(world.keys.run_value("Browser"), flagged);
    assert_eq!(world.keys.run_value("Other"), other);
    assert!(world.runtime.join("quiet-debugging.on").exists());
    let again = world.run(&argv("on")).unwrap();
    assert_eq!(world.keys.run_value("Browser"), flagged);
    assert!(again.contains("Quiet debugging on"), "{again}");
    world.run(&argv("off")).unwrap();
    assert_eq!(world.keys.run_value("Browser"), browser);
    assert_eq!(world.keys.run_value("Other"), other);
    assert!(!world.runtime.join("quiet-debugging.on").exists());
    assert!(world.runtime.join("quiet-debugging.off").exists(), "off is an answer too");
    assert!(!world.runtime.join("registration-v2.json").exists(), "quiet mode registers nothing");
}

/// The shortcuts a Windows install edits, on a scratch folder (`--shortcut-dir`): on adds the flag, off
/// and uninstall restore the arguments as they were, and a shortcut to another program is never touched.
/// An uninstall whose off fails keeps the answer, so the next uninstall takes the flag off.
#[cfg(windows)]
#[test]
fn quiet_debugging_round_trip_on_scratch_shortcuts() {
    let world = Fixture::new("quiet-shortcuts").with_runtime("1");
    let dir = world.root.join("shortcuts");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = format!(r#"--user-data-dir="{}" --profile-directory=Default"#, world.browser.display());
    let flagged = format!("--silent-debugger-extension-api {plain}");
    let (ours, other) = (dir.join("Chrome.lnk"), dir.join("Other.lnk"));
    lnk::make(&ours, &world.chrome, &plain);
    lnk::make(&other, &world.exe, "--silent-debugger-extension-api");
    let mut argv = world.argv(&["--shortcut-dir"]);
    argv.push(dir.display().to_string());
    let with = |extra: &[&str]| {
        let mut words = argv.clone();
        words.extend(extra.iter().map(|s| (*s).to_owned()));
        words
    };

    let on = world.run(&with(&["--quiet-debugging", "on"])).unwrap();
    assert!(on.contains("1 shortcut start Chrome with the flag (1 changed now)"), "{on}");
    assert_eq!(lnk::arguments(&ours), flagged);
    let again = world.run(&with(&["--quiet-debugging", "on"])).unwrap();
    assert!(again.contains("(0 changed now)"), "{again}");
    let off = world.run(&with(&["--quiet-debugging", "off"])).unwrap();
    assert!(off.contains("phantab took the flag off 1 shortcut."), "{off}");
    assert_eq!(lnk::arguments(&ours), plain);
    assert_eq!(lnk::arguments(&other), "--silent-debugger-extension-api", "another program's shortcut");

    world.run(&with(&["--quiet-debugging", "on"])).unwrap();
    assert_eq!(lnk::arguments(&ours), flagged);
    let refused = with(&["--run-key", r"HKLM\Software\phantab-test-refused"]);
    let failed = phantab::install::run_with(&refused, true, &world.exe, &mut Vec::new());
    assert!(failed.is_err(), "an off the run key refuses fails the uninstall");
    assert!(format!("{:#}", failed.unwrap_err()).contains("nothing was uninstalled"));
    assert!(world.runtime.join("quiet-debugging.on").exists(), "the answer stays for the next uninstall");
    let gone = world.run_as(&argv, true).unwrap();
    assert!(gone.contains("phantab took the flag off 1 shortcut."), "{gone}");
    assert_eq!(lnk::arguments(&ours), plain);
    assert_eq!(world.answer(), (false, false));
}

#[cfg(windows)]
mod lnk {
    //! Scratch `.lnk` shortcuts through Windows' own `WScript.Shell`, the shell link files Explorer makes.
    use std::path::Path;
    use std::process::Command;

    fn powershell(script: &str, envs: &[(&str, &str)]) -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let out = Command::new(format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe"))
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .envs(envs.iter().copied())
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim_end_matches(['\r', '\n']).to_owned()
    }

    pub fn make(path: &Path, target: &Path, args: &str) {
        powershell(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK); $s.TargetPath = $env:TARGET; \
             $s.Arguments = $env:ARGS; $s.Save()",
            &[
                ("LNK", &path.display().to_string()),
                ("TARGET", &target.display().to_string()),
                ("ARGS", args),
            ],
        );
    }

    pub fn arguments(path: &Path) -> String {
        powershell(
            "(New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK).Arguments",
            &[("LNK", &path.display().to_string())],
        )
    }
}

const QUESTION: &str = "Hide Chrome's debugging bar?";

impl Fixture {
    /// [`Fixture::run`] at a terminal where the owner types `typed`.
    fn run_typing(&self, words: &[String], typed: &str) -> String {
        let mut out = Vec::new();
        let code =
            phantab::install::run_at_terminal(words, false, &self.exe, &mut out, &mut typed.as_bytes())
                .unwrap();
        assert_eq!(code, 0, "{words:?}");
        String::from_utf8(out).unwrap()
    }

    fn answer(&self) -> (bool, bool) {
        (self.runtime.join("quiet-debugging.on").exists(), self.runtime.join("quiet-debugging.off").exists())
    }
}

/// An install at a terminal asks once, Enter being yes; later installs keep the answer and never ask.
#[test]
fn an_install_at_a_terminal_asks_about_quiet_debugging_once() {
    let world = Fixture::new("ask-yes").with_runtime("1");
    let said = world.run_typing(&world.argv(&[]), "\n");
    assert!(said.contains(QUESTION), "{said}");
    assert!(said.contains("every extension that uses Chrome's debugger attaches silently"), "{said}");
    assert!(said.contains("Quiet debugging on"), "{said}");
    assert_eq!(world.answer(), (true, false));
    let again = world.run_typing(&world.argv(&[]), "n\n");
    assert!(!again.contains(QUESTION), "{again}");
    assert!(again.contains("Quiet debugging on"), "on is applied again: {again}");
    assert_eq!(world.answer(), (true, false));
    let flag = world.run(&world.argv(&["--quiet-debugging", "off"])).unwrap();
    assert!(flag.contains("Quiet debugging off"), "{flag}");
    assert_eq!(world.answer(), (false, true));
    world.run_as(&world.argv(&[]), true).unwrap();
    assert_eq!(world.answer(), (false, false), "uninstall forgets the answer");
}

/// No is kept too: later installs neither ask nor change anything. Without a terminal nothing is asked.
#[test]
fn a_no_is_kept_and_without_a_terminal_nothing_is_asked() {
    let world = Fixture::new("ask-no").with_runtime("1");
    let quiet = world.run(&world.argv(&[])).unwrap();
    assert!(!quiet.contains(QUESTION), "{quiet}");
    assert!(quiet.contains("run phantab install --quiet-debugging on"), "{quiet}");
    assert_eq!(world.answer(), (false, false));
    let said = world.run_typing(&world.argv(&[]), "no\n");
    assert!(said.contains(QUESTION), "{said}");
    assert!(said.contains("Quiet debugging off"), "{said}");
    assert_eq!(world.answer(), (false, true));
    let again = world.run_typing(&world.argv(&[]), "\n");
    assert!(!again.contains(QUESTION) && !again.contains("Quiet debugging"), "{again}");
    assert_eq!(world.answer(), (false, true));
}

#[cfg(windows)]
#[test]
fn uninstall_turns_quiet_debugging_off() {
    let world = Fixture::new("uninstall-quiet").with_runtime("1");
    let chrome = world.chrome.display().to_string();
    let flagged = format!(r#""{chrome}" --silent-debugger-extension-api --no-startup-window"#);
    world.keys.set_run("Browser", &flagged);
    world.run(&world.argv(&[])).unwrap();
    world.run(&world.argv(&["--uninstall"])).unwrap();
    assert_eq!(world.keys.run_value("Browser"), flagged, "no marker: the Run key is left alone");
    world.run(&world.argv(&[])).unwrap();
    std::fs::write(world.runtime.join("quiet-debugging.on"), "").unwrap();
    world.run_as(&world.argv(&[]), true).unwrap();
    assert_eq!(world.keys.run_value("Browser"), format!(r#""{chrome}" --no-startup-window"#));
    assert!(!world.runtime.join("quiet-debugging.on").exists());
}

#[test]
fn single_client_install_rerun_uninstall() {
    let world = Fixture::new("single");
    let profile = world.browser.join("Work Profile");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(profile.join("Preferences"), "{}").unwrap();
    let mut argv = world.base();
    argv.extend(words(&["--profile", "Work Profile", "--user-data-dir"]));
    argv.extend([
        world.browser.display().to_string(),
        "--chrome".to_owned(),
        world.chrome.display().to_string(),
    ]);
    argv.extend(["--codex-config".to_owned(), world.target.display().to_string()]);
    let output = world.run(&argv).unwrap();
    assert!(output.contains("Registered phantab in 1 selected clients; browser not restarted."), "{output}");
    assert!(output.contains("Load unpacked"), "{output}");
    let once = std::fs::read(&world.target).unwrap();
    world.run(&argv).unwrap();
    assert_eq!(std::fs::read(&world.target).unwrap(), once);

    let binary = world.binary().display().to_string();
    let entry = &toml_of(&world.target)["mcp_servers"]["phantab"];
    assert_eq!(entry["command"].as_str(), Some(binary.as_str()));
    assert_eq!(entry["args"].as_array().unwrap(), &vec![toml::Value::from("mcp")]);
    assert_eq!(entry["startup_timeout_sec"].as_integer(), Some(30));
    assert_eq!(entry["tool_timeout_sec"].as_integer(), Some(120));
    let config = world.config();
    assert_eq!(config["profileDirectory"], "Work Profile");
    assert_eq!(config["userDataDir"], json!(world.browser));
    assert_eq!(config["chromeExecutable"], json!(world.chrome));
    assert_eq!(config["installedSource"], json!(binary));
    assert_eq!(std::fs::read(world.binary()).unwrap(), FAKE_EXE);

    // Later edits to other settings must survive uninstall.
    let later = std::fs::read_to_string(&world.target).unwrap().replace("unchanged", "later");
    std::fs::write(&world.target, later).unwrap();
    let uninstall = vec![
        "--runtime".to_owned(),
        world.runtime.display().to_string(),
        "--codex-config".to_owned(),
        world.target.display().to_string(),
    ];
    let output = world.run_as(&uninstall, true).unwrap();
    assert!(output.contains("Removed phantab in 1 selected clients"), "{output}");
    assert_eq!(toml_of(&world.target), "model = \"later\"".parse::<toml::Table>().unwrap());
}

#[test]
fn sign_in_provider_is_written_kept_and_removed_only_by_the_installer() {
    let world = Fixture::new("provider").with_runtime("1");
    let read = || world.config().get("signInProvider").cloned();
    world.run(&world.argv(&[])).unwrap();
    assert_eq!(read(), None);
    let command = json!([NODE, "provider one.mjs"]);
    world.run(&world.argv(&["--sign-in-provider", &command.to_string()])).unwrap();
    let expected = json!({ "command": command });
    assert_eq!(read(), Some(expected.clone()));
    world.run(&world.argv(&[])).unwrap();
    assert_eq!(read(), Some(expected.clone()), "a later install keeps it");
    // A bare program would be looked up on PATH: refused (sec-creds-8).
    for bad in
        [r#""node provider.mjs""#, r#"["node",1]"#, r#"["node",""]"#, "{}", r#"["node","provider.mjs"]"#]
    {
        assert!(world.run(&world.argv(&["--sign-in-provider", bad])).is_err(), "{bad}");
    }
    assert_eq!(read(), Some(expected), "a refused value changes nothing");
    world.run(&world.argv(&["--sign-in-provider", "[]"])).unwrap();
    assert_eq!(read(), None);
}

/// SR-92: `--work` writes `work` and `devTools` on and keeps every other setting; an install without it
/// removes neither, and a `false` already there is turned on.
#[test]
fn work_writes_work_and_dev_tools_and_a_later_install_keeps_them() {
    let world = Fixture::new("work").with_runtime(r#"{"kept":true}"#);
    let path = world.runtime.join("config.json");
    let mut config = world.config();
    config["work"] = json!(false);
    config["devTools"] = json!(false);
    config["siteLock"] = json!("exclusive");
    std::fs::write(&path, config.to_string()).unwrap();
    world.run(&world.argv(&["--work"])).unwrap();
    let written = world.config();
    assert_eq!(written["work"], json!(true));
    assert_eq!(written["devTools"], json!(true));
    assert_eq!(written["retained"], json!({"kept": true}));
    assert_eq!(written["siteLock"], json!("exclusive"));
    assert_eq!(written["profileDirectory"], json!("Default"));
    assert_eq!(written["userDataDir"], config["userDataDir"]);
    world.run(&world.argv(&[])).unwrap();
    let later = world.config();
    assert_eq!(
        (&later["work"], &later["devTools"]),
        (&json!(true), &json!(true)),
        "a later install keeps them"
    );
}

#[test]
fn sign_in_providers_are_added_replaced_and_removed_and_a_bad_list_is_never_written() {
    let world = Fixture::new("providers").with_runtime("1");
    let read = |key: &str| world.config().get(key).cloned();
    let legacy = json!([NODE, "legacy.mjs"]);
    world.run(&world.argv(&["--sign-in-provider", &legacy.to_string()])).unwrap();
    // The first list edit makes the legacy provider the list's `default`.
    let script = if cfg!(windows) { r"C:\tools\fixture.mjs" } else { "/opt/tools/fixture.mjs" };
    let sha = "a".repeat(64);
    let fixture = json!({
        "name": "fixture",
        "command": [NODE, script],
        "caps": ["lookup", "totp", "create"],
        "pin": { NODE: sha, script: sha },
        "sites": ["https://login.site.test"],
    });
    world
        .run(&world.argv(&["--add-sign-in-provider", &fixture.to_string(), "--sign-in-save-to", "fixture"]))
        .unwrap();
    assert_eq!(read("signInProvider"), None, "moved into the list");
    assert_eq!(read("signInProviders"), Some(json!([{ "command": legacy, "name": "default" }, fixture])),);
    assert_eq!(read("signInSaveTo"), Some(json!("fixture")));
    world.run(&world.argv(&[])).unwrap();
    assert_eq!(read("signInSaveTo"), Some(json!("fixture")), "a later install keeps the list");
    // The old flag now sets the list's default.
    let other = json!([NODE, "other.mjs"]);
    world.run(&world.argv(&["--sign-in-provider", &other.to_string()])).unwrap();
    assert_eq!(read("signInProviders").unwrap()[0], json!({ "name": "default", "command": other }));
    // Refused, and nothing written: an unknown key, a bad name, caps without a pin, a duplicate
    // bitwarden, saveTo a provider without create, removing one that is not there.
    let before = world.config();
    let bad_entries = [
        json!({ "name": "x", "command": [NODE], "extra": 1 }),
        json!({ "name": "Not Ok", "command": [NODE] }),
        json!({ "name": "x", "command": [NODE], "caps": ["lookup"] }),
        json!({ "name": "x", "command": ["node"] }),
        json!({ "name": "x", "command": [NODE], "sites": ["http://plain.test"] }),
    ];
    for bad in bad_entries {
        assert!(world.run(&world.argv(&["--add-sign-in-provider", &bad.to_string()])).is_err(), "{bad}");
    }
    let bw = |name: &str| json!({ "name": name, "source": "bitwarden" }).to_string();
    world.run(&world.argv(&["--add-sign-in-provider", &bw("bw")])).unwrap();
    assert!(world.run(&world.argv(&["--add-sign-in-provider", &bw("bw2")])).is_err(), "two bitwardens");
    assert!(world.run(&world.argv(&["--sign-in-save-to", "default"])).is_err(), "default cannot create");
    assert!(world.run(&world.argv(&["--remove-sign-in-provider", "nobody"])).is_err());
    world.run(&world.argv(&["--remove-sign-in-provider", "bw"])).unwrap();
    assert_eq!(world.config(), before, "a refused flag changes nothing");
    // Removing the save target removes signInSaveTo; removing the last entry removes the list.
    world.run(&world.argv(&["--remove-sign-in-provider", "fixture"])).unwrap();
    assert_eq!(read("signInSaveTo"), None);
    world.run(&world.argv(&["--sign-in-provider", "[]"])).unwrap();
    assert_eq!(read("signInProviders"), None);
    assert_eq!(read("signInProvider"), None);
}

#[cfg(windows)]
#[test]
fn native_host_registration_restores_on_uninstall() {
    let world = Fixture::new("host").with_runtime("1");
    world.keys.set_host(r"C:\earlier\host.json");
    world.run(&world.argv(&[])).unwrap();
    let manifest_path = world.runtime.join("native-host.json");
    assert_eq!(world.keys.host_value().as_deref(), Some(manifest_path.display().to_string().as_str()));
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(
        manifest,
        json!({
            "name": "dev.phantab.bridge",
            "description": "phantab bridge native host",
            "path": world.binary(),
            "type": "stdio",
            "allowed_origins": [format!("chrome-extension://{}/", phantab::install::EXTENSION_ID)],
        })
    );
    assert_eq!(files(&world.runtime.join("extension")), files(&world.extension));
    world.run(&world.argv(&[])).unwrap();
    let record = world.record();
    assert_eq!(record["native-host"]["original"], r"C:\earlier\host.json");
    assert_eq!(record["native-host"]["location"], world.keys.host());
    world.run(&world.argv(&["--uninstall"])).unwrap();
    assert_eq!(world.keys.host_value().as_deref(), Some(r"C:\earlier\host.json"));
}

#[cfg(windows)]
#[test]
fn uninstall_removes_a_host_registration_it_created() {
    let world = Fixture::new("host-new").with_runtime("1");
    world.run(&world.argv(&[])).unwrap();
    assert!(world.keys.host_value().is_some());
    world.run(&world.argv(&["--uninstall"])).unwrap();
    assert!(!world.keys.host_key_exists());
}

#[cfg(windows)]
#[test]
fn uninstall_preserves_a_changed_native_host_registration() {
    let world = Fixture::new("host-changed").with_runtime("1");
    world.run(&world.argv(&[])).unwrap();
    let installed = std::fs::read(&world.target).unwrap();
    world.keys.set_host(r"C:\someone-else.json");
    let error = world.run(&world.argv(&["--uninstall"])).unwrap_err();
    assert!(error.to_string().contains("Native host registration changed"), "{error:#}");
    assert_eq!(std::fs::read(&world.target).unwrap(), installed);
    assert_eq!(world.keys.host_value().as_deref(), Some(r"C:\someone-else.json"));
}

#[test]
fn uninstall_preserves_a_changed_entry() {
    let world = Fixture::new("entry-changed").with_runtime("1");
    world.run(&world.argv(&[])).unwrap();
    let edited =
        std::fs::read_to_string(&world.target).unwrap().replace("args = [\"mcp\"]", "args = [\"other\"]");
    std::fs::write(&world.target, &edited).unwrap();
    let error = world.run(&world.argv(&["--uninstall"])).unwrap_err();
    assert!(format!("{error:#}").contains("Registration changed since install"), "{error:#}");
    assert_eq!(std::fs::read_to_string(&world.target).unwrap(), edited);
}

#[test]
fn invalid_second_config_does_not_mutate_first() {
    let world = Fixture::new("second").with_runtime("1");
    let second = world.root.join("bad.json");
    std::fs::write(&second, "{broken").unwrap();
    let before = world.files();
    let mut argv = world.argv(&[]);
    argv.extend(["--claude-config".to_owned(), second.display().to_string()]);
    assert!(world.run(&argv).is_err());
    assert_eq!(world.files(), before);
}

#[test]
fn refuses_missing_or_repeated_client_configs() {
    let world = Fixture::new("targets").with_runtime("1");
    let before = world.files();
    assert!(world.run(&world.base()).is_err(), "no client");
    let mut twice = world.argv(&[]);
    twice.extend(["--codex-config".to_owned(), world.target.display().to_string()]);
    assert!(world.run(&twice).is_err(), "the same file twice");
    let mut missing = world.base();
    missing.extend(["--claude-config".to_owned(), world.root.join("absent.json").display().to_string()]);
    assert!(world.run(&missing).is_err(), "a missing file");
    assert_eq!(world.files(), before);
}

#[test]
fn claude_install_keeps_neighbours_and_uninstall_removes_the_entry() {
    let world = Fixture::new("claude").with_runtime("1");
    let claude = world.root.join(".claude.json");
    let original =
        r#"{"projects":{"C:/Project":1,"c:/project":2},"mcpServers":{"other":{"command":"keep"}}}"#;
    std::fs::write(&claude, original).unwrap();
    let mut argv = world.base();
    argv.extend(["--claude-config".to_owned(), claude.display().to_string()]);
    world.run(&argv).unwrap();
    let once = std::fs::read(&claude).unwrap();
    let data: Value = serde_json::from_slice(&once).unwrap();
    assert_eq!(data["projects"], json!({"C:/Project": 1, "c:/project": 2}));
    assert_eq!(data["mcpServers"]["other"], json!({"command": "keep"}));
    assert_eq!(
        data["mcpServers"]["phantab"],
        json!({"command": world.binary(), "args": ["mcp"], "type": "stdio"})
    );
    world.run(&argv).unwrap();
    assert_eq!(std::fs::read(&claude).unwrap(), once);
    argv.push("--uninstall".to_owned());
    world.run(&argv).unwrap();
    let after: Value = serde_json::from_slice(&std::fs::read(&claude).unwrap()).unwrap();
    assert_eq!(after, serde_json::from_str::<Value>(original).unwrap());
}

/// `--server-name my-browser` takes over an existing entry of that name (another tool's) in place, and
/// uninstall puts that entry back.
#[test]
fn server_name_replaces_an_existing_entry_in_place() {
    let world = Fixture::new("swap").with_runtime("1");
    let codex = "model = \"x\"\n\
                 [mcp_servers.other]\n\
                 command = \"keep\"\n\
                 [mcp_servers.my-browser]\n\
                 command = 'C:\\tools\\node.exe'\n\
                 args = ['C:\\tools\\mcp.mjs']\n\
                 [mcp_servers.my-browser.env]\n\
                 OLD_TOOL_RUNTIME = 'C:\\old'\n\
                 [projects.\"elsewhere\"]\n\
                 trust_level = \"trusted\"\n";
    std::fs::write(&world.target, codex).unwrap();
    let claude = world.root.join(".claude.json");
    let claude_text = r#"{"mcpServers":{"my-browser":{"command":"C:/tools/node.exe","args":["C:/tools/mcp.mjs"],"env":{"OLD_TOOL_RUNTIME":"C:/old"}},"other":{"command":"keep"}},"theme":"dark"}"#;
    std::fs::write(&claude, claude_text).unwrap();
    let mut argv = world.argv(&["--server-name", "my-browser"]);
    argv.extend(["--claude-config".to_owned(), claude.display().to_string()]);
    let output = world.run(&argv).unwrap();
    assert!(output.contains("Registered my-browser in 2 selected clients"), "{output}");

    let binary = json!(world.binary());
    let text = std::fs::read_to_string(&world.target).unwrap();
    let swapped: toml::Table = text.parse().unwrap();
    let entry = &swapped["mcp_servers"]["my-browser"];
    assert_eq!(entry.get("env"), None, "the old entry's env goes with it");
    assert_eq!(entry["command"].as_str(), binary.as_str());
    let parts: Vec<&str> = entry["args"].as_array().unwrap().iter().filter_map(toml::Value::as_str).collect();
    assert_eq!(parts, ["mcp", "--server-name", "my-browser"]);
    assert_eq!(swapped["mcp_servers"]["other"]["command"].as_str(), Some("keep"));
    assert_eq!(swapped["projects"]["elsewhere"]["trust_level"].as_str(), Some("trusted"));
    assert!(text.find("my-browser").unwrap() < text.find("[projects").unwrap(), "in place:\n{text}");
    let data: Value = serde_json::from_slice(&std::fs::read(&claude).unwrap()).unwrap();
    let names: Vec<&String> = data["mcpServers"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["my-browser", "other"], "in place");
    assert_eq!(
        data["mcpServers"]["my-browser"],
        json!({"command": binary, "args": ["mcp", "--server-name", "my-browser"], "type": "stdio"})
    );
    for entry in world.record().as_object().unwrap().values().filter(|e| e.get("serverName").is_some()) {
        assert_eq!(entry["serverName"], "my-browser");
    }

    // A rerun without the flag keeps the recorded name; another name is refused.
    let mut rerun = world.argv(&[]);
    rerun.extend(["--claude-config".to_owned(), claude.display().to_string()]);
    world.run(&rerun).unwrap();
    assert_eq!(std::fs::read_to_string(&world.target).unwrap(), text);
    let mut other = world.argv(&["--server-name", "phantab"]);
    other.extend(["--claude-config".to_owned(), claude.display().to_string()]);
    assert!(world.run(&other).is_err());

    // Rollback: uninstall (no name needed) restores the old entry.
    world.run_as(&rerun, true).unwrap();
    assert_eq!(std::fs::read_to_string(&world.target).unwrap(), codex);
    let restored: Value = serde_json::from_slice(&std::fs::read(&claude).unwrap()).unwrap();
    assert_eq!(restored, serde_json::from_str::<Value>(claude_text).unwrap());
}

#[test]
fn first_install_needs_a_binding() {
    let world = Fixture::new("binding");
    let mut argv = world.argv(&["--user-data-dir"]);
    argv.extend([
        world.browser.display().to_string(),
        "--chrome".to_owned(),
        world.chrome.display().to_string(),
    ]);
    let error = world.run(&argv).unwrap_err().to_string();
    assert!(error.contains("First install needs --profile"), "{error}");
    assert!(error.contains("Profiles in") && error.contains("Default"), "{error}");
    argv.extend(words(&["--profile", r"..\Default"]));
    let error = world.run(&argv).unwrap_err().to_string();
    assert!(error.contains("directly inside the user-data directory"), "{error}");
    assert!(!world.runtime.join("config.json").exists());
}

#[test]
fn missing_or_foreign_extension_is_refused() {
    let world = Fixture::new("extension").with_runtime("1");
    let before = world.files();
    let empty = world.root.join("not built");
    std::fs::create_dir_all(&empty).unwrap();
    let mut argv = world.argv(&[]);
    let at = argv.iter().position(|w| w == "--extension-dir").unwrap();
    argv[at + 1] = empty.display().to_string();
    let error = world.run(&argv).unwrap_err().to_string();
    assert!(error.contains("The built extension was not found"), "{error}");
    std::fs::write(empty.join("manifest.json"), r#"{"key":"AAAA"}"#).unwrap();
    let error = world.run(&argv).unwrap_err().to_string();
    assert!(error.contains("is not the phantab bridge"), "{error}");
    let mut after = world.files();
    after.remove(&PathBuf::from("not built").join("manifest.json"));
    assert_eq!(after, before);
}

#[test]
fn installed_runtime_is_the_folder_above_bin() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("rt");
    let exe = runtime.join("bin").join("phantab.exe");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    assert_eq!(phantab::paths::installed_runtime(&exe), None, "no config.json yet");
    std::fs::write(runtime.join("config.json"), "{}").unwrap();
    assert_eq!(phantab::paths::installed_runtime(&exe).map(|p| plain(&p)), Some(plain(&runtime)));
    assert_eq!(phantab::paths::installed_runtime(&runtime.join("phantab.exe")), None, "not in bin");
}

#[test]
fn help_and_bad_flags() {
    let world = Fixture::new("help");
    assert!(world.run(&words(&["--help"])).unwrap().contains("Usage: phantab install"));
    let mut out = Vec::new();
    assert_eq!(phantab::install::run_with(&words(&["--bogus"]), false, &world.exe, &mut out).unwrap(), 2);
}

/// The real binary, end to end: a copy of it is installed and the entries run that copy, which then
/// uninstalls. This binary is a test-seams build, which refuses to install itself (SR-73, below), so the
/// install half runs through `run_with` with the binary named.
#[cfg(windows)]
#[test]
fn the_binary_installs_a_copy_of_itself() {
    let world = Fixture::new("binary").with_runtime("1");
    let bin = env!("CARGO_BIN_EXE_phantab");
    let mut out = Vec::new();
    assert_eq!(phantab::install::run_with(&world.argv(&[]), false, Path::new(bin), &mut out).unwrap(), 0);
    assert_eq!(std::fs::read(world.binary()).unwrap(), std::fs::read(bin).unwrap());
    let command = toml_of(&world.target)["mcp_servers"]["phantab"]["command"].as_str().map(PathBuf::from);
    assert_eq!(command, Some(world.binary()));
    let status =
        std::process::Command::new(world.binary()).arg("uninstall").args(world.argv(&[])).output().unwrap();
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    assert_eq!(toml_of(&world.target)["model"].as_str(), Some("unchanged"));
    assert!(toml_of(&world.target).get("mcp_servers").is_none());
}

/// SR-48, SR-50, SR-51, L1: install leaves the runtime and its `bin` owner-only, keeps a `0600` client
/// config `0600`, and replaces the extension folder whole, so a stale file is gone.
#[test]
fn install_locks_the_binary_folder_keeps_modes_and_replaces_the_extension_whole() {
    use phantab_window::secure_dir::inspect;
    let world = Fixture::new("whole").with_runtime("1");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&world.target, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    world.run(&world.argv(&[])).unwrap();
    for dir in [world.runtime.clone(), world.binary().parent().unwrap().to_path_buf()] {
        let found = inspect(&dir).unwrap();
        assert!(found.owned_by_me && found.owner_only && found.protected, "{}: {found:?}", dir.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&world.target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let installed = world.runtime.join("extension");
    std::fs::write(installed.join("stale.js"), "from an older version").unwrap();
    world.run(&world.argv(&[])).unwrap();
    assert!(!installed.join("stale.js").exists());
    assert_eq!(files(&installed), files(&world.extension));
}

/// SR-53, L1: `doctor`'s drift check is quiet after install and names a changed binary, manifest and
/// registration; after uninstall it checks nothing.
#[test]
fn drift_names_a_changed_binary_manifest_and_registration() {
    let world = Fixture::new("drift").with_runtime("1");
    world.run(&world.argv(&[])).unwrap();
    let drift = || phantab::install::drift(&world.runtime).unwrap();
    assert_eq!(drift(), Vec::<String>::new());
    assert_eq!(world.record()["binary"]["path"], json!(world.binary()));

    std::fs::write(world.binary(), b"tampered").unwrap();
    let found = drift();
    assert!(found.len() == 1 && found[0].contains("SHA-256"), "{found:?}");
    world.run(&world.argv(&[])).unwrap();
    assert_eq!(drift(), Vec::<String>::new(), "a re-install puts the recorded binary back");

    #[cfg(windows)]
    let manifest = world.runtime.join("native-host.json");
    #[cfg(not(windows))]
    let manifest = world.browser.join("NativeMessagingHosts").join("dev.phantab.bridge.json");
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(&manifest, text.replace("chrome-extension://", "chrome-extension://x")).unwrap();
    let found = drift();
    assert!(found.iter().any(|l| l.contains("admits an origin other")), "{found:?}");
    #[cfg(windows)]
    {
        world.keys.set_host(r"C:\elsewhere\host.json");
        let found = drift();
        assert!(found.iter().any(|l| l.contains("registration") && l.contains("changed")), "{found:?}");
        assert!(found.iter().any(|l| l.contains("does not run the installed binary")), "{found:?}");
    }

    world.run(&world.argv(&[])).unwrap();
    assert_eq!(drift(), Vec::<String>::new());
    world.run(&world.argv(&["--uninstall"])).unwrap();
    assert!(world.record().get("binary").is_none());
    assert_eq!(drift(), Vec::<String>::new(), "nothing installed, nothing to check");
}

/// The words of the test-seams refusal that `scripts/release.sh` looks for in a release binary (SR-73).
const TEST_BUILD_NEEDLE: &str = "built with the test-seams feature";

/// SR-73, L1: a test-seams build (`cargo test` builds this binary with the feature) refuses to install
/// itself, and writes nothing. Uninstall still runs. The refusal's words are in this build's bytes and in
/// `scripts/release.sh`, whose gate refuses a release binary holding them.
#[test]
fn a_test_seams_build_refuses_to_install_itself() {
    let world = Fixture::new("seams").with_runtime("1");
    let before = world.files();
    let bin = env!("CARGO_BIN_EXE_phantab");
    let run = |verb: &str, extra: &[&str]| {
        std::process::Command::new(bin)
            .arg(verb)
            .args(world.argv(extra))
            .env_remove("PHANTAB_RUNTIME")
            .output()
            .unwrap()
    };
    for (verb, extra) in [("install", &[][..]), ("install", &["--quiet-debugging", "on"][..])] {
        let output = run(verb, extra);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{verb} {extra:?}: {stderr}");
        assert!(stderr.contains(TEST_BUILD_NEEDLE), "{stderr}");
        assert_eq!(world.files(), before, "a refused install writes nothing");
    }
    // Uninstall is not refused: with nothing recorded it stops at the missing recovery record.
    let stderr = String::from_utf8_lossy(&run("uninstall", &[]).stderr).into_owned();
    assert!(
        !stderr.contains(TEST_BUILD_NEEDLE) && stderr.contains("No registration recovery record"),
        "{stderr}"
    );

    let bytes = std::fs::read(bin).unwrap();
    assert!(bytes.windows(TEST_BUILD_NEEDLE.len()).any(|w| w == TEST_BUILD_NEEDLE.as_bytes()));
    let release = std::fs::read_to_string(repo().join("scripts").join("release.sh")).unwrap();
    assert!(
        release.contains(&format!("--exact '{TEST_BUILD_NEEDLE}'")),
        "release.sh gates on the same words"
    );
}

/// SR-56, L1: every action a workflow runs is named by its full commit, with its release in a comment. A
/// tag (`@v4`) can be moved to other code, and the release workflow builds the files users install.
#[test]
fn workflows_name_every_action_by_its_commit() {
    let folder = repo().join(".github").join("workflows");
    let mut seen = 0;
    for entry in std::fs::read_dir(&folder).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((_, used)) = line.split_once("uses:") else { continue };
            let at = format!("{}:{}: {line}", path.display(), number + 1);
            let (action, note) =
                used.trim().split_once(" # ").unwrap_or_else(|| panic!("no release named: {at}"));
            let (name, commit) = action.split_once('@').unwrap_or_else(|| panic!("no commit: {at}"));
            assert!(name.split('/').count() >= 2 && !name.starts_with('.'), "not a published action: {at}");
            assert!(
                commit.len() == 40
                    && commit.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "pinned by something that can move, not a commit: {at}"
            );
            assert!(
                note.starts_with('v') && note[1..].split('.').count() == 3,
                "the comment names the exact release: {at}"
            );
            seen += 1;
        }
    }
    assert!(seen > 0, "no workflow uses an action; has the folder moved?");
}

/// A program's trimmed stdout, when it runs and exits 0.
fn stdout_of(program: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// A POSIX bash for the release and check scripts' own functions, and node when `node` (release.sh's
/// gate runs path-gate.mjs; check.sh's step needs none). `None` skips the test, unless check.sh runs it:
/// it sets `PHANTAB_REQUIRE_SCRIPT_TESTS=1`, and then a missing one fails the test (review r2 R2-5), since
/// a skip reads as a pass. The bash tried first is `PHANTAB_SCRIPT_BASH` (check.sh names the bash running
/// it); then, on Windows, Git for Windows' (`git --exec-path` is `<git>/mingw64/libexec/git-core`, or
/// the usual install folder); then `bash` on PATH. On Windows only an MSYS or Cygwin bash counts:
/// `System32\bash.exe` is WSL, which cannot run them here.
fn script_bash(what: &str, node: bool) -> Option<PathBuf> {
    let usable = |bash: &PathBuf| {
        stdout_of(bash, &["-c", "uname -s"]).is_some_and(|os| {
            !cfg!(windows) || ["MINGW", "MSYS", "CYGWIN"].iter().any(|unix| os.starts_with(unix))
        })
    };
    let mut candidates: Vec<PathBuf> =
        std::env::var_os("PHANTAB_SCRIPT_BASH").map(PathBuf::from).into_iter().collect();
    if cfg!(windows) {
        if let Some(exec) = stdout_of(Path::new("git"), &["--exec-path"]) {
            candidates
                .push(PathBuf::from(exec).join("..").join("..").join("..").join("bin").join("bash.exe"));
        }
        if let Some(programs) = std::env::var_os("ProgramFiles") {
            candidates.push(PathBuf::from(programs).join("Git").join("bin").join("bash.exe"));
        }
    }
    candidates.push(PathBuf::from("bash"));
    let bash = candidates.into_iter().find(usable);
    let has_node = !node || stdout_of(Path::new("node"), &["--version"]).is_some();
    if bash.is_some() && has_node {
        return bash;
    }
    let missing = if bash.is_none() { "a bash that runs the scripts" } else { "node" };
    let required = std::env::var_os("PHANTAB_REQUIRE_SCRIPT_TESTS").is_some_and(|v| v == "1");
    assert!(!required, "PHANTAB_REQUIRE_SCRIPT_TESTS=1, but there is no {missing} to run {what}");
    eprintln!("skipped: no {missing} to run {what}");
    None
}

/// Runs `script` in `bash` from the repo with these functions of `scripts/<file>` defined (each copied
/// out by `sed`, so the test runs the script's own text), and `args` as `$1`...; (exit code, all output).
fn script_functions(
    bash: &Path,
    file: &str,
    functions: &[&str],
    script: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> (Option<i32>, String) {
    // A function from its `name() {` line to its closing `}` line, or one written on a single line.
    let picks: Vec<String> =
        functions.iter().map(|f| format!("-e '/^{f}() {{$/,/^}}$/p' -e '/^{f}() {{.*}}$/p'")).collect();
    let full = format!("eval \"$(sed -n {} scripts/{file})\"\n{script}", picks.join(" "));
    let output = std::process::Command::new(bash)
        .current_dir(repo())
        .arg("-c")
        .arg(&full)
        .arg("gate-test")
        .args(args)
        .envs(env.iter().copied())
        .output()
        .unwrap();
    let text =
        format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    (output.status.code(), text)
}

/// SR-73 (review F6), L1: release.sh's test-build gate, run from the script's own text, refuses this
/// test build's binary, passes a file without the words, and fails (does not pass) on one it cannot read.
#[test]
fn the_release_test_build_gate_refuses_a_test_build() {
    let Some(bash) = script_bash("scripts/release.sh's test-build gate", true) else { return };
    let gate = |file: &str| {
        script_functions(
            &bash,
            "release.sh",
            &["die", "native_path", "test_build_gate"],
            "test_build_gate \"$1\"",
            &[file],
            &[],
        )
    };
    let (code, text) = gate(env!("CARGO_BIN_EXE_phantab"));
    assert!(code == Some(1) && text.contains("is a test-seams build"), "{code:?}: {text}");
    let dir = tempfile::tempdir().unwrap();
    let clean = dir.path().join("phantab");
    std::fs::write(&clean, b"a release binary has no test overrides").unwrap();
    let (code, text) = gate(clean.to_str().unwrap());
    assert_eq!(code, Some(0), "{text}");
    let (code, text) = gate(dir.path().join("missing").to_str().unwrap());
    assert!(code == Some(1) && text.contains("could not check"), "{code:?}: {text}");
}

/// SR-73 (review F6), L1: check.sh's `release_features_check`, run from the script's own text against
/// a stand-in `cargo tree`, passes a tree without test-seams and fails one that turns it on, one with no
/// phantab root, and a `cargo tree` that fails.
#[test]
fn the_check_release_features_step_fails_when_test_seams_is_on() {
    let Some(bash) = script_bash("scripts/check.sh's release_features_check", false) else { return };
    let script = concat!(
        "set -euo pipefail\n",
        "cargo() { [ \"$FAKE_RC\" = 0 ] || return \"$FAKE_RC\"; printf '%s\\n' \"$FAKE_TREE\"; }\n",
        "release_features_check",
    );
    let step = |tree: &str, rc: &str| {
        script_functions(
            &bash,
            "check.sh",
            &["release_features_check"],
            script,
            &[],
            &[("FAKE_TREE", tree), ("FAKE_RC", rc)],
        )
    };
    let root = "phantab v0.1.0 (/src/crates/phantab) [default]";
    let (code, text) = step(&format!("{root}\n|-- anyhow v1.0.0 [default,std]"), "0");
    assert_eq!(code, Some(0), "{text}");
    let (code, text) = step("phantab v0.1.0 (/src/crates/phantab) [default,test-seams]", "0");
    assert!(code == Some(1) && text.contains("turns test-seams on"), "{code:?}: {text}");
    let (code, text) = step(&format!("{root}\n|-- phantab-testkit v0.1.0 [test-seams]"), "0");
    assert!(code == Some(1) && text.contains("turns test-seams on"), "{code:?}: {text}");
    let (code, text) = step("anyhow v1.0.0 [default,std]", "0");
    assert!(code == Some(1) && text.contains("named no phantab root"), "{code:?}: {text}");
    let (code, text) = step(root, "101");
    assert!(code == Some(1) && text.contains("cargo tree failed"), "{code:?}: {text}");
}

/// SR-74, L1: install records each installed extension file's SHA-256 beside the folder. `doctor` names a
/// changed file, a missing record and an `installedSource` that is not the installed binary. The installed
/// binary reinstalling from the folder itself refuses a changed file and writes nothing; an install from
/// the release's extension puts the folder and the record right.
#[test]
fn install_records_the_extension_files_and_doctor_names_a_changed_one() {
    let world = Fixture::new("files").with_runtime("1");
    world.run(&world.argv(&[])).unwrap();
    let installed = world.runtime.join("extension");
    let record_path = world.runtime.join("extension-files.json");
    let record: Value = serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    let sha = |bytes: &[u8]| phantab::util::hex(&<sha2::Sha256 as sha2::Digest>::digest(bytes));
    let manifest = std::fs::read(world.extension.join("manifest.json")).unwrap();
    assert_eq!(
        record,
        json!({ "sha256": { "icons/icon.txt": sha(b"icon"), "manifest.json": sha(&manifest) } })
    );
    let drift = || phantab::install::drift(&world.runtime).unwrap();
    assert_eq!(drift(), Vec::<String>::new());

    std::fs::write(installed.join("icons").join("icon.txt"), "swapped").unwrap();
    let found = drift();
    assert!(
        found.len() == 1 && found[0].contains(r#"files changed since install: "icons/icon.txt"."#),
        "{found:?}"
    );

    // The installed binary, with no --extension-dir, finds the installed folder itself.
    let mut own = world.argv(&[]);
    let at = own.iter().position(|w| w == "--extension-dir").unwrap();
    own.drain(at..at + 2);
    let reinstall = |argv: &[String]| {
        let mut out = Vec::new();
        phantab::install::run_with(argv, false, &world.binary(), &mut out).map(|_| ())
    };
    let before = world.files();
    let error = reinstall(&own).unwrap_err().to_string();
    assert!(
        error.contains(r#"changed since install ("icons/icon.txt")"#) && error.contains("--extension-dir"),
        "{error}"
    );
    assert_eq!(world.files(), before, "the refusal writes nothing");
    // Review r4 R4-6: a planted name reaches doctor and install escaped, never as a line of its own.
    let planted = plant_a_newline(&installed);
    let found = drift();
    let error = reinstall(&own).unwrap_err().to_string();
    let shown = shown_and_removed(&installed, &planted);
    assert!(
        found.len() == 1
            && found[0].contains(&shown)
            && !found[0].contains(['\n', '\u{e0049}', '\u{2028}', '\u{180e}']),
        "{found:?}"
    );
    assert!(
        error.contains(&shown) && !error.contains(['\n', '\u{e0049}', '\u{2028}', '\u{180e}']),
        "{error}"
    );

    world.run(&world.argv(&[])).unwrap();
    assert_eq!(std::fs::read(installed.join("icons").join("icon.txt")).unwrap(), b"icon");
    assert_eq!(drift(), Vec::<String>::new(), "the release's extension is back, and recorded");
    reinstall(&own).unwrap();
    assert_eq!(drift(), Vec::<String>::new(), "an intact folder reinstalls from itself");

    // Review F1: config.json says a record was written, so deleting it is refused, not re-recorded.
    assert_eq!(world.config()["extensionFilesRecorded"], json!(true));
    std::fs::remove_file(&record_path).unwrap();
    let found = drift();
    assert!(found.len() == 1 && found[0].contains("is missing, so the bridge is refused"), "{found:?}");
    let before = world.files();
    let error = reinstall(&own).unwrap_err().to_string();
    assert!(error.contains("is missing") && error.contains("--extension-dir"), "{error}");
    assert_eq!(world.files(), before, "the refusal writes nothing");
    std::fs::write(&record_path, "{}").unwrap();
    let found = drift();
    assert!(found.len() == 1 && found[0].contains("cannot be read"), "{found:?}");
    assert!(reinstall(&own).unwrap_err().to_string().contains("cannot be read"));

    // An install from before SR-74: no marker and no record. Doctor says so; reinstalling from the folder
    // records it as it is, and sets the marker.
    std::fs::remove_file(&record_path).unwrap();
    let mut config = world.config();
    config.as_object_mut().unwrap().remove("extensionFilesRecorded");
    std::fs::write(world.runtime.join("config.json"), config.to_string()).unwrap();
    let found = drift();
    assert!(found.len() == 1 && found[0].contains("no record of its files"), "{found:?}");
    reinstall(&own).unwrap();
    assert_eq!(drift(), Vec::<String>::new(), "a folder with no record is recorded as it is");
    assert_eq!(world.config()["extensionFilesRecorded"], json!(true));

    let mut config = world.config();
    config["installedSource"] = json!(world.root.join("elsewhere").join("phantab.exe"));
    std::fs::write(world.runtime.join("config.json"), config.to_string()).unwrap();
    let found = drift();
    assert!(
        found.len() == 1 && found[0].contains("as installedSource, not the installed binary"),
        "{found:?}"
    );
    config.as_object_mut().unwrap().remove("installedSource");
    std::fs::write(world.runtime.join("config.json"), config.to_string()).unwrap();
    let found = drift();
    assert!(found.len() == 1 && found[0].contains("names nothing as installedSource"), "{found:?}");
}

/// Plants a name holding a newline in `ext` (review r4 R4-6): a file on macOS and Linux, a named stream
/// on Windows, which takes control characters in a stream name only. Returns how the check names it.
/// Review r5 R5-7: with a newline, a tag character (`I`, which an LLM reads), U+2028 and U+180E.
fn plant_a_newline(ext: &Path) -> String {
    let planted = "x\nThe bridge\u{e0049}\u{2028}\u{180e} is fine.html";
    if cfg!(windows) {
        let mut stream = ext.join("manifest.json").into_os_string();
        stream.push(format!(":{planted}"));
        std::fs::write(&stream, b"<p>").unwrap();
        format!("manifest.json:{planted}")
    } else {
        std::fs::write(ext.join(planted), b"<p>").unwrap();
        planted.to_owned()
    }
}

/// The plant's name as an error shows it, and the plant gone (review r4 R4-6).
fn shown_and_removed(ext: &Path, name: &str) -> String {
    std::fs::remove_file(ext.join(name)).unwrap();
    let escaped = name
        .replace('\n', "\\n")
        .replace('\u{e0049}', r"\u{e0049}")
        .replace('\u{2028}', r"\u{2028}")
        .replace('\u{180e}', r"\u{180e}");
    format!("\"{escaped}\"")
}

/// SR-74 (review F2, F3, F5, r2 R2-1), L1: files the OS writes into the source are neither copied nor
/// recorded, so their later rewrite is not a refusal; install copies exactly what it records, and doctor
/// names a file planted beside them; a file install cannot record (too large, a name a record cannot
/// hold) refuses the install before its first write.
#[test]
fn install_skips_os_files_and_refuses_what_it_cannot_record_before_writing() {
    let world = Fixture::new("files-os").with_runtime("1");
    std::fs::write(world.extension.join(".DS_Store"), "finder").unwrap();
    std::fs::write(world.extension.join("icons").join("Thumbs.db"), "explorer").unwrap();
    world.run(&world.argv(&[])).unwrap();
    let installed = world.runtime.join("extension");
    let record: Value =
        serde_json::from_slice(&std::fs::read(world.runtime.join("extension-files.json")).unwrap()).unwrap();
    let names: Vec<&String> = record["sha256"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["icons/icon.txt", "manifest.json"]);
    assert!(!installed.join(".DS_Store").exists() && !installed.join("icons").join("Thumbs.db").exists());
    assert!(!world.runtime.join("extension.phantab-stage").exists(), "the stage is removed");
    std::fs::write(installed.join(".DS_Store"), "rewritten by Finder").unwrap();
    std::fs::write(installed.join("icons").join("Thumbs.db"), "rewritten").unwrap();
    assert_eq!(phantab::install::drift(&world.runtime).unwrap(), Vec::<String>::new());
    std::fs::write(installed.join(".x.html"), "<script src=.x.js></script>").unwrap();
    let found = phantab::install::drift(&world.runtime).unwrap();
    assert!(found.len() == 1 && found[0].contains(r#"changed since install: ".x.html"."#), "{found:?}");
    std::fs::remove_file(installed.join(".x.html")).unwrap();

    let refused = |name: std::ffi::OsString, bytes: &[u8], why: &str| {
        let path = world.extension.join(&name);
        std::fs::write(&path, bytes).unwrap();
        let before = world.files();
        let error = format!("{:#}", world.run(&world.argv(&[])).unwrap_err());
        assert!(error.contains(why), "{name:?}: {error}");
        assert_eq!(world.files(), before, "{name:?}: the refusal writes nothing");
        std::fs::remove_file(&path).unwrap();
    };
    let big = vec![b'x'; 8 * 1024 * 1024 + 1];
    refused("big.js".into(), &big, "is larger than 8 MiB");
    #[cfg(unix)]
    refused("a:b.js".into(), b"x", "a name a record cannot hold");
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt as _;
        refused(std::ffi::OsString::from_wide(&[0xD800, u16::from(b'x')]), b"x", "not UTF-8");
    }
    world.run(&world.argv(&[])).unwrap();
}

/// SR-76, L1: `--add-profile` allows another profile by Chrome's name for it or its folder, writes it to
/// `otherProfiles` and installs its own recorded copy of the bridge with a `profile.json`; later installs
/// keep it, doctor checks it, and `--remove-profile` takes the copy and its record away. The usual profile,
/// an unknown one and a source that is itself a profile's copy are refused before any write.
#[test]
fn add_profile_installs_a_recorded_copy_and_remove_profile_takes_it_away() {
    let world = Fixture::new("profiles").with_runtime("1");
    for folder in ["Profile 1", "Profile 5"] {
        std::fs::create_dir_all(world.browser.join(folder)).unwrap();
        std::fs::write(world.browser.join(folder).join("Preferences"), "{}").unwrap();
    }
    let state = json!({ "profile": { "info_cache": {
        "Default": { "name": "Person 1" },
        "Profile 1": { "name": "Work" },
        "Profile 5": { "name": "Other" },
    } } });
    std::fs::write(world.browser.join("Local State"), state.to_string()).unwrap();
    let copy = |folder: &str| world.runtime.join("extension-profiles").join(folder).join("extension");
    let drift = || phantab::install::drift(&world.runtime).unwrap();

    let out = world.run(&world.argv(&["--all-profiles", "off", "--add-profile", "work"])).unwrap();
    assert_eq!(world.config()["otherProfiles"], json!(["Profile 1"]));
    assert_eq!(
        std::fs::read(copy("Profile 1").join("profile.json")).unwrap(),
        b"{\"profile\":\"Profile 1\"}\n"
    );
    assert_eq!(
        std::fs::read(copy("Profile 1").join("icons").join("icon.txt")).unwrap(),
        b"icon",
        "the same files as the usual copy"
    );
    let record: Value = serde_json::from_slice(
        &std::fs::read(
            world.runtime.join("extension-profiles").join("Profile 1").join("extension-files.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let names: Vec<&String> = record["sha256"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["icons/icon.txt", "manifest.json", "profile.json"]);
    assert!(
        out.contains("in Chrome profile Work (Profile 1) open chrome://extensions")
            && out.contains(&copy("Profile 1").display().to_string()),
        "{out}"
    );
    let restart = "The allowed Chrome profiles changed: restart only the phantab service";
    assert!(out.contains(restart), "a running service read the list at its start: {out}");
    assert_eq!(drift(), Vec::<String>::new());

    // A later install keeps the profile, and rewrites its copy.
    std::fs::write(copy("Profile 1").join("icons").join("icon.txt"), "swapped").unwrap();
    let found = drift();
    assert!(
        found.len() == 1
            && found[0].contains(
                r#"Profile 1 copy of the extension's files changed since install: "icons/icon.txt"."#
            ),
        "{found:?}"
    );
    let out = world.run(&world.argv(&[])).unwrap();
    assert_eq!(world.config()["otherProfiles"], json!(["Profile 1"]));
    assert!(out.contains("Work (Profile 1)") && !out.contains(restart), "the list is unchanged: {out}");
    assert_eq!(drift(), Vec::<String>::new());
    // Doctor reads the list as the service does: the usual folder and a repeat name no copy of their own.
    let config_path = world.runtime.join("config.json");
    let kept = std::fs::read(&config_path).unwrap();
    let mut config = world.config();
    config["otherProfiles"] = json!(["Profile 1", "Default", "Profile 1"]);
    std::fs::write(&config_path, config.to_string()).unwrap();
    assert_eq!(drift(), Vec::<String>::new());
    std::fs::write(&config_path, kept).unwrap();

    let before = world.files();
    for (arg, needle) in [
        ("Default", "is the usual Chrome profile"),
        ("Person 1", "is the usual Chrome profile"),
        ("Nobody", "Unknown Chrome profile Nobody"),
        ("../x", "Unknown Chrome profile"),
    ] {
        let error = world.run(&world.argv(&["--add-profile", arg])).unwrap_err().to_string();
        assert!(error.contains(needle), "{arg}: {error}");
    }
    let error = world.run(&world.argv(&["--remove-profile", "Other"])).unwrap_err().to_string();
    assert!(
        error.contains("--remove-profile: Unknown Chrome profile Other. Allowed: Work (Profile 1)."),
        "{error}"
    );
    std::fs::write(world.extension.join("profile.json"), "{\"profile\":\"Profile 5\"}").unwrap();
    let error = world.run(&world.argv(&[])).unwrap_err().to_string();
    assert!(error.contains("so it is a profile's copy of the bridge"), "{error}");
    std::fs::remove_file(world.extension.join("profile.json")).unwrap();
    assert_eq!(world.files(), before, "the refusals write nothing");

    // The owner loaded Work's copy, so leaving Work says to remove it there (SR-76's stray copy).
    world.loads_bridge("Profile 1", &copy("Profile 1"));
    let out = world.run(&world.argv(&["--add-profile", "Profile 5", "--remove-profile", "Work"])).unwrap();
    assert_eq!(world.config()["otherProfiles"], json!(["Profile 5"]));
    assert!(!world.runtime.join("extension-profiles").join("Profile 1").exists(), "copy and record removed");
    assert!(copy("Profile 5").join("profile.json").is_file());
    assert!(out.contains("in Chrome profile Work (Profile 1) remove the phantab bridge"), "{out}");
    assert!(out.contains(restart), "{out}");

    world.run(&world.argv(&["--remove-profile", "other"])).unwrap();
    assert_eq!(world.config().get("otherProfiles"), None, "an empty list is no key");
    assert!(!world.runtime.join("extension-profiles").join("Profile 5").exists());
    assert_eq!(drift(), Vec::<String>::new());
}

/// SR-76, `--all-profiles on` (the default): every profile folder but the usual one is allowed, and an
/// install from before it (an `otherProfiles` list, no `allProfiles` key) turns it on. `--remove-profile`
/// leaves one out (`excludeProfiles`), `--add-profile` takes it back, a new profile joins at the next
/// install, and `--all-profiles off` keeps the list as it stands. Guest and System profiles never join.
/// The owner is told to load a copy only where the bridge is not loaded yet, to reload it where it is,
/// and to remove it only from a profile left out that had loaded it.
#[test]
fn every_profile_is_allowed_by_default_but_those_left_out() {
    let world = Fixture::new("allprofiles").with_runtime("1");
    for folder in ["Profile 1", "Profile 5", "Guest Profile", "System Profile"] {
        std::fs::create_dir_all(world.browser.join(folder)).unwrap();
        std::fs::write(world.browser.join(folder).join("Preferences"), "{}").unwrap();
    }
    let state = json!({ "profile": { "info_cache": {
        "Default": { "name": "Person 1" },
        "Profile 1": { "name": "Remi" },
        "Profile 5": { "name": "Barry" },
    } } });
    std::fs::write(world.browser.join("Local State"), state.to_string()).unwrap();
    let copy = |folder: &str| world.runtime.join("extension-profiles").join(folder).join("extension");
    let new_profile = |folder: &str| {
        std::fs::create_dir_all(world.browser.join(folder)).unwrap();
        std::fs::write(world.browser.join(folder).join("Preferences"), "{}").unwrap();
    };
    let restart = "The allowed Chrome profiles changed: restart only the phantab service";
    let load =
        |label: &str| format!("in Chrome profile {label} open chrome://extensions, turn on Developer mode");
    let leave = |label: &str| format!("in Chrome profile {label} remove the phantab bridge");

    // An install from #35's named-only days, with Remi named and loaded: the next install turns on.
    let config_path = world.runtime.join("config.json");
    let mut config = world.config();
    config["otherProfiles"] = json!(["Profile 1"]);
    std::fs::write(&config_path, config.to_string()).unwrap();
    world.loads_bridge("Profile 1", &copy("Profile 1"));
    let out = world.run(&world.argv(&[])).unwrap();
    assert_eq!(world.config()["otherProfiles"], json!(["Profile 1", "Profile 5"]));
    assert_eq!(world.config().get("allProfiles"), None, "on is the default, no key");
    assert_eq!(world.config().get("excludeProfiles"), None);
    assert!(
        copy("Profile 1").join("profile.json").is_file() && copy("Profile 5").join("profile.json").is_file()
    );
    assert!(
        out.contains(
            "Other Chrome profiles agents may use: Remi (Profile 1), Barry (Profile 5) (every profile but the usual one; a new one joins at the next phantab install)."
        ),
        "{out}"
    );
    assert!(
        out.contains("in Chrome profile Remi (Profile 1) click the phantab bridge's reload button"),
        "Remi loaded it already: {out}"
    );
    assert!(!out.contains(&load("Remi (Profile 1)")), "{out}");
    assert!(
        out.contains(&load("Barry (Profile 5)")) && out.contains(&copy("Profile 5").display().to_string()),
        "{out}"
    );
    assert!(out.contains(restart), "{out}");

    // Leaving out Barry, who never loaded it, needs no removal there.
    let out = world.run(&world.argv(&["--remove-profile", "Barry"])).unwrap();
    assert_eq!(world.config()["otherProfiles"], json!(["Profile 1"]));
    assert_eq!(world.config()["excludeProfiles"], json!(["Profile 5"]));
    assert!(!world.runtime.join("extension-profiles").join("Profile 5").exists());
    assert!(
        out.contains("Remi (Profile 1) (every profile but the usual one; left out: Barry (Profile 5);"),
        "{out}"
    );
    assert!(!out.contains(&leave("Barry (Profile 5)")) && out.contains(restart), "{out}");

    new_profile("Profile 7");
    let out = world.run(&world.argv(&[])).unwrap();
    assert_eq!(
        world.config()["otherProfiles"],
        json!(["Profile 1", "Profile 7"]),
        "a new profile joins, Barry stays out"
    );
    assert!(out.contains(&load("Profile 7")), "{out}");

    // Leaving out Remi, who loaded it, says to remove it there.
    let out = world.run(&world.argv(&["--remove-profile", "remi", "--add-profile", "Barry"])).unwrap();
    assert_eq!(world.config()["otherProfiles"], json!(["Profile 5", "Profile 7"]));
    assert_eq!(world.config()["excludeProfiles"], json!(["Profile 1"]));
    assert!(out.contains(&leave("Remi (Profile 1)")), "{out}");
    world.run(&world.argv(&["--add-profile", "Profile 1"])).unwrap();
    assert_eq!(world.config()["otherProfiles"], json!(["Profile 1", "Profile 5", "Profile 7"]));
    assert_eq!(world.config().get("excludeProfiles"), None, "an empty leave-out list is no key");

    let out = world.run(&world.argv(&["--all-profiles", "off"])).unwrap();
    assert_eq!(world.config()["allProfiles"], json!(false));
    assert!(out.contains("(only those named with --add-profile)") && !out.contains(restart), "{out}");
    new_profile("Profile 8");
    world.run(&world.argv(&[])).unwrap();
    assert_eq!(
        world.config()["otherProfiles"],
        json!(["Profile 1", "Profile 5", "Profile 7"]),
        "off: no pick-up"
    );
    world.run(&world.argv(&["--all-profiles", "on"])).unwrap();
    assert_eq!(world.config()["otherProfiles"], json!(["Profile 1", "Profile 5", "Profile 7", "Profile 8"]));
    assert_eq!(world.config().get("allProfiles"), None);

    let before = world.files();
    for (args, needle) in [
        (
            ["--remove-profile", "Person 1"],
            "--remove-profile: Person 1 is the usual Chrome profile (Default)",
        ),
        (["--add-profile", "Default"], "--add-profile: Default is the usual Chrome profile (Default)"),
        (["--remove-profile", "Guest Profile"], "--remove-profile: Unknown Chrome profile Guest Profile"),
        (["--remove-profile", "Nobody"], "--remove-profile: Unknown Chrome profile Nobody"),
    ] {
        let error = world.run(&world.argv(&args)).unwrap_err().to_string();
        assert!(error.contains(needle), "{args:?}: {error}");
    }
    assert_eq!(world.files(), before, "the refusals write nothing");
    assert_eq!(phantab::install::drift(&world.runtime).unwrap(), Vec::<String>::new());
}
