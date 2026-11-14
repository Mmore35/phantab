//! `phantab install` / `phantab uninstall`: register phantab in the selected MCP clients, and undo it.
//!
//! Changes only the client config files named on the command line, and in them only the one MCP entry;
//! refuses when anything else in a file would change meaning, or when a file changed while it ran. Every
//! check runs before the first write. What it replaced goes in the runtime's recovery record
//! (`registration-v2.json`), and uninstall puts exactly that back, refusing when the entry changed since.
//!
//! The runtime gets a copy of this binary, which the entries and the native host run; `--server-name`
//! names the entry; the quiet-debugging edit goes through phantab-window; Windows and macOS.

mod args;
mod claude;
mod codex;
pub(crate) mod discover;
mod drift;
mod fsops;
mod host;
mod quiet;

use std::io::{BufRead, IsTerminal as _, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use serde_json::{Map, Value, json};
use sha2::Digest as _;

use crate::extension_files::{self, Verdict};
use crate::paths;
pub use drift::drift;

/// The MCP entry's name when `--server-name` gives none.
pub const DEFAULT_SERVER_NAME: &str = "phantab";
/// The extension ID Chrome derives from the bridge's manifest key; the native host admits only this origin.
pub const EXTENSION_ID: &str = include_str!("../../../../extension/extension-id.txt").trim_ascii();

const RECORD: &str = "registration-v2.json";
const HOST_RECORD: &str = "native-host";
/// The installed binary's path and SHA-256, for `doctor` (SR-53). Removed by uninstall.
const BINARY_RECORD: &str = "binary";
pub(crate) const CONFIG: &str = "config.json";
pub(crate) const QUIET_MARKER: &str = "quiet-debugging.on";
/// The owner answered no to the quiet-debugging question, so later installs neither ask nor change it.
pub(crate) const QUIET_OFF_MARKER: &str = "quiet-debugging.off";
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Codex,
    Claude,
}

#[derive(Debug, Clone)]
pub(crate) struct Target {
    /// Resolved, as the recovery record keys it.
    pub path: PathBuf,
    pub kind: Kind,
}

impl Target {
    fn key(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

/// `phantab install …` (`uninstall` for `phantab uninstall …`). Returns the exit code.
///
/// At a terminal, an install that has no answer about quiet debugging yet asks it.
pub fn run(words: &[String], uninstall: bool) -> Result<i32> {
    let exe = std::env::current_exe().context("Could not locate the running phantab binary")?;
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let terminal: Option<&mut dyn BufRead> =
        if stdin.is_terminal() && std::io::stdout().is_terminal() { Some(&mut lock) } else { None };
    run_as(words, uninstall, &exe, &mut std::io::stdout().lock(), true, terminal)
}

/// [`run`] with the binary to install and the output named, for tests. It installs `exe` whatever it
/// was built with: the test-build refusal (SR-73) is about the running binary, which [`run`] installs.
/// No terminal: nothing is asked.
pub fn run_with(words: &[String], uninstall: bool, exe: &Path, out: &mut dyn Write) -> Result<i32> {
    run_as(words, uninstall, exe, out, false, None)
}

/// [`run_with`] at a terminal that types `terminal`, for tests of the quiet-debugging question.
pub fn run_at_terminal(
    words: &[String],
    uninstall: bool,
    exe: &Path,
    out: &mut dyn Write,
    terminal: &mut dyn BufRead,
) -> Result<i32> {
    run_as(words, uninstall, exe, out, false, Some(terminal))
}

fn run_as(
    words: &[String],
    uninstall: bool,
    exe: &Path,
    out: &mut dyn Write,
    running: bool,
    terminal: Option<&mut dyn BufRead>,
) -> Result<i32> {
    let mut args = match args::parse(words) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("phantab: {message}\n\n{}", args::USAGE);
            return Ok(2);
        }
    };
    if args.help {
        out.write_all(args::USAGE.as_bytes())?;
        return Ok(0);
    }
    args.uninstall |= uninstall;
    if running {
        refuse_a_test_build(&args)?;
    }
    execute(&args, exe, out, terminal)?;
    Ok(0)
}

/// SR-73: a binary built with the `test-seams` feature (every `cargo test` build of this crate, through
/// the self dev-dependency, so also `target/debug/phantab` after a test run) never installs itself. Its
/// sign-in timings, loopback sign-in and `PHANTAB_TEST_*` pass-through are test overrides. Uninstall still
/// runs. The text is compiled into test builds only: `scripts/release.sh` refuses a binary holding it.
#[cfg(feature = "test-seams")]
fn refuse_a_test_build(args: &args::Args) -> Result<()> {
    if args.uninstall {
        return Ok(());
    }
    bail!(
        "This phantab binary was built with the test-seams feature (a cargo test build), whose test \
         overrides must never run as the installed phantab. Install a release build, or one from cargo \
         build without --features test-seams."
    )
}

#[cfg(not(feature = "test-seams"))]
#[allow(clippy::unnecessary_wraps, reason = "the test-seams build's version refuses")]
fn refuse_a_test_build(_args: &args::Args) -> Result<()> {
    Ok(())
}

/// What an install writes besides the client configs, all decided before the first write.
struct Prepared {
    /// The running binary, read once: these bytes are hashed for the record and copied to `bin`, so the
    /// recorded SHA-256 is the installed file's even if the source changes during the install (SR-53).
    binary: Vec<u8>,
    /// `config.json` as install first writes it: an [`extension_files::MARKER`] it already had is kept,
    /// none is added.
    config_bytes: Vec<u8>,
    /// `config.json` with the marker, written last, once the record is written and the folder checked
    /// against it, so a failed install never leaves the marker without a record (SR-74).
    recorded_config_bytes: Vec<u8>,
    user_data_dir: PathBuf,
    extension: PathBuf,
    /// SR-74: the source's files, their bytes and hashes, read before the first write. Install writes
    /// exactly these bytes and records exactly these hashes.
    files: extension_files::Files,
    /// SR-76: `otherProfiles` after this install, each of which gets its own copy of the bridge.
    other_profiles: Vec<Other>,
    /// Profiles this install stopped allowing, whose copies it removes.
    removed_profiles: Vec<Other>,
    /// Whether `otherProfiles` changed. A running service read the list at its start (SR-76).
    profiles_changed: bool,
}

/// One of `otherProfiles`: its folder, and Chrome's name for it when it has one.
#[derive(Debug, Clone)]
struct Other {
    folder: String,
    name: Option<String>,
}

impl Other {
    fn label(&self) -> String {
        match &self.name {
            Some(name) => format!("{name} ({})", self.folder),
            None => self.folder.clone(),
        }
    }
}

/// One client config's planned write.
struct Change {
    path: PathBuf,
    original: Vec<u8>,
    rendered: Vec<u8>,
}

fn execute(
    args: &args::Args,
    exe: &Path,
    out: &mut dyn Write,
    terminal: Option<&mut dyn BufRead>,
) -> Result<()> {
    if !cfg!(any(windows, target_os = "macos")) {
        bail!("phantab install supports Windows and macOS only.");
    }
    let runtime = fsops::resolve(&args.runtime.clone().unwrap_or_else(paths::runtime_dir));
    let places = args.quiet_places();
    // With no client named, `--quiet-debugging` changes only that, on the installed runtime.
    if let Some(on) = args.quiet_debugging
        && !args.uninstall
        && args.codex_configs.is_empty()
        && args.claude_configs.is_empty()
    {
        return quiet::set(&runtime, on, &places, out);
    }
    let targets = targets(args)?;
    let record_path = runtime.join(RECORD);
    let mut record = load_object(&record_path)?.unwrap_or_default();
    let name = server_name(args, &record, &targets)?;
    let binary = runtime.join("bin").join(format!("phantab{}", std::env::consts::EXE_SUFFIX));
    let binary_text = binary.to_string_lossy().into_owned();
    let prepared = if args.uninstall { None } else { Some(prepare(args, exe, &runtime, &binary_text)?) };
    // Chrome on Windows starts the host through `cmd.exe /d /c "<path>" …`, where these break the quoting.
    if cfg!(windows) && prepared.is_some() && binary_text.contains(['%', '"', '\r', '\n']) {
        bail!("Path cannot be written safely for Chrome's native-host launch: {binary_text}");
    }

    let manifest_path = runtime.join("native-host.json");
    let manifest = host_manifest(&binary_text)?;
    let host_saved = record.get(HOST_RECORD).cloned();
    // An uninstall with nothing recorded for the host leaves the host alone and never looks at it.
    let site = if args.uninstall && host_saved.is_none() {
        None
    } else {
        Some(host_site(args, host_saved.as_ref(), prepared.as_ref())?)
    };
    let registered = site.as_ref().map(host::Site::read).transpose()?.flatten();
    let host_value = site.as_ref().map(|s| s.value(&manifest_path, &manifest)).unwrap_or_default();
    if args.uninstall {
        if let Some(saved) = &host_saved
            && registered.clone().map_or(Value::Null, Value::String) != saved["installed"]
        {
            bail!("Native host registration changed since install; preserving it.");
        }
        record.remove(BINARY_RECORD);
    } else {
        let location = site.as_ref().map(host::Site::location);
        let entry = record
            .entry(HOST_RECORD)
            .or_insert_with(|| json!({ "original": registered, "location": location }));
        let entry = entry.as_object_mut().with_context(|| damaged(&record_path))?;
        entry.insert("installed".to_owned(), Value::String(host_value.clone()));
        // Not an uninstall, so `prepared` is there: hash the bytes `write_runtime` will copy.
        if let Some(prepared) = &prepared {
            let sha256 = crate::util::hex(&sha2::Sha256::digest(&prepared.binary));
            record.insert(BINARY_RECORD.to_owned(), json!({ "path": binary_text, "sha256": sha256 }));
        }
    }

    let mcp_args = mcp_args(&name);
    let mut changes = Vec::new();
    for target in &targets {
        changes.push(
            plan(target, &name, args.uninstall, &mut record, &binary_text, &mcp_args)
                .with_context(|| format!("{}", target.path.display()))?,
        );
    }
    // Uninstall takes the flag off again, before any other write: a failed off then leaves everything,
    // the answer included, as it was, so the next uninstall tries again. The answer goes only once it is off.
    let quiet_off = if args.uninstall && quiet::answered(&runtime) == Some(true) {
        let browser = quiet::browser_of(&runtime)?;
        Some(quiet::apply(false, browser, &places).context(
            "Quiet debugging could not be turned off, so nothing was uninstalled; run phantab uninstall again",
        )?)
    } else {
        None
    };

    // Everything is checked; write. The recovery record first, so a failure later can still be undone.
    // R15: lock_down creates a missing runtime owner-only in the create call, never open first.
    fsops::lock_down(&runtime)?;
    fsops::atomic(&record_path, &pretty(&Value::Object(record))?, None)?;
    if let Some(prepared) = &prepared {
        write_runtime(prepared, &runtime, exe, &binary)?;
    }
    for change in &changes {
        fsops::atomic(&change.path, &change.rendered, Some(&change.original))?;
    }
    if args.uninstall {
        if let (Some(saved), Some(site)) = (&host_saved, &site) {
            site.write(saved["original"].as_str())?;
        }
        quiet::remove_markers(&runtime)?;
        if let Some(state) = &quiet_off {
            quiet::report(false, state, out)?;
        }
    } else {
        if cfg!(windows) {
            fsops::atomic(&manifest_path, manifest.as_bytes(), None)?;
        }
        if let Some(site) = &site
            && registered.as_deref() != Some(host_value.as_str())
        {
            site.write(Some(&host_value))?;
        }
    }
    report(out, &name, targets.len(), &runtime, prepared.as_ref())?;
    if !args.uninstall {
        install_quiet(args, &runtime, &places, out, terminal)?;
    }
    Ok(())
}

/// After an install: `--quiet-debugging`, else the owner's earlier answer (on is applied again, as the
/// install may have changed the browser), else the question at a terminal, else how to turn it on.
fn install_quiet(
    args: &args::Args,
    runtime: &Path,
    places: &quiet::Places,
    out: &mut dyn Write,
    terminal: Option<&mut dyn BufRead>,
) -> Result<()> {
    let on = match (args.quiet_debugging, quiet::answered(runtime), terminal) {
        (Some(on), _, _) | (None, Some(on @ true), _) => on,
        (None, Some(false), _) => return Ok(()),
        (None, None, Some(terminal)) => quiet::ask(terminal, out)?,
        (None, None, None) => {
            writeln!(
                out,
                "Chrome's debugging bar shows on agent pages. To hide it, run phantab install \
                 --quiet-debugging on; every extension that uses Chrome's debugger then attaches silently."
            )?;
            return Ok(());
        }
    };
    quiet::set(runtime, on, places, out)
}

fn report(
    out: &mut dyn Write,
    name: &str,
    count: usize,
    runtime: &Path,
    prepared: Option<&Prepared>,
) -> Result<()> {
    let verb = if prepared.is_none() { "Removed" } else { "Registered" };
    writeln!(out, "{verb} {name} in {count} selected clients; browser not restarted.")?;
    let Some(prepared) = prepared else { return Ok(()) };
    writeln!(
        out,
        "Owner step, once per update: in the usual Chrome profile open chrome://extensions, turn on Developer \
         mode and Load unpacked {}; if it is already loaded, click its reload button.",
        runtime.join("extension").display()
    )?;
    for other in &prepared.other_profiles {
        writeln!(
            out,
            "Owner step, once per update: in Chrome profile {} open chrome://extensions, turn on Developer mode \
             and Load unpacked {} (its own copy of the bridge, not the usual one); if it is already loaded, \
             click its reload button.",
            other.label(),
            paths::profile_extension_dir_in(runtime, &other.folder).display()
        )?;
    }
    for other in &prepared.removed_profiles {
        writeln!(
            out,
            "Owner step: in Chrome profile {} remove the phantab bridge at chrome://extensions. Until then the \
             bridge is refused in every profile, as a copy in a profile phantab does not allow is.",
            other.label()
        )?;
    }
    if prepared.profiles_changed {
        writeln!(
            out,
            "The allowed Chrome profiles changed: restart only the phantab service, once its pages are drained, \
             so it reads them; never close Chrome. Until then it allows the profiles it started with."
        )?;
    }
    Ok(())
}

fn targets(args: &args::Args) -> Result<Vec<Target>> {
    let refusal = || anyhow!("Select distinct existing client config files explicitly.");
    let targets: Vec<Target> = (args.codex_configs.iter().map(|p| (p, Kind::Codex)))
        .chain(args.claude_configs.iter().map(|p| (p, Kind::Claude)))
        .map(|(path, kind)| Target { path: fsops::resolve(path), kind })
        .collect();
    if targets.is_empty() || targets.iter().any(|t| !t.path.is_file()) {
        return Err(refusal());
    }
    for (i, a) in targets.iter().enumerate() {
        if targets[i + 1..].iter().any(|b| fsops::same_path(&a.path, &b.path)) {
            return Err(refusal());
        }
    }
    Ok(targets)
}

/// `--server-name`; else the name this runtime registered in these files before; else `phantab`.
fn server_name(args: &args::Args, record: &Map<String, Value>, targets: &[Target]) -> Result<String> {
    let recorded =
        |t: &Target| record.get(&t.key()).and_then(|e| e.get("serverName")).and_then(Value::as_str);
    let name = if let Some(name) = &args.server_name {
        name.clone()
    } else {
        let mut names: Vec<&str> = targets.iter().filter_map(recorded).collect();
        names.sort_unstable();
        names.dedup();
        match names.as_slice() {
            [] => DEFAULT_SERVER_NAME.to_owned(),
            [one] => (*one).to_owned(),
            many => bail!(
                "The selected clients were registered under different names ({}); pass --server-name.",
                many.join(", ")
            ),
        }
    };
    let valid = name.len() <= 64
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        bail!("--server-name takes 1 to 64 letters, digits, '-' or '_', starting with a letter or digit.");
    }
    for target in targets {
        if let Some(old) = recorded(target)
            && old != name
        {
            bail!(
                "{} has {old} registered from this runtime; uninstall that first, or pass --server-name {old}.",
                target.path.display()
            );
        }
    }
    Ok(name)
}

/// The arguments the client entries run the binary with.
fn mcp_args(name: &str) -> Vec<String> {
    let mut args = vec!["mcp".to_owned()];
    if name != DEFAULT_SERVER_NAME {
        args.extend(["--server-name".to_owned(), name.to_owned()]);
    }
    args
}

/// `--sign-in-provider <JSON array>`: sets the config's provider command, or removes it for `[]`.
fn set_sign_in_provider(config: &mut Map<String, Value>, raw: &str) -> Result<()> {
    let command = serde_json::from_str::<Vec<String>>(raw)
        .ok()
        .filter(|parts| parts.iter().all(|p| !p.is_empty()))
        .context("--sign-in-provider takes a JSON array of command parts.")?;
    if let Some(program) = command.first()
        && !crate::signin::program_is_absolute(program)
    {
        // sec-creds-8: the service refuses a bare name, so a config with one would never sign in.
        bail!("--sign-in-provider: the program ({program}) must be an absolute path, never a name on PATH.");
    }
    if command.is_empty() {
        config.retain(|key, _| key != "signInProvider");
    } else {
        config.insert("signInProvider".to_owned(), json!({ "command": command }));
    }
    Ok(())
}

/// Install only: the runtime's config and the extension to copy.
fn prepare(args: &args::Args, exe: &Path, runtime: &Path, binary: &str) -> Result<Prepared> {
    let existing = load_object(&runtime.join(CONFIG))?;
    let recorded = existing
        .as_ref()
        .is_some_and(|config| config.get(extension_files::MARKER) == Some(&Value::Bool(true)));
    let mut config = existing.unwrap_or_default();
    let path_text = |p: &PathBuf| Value::String(fsops::resolve(p).to_string_lossy().into_owned());
    if let Some(profile) = &args.profile {
        config.insert("profileDirectory".to_owned(), Value::String(profile.clone()));
    }
    if let Some(dir) = &args.user_data_dir {
        config.insert("userDataDir".to_owned(), path_text(dir));
    }
    if let Some(chrome) = &args.chrome {
        config.insert("chromeExecutable".to_owned(), path_text(chrome));
    }
    if text(&config, "chromeExecutable").is_none()
        && let Some(found) = discover::chrome()
    {
        config.insert("chromeExecutable".to_owned(), path_text(&found));
    }
    if text(&config, "userDataDir").is_none()
        && let Some(found) = discover::user_data_dir()
    {
        config.insert("userDataDir".to_owned(), path_text(&found));
    }
    let user_data_dir = check_binding(&config)?;
    let (other_profiles, removed_profiles, changed) = other_profiles(args, &mut config, &user_data_dir)?;
    config.insert("installedSource".to_owned(), Value::String(binary.to_owned()));
    if let Some(raw) = &args.sign_in_provider {
        set_sign_in_provider(&mut config, raw)?;
    }
    let binary = std::fs::read(exe).with_context(|| format!("Could not read {}", exe.display()))?;
    let extension = extension_source(args.extension_dir.as_deref(), exe)?;
    // SR-74: the installed binary reinstalling from the installed folder itself (no --extension-dir) copies
    // nothing and records what is there, so a swapped file there must not be recorded as installed, nor
    // one whose record was deleted after an install wrote it (the marker says so).
    if fsops::same_path(&extension, &fsops::resolve(&runtime.join("extension"))) {
        match extension_files::check(&extension) {
            Verdict::Unrecorded if recorded => bail!(
                "The record of the installed extension's files ({}) is missing. Install from the release's \
                 extension instead: pass --extension-dir <its extension folder>.",
                extension_files::record_path(&extension).display()
            ),
            Verdict::Unrecorded | Verdict::Intact => {}
            Verdict::Changed(files) => bail!(
                "The installed extension's files changed since install ({}). Install from the release's \
                 extension instead: pass --extension-dir <its extension folder>.",
                extension_files::listed(&files)
            ),
            Verdict::Refused(found) => bail!(
                "The installed extension's files are not the plain files install wrote ({}). Install from \
                 the release's extension instead: pass --extension-dir <its extension folder>.",
                extension_files::explained(&found)
            ),
            Verdict::Damaged => bail!(
                "The record of the installed extension's files ({}) cannot be read. Install from the \
                 release's extension instead: pass --extension-dir <its extension folder>.",
                extension_files::record_path(&extension).display()
            ),
            Verdict::Unverifiable(why) => bail!("The installed extension's files cannot be checked: {why}."),
        }
    }
    // SR-74: read and hashed from the source before the first write, so a file install cannot record (a
    // link, a name, a size) refuses the install with nothing changed. These bytes are what install writes.
    let files = extension_files::read(&extension)
        .with_context(|| format!("Could not record the extension's files in {}", extension.display()))?;
    refuse_profile_copy(&extension, &files)?;
    let config_bytes = pretty(&Value::Object(config.clone()))?;
    config.insert(extension_files::MARKER.to_owned(), Value::Bool(true));
    let recorded_config_bytes = pretty(&Value::Object(config))?;
    Ok(Prepared {
        binary,
        config_bytes,
        recorded_config_bytes,
        user_data_dir,
        extension,
        files,
        other_profiles,
        removed_profiles,
        profiles_changed: changed,
    })
}

/// SR-76: a `profile.json` is what makes a copy another profile's, so the usual bridge never has one.
fn refuse_profile_copy(extension: &Path, files: &extension_files::Files) -> Result<()> {
    if files.contents.contains_key(PROFILE_FILE) {
        bail!(
            "{} has a {PROFILE_FILE}, so it is a profile's copy of the bridge, not the built bridge. Install \
             from the release's extension: pass --extension-dir <its extension folder>.",
            extension.display()
        );
    }
    Ok(())
}

/// Keeps the first of each entry.
fn unique(list: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    list.retain(|f| seen.insert(f.clone()));
}

/// The file in a profile's copy of the bridge that names its profile (`{"profile": "<folder>"}`); the
/// extension reads it and says so in its hello (SR-76).
const PROFILE_FILE: &str = "profile.json";

/// `--add-profile` and `--remove-profile` applied to `config.json`'s `otherProfiles` (SR-76): profile
/// folders in `user_data_dir`, never the usual one. Returns the list after this install, the profiles it
/// stopped allowing, and whether the list changed. An entry that is now the usual profile (`--profile` moved there) is dropped too.
fn other_profiles(
    args: &args::Args,
    config: &mut Map<String, Value>,
    user_data_dir: &Path,
) -> Result<(Vec<Other>, Vec<Other>, bool)> {
    let usual = text(config, "profileDirectory").unwrap_or_default().to_owned();
    let before = config.get("otherProfiles").cloned();
    let mut list: Vec<String> = config
        .get("otherProfiles")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    let mut removed: Vec<String> = Vec::new();
    list.retain(|f| {
        let keep = *f != usual && paths::valid_profile_dir(f);
        if *f == usual && paths::valid_profile_dir(f) {
            removed.push(f.clone());
        }
        keep
    });
    unique(&mut list);
    let names = crate::bridge::profile_names(user_data_dir);
    for arg in &args.remove_profiles {
        let allowed: Vec<&str> = list.iter().map(String::as_str).collect();
        let folder = crate::bridge::resolve_profile(&names, &allowed, arg)
            .map_err(|e| anyhow!("--remove-profile: {e}"))?;
        list.retain(|f| *f != folder);
        removed.push(folder);
    }
    let found = discover::profiles(user_data_dir);
    for arg in &args.add_profiles {
        let mut candidates: Vec<&str> =
            found.iter().map(String::as_str).filter(|f| paths::valid_profile_dir(f)).collect();
        // The usual one too, so naming it says it is the usual one rather than unknown.
        if !candidates.contains(&usual.as_str()) {
            candidates.push(&usual);
        }
        let folder = crate::bridge::resolve_profile(&names, &candidates, arg)
            .map_err(|e| anyhow!("--add-profile: {e}"))?;
        if folder == usual {
            bail!("--add-profile: {arg} is the usual Chrome profile ({usual}), which agents reach already.");
        }
        if !list.contains(&folder) {
            list.push(folder.clone());
        }
        removed.retain(|f| *f != folder);
    }
    unique(&mut removed);
    if list.is_empty() {
        config.remove("otherProfiles");
    } else {
        config.insert("otherProfiles".to_owned(), json!(list));
    }
    let changed = config.get("otherProfiles") != before.as_ref();
    let other = |folder: String| {
        let name = names.iter().find(|(f, _)| *f == folder).map(|(_, n)| n.clone());
        Other { folder, name }
    };
    Ok((list.into_iter().map(other).collect(), removed.into_iter().map(other).collect(), changed))
}

fn text<'a>(config: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    config.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// The browser binding's checks; returns the user-data dir.
fn check_binding(config: &Map<String, Value>) -> Result<PathBuf> {
    let (Some(profile), Some(user_data_dir), Some(chrome)) =
        (text(config, "profileDirectory"), text(config, "userDataDir"), text(config, "chromeExecutable"))
    else {
        let mut message =
            "First install needs --profile, --user-data-dir and --chrome; later installs keep the values they find."
                .to_owned();
        if let Some(dir) = text(config, "userDataDir") {
            let found = discover::profiles(Path::new(dir));
            if !found.is_empty() {
                message = format!("{message} Profiles in {dir}: {}.", found.join(", "));
            }
        }
        bail!(message);
    };
    let user_data_dir = PathBuf::from(user_data_dir);
    let profile_dir = user_data_dir.join(profile);
    let single = {
        let mut parts = Path::new(profile).components();
        matches!((parts.next(), parts.next()), (Some(std::path::Component::Normal(_)), None))
    };
    let inside = fsops::resolve(&profile_dir)
        .parent()
        .is_some_and(|parent| fsops::same_path(parent, &fsops::resolve(&user_data_dir)));
    if !single || !inside || !profile_dir.join("Preferences").is_file() {
        bail!("Select an existing profile directly inside the user-data directory.");
    }
    if !Path::new(chrome).is_file() {
        bail!("Chrome executable does not exist.");
    }
    Ok(user_data_dir)
}

/// The built extension: `--extension-dir`; else `extension/` beside the binary (a release), or beside its
/// `bin` (the installed copy, which then copies nothing); else, in a debug build only, the source tree's
/// `extension/dist`. It must be the bridge whose key gives [`EXTENSION_ID`], or Chrome would give it an ID
/// the host refuses.
fn extension_source(explicit: Option<&Path>, exe: &Path) -> Result<PathBuf> {
    let candidates: Vec<PathBuf> = if let Some(dir) = explicit {
        vec![dir.to_path_buf()]
    } else {
        let mut found = Vec::new();
        if let Some(dir) = exe.parent() {
            found.push(dir.join("extension"));
            if dir.file_name().is_some_and(|n| n == "bin")
                && let Some(up) = dir.parent()
            {
                found.push(up.join("extension"));
            }
        }
        // Debug builds only: `env!` bakes the checkout's absolute path into the binary, and
        // --remap-path-prefix does not reach it, so a release would fail scripts/release.sh's path gate.
        #[cfg(debug_assertions)]
        found
            .push(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("extension").join("dist"));
        found
    };
    let Some(dir) = candidates.iter().find(|d| d.join("manifest.json").is_file()) else {
        let looked: Vec<String> = candidates.iter().map(|d| d.display().to_string()).collect();
        bail!(
            "The built extension was not found (looked in {}). Build it first (npm run build in extension/), \
             or pass --extension-dir.",
            looked.join(", ")
        );
    };
    let dir = fsops::resolve(dir);
    let id = extension_id(&dir.join("manifest.json"))?;
    if id != EXTENSION_ID {
        bail!(
            "{} is not the phantab bridge: its key gives extension ID {id}, not {EXTENSION_ID}.",
            dir.display()
        );
    }
    Ok(dir)
}

/// Chrome's ID for an unpacked extension with a manifest `key`: the SHA-256 of the decoded key, first 32
/// hex digits written with `a`-`p` for 0-f.
fn extension_id(manifest: &Path) -> Result<String> {
    let text = std::fs::read_to_string(manifest)
        .with_context(|| format!("Could not read {}", manifest.display()))?;
    let data: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("Could not read {}", manifest.display()))?;
    let key = data["key"].as_str().with_context(|| format!("{} has no key", manifest.display()))?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(key)
        .with_context(|| format!("{} has a key that is not base64", manifest.display()))?;
    let digest = sha2::Sha256::digest(&der);
    Ok(digest.iter().take(16).flat_map(|b| [b >> 4, b & 0xf]).map(|n| char::from(b'a' + n)).collect())
}

fn host_manifest(binary: &str) -> Result<String> {
    let manifest = json!({
        "name": paths::HOST_NAME,
        "description": "phantab bridge native host",
        "path": binary,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    });
    Ok(serde_json::to_string_pretty(&manifest)? + "\n")
}

/// Uninstall goes back to where install registered; an install must register where the record says.
fn host_site(args: &args::Args, saved: Option<&Value>, prepared: Option<&Prepared>) -> Result<host::Site> {
    let saved_location = saved.and_then(|s| s["location"].as_str());
    if args.uninstall
        && let Some(location) = saved_location
    {
        return host::Site::from_location(location);
    }
    let site = host::chosen(args.native_host_key.as_deref(), prepared.map(|p| p.user_data_dir.as_path()))?;
    if let Some(location) = saved_location
        && !host::Site::same(location, &site.location())
    {
        bail!(
            "This runtime registered its native host at {location}; uninstall first to register it at {}.",
            site.location()
        );
    }
    Ok(site)
}

/// One client config: the edit, its recovery record, and the checks before it.
fn plan(
    target: &Target,
    name: &str,
    uninstall: bool,
    record: &mut Map<String, Value>,
    command: &str,
    args: &[String],
) -> Result<Change> {
    let original = std::fs::read(&target.path).context("Could not read it")?;
    let (bom, body) = match original.strip_prefix(UTF8_BOM) {
        Some(rest) => (UTF8_BOM, rest),
        None => (&[][..], original.as_slice()),
    };
    let text = std::str::from_utf8(body).context("not UTF-8")?;
    let key = target.key();
    let saved = if uninstall {
        let saved = record.get(&key).filter(|v| v.is_object());
        Some(
            saved
                .ok_or_else(|| anyhow!("No registration recovery record: {}", target.path.display()))?
                .clone(),
        )
    } else {
        None
    };
    let changed = |previous: Option<Value>, installed: &Value| {
        if previous.unwrap_or(Value::Null) != *installed {
            bail!("Registration changed since install; preserving it: {}", target.path.display());
        }
        Ok(())
    };
    let updated = match target.kind {
        Kind::Codex => {
            let before = codex::parse(text)?;
            let previous = codex::entry(&before, name)?;
            let block = if let Some(saved) = &saved {
                changed(previous.as_ref().map(codex::to_json), &saved["installed"])?;
                saved["original"].as_str().unwrap_or_default().to_owned()
            } else {
                let old = codex::original(text, name);
                remember(
                    record,
                    &key,
                    old.map_or(Value::Null, Value::String),
                    codex::desired(command, args),
                    name,
                )?;
                codex::block(name, command, args)
            };
            let updated = codex::edit(text, name, &block);
            let after = codex::parse(&updated).context("the edit would not be valid TOML")?;
            if codex::without_entry(before, name)? != codex::without_entry(after.clone(), name)? {
                bail!("Unrelated configuration would change.");
            }
            (codex::entry(&after, name)? != previous).then_some(updated)
        }
        Kind::Claude => {
            let before = claude::parse(text)?;
            let previous = claude::entry(&before, name)?;
            let replacement = if let Some(saved) = &saved {
                changed(previous.clone(), &saved["installed"])?;
                Some(saved["original"].clone()).filter(|v| !v.is_null())
            } else {
                let desired = claude::desired(command, args);
                remember(record, &key, previous.clone().unwrap_or(Value::Null), desired.clone(), name)?;
                Some(desired)
            };
            let updated = claude::edit(text, &before, name, replacement.as_ref())?;
            let after = claude::parse(&updated)?;
            if claude::without_entry(before, name)? != claude::without_entry(after.clone(), name)? {
                bail!("Unrelated configuration would change.");
            }
            (claude::entry(&after, name)? != previous).then_some(updated)
        }
    };
    // The original bytes when the entry already holds what it should.
    let rendered = updated.map_or_else(|| original.clone(), |text| [bom, text.as_bytes()].concat());
    Ok(Change { path: target.path.clone(), original, rendered })
}

/// Records `desired` as the entry's `installed` value; the first install's
/// `original` is kept for good, so reinstalling never forgets what was there before phantab.
fn remember(
    record: &mut Map<String, Value>,
    key: &str,
    old: Value,
    desired: Value,
    name: &str,
) -> Result<()> {
    let entry = record
        .entry(key.to_owned())
        .or_insert_with(|| Value::Object(Map::from_iter([("original".to_owned(), old)])));
    let entry = entry.as_object_mut().context("its recovery record entry is damaged")?;
    entry.insert("installed".to_owned(), desired);
    entry.insert("serverName".to_owned(), Value::String(name.to_owned()));
    Ok(())
}

/// The runtime's own files, in order: config, then what the entries and Chrome start.
fn write_runtime(prepared: &Prepared, runtime: &Path, exe: &Path, binary: &Path) -> Result<()> {
    fsops::atomic(&runtime.join(CONFIG), &prepared.config_bytes, None)?;
    // SR-48: the binary's own folder is locked and checked like the runtime, as at service start. Before
    // the copy, so a new `bin` is created owner-only (R15) and the binary lands in a locked folder.
    if let Some(bin) = binary.parent() {
        fsops::lock_down(bin)?;
    }
    fsops::install_binary(exe, &prepared.binary, binary)?;
    let extension = runtime.join("extension");
    if !fsops::same_path(&prepared.extension, &fsops::resolve(&extension)) {
        // SR-74: only the files prepare read, from the bytes it hashed, so the installed folder holds
        // nothing the record does not name (Chrome serves any file there as an extension page). They are
        // staged, then swapped in whole by replace_tree, which copies the stage and nothing else. Both
        // write each file's bytes themselves (fsops::atomic), never with fs::copy or CopyFileEx, which
        // carry a file's named NTFS streams along: a source's Zone.Identifier, or a planted page, never
        // reaches the installed folder, where the check refuses any stream.
        let stage = runtime.join(STAGE);
        if let Err(e) = stage_files(&stage, &prepared.files) {
            let _ = remove_stage(&stage);
            return Err(e);
        }
        let replaced = fsops::replace_tree(&stage, &extension);
        let cleaned = remove_stage(&stage);
        replaced?;
        cleaned?;
    }
    record_and_verify(&extension, &prepared.files.sha256)?;
    // SR-76: each other profile's copy is the same files and its own profile.json, staged, swapped in and
    // recorded the same way (SR-74).
    for other in &prepared.other_profiles {
        let copy = paths::profile_extension_dir_in(runtime, &other.folder);
        let files = profile_copy(&prepared.files, &other.folder)?;
        let stage = copy.parent().unwrap_or(runtime).join(STAGE);
        if let Err(e) = stage_files(&stage, &files) {
            let _ = remove_stage(&stage);
            return Err(e);
        }
        let replaced = fsops::replace_tree(&stage, &copy);
        let cleaned = remove_stage(&stage);
        replaced?;
        cleaned?;
        record_and_verify(&copy, &files.sha256)?;
    }
    // A removed profile's copy goes with its record, so nothing of it is left to look installed.
    for other in &prepared.removed_profiles {
        let copy = paths::profile_extension_dir_in(runtime, &other.folder);
        remove_stage(copy.parent().unwrap_or(&copy))?;
    }
    // The marker last: a failed install leaves no marker without a record, which would refuse the bridge.
    fsops::atomic(&runtime.join(CONFIG), &prepared.recorded_config_bytes, None)
}

/// `files` with the [`PROFILE_FILE`] that makes them `folder`'s copy.
fn profile_copy(files: &extension_files::Files, folder: &str) -> Result<extension_files::Files> {
    let mut files = files.clone();
    let bytes = (serde_json::to_string(&json!({ "profile": folder }))? + "\n").into_bytes();
    files.sha256.insert(PROFILE_FILE.to_owned(), crate::util::hex(&sha2::Sha256::digest(&bytes)));
    files.contents.insert(PROFILE_FILE.to_owned(), bytes);
    Ok(files)
}

/// The folder install stages the extension's files in before it swaps them in (`<runtime>/<STAGE>`).
const STAGE: &str = "extension.phantab-stage";

/// Writes `files` into a fresh `stage`, each `/`-separated path as folders. A stage a failed install left
/// is removed first, never written into.
fn stage_files(stage: &Path, files: &extension_files::Files) -> Result<()> {
    remove_stage(stage)?;
    std::fs::create_dir_all(stage).with_context(|| format!("Could not create {}", stage.display()))?;
    for (rel, bytes) in &files.contents {
        let path = rel.split('/').fold(stage.to_path_buf(), |path, part| path.join(part));
        fsops::atomic(&path, bytes, None)?;
    }
    Ok(())
}

/// Removes a stage without following a link at its path (a Windows junction or folder link goes with
/// `remove_dir`, a file link with `remove_file`).
fn remove_stage(stage: &Path) -> Result<()> {
    let removed = match std::fs::symlink_metadata(stage) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::remove_file(stage).or_else(|_| std::fs::remove_dir(stage))
        }
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(stage),
        Ok(_) => std::fs::remove_file(stage),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    removed.with_context(|| format!("Could not remove {}", stage.display()))
}

/// SR-74: writes the record of the hashes prepare took before any write, for the profile check and
/// doctor, then checks the installed folder against it. A source that changed while install read it, or
/// a folder that gained a file, is not left looking installed: the record names what should be there, so
/// the bridge refuses until a reinstall.
fn record_and_verify(extension: &Path, sha256: &std::collections::BTreeMap<String, String>) -> Result<()> {
    let record = extension_files::record_path(extension);
    fsops::atomic(&record, &extension_files::render(sha256), None)?;
    match extension_files::check(extension) {
        Verdict::Intact => Ok(()),
        Verdict::Changed(files) => bail!(
            "The extension's files changed while install copied them ({}). Run phantab install again.",
            extension_files::listed(&files)
        ),
        Verdict::Refused(found) => bail!(
            "The extension's files are not the plain files install wrote ({}): something links, syncs, \
             mounts over or virtualizes the runtime folder. Run phantab install again once nothing does.",
            extension_files::explained(&found)
        ),
        Verdict::Unrecorded | Verdict::Damaged => {
            bail!("The record of the extension's files ({}) did not read back.", record.display())
        }
        // Review r8 R8-1: a runtime folder on a FUSE, FSKit or network file system is refused here, so
        // an install there never looks done.
        Verdict::Unverifiable(why) => bail!("The extension's files cannot be checked: {why}."),
    }
}

/// A JSON object file, `None` when it does not exist.
fn load_object(path: &Path) -> Result<Option<Map<String, Value>>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("Could not read {}", path.display())),
    };
    match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
        Ok(Value::Object(map)) => Ok(Some(map)),
        Ok(_) => bail!("{} is not a JSON object", path.display()),
        Err(e) => Err(e).with_context(|| format!("Could not read {}", path.display())),
    }
}

fn damaged(path: &Path) -> String {
    format!("{} is damaged", path.display())
}

fn pretty(value: &Value) -> Result<Vec<u8>> {
    Ok((serde_json::to_string_pretty(value)? + "\n").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_id_matches_the_checked_in_manifest() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extension/manifest.json");
        assert_eq!(extension_id(&manifest).unwrap(), EXTENSION_ID);
        assert_eq!(EXTENSION_ID.len(), 32);
    }

    /// SR-74 (review r2 R2-6), L1: the check after the copy refuses a folder that is not what prepare
    /// read, a changed file or an added one, and passes the one it read.
    #[test]
    fn the_check_after_the_copy_refuses_a_folder_that_is_not_what_prepare_read() {
        let dir = tempfile::tempdir().unwrap();
        let ext = dir.path().join("extension");
        std::fs::create_dir(&ext).unwrap();
        std::fs::write(ext.join("manifest.json"), b"{}").unwrap();
        std::fs::write(ext.join("background.js"), b"code").unwrap();
        let read = extension_files::read(&ext).unwrap();
        record_and_verify(&ext, &read.sha256).unwrap();
        std::fs::write(ext.join("background.js"), b"code, changed while copied").unwrap();
        let error = record_and_verify(&ext, &read.sha256).unwrap_err().to_string();
        assert!(error.contains(r#"changed while install copied them ("background.js")"#), "{error}");
        std::fs::write(ext.join("background.js"), b"code").unwrap();
        std::fs::write(ext.join("x.html"), b"page").unwrap();
        let error = record_and_verify(&ext, &read.sha256).unwrap_err().to_string();
        assert!(error.contains(r#"("x.html")"#), "{error}");
        std::fs::remove_file(ext.join("x.html")).unwrap();
        // Review r4 R4-6, r5 R5-7: a planted name is shown escaped, a newline, a tag character, U+2028 and
        // U+180E alike (Windows takes a newline in a stream name only).
        let planted = if cfg!(windows) {
            "background.js:x\n\u{e0049}\u{2028}\u{180e}ok.html"
        } else {
            "x\n\u{e0049}\u{2028}\u{180e}ok.html"
        };
        std::fs::write(ext.join(planted), b"page").unwrap();
        let error = record_and_verify(&ext, &read.sha256).unwrap_err().to_string();
        let shown = format!("(\"{}\")", planted.replace('\n', "\\n"))
            .replace("\u{e0049}\u{2028}\u{180e}", r"\u{e0049}\u{2028}\u{180e}");
        assert!(
            error.contains(&shown) && !error.contains(['\n', '\u{e0049}', '\u{2028}', '\u{180e}']),
            "{error}"
        );
    }

    /// SR-74 (review r2 R2-1), L1: the stage holds exactly the files prepare read, and a stage a failed
    /// install left, even a file at its path, is replaced rather than written into.
    #[test]
    fn the_stage_holds_only_what_prepare_read() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("icons")).unwrap();
        std::fs::write(src.join("manifest.json"), b"{}").unwrap();
        std::fs::write(src.join("icons").join("a.png"), b"png").unwrap();
        std::fs::write(src.join("Thumbs.db"), b"os").unwrap();
        let read = extension_files::read(&src).unwrap();
        let stage = dir.path().join(STAGE);
        std::fs::write(&stage, b"left over").unwrap();
        stage_files(&stage, &read).unwrap();
        assert_eq!(extension_files::read(&stage).unwrap(), read);
        assert!(!stage.join("Thumbs.db").exists());
        std::fs::write(stage.join("x.html"), b"left over").unwrap();
        stage_files(&stage, &read).unwrap();
        assert!(!stage.join("x.html").exists());
        remove_stage(&stage).unwrap();
        assert!(!stage.exists());
        remove_stage(&stage).unwrap();
    }

    /// SR-74 (review r2 R2-1b, r3 R3-7), L1: an install that fails before its record is written and
    /// checked leaves `config.json` without the marker, so the bridge never demands a record that is not
    /// there; the same install, unblocked, sets it last.
    #[test]
    fn a_failed_install_leaves_no_marker() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("manifest.json"), b"{}").unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        let exe = dir.path().join("phantab-built");
        // The file on disk changes after prepare read it: the install must use the bytes prepare read.
        std::fs::write(&exe, b"swapped after prepare").unwrap();
        let config = Map::from_iter([("browser".to_owned(), json!("chrome"))]);
        let mut recorded = config.clone();
        recorded.insert(extension_files::MARKER.to_owned(), Value::Bool(true));
        let prepared = Prepared {
            binary: b"read by prepare".to_vec(),
            config_bytes: pretty(&Value::Object(config)).unwrap(),
            recorded_config_bytes: pretty(&Value::Object(recorded)).unwrap(),
            user_data_dir: dir.path().join("user-data"),
            extension: src.clone(),
            files: extension_files::read(&src).unwrap(),
            other_profiles: Vec::new(),
            removed_profiles: Vec::new(),
            profiles_changed: false,
        };
        let binary = runtime.join("bin").join("phantab");
        // A folder where fsops::atomic writes the record's temp file (its `.phantab.tmp`), so the
        // record write fails after the config, the binary and the extension are written.
        let blocker = runtime.join(format!("{}.phantab.tmp", extension_files::RECORD));
        std::fs::create_dir(&blocker).unwrap();
        assert!(write_runtime(&prepared, &runtime, &exe, &binary).is_err());
        let written: Value = serde_json::from_slice(&std::fs::read(runtime.join(CONFIG)).unwrap()).unwrap();
        assert_eq!(written["browser"], "chrome", "the config was written");
        assert!(runtime.join("extension").join("manifest.json").exists(), "so was the extension");
        assert_eq!(std::fs::read(&binary).unwrap(), b"read by prepare", "SR-53: the bytes prepare read");
        assert_eq!(written.get(extension_files::MARKER), None, "but not the marker");
        std::fs::remove_dir(&blocker).unwrap();
        write_runtime(&prepared, &runtime, &exe, &binary).unwrap();
        let written: Value = serde_json::from_slice(&std::fs::read(runtime.join(CONFIG)).unwrap()).unwrap();
        assert_eq!(written[extension_files::MARKER], true);
        assert_eq!(extension_files::check(&runtime.join("extension")), Verdict::Intact);
    }

    #[test]
    fn mcp_args_name_only_a_non_default_server() {
        assert_eq!(mcp_args("phantab"), ["mcp"]);
        assert_eq!(mcp_args("my-browser"), ["mcp", "--server-name", "my-browser"]);
    }

    #[test]
    fn host_manifest_admits_only_the_bridge() {
        let manifest: Value =
            serde_json::from_str(&host_manifest(r"C:\rt\bin\phantab.exe").unwrap()).unwrap();
        assert_eq!(manifest["name"], "dev.phantab.bridge");
        assert_eq!(manifest["path"], r"C:\rt\bin\phantab.exe");
        assert_eq!(manifest["type"], "stdio");
        assert_eq!(manifest["allowed_origins"], json!([format!("chrome-extension://{EXTENSION_ID}/")]));
    }
}
