//! The `bw` a session key was made with (docs/BITWARDEN.md § Session storage; THREAT-MODEL SR-64):
//! `connect` records the configured command and the SHA-256 of each file in it that runs, and keeps the
//! record with the key in the protected store. A session key goes into a child's `BW_SESSION` only while
//! the configured command and those files are still the ones recorded ([`hold`], checked by `cli::run`
//! before every spawn that carries a key). Otherwise every call answers `locked` and
//! `phantab bitwarden status` tells the owner to run `phantab bitwarden connect` again (sec-creds-2).
//!
//! What runs must be what is hashed, so only two shapes are pinned ([`SHAPES`]) and anything else is
//! refused, never pinned in part:
//! - the standalone `bw` program, with no argument: its file is named `bw` (`bw.exe` on Windows), in any
//!   case (Windows names and macOS's default volume are not case-sensitive). Any other program alone
//!   would be given `bw`'s arguments (`status`, `unlock`), which an interpreter such as `node`, `sh` or
//!   `powershell` runs as code that is not hashed;
//! - `node` and the absolute path of one `.js` script, with nothing else: no Node option, since
//!   `--eval=`, `--require=` and `--env-file=` all run or load code that is not hashed.
//!
//! A launcher is refused, the same on every system: npm's (`bw`, `bw.cmd`, `bw.ps1`, or on macOS a link
//! to `bw.js`, a `#!` script, as npm and Homebrew make it), Scoop's shim (a native `bw.exe` that starts
//! the program its `bw.shim` names) and Chocolatey's (a native `bw.exe` its shimgen made, which says so
//! in its own text: [`chocolatey_target`]) and Volta's (a `node` that starts the node Volta picks: on
//! Windows a copy of `volta-shim.exe`, on macOS a link to `volta-shim`, judged as the file and not by
//! its folder: [`volta_shim`]). For those the refusal names the exact `bw` to set ([`install_hint`]). A
//! launcher of another kind is not known.
//!
//! The program must be a native one ([`NATIVE`]): on Windows a `.exe` (checked by the config, since
//! Windows would otherwise run `bw.exe` for a configured `bw`), on macOS a Mach-O, elsewhere an ELF. A
//! `#!` script would have its interpreter looked up on `PATH`, and a text file the kernel will not load is
//! run by `/bin/sh`. A folder (Node runs its package's main file) or a relative path (looked up from the
//! working folder) is refused. A link is followed, so the hash is of what runs.
//!
//! Each pinned file is hashed through a handle that stays open until the child it was checked for has
//! exited ([`Held`]), and the child is started by the file's resolved path, every link and junction on
//! the way followed: on Windows the path read back from that handle
//! ([`phantab_window::file_identity::HeldFile`]); on unix the configured path canonicalized, checked to
//! name the open file (its device and inode). There the handle shares reading only, so while it is
//! open no one can open the file for writing, rename or delete it, or rename a folder on its resolved
//! path; a link in the configured path can still be repointed, but the child does not go through it. Not
//! stopped: a writable mapping of the file made before it was opened, and same-user code in general
//! (THREAT-MODEL R16). Unix has no such lock, so there a writer that swaps or rewrites a file between the
//! check and the moment the system (or Node, for `bw.js`) opens it wins.
//!
//! What is not pinned: modules a script loads from elsewhere (`bw.js`'s `node_modules`), what a launcher
//! such as a Scoop shim starts, and the system's own libraries. It keeps the key from a `bw` other than the
//! one connected with (a changed `config.json`, an updated or replaced program). It is no boundary
//! against a same-user process that can already open the store (THREAT-MODEL R16).
//!
//! Hashing a standalone `bw` (about 100 MB) takes a fraction of a second, so each file's hash is kept for
//! the life of the process, keyed by its path and a stamp read from the open handle: size and
//! modification time, plus the inode, device and change time on unix (which no unprivileged writer can
//! set back), or on Windows the creation time, volume, file ID and update sequence number
//! (`phantab_window::file_identity`; the times alone can be set back). A file whose stamp changed while
//! it was read, or whose USN Windows cannot give, is not kept.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use phantab_window::file_identity::HeldFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::config::Config;
use super::vault::SessionKey;

/// What `signInProvider.bitwarden.bw` may be, for a refusal's text.
pub(crate) const SHAPES: &str = "set signInProvider.bitwarden.bw to the absolute path of the standalone bw \
                                 program itself (bw on macOS, bw.exe on Windows, as Bitwarden's download, \
                                 WinGet, Scoop and Chocolatey install it; not a launcher such as a Scoop or \
                                 Chocolatey shim), or, for the npm package (npm, and Homebrew on macOS), to \
                                 [\"<absolute path of node>\", \"<absolute path of \
                                 @bitwarden/cli/build/bw.js>\"] with nothing else (docs/BITWARDEN.md § \
                                 Installs)";

/// Chocolatey's launchers are made by its shimgen, whose every shim carries the help it prints for
/// `--shimgen-help` (a switch Chocolatey documents for all of them) as UTF-16 text. A shim is small (about
/// 400 KB); a larger file is not read again for it (the standalone `bw` is about 100 MB).
const SHIM_MAX: u64 = 8 << 20;

/// Volta's `volta-shim` is a few MB; a larger file beside a program is not read to compare with it.
const VOLTA_SHIM_MAX: u64 = 64 << 20;

/// Where the npm package keeps the script it runs, as a path ends.
const NPM_SCRIPT: &str = "node_modules/@bitwarden/cli/build/bw.js";

/// How a native program starts: what the system loads itself, never through a shell or an interpreter
/// the file names. Windows: `MZ`.
#[cfg(windows)]
pub(crate) const NATIVE: &[&[u8]] = &[b"MZ"];
/// How a native program starts: what the system loads itself, never through a shell or an interpreter
/// the file names. macOS: Mach-O, 32- and 64-bit in either byte order, and universal.
#[cfg(target_os = "macos")]
pub(crate) const NATIVE: &[&[u8]] = &[
    &[0xfe, 0xed, 0xfa, 0xce],
    &[0xce, 0xfa, 0xed, 0xfe],
    &[0xfe, 0xed, 0xfa, 0xcf],
    &[0xcf, 0xfa, 0xed, 0xfe],
    &[0xca, 0xfe, 0xba, 0xbe],
    &[0xbe, 0xba, 0xfe, 0xca],
    &[0xca, 0xfe, 0xba, 0xbf],
    &[0xbf, 0xba, 0xfe, 0xca],
];
/// How a native program starts: what the system loads itself, never through a shell or an interpreter
/// the file names. Elsewhere: ELF.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) const NATIVE: &[&[u8]] = &[b"\x7fELF"];

/// How many leading bytes [`NATIVE`] needs.
const MAGIC_LEN: usize = 4;

/// The command a session key was made with, and the hash of each of its files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pin {
    /// The program, then its configured arguments, as `config.json` names them.
    command: Vec<String>,
    files: Vec<PinnedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedFile {
    path: String,
    sha256: String,
}

/// One pinned file as it runs: the path a child is started by (links followed), and its SHA-256.
#[derive(Debug)]
struct Runs {
    path: PathBuf,
    sha256: String,
}

/// The pinned files, open (on Windows no one can write, rename or delete them until this is dropped),
/// and the paths a child is started by.
#[derive(Debug)]
pub(crate) struct Held {
    _files: Vec<HeldFile>,
    program: Runs,
    script: Option<Runs>,
}

impl Held {
    /// The program to start: the resolved path of the file that was hashed.
    pub(crate) fn program(&self) -> &Path {
        &self.program.path
    }

    /// The script to give it, when the command is Node and `bw.js`.
    pub(crate) fn script(&self) -> Option<&Path> {
        self.script.as_ref().map(|s| s.path.as_path())
    }

    /// The files that will run, each with its SHA-256, for the owner to check before `connect` pins them.
    pub(crate) fn describe(&self) -> String {
        let mut shown = String::new();
        for r in std::iter::once(&self.program).chain(&self.script) {
            let _ = writeln!(shown, "  {}\n    sha256 {}", escaped(&r.path), r.sha256);
        }
        shown
    }
}

/// `path` as the owner reads it at a terminal, and as every refusal names it: printable ASCII as it is,
/// but `{`, every other character written as `\u{..}` and every byte that is not UTF-8 as `\x{..}`. That
/// one rule needs no list of the characters that hide or reorder text (controls, bidirectional marks,
/// zero-width and other default-ignorable code points, variation selectors, combining marks, Hangul
/// fillers, spaces other than U+0020), so none can be missed, and it shows a letter that only looks like
/// an ASCII one (Cyrillic `а`) too. A `{` is written `\u{7b}`, so it is never shown as it is: every `{`
/// shown opens an escape, and the text reads back to one path only. A name cannot spell an escape, not
/// even after a `\` that is the separator (Windows: folder `x` then `u{202e}nib` is not `x` then U+202E
/// `nib`). The same on every system. A non-ASCII folder name reads escaped, which is the price.
pub(crate) fn escaped(path: &Path) -> String {
    let mut out = String::new();
    for chunk in path.as_os_str().as_encoded_bytes().utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '{' => out.push_str(r"\u{7b}"),
                ' '..='~' => out.push(c),
                _ => {
                    let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
                }
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{{{b:02x}}}");
        }
    }
    out
}

/// A command that cannot be pinned: the error says why and what to set.
fn refuse(why: &str) -> std::io::Error {
    refuse_with(why, None)
}

/// [`refuse`], naming the exact `bw` to set when the install is known.
fn refuse_with(why: &str, set: Option<&str>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{why}: {}", set.unwrap_or(SHAPES)))
}

/// `path` as a JSON string, to paste into `config.json`: every character but printable ASCII written as
/// a `\u` escape, so the hint shows what it names as [`escaped`] does and still parses to the path.
fn json_path(path: &Path) -> String {
    let mut out = String::from('"');
    for c in path.to_string_lossy().chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            _ => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

/// What to set `bw` to when `program` is the launcher of a known install, for a refusal's text: the
/// `bw.exe` a Scoop shim starts, or node and the npm package's `bw.js` that one of npm's launchers runs
/// (`bw`, `bw.cmd` or `bw.ps1` beside `node_modules`, or a link to `bw.js`, as npm and Homebrew make on
/// macOS).
pub(crate) fn install_hint(program: &Path) -> Option<String> {
    if let Some(target) = scoop_target(program) {
        return Some(format!("set bw to {}", json_path(&target)));
    }
    let npm: PathBuf = NPM_SCRIPT.split('/').collect();
    let beside = program.parent()?.join(&npm);
    let script = if beside.is_file() {
        beside
    } else {
        let real = std::fs::canonicalize(program).ok()?;
        if !real.ends_with(&npm) {
            return None;
        }
        real
    };
    let (node, script) = node_for(&script);
    Some(format!(
        "set bw to [{}, {}]",
        node.map_or_else(|| "\"<absolute path of node>\"".to_owned(), |n| json_path(&n)),
        json_path(&script)
    ))
}

/// Whether `program` is a launcher Chocolatey's shimgen made, and if so the program it starts when that
/// is a file: the shim names it relative to its own folder (`..\\lib\<package>\tools\bw.exe`), and
/// its help text gives it away ([`SHIM_MAX`]). The text is the most reliable mark: it is in every shim
/// wherever it was put, unlike a path under `%ChocolateyInstall%\bin`, which needs that variable or the
/// default folder and misses a shim copied elsewhere.
fn chocolatey_target(program: &Path) -> Option<Shimgen> {
    if std::fs::metadata(program).ok()?.len() > SHIM_MAX {
        return None;
    }
    let bytes = std::fs::read(program).ok()?;
    // A .NET string need not start at an even offset, so the text is read at both.
    let texts: Vec<String> = (0..2)
        .flat_map(|shift| {
            let units: Vec<u16> =
                bytes[shift..].as_chunks::<2>().0.iter().map(|&pair| u16::from_le_bytes(pair)).collect();
            units
                .split(|&u| !(0x20..0x7f).contains(&u))
                .filter(|run| run.len() >= 8)
                .filter_map(|run| String::from_utf16(run).ok())
                .collect::<Vec<_>>()
        })
        .collect();
    if !texts.iter().any(|text| text.contains("shimgen-help")) {
        return None;
    }
    let target = texts
        .iter()
        .find(|text| text.to_ascii_lowercase().contains("lib\\") && ends_with(Path::new(text), ".exe"))
        .and_then(|relative| {
            let mut target = program.parent()?.to_path_buf();
            for part in Path::new(&relative).components() {
                match part {
                    std::path::Component::ParentDir => {
                        target.pop();
                    }
                    std::path::Component::Normal(name) => target.push(name),
                    _ => {}
                }
            }
            target.is_file().then_some(target)
        });
    Some(Shimgen { target })
}

/// A launcher Chocolatey's shimgen made ([`chocolatey_target`]).
#[derive(Debug, PartialEq, Eq)]
struct Shimgen {
    /// The program it starts, when that is a file.
    target: Option<PathBuf>,
}

/// Whether the program at `path` (its links followed) is one of Volta's launchers, and if so the node it
/// starts by default. Each starts the node Volta picks, under its home's `tools/image/node`, which the pin
/// never sees. On macOS each launcher (`~/.volta/bin/node` and the like) is a link to `volta-shim`, so
/// `path` is `volta-shim` itself; Volta's Windows installer puts `node.exe`, `npm.exe` and the like beside
/// `volta-shim.exe` (`C:\Program Files\Volta`) as copies of it. So, the same on every system, a program is
/// one when it is named `volta-shim` (in any case), or when a `volta-shim` beside it holds the same bytes
/// (`sha256`, the program's). The file is judged, not its folder: a real `bw` that only shares a folder
/// with Volta (Homebrew's `/usr/local/bin` on an Intel Mac) is not one. A Volta home's `bin` is no mark
/// either, since a program put there by hand may be a real `bw`, and the launchers there are caught
/// anyway: Volta 2's own are `.cmd` files and scripts, refused as not native; Volta 1's were links to
/// `volta-shim.exe`, caught by name; Scoop's Volta copies `volta-shim.exe` there beside its copies,
/// caught by bytes. `homes` ([`volta_homes`]) only give the node to name.
fn volta_shim(path: &Path, sha256: &str, homes: &[PathBuf]) -> Option<VoltaShim> {
    let shim = if cfg!(windows) { "volta-shim.exe" } else { "volta-shim" };
    let named = path.file_name().is_some_and(|name| name.eq_ignore_ascii_case(shim));
    if !named && sha256_of(&path.parent()?.join(shim), VOLTA_SHIM_MAX).as_deref() != Some(sha256) {
        return None;
    }
    Some(VoltaShim { node: homes.iter().find_map(|home| volta_node(home)) })
}

/// The SHA-256 of the file at `path` (a link followed) in lower-case hex, when it is a regular file of at
/// most `max` bytes.
fn sha256_of(path: &Path, max: u64) -> Option<String> {
    // Checked by path first so that opening never waits on a FIFO; then again on the handle.
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > max {
        return None;
    }
    let mut digest = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut file = file.take(max + 1);
    let mut read = 0u64;
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                read += n as u64;
                digest.update(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    (read <= max).then(|| crate::util::hex(&digest.finalize()))
}

/// A launcher of Volta's ([`volta_shim`]).
#[derive(Debug, PartialEq, Eq)]
struct VoltaShim {
    /// The node Volta runs by default, when that is a file.
    node: Option<PathBuf>,
}

/// Where Volta keeps its home: `VOLTA_HOME`, and the default (`%LOCALAPPDATA%\Volta`, `~/.volta`).
fn volta_homes() -> Vec<PathBuf> {
    let default = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(|dir| PathBuf::from(dir).join("Volta"))
    } else {
        std::env::var_os("HOME").map(|dir| PathBuf::from(dir).join(".volta"))
    };
    std::env::var_os("VOLTA_HOME")
        .map(PathBuf::from)
        .into_iter()
        .chain(default)
        .filter(|home| home.is_absolute())
        .collect()
}

/// The node Volta runs by default from `home`: the version its `tools/user/platform.json` names
/// (`{"node": {"runtime": "<version>"}}`), at `tools/image/node/<version>` (`node.exe` there on Windows,
/// `bin/node` on macOS), when that is a file.
fn volta_node(home: &Path) -> Option<PathBuf> {
    let file = home.join("tools").join("user").join("platform.json");
    if std::fs::metadata(&file).ok()?.len() > 1 << 16 {
        return None;
    }
    let platform: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).ok()?).ok()?;
    let version = platform.get("node")?.get("runtime")?.as_str()?;
    if !version.starts_with(|c: char| c.is_ascii_digit())
        || !version.chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c))
    {
        return None;
    }
    let image = home.join("tools").join("image").join("node").join(version);
    let node = if cfg!(windows) { image.join("node.exe") } else { image.join("bin").join("node") };
    node.is_file().then_some(node)
}

/// The `bw` to set for a Volta launcher: the node it starts (or how to find it) and the script.
fn volta_hint(node: Option<&Path>, script: Option<&String>) -> String {
    let node = node.map_or_else(|| "\"<the node `volta which node` prints>\"".to_owned(), json_path);
    let script = script.map_or_else(
        || "\"<absolute path of @bitwarden/cli/build/bw.js>\"".to_owned(),
        |script| json_path(Path::new(script)),
    );
    format!("set bw to [{node}, {script}]")
}

/// The program a Scoop shim at `program` starts: the `path` its `.shim` file beside it names.
fn scoop_target(program: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(program.with_extension("shim")).ok()?;
    text.lines().find_map(|line| {
        let value = line.trim().strip_prefix("path")?.trim_start().strip_prefix('=')?;
        Some(PathBuf::from(value.trim().trim_matches('"')))
    })
}

/// The node to run the npm package's `script` with, and the script by a path that names no version.
/// Homebrew's `<brew>/Cellar/bitwarden-cli/<version>/...` is also `<brew>/opt/bitwarden-cli/...`, which
/// `brew upgrade` keeps, run by Homebrew's `<brew>/bin/node`. npm's global `<prefix>/lib/node_modules`
/// (unix) or `<prefix>\node_modules` (Windows) has the node whose npm made it at `<prefix>/bin/node` or
/// `<prefix>\node.exe`; else, on Windows, the installer's `%ProgramFiles%\nodejs\node.exe`. `None`: no
/// node found to name.
fn node_for(script: &Path) -> (Option<PathBuf>, PathBuf) {
    let parts: Vec<&std::ffi::OsStr> = script.iter().collect();
    if let Some(at) = parts.windows(2).position(|w| w[0] == "Cellar" && w[1] == "bitwarden-cli")
        && parts.len() > at + 3
    {
        let brew: PathBuf = parts[..at].iter().collect();
        let rest: PathBuf = parts[at + 3..].iter().collect();
        return (Some(brew.join("bin").join("node")), brew.join("opt").join("bitwarden-cli").join(rest));
    }
    let prefix = script.ancestors().nth(5);
    let mut near = Vec::new();
    if let Some(prefix) = prefix {
        if cfg!(windows) {
            near.push(prefix.join("node.exe"));
        } else if prefix.ends_with("lib")
            && let Some(top) = prefix.parent()
        {
            near.push(top.join("bin").join("node"));
        }
    }
    if cfg!(windows)
        && let Some(files) = std::env::var_os("ProgramFiles")
    {
        near.push(PathBuf::from(files).join("nodejs").join("node.exe"));
    }
    (near.into_iter().find(|n| n.is_file()), script.to_path_buf())
}

/// Whether `path` names node, the program a script must be given to.
fn is_node(path: &Path) -> bool {
    path.file_stem().is_some_and(|s| s.eq_ignore_ascii_case("node"))
}

/// Whether `path` names the standalone bw: `bw`, or on Windows `bw.exe`, in any case on both (Windows
/// names and macOS's default volume are not case-sensitive), as [`is_node`] is.
fn is_bw(path: &Path) -> bool {
    let bw = if cfg!(windows) { "bw.exe" } else { "bw" };
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.eq_ignore_ascii_case(bw))
}

/// Whether `path`'s file name ends in `suffix`, in any case.
fn ends_with(path: &Path, suffix: &str) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.len().checked_sub(suffix.len()).and_then(|at| n.get(at..)))
        .is_some_and(|end| end.eq_ignore_ascii_case(suffix))
}

/// The path a child is started by for the file `held` opened at `path`. On Windows it is read back from
/// the handle, so no link on the configured path is followed again; on unix it is the configured path,
/// resolved, and refused unless it names the open file: a link repointed after the open would otherwise
/// start another one.
fn run_path(path: &Path, held: &HeldFile) -> std::io::Result<PathBuf> {
    #[cfg(windows)]
    let resolved = held.final_path().ok_or_else(|| {
        std::io::Error::other(format!("Windows cannot say which file {} opened", escaped(path)))
    })?;
    #[cfg(not(windows))]
    let resolved = {
        use std::os::unix::fs::MetadataExt as _;
        let resolved = std::fs::canonicalize(path)?;
        let (now, opened) = (std::fs::metadata(&resolved)?, held.file().metadata()?);
        if (now.dev(), now.ino()) != (opened.dev(), opened.ino()) {
            return Err(std::io::Error::other(format!("{} changed while it was checked", escaped(path))));
        }
        resolved
    };
    Ok(resolved)
}

/// The resolved `script` for a Node program at `program`, checked to be a `.js` file.
fn script_of(program: &Path, script: &str) -> std::io::Result<(HeldFile, String, PathBuf)> {
    if !is_node(program) {
        return Err(refuse(&format!("with a script, the program must be node, not {}", escaped(program))));
    }
    let given = Path::new(script);
    if !given.is_absolute() || !ends_with(given, ".js") {
        return Err(refuse(&format!("\"{}\" is not the absolute path of a .js file", escaped(given))));
    }
    let (file, sha256, _) = hashed(given)?;
    let path = run_path(given, &file)?;
    if !ends_with(&path, ".js") {
        return Err(refuse(&format!(
            "{} leads to {}, which is not a .js file",
            escaped(given),
            escaped(&path)
        )));
    }
    Ok((file, sha256, path))
}

impl Pin {
    /// The pin of `config`'s command as its files are now. Blocking: it may hash them.
    ///
    /// # Errors
    /// A file of the command cannot be read, or the command cannot be pinned (`InvalidInput`).
    #[cfg(test)]
    pub(crate) fn of(config: &Config) -> std::io::Result<Pin> {
        Pin::open(config).map(|(pin, _)| pin)
    }

    /// The pin of `config`'s command, and its files held open. Blocking: it may hash them.
    ///
    /// # Errors
    /// As [`Pin::of`].
    pub(crate) fn open(config: &Config) -> std::io::Result<(Pin, Held)> {
        let program = config.program.to_string_lossy().into_owned();
        let mut command = vec![program.clone()];
        command.extend(config.prefix.iter().cloned());
        // Every path in a refusal is shown escaped, as at the confirmation: a planted name cannot hide
        // part of itself there either.
        let shown = escaped(&config.program);
        let script = match config.prefix.as_slice() {
            [] => None,
            [script] if !script.starts_with('-') => Some(script),
            _ => {
                let listed: Vec<String> =
                    command.iter().map(|arg| format!("\"{}\"", escaped(Path::new(arg)))).collect();
                return Err(refuse(&format!(
                    "the bw command [{}] gives the program options or more than one argument, which could \
                     run code that is not pinned",
                    listed.join(", ")
                )));
            }
        };
        let (file, sha256, start) = hashed(&config.program)?;
        if !NATIVE.iter().any(|magic| start.starts_with(magic)) {
            return Err(refuse_with(
                &format!(
                    "{shown} is not a native program (a #! script or another text file, which would run \
                     through an interpreter or a shell); name the program itself"
                ),
                install_hint(&config.program).as_deref(),
            ));
        }
        let path = run_path(&config.program, &file)?;
        if cfg!(windows) && !super::config::is_exe(&path) {
            return Err(refuse(&format!("{shown} leads to {}, which is not a .exe", escaped(&path))));
        }
        if let Some(target) = scoop_target(&path) {
            return Err(refuse_with(
                &format!("{shown} is a Scoop launcher, which starts a program the pin never sees"),
                Some(&format!("set bw to {}", json_path(&target))),
            ));
        }
        if let Some(Shimgen { target }) = chocolatey_target(&path) {
            return Err(refuse_with(
                &format!(
                    "{shown} is a Chocolatey launcher (shimgen), which starts a program the pin never sees"
                ),
                target.map(|target| format!("set bw to {}", json_path(&target))).as_deref(),
            ));
        }
        if let Some(VoltaShim { node }) = volta_shim(&path, &sha256, &volta_homes()) {
            return Err(refuse_with(
                &format!(
                    "{shown} is a Volta launcher, which starts the node Volta picks, a program the pin never \
                     sees"
                ),
                Some(&volta_hint(node.as_deref(), script)),
            ));
        }
        if script.is_none() && is_node(&path) {
            return Err(refuse(&format!(
                "{shown} is node with no script: node would run bw's first argument (status, unlock) as a \
                 script that is not pinned"
            )));
        }
        if script.is_none() && !is_bw(&path) {
            return Err(refuse(&format!(
                "{shown} leads to {}, which is not the bw program: any other program alone would be given \
                 bw's arguments, which an interpreter runs as code that is not pinned",
                escaped(&path)
            )));
        }
        let mut files = vec![PinnedFile { sha256: sha256.clone(), path: program }];
        let mut held = vec![file];
        let script = match script {
            None => None,
            Some(script) => {
                let (file, sha256, path) = script_of(&path, script)?;
                files.push(PinnedFile { sha256: sha256.clone(), path: script.clone() });
                held.push(file);
                Some(Runs { path, sha256 })
            }
        };
        Ok((Pin { command, files }, Held { _files: held, program: Runs { path, sha256 }, script }))
    }

    /// [`Pin::open`], off the runtime's threads.
    pub(crate) async fn current(config: &Config) -> std::io::Result<(Pin, Held)> {
        let config = config.clone();
        tokio::task::spawn_blocking(move || Pin::open(&config))
            .await
            .map_err(|_| std::io::Error::other("the pin check stopped"))?
    }
}

/// The pinned files, held, when `key` may go to a child of `config`'s command: it was made with this
/// command, and its files are unchanged. A key with no pin (stored by an earlier phantab) never may.
/// Keep the [`Held`] until the child has exited, and start the child by the paths it names.
pub(crate) async fn hold(config: &Config, key: &SessionKey) -> Option<Held> {
    let pin = key.pin()?;
    match Pin::current(config).await {
        Ok((now, held)) if &now == pin => Some(held),
        _ => None,
    }
}

/// Whether [`hold`] would hold.
pub(crate) async fn holds(config: &Config, key: &SessionKey) -> bool {
    hold(config, key).await.is_some()
}

/// What a file's hash was taken over: when this changes, the file is hashed again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    dev_ino_ctime: (u64, u64, i64, i64),
    #[cfg(windows)]
    created: u64,
    #[cfg(windows)]
    volume_id_usn: (u64, u128, i64),
}

impl Stamp {
    /// The stamp of an open file, or `None` when it cannot be trusted to show a change.
    fn of(held: &HeldFile) -> std::io::Result<Option<Stamp>> {
        let m = held.file().metadata()?;
        #[cfg(windows)]
        let Some(volume_id_usn) = held.change_stamp() else {
            return Ok(None);
        };
        Ok(Some(Stamp {
            len: m.len(),
            modified: m.modified().ok(),
            #[cfg(unix)]
            dev_ino_ctime: {
                use std::os::unix::fs::MetadataExt as _;
                (m.dev(), m.ino(), m.ctime(), m.ctime_nsec())
            },
            #[cfg(windows)]
            created: {
                use std::os::windows::fs::MetadataExt as _;
                m.creation_time()
            },
            #[cfg(windows)]
            volume_id_usn,
        }))
    }
}

/// A file's hash, and its first [`MAGIC_LEN`] bytes.
#[derive(Clone)]
struct Hashed {
    sha256: String,
    start: Vec<u8>,
}

fn cache() -> &'static Mutex<HashMap<PathBuf, (Stamp, Hashed)>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, (Stamp, Hashed)>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// The file at `path` (a link followed), held ([`HeldFile::open`]: on Windows no one can write, rename or
/// delete it while it is open, and the loader's and Node's own opens, which read, still can), with the
/// SHA-256 of what it holds in lower-case hex and its first [`MAGIC_LEN`] bytes. Anything but a regular
/// file is refused.
fn hashed(path: &Path) -> std::io::Result<(HeldFile, String, Vec<u8>)> {
    let refuse_kind = || refuse(&format!("{} is not a file", escaped(path)));
    if !std::fs::metadata(path)?.is_file() {
        return Err(refuse_kind());
    }
    let held = HeldFile::open(path)?;
    if !held.file().metadata()?.is_file() {
        return Err(refuse_kind());
    }
    let before = Stamp::of(&held)?;
    if let Some(before) = &before
        && let Ok(cache) = cache().lock()
        && let Some((stamp, hashed)) = cache.get(path)
        && stamp == before
    {
        let hashed = hashed.clone();
        return Ok((held, hashed.sha256, hashed.start));
    }
    let mut digest = Sha256::new();
    let mut start = Vec::with_capacity(MAGIC_LEN);
    let mut buf = vec![0u8; 1 << 20];
    let mut file = held.file();
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let want = MAGIC_LEN.saturating_sub(start.len()).min(n);
                start.extend_from_slice(&buf[..want]);
                digest.update(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let hashed = Hashed { sha256: crate::util::hex(&digest.finalize()), start };
    if let Some(before) = before
        && Stamp::of(&held)?.as_ref() == Some(&before)
        && let Ok(mut cache) = cache().lock()
    {
        cache.insert(path.to_path_buf(), (before, hashed.clone()));
    }
    Ok((held, hashed.sha256, hashed.start))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn config(program: &Path, prefix: &[String]) -> Config {
        Config {
            program: program.to_path_buf(),
            prefix: prefix.to_vec(),
            data_dir: PathBuf::from("data"),
            ask_first: vec![],
            policy_file: None,
            sync_after: Duration::ZERO,
            server: None,
            proxy: None,
        }
    }

    fn hash(path: &Path) -> String {
        hashed(path).unwrap().1
    }

    /// Bytes that start as a native program of this system does, then `rest`.
    fn native(rest: &[u8]) -> Vec<u8> {
        [NATIVE[0], rest].concat()
    }

    fn refusal(config: &Config) -> String {
        let e = Pin::of(config).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
        assert!(e.to_string().contains(SHAPES) || e.to_string().contains("set bw to"), "{e}");
        e.to_string()
    }

    /// A program named `name` as this system names programs.
    fn program_named(dir: &Path, name: &str) -> PathBuf {
        dir.join(if cfg!(windows) { format!("{name}.exe") } else { name.to_owned() })
    }

    /// The temporary folder, by its real path on unix (macOS's `/var` is a link to `/private/var`), as the
    /// pin resolves it.
    fn real_dir(dir: &tempfile::TempDir) -> PathBuf {
        if cfg!(windows) { dir.path().to_path_buf() } else { std::fs::canonicalize(dir.path()).unwrap() }
    }

    /// A Node program and a `bw.js` beside it, in `dir`.
    fn node_and_script(dir: &Path) -> (PathBuf, PathBuf) {
        let node = dir.join(if cfg!(windows) { "node.exe" } else { "node" });
        let script = dir.join("bw.js");
        std::fs::write(&node, native(b"node")).unwrap();
        std::fs::write(&script, b"#!/usr/bin/env node\nbw").unwrap();
        (node, script)
    }

    fn text(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn a_pin_names_the_command_and_hashes_its_files() {
        let dir = tempfile::tempdir().unwrap();
        let (node, script) = node_and_script(dir.path());
        let prefix = vec![text(&script)];
        let (pin, held) = Pin::open(&config(&node, &prefix)).unwrap();
        assert_eq!(pin.command, [text(&node), text(&script)]);
        assert_eq!(pin.files.len(), 2, "the program and the script (which may start #!): {pin:?}");
        let real = |p: &Path| std::fs::canonicalize(p).unwrap();
        assert_eq!(
            (std::fs::canonicalize(held.program()).unwrap(), held.script().map(real)),
            (real(&node), Some(real(&script))),
            "a child is started by the files that were hashed"
        );
        let shown = held.describe();
        assert!(shown.contains(&pin.files[0].sha256) && shown.contains(&pin.files[1].sha256), "{shown}");
        assert!(shown.contains("bw.js"), "{shown}");
        drop(held);
        assert_eq!(Pin::of(&config(&node, &prefix)).unwrap(), pin, "the same files pin the same");
        // A changed script, another command, or a missing program: another pin, or none.
        std::fs::write(&script, b"bw changed").unwrap();
        assert_ne!(Pin::of(&config(&node, &prefix)).unwrap(), pin);
        let bw = dir.path().join(if cfg!(windows) { "bw.exe" } else { "bw" });
        std::fs::write(&bw, native(b"bw")).unwrap();
        let alone = Pin::of(&config(&bw, &[])).unwrap();
        assert_eq!((alone.command.len(), alone.files.len()), (1, 1));
        let gone = dir.path().join("gone").join(if cfg!(windows) { "bw.exe" } else { "bw" });
        let gone = Pin::of(&config(&gone, &[])).unwrap_err();
        assert_eq!(gone.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn only_the_two_shapes_are_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let (node, script) = node_and_script(dir.path());
        let script = text(&script);
        let package = dir.path().join("cli");
        std::fs::create_dir_all(package.join("build")).unwrap();
        std::fs::write(package.join("build").join("bw.js"), b"bw").unwrap();
        let main = text(&package.join("build").join("bw"));
        for prefix in [
            // Node options, before or after the script: each can run code that is not hashed.
            vec!["--eval=require(atob('eA'))".to_owned(), script.clone()],
            vec!["--eval=1".to_owned()],
            vec!["--env-file=env".to_owned(), script.clone()],
            vec![format!("--require={main}.js"), script.clone()],
            vec![script.clone(), "--flag".to_owned()],
            vec!["--no-deprecation".to_owned(), script.clone()],
            vec![script.clone(), script.clone()],
            // A folder (Node runs the package's main file), relative paths, a script that is not .js, and
            // one Node would complete (`build/bw` runs `build/bw.js`).
            vec![text(&package)],
            vec!["build/bw.js".to_owned()],
            vec!["bw.js".to_owned()],
            vec![main.clone()],
            vec![text(&node)],
        ] {
            refusal(&config(&node, &prefix));
        }
        // With a script, the program must be node.
        let other = dir.path().join(if cfg!(windows) { "bw.exe" } else { "bw" });
        std::fs::write(&other, native(b"bw")).unwrap();
        assert!(refusal(&config(&other, std::slice::from_ref(&script))).contains("must be node"));
        // The program itself: a folder, or not a native program.
        refusal(&config(dir.path(), &[]));
        let shebang = dir.path().join(if cfg!(windows) { "sh.exe" } else { "bw-sh" });
        std::fs::write(&shebang, b"#!/usr/bin/env node\nrequire('./bw.js')").unwrap();
        assert!(refusal(&config(&shebang, &[])).contains("not a native program"));
        // No #! line: the kernel will not load it, and execvp hands it to /bin/sh.
        let plain = dir.path().join(if cfg!(windows) { "plain.exe" } else { "bw-plain" });
        std::fs::write(&plain, b"node ./bw.js\n").unwrap();
        assert!(refusal(&config(&plain, &[])).contains("not a native program"));
        std::fs::write(&plain, b"").unwrap();
        assert!(refusal(&config(&plain, &[])).contains("not a native program"));
        // node with nothing after it: it would run bw's first argument as a script.
        assert!(refusal(&config(&node, &[])).contains("node with no script"));
    }

    #[test]
    fn alone_only_the_bw_program_is_pinned() {
        let dir = tempfile::tempdir().unwrap();
        // Interpreters and the like, which would run bw's arguments (`status`, `unlock`) as code.
        for name in ["node", "sh", "bash", "powershell", "pwsh", "python", "env", "bw-real", "bwx"] {
            let program = program_named(dir.path(), name);
            std::fs::write(&program, native(name.as_bytes())).unwrap();
            let why = refusal(&config(&program, &[]));
            let expect = if name == "node" { "node with no script" } else { "not the bw program" };
            assert!(why.contains(expect), "{name}: {why}");
        }
        // The standalone bw: `bw`, or on Windows `bw.exe`, in any case on both.
        let bw = program_named(dir.path(), "BW");
        std::fs::write(&bw, native(b"bw")).unwrap();
        Pin::of(&config(&bw, &[])).unwrap();
        // A link named bw is judged by the file it leads to, and started by that file's path.
        #[cfg(unix)]
        {
            let link = dir.path().join("links").join("bw");
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(program_named(dir.path(), "sh"), &link).unwrap();
            assert!(refusal(&config(&link, &[])).contains("not the bw program"));
            std::fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&bw, &link).unwrap();
            let (_, held) = Pin::open(&config(&link, &[])).unwrap();
            assert_eq!(held.program(), std::fs::canonicalize(&bw).unwrap());
        }
    }

    #[test]
    fn a_launcher_is_refused_with_the_exact_bw_to_set() {
        let tmp = tempfile::tempdir().unwrap();
        let root = real_dir(&tmp);
        // Scoop: its shim is a native bw.exe that starts the program its .shim names.
        let real =
            program_named(&root.join("scoop").join("apps").join("bitwarden-cli").join("current"), "bw");
        let shim = program_named(&root.join("scoop").join("shims"), "bw");
        for (path, bytes) in [(&real, native(b"bw")), (&shim, native(b"shim"))] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        std::fs::write(shim.with_extension("shim"), format!("path = \"{}\"\n", real.display())).unwrap();
        let why = refusal(&config(&shim, &[]));
        assert!(why.contains("Scoop launcher"), "{why}");
        assert!(why.contains(&format!("set bw to {}", json_path(&real))), "{why}");
        Pin::of(&config(&real, &[])).unwrap();
        // npm: on Windows its launchers sit beside node_modules; on unix bin/bw is a link to bw.js.
        let prefix = root.join("npm");
        let modules = if cfg!(windows) { prefix.clone() } else { prefix.join("lib") }.join("node_modules");
        let script = modules.join("@bitwarden").join("cli").join("build").join("bw.js");
        let node = if cfg!(windows) { prefix.join("node.exe") } else { prefix.join("bin").join("node") };
        let launcher = if cfg!(windows) { prefix.join("bw") } else { prefix.join("bin").join("bw") };
        std::fs::create_dir_all(script.parent().unwrap()).unwrap();
        std::fs::create_dir_all(node.parent().unwrap()).unwrap();
        std::fs::write(&script, b"#!/usr/bin/env node\nbw").unwrap();
        std::fs::write(&node, native(b"node")).unwrap();
        #[cfg(windows)]
        std::fs::write(
            &launcher,
            b"#!/bin/sh\nexec node \"$basedir/node_modules/@bitwarden/cli/build/bw.js\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&script, &launcher).unwrap();
        let set = format!("set bw to [{}, {}]", json_path(&node), json_path(&script));
        let why = refusal(&config(&launcher, &[]));
        assert!(why.contains("not a native program") && why.contains(&set), "{why}");
        // On Windows `bw.cmd` and `bw.ps1` stop at the config, with the same text.
        #[cfg(windows)]
        for name in ["bw.cmd", "bw.ps1"] {
            let block = serde_json::json!({"bw": prefix.join(name)});
            let e = Config::parse(Some(&block), &root).unwrap_err();
            assert!(e.0.contains(&set), "{name}: {}", e.0);
        }
        Pin::of(&config(&node, &[text(&script)])).unwrap();
        // Homebrew on macOS: bin/bw leads into the versioned Cellar; the hint names opt/, which no
        // `brew upgrade` moves, and Homebrew's node.
        #[cfg(unix)]
        {
            let brew = root.join("homebrew");
            let tail: PathBuf =
                ["libexec", "lib", "node_modules", "@bitwarden", "cli", "build", "bw.js"].iter().collect();
            let cellar = brew.join("Cellar").join("bitwarden-cli").join("2026.10.1").join(&tail);
            std::fs::create_dir_all(cellar.parent().unwrap()).unwrap();
            std::fs::write(&cellar, b"#!/usr/bin/env node\nbw").unwrap();
            std::fs::create_dir_all(brew.join("bin")).unwrap();
            std::os::unix::fs::symlink(&cellar, brew.join("bin").join("bw")).unwrap();
            let opt = brew.join("opt").join("bitwarden-cli").join(&tail);
            let set =
                format!("set bw to [{}, {}]", json_path(&brew.join("bin").join("node")), json_path(&opt));
            let why = refusal(&config(&brew.join("bin").join("bw"), &[]));
            assert!(why.contains(&set), "{why}");
        }
    }

    #[test]
    fn a_chocolatey_shim_is_refused_with_the_program_it_starts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = real_dir(&tmp).join("chocolatey");
        let real = program_named(&root.join("lib").join("bitwarden-cli").join("tools"), "bw");
        let shim = program_named(&root.join("bin"), "bw");
        // What shimgen writes, in part: its help text and the target relative to the shim, as UTF-16.
        let utf16 = |text: &str| text.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        let relative = if cfg!(windows) { r"..\\lib\bitwarden-cli\tools\bw.exe" } else { r"..\lib\x\bw" };
        let mut bytes = native(b"\0\0");
        for text in
            ["\0shimgen-help\0".to_owned(), "\0This is a shim\0".to_owned(), format!("\0{relative}\0")]
        {
            bytes.extend(utf16(&text));
        }
        for (path, bytes) in [(&real, native(b"bw")), (&shim, bytes)] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        let why = refusal(&config(&shim, &[]));
        assert!(why.contains("Chocolatey launcher"), "{why}");
        if cfg!(windows) {
            assert!(why.contains(&format!("set bw to {}", json_path(&real))), "{why}");
        }
        Pin::of(&config(&real, &[])).unwrap();
        // A program without shimgen's text is not a shim.
        assert_eq!(chocolatey_target(&real), None);
    }

    /// On unix the configured path, resolved, must name the file that was opened and hashed.
    #[cfg(unix)]
    #[test]
    fn a_path_that_names_another_file_than_the_one_held_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let held = HeldFile::open(&b).unwrap();
        let e = run_path(&a, &held).unwrap_err();
        assert!(e.to_string().contains("changed while it was checked"), "{e}");
        assert_eq!(run_path(&b, &held).unwrap(), std::fs::canonicalize(&b).unwrap());
    }

    #[test]
    fn a_volta_launcher_is_refused_with_the_node_it_starts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = real_dir(&tmp);
        // Volta's install folder (`C:\Program Files\Volta`, `~/.volta/bin`): its node is a copy of the shim.
        let install = root.join("Volta");
        let home = root.join("home");
        let image = home.join("tools").join("image").join("node").join("20.11.1");
        let real = if cfg!(windows) { image.join("node.exe") } else { image.join("bin").join("node") };
        let (shim, node) = (program_named(&install, "volta-shim"), program_named(&install, "node"));
        // A real bw that only shares the folder with Volta (Homebrew's `/usr/local/bin` on an Intel Mac).
        let (volta, bw) = (program_named(&install, "volta"), program_named(&install, "bw"));
        let platform = home.join("tools").join("user").join("platform.json");
        let script = root.join("bw.js");
        for (path, bytes) in [
            (&shim, native(b"volta-shim")),
            (&node, native(b"volta-shim")),
            (&volta, native(b"volta")),
            (&bw, native(b"bw")),
            (&real, native(b"node")),
            (&platform, br#"{"node": {"runtime": "20.11.1", "npm": null}}"#.to_vec()),
            (&script, b"bw".to_vec()),
        ] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        let homes = [home.clone()];
        let sha = |path: &Path| hashed(path).unwrap().1;
        let found = Some(VoltaShim { node: Some(real.clone()) });
        assert_eq!(volta_shim(&node, &sha(&node), &homes), found);
        assert_eq!(volta_shim(&shim, &sha(&shim), &homes), found);
        assert_eq!(volta_shim(&bw, &sha(&bw), &homes), None);
        assert_eq!(volta_shim(&volta, &sha(&volta), &homes), None);
        assert_eq!(volta_shim(&real, &sha(&real), &homes), None);
        assert_eq!(volta_shim(&script, &sha(&script), &[]), None);
        Pin::of(&config(&bw, &[])).unwrap();
        // The name in any case; a file over the size limit is never hashed.
        let upper = program_named(&root.join("upper"), "VOLTA-SHIM");
        std::fs::create_dir_all(upper.parent().unwrap()).unwrap();
        std::fs::write(&upper, native(b"volta-shim")).unwrap();
        assert_eq!(volta_shim(&upper, &sha(&upper), &homes), found);
        let len = std::fs::metadata(&shim).unwrap().len();
        assert_eq!(sha256_of(&shim, len).as_deref(), Some(sha(&shim).as_str()));
        assert_eq!(sha256_of(&shim, len - 1), None);
        let big = root.join("big");
        std::fs::create_dir_all(&big).unwrap();
        let over = std::fs::File::create(program_named(&big, "volta-shim")).unwrap();
        over.set_len(VOLTA_SHIM_MAX + 1).unwrap();
        drop(over);
        assert_eq!(sha256_of(&program_named(&big, "volta-shim"), VOLTA_SHIM_MAX), None);
        let script_text = script.to_str().unwrap().to_owned();
        assert_eq!(
            volta_hint(Some(&real), Some(&script_text)),
            format!("set bw to [{}, {}]", json_path(&real), json_path(&script))
        );
        assert!(volta_hint(None, None).contains("volta which node"));
        let why = refusal(&config(&node, std::slice::from_ref(&script_text)));
        assert!(why.contains("Volta launcher"), "{why}");
        Pin::of(&config(&real, std::slice::from_ref(&script_text))).unwrap();
        // A version that would leave the image folder names no node.
        std::fs::write(&platform, br#"{"node": {"runtime": "../../.."}}"#).unwrap();
        assert_eq!(volta_shim(&node, &sha(&node), &homes), Some(VoltaShim { node: None }));
        // A program in a Volta home's `bin` is judged as itself: a real bw there is accepted.
        let in_home = program_named(&home.join("bin"), "bw");
        std::fs::create_dir_all(in_home.parent().unwrap()).unwrap();
        std::fs::write(&in_home, native(b"bw")).unwrap();
        assert_eq!(volta_shim(&in_home, &sha(&in_home), &homes), None);
        #[cfg(unix)]
        {
            // macOS: Volta's `node` is a link to `volta-shim`, which is judged as the file it leads to.
            let link = root.join("link").join("node");
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&shim, &link).unwrap();
            let why = refusal(&config(&link, std::slice::from_ref(&script_text)));
            assert!(why.contains("Volta launcher"), "{why}");
        }
    }

    #[test]
    fn homebrew_s_bw_js_is_named_by_a_path_no_upgrade_moves() {
        let brew = Path::new(if cfg!(windows) { r"C:\opt\homebrew" } else { "/opt/homebrew" });
        let tail: PathBuf =
            ["libexec", "lib", "node_modules", "@bitwarden", "cli", "build", "bw.js"].iter().collect();
        let cellar = brew.join("Cellar").join("bitwarden-cli").join("2026.10.1").join(&tail);
        let (node, script) = node_for(&cellar);
        assert_eq!(node, Some(brew.join("bin").join("node")));
        assert_eq!(script, brew.join("opt").join("bitwarden-cli").join(&tail));
    }

    #[test]
    fn the_paths_shown_cannot_hide_or_reorder_what_they_name() {
        // Fixed inputs and what the owner must see, written out by hand: no oracle shared with the code.
        for (input, expect) in [
            (
                "/x/\u{1b}[2K\r  /usr/local/bin/\u{202e}exe.bw",
                r"/x/\u{1b}[2K\u{d}  /usr/local/bin/\u{202e}exe.bw",
            ),
            ("/opt/homebrew/bin/node\u{fe0f}", r"/opt/homebrew/bin/node\u{fe0f}"),
            ("/opt/a\u{34f}b/\u{3164}/bw", r"/opt/a\u{34f}b/\u{3164}/bw"),
            ("/x\u{200b}\u{2060}\u{180e}y", r"/x\u{200b}\u{2060}\u{180e}y"),
            (
                "/\u{2066}\u{200f}\u{feff}\u{85}\u{a0}\u{3000}\u{e0100}",
                r"/\u{2066}\u{200f}\u{feff}\u{85}\u{a0}\u{3000}\u{e0100}",
            ),
            ("/Users/zo\u{eb}/\u{430}bw/\u{1f600}", r"/Users/zo\u{eb}/\u{430}bw/\u{1f600}"),
            ("/opt/homebrew/bin/node", "/opt/homebrew/bin/node"),
            ("/x/~!@#$%^&*()_+{}|:\"<>?`-=[];',.", r#"/x/~!@#$%^&*()_+\u{7b}}|:"<>?`-=[];',."#),
            (r"C:\Program Files\Bitwarden CLI\bw.exe", r"C:\Program Files\Bitwarden CLI\bw.exe"),
            // Pairs that read the same under a scheme that shows `{` as it is: a character escaped in
            // a name, and a separator then a folder that spells its escape.
            ("C:\\x\u{202e}nib", r"C:\x\u{202e}nib"),
            (r"C:\x\u{202e}nib", r"C:\x\u\u{7b}202e}nib"),
            ("/a\u{202e}b", r"/a\u{202e}b"),
            (r"/a\u{202e}b", r"/a\u\u{7b}202e}b"),
            (r"/a\x{ff}b", r"/a\x\u{7b}ff}b"),
            (r"C:\xed\xa0\x80", r"C:\xed\xa0\x80"),
        ] {
            assert_eq!(escaped(Path::new(input)), expect, "{input:?}");
            // Every `{` shown opens an escape.
            assert!(
                expect
                    .match_indices('{')
                    .all(|(at, _)| [r"\u", r"\x"].iter().any(|e| expect[..at].ends_with(e)))
            );
        }
        // A byte that is not UTF-8 (unix), or a lone surrogate (Windows, held as its WTF-8 bytes).
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            assert_eq!(escaped(Path::new(std::ffi::OsStr::from_bytes(b"/a\xffb"))), r"/a\x{ff}b");
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt as _;
            let lone =
                std::ffi::OsString::from_wide(&[u16::from(b'C'), u16::from(b':'), u16::from(b'\\'), 0xd800]);
            assert_eq!(escaped(Path::new(&lone)), r"C:\\x{ed}\x{a0}\x{80}");
        }
        // A hint to paste is JSON that shows the same way and still parses to the path.
        let odd = Path::new("/opt/\u{202e}\u{fe0f}\u{1f600}\"\\bw");
        let json = json_path(odd);
        assert_eq!(json, r#""/opt/\u202e\ufe0f\ud83d\ude00\"\\bw""#);
        assert_eq!(serde_json::from_str::<String>(&json).unwrap(), odd.to_str().unwrap());
        // What `connect` shows for a folder so named: control characters are not allowed in Windows names,
        // but the bidirectional ones are.
        let dir = tempfile::tempdir().unwrap();
        let odd = dir.path().join(if cfg!(windows) { "\u{202e}nib" } else { "\u{1b}[2K\rbin" });
        std::fs::create_dir_all(&odd).unwrap();
        let bw = program_named(&odd, "bw");
        std::fs::write(&bw, native(b"bw")).unwrap();
        let (_, held) = Pin::open(&config(&bw, &[])).unwrap();
        let shown = held.describe();
        assert!(shown.chars().all(|c| c == '\n' || (' '..='~').contains(&c)), "{shown:?}");
        assert!(
            shown.contains(if cfg!(windows) { r"\u{202e}nib" } else { r"\u{1b}[2K\u{d}bin" }),
            "{shown:?}"
        );
    }

    #[test]
    fn a_rewritten_file_is_hashed_again() {
        let dir = tempfile::tempdir().unwrap();
        let bw = dir.path().join("bw");
        std::fs::write(&bw, b"one").unwrap();
        let first = hash(&bw);
        assert_eq!(hash(&bw), first);
        std::fs::write(&bw, b"two!").unwrap();
        assert_ne!(hash(&bw), first);
    }

    /// The same length, and the times put back: unix sees the change time move, Windows the USN.
    #[test]
    fn a_same_length_rewrite_with_its_times_put_back_is_hashed_again() {
        let dir = tempfile::tempdir().unwrap();
        let bw = dir.path().join("bw.exe");
        std::fs::write(&bw, b"one!").unwrap();
        let first = hash(&bw);
        assert_eq!(hash(&bw), first);
        let times = std::fs::metadata(&bw).unwrap();
        let modified = times.modified().unwrap();
        let put_back = std::fs::FileTimes::new().set_modified(modified);
        #[cfg(windows)]
        let put_back = {
            use std::os::windows::fs::FileTimesExt as _;
            put_back.set_created(times.created().unwrap())
        };
        std::fs::write(&bw, b"two!").unwrap();
        std::fs::File::options().write(true).open(&bw).unwrap().set_times(put_back).unwrap();
        let after = std::fs::metadata(&bw).unwrap();
        assert_eq!((after.len(), after.modified().unwrap()), (4, modified), "only the content differs");
        assert_ne!(hash(&bw), first);
    }

    #[test]
    fn a_held_file_cannot_be_changed_but_can_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let (node, script) = node_and_script(dir.path());
        std::fs::write(&script, b"bw").unwrap();
        let c = config(&node, &[text(&script)]);
        let (pin, held) = Pin::open(&c).unwrap();
        // What the loader and Node do: open to read, sharing everything.
        assert_eq!(std::fs::read(&script).unwrap(), b"bw");
        assert_eq!(Pin::of(&c).unwrap(), pin, "a second check opens it too");
        let moved = dir.path().join("moved.js");
        if cfg!(windows) {
            assert!(std::fs::write(&script, b"swapped").is_err(), "no write while held");
            assert!(std::fs::rename(&script, &moved).is_err(), "no rename while held");
            assert!(std::fs::remove_file(&node).is_err(), "no delete while held");
            std::fs::write(&moved, b"swapped").unwrap();
            assert!(std::fs::rename(&moved, &script).is_err(), "no replace while held");
        }
        drop(held);
        std::fs::write(&script, b"swapped").unwrap();
        assert_ne!(Pin::of(&c).unwrap(), pin);
    }

    /// A link on the configured path (a junction on Windows, which needs no privilege; a symbolic link on
    /// unix) can be repointed after the check, but the child is started by the resolved paths, so it still
    /// opens the files that were hashed.
    #[test]
    fn a_child_is_started_past_the_links_on_the_configured_path() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let (node, _) = node_and_script(&real);
        let node = node.file_name().unwrap().to_owned();
        let link = dir.path().join("current");
        let junction = |to: &Path| {
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
        junction(&real);
        let c = config(&link.join(&node), &[text(&link.join("bw.js"))]);
        let (pin, held) = Pin::open(&c).unwrap();
        for path in std::iter::once(held.program()).chain(held.script()) {
            assert!(!text(path).contains("current"), "{}", path.display());
            assert!(text(path).contains("real"), "{}", path.display());
        }
        // Repointed while held: the held paths still name the hashed files.
        let planted = dir.path().join("planted");
        std::fs::create_dir_all(&planted).unwrap();
        std::fs::write(planted.join(&node), native(b"planted")).unwrap();
        std::fs::write(planted.join("bw.js"), b"planted").unwrap();
        unlink();
        junction(&planted);
        assert_eq!(std::fs::read(held.program()).unwrap(), native(b"node"));
        assert_eq!(std::fs::read(held.script().unwrap()).unwrap(), b"#!/usr/bin/env node\nbw");
        drop(held);
        assert_ne!(Pin::of(&c).unwrap(), pin, "through the repointed link it is another pin");
        unlink();
    }

    #[test]
    fn a_pin_round_trips_as_json() {
        let pin = Pin {
            command: vec!["/opt/bw".into()],
            files: vec![PinnedFile { path: "/opt/bw".into(), sha256: "ab".into() }],
        };
        let text = serde_json::to_string(&pin).unwrap();
        assert_eq!(serde_json::from_str::<Pin>(&text).unwrap(), pin);
        assert!(serde_json::from_str::<Pin>(r#"{"command":[],"files":[],"x":1}"#).is_err());
    }
}
