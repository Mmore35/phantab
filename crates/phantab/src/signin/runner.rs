//! Starting a command provider by the files the owner pinned (docs/VAULTS.md § Pins; THREAT-MODEL SR-85).
//! A provider sees plaintext, so it gets the bar the built-in Bitwarden source's `bw` has: each pinned
//! file is hashed through a handle that stays open until the provider has exited, and the provider is
//! started by the path read back from that handle, so the file that runs is the file that was hashed.
//! The hashing and the held handle are the Bitwarden pin's ([`super::bitwarden::pin`]); what differs is
//! the shape: the owner names every file to pin, the program among them, instead of phantab knowing the
//! two shapes `bw` comes in.
//!
//! A pin is `{"<absolute path>": "<sha256 in lower-case hex>"}`. Every key is the program or one of its
//! arguments, and the program is always one: an interpreter such as `node` runs its script, so the
//! owner pins both. What a pinned program loads from elsewhere is not pinned (a script's modules, the
//! system's libraries), as for `bw.js`. A missing or changed file answers `provider-failed`.

use std::ffi::OsString;
use std::path::Path;

use phantab_window::file_identity::HeldFile;
use serde_json::Value;

use super::bitwarden::pin::{escaped, hashed, run_path};

/// The pinned files, as `(path, sha256)` in the config's key order.
pub(crate) type PinList = Vec<(String, String)>;

/// A config's `pin` for the command `program` and `args`.
///
/// # Errors
/// Not an object of absolute paths to SHA-256 hex, a path that is not the program or an argument, or no
/// entry for the program: why, for the owner.
pub(crate) fn parse_pin(value: &Value, program: &str, args: &[String]) -> Result<PinList, String> {
    let map = value.as_object().ok_or("pin must be an object of file paths to their sha256")?;
    let mut out = PinList::new();
    for (path, sha) in map {
        if !Path::new(path).is_absolute() {
            return Err(format!("pin path {:?} is not absolute", escaped(Path::new(path))));
        }
        if path != program && !args.iter().any(|a| a == path) {
            return Err(format!(
                "pin path {:?} is neither the program nor one of its arguments",
                escaped(Path::new(path))
            ));
        }
        let sha = sha.as_str().filter(|s| is_sha256(s)).ok_or_else(|| {
            format!("pin for {:?} must be a sha256 in lower-case hex", escaped(Path::new(path)))
        })?;
        out.push((path.clone(), sha.to_owned()));
    }
    if !out.iter().any(|(p, _)| p == program) {
        return Err("pin must include the program".into());
    }
    Ok(out)
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A pinned command, its files held open: start it by [`Pinned::program`] and [`Pinned::args`], and drop
/// it only once the child has exited.
#[derive(Debug)]
pub(crate) struct Pinned {
    _files: Vec<HeldFile>,
    program: OsString,
    args: Vec<OsString>,
}

impl Pinned {
    pub(crate) fn program(&self) -> &std::ffi::OsStr {
        &self.program
    }

    pub(crate) fn args(&self) -> &[OsString] {
        &self.args
    }
}

/// Holds and checks every pinned file, and gives the command with each pinned part replaced by the path
/// read back from its handle. Blocking: it may hash the files.
///
/// # Errors
/// A pinned file cannot be opened or read, is not a regular file, or its hash is not the pinned one.
pub(crate) fn hold(program: &str, args: &[String], pin: &[(String, String)]) -> std::io::Result<Pinned> {
    let mut files = Vec::with_capacity(pin.len());
    let mut run_program: OsString = program.into();
    let mut run_args: Vec<OsString> = args.iter().map(OsString::from).collect();
    for (path, want) in pin {
        let given = Path::new(path);
        let (held, sha256, _) = hashed(given)?;
        if sha256 != *want {
            return Err(std::io::Error::other(format!("{} is not the pinned file", escaped(given))));
        }
        let resolved = run_path(given, &held)?;
        if path == program {
            run_program = resolved.clone().into_os_string();
        }
        for (arg, run) in args.iter().zip(run_args.iter_mut()) {
            if arg == path {
                *run = resolved.clone().into_os_string();
            }
        }
        files.push(held);
    }
    Ok(Pinned { _files: files, program: run_program, args: run_args })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn sha(bytes: &[u8]) -> String {
        crate::util::hex(&Sha256::digest(bytes))
    }

    #[test]
    fn a_pin_names_only_the_command_s_files() {
        let (p, a) = if cfg!(windows) { (r"C:\t\node.exe", r"C:\t\p.mjs") } else { ("/t/node", "/t/p.mjs") };
        let h = "a".repeat(64);
        let args = vec![a.to_owned()];
        let mut got = parse_pin(&json!({p: h, a: h}), p, &args).unwrap();
        got.sort();
        let mut want = vec![(p.to_owned(), h.clone()), (a.to_owned(), h.clone())];
        want.sort();
        assert_eq!(got, want);
        assert!(parse_pin(&json!({a: h}), p, &args).is_err(), "the program must be pinned");
        assert!(parse_pin(&json!({p: "A".repeat(64)}), p, &args).is_err(), "lower-case hex");
        assert!(parse_pin(&json!({p: "a".repeat(63)}), p, &args).is_err());
        assert!(parse_pin(&json!({p: 5}), p, &args).is_err());
        assert!(parse_pin(&json!([p]), p, &args).is_err());
        assert!(parse_pin(&json!({"rel": h, p: h}), p, &args).is_err(), "relative");
        let other = if cfg!(windows) { r"C:\t\other.mjs" } else { "/t/other.mjs" };
        assert!(parse_pin(&json!({p: h, other: h}), p, &args).is_err(), "not in the command");
    }

    #[test]
    fn a_held_command_starts_by_the_hashed_files_and_a_changed_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("prog.bin");
        let script = dir.path().join("script.txt");
        std::fs::write(&program, b"program bytes").unwrap();
        std::fs::write(&script, b"script bytes").unwrap();
        let (p, s) = (program.to_string_lossy().into_owned(), script.to_string_lossy().into_owned());
        let args = vec!["--flag".to_owned(), s.clone()];
        let pin = vec![(p.clone(), sha(b"program bytes")), (s.clone(), sha(b"script bytes"))];
        let held = hold(&p, &args, &pin).unwrap();
        assert_eq!(held.args()[0], OsString::from("--flag"), "an unpinned argument is passed as it is");
        assert!(Path::new(held.program()).ends_with("prog.bin"));
        assert!(Path::new(&held.args()[1]).ends_with("script.txt"));
        drop(held);
        std::fs::write(&script, b"changed").unwrap();
        assert!(hold(&p, &args, &pin).is_err(), "a changed file");
        std::fs::remove_file(&script).unwrap();
        assert!(hold(&p, &args, &pin).is_err(), "a missing file");
        assert!(hold(&p, &[], &[(p.clone(), "0".repeat(64))]).is_err(), "a wrong hash");
    }
}
