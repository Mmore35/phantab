//! `doctor`'s drift checks (THREAT-MODEL SR-53): the native host registration, the manifest Chrome reads
//! through it, the installed binary, the installed extension's files (SR-74) and the binary `config.json`
//! names as `installedSource`, each against what install wrote. Read-only; a same-user program can still
//! change them (R1), and this only says so.

use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};
use sha2::Digest as _;

use super::{BINARY_RECORD, CONFIG, EXTENSION_ID, HOST_RECORD, RECORD, fsops, host, load_object};
use crate::extension_files::{self, Verdict};
use crate::paths;

/// What changed since install, one sentence each. Empty when nothing did, or when nothing is installed
/// (no record, or an uninstall removed the binary entry).
///
/// # Errors
/// The install record cannot be read or parsed, or the registration cannot be read.
pub fn drift(runtime: &Path) -> Result<Vec<String>> {
    let runtime = fsops::resolve(runtime);
    let Some(record) = load_object(&runtime.join(RECORD))? else { return Ok(Vec::new()) };
    let Some(binary) = record.get(BINARY_RECORD) else { return Ok(Vec::new()) };
    let mut found = Vec::new();
    let path = binary.get("path").and_then(Value::as_str).unwrap_or_default();
    match std::fs::read(path) {
        Ok(bytes) => {
            let now = crate::util::hex(&sha2::Sha256::digest(&bytes));
            if binary.get("sha256").and_then(Value::as_str) != Some(now.as_str()) {
                found.push(format!(
                    "The installed binary {path} is not the one install wrote (its SHA-256 differs)."
                ));
            }
        }
        Err(_) => found.push(format!("The installed binary {path} is missing or unreadable.")),
    }

    let entry = record.get(HOST_RECORD);
    let installed = entry.and_then(|h| h.get("installed")).and_then(Value::as_str);
    let location = entry.and_then(|h| h.get("location")).and_then(Value::as_str);
    let registered = match location {
        Some(l) => host::Site::from_location(l)?.read()?,
        None => None,
    };
    if location.is_none() || registered.as_deref() != installed {
        found.push(format!(
            "The native host registration {} changed since install.",
            location.unwrap_or("(not recorded)")
        ));
    }
    // What Chrome would read now: on Windows the registration names the manifest file; on macOS it is it.
    let manifest = if cfg!(windows) {
        registered.as_deref().and_then(|p| std::fs::read_to_string(p).ok())
    } else {
        registered
    };
    let manifest: Option<Value> = manifest.and_then(|t| serde_json::from_str(&t).ok());
    let origins = json!([format!("chrome-extension://{EXTENSION_ID}/")]);
    if !manifest.as_ref().is_some_and(|m| m.get("allowed_origins") == Some(&origins)) {
        found.push(
            "The native host manifest cannot be read, or admits an origin other than the phantab extension."
                .to_owned(),
        );
    }
    if manifest.as_ref().is_none_or(|m| m.get("path").and_then(Value::as_str) != Some(path)) {
        found.push(format!("The native host manifest does not run the installed binary {path}."));
    }

    let config = load_object(&runtime.join(CONFIG)).ok().flatten();
    let marked = config.as_ref().and_then(|c| c.get(extension_files::MARKER)) == Some(&Value::Bool(true));
    extension_drift(&mut found, &runtime.join("extension"), "installed extension", marked);
    // SR-76: each allowed profile's copy is checked the same way, as the service filters the list
    // (`Config::allowed_other_profiles`): not the usual folder, and each folder once.
    let others = config.as_ref().and_then(|c| c.get("otherProfiles")).and_then(Value::as_array);
    let usual = config.as_ref().and_then(|c| c.get("profileDirectory")).and_then(Value::as_str);
    let mut seen: Vec<&str> = Vec::new();
    for folder in others.into_iter().flatten().filter_map(Value::as_str) {
        if paths::valid_profile_dir(folder) && usual != Some(folder) && !seen.contains(&folder) {
            seen.push(folder);
            let what = format!("{folder} copy of the extension");
            extension_drift(&mut found, &paths::profile_extension_dir_in(&runtime, folder), &what, marked);
        }
    }
    // sec-supply-6: a setup tool may register the binary this names, so it must be the installed one.
    let source = config.as_ref().and_then(|c| c.get("installedSource")).and_then(Value::as_str);
    if !source
        .is_some_and(|s| fsops::same_path(&fsops::resolve(Path::new(s)), &fsops::resolve(Path::new(path))))
    {
        found.push(format!(
            "{CONFIG} names {} as installedSource, not the installed binary {path}.",
            source.unwrap_or("nothing")
        ));
    }
    Ok(found)
}

/// SR-74: what changed in one installed copy of the extension, `what` naming it.
fn extension_drift(found: &mut Vec<String>, extension: &Path, what: &str, marked: bool) {
    match extension_files::check(extension) {
        Verdict::Intact => {}
        Verdict::Unrecorded if marked => {
            found.push(format!(
                "The record of the {what}'s files ({}) is missing, so the bridge is refused \
             until phantab install runs again from the release's extension.",
                extension_files::record_path(extension).display()
            ));
        }
        Verdict::Unrecorded => found.push(format!(
            "The {what} {} has no record of its files ({}); run phantab install again to write one.",
            extension.display(),
            extension_files::RECORD
        )),
        Verdict::Changed(files) => found.push(format!(
            "The {what}'s files changed since install: {}. The bridge is refused until phantab \
         install runs again from the release's extension.",
            extension_files::listed(&files)
        )),
        Verdict::Refused(refused) => found.push(format!(
            "The {what}'s files are not the plain files install wrote: {}. A hard link, a cloud \
         placeholder, another reparse point or a file system mounted there lets another program change \
         what Chrome loads unseen, so the bridge is refused until phantab install runs again from the \
         release's extension; a backup, dedupe, sync or mount tool that does this to the runtime folder \
         will do it again.",
            extension_files::explained(&refused)
        )),
        Verdict::Damaged => found.push(format!(
            "The record of the {what}'s files ({}) cannot be read.",
            extension_files::record_path(extension).display()
        )),
        Verdict::Unverifiable(why) => {
            found.push(format!("The {what}'s files cannot be checked, so the bridge is refused: {why}."));
        }
    }
}
