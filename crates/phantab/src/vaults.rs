//! `phantab vaults status` (docs/VAULTS.md § Status; THREAT-MODEL SR-84, SR-85): the owner's view of the
//! configured sign-in providers. Per provider, in the order they are asked: its name, source, caps, the
//! protocol it is sent, whether its account keys go out bare, its sites, its pin's state and, for the
//! Bitwarden source, its session and lock state. Then the sign-up target and the sites more than one
//! provider names. Names and states only: never a value, an item, an account, a command line or a pinned
//! file's path. It needs no service; `phantab bitwarden …` stays for the Bitwarden source's own steps.

use std::path::Path;

use serde_json::{Map, Value, json};

use crate::paths;
use crate::signin::bitwarden::config::Config;
use crate::signin::bitwarden::vault::{OsVault, SessionVault};
use crate::signin::provider::command_parts;
use crate::signin::runner;
use crate::signin::source::{self, Kind};

const USAGE: &str = "Usage: phantab vaults status";

/// Runs `phantab vaults <args>`. Returns the exit code.
#[allow(clippy::print_stdout)] // stdout is the result
pub async fn run(args: &[String]) -> i32 {
    // SR-59, as `phantab bitwarden` does: a Bitwarden status runs `bw` with the session key.
    let _ = phantab_window::process::disable_core_dumps();
    if args.len() != 1 || args[0] != "status" {
        eprintln!("{USAGE}");
        return 2;
    }
    let config = match crate::runtime::read_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("phantab: {e:#}");
            return 1;
        }
    };
    let dir = paths::runtime_dir().join("bitwarden");
    match status(source::provider_config(&config).as_ref(), &dir, &OsVault::new(&dir)).await {
        Ok(shown) => {
            println!("{shown}");
            0
        }
        Err(why) => {
            eprintln!("{}: {why}", paths::config_path().display());
            1
        }
    }
}

/// `status`, as the JSON it prints. `config` is what [`source::provider_config`] reads.
///
/// # Errors
/// The list does not check ([`source::entries`]): why, and every sign-in answers `provider-failed`.
pub(crate) async fn status(
    config: Option<&Value>,
    bitwarden_dir: &Path,
    vault: &dyn SessionVault,
) -> Result<Value, String> {
    let Some(config) = config else {
        return Ok(json!({"providers": [], "saveTo": null, "overlaps": []}));
    };
    let wrapped;
    let config = if config.get(source::LIST).is_some() {
        config
    } else {
        wrapped = json!({ source::LEGACY: config });
        &wrapped
    };
    let list = source::entries(config)?;
    let mut providers = Vec::with_capacity(list.entries.len());
    for e in &list.entries {
        let mut shown = Map::new();
        shown.insert("name".into(), json!(e.name));
        let caps = source::entry_caps(e);
        match &e.kind {
            Kind::Command { command, caps: declared, pin } => {
                shown.insert("source".into(), json!("command"));
                shown.insert("caps".into(), json!(caps.names()));
                shown.insert("protocol".into(), json!(if declared.is_some() { 2 } else { 1 }));
                shown.insert("pin".into(), json!(pin_state(command, pin.as_deref()).await));
                // A command provider has no status call: it is asked only by a sign-in.
                shown.insert("lock".into(), json!("not-asked"));
            }
            Kind::Bitwarden(v) => {
                shown.insert("source".into(), json!("bitwarden"));
                shown.insert("caps".into(), json!(caps.names()));
                let (pin, lock) = match Config::parse(v.get("bitwarden"), bitwarden_dir) {
                    Ok(c) => {
                        let s = crate::bitwarden::status_with(&c, vault).await;
                        let pin = match s["session"].as_str() {
                            Some("stored") => "ok",
                            Some("stale") => "changed",
                            Some("none") => "not-connected",
                            _ => "unknown",
                        };
                        (pin, s["vault"].as_str().unwrap_or("unknown").to_owned())
                    }
                    Err(_) => ("unknown", "misconfigured".to_owned()),
                };
                shown.insert("pin".into(), json!(pin));
                shown.insert("lock".into(), json!(lock));
            }
        }
        shown.insert("bare".into(), json!(e.bare));
        shown.insert("sites".into(), json!(e.sites));
        providers.push(Value::Object(shown));
    }
    let mut overlaps: Vec<(String, Vec<String>)> = Vec::new();
    for e in &list.entries {
        for site in &e.sites {
            match overlaps.iter_mut().find(|(s, _)| s == site) {
                Some((_, names)) => names.push(e.name.clone()),
                None => overlaps.push((site.clone(), vec![e.name.clone()])),
            }
        }
    }
    let overlaps: Vec<Value> = overlaps
        .into_iter()
        .filter(|(_, names)| names.len() > 1)
        .map(|(site, names)| json!({"site": site, "providers": names, "asked": names[0]}))
        .collect();
    Ok(json!({"providers": providers, "saveTo": list.save_to, "overlaps": overlaps}))
}

/// A command provider's pin: `none` (not pinned), `ok`, `missing` or `changed`.
async fn pin_state(command: &Value, pin: Option<&[(String, String)]>) -> &'static str {
    let Some(pin) = pin else { return "none" };
    let Some((program, args)) = command_parts(command) else { return "changed" };
    let pin = pin.to_vec();
    match tokio::task::spawn_blocking(move || runner::hold(&program, &args, &pin)).await {
        Ok(Ok(_)) => "ok",
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => "missing",
        _ => "changed",
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::signin::bitwarden::vault::MemoryVault;

    #[tokio::test]
    async fn status_names_states_and_overlaps_and_never_a_command_or_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("provider.bin");
        std::fs::write(&program, b"provider bytes").unwrap();
        let p = program.to_string_lossy().into_owned();
        let good = crate::util::hex(&Sha256::digest(b"provider bytes"));
        let canary = "--token=CANARY-7f3a91";
        let gone = dir.path().join("gone.bin").to_string_lossy().into_owned();
        let config = json!({
            "signInProviders": [
                {"name": "default", "command": [p, canary]},
                {"name": "pinned", "command": [p, canary], "caps": ["lookup", "create"], "pin": {&p: good},
                 "sites": ["https://a.test", "https://b.test"]},
                {"name": "changed", "command": [p], "caps": ["lookup"], "pin": {&p: "0".repeat(64)},
                 "sites": ["https://a.test"]},
                {"name": "missing", "command": [gone], "caps": ["lookup"], "pin": {&gone: good}},
            ],
            "signInSaveTo": "pinned",
            "signInProvider": null,
        });
        let shown = status(Some(&config), dir.path(), &MemoryVault::default()).await.unwrap();
        let by = |name: &str| {
            shown["providers"].as_array().unwrap().iter().find(|p| p["name"] == name).unwrap().clone()
        };
        assert_eq!(by("default")["pin"], "none");
        assert_eq!(by("default")["protocol"], 1);
        assert_eq!(by("default")["bare"], true);
        assert_eq!(by("default")["caps"], json!(["lookup", "totp"]));
        assert_eq!(by("pinned")["pin"], "ok");
        assert_eq!(by("pinned")["protocol"], 2);
        assert_eq!(by("pinned")["bare"], false);
        assert_eq!(by("changed")["pin"], "changed");
        assert_eq!(by("missing")["pin"], "missing");
        assert_eq!(shown["saveTo"], "pinned");
        assert_eq!(
            shown["overlaps"],
            json!([{"site": "https://a.test", "providers": ["pinned", "changed"], "asked": "pinned"}])
        );
        let text = shown.to_string();
        assert!(!text.contains("CANARY"), "no command line: {text}");
        assert!(!text.contains("provider.bin") && !text.contains("gone.bin"), "no path: {text}");
        // Nothing configured, and a list that does not check.
        assert_eq!(status(None, dir.path(), &MemoryVault::default()).await.unwrap()["providers"], json!([]));
        let twice =
            json!({"signInProviders": [{"name": "a", "command": [p]}, {"name": "a", "command": [p]}]});
        assert!(status(Some(&twice), dir.path(), &MemoryVault::default()).await.is_err());
    }
}
