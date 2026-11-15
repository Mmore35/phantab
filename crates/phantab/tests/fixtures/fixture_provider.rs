//! The stand-in password manager the provider tests drive (docs/VAULTS.md § Conformance kit). Its vault is
//! a JSON file of made-up logins; it is never a real vault, and its log holds what was asked, never a
//! value.
//!
//! `phantab-fixture-provider <vault.json> <public key>`. It speaks protocol v1 (a sign-in with no `v`)
//! and v2 (`sign-in` and `create`), and answers sealed to the digest of the exact request it read.
//!
//! Vault fields:
//! - `logins`: `[{id, origin, username, password, totp?}]`. A sign-in matches a login whose origin is
//!   one of the request's URL origins, then by `accountKey` (the login's `id`) or `account` (its
//!   username). None is `none`, more than one is `ambiguous` with the count, one is sealed with the
//!   login's `id` as its account key. `code` without a `totp` is `wall code-not-saved`.
//! - `create` writes the vault back: the login for this origin and username is `existing` (its saved
//!   password, unless `regenerate`), `replaced` (with `regenerate`) or `new`.
//! - `log`: a JSON-lines file; each line is the operation and the request's field names only.
//! - `behave`: how to misbehave instead of answering: `slow` (sleep 30 s), `crash` (exit 3 with no
//!   output), `huge` (a line over phantab's 256 KiB output cap), `unsealed` (the values in the clear),
//!   `extra-field` (an unknown key inside the seal), `extra-plain` (an unknown key on a plain answer),
//!   `bad-digest`, `locked`, `garbage` (not JSON).

use std::io::{Read as _, Write as _};

use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let vault_path = args.get(1).ok_or("no vault file")?.clone();
    let public_key = args.last().ok_or("no public key")?.clone();
    let mut vault: Value = serde_json::from_str(&std::fs::read_to_string(&vault_path)?)?;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: Value = serde_json::from_str(&input)?;
    let operation = match request.get("v").and_then(Value::as_u64) {
        None => "sign-in".to_owned(),
        Some(2) => request.get("operation").and_then(Value::as_str).unwrap_or("").to_owned(),
        Some(_) => String::new(),
    };
    if let Some(log) = vault.get("log").and_then(Value::as_str) {
        let fields: Vec<&String> = request.as_object().map(|m| m.keys().collect()).unwrap_or_default();
        let line = json!({"operation": operation, "fields": fields});
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
        file.write_all(format!("{line}\n").as_bytes())?;
    }
    let digest = phantab::util::hex(&Sha256::digest(input.as_bytes()));
    let behave = vault.get("behave").and_then(Value::as_str).unwrap_or("").to_owned();
    match behave.as_str() {
        "slow" => std::thread::sleep(std::time::Duration::from_secs(30)),
        "crash" => std::process::exit(3),
        "huge" => return say(&"x".repeat(300_000)),
        "garbage" => return say("this is not json"),
        "locked" => return say(&json!({"status": "locked"}).to_string()),
        "extra-plain" => return say(&json!({"status": "none", "hint": "unasked"}).to_string()),
        _ => {}
    }
    let sealed = match operation.as_str() {
        "sign-in" => match sign_in(&vault, &request) {
            Ok(payload) => payload,
            Err(plain) => return say(&plain.to_string()),
        },
        "create" => {
            let payload = create(&mut vault, &request);
            std::fs::write(&vault_path, serde_json::to_string_pretty(&vault)?)?;
            payload
        }
        _ => return say(&json!({"status": "provider-failed"}).to_string()),
    };
    let mut payload = sealed;
    payload.insert("digest".into(), json!(if behave == "bad-digest" { "0".repeat(64) } else { digest }));
    if behave == "extra-field" {
        payload.insert("note".into(), json!("unasked"));
    }
    let payload = Value::Object(payload);
    if behave == "unsealed" {
        return say(&json!({"status": "ok", "values": payload["values"]}).to_string());
    }
    let sealed = phantab::signin::seal(&public_key, &payload)?;
    say(&json!({"status": "ok", "sealed": sealed}).to_string())
}

/// A sign-in: the sealed payload's fields besides the digest, or the plain answer.
fn sign_in(vault: &Value, request: &Value) -> std::result::Result<Map<String, Value>, Value> {
    let origins: Vec<String> = request
        .get("urls")
        .and_then(Value::as_array)
        .map(|urls| urls.iter().filter_map(Value::as_str).filter_map(origin).collect())
        .unwrap_or_default();
    let account_key = request.get("accountKey").and_then(Value::as_str);
    let account = request.get("account").and_then(Value::as_str);
    let found: Vec<&Value> = logins(vault)
        .iter()
        .filter(|l| l["origin"].as_str().is_some_and(|o| origins.iter().any(|u| u == o)))
        .filter(|l| account_key.is_none_or(|k| l["id"] == k))
        .filter(|l| account.is_none_or(|a| l["username"] == a))
        .collect();
    let login = match found.as_slice() {
        [] => return Err(json!({"status": "none"})),
        [one] => *one,
        many => return Err(json!({"status": "ambiguous", "count": many.len()})),
    };
    let mut values = Map::new();
    for name in request.get("want").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
    {
        let field = if name == "code" { "totp" } else { name };
        match login.get(field).and_then(Value::as_str) {
            Some(v) => values.insert(name.to_owned(), json!(v)),
            None if name == "code" => return Err(json!({"status": "wall", "reason": "code-not-saved"})),
            None => return Err(json!({"status": "provider-failed"})),
        };
    }
    let mut out = Map::new();
    out.insert("accountKey".into(), login["id"].clone());
    out.insert("values".into(), Value::Object(values));
    Ok(out)
}

/// A create: saves (or keeps) the login and answers which it is, with the password it now holds.
fn create(vault: &mut Value, request: &Value) -> Map<String, Value> {
    let field = |name: &str| request.get(name).and_then(Value::as_str).unwrap_or("").to_owned();
    let (origin, username, password) = (field("origin"), field("username"), field("password"));
    let regenerate = request.get("regenerate").and_then(Value::as_bool).unwrap_or(false);
    let list = vault.as_object_mut().map(|m| m.entry("logins").or_insert_with(|| json!([])));
    let Some(Value::Array(list)) = list else { return Map::new() };
    let at = list.iter().position(|l| l["origin"] == origin.as_str() && l["username"] == username.as_str());
    let (saved, held) = match at {
        Some(i) if !regenerate => ("existing", list[i]["password"].as_str().unwrap_or("").to_owned()),
        Some(i) => {
            list[i]["password"] = json!(password);
            ("replaced", password)
        }
        None => {
            let id = format!("fixture-{}", list.len() + 1);
            list.push(json!({"id": id, "origin": origin, "username": username, "password": password}));
            ("new", password)
        }
    };
    let mut out = Map::new();
    out.insert("saved".into(), json!(saved));
    out.insert("values".into(), json!({"password": held}));
    out
}

fn logins(vault: &Value) -> &[Value] {
    vault.get("logins").and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// `scheme://host[:port]` of a URL, lower-cased; `None` for anything without one.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then(|| format!("{}://{}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

fn say(line: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(line.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
