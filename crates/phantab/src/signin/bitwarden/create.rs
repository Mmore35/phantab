//! `browser_sign_up`'s save in the owner's vault (THREAT-MODEL SR-78 to SR-83;
//! docs/BITWARDEN.md § Sign-up). One call: the page `https` → ask-first sites → the stored session, as a
//! sign-in opens it → one `bw list items --url <origin>` → the logins saved for this exact origin and
//! username. One, and no `regenerate`: its password is the answer (`existing`). Otherwise phantab makes
//! a new one ([`generate`]) and saves it before anything is filled: `bw create item` (a new login) or
//! `bw edit item <id>` (`regenerate`), the encoded login on the child's stdin, never its command line →
//! `bw get item <id>` reads it back, and only a read-back that holds the same password and username is
//! answered → `bw sync`, best effort.

use base64::Engine as _;
use serde_json::{Value, json};
use tokio::time::Instant;
use zeroize::{Zeroize as _, Zeroizing};

use super::cli::{self, Call, Ran};
use super::{BitwardenSource, matching, no_reprompt, now_millis, policy, take};
use crate::signin::Outcome;
use crate::signin::generate;
use crate::signin::secret::{Scrubbed, Secret};
use crate::signin::source::{CreateRequest, Saved};

/// What a failed `bw` command answers: as a sign-in's do.
fn failed(ran: &Ran) -> Outcome {
    match ran {
        Ran::TimedOut => Outcome::of("busy"),
        Ran::Unpinned => Outcome::of("locked"),
        Ran::Out(_) | Ran::Failed | Ran::TooBig => Outcome::of("provider-failed"),
    }
}

/// One `bw` command's JSON output, scrubbed when it is dropped.
async fn json_of(c: &super::config::Config, call: &Call<'_>, deadline: Instant) -> Result<Scrubbed, Outcome> {
    let raw = match cli::run(c, call, deadline).await {
        Ran::Out(out) => out,
        other => return Err(failed(&other)),
    };
    let parsed = serde_json::from_slice::<Value>(&raw);
    drop(raw);
    Ok(Scrubbed(parsed.map_err(|_| Outcome::of("provider-failed"))?))
}

/// A login saved for exactly this origin (one of its entries is it) and exactly this username.
fn same_login(item: &Value, origin: &matching::Origin, username: &str) -> bool {
    item.get("type").and_then(Value::as_i64) == Some(1)
        && item.pointer("/login/username").and_then(Value::as_str) == Some(username)
        && matching::entries(item).iter().any(|(uri, _)| matching::entry_origin(uri).as_ref() == Some(origin))
}

/// A string field set to `value` in place: the old text is zeroized first, so no copy of an old password
/// is left behind when the field is replaced.
fn set_string(item: &mut Value, pointer: &str, value: &str) -> Option<()> {
    match item.pointer_mut(pointer)? {
        Value::String(s) => {
            s.zeroize();
            s.push_str(value);
        }
        other => *other = Value::String(value.to_owned()),
    }
    Some(())
}

/// The login as `bw create item` and `bw edit item` read it: its JSON, base64. Both buffers are allocated
/// once at their final size, so neither grows and leaves a copy of the password behind.
fn encoded(item: &Value, password_len: usize) -> Option<Zeroizing<String>> {
    // The item's size without the password, then room for the password at its longest JSON escape.
    let mut bare = Scrubbed(item.clone());
    set_string(&mut bare.0, "/login/password", "")?;
    let without = serde_json::to_vec(&bare.0).ok().map(Zeroizing::new)?.len();
    drop(bare);
    let mut text = Zeroizing::new(Vec::with_capacity(without + password_len * 6 + 16));
    serde_json::to_writer(&mut *text, item).ok()?;
    let mut out = Zeroizing::new(String::with_capacity(base64::encoded_len(text.len(), true)?));
    base64::engine::general_purpose::STANDARD.encode_string(&*text, &mut out);
    Some(out)
}

impl BitwardenSource {
    /// The password for `request`, saved and read back, and which login it is.
    pub(super) async fn make(
        &self,
        request: &CreateRequest,
        deadline: Instant,
    ) -> Result<(Secret, Saved), Outcome> {
        let c = &self.config;
        let origin = matching::page_origin(&request.origin).ok_or(Outcome::of("refused"))?;
        let sites = policy::sites(&c.ask_first, c.policy_file.as_deref(), now_millis())
            .map_err(|()| Outcome::of("refused"))?;
        if sites.iter().any(|s| policy::host_on(origin.host(), s)) {
            return Err(Outcome::of("ask-first"));
        }
        let session = self.open_vault(deadline).await?;
        let mut list = json_of(
            c,
            &Call::new(&["list", "items", "--url", &request.origin, "--raw"], Some(&session)),
            deadline,
        )
        .await?;
        let Some(items) = list.0.as_array_mut() else { return Err(Outcome::of("provider-failed")) };
        let found: Vec<usize> =
            (0..items.len()).filter(|&i| same_login(&items[i], &origin, &request.username)).collect();
        let found = match found.as_slice() {
            [] => None,
            [one] => Some(&mut items[*one]),
            many => {
                return Err(Outcome { count: i64::try_from(many.len()).ok(), ..Outcome::of("ambiguous") });
            }
        };
        if let Some(item) = found.as_deref() {
            if !no_reprompt(item.get("reprompt")) {
                // The owner asked Bitwarden for the master password before this login is used or changed.
                return Err(Outcome::of("refused"));
            }
            if matching::entries(item).iter().any(|(uri, _)| sites.iter().any(|s| policy::uri_names(uri, s)))
            {
                return Err(Outcome::of("ask-first"));
            }
        }
        let (mut login, id) = match found {
            Some(item) if !request.regenerate => {
                // A saved login without a password is changed only when the agent asks to regenerate.
                let password = take(item, "/login/password").ok_or(Outcome::of("refused"))?;
                return Ok((password, Saved::Existing));
            }
            Some(item) => {
                let id =
                    item.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()).map(str::to_owned);
                (Scrubbed(item.clone()), Some(id.ok_or(Outcome::of("provider-failed"))?))
            }
            None => (Scrubbed(new_login(request)), None),
        };
        drop(list);
        let password = generate::password(&request.rules).ok_or(Outcome::of("provider-failed"))?;
        if login.0.pointer("/login/password").is_none()
            && let Some(Value::Object(fields)) = login.0.get_mut("login")
        {
            fields.insert("password".into(), Value::String(String::new()));
        }
        set_string(&mut login.0, "/login/password", password.expose())
            .ok_or(Outcome::of("provider-failed"))?;
        let input = encoded(&login.0, password.expose().len()).ok_or(Outcome::of("provider-failed"))?;
        drop(login);
        let write: Vec<&str> = match &id {
            Some(id) => vec!["edit", "item", id],
            None => vec!["create", "item"],
        };
        let saved = json_of(
            c,
            &Call { stdin: Some(input.as_bytes()), ..Call::new(&write, Some(&session)) },
            deadline,
        )
        .await?;
        drop(input);
        let saved_id = saved.0.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()).map(str::to_owned);
        // It prints the whole login back, the password with it.
        drop(saved);
        let saved_id = saved_id.ok_or(Outcome::of("provider-failed"))?;
        if id.as_ref().is_some_and(|id| *id != saved_id) {
            return Err(Outcome::of("provider-failed"));
        }
        // What the vault now holds, read back by its id: only the same password and username are answered.
        let mut back = json_of(c, &Call::new(&["get", "item", &saved_id], Some(&session)), deadline).await?;
        let held = same_login(&back.0, &origin, &request.username)
            && take(&mut back.0, "/login/password").is_some_and(|p| {
                crate::util::same_secret(p.expose().as_bytes(), password.expose().as_bytes())
            });
        drop(back);
        if !held {
            return Err(Outcome::of("provider-failed"));
        }
        // Offline or refused, the write already reached the server: the next sign-in's sync picks it up.
        let _ = cli::run(c, &Call::new(&["sync"], Some(&session)), deadline).await;
        Ok((password, if id.is_some() { Saved::Replaced } else { Saved::New }))
    }
}

/// A new login as `bw get template item` shapes one, without its password yet: one entry, the page's
/// origin, matched by Bitwarden's default.
fn new_login(request: &CreateRequest) -> Value {
    json!({
        "organizationId": null,
        "collectionIds": null,
        "folderId": null,
        "type": 1,
        "name": request.name,
        "notes": null,
        "favorite": false,
        "fields": [],
        "login": {
            "uris": [{"match": null, "uri": request.origin}],
            "username": request.username,
            "password": "",
            "totp": null,
        },
        "reprompt": 0,
    })
}
