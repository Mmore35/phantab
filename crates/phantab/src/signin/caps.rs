//! What a credential source can do (docs/VAULTS.md § Capabilities; THREAT-MODEL SR-87). The chain asks a
//! source only for what it declared, as git's and docker's credential helpers do: a source that never
//! said `create` is never sent a sign-up's password.

use serde_json::Value;

/// A set of capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Caps(u8);

impl Caps {
    /// Find the saved login for a page and answer its username and password.
    pub(crate) const LOOKUP: Caps = Caps(1);
    /// Answer the login's one-time code.
    pub(crate) const TOTP: Caps = Caps(1 << 1);
    /// Save a new login made at sign-up.
    pub(crate) const CREATE: Caps = Caps(1 << 2);
    /// Change a saved login. Declared; nothing asks for it yet.
    pub(crate) const UPDATE: Caps = Caps(1 << 3);
    /// Hand a passkey's private key to phantab's virtual authenticator. Declared; no source answers it
    /// until passkey sign-in is built.
    pub(crate) const PASSKEY_RELEASE: Caps = Caps(1 << 4);
    /// Sign a passkey challenge inside the vault, the key never leaving it. Declared only.
    pub(crate) const PASSKEY_SIGN: Caps = Caps(1 << 5);
    /// Remove a saved login. Declared only.
    pub(crate) const DELETE: Caps = Caps(1 << 6);

    /// Every capability by the name a config gives it, in the order `phantab vaults status` shows them.
    pub(crate) const NAMES: &'static [(&'static str, Caps)] = &[
        ("lookup", Caps::LOOKUP),
        ("totp", Caps::TOTP),
        ("create", Caps::CREATE),
        ("update", Caps::UPDATE),
        ("passkey-release", Caps::PASSKEY_RELEASE),
        ("passkey-sign", Caps::PASSKEY_SIGN),
        ("delete", Caps::DELETE),
    ];

    /// The capabilities a protocol-v2 command provider may declare today: the ones phantab sends it an
    /// operation for. A name in [`Caps::NAMES`] outside this set is refused in a config, so a provider is
    /// never trusted with an operation whose checks are not written yet.
    pub(crate) const COMMAND_V2: Caps = Caps(Caps::LOOKUP.0 | Caps::TOTP.0 | Caps::CREATE.0);

    /// The union of two sets.
    #[must_use]
    pub(crate) const fn with(self, other: Caps) -> Caps {
        Caps(self.0 | other.0)
    }

    /// Whether every capability in `other` is in this set.
    #[must_use]
    pub(crate) const fn has(self, other: Caps) -> bool {
        self.0 & other.0 == other.0
    }

    /// The set's names, in [`Caps::NAMES`] order.
    pub(crate) fn names(self) -> Vec<&'static str> {
        Caps::NAMES.iter().filter(|(_, c)| self.has(*c)).map(|(n, _)| *n).collect()
    }

    /// A config's `caps` array: known names only, each at most once, at least one, and only those in
    /// `allowed`.
    ///
    /// # Errors
    /// Not an array of strings, empty, an unknown, repeated or not-allowed name: why, for the owner.
    pub(crate) fn parse(value: &Value, allowed: Caps) -> Result<Caps, String> {
        let names = value.as_array().ok_or("caps must be an array of capability names")?;
        if names.is_empty() {
            return Err("caps must name at least one capability".into());
        }
        let mut caps = Caps::default();
        for name in names {
            let name = name.as_str().ok_or("caps must be an array of capability names")?;
            let Some((_, cap)) = Caps::NAMES.iter().find(|(n, _)| *n == name) else {
                return Err(format!("unknown capability {name:?}"));
            };
            if caps.has(*cap) {
                return Err(format!("capability {name:?} is named twice"));
            }
            if !allowed.has(*cap) {
                return Err(format!("capability {name:?} is not offered to this source yet"));
            }
            caps = caps.with(*cap);
        }
        if !caps.has(Caps::LOOKUP) && caps.has(Caps::TOTP) {
            return Err("capability \"totp\" needs \"lookup\"".into());
        }
        Ok(caps)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn caps_parse_known_names_once() {
        let all = Caps::NAMES.iter().fold(Caps::default(), |a, (_, c)| a.with(*c));
        assert_eq!(Caps::parse(&json!(["lookup"]), all), Ok(Caps::LOOKUP));
        assert_eq!(
            Caps::parse(&json!(["create", "lookup", "totp"]), all).map(Caps::names),
            Ok(vec!["lookup", "totp", "create"])
        );
        assert_eq!(Caps::parse(&json!(["create"]), all), Ok(Caps::CREATE), "a write-only vault");
        for bad in [
            json!([]),
            json!("lookup"),
            json!(["lookup", "lookup"]),
            json!(["Lookup"]),
            json!(["lookup", 5]),
            json!(["teleport"]),
            json!(["totp"]),
            json!(null),
        ] {
            assert!(Caps::parse(&bad, all).is_err(), "{bad}");
        }
        assert!(Caps::parse(&json!(["lookup", "passkey-release"]), Caps::COMMAND_V2).is_err());
        assert!(Caps::parse(&json!(["delete"]), Caps::COMMAND_V2).is_err());
    }

    #[test]
    fn sets_combine() {
        let s = Caps::LOOKUP.with(Caps::TOTP);
        assert!(s.has(Caps::LOOKUP) && s.has(Caps::TOTP) && s.has(s));
        assert!(!s.has(Caps::CREATE));
        assert!(!s.has(Caps::LOOKUP.with(Caps::CREATE)));
        assert_eq!(Caps::default().names(), Vec::<&str>::new());
        assert_eq!(Caps::NAMES.len(), 7);
    }
}
