//! Credential holders (THREAT-MODEL SR-38). A value lives in one of these from the moment it leaves the
//! seal until the call ends; dropping it zeroizes the bytes. No `Display`, `Serialize` or `Clone`, and
//! `Debug` prints `[redacted]`, so neither a format string nor an error can carry one by accident.

use std::fmt;

use hmac::{KeyInit as _, Mac as _};
use phantab_cdp::FrameId;
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

type HmacSha256 = hmac::Hmac<Sha256>;

/// One saved-login value: a username, a password or a one-time code.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub(crate) fn new(value: String) -> Self {
        Secret(Zeroizing::new(value))
    }

    /// The value, for the one place that needs it: the page-call argument, the sweep's comparisons.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// Constant-time equality, so a sweep's comparison says nothing about how much of a field matched.
    pub(crate) fn matches(&self, other: &str) -> bool {
        self.0.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The values the provider released for one call, in fill order.
#[derive(Default)]
pub struct Values {
    pub(crate) username: Option<Secret>,
    pub(crate) password: Option<Secret>,
    pub(crate) code: Option<Secret>,
}

impl fmt::Debug for Values {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Values([redacted])")
    }
}

impl Values {
    /// `[values.password, values.code].filter(Boolean)`: what the sweep blanks wherever it sits.
    pub(crate) fn secrets(&self) -> Vec<&Secret> {
        [self.password.as_ref(), self.code.as_ref()]
            .into_iter()
            .flatten()
            .filter(|s| !s.expose().is_empty())
            .collect()
    }

    /// `values` as the page-call argument, keys in `want` order (`Object.keys(values)` is the fill order).
    /// The JSON value goes into the CDP layer, which does not zeroize (a gap the report names).
    pub(crate) fn page_argument(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (name, value) in
            [("username", &self.username), ("password", &self.password), ("code", &self.code)]
        {
            if let Some(v) = value {
                map.insert(name.to_owned(), Value::String(v.expose().to_owned()));
            }
        }
        Value::Object(map)
    }
}

/// What a sign-in that could not confirm its cleanup leaves on the page's record for the re-blank: a
/// keyed digest of the password and the code under a random key of its own, never a value (SR-38), and
/// the frames where one was filled or seen and not confirmed blanked. The re-blank finds a value by it in
/// whatever field the value now sits, of whatever type. Dropped, with its key zeroized, once the re-blank
/// confirms or the record goes.
pub struct Leftover {
    /// `None` when no random key could be had: then nothing can be confirmed, and the page stays held.
    key: Option<Zeroizing<[u8; 32]>>,
    digests: Vec<[u8; 32]>,
    frames: Vec<FrameId>,
}

impl fmt::Debug for Leftover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Leftover([redacted])")
    }
}

impl Leftover {
    pub(crate) fn new(secrets: &[&Secret], frames: Vec<FrameId>) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        if getrandom::fill(&mut key[..]).is_err() {
            return Leftover { key: None, digests: Vec::new(), frames };
        }
        let digests = secrets.iter().filter_map(|s| digest(&key, s.expose())).collect();
        Leftover { key: Some(key), digests, frames }
    }

    /// The frames whose failed read keeps the page held, besides the main frame.
    pub(crate) fn frames(&self) -> &[FrameId] {
        &self.frames
    }

    /// Whether the re-blank can tell a value at all (it has its key).
    pub(crate) fn can_check(&self) -> bool {
        self.key.is_some()
    }

    /// Whether `value` is the password or the code, in constant time per digest.
    pub(crate) fn holds(&self, value: &str) -> bool {
        let Some(key) = &self.key else { return false };
        if value.is_empty() || self.digests.is_empty() {
            return false;
        }
        let Some(seen) = digest(key, value) else { return false };
        self.digests.iter().fold(false, |any, d| any | bool::from(d.ct_eq(&seen)))
    }
}

fn digest(key: &[u8; 32], value: &str) -> Option<[u8; 32]> {
    digest_bytes(key, value.as_bytes())
}

fn digest_bytes(key: &[u8; 32], value: &[u8]) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(value);
    Some(mac.finalize().into_bytes().into())
}

/// What phantab writes where it took a value out of a result.
pub(crate) const REDACTED: &str = "[redacted]";

/// The modulus of [`Echo`]'s rolling hash, the Mersenne prime 2^61 - 1.
const ROLL_MOD: u64 = (1 << 61) - 1;
/// How many bits of a form's rolling hash [`Echo`] keeps: enough to skip nearly every window without a
/// digest, too few to say anything about a value (a 20-bit hint fits about a million values each).
const NEAR_BITS: u32 = 20;

fn roll_mul(a: u64, b: u64) -> u64 {
    let wide = u128::from(a) * u128::from(b);
    let folded = (wide & u128::from(ROLL_MOD)) + (wide >> 61);
    let folded = u64::try_from(folded).unwrap_or(u64::MAX);
    if folded >= ROLL_MOD { folded - ROLL_MOD } else { folded }
}

fn roll_add(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= ROLL_MOD { sum - ROLL_MOD } else { sum }
}

fn near(hash: u64) -> u32 {
    u32::try_from(hash & ((1 << NEAR_BITS) - 1)).unwrap_or(u32::MAX)
}

/// One form [`Echo`] looks for: its length, a 20-bit hint of its rolling hash, and its keyed digest.
struct EchoForm {
    len: usize,
    near: u32,
    digest: [u8; 32],
    /// The code: found only as a whole token, as the sweep finds it.
    token: bool,
}

/// What a sign-in whose sweep found the password or code shown back on the page leaves with the engine,
/// so the value never reaches the agent. Like [`Leftover`] it holds no value
/// (SR-38): each form the sweep looks for is kept as its length, a keyed digest under a random key of
/// its own, and a 20-bit hint of a rolling hash under a random base, which lets a scan skip a window
/// without a digest. [`Echo::redact`] finds each form in a text by the hint, confirms it by the digest,
/// and writes `[redacted]` in its place.
pub struct Echo {
    key: Zeroizing<[u8; 32]>,
    base: u64,
    forms: Vec<EchoForm>,
    password: bool,
}

impl fmt::Debug for Echo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Echo([redacted])")
    }
}

impl Echo {
    /// The forms of the password to redact, and the code as a whole token. `None` when no random key
    /// could be had: then nothing can be redacted, and the caller keeps the page held instead.
    pub(crate) fn new(forms: &[Secret], code: Option<&Secret>, password: bool) -> Option<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        let mut seed = Zeroizing::new([0u8; 8]);
        if getrandom::fill(&mut key[..]).is_err() || getrandom::fill(&mut seed[..]).is_err() {
            return None;
        }
        // A base in [2, 2^61 - 2], away from the degenerate 0 and 1.
        let base = 2 + u64::from_le_bytes(*seed) % (ROLL_MOD - 3);
        let mut echo = Echo { key, base, forms: Vec::new(), password };
        let found = forms.iter().map(|f| (f, false)).chain(code.map(|c| (c, true)));
        for (form, token) in found {
            let bytes = form.expose().as_bytes();
            if bytes.is_empty() {
                continue;
            }
            let digest = digest_bytes(&echo.key, bytes)?;
            if echo.forms.iter().any(|f| f.token == token && bool::from(f.digest.ct_eq(&digest))) {
                continue;
            }
            let near = near(echo.hash(bytes));
            echo.forms.push(EchoForm { len: bytes.len(), near, digest, token });
        }
        Some(echo)
    }

    /// Whether the password was among the values (else only the code was).
    pub fn password(&self) -> bool {
        self.password
    }

    fn hash(&self, bytes: &[u8]) -> u64 {
        bytes.iter().fold(0, |h, b| roll_add(roll_mul(h, self.base), u64::from(*b)))
    }

    /// `text` with every form in it written `[redacted]`, or `None` when it holds none.
    pub fn redact(&self, text: &str) -> Option<String> {
        let bytes = text.as_bytes();
        let mut lens: Vec<usize> = self.forms.iter().map(|f| f.len).collect();
        lens.sort_unstable();
        lens.dedup();
        let mut hits: Vec<(usize, usize)> = Vec::new();
        for len in lens {
            if bytes.len() < len {
                continue;
            }
            // base^(len-1): what the byte leaving the window weighs.
            let top = (1..len).fold(1, |p, _| roll_mul(p, self.base));
            let mut hash = self.hash(&bytes[..len]);
            let mut at = 0;
            loop {
                let hint = near(hash);
                if self.forms.iter().any(|f| f.len == len && f.near == hint)
                    && self.confirmed(text, at, len, hint)
                {
                    hits.push((at, at + len));
                }
                if at + len >= bytes.len() {
                    break;
                }
                let out = roll_mul(u64::from(bytes[at]), top);
                hash =
                    roll_add(roll_mul(roll_add(hash, ROLL_MOD - out), self.base), u64::from(bytes[at + len]));
                at += 1;
            }
        }
        if hits.is_empty() {
            return None;
        }
        hits.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in hits {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        let mut out = String::with_capacity(text.len());
        let mut done = 0;
        for (start, end) in merged {
            out.push_str(&text[done..start]);
            out.push_str(REDACTED);
            done = end;
        }
        out.push_str(&text[done..]);
        Some(out)
    }

    /// Whether the window at `at` is one of the forms whose hint is `hint`. An exact match of a form,
    /// itself whole characters, starts and ends on character boundaries; a window that does not is none.
    fn confirmed(&self, text: &str, at: usize, len: usize, hint: u32) -> bool {
        if !text.is_char_boundary(at) || !text.is_char_boundary(at + len) {
            return false;
        }
        let Some(seen) = digest_bytes(&self.key, &text.as_bytes()[at..at + len]) else { return false };
        let edge = |c: Option<char>| !c.is_some_and(char::is_alphanumeric);
        let whole = edge(text[..at].chars().next_back()) && edge(text[at + len..].chars().next());
        self.forms
            .iter()
            .filter(|f| f.len == len && f.near == hint)
            .fold(false, |any, f| any | (bool::from(f.digest.ct_eq(&seen)) && (!f.token || whole)))
    }
}

/// Zeroizes every string in a JSON value from the page or the seal before it is dropped: a read of the
/// inputs carries the filled values back, and an unsealed payload carries them all.
pub(crate) fn scrub(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(map) => map.values_mut().for_each(scrub),
        _ => {}
    }
}

/// A JSON value that is scrubbed when dropped.
pub(crate) struct Scrubbed(pub(crate) Value);

impl Drop for Scrubbed {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

impl fmt::Debug for Scrubbed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "S3ntinel pw+/=!";

    #[test]
    fn debug_prints_no_value() {
        let s = Secret::new(PW.to_owned());
        assert_eq!(format!("{s:?}"), "[redacted]");
        assert_eq!(format!("{s:#?}"), "[redacted]");
        let v = Values { username: Some(Secret::new("u".into())), password: Some(s), code: None };
        let text = format!("{v:?} {v:#?}");
        assert!(!text.contains(PW) && !text.contains("S3ntinel"), "{text}");
        let sc = Scrubbed(serde_json::json!({ "p": PW }));
        assert!(!format!("{sc:?}").contains(PW));
    }

    #[test]
    fn matches_and_order() {
        let v = Values {
            username: Some(Secret::new("u".into())),
            password: Some(Secret::new(PW.into())),
            code: Some(Secret::new(String::new())),
        };
        assert!(v.password.as_ref().is_some_and(|p| p.matches(PW)));
        assert!(!v.password.as_ref().is_some_and(|p| p.matches("S3ntinel")));
        // An empty code is not a secret to look for (filter(Boolean)).
        assert_eq!(v.secrets().len(), 1);
        let arg = v.page_argument();
        let keys: Vec<_> = arg.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
        assert_eq!(keys, ["username", "password", "code"]);
    }

    #[test]
    fn leftover_knows_a_value_only_by_its_digest() {
        let (pw, code) = (Secret::new(PW.into()), Secret::new("123456".into()));
        let l = Leftover::new(&[&pw, &code], vec![FrameId("F".into())]);
        assert!(l.can_check());
        assert!(l.holds(PW) && l.holds("123456"));
        assert!(!l.holds("S3ntinel") && !l.holds("") && !l.holds("1234567"));
        assert_eq!(l.frames(), [FrameId("F".into())]);
        assert_eq!(format!("{l:?}"), "Leftover([redacted])");
        // Another sign-in's leftover has its own key: the same value, another digest.
        let other = Leftover::new(&[&pw], Vec::new());
        assert_ne!(l.digests[0], other.digests[0]);
        // A username-only sign-in leaves nothing to look for.
        assert!(!Leftover::new(&[], Vec::new()).holds(PW));
    }

    #[test]
    fn an_echo_redacts_each_form_found_by_its_digest_alone() {
        let forms: Vec<Secret> =
            [PW, "S3ntinel%20pw%2B%2F%3D!", "UzNudGluZWwgcHcrLz0h"].map(|f| Secret::new(f.into())).into();
        let code = Secret::new("914207".into());
        let e = Echo::new(&forms, Some(&code), true).unwrap();
        assert!(e.password());
        assert_eq!(format!("{e:?}"), "Echo([redacted])");
        for (text, want) in [
            ("You typed S3ntinel pw+/=!", "You typed [redacted]"),
            ("?t=S3ntinel%20pw%2B%2F%3D!&x=1", "?t=[redacted]&x=1"),
            ("#UzNudGluZWwgcHcrLz0h", "#[redacted]"),
            ("S3ntinel pw+/=!", "[redacted]"),
            ("S3ntinel pw+/=!S3ntinel pw+/=! é", "[redacted] é"),
            ("é S3ntinel pw+/=! ü S3ntinel pw+/=!", "é [redacted] ü [redacted]"),
            ("Your code 914207.", "Your code [redacted]."),
            ("code=914207&next=S3ntinel pw+/=!", "code=[redacted]&next=[redacted]"),
        ] {
            assert_eq!(e.redact(text).as_deref(), Some(want), "{want}");
        }
        // Not a form: a near miss, the code inside a longer number, nothing at all.
        for text in ["S3ntinel pw+/=", "s3ntinel pw+/=!", "order 19142078", "x914207", "", "short"] {
            assert_eq!(e.redact(text), None, "{text:?}");
        }
        // Another echo has its own key and base.
        let other = Echo::new(&forms[..1], None, false).unwrap();
        assert!(!other.password());
        assert_ne!(other.forms[0].digest, e.forms[0].digest);
        assert_eq!(other.redact("Your code 914207"), None);
        // Nothing to look for: nothing redacted.
        assert_eq!(Echo::new(&[], None, false).unwrap().redact(PW), None);
    }

    #[test]
    fn scrub_clears_every_string() {
        let mut v = serde_json::json!({ "a": [PW, { "b": PW }], "n": 1 });
        scrub(&mut v);
        assert!(!v.to_string().contains("S3ntinel"));
    }
}
