//! Small helpers the service shell shares: randomness, and the JavaScript formatting rules that some
//! messages depend on.

use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::Value;

/// `n` random bytes from the OS as lowercase hex (`crypto.randomBytes(n).toString('hex')`).
///
/// # Errors
/// The OS refused randomness, which leaves nothing safe to make a token from.
pub fn random_hex(n: usize) -> std::io::Result<String> {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
    Ok(hex(&bytes))
}

/// A random version 4 UUID in its usual lowercase form (`crypto.randomUUID()`).
///
/// # Errors
/// The OS refused randomness.
pub fn uuid_v4() -> std::io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(std::io::Error::other)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `String(value)` for the values the bridge and service put into messages: a string as itself, an absent
/// value as `undefined`, anything else as its JSON (close enough for numbers, booleans and null).
#[must_use]
pub fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(_)) => "[object Object]".to_owned(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| if v.is_null() { String::new() } else { js_string(Some(v)) })
            .collect::<Vec<_>>()
            .join(","),
        Some(other) => other.to_string(),
    }
}

/// JavaScript truthiness of a JSON value.
#[must_use]
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::Array(_) | Value::Object(_) => true,
        Value::String(s) => !s.is_empty(),
    }
}

/// Seconds the way `${ms/1000}` prints them: `15`, `2.5`.
#[must_use]
pub fn js_seconds(d: Duration) -> String {
    let ms = d.as_millis();
    if ms.is_multiple_of(1000) {
        (ms / 1000).to_string()
    } else {
        let s = format!("{:.3}", d.as_secs_f64());
        s.trim_end_matches('0').to_owned()
    }
}

/// Locks a std mutex, taking the data back from a panicked holder: every guarded value here stays
/// consistent between statements, so a poisoned lock carries no half-made state.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Compares two secrets in time that does not depend on where they first differ (THREAT-MODEL SR-4,
/// `subtle`). A length mismatch answers early; the token's length is public.
#[must_use]
pub fn same_secret(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    a.ct_eq(b).into()
}

/// The longest client id, in UTF-16 units as JavaScript counts a string's length.
pub const CLIENT_ID_MAX: usize = 150;

/// A client id is 1 to [`CLIENT_ID_MAX`] characters (THREAT-MODEL SR-26). It labels a session's pages;
/// it is not authentication.
#[must_use]
pub fn client_id_ok(id: &str) -> bool {
    !id.is_empty() && id.encode_utf16().count() <= CLIENT_ID_MAX
}

/// Milliseconds since the Unix epoch as an ISO 8601 UTC string (`new Date().toISOString()`).
#[must_use]
pub fn iso_now() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    iso_from_millis(now.as_millis())
}

#[must_use]
pub fn iso_from_millis(ms: u128) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant), valid for every date this service will see.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// An fs error the way Node words it (`ENOENT: no such file or directory, open '<path>'`), for the
/// messages that pass an fs error through.
#[must_use]
pub fn node_fs_error(e: &std::io::Error, syscall: &str, path: &std::path::Path) -> String {
    use std::io::ErrorKind;
    let code = match e.kind() {
        ErrorKind::NotFound => "ENOENT: no such file or directory",
        ErrorKind::PermissionDenied => "EPERM: operation not permitted",
        ErrorKind::AlreadyExists => "EEXIST: file already exists",
        ErrorKind::NotADirectory => "ENOTDIR: not a directory",
        ErrorKind::IsADirectory => "EISDIR: illegal operation on a directory",
        _ => return format!("{e}, {syscall} '{}'", path.display()),
    };
    format!("{code}, {syscall} '{}'", path.display())
}

/// A JSON parse failure in about the words `JSON.parse` uses for the common case of no input.
#[must_use]
pub fn json_error(text: &[u8], e: &serde_json::Error) -> String {
    if text.iter().all(u8::is_ascii_whitespace) {
        "Unexpected end of JSON input".to_owned()
    } else {
        format!("Invalid JSON: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn uuid_has_the_v4_shape() {
        let u = uuid_v4().unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert!(matches!(&u[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn js_formatting() {
        assert_eq!(js_seconds(Duration::from_secs(15)), "15");
        assert_eq!(js_seconds(Duration::from_millis(2_500)), "2.5");
        assert_eq!(js_string(None), "undefined");
        assert_eq!(js_string(Some(&json!(2))), "2");
        assert_eq!(js_string(Some(&json!("x"))), "x");
    }

    #[test]
    fn iso_dates() {
        assert_eq!(iso_from_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_from_millis(1_793_750_400_123), "2026-11-04T00:00:00.123Z");
    }
}
