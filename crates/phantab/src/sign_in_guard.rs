//! The sign-in guard file: per saved account, its hosts, recent password sends
//! and whether sign-in was stopped. No secret in it. Read at each call, so `sign-in-clear` works with
//! no service running, and with a damaged file, which is one reason to run it.
//!
//! An empty path is no guard: it reads as an empty guard and every write is skipped, so nothing is
//! counted or stopped. The engine passes one unless `guardrails` is `full` (`docs/GUARDRAILS.md`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    /// Not JSON, or not version 1 with an accounts object.
    #[error("damaged")]
    Damaged,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A file that parses but holds the wrong shapes inside an account.
    #[error("{0}")]
    Invalid(String),
}

fn empty() -> Value {
    json!({ "version": 1, "accounts": {} })
}

/// No guard: see the module docs.
fn off(file: &Path) -> bool {
    file.as_os_str().is_empty()
}

/// # Errors
/// Unreadable or damaged. A missing file is an empty guard.
pub fn read_guard(file: &Path) -> Result<Value, GuardError> {
    if off(file) {
        return Ok(empty());
    }
    let text = match std::fs::read(file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(empty()),
        Err(e) => return Err(e.into()),
    };
    let data: Value = serde_json::from_slice(&text).map_err(|_| GuardError::Damaged)?;
    if data.get("version") != Some(&json!(1)) || !data.get("accounts").is_some_and(Value::is_object) {
        return Err(GuardError::Damaged);
    }
    Ok(data)
}

/// Writes through an owner-only temp file, synced, then renamed in place. The rename is retried
/// because on Windows a reader holding the old file briefly blocks it.
///
/// # Errors
/// The temp file could not be written or renamed.
pub async fn write_guard(file: &Path, data: &Value) -> Result<(), GuardError> {
    if off(file) {
        return Ok(());
    }
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    {
        use std::io::Write as _;
        // A stale temp file from a crash is removed (a link itself, never its target), and the new one
        // must be new, so a planted link is never followed.
        let _ = std::fs::remove_file(&tmp);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp)?;
        f.write_all(&serde_json::to_vec(data).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
    }
    let mut attempt = 0;
    loop {
        match std::fs::rename(&tmp, file) {
            Ok(()) => return Ok(()),
            Err(e) if attempt >= 8 => return Err(e.into()),
            Err(_) => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// One read-change-write at a time in this process, so two sign-ins never lose each other's counts.
static CHAIN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Reads, changes and writes the guard under the in-process chain.
///
/// # Errors
/// Reading, the change or writing failed; the file is then as it was.
pub async fn guard_write<F>(file: &Path, change: F) -> Result<(), GuardError>
where
    F: FnOnce(&mut Value) -> Result<(), GuardError> + Send,
{
    if off(file) {
        return Ok(());
    }
    let _turn = CHAIN.lock().await;
    let mut data = read_guard(file)?;
    change(&mut data)?;
    write_guard(file, &data).await
}

/// Clears the stop on every account that lists `host`, or with `all` removes the file, which also
/// resets a damaged one. A rule for agents to run only on the owner's word, not a lock.
///
/// # Errors
/// Damaged, unreadable or unwritable.
pub async fn clear_guard(file: &Path, host: &str) -> Result<Value, GuardError> {
    if host == "all" {
        match std::fs::remove_file(file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        return Ok(json!({ "cleared": "all" }));
    }
    let host = host.to_lowercase();
    let mut cleared = 0u64;
    guard_write(file, |data| {
        let Some(accounts) = data.get_mut("accounts").and_then(Value::as_object_mut) else {
            return Err(GuardError::Damaged);
        };
        for entry in accounts.values_mut() {
            if !entry.get("stopped").is_some_and(crate::util::truthy) {
                continue;
            }
            let Some(hosts) = entry.get("hosts").and_then(Value::as_array) else {
                return Err(GuardError::Invalid("entry.hosts.includes is not a function".to_owned()));
            };
            if hosts.iter().any(|h| h.as_str() == Some(host.as_str())) {
                entry["stopped"] = Value::Null;
                cleared += 1;
            }
        }
        Ok(())
    })
    .await?;
    Ok(json!({ "cleared": cleared }))
}

// ---- What a sign-in reads and writes. ----------------------------------------------------------------

/// Password sends allowed per account in an hour and in a day (`SUBMITS_PER_HOUR`, `SUBMITS_PER_DAY`).
pub const SUBMITS_PER_HOUR: usize = 2;
pub const SUBMITS_PER_DAY: usize = 6;
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// Milliseconds since the Unix epoch, now.
#[must_use]
pub fn now_millis() -> i64 {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    i64::try_from(now.as_millis()).unwrap_or(i64::MAX)
}

/// `new Date(ms).toISOString()`, as the guard file stores a send.
#[must_use]
pub fn iso(ms: i64) -> String {
    crate::util::iso_from_millis(u128::try_from(ms).unwrap_or(0))
}

fn digits(s: &[u8]) -> Option<i64> {
    s.iter().all(u8::is_ascii_digit).then(|| s.iter().fold(0i64, |n, d| n * 10 + i64::from(d - b'0')))
}

/// `Date.parse(t)` for the timestamps this file holds: the ISO 8601 form `toISOString` writes
/// (`YYYY-MM-DDTHH:mm:ss.sssZ`), with the seconds or the fraction optional and `±HH:mm` for `Z`.
/// `None` (NaN) for anything else, which then counts as no send, since NaN compares false in Node.
/// Stricter than V8's fallback parser, which also reads forms like `5` or `Nov 4 2026`.
#[must_use]
pub fn parse_iso_millis(v: &Value) -> Option<i64> {
    let src = v.as_str()?.as_bytes();
    let num = |from: usize, len: usize| src.get(from..from + len).and_then(digits);
    let at = |i: usize, c: u8| src.get(i) == Some(&c);
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    if !(at(4, b'-') && at(7, b'-') && at(10, b'T') && at(13, b':')) {
        return None;
    }
    let (hour, minute) = (num(11, 2)?, num(14, 2)?);
    let (mut i, mut second, mut millis) = (16, 0, 0);
    if at(i, b':') {
        second = num(i + 1, 2)?;
        i += 3;
        if at(i, b'.') {
            let width = src[i + 1..].iter().take_while(|b| b.is_ascii_digit()).count();
            if width == 0 {
                return None;
            }
            // V8 keeps the first three digits.
            let kept = width.min(3);
            millis = digits(&src[i + 1..i + 1 + kept])? * [100, 10, 1][kept - 1];
            i += 1 + width;
        }
    }
    let offset = match src.get(i..) {
        Some(b"Z") => 0,
        Some([sign @ (b'+' | b'-'), _, _, b':', _, _]) => {
            let (off_h, off_m) = (num(i + 1, 2)?, num(i + 4, 2)?);
            if off_h > 23 || off_m > 59 {
                return None;
            }
            if *sign == b'+' { (off_h * 60 + off_m) * 60_000 } else { -(off_h * 60 + off_m) * 60_000 }
        }
        _ => return None,
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&month) || day < 1 || day > days_in[usize::try_from(month - 1).ok()?] {
        return None;
    }
    // 24:00:00.000 is the next day's midnight; any other time past 23:59 is invalid.
    if hour > 24 || minute > 59 || second > 59 || (hour == 24 && (minute, second, millis) != (0, 0, 0)) {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some((((days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + millis - offset)
}

fn accounts(data: &Value) -> Result<&serde_json::Map<String, Value>, GuardError> {
    data.get("accounts").and_then(Value::as_object).ok_or(GuardError::Damaged)
}

/// `entry.stopped.reason==='unknown'?'unknown':'rejected'`, for an entry whose `stopped` is truthy.
fn stop_label(entry: &Value) -> Option<&'static str> {
    let stopped = entry.get("stopped").filter(|s| crate::util::truthy(s))?;
    Some(if stopped.get("reason").and_then(Value::as_str) == Some("unknown") {
        "unknown"
    } else {
        "rejected"
    })
}

/// The stop on any account that lists one of `hosts`, as the agent hears it (`unknown` or `rejected`).
///
/// # Errors
/// A malformed entry (`null`, or a stopped entry whose `hosts` is not an array) is an error, and the
/// call then ends `failed` / `error`.
pub fn host_stopped(data: &Value, hosts: &[String]) -> Result<Option<&'static str>, GuardError> {
    for entry in accounts(data)?.values() {
        if entry.is_null() {
            return Err(GuardError::Invalid("Cannot read properties of null (reading 'stopped')".to_owned()));
        }
        let Some(label) = stop_label(entry) else { continue };
        let Some(listed) = entry.get("hosts").and_then(Value::as_array) else {
            return Err(GuardError::Invalid("entry.hosts.some is not a function".to_owned()));
        };
        if listed.iter().any(|h| h.as_str().is_some_and(|h| hosts.iter().any(|x| x == h))) {
            return Ok(Some(label));
        }
    }
    Ok(None)
}

/// `guard.accounts[key]?.stopped`, as the agent hears it.
///
/// # Errors
/// Damaged (no accounts object).
pub fn account_stopped(data: &Value, key: &str) -> Result<Option<&'static str>, GuardError> {
    Ok(accounts(data)?.get(key).and_then(stop_label))
}

/// Whether a password send now would pass [`SUBMITS_PER_HOUR`] or [`SUBMITS_PER_DAY`] for `key`. An
/// account with no entry has sent nothing.
///
/// # Errors
/// The entry's `submits` is not an array (Node's `entry.submits.map` throws: `failed` / `error`).
pub fn over_limit(data: &Value, key: &str, now: i64) -> Result<bool, GuardError> {
    let Some(entry) = accounts(data)?.get(key).filter(|e| crate::util::truthy(e)) else { return Ok(false) };
    let Some(submits) = entry.get("submits").and_then(Value::as_array) else {
        return Err(GuardError::Invalid("entry.submits.map is not a function".to_owned()));
    };
    let times: Vec<i64> = submits.iter().filter_map(parse_iso_millis).collect();
    let within = |window: i64| times.iter().filter(|t| now.saturating_sub(**t) < window).count();
    Ok(within(HOUR_MS) >= SUBMITS_PER_HOUR || within(DAY_MS) >= SUBMITS_PER_DAY)
}

/// `account(data,key)` then `addHosts(entry,hosts)`: the entry, made when absent or falsy, with `hosts`
/// merged in (first occurrence kept, in order).
fn account_with_hosts<'a>(
    data: &'a mut Value,
    key: &str,
    hosts: &[String],
) -> Result<&'a mut Value, GuardError> {
    let accounts = data.get_mut("accounts").and_then(Value::as_object_mut).ok_or(GuardError::Damaged)?;
    let entry = accounts.entry(key.to_owned()).or_insert(Value::Null);
    if !crate::util::truthy(entry) {
        *entry = json!({ "hosts": [], "submits": [], "stopped": null });
    }
    // Node spreads `entry.hosts`, so anything but an array throws there (a string would spread into its
    // characters; phantab refuses that too).
    let Some(listed) = entry.get_mut("hosts").and_then(Value::as_array_mut) else {
        return Err(GuardError::Invalid("entry.hosts is not iterable".to_owned()));
    };
    let mut merged: Vec<Value> = Vec::with_capacity(listed.len() + hosts.len());
    for h in listed.drain(..).chain(hosts.iter().map(|h| Value::String(h.clone()))) {
        if !merged.contains(&h) {
            merged.push(h);
        }
    }
    *listed = merged;
    Ok(entry)
}

/// Before the click, durably: the hosts, and for a password send the time, after dropping sends a day
/// old or older. A crash after the click must still count.
///
/// SR-46: the stop and the limit are checked again here, inside the same read-change-write, so calls
/// running side by side cannot all pass the earlier check and then all send. `Some(reason)` (a stop
/// label, or `limit`) means nothing was recorded and nothing may be sent.
///
/// # Errors
/// Unreadable, damaged, a wrong-shaped entry, or unwritable: the call stops with `guard-file` before
/// anything goes out.
pub async fn record_send(
    file: &Path,
    key: &str,
    hosts: &[String],
    password: bool,
    now: i64,
) -> Result<Option<&'static str>, GuardError> {
    let mut refused = None;
    guard_write(file, |data| {
        if let Some(why) = account_stopped(data, key)? {
            refused = Some(why);
            return Ok(());
        }
        if password && over_limit(data, key, now)? {
            refused = Some("limit");
            return Ok(());
        }
        let entry = account_with_hosts(data, key, hosts)?;
        if password {
            let Some(submits) = entry.get_mut("submits").and_then(Value::as_array_mut) else {
                return Err(GuardError::Invalid("e.submits.filter is not a function".to_owned()));
            };
            submits.retain(|t| parse_iso_millis(t).is_some_and(|t| now.saturating_sub(t) < DAY_MS));
            submits.push(Value::String(iso(now)));
        }
        Ok(())
    })
    .await?;
    Ok(refused)
}

/// `stopAccount`: the account stops for these hosts until `sign-in-clear`. `reason` is `rejected` or
/// `unknown`.
///
/// # Errors
/// As [`record_send`]; the caller ignores it.
pub async fn stop_account(file: &Path, key: &str, hosts: &[String], reason: &str) -> Result<(), GuardError> {
    let at = crate::util::iso_now();
    guard_write(file, |data| {
        let entry = account_with_hosts(data, key, hosts)?;
        entry["stopped"] = json!({ "reason": reason, "at": at });
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(accounts: &Value) -> Value {
        json!({ "version": 1, "accounts": accounts })
    }

    #[test]
    fn iso_parse_matches_date_parse() {
        // Node 22's Date.parse gives each of these, apart from the three marked: forms this file never
        // holds, which V8's fallback parser reads and phantab counts as no send.
        for (text, want) in [
            ("1970-01-01T00:00:00.000Z", Some(0)),
            ("2026-11-04T01:02:03.456Z", Some(1_793_754_123_456)),
            ("2026-11-04T01:02:03Z", Some(1_793_754_123_000)),
            ("2026-11-04T01:02Z", Some(1_793_754_120_000)),
            ("2026-11-04T01:02:03.4Z", Some(1_793_754_123_400)),
            ("2026-11-04T01:02:03.45678Z", Some(1_793_754_123_456)),
            ("2026-11-04T03:02:03.456+02:00", Some(1_793_754_123_456)),
            ("2026-11-03T23:02:03.456-02:00", Some(1_793_754_123_456)),
            ("2024-02-29T00:00:00.000Z", Some(1_709_164_800_000)),
            ("2026-11-04T24:00:00.000Z", Some(1_793_836_800_000)),
            ("1969-12-31T23:59:59.999Z", Some(-1)),
            ("2025-02-29T00:00:00.000Z", None), // V8: 2025-03-01
            ("2026-13-01T00:00:00.000Z", None),
            ("2026-11-04T24:00:01.000Z", None),
            ("2026-11-04T01:60:00.000Z", None),
            ("2026-11-04T01:02:03.Z", None),
            ("2026-11-04 01:02:03Z", None),    // V8: the legacy form, read
            ("2026-11-04T01:02:03.456", None), // V8: local time
            ("", None),
        ] {
            assert_eq!(parse_iso_millis(&json!(text)), want, "{text}");
        }
        assert_eq!(parse_iso_millis(&json!(5)), None);
        assert_eq!(parse_iso_millis(&Value::Null), None);
        let now = now_millis();
        assert_eq!(parse_iso_millis(&json!(iso(now))), Some(now));
    }

    #[test]
    fn stops_by_host_and_account() {
        let data = guard(&json!({
            "a": {"hosts": ["one.test"], "submits": [], "stopped": {"reason": "unknown", "at": "t"}},
            "b": {"hosts": ["two.test"], "submits": [], "stopped": {"reason": "rejected"}},
            "c": {"hosts": ["three.test"], "submits": [], "stopped": true},
            "d": {"hosts": "not read when not stopped", "stopped": null},
            "e": 5,
        }));
        let h = |x: &str| vec![x.to_owned()];
        assert_eq!(host_stopped(&data, &h("one.test")).unwrap(), Some("unknown"));
        assert_eq!(host_stopped(&data, &h("two.test")).unwrap(), Some("rejected"));
        assert_eq!(host_stopped(&data, &h("three.test")).unwrap(), Some("rejected"));
        assert_eq!(host_stopped(&data, &h("four.test")).unwrap(), None);
        assert_eq!(host_stopped(&data, &[]).unwrap(), None);
        assert_eq!(account_stopped(&data, "a").unwrap(), Some("unknown"));
        assert_eq!(account_stopped(&data, "d").unwrap(), None);
        assert_eq!(account_stopped(&data, "e").unwrap(), None);
        assert_eq!(account_stopped(&data, "zz").unwrap(), None);
        // What Node throws on.
        assert!(host_stopped(&guard(&json!({"n": null})), &h("x")).is_err());
        assert!(
            host_stopped(&guard(&json!({"s": {"stopped": {"reason": "x"}, "hosts": "x"}})), &h("x")).is_err()
        );
    }

    #[test]
    fn limits_by_hour_and_day() {
        let now = now_millis();
        let at = |ago: i64| json!(iso(now - ago));
        let one = |submits: Value| guard(&json!({"k": {"hosts": [], "submits": submits, "stopped": null}}));
        assert!(!over_limit(&one(json!([])), "k", now).unwrap());
        assert!(!over_limit(&guard(&json!({})), "k", now).unwrap());
        assert!(!over_limit(&one(json!([at(1000)])), "k", now).unwrap());
        assert!(over_limit(&one(json!([at(1000), at(3_599_000)])), "k", now).unwrap());
        assert!(!over_limit(&one(json!([at(1000), at(3_600_000)])), "k", now).unwrap());
        let day: Vec<Value> = (0..6).map(|i| at(2 * HOUR_MS + i * 60_000)).collect();
        assert!(over_limit(&one(json!(day)), "k", now).unwrap());
        let old: Vec<Value> = (0..6).map(|i| at(25 * HOUR_MS + i)).collect();
        assert!(!over_limit(&one(json!(old)), "k", now).unwrap());
        // Unparseable times count as nothing.
        assert!(!over_limit(&one(json!(["x", 5, null, "y", "z", "w"])), "k", now).unwrap());
        assert!(over_limit(&one(json!("abc")), "k", now).is_err());
        // A falsy entry is no entry.
        assert!(!over_limit(&guard(&json!({"k": 0})), "k", now).unwrap());
    }

    #[tokio::test]
    async fn sends_and_stops_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sign-in-guard.json");
        let hosts = vec!["a.test".to_owned(), "b.test".to_owned()];
        let now = now_millis();
        record_send(&file, "k", &hosts, false, now).await.unwrap();
        let data = read_guard(&file).unwrap();
        assert_eq!(
            data["accounts"]["k"],
            json!({"hosts": ["a.test", "b.test"], "submits": [], "stopped": null})
        );
        // A day-old send is dropped, the new one appended, and hosts merged without repeats.
        let before = guard(&json!({"k": {
            "hosts": ["b.test", "c.test"],
            "submits": [iso(now - 25 * HOUR_MS), iso(now - 1000), "junk"],
            "stopped": null,
        }}));
        std::fs::write(&file, before.to_string()).unwrap();
        record_send(&file, "k", &hosts, true, now).await.unwrap();
        let data = read_guard(&file).unwrap();
        assert_eq!(data["accounts"]["k"]["hosts"], json!(["b.test", "c.test", "a.test"]));
        assert_eq!(data["accounts"]["k"]["submits"], json!([iso(now - 1000), iso(now)]));
        stop_account(&file, "k", &hosts, "unknown").await.unwrap();
        let data = read_guard(&file).unwrap();
        assert_eq!(data["accounts"]["k"]["stopped"]["reason"], "unknown");
        assert!(parse_iso_millis(&data["accounts"]["k"]["stopped"]["at"]).is_some());
        assert_eq!(host_stopped(&data, &["c.test".to_owned()]).unwrap(), Some("unknown"));
        // Wrong shapes fail and leave the file as it was.
        for bad in [json!({"k": 5}), json!({"k": {"hosts": "x"}}), json!({"k": {"hosts": [], "submits": {}}})]
        {
            let text = guard(&bad).to_string();
            std::fs::write(&file, &text).unwrap();
            assert!(
                matches!(record_send(&file, "k", &hosts, true, now).await, Err(GuardError::Invalid(_))),
                "{text}"
            );
            assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
        }
        // A damaged file fails both, and stays.
        std::fs::write(&file, "{not json").unwrap();
        assert!(matches!(record_send(&file, "k", &hosts, true, now).await, Err(GuardError::Damaged)));
        assert!(matches!(stop_account(&file, "k", &hosts, "rejected").await, Err(GuardError::Damaged)));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{not json");
        for damaged in [
            "[]",
            r#"{"version":2,"accounts":{}}"#,
            r#"{"version":1,"accounts":null}"#,
            r#"{"version":"1","accounts":{}}"#,
        ] {
            std::fs::write(&file, damaged).unwrap();
            assert!(matches!(read_guard(&file), Err(GuardError::Damaged)), "{damaged}");
        }
    }

    #[tokio::test]
    async fn writes_are_atomic_and_serialized() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sign-in-guard.json");
        let now = now_millis();
        let mut tasks = Vec::new();
        for i in 0..20 {
            let file = file.clone();
            tasks.push(tokio::spawn(async move {
                record_send(&file, &format!("k{i}"), &[format!("h{i}.test")], true, now).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        let data = read_guard(&file).unwrap();
        assert_eq!(data["accounts"].as_object().unwrap().len(), 20, "no write lost another's");
        // No temp file is left behind.
        let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, [std::ffi::OsString::from("sign-in-guard.json")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    /// SR-46: sends side by side on one account pass the hourly limit only as often as it allows, and a
    /// stop written first refuses the rest.
    #[tokio::test]
    async fn parallel_sends_cannot_pass_the_limit_or_a_stop() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sign-in-guard.json");
        let now = now_millis();
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let file = file.clone();
            tasks.push(tokio::spawn(async move {
                record_send(&file, "k", &["a.test".to_owned()], true, now).await
            }));
        }
        let mut sent = 0;
        for t in tasks {
            match t.await.unwrap().unwrap() {
                None => sent += 1,
                Some(why) => assert_eq!(why, "limit"),
            }
        }
        assert_eq!(sent, SUBMITS_PER_HOUR);
        let data = read_guard(&file).unwrap();
        assert_eq!(data["accounts"]["k"]["submits"].as_array().unwrap().len(), SUBMITS_PER_HOUR);
        stop_account(&file, "j", &["b.test".to_owned()], "rejected").await.unwrap();
        let before = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            record_send(&file, "j", &["b.test".to_owned()], false, now).await.unwrap(),
            Some("rejected")
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before, "a refused send records nothing");
    }

    #[tokio::test]
    async fn clear_by_host_and_all() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sign-in-guard.json");
        std::fs::write(
            &file,
            r#"{"version":1,"accounts":{"a":{"hosts":["example.com"],"submits":[],"stopped":{"reason":"x","at":"t"}},"b":{"hosts":["other.org"],"submits":[],"stopped":{"reason":"y","at":"t"}}}}"#,
        )
        .unwrap();
        assert_eq!(clear_guard(&file, "EXAMPLE.com").await.unwrap(), json!({"cleared": 1}));
        let data = read_guard(&file).unwrap();
        assert_eq!(data["accounts"]["a"]["stopped"], Value::Null);
        assert!(data["accounts"]["b"]["stopped"].is_object());
        std::fs::write(&file, "{broken").unwrap();
        assert!(matches!(clear_guard(&file, "other.org").await, Err(GuardError::Damaged)));
        assert_eq!(clear_guard(&file, "all").await.unwrap(), json!({"cleared": "all"}));
        assert!(!file.exists());
    }

    /// Without `guardrails: full` the engine passes an empty path: nothing is counted, stopped or written,
    /// however many sends there are.
    #[tokio::test]
    async fn an_empty_path_is_no_guard() {
        let none = Path::new("");
        let now = now_millis();
        let hosts = ["example.com".to_owned()];
        for _ in 0..=SUBMITS_PER_DAY {
            assert_eq!(record_send(none, "a", &hosts, true, now).await.unwrap(), None);
        }
        stop_account(none, "a", &hosts, "rejected").await.unwrap();
        let data = read_guard(none).unwrap();
        assert_eq!(data, empty());
        assert_eq!(host_stopped(&data, &hosts).unwrap(), None);
        assert_eq!(account_stopped(&data, "a").unwrap(), None);
        assert!(!over_limit(&data, "a", now).unwrap());
        write_guard(none, &json!({ "version": 1, "accounts": { "a": {} } })).await.unwrap();
        assert_eq!(read_guard(none).unwrap(), empty());
    }
}
