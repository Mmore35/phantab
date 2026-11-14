//! Ask-first sites (docs/BITWARDEN.md § Ask first; THREAT-MODEL SR-66): a page or a saved login on one
//! of them answers `ask-first`, so the agent asks the owner before anything is typed. The list is the
//! config's `askFirst` plus, when `policyFile` is set, that file's, in the
//! `sign-in-policy.json` shape: `{"askFirst": [site...], "approvals": [{site, at, until, words}]}`. An
//! approval takes its site off the list from `at` to `until` (an hour at most) when it carries the
//! owner's `words`; a malformed one counts for nothing. A policy file that cannot be read or parsed
//! answers `refused`: the owner said some sites need asking, and phantab cannot tell which.

use std::path::Path;

use serde_json::Value;

use super::config::valid_site;

/// The longest an approval may run.
pub(crate) const APPROVAL_MAX_MS: i64 = 60 * 60_000;
/// How far ahead of now an approval's `at` may sit (clock skew between the owner's tools).
const SKEW_MS: i64 = 60_000;
/// A policy file larger than this is not one.
const MAX_POLICY: u64 = 1 << 20;

/// Milliseconds since 1970 for an RFC 3339 time (`2026-11-05T10:00:00Z`, `...00.123+01:00`), as
/// JavaScript's `Date.parse` reads them; `None` for anything else.
pub(crate) fn parse_time(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = text.get(r)?;
        s.bytes().all(|c| c.is_ascii_digit()).then(|| s.parse().ok()).flatten()
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut end = 19;
    let mut millis = 0;
    if b.get(end) == Some(&b'.') {
        let start = end + 1;
        end = start;
        while b.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        let fraction = text.get(start..end).filter(|f| !f.is_empty())?;
        millis = fraction.chars().chain("00".chars()).take(3).collect::<String>().parse().ok()?;
    }
    let offset = match text.get(end..)? {
        "Z" | "z" => 0,
        zone if zone.len() == 6
            && matches!(zone.as_bytes()[0], b'+' | b'-')
            && zone.as_bytes()[3] == b':' =>
        {
            let (zone_hours, zone_minutes) = (num(end + 1..end + 3)?, num(end + 4..end + 6)?);
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            sign * (zone_hours * 60 + zone_minutes) * 60_000
        }
        _ => return None,
    };
    // Days from the civil date (Howard Hinnant's `days_from_civil`).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis - offset)
}

fn approval_open(a: &Value, now: i64) -> Option<&str> {
    let site = a.get("site")?.as_str().filter(|s| valid_site(s))?;
    a.get("words")?.as_str().filter(|w| !w.trim().is_empty())?;
    let at = parse_time(a.get("at")?.as_str()?)?;
    let until = parse_time(a.get("until")?.as_str()?)?;
    (at <= now + SKEW_MS && now < until && until - at <= APPROVAL_MAX_MS).then_some(site)
}

/// The sites that ask first now: `inline` plus the policy file's, less the ones with an open approval.
///
/// # Errors
/// The policy file is unreadable, too large, not JSON, or not the shape above.
pub(crate) fn sites(inline: &[String], policy_file: Option<&Path>, now: i64) -> Result<Vec<String>, ()> {
    let mut sites: Vec<String> = inline.to_vec();
    let Some(file) = policy_file else { return Ok(sites) };
    if std::fs::metadata(file).map_err(drop)?.len() > MAX_POLICY {
        return Err(());
    }
    let policy: Value = serde_json::from_slice(&std::fs::read(file).map_err(drop)?).map_err(drop)?;
    let listed = policy.get("askFirst").and_then(Value::as_array).ok_or(())?;
    for s in listed {
        sites.push(s.as_str().filter(|s| valid_site(s)).ok_or(())?.to_owned());
    }
    let approvals = match policy.get("approvals") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(a)) => a.as_slice(),
        Some(_) => return Err(()),
    };
    let open: Vec<&str> = approvals.iter().filter_map(|a| approval_open(a, now)).collect();
    sites.retain(|s| !open.contains(&s.as_str()));
    Ok(sites)
}

/// A host is on a site when it is the site or under it.
pub(crate) fn host_on(host: &str, site: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == site || host.strip_suffix(site).is_some_and(|rest| rest.ends_with('.'))
}

/// A saved URI's text names a site: read as text, since a saved URI can
/// be a bare host or a pattern. A false hit only asks the owner.
pub(crate) fn uri_names(uri: &str, site: &str) -> bool {
    uri.to_ascii_lowercase().replace('\\', "").contains(site)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn times_parse_as_date_parse_does() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("1970-01-01T00:00:01.5Z"), Some(1500));
        assert_eq!(parse_time("2026-11-05T10:00:00.123Z"), Some(1_793_872_800_123));
        assert_eq!(parse_time("2026-11-05T11:00:00+01:00"), parse_time("2026-11-05T10:00:00Z"));
        assert_eq!(parse_time("2000-02-29T00:00:00Z"), Some(951_782_400_000));
        for bad in [
            "",
            "2026-11-05",
            "2026-11-05T10:00:00",
            "2026-13-05T10:00:00Z",
            "2026-11-05T10:00:00Q",
            "x026-11-05T10:00:00Z",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn hosts_and_uris() {
        assert!(host_on("bank.example", "bank.example"));
        assert!(host_on("secure.Bank.example", "bank.example"));
        assert!(!host_on("notbank.example", "bank.example"));
        assert!(!host_on("bank.example.evil.test", "bank.example"));
        assert!(uri_names("https://SECURE.bank.example/login", "bank.example"));
        assert!(
            uri_names("^https://(www\\.)?bank\\.example", "bank.example")
                || uri_names("bank\\.example", "bank.example")
        );
        assert!(!uri_names("https://bank.test", "bank.example"));
    }

    #[test]
    fn approvals_open_and_close() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.json");
        let now = parse_time("2026-11-05T10:00:00Z").unwrap();
        let write = |v: Value| std::fs::write(&file, v.to_string()).unwrap();
        let approval = |site: &str, at: &str, until: &str, words: &str| json!({"site": site, "at": at, "until": until, "words": words});
        write(json!({"askFirst": ["bank.example", "bank.test"], "approvals": [
            approval("bank.example", "2026-11-05T09:30:00Z", "2026-11-05T10:15:00Z", "approved"),
            approval("bank.test", "2026-11-05T09:00:00Z", "2026-11-05T09:59:00Z", "expired"),
        ]}));
        assert_eq!(sites(&["inline.test".into()], Some(&file), now).unwrap(), ["inline.test", "bank.test"]);
        for closed in [
            approval("bank.example", "2026-11-05T09:30:00Z", "2026-11-05T10:31:00Z", "too long"),
            approval("bank.example", "2026-11-05T10:05:00Z", "2026-11-05T10:30:00Z", "ahead"),
            approval("bank.example", "2026-11-05T09:30:00Z", "2026-11-05T10:15:00Z", "  "),
            approval("bank.example", "yesterday", "2026-11-05T10:15:00Z", "words"),
            json!("bank.example"),
        ] {
            write(json!({"askFirst": ["bank.example"], "approvals": [closed]}));
            assert_eq!(sites(&[], Some(&file), now).unwrap(), ["bank.example"]);
        }
        for broken in [
            json!({}),
            json!({"askFirst": "bank.example"}),
            json!({"askFirst": ["Bank.example"]}),
            json!({"askFirst": [], "approvals": {}}),
        ] {
            write(broken);
            assert!(sites(&[], Some(&file), now).is_err());
        }
        std::fs::write(&file, "not json").unwrap();
        assert!(sites(&[], Some(&file), now).is_err());
        assert!(sites(&[], Some(&dir.path().join("missing.json")), now).is_err());
        assert_eq!(sites(&["a.test".into()], None, now).unwrap(), ["a.test"]);
    }
}
