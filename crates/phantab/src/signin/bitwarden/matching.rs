//! Which saved login fits the page (docs/BITWARDEN.md § Matching; THREAT-MODEL SR-67). Each saved URI
//! is compared by its own `match` setting, the way Bitwarden's clients do by default
//! (`LoginUriView.matchesUri` in bitwarden/clients `libs/common`). `bw list items --url` has already
//! applied Bitwarden's own matching to the page, so a login phantab keeps fits both.
//!
//! | Entry match (`login.uris[].match`)   | Counts when                                                    |
//! |--------------------------------------|----------------------------------------------------------------|
//! | default (`null`), 0 base domain      | the same registrable domain (eTLD+1): subdomains fit, any port |
//! | 1 host                               | the same host and port                                         |
//! | 2 starts with                        | the same host and port, and the page URL starts with the entry |
//! | 3 exact                              | the same host and port, and the page URL is the entry          |
//! | 4 regular expression, 5 never, other | never (phantab runs no saved pattern)                          |
//!
//! Where phantab is stricter than Bitwarden, on purpose:
//! - Only `https`. The page must be `https` (the source refuses anything else first), and an `http://`
//!   entry never fits: Bitwarden ignores the scheme, phantab does not hand a login saved for a plain-text
//!   page to another one. An entry without a scheme (`bank.example`, as people type them) is read as
//!   `https://bank.example`.
//! - An IP address, `localhost` or `*.localhost` has no registrable domain here, so base domain is host
//!   and port equality for it (Bitwarden compares the bare host, any port).
//! - A `match` value that is there but not a number phantab knows (`"5"`, `5.0`, `true`, `99`) never
//!   fits; only an absent or `null` one is the default.
//! - Starts with and exact also need the same host and port, so `https://site.test` "starting" the URL
//!   `https://site.test.evil.test/` is not a fit.
//! - Bitwarden's equivalent domains (`google.com` with `youtube.com`) are not followed.
//! - A regular expression never fits: phantab does not run a pattern from the vault against pages.
//!
//! Looser than Bitwarden, but only ever on the same origin: a host that is itself a public suffix
//! (`github.io`, `co.uk`), a name without a dot (`router`) or one ending in a dot has no registrable
//! domain, and Bitwarden never fills it under base domain; phantab fills it when the host and port are
//! the entry's own.
//!
//! Kept from Bitwarden: the registrable domain uses the Public Suffix List's private section too (its
//! tldts call sets `allowPrivateDomains`), so `a.github.io` and `b.github.io` are different sites; and
//! its one exception, a `google.com` login never fits `script.google.com` (Apps Script serves other
//! people's pages there).

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use url::{Host, Url};

use crate::signin::Outcome;

/// An `https` origin: lower-case host and port (443 when absent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Origin {
    host: String,
    port: u16,
}

impl Origin {
    pub(crate) fn host(&self) -> &str {
        &self.host
    }
}

fn origin_of(url: &Url) -> Option<Origin> {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    Some(Origin { host: url.host_str()?.to_ascii_lowercase(), port: url.port_or_known_default()? })
}

/// The page URL's origin; `None` unless it is `https` without credentials.
pub(crate) fn page_origin(url: &str) -> Option<Origin> {
    origin_of(&Url::parse(url).ok()?)
}

/// A saved entry's origin, read as [`entry_url`] reads it; `None` unless it is `https` without
/// credentials. A sign-up reuses a login only when one of its entries is the page's exact origin.
pub(crate) fn entry_origin(uri: &str) -> Option<Origin> {
    origin_of(&entry_url(uri)?)
}

/// A saved URI as a URL: as written when it has a scheme, else as `https://` + it.
fn entry_url(uri: &str) -> Option<Url> {
    let uri = uri.trim();
    if uri.is_empty() {
        return None;
    }
    if uri.contains("://") { Url::parse(uri).ok() } else { Url::parse(&format!("https://{uri}")).ok() }
}

/// How one saved URI is compared (`login.uris[].match`; Bitwarden's `UriMatchStrategy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    BaseDomain,
    Host,
    StartsWith,
    Exact,
    Never,
}

fn rule(kind: Option<i64>) -> Rule {
    match kind {
        // Absent or `null` is the default, and Bitwarden's default is base domain. A value that is there
        // but not readable arrives as UNREADABLE_MATCH, so it is never.
        None | Some(0) => Rule::BaseDomain,
        Some(1) => Rule::Host,
        Some(2) => Rule::StartsWith,
        Some(3) => Rule::Exact,
        // 4 is a regular expression: unsupported, so it never fits. 5 is never; anything newer, never.
        Some(_) => Rule::Never,
    }
}

/// Base-domain logins that do not fit these hosts: Bitwarden's `Utils.DomainMatchBlacklist`.
const BASE_DOMAIN_EXCEPTIONS: &[(&str, &[&str])] = &[("google.com", &["script.google.com"])];

/// The registrable domain (eTLD+1) of a URL's host, or `None` when it has none to share: an IP address,
/// `localhost` or a name under it, a public suffix itself (`github.io`, `co.uk`), a name without a dot,
/// or a host ending in a dot (which the list lookup would not read as the same name). `url` has already made the host
/// lower-case ASCII (punycode), the form the list is matched in.
fn base_domain(url: &Url) -> Option<&str> {
    let Some(Host::Domain(host)) = url.host() else { return None };
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with('.') {
        return None;
    }
    psl::domain_str(host)
}

/// Base domain: the same registrable domain, else (no registrable domain on either side) the same host
/// and port.
fn same_site(entry: &Url, url: &Url) -> bool {
    match (base_domain(entry), base_domain(url)) {
        (Some(saved), Some(here)) => {
            saved == here
                && !BASE_DOMAIN_EXCEPTIONS
                    .iter()
                    .any(|(d, hosts)| *d == saved && url.host_str().is_some_and(|h| hosts.contains(&h)))
        }
        _ => origin_of(entry) == origin_of(url),
    }
}

/// Whether one saved entry counts for `url`. `whole` holds `url` to the entry's path rule (starts with,
/// exact): true for the page, false for a frame or a form's target, which only must not leave the site.
/// A login saved "exact" for `/signin` still posts to `/session`; the path rule is for the page the
/// owner saved, and the site is what a credential must not leave.
fn entry_fits(uri: &str, kind: Option<i64>, url: &str, whole: bool) -> bool {
    let (Some(entry), Ok(url)) = (entry_url(uri), Url::parse(url)) else { return false };
    let (Some(saved), Some(here)) = (origin_of(&entry), origin_of(&url)) else { return false };
    match rule(kind) {
        Rule::BaseDomain => same_site(&entry, &url),
        Rule::Host => saved == here,
        Rule::StartsWith => saved == here && (!whole || url.as_str().starts_with(entry.as_str())),
        Rule::Exact => saved == here && (!whole || url.as_str() == entry.as_str()),
        Rule::Never => false,
    }
}

/// Whether one saved entry counts for the page URL `page` (already without query and fragment).
pub(crate) fn entry_matches(uri: &str, kind: Option<i64>, page: &str) -> bool {
    entry_fits(uri, kind, page, true)
}

/// The account key of a vault item: `sha256('phantab-sign-in:' + id)`, first 32 hex digits. It is stable
/// per item, so the guard file's stops and counts keep meaning the same login across runs and vault
/// syncs, and it names the item without carrying its id or any of its fields.
pub(crate) fn account_key(id: &str) -> String {
    let mut hex = crate::util::hex(&Sha256::digest(format!("phantab-sign-in:{id}").as_bytes()));
    hex.truncate(32);
    hex
}

fn uuid(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A live login item: type 1, not in the trash, a UUID id.
fn login(item: &Value) -> bool {
    item.get("type").and_then(Value::as_i64) == Some(1)
        && item.get("deletedDate").is_none_or(Value::is_null)
        && item.get("id").and_then(Value::as_str).is_some_and(uuid)
        && item.get("login").is_some_and(Value::is_object)
}

/// A `match` value that is there but is not a whole number (`"5"`, `"never"`, `5.0`, `true`, a number
/// past `i64`): no setting phantab knows, so [`rule`] reads it as never. Defaulting it would give the
/// widest rule, base domain, to an entry whose owner chose something else; Bitwarden fails closed too.
const UNREADABLE_MATCH: i64 = -1;

/// An entry's `match`: `None` (the default) only when it is absent or `null`.
fn match_setting(value: Option<&Value>) -> Option<i64> {
    match value {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_i64().unwrap_or(UNREADABLE_MATCH)),
    }
}

/// A login's saved entries as `(uri, match)`.
pub(crate) fn entries(item: &Value) -> Vec<(&str, Option<i64>)> {
    item.pointer("/login/uris")
        .and_then(Value::as_array)
        .map(|uris| {
            uris.iter()
                .filter_map(|e| Some((e.get("uri")?.as_str()?, match_setting(e.get("match")))))
                .collect()
        })
        .unwrap_or_default()
}

fn fits(item: &Value, url: &str) -> bool {
    entries(item).iter().any(|(uri, kind)| entry_matches(uri, *kind, url))
}

/// A frame or a form's target: the entry's site rule without its path rule ([`entry_fits`]).
fn fits_site(item: &Value, url: &str) -> bool {
    entries(item).iter().any(|(uri, kind)| entry_fits(uri, *kind, url, false))
}

/// Picks the one login for the call, or the label that says why not. `urls[0]` is the page; the rest are
/// the frames and the form's target, and the login must have an entry that fits each of them too (else
/// the form would send it somewhere it was not saved for: `wall`/`form-posts-elsewhere`). Only the page
/// is held to an entry's path rule. `account` is the agent's exact item name; `held` is the account key
/// this page already used (a later step of the same sign-in must use the same login).
pub(crate) fn choose(
    items: &[Value],
    urls: &[String],
    account: Option<&str>,
    held: Option<&str>,
) -> Result<usize, Outcome> {
    let Some(page) = urls.first() else { return Err(Outcome::of("refused")) };
    let mut found: Vec<usize> =
        items.iter().enumerate().filter(|(_, i)| login(i) && fits(i, page)).map(|(n, _)| n).collect();
    if let Some(name) = account {
        found.retain(|n| items[*n].get("name").and_then(Value::as_str) == Some(name));
    }
    if let Some(key) = held {
        found
            .retain(|n| items[*n].get("id").and_then(Value::as_str).is_some_and(|id| account_key(id) == key));
        if found.is_empty() {
            return Err(Outcome::of("refused"));
        }
    }
    if found.is_empty() {
        return Err(Outcome::of("none"));
    }
    found.retain(|n| urls[1..].iter().all(|u| fits_site(&items[*n], u)));
    match found.as_slice() {
        [] => Err(Outcome::with("wall", "form-posts-elsewhere")),
        [one] => Ok(*one),
        many => Err(Outcome { count: i64::try_from(many.len()).ok(), ..Outcome::of("ambiguous") }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ID1: &str = "0b9f3a52-1111-4c3e-9a4e-7c2f0d6b1a01";
    const ID2: &str = "0b9f3a52-2222-4c3e-9a4e-7c2f0d6b1a02";

    fn item(id: &str, name: &str, uris: &Value) -> Value {
        json!({"id": id, "type": 1, "name": name, "deletedDate": null, "login": {"uris": uris}})
    }

    #[test]
    fn each_entry_matches_by_its_own_setting() {
        let page = "https://login.site.test/signin";
        for (uri, kind, want) in [
            // Base domain, the default (`null`) and 0: the registrable domain, so subdomains, the parent
            // and siblings fit, on any port.
            ("https://login.site.test", None, true),
            ("https://login.site.test/other/path", Some(0), true),
            ("login.site.test", None, true),
            ("https://LOGIN.site.test", None, true),
            ("https://site.test", None, true),
            ("site.test", Some(0), true),
            ("https://www.site.test", Some(0), true),
            ("https://evil.login.site.test", None, true),
            ("https://login.site.test:8443", None, true),
            ("https://login.site.test.evil.test", None, false),
            ("https://site.test.evil.test", Some(0), false),
            ("https://othersite.test", None, false),
            // Host (1): host and port.
            ("login.site.test:443", Some(1), true),
            ("https://login.site.test/elsewhere", Some(1), true),
            ("https://site.test", Some(1), false),
            ("https://www.login.site.test", Some(1), false),
            ("https://login.site.test:8443", Some(1), false),
            // Starts with (2) and exact (3): the string, on the same host and port.
            ("https://login.site.test/sign", Some(2), true),
            ("https://login.site.test/other", Some(2), false),
            ("https://site.test/", Some(2), false),
            ("https://login.site.test/signin", Some(3), true),
            ("https://login.site.test/", Some(3), false),
            // Regular expression (4) is not run; never (5) and unknown settings never fit.
            ("https://login.site.test", Some(4), false),
            (".*", Some(4), false),
            ("^https://login\\.site\\.test/.*$", Some(4), false),
            ("https://login.site.test", Some(5), false),
            ("https://login.site.test", Some(9), false),
            ("https://login.site.test", Some(-1), false),
            // Never `http`, never credentials, never another scheme or nothing.
            ("http://login.site.test", None, false),
            ("http://site.test", Some(0), false),
            ("http://login.site.test", Some(1), false),
            ("", None, false),
            ("androidapp://test.site", None, false),
            ("https://user:pw@login.site.test", None, false),
        ] {
            assert_eq!(entry_matches(uri, kind, page), want, "{uri} {kind:?}");
        }
        assert!(page_origin("https://a.test/x").is_some_and(|o| o.host() == "a.test"));
        assert!(page_origin("http://a.test/").is_none());
        assert!(page_origin("https://u:p@a.test/").is_none());
    }

    #[test]
    fn an_http_page_gets_no_https_entry() {
        for kind in [None, Some(0), Some(1), Some(2), Some(3)] {
            assert!(!entry_matches("https://login.site.test", kind, "http://login.site.test/"), "{kind:?}");
            assert!(!entry_matches("http://login.site.test", kind, "http://login.site.test/"), "{kind:?}");
        }
    }

    #[test]
    fn base_domain_follows_the_public_suffix_list() {
        for (uri, page, want) in [
            // The list's private section counts: these are other people's sites on a shared suffix.
            ("https://a.github.io", "https://b.github.io/login", false),
            ("https://a.github.io", "https://a.github.io/login", true),
            ("https://a.github.io", "https://x.a.github.io/login", true),
            ("https://github.io", "https://a.github.io/login", false),
            ("https://bbc.co.uk", "https://www.bbc.co.uk/signin", true),
            ("https://bbc.co.uk", "https://evil.co.uk/signin", false),
            ("https://co.uk", "https://bbc.co.uk/signin", false),
            ("https://example.com", "https://accounts.example.com/", true),
            // Unicode and punycode are one name.
            ("https://bücher.example", "https://www.xn--bcher-kva.example/", true),
            // Bitwarden's one exception.
            ("https://google.com", "https://accounts.google.com/", true),
            ("https://google.com", "https://script.google.com/macros/s/x", false),
            ("https://accounts.google.com", "https://script.google.com/", false),
            // No registrable domain: host and port only.
            ("https://127.0.0.1", "https://127.0.0.1/login", true),
            ("https://127.0.0.1:8443", "https://127.0.0.1/login", false),
            ("https://10.0.0.1", "https://10.0.0.2/login", false),
            ("https://[::1]", "https://[::1]/login", true),
            ("https://localhost", "https://localhost/login", true),
            ("https://localhost", "https://app.localhost/login", false),
            ("https://localhost:8443", "https://localhost:9443/login", false),
            ("https://router", "https://router/", true),
            ("https://site.test.", "https://login.site.test./", false),
        ] {
            assert_eq!(entry_matches(uri, None, page), want, "{uri} on {page}");
        }
    }

    #[test]
    fn choosing_one_login() {
        let urls = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let page = urls(&["https://site.test/login"]);
        let one = item(ID1, "Work", &json!([{"uri": "https://site.test", "match": null}]));
        let two = item(ID2, "Home", &json!([{"uri": "site.test"}, {"uri": "https://sso.test"}]));
        let www = item(ID2, "Www", &json!([{"uri": "https://www.site.test"}]));
        let host = item(ID2, "Host", &json!([{"uri": "https://www.site.test", "match": 1}]));
        assert_eq!(choose(std::slice::from_ref(&one), &page, None, None), Ok(0));
        assert_eq!(
            choose(std::slice::from_ref(&www), &page, None, None),
            Ok(0),
            "base domain: a sibling fits"
        );
        assert_eq!(
            choose(&[host.clone(), one.clone()], &page, None, None),
            Ok(1),
            "a host entry for another host is not a fit"
        );
        assert_eq!(choose(std::slice::from_ref(&host), &page, None, None), Err(Outcome::of("none")));
        let both = [one.clone(), two.clone()];
        assert_eq!(
            choose(&both, &page, None, None),
            Err(Outcome { count: Some(2), ..Outcome::of("ambiguous") })
        );
        assert_eq!(choose(&both, &page, Some("Home"), None), Ok(1));
        assert_eq!(choose(&both, &page, Some("home"), None), Err(Outcome::of("none")), "names are exact");
        assert_eq!(choose(&both, &page, None, Some(&account_key(ID1))), Ok(0));
        assert_eq!(choose(&both, &page, None, Some("0".repeat(32).as_str())), Err(Outcome::of("refused")));
        // A frame or form target on another site needs an entry of its own; one on a subdomain is the site.
        let sso = urls(&["https://site.test/login", "https://sso.test/form"]);
        assert_eq!(choose(&both, &sso, None, None), Ok(1));
        let sub = urls(&["https://site.test/login", "https://auth.site.test/form"]);
        assert_eq!(choose(std::slice::from_ref(&one), &sub, None, None), Ok(0));
        assert_eq!(
            choose(
                std::slice::from_ref(&host),
                &urls(&["https://www.site.test/", "https://site.test/form"]),
                None,
                None
            ),
            Err(Outcome::with("wall", "form-posts-elsewhere")),
            "a host entry holds its frames and targets to its host"
        );
        assert_eq!(
            choose(std::slice::from_ref(&one), &sso, None, None),
            Err(Outcome::with("wall", "form-posts-elsewhere"))
        );
        // A frame or form target is held to the entry's site rule only, not its path: a login saved "exact" or
        // "starts with" for the sign-in page still posts to another path on the same host.
        let post = urls(&["https://site.test/login", "https://site.test/session"]);
        for kind in [3, 2] {
            let pinned = item(ID1, "Pinned", &json!([{"uri": "https://site.test/login", "match": kind}]));
            assert_eq!(choose(std::slice::from_ref(&pinned), &post, None, None), Ok(0), "match {kind}");
        }
        let never = item(
            ID1,
            "Never",
            &json!([{"uri": "https://site.test/login", "match": 3}, {"uri": "https://sso.test", "match": 5}]),
        );
        assert_eq!(
            choose(std::slice::from_ref(&never), &sso, None, None),
            Err(Outcome::with("wall", "form-posts-elsewhere")),
            "a never entry is no entry"
        );
        // Not a live login item.
        let mut trash = one.clone();
        trash["deletedDate"] = json!("2026-11-01T00:00:00Z");
        let mut card = one.clone();
        card["type"] = json!(3);
        let mut bad_id = one.clone();
        bad_id["id"] = json!("../etc");
        for i in [trash, card, bad_id, json!("item"), json!({"type": 1})] {
            assert_eq!(choose(std::slice::from_ref(&i), &page, None, None), Err(Outcome::of("none")), "{i}");
        }
        assert_eq!(choose(&[one], &[], None, None), Err(Outcome::of("refused")));
    }

    #[test]
    fn an_unreadable_match_setting_is_never() {
        for (setting, want) in [
            (json!(null), None),
            (json!(0), Some(0)),
            (json!(5), Some(5)),
            (json!(-3), Some(-3)),
            (json!("5"), Some(UNREADABLE_MATCH)),
            (json!("never"), Some(UNREADABLE_MATCH)),
            (json!(5.0), Some(UNREADABLE_MATCH)),
            (json!(true), Some(UNREADABLE_MATCH)),
            (json!(u64::MAX), Some(UNREADABLE_MATCH)),
            (json!({}), Some(UNREADABLE_MATCH)),
        ] {
            assert_eq!(match_setting(Some(&setting)), want, "{setting}");
            if let Some(kind) = want.filter(|k| !(0..=3).contains(k)) {
                assert_eq!(rule(Some(kind)), Rule::Never, "{setting}");
            }
        }
        assert_eq!(match_setting(None), None);
        let urls = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        // Not chosen for a sibling host, which base domain would have allowed.
        let sibling = item(ID1, "Sibling", &json!([{"uri": "https://www.site.test", "match": "5"}]));
        assert_eq!(
            choose(std::slice::from_ref(&sibling), &urls(&["https://site.test/login"]), None, None),
            Err(Outcome::of("none"))
        );
        // A frame or form target `bw` never filtered: an entry with an unreadable setting does not cover it.
        let framed = item(
            ID1,
            "Framed",
            &json!([{"uri": "https://site.test"}, {"uri": "https://sso.test", "match": "5"}]),
        );
        for setting in [json!("5"), json!(5.0), json!(true), json!(u64::MAX)] {
            let mut framed = framed.clone();
            framed["login"]["uris"][1]["match"] = setting.clone();
            assert_eq!(
                choose(
                    std::slice::from_ref(&framed),
                    &urls(&["https://site.test/login", "https://sso.test/form"]),
                    None,
                    None
                ),
                Err(Outcome::with("wall", "form-posts-elsewhere")),
                "{setting}"
            );
        }
        framed_ok(&framed);
    }

    /// The same login with a readable setting on its second entry covers the frame.
    fn framed_ok(framed: &Value) {
        let mut ok = framed.clone();
        ok["login"]["uris"][1]["match"] = json!(null);
        let urls = ["https://site.test/login".to_owned(), "https://sso.test/form".to_owned()];
        assert_eq!(choose(std::slice::from_ref(&ok), &urls, None, None), Ok(0));
    }

    #[test]
    fn account_keys_are_fixed() {
        // sha256("phantab-sign-in:abc"), first 32 hex digits, worked out outside this code, so a change
        // to the formula here fails.
        assert_eq!(account_key("abc"), "96973a5e35875f0d0a664e03cc734752");
        assert_ne!(account_key(ID1), account_key(ID2));
    }
}
