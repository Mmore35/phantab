//! The URL rules (`hostOf`, `strip`, `readable`, `secure`, `CAPTCHA_FRAME`) and the leak
//! forms the sweep looks for (`encodeURIComponent`, `encodeURI`, base64, base64url).

use base64::Engine as _;
use url::Url;

use super::secret::Secret;

/// A URL the page gave that the WHATWG URL parser rejects. The call then ends `failed` / `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BadUrl;

fn parse(url: &str) -> Result<Url, BadUrl> {
    Url::parse(url).map_err(|_| BadUrl)
}

/// `new URL(url).hostname.toLowerCase()`.
pub(crate) fn host_of(url: &str) -> Result<String, BadUrl> {
    Ok(parse(url)?.host_str().unwrap_or_default().to_lowercase())
}

/// The URL without its query and fragment.
pub(crate) fn strip(url: &str) -> Result<String, BadUrl> {
    let mut u = parse(url)?;
    u.set_query(None);
    u.set_fragment(None);
    Ok(u.into())
}

/// Whether two URLs name the same document, query and fragment aside (phantab's cross-check of the
/// page's report against Chrome's frame tree).
pub(crate) fn same_document(a: &str, b: &str) -> bool {
    match (strip(a), strip(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// A URL's origin as `location.ancestorOrigins` writes it (`https://a.test`), or `None` for an opaque one
/// (`about:blank`, `about:srcdoc`, `data:`), whose frame takes its origin from elsewhere.
pub(crate) fn origin_of(url: &str) -> Option<String> {
    let origin = parse(url).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// The shortest one-time code the sweep looks for: a shorter run of digits turns up in page text by
/// chance.
pub(crate) const CODE_TOKEN_MIN: usize = 6;

/// Whether `code` appears in `text` as a whole token: neither side touches another letter or digit, so
/// `123456` is not found in `91234567`.
pub(crate) fn holds_token(text: &str, code: &str) -> bool {
    if code.len() < CODE_TOKEN_MIN {
        return false;
    }
    let edge = |c: Option<char>| !c.is_some_and(char::is_alphanumeric);
    text.match_indices(code)
        .any(|(at, _)| edge(text[..at].chars().next_back()) && edge(text[at + code.len()..].chars().next()))
}

/// `!/^(chrome-extension|devtools):/.test(f.url())`.
pub(crate) fn readable(url: &str) -> bool {
    !(url.starts_with("chrome-extension:") || url.starts_with("devtools:"))
}

/// HTTPS, or (test builds only, through [`super::Options`]) plain HTTP to `127.0.0.1` or `localhost`.
pub(crate) fn secure(url: &str, allow_loopback: bool) -> Result<bool, BadUrl> {
    let u = parse(url)?;
    Ok(u.scheme() == "https"
        || (allow_loopback
            && u.scheme() == "http"
            && matches!(u.host_str(), Some("127.0.0.1" | "localhost"))))
}

/// `CAPTCHA_FRAME.test(url)`, by hand since the regex crate has no look-ahead:
/// `(google|recaptcha)\.[a-z.]+\/recaptcha\/(api2|enterprise)\/anchor(?!.*size=invisible)`, or
/// `hcaptcha\.com\/captcha`, or `challenges\.cloudflare\.com`. Unanchored and case-sensitive. The
/// `[a-z.]+` run cannot hold a `/`, so it matches only when the whole run up to the next other
/// character is followed by `/recaptcha/`.
pub(crate) fn captcha_frame(url: &str) -> bool {
    url.contains("hcaptcha.com/captcha") || url.contains("challenges.cloudflare.com") || recaptcha_anchor(url)
}

/// The response field a [`captcha_frame`]'s check fills once solved, by the frame's provider, in
/// [`captcha_frame`]'s order: hCaptcha, Turnstile, else a reCAPTCHA anchor.
pub(crate) fn captcha_field(url: &str) -> &'static str {
    if url.contains("hcaptcha.com/captcha") {
        "h-captcha-response"
    } else if url.contains("challenges.cloudflare.com") {
        "cf-turnstile-response"
    } else {
        "g-recaptcha-response"
    }
}

/// A verification check's frame, for the owner hand-off (`engine::verify`): [`captcha_frame`] plus
/// the frames of `DataDome` and `Arkose`, which only ever block a whole page. Sign-in keeps its own rule, so this
/// change does not move its outcomes.
pub(crate) fn challenge_frame(url: &str) -> bool {
    captcha_frame(url) || url.contains("captcha-delivery.com") || url.contains("arkoselabs.com")
}

fn recaptcha_anchor(url: &str) -> bool {
    for name in ["google.", "recaptcha."] {
        for (at, _) in url.match_indices(name) {
            let rest = &url[at + name.len()..];
            let run = rest.bytes().take_while(|b| b.is_ascii_lowercase() || *b == b'.').count();
            if run == 0 {
                continue;
            }
            let Some(after) = rest[run..].strip_prefix("/recaptcha/") else { continue };
            let Some(tail) =
                after.strip_prefix("api2/anchor").or_else(|| after.strip_prefix("enterprise/anchor"))
            else {
                continue;
            };
            // `(?!.*size=invisible)`: `.` stops at a line break.
            let line = tail.split(['\n', '\r', '\u{2028}', '\u{2029}']).next().unwrap_or_default();
            if !line.contains("size=invisible") {
                return true;
            }
        }
    }
    false
}

fn percent_encode(input: &str, keep: impl Fn(u8) -> bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() * 3);
    for &b in input.as_bytes() {
        if keep(b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        }
    }
    out
}

/// `encodeURIComponent` (a Rust string has no lone surrogate, the one input it throws on).
pub(crate) fn encode_uri_component(input: &str) -> String {
    percent_encode(input, |b| b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b))
}

/// `encodeURI`.
pub(crate) fn encode_uri(input: &str) -> String {
    percent_encode(input, |b| b.is_ascii_alphanumeric() || b"-_.!~*'();/?:@&=+$,#".contains(&b))
}

/// The six forms of the password the sweep looks for, in this order: raw,
/// `encodeURIComponent`, `encodeURI`, `encodeURIComponent` with `%20` as `+`, base64, base64url. None
/// when there is no password (a code is looked for as itself, a whole token: [`holds_token`]).
pub(crate) fn sweep_forms(password: Option<&Secret>) -> Vec<Secret> {
    let Some(pw) = password.map(Secret::expose).filter(|p| !p.is_empty()) else { return Vec::new() };
    let component = zeroize::Zeroizing::new(encode_uri_component(pw));
    vec![
        Secret::new(pw.to_owned()),
        Secret::new((*component).clone()),
        Secret::new(encode_uri(pw)),
        Secret::new(component.replace("%20", "+")),
        Secret::new(base64::engine::general_purpose::STANDARD.encode(pw.as_bytes())),
        Secret::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pw.as_bytes())),
    ]
}

/// What `URLSearchParams` and a form post write for a value (`application/x-www-form-urlencoded`).
fn form_urlencode(input: &str) -> String {
    percent_encode(input, |b| b.is_ascii_alphanumeric() || b" *-._".contains(&b)).replace(' ', "+")
}

/// `s` with the two hex digits after each `%` in lower case, as some servers write them.
fn lower_hex(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut after = 0;
    for c in s.chars() {
        if after > 0 {
            out.push(c.to_ascii_lowercase());
            after -= 1;
        } else {
            out.push(c);
            if c == '%' {
                after = 2;
            }
        }
    }
    out
}

/// What a sign-in looks for in the page after the submit, and redacts once it has seen it: the six [`sweep_forms`], the form-encoded body, each percent form with
/// lower-case hex, and base64 without its padding (which the padded form holds). None when there is no
/// password.
pub(crate) fn echo_forms(password: Option<&Secret>) -> Vec<Secret> {
    let mut forms = sweep_forms(password);
    let Some(pw) = password.map(Secret::expose).filter(|p| !p.is_empty()) else { return forms };
    forms.push(Secret::new(form_urlencode(pw)));
    let lower: Vec<Secret> = forms
        .iter()
        .filter(|f| f.expose().contains('%'))
        .map(|f| Secret::new(lower_hex(f.expose())))
        .collect();
    forms.extend(lower);
    forms.push(Secret::new(base64::engine::general_purpose::STANDARD_NO_PAD.encode(pw.as_bytes())));
    let mut unique: Vec<Secret> = Vec::with_capacity(forms.len());
    for f in forms {
        if !unique.iter().any(|u| u.matches(f.expose())) {
            unique.push(f);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_strip() {
        assert_eq!(host_of("https://Example.COM:8443/a?b#c").as_deref(), Ok("example.com"));
        assert_eq!(host_of("http://[::1]:5/").as_deref(), Ok("[::1]"));
        assert_eq!(strip("https://a.test/p/q?x=1#y").as_deref(), Ok("https://a.test/p/q"));
        assert_eq!(strip("https://a.test/p?").as_deref(), Ok("https://a.test/p"));
        assert_eq!(strip("https://a.test").as_deref(), Ok("https://a.test/"));
        assert_eq!(strip("https://u:p@a.test/").as_deref(), Ok("https://u:p@a.test/"));
        assert_eq!(host_of("null"), Err(BadUrl));
        assert_eq!(strip("not a url"), Err(BadUrl));
    }

    #[test]
    fn frame_tree_cross_checks() {
        assert!(same_document("https://a.test/login?x=1#y", "https://a.test/login"));
        assert!(!same_document("https://a.test/login", "https://b.test/login"));
        assert!(!same_document("https://a.test/login", "https://a.test/other"));
        assert!(!same_document("not a url", "not a url"));
        assert_eq!(origin_of("https://A.test:443/p?q").as_deref(), Some("https://a.test"));
        assert_eq!(origin_of("http://127.0.0.1:8080/").as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(origin_of("about:blank"), None);
        assert_eq!(origin_of("about:srcdoc"), None);
        assert_eq!(origin_of("data:text/html,x"), None);
    }

    #[test]
    fn codes_match_as_whole_tokens() {
        assert!(holds_token("Your code 123456 is wrong", "123456"));
        assert!(holds_token("123456", "123456"));
        assert!(holds_token("code=123456&x", "123456"));
        assert!(holds_token("9123456 then 123456.", "123456"));
        assert!(!holds_token("order 91234567", "123456"));
        assert!(!holds_token("id x123456", "123456"));
        assert!(!holds_token("1234560", "123456"));
        assert!(!holds_token("é123456", "123456"));
        // Shorter codes are not looked for.
        assert!(!holds_token("code 1234 here", "1234"));
        assert!(!holds_token("anything", ""));
    }

    #[test]
    fn readable_frames() {
        assert!(readable("https://a.test/"));
        assert!(readable("about:blank"));
        assert!(!readable("chrome-extension://abc/overlay/menu.html"));
        assert!(!readable("devtools://devtools/bundled/x.html"));
        assert!(readable("x-chrome-extension://abc/"));
    }

    #[test]
    fn secure_at_each_level() {
        assert_eq!(secure("https://a.test/", false), Ok(true));
        assert_eq!(secure("https://127.0.0.1/", false), Ok(true));
        assert_eq!(secure("http://a.test/", false), Ok(false));
        assert_eq!(secure("http://a.test/", true), Ok(false));
        assert_eq!(secure("http://127.0.0.1:5000/x", false), Ok(false));
        assert_eq!(secure("http://127.0.0.1:5000/x", true), Ok(true));
        assert_eq!(secure("http://localhost:5000", true), Ok(true));
        assert_eq!(secure("http://LOCALHOST:5000", true), Ok(true));
        assert_eq!(secure("http://[::1]:5000", true), Ok(false));
        assert_eq!(secure("http://127.0.0.2/", true), Ok(false));
        assert_eq!(secure("ws://127.0.0.1/", true), Ok(false));
        assert_eq!(secure("javascript:void(0)", true), Ok(false));
        assert_eq!(secure("about:blank", true), Ok(false));
        assert_eq!(secure("null", true), Err(BadUrl));
    }

    #[test]
    fn captcha_fields() {
        for (url, field) in [
            ("https://newassets.hcaptcha.com/captcha/v1/x", "h-captcha-response"),
            ("https://challenges.cloudflare.com/cdn-cgi/x", "cf-turnstile-response"),
            ("https://www.google.com/recaptcha/api2/anchor?k=x", "g-recaptcha-response"),
            (
                "http://127.0.0.1:1/captcha-frame/newassets.hcaptcha.com/captcha/v1/fixture",
                "h-captcha-response",
            ),
        ] {
            assert_eq!(captcha_field(url), field, "{url}");
        }
    }

    #[test]
    fn captcha_frames() {
        for yes in [
            "https://www.google.com/recaptcha/api2/anchor?k=x",
            "https://www.recaptcha.net/recaptcha/enterprise/anchor?k=x",
            "http://127.0.0.1:1/captcha-frame/www.google.com/recaptcha/api2/anchor?k=fixture",
            "https://www.google.co.uk/recaptcha/api2/anchor",
            "https://newassets.hcaptcha.com/captcha/v1/x",
            "https://challenges.cloudflare.com/cdn-cgi/x",
            // `size=invisible` before `anchor` does not count.
            "https://www.google.com/x?size=invisible/www.google.com/recaptcha/api2/anchor?k=x",
        ] {
            assert!(captcha_frame(yes), "{yes}");
        }
        for no in [
            "https://www.google.com/recaptcha/api2/anchor?k=x&size=invisible",
            "https://www.google.com/recaptcha/api2/bframe?k=x",
            "https://www.GOOGLE.com/recaptcha/api2/anchor",
            "https://www.google.com/Recaptcha/api2/anchor",
            "https://google./recaptcha/api2/anchor",
            "https://www.google.com:443/recaptcha/api2/anchor",
            "https://example.test/",
        ] {
            assert!(!captcha_frame(no), "{no}");
        }
    }

    /// Frame URLs read from real providers' public demo pages (read only, never touched), 2026-11-06.
    #[test]
    fn challenge_frames_of_real_providers() {
        for yes in [
            "https://www.google.com/recaptcha/api2/anchor?ar=1&k=6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-&co=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTo0NDM.&hl=en&v=x&size=normal&cb=y",
            "https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html#frame=checkbox&id=0",
            "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2/av0/rcv/x/0x4AAAAAAA/auto/fbE/new/normal/auto/",
            "https://geo.captcha-delivery.com/captcha/?initialCid=x&hash=y",
            "https://client-api.arkoselabs.com/fc/gc/?token=x",
        ] {
            assert!(challenge_frame(yes), "{yes}");
        }
        for no in [
            "https://www.google.com/recaptcha/api2/anchor?ar=1&k=x&size=invisible&cb=y",
            "https://www.google.com/recaptcha/api2/bframe?hl=en&v=x&k=y",
            "https://www.youtube.com/embed/x",
            "https://js.stripe.com/v3/m-outer-x.html",
            "about:blank",
        ] {
            assert!(!challenge_frame(no), "{no}");
        }
    }

    #[test]
    fn sweep_forms_match_the_testkit() {
        use phantab_testkit::sign_in::{PASSWORD, leak_forms, sweep_forms as kit};
        let pw = Secret::new(PASSWORD.to_owned());
        let ours: Vec<String> = sweep_forms(Some(&pw)).iter().map(|s| s.expose().to_owned()).collect();
        assert_eq!(ours, kit(PASSWORD).to_vec());
        // Every sweep form is one the no-leak search looks for; the form-encoded body is extra.
        let all = leak_forms(PASSWORD, "914207");
        assert!(ours.iter().all(|f| all.contains(f)));
        for odd in ["é ü", "a'b(c)~d*e", "x;y,z/?:@&=+$#", "\u{1F600}", " "] {
            let s = Secret::new(odd.to_owned());
            let ours: Vec<String> = sweep_forms(Some(&s)).iter().map(|s| s.expose().to_owned()).collect();
            assert_eq!(ours, kit(odd).to_vec(), "{odd}");
        }
        assert!(sweep_forms(None).is_empty());
        assert!(sweep_forms(Some(&Secret::new(String::new()))).is_empty());
    }

    #[test]
    fn echo_forms_hold_every_form_the_no_leak_search_looks_for() {
        use phantab_testkit::sign_in::{PASSWORD, form_urlencode as kit_form, leak_forms};
        let pw = Secret::new(PASSWORD.to_owned());
        let ours: Vec<String> = echo_forms(Some(&pw)).iter().map(|s| s.expose().to_owned()).collect();
        // Each password form the testkit searches for holds one of ours (the code is redacted as a token).
        for form in leak_forms(PASSWORD, "914207").iter().filter(|f| *f != "914207") {
            assert!(ours.iter().any(|o| form.contains(o.as_str())), "{form}");
        }
        assert!(ours.contains(&"S3ntinel%20pw%2b%2f%3d!".to_owned()));
        assert!(ours.contains(&"S3ntinel+pw%2b%2f%3d%21".to_owned()));
        let mut sorted = ours.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ours.len(), "no form twice");
        for odd in ["é ü", "a'b(c)~d*e", "x;y,z/?:@&=+$#", "\u{1F600}", " "] {
            let s = Secret::new(odd.to_owned());
            let ours: Vec<String> = echo_forms(Some(&s)).iter().map(|s| s.expose().to_owned()).collect();
            assert!(ours.contains(&kit_form(odd)), "{odd}");
        }
        assert!(echo_forms(None).is_empty());
    }
}
