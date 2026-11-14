//! The saved-login values a fake provider hands out, and the forms a leak takes.
//!
//! The values are fixed, so every run sees the same
//! bytes. They are fixtures, not credentials.

/// The password the fake provider returns. It has a space, `+`, `/`, `=` and `!`
/// so every encoding below differs from the raw text.
pub const PASSWORD: &str = "S3ntinel pw+/=!";
/// The username the fake provider returns.
pub const USERNAME: &str = "fixture-user@example.test";
/// The one-time code the fake provider returns.
pub const CODE: &str = "914207";

/// The six forms the sign-in sweep looks for in a frame's URL, `location.href`
/// and text: raw, `encodeURIComponent`, `encodeURI`,
/// `encodeURIComponent` with `%20` as `+`, base64 and base64url (unpadded).
pub fn sweep_forms(password: &str) -> [String; 6] {
    let component = encode_uri_component(password);
    [
        password.to_owned(),
        component.clone(),
        encode_uri(password),
        component.replace("%20", "+"),
        base64(password.as_bytes(), STANDARD, true),
        base64(password.as_bytes(), URL_SAFE, false),
    ]
}

/// Every form a no-leak check searches results, logs and the runtime folder for:
/// the sweep forms of the password, its `application/x-www-form-urlencoded` form
/// (which differs from the sweep's `+` form for `!`, `'`, `(`, `)` and `~`), and the code.
pub fn leak_forms(password: &str, code: &str) -> Vec<String> {
    let mut forms = sweep_forms(password).to_vec();
    forms.push(form_urlencode(password));
    forms.push(code.to_owned());
    forms.sort();
    forms.dedup();
    forms
}

/// The forms of a value no test output may contain: `leak_forms(PASSWORD, CODE)`.
pub fn fixture_leak_forms() -> Vec<String> {
    leak_forms(PASSWORD, CODE)
}

/// The first leak form found in `haystack`, if any. Name it in a failure without
/// printing the haystack (it may hold the value).
pub fn find_leak<'a>(haystack: &str, forms: &'a [String]) -> Option<&'a str> {
    forms.iter().find(|form| haystack.contains(form.as_str())).map(String::as_str)
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let symbols = chunk.len() + 1;
        for i in 0..4 {
            if i < symbols {
                out.push(char::from(alphabet[(n >> (18 - 6 * i) & 63) as usize]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn percent_encode(input: &str, keep: impl Fn(u8) -> bool, space_as_plus: bool) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for &b in input.as_bytes() {
        if space_as_plus && b == b' ' {
            out.push('+');
        } else if keep(b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[usize::from(b >> 4)]));
            out.push(char::from(b"0123456789ABCDEF"[usize::from(b & 15)]));
        }
    }
    out
}

/// JavaScript's `encodeURIComponent` (for well-formed strings).
pub fn encode_uri_component(input: &str) -> String {
    percent_encode(input, |b| b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b), false)
}

/// JavaScript's `encodeURI` (for well-formed strings).
pub fn encode_uri(input: &str) -> String {
    percent_encode(input, |b| b.is_ascii_alphanumeric() || b"-_.!~*'();/?:@&=+$,#".contains(&b), false)
}

/// What `URLSearchParams` (and a form post) writes for a value.
pub fn form_urlencode(input: &str) -> String {
    percent_encode(input, |b| b.is_ascii_alphanumeric() || b"*-._".contains(&b), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_node() {
        // Expected values from Node 22 for the same input.
        assert_eq!(
            sweep_forms(PASSWORD),
            [
                "S3ntinel pw+/=!",
                "S3ntinel%20pw%2B%2F%3D!",
                "S3ntinel%20pw+/=!",
                "S3ntinel+pw%2B%2F%3D!",
                "UzNudGluZWwgcHcrLz0h",
                "UzNudGluZWwgcHcrLz0h",
            ]
            .map(str::to_owned)
        );
        assert_eq!(form_urlencode(PASSWORD), "S3ntinel+pw%2B%2F%3D%21");
        assert_eq!(base64(b"a?>", URL_SAFE, false), "YT8-");
        assert_eq!(base64(b"ab", STANDARD, true), "YWI=");
        assert_eq!(base64(b"ab", URL_SAFE, false), "YWI");
        assert_eq!(encode_uri_component("é"), "%C3%A9");
    }

    #[test]
    fn finds_leaks() {
        let forms = fixture_leak_forms();
        assert_eq!(find_leak("all clear", &forms), None);
        assert_eq!(find_leak("x?t=S3ntinel%20pw%2B%2F%3D!", &forms), Some("S3ntinel%20pw%2B%2F%3D!"));
        assert_eq!(find_leak("code 914207", &forms), Some(CODE));
    }
}
