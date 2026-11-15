//! A new sign-up password (THREAT-MODEL SR-78): 20 characters from `A–Z a–z 0–9 !@$%*-_`
//! with one of each class, cut to the form's `maxlength` (never below 12) and narrowed by its
//! `passwordrules`. phantab's own generator, not `bw generate`: the CLI's special set (`!@#$%^&*`) is not
//! this alphabet, and it cannot narrow to a site's rules. Every pick is unbiased (rejection sampling on
//! the OS's random source).

use zeroize::Zeroizing;

use super::label::Outcome;
use super::secret::Secret;

/// The length a sign-up password gets when the form does not ask for another.
pub(crate) const LENGTH: usize = 20;
/// The shortest password phantab makes: a form that allows less is refused.
pub(crate) const SHORTEST: usize = 12;
/// The longest, whatever a form's `minlength` says.
pub(crate) const LONGEST: usize = 128;

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@$%*-_";
/// How much text of a `passwordrules` attribute is read.
const RULES_LIMIT: usize = 500;

/// What a password must be: its length, the characters it may use, the sets it needs one of each of, and
/// how many of one character may follow each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rules {
    pub(crate) length: usize,
    pub(crate) alphabet: Vec<u8>,
    pub(crate) required: Vec<Vec<u8>>,
    pub(crate) max_consecutive: Option<usize>,
}

/// One `passwordrules` character class, inside phantab's alphabet.
fn class(name: &str) -> Option<Vec<u8>> {
    let all = || [UPPER, LOWER, DIGIT, SPECIAL].concat();
    Some(match name {
        "upper" => UPPER.to_vec(),
        "lower" => LOWER.to_vec(),
        "digit" => DIGIT.to_vec(),
        "special" => SPECIAL.to_vec(),
        "ascii-printable" | "unicode" => all(),
        _ => {
            let inner = name.strip_prefix('[')?.strip_suffix(']')?;
            let set: Vec<u8> = all().into_iter().filter(|c| inner.as_bytes().contains(c)).collect();
            set
        }
    })
}

/// What a `passwordrules` attribute asks, as far as phantab reads it: `required`, `allowed`,
/// `max-consecutive`, `minlength`, `maxlength` (the WHATWG proposal's properties).
#[derive(Debug, Default)]
struct Asked {
    required: Vec<Vec<u8>>,
    allowed: Vec<u8>,
    named: bool,
    max_consecutive: Option<usize>,
    min: Option<usize>,
    max: Option<usize>,
}

/// Splits on `,` outside a `[...]` class.
fn classes(value: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth) = (Vec::new(), String::new(), false);
    for ch in value.chars() {
        match ch {
            '[' => {
                depth = true;
                cur.push(ch);
            }
            ']' => {
                depth = false;
                cur.push(ch);
            }
            ',' if !depth => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out.into_iter().map(|c| c.trim().to_lowercase()).filter(|c| !c.is_empty()).collect()
}

/// `None` when a class it names has no character phantab may use.
fn parse(text: &str) -> Option<Asked> {
    let mut asked = Asked::default();
    let text: String = text.chars().take(RULES_LIMIT).collect();
    for part in text.split(';') {
        let Some((key, value)) = part.split_once(':') else { continue };
        let key = key.trim().to_lowercase();
        let number = || value.trim().parse::<usize>().ok().filter(|n| *n > 0);
        match key.as_str() {
            "required" | "allowed" => {
                asked.named = true;
                let mut union = Vec::new();
                for c in classes(value) {
                    let set = class(&c)?;
                    if set.is_empty() {
                        return None;
                    }
                    union.extend(set);
                }
                if union.is_empty() {
                    continue;
                }
                if key == "required" {
                    asked.allowed.extend(&union);
                    asked.required.push(union);
                } else {
                    asked.allowed.extend(union);
                }
            }
            "max-consecutive" => asked.max_consecutive = number().or(asked.max_consecutive),
            "minlength" => asked.min = number().or(asked.min),
            "maxlength" => asked.max = number().or(asked.max),
            _ => {}
        }
    }
    Some(asked)
}

fn sorted(mut set: Vec<u8>) -> Vec<u8> {
    set.sort_unstable();
    set.dedup();
    set
}

/// The rules a form's `maxlength`, `minlength` and `passwordrules` make, or the refusal:
/// `password-too-short` when the form allows less than [`SHORTEST`], `password-rules` when its rules
/// leave nothing phantab can make.
pub(crate) fn rules(
    max_length: Option<usize>,
    min_length: Option<usize>,
    text: Option<&str>,
) -> Result<Rules, Outcome> {
    let refused = |why| Outcome::with("not-a-sign-up", why);
    let asked = match text {
        Some(t) => parse(t).ok_or_else(|| refused("password-rules"))?,
        None => Asked::default(),
    };
    let max = [max_length, asked.max].into_iter().flatten().min();
    let min = [min_length, asked.min].into_iter().flatten().max().unwrap_or(0);
    let mut length = LENGTH.max(min).min(LONGEST);
    if let Some(max) = max {
        length = length.min(max);
    }
    if length < SHORTEST || max.is_some_and(|m| m < SHORTEST) {
        return Err(refused("password-too-short"));
    }
    if length < min {
        return Err(refused("password-rules"));
    }
    let (alphabet, required) = if asked.named {
        let required: Vec<Vec<u8>> = asked.required.into_iter().map(sorted).collect();
        (sorted(asked.allowed), required)
    } else {
        (
            [UPPER, LOWER, DIGIT, SPECIAL].concat(),
            vec![UPPER.to_vec(), LOWER.to_vec(), DIGIT.to_vec(), SPECIAL.to_vec()],
        )
    };
    if alphabet.is_empty() || required.len() > length || asked.max_consecutive == Some(0) {
        return Err(refused("password-rules"));
    }
    if asked.max_consecutive == Some(1) && alphabet.len() < 2 {
        return Err(refused("password-rules"));
    }
    Ok(Rules { length, alphabet, required, max_consecutive: asked.max_consecutive })
}

/// An unbiased index below `n` (`0 < n <= 256`), or `None` when the OS gives no random bytes.
fn pick(n: usize) -> Option<usize> {
    let n = u16::try_from(n).ok().filter(|n| (1..=256).contains(n))?;
    // The largest multiple of n that fits in 0..256: bytes at or above it are drawn again.
    let limit = 256 - (256 % n);
    loop {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).ok()?;
        if u16::from(b[0]) < limit {
            return Some(usize::from(u16::from(b[0]) % n));
        }
    }
}

fn fits(candidate: &[u8], rules: &Rules) -> bool {
    let classes = rules.required.iter().all(|set| candidate.iter().any(|c| set.contains(c)));
    let runs = rules.max_consecutive.is_none_or(|n| {
        let mut run = 0usize;
        let mut last = None;
        candidate.iter().all(|c| {
            run = if last == Some(c) { run + 1 } else { 1 };
            last = Some(c);
            run <= n
        })
    });
    classes && runs
}

/// A new password under `rules`; `None` when the OS gives no random bytes, or no try fits.
pub(crate) fn password(rules: &Rules) -> Option<Secret> {
    for _ in 0..1000 {
        let mut bytes = Zeroizing::new(Vec::with_capacity(rules.length));
        for _ in 0..rules.length {
            bytes.push(rules.alphabet[pick(rules.alphabet.len())?]);
        }
        if fits(&bytes, rules) {
            // Every byte is ASCII from the alphabet.
            let text: String = bytes.iter().map(|b| char::from(*b)).collect();
            return Some(Secret::new(text));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn made(rules: &Rules) -> String {
        password(rules).unwrap().expose().to_owned()
    }

    #[test]
    fn the_default_shape() {
        let r = rules(None, None, None).unwrap();
        assert_eq!(r.length, 20);
        for _ in 0..200 {
            let p = made(&r);
            assert_eq!(p.len(), 20);
            assert!(p.bytes().all(|b| r.alphabet.contains(&b)));
            for set in [UPPER, LOWER, DIGIT, SPECIAL] {
                assert!(p.bytes().any(|b| set.contains(&b)));
            }
        }
        assert_ne!(made(&r), made(&r));
    }

    #[test]
    fn maxlength_cuts_and_never_below_twelve() {
        assert_eq!(rules(Some(16), None, None).unwrap().length, 16);
        assert_eq!(rules(Some(12), None, None).unwrap().length, 12);
        assert_eq!(rules(Some(64), None, None).unwrap().length, 20);
        assert_eq!(rules(Some(11), None, None), Err(Outcome::with("not-a-sign-up", "password-too-short")));
        assert_eq!(rules(None, Some(30), None).unwrap().length, 30);
        assert_eq!(rules(None, Some(LONGEST), None).unwrap().length, LONGEST);
        // A form that wants more than phantab makes is refused, not handed a password it would reject.
        assert_eq!(rules(None, Some(500), None), Err(Outcome::with("not-a-sign-up", "password-rules")));
        assert_eq!(rules(Some(14), Some(16), None), Err(Outcome::with("not-a-sign-up", "password-rules")));
        assert_eq!(
            rules(None, None, Some("maxlength: 8;")),
            Err(Outcome::with("not-a-sign-up", "password-too-short"))
        );
        assert_eq!(rules(Some(40), None, Some("minlength: 24")).unwrap().length, 24);
    }

    #[test]
    fn passwordrules_narrow_the_alphabet() {
        let r = rules(None, None, Some("required: lower; required: digit; allowed: [-_]")).unwrap();
        assert_eq!(r.alphabet, sorted([LOWER, DIGIT, b"-_"].concat()));
        for _ in 0..100 {
            let p = made(&r);
            assert!(p.bytes().all(|b| r.alphabet.contains(&b)));
            assert!(p.bytes().any(|b| b.is_ascii_lowercase()) && p.bytes().any(|b| b.is_ascii_digit()));
        }
        let only = rules(None, None, Some("required: upper, digit; max-consecutive: 1")).unwrap();
        assert_eq!(only.required.len(), 1);
        for _ in 0..100 {
            let p = made(&only);
            assert!(p.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
            assert!(p.as_bytes().windows(2).all(|w| w[0] != w[1]));
        }
        // A class phantab has no character for (`#` is not in its alphabet).
        assert_eq!(
            rules(None, None, Some("required: [#]")),
            Err(Outcome::with("not-a-sign-up", "password-rules"))
        );
        // Rules that name nothing keep the default.
        assert_eq!(rules(None, None, Some("nonsense")).unwrap().alphabet.len(), 69);
    }

    #[test]
    fn picks_are_in_range() {
        for n in [1, 2, 7, 69, 255, 256] {
            for _ in 0..50 {
                assert!(pick(n).unwrap() < n);
            }
        }
        assert_eq!(pick(0), None);
        assert_eq!(pick(257), None);
    }
}
