//! The service hello (THREAT-MODEL SR-13): before a client sends the bearer token, the listener on the
//! endpoint's port must prove it knows that token. The client sends a random nonce to the
//! unauthenticated `GET /hello?nonce=<hex>`; the service answers `{"proof": hex(HMAC-SHA256(token,
//! "phantab-hello" || nonce)), "keep": 120}`, nonce as raw bytes. A stale endpoint whose port another
//! process now holds cannot answer, so it never sees `Authorization`.
//!
//! `keep` is how many seconds the service holds a connection that has carried a valid token idle
//! between requests. A client reuses the proven connection only when it is there, so a client newer
//! than its service (whose hold is the 30 s header wait) opens a connection per call, as before.

use hmac::{KeyInit as _, Mac as _};
use sha2::Sha256;

use crate::util::hex;

type HmacSha256 = hmac::Hmac<Sha256>;

/// The nonce is this many random bytes, hex in the query.
pub const NONCE_LEN: usize = 32;
const CONTEXT: &[u8] = b"phantab-hello";
/// The hello answer's field for the service's idle hold, in seconds.
pub const KEEP: &str = "keep";

fn mac(token: &str, nonce: &[u8]) -> Option<HmacSha256> {
    // HMAC accepts a key of any length, so this never fails; `None` keeps the caller panic-free.
    let mut mac = HmacSha256::new_from_slice(token.as_bytes()).ok()?;
    mac.update(CONTEXT);
    mac.update(nonce);
    Some(mac)
}

/// The service's answer to `nonce`, as lowercase hex.
#[must_use]
pub fn proof(token: &str, nonce: &[u8]) -> Option<String> {
    Some(hex(&mac(token, nonce)?.finalize().into_bytes()))
}

/// Whether `proof_hex` is the answer to `nonce` for `token`, compared in constant time.
#[must_use]
pub fn verify(token: &str, nonce: &[u8], proof_hex: &str) -> bool {
    let (Some(mac), Some(proof)) = (mac(token, nonce), from_hex(proof_hex)) else { return false };
    mac.verify_slice(&proof).is_ok()
}

/// The `nonce` of a `/hello` request target: exactly [`NONCE_LEN`] bytes of hex, else `None`.
#[must_use]
pub fn nonce_of(target: &str) -> Option<Vec<u8>> {
    let hex = target.strip_prefix("/hello?nonce=")?;
    from_hex(hex).filter(|n| n.len() == NONCE_LEN)
}

/// Lowercase or uppercase hex to bytes; `None` for an odd length or a non-hex digit.
#[must_use]
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let value = |d: u8| char::from(d).to_digit(16).and_then(|v| u8::try_from(v).ok());
    digits.as_chunks::<2>().0.iter().map(|&[hi, lo]| Some(value(hi)? << 4 | value(lo)?)).collect()
}

/// A fresh nonce.
///
/// # Errors
/// The OS refused randomness.
pub fn nonce() -> std::io::Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n).map_err(std::io::Error::other)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proof_is_hmac_sha256_over_the_context_and_nonce() {
        let token = "aa".repeat(32);
        let nonce = [7u8; NONCE_LEN];
        let p = proof(&token, &nonce).unwrap();
        assert_eq!(p.len(), 64);
        assert!(verify(&token, &nonce, &p));
        assert!(verify(&token, &nonce, &p.to_uppercase()));
        assert!(!verify(&token, &[8u8; NONCE_LEN], &p));
        assert!(!verify(&"bb".repeat(32), &nonce, &p));
        assert!(!verify(&token, &nonce, &p[..62]));
        assert!(!verify(&token, &nonce, ""));
        assert!(!verify(&token, &nonce, "zz"));
        let mut manual = HmacSha256::new_from_slice(token.as_bytes()).unwrap();
        manual.update(b"phantab-hello");
        manual.update(&nonce);
        assert_eq!(hex(&manual.finalize().into_bytes()), p);
    }

    #[test]
    fn only_a_full_length_hex_nonce_is_taken() {
        let good = "0f".repeat(NONCE_LEN);
        assert_eq!(nonce_of(&format!("/hello?nonce={good}")), Some(vec![0x0f; NONCE_LEN]));
        assert_eq!(nonce_of(&format!("/hello?nonce={}", "0f".repeat(NONCE_LEN - 1))), None);
        assert_eq!(nonce_of(&format!("/hello?nonce={good}&x=1")), None);
        assert_eq!(nonce_of("/hello"), None);
        assert_eq!(nonce_of(&format!("/hello?nonce={}", "g0".repeat(NONCE_LEN))), None);
    }
}
