//! The provider seal (`requestDigest`, `seal`, `unseal`; THREAT-MODEL SR-43): X25519, then
//! HKDF-SHA256 with an empty salt and info `phantab-sign-in-seal-1` to a 32-byte AES-256-GCM key. Keys travel
//! as SPKI DER in base64, as Node's `export({format:'der',type:'spki'})` writes them.

use aes_gcm::aead::Aead as _;
use aes_gcm::{Aes256Gcm, KeyInit as _};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::secret::Scrubbed;

pub(crate) const INFO: &[u8] = b"phantab-sign-in-seal-1";
/// SPKI DER for an X25519 key is this 12-byte header and the 32 key bytes (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];

/// What the service asks the provider: `{urls, account, accountKey, want}`, in that key order.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) urls: Vec<String>,
    pub(crate) account: Option<String>,
    #[serde(rename = "accountKey")]
    pub(crate) account_key: Option<String>,
    pub(crate) want: Vec<&'static str>,
}

impl Request {
    /// `JSON.stringify(request)`: the stdin bytes and the digest's input. `serde_json`
    /// writes what Node writes for these shapes: no spaces, fields in declaration order, and only `"`,
    /// `\` and control characters escaped (`\b \f \n \r \t`, else `\u00xx` in lower case). A Rust string
    /// cannot hold the lone surrogate that Node writes as `\udxxx`.
    pub(crate) fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// `sha256(JSON.stringify({urls,account,accountKey,want}))` in lower-case hex.
pub(crate) fn digest(json: &str) -> String {
    crate::util::hex(&Sha256::digest(json.as_bytes()))
}

pub(crate) fn spki(public: &PublicKey) -> String {
    let mut der = [0u8; 44];
    der[..12].copy_from_slice(&SPKI_PREFIX);
    der[12..].copy_from_slice(public.as_bytes());
    STANDARD.encode(der)
}

fn parse_spki(b64: &str) -> Option<PublicKey> {
    let der = STANDARD.decode(b64).ok()?;
    let key: [u8; 32] = der.strip_prefix(&SPKI_PREFIX[..])?.try_into().ok()?;
    Some(PublicKey::from(key))
}

fn aes_key(secret: &StaticSecret, peer: &PublicKey) -> Option<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(peer);
    // OpenSSL refuses an all-zero shared secret (a low-order peer key), so Node's unseal throws: refused.
    if !shared.was_contributory() {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&[]), shared.as_bytes()).expand(INFO, &mut key[..]).ok()?;
    Some(key)
}

fn random_secret() -> std::io::Result<StaticSecret> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut bytes[..]).map_err(std::io::Error::other)?;
    Ok(StaticSecret::from(*bytes))
}

/// The service's key pair for one call. The secret zeroizes itself when dropped (x25519-dalek's
/// `zeroize` feature).
pub(crate) struct KeyPair {
    secret: StaticSecret,
    public: String,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair").field("public", &self.public).finish_non_exhaustive()
    }
}

impl KeyPair {
    pub(crate) fn generate() -> std::io::Result<Self> {
        Ok(Self::from_secret(random_secret()?))
    }

    fn from_secret(secret: StaticSecret) -> Self {
        let public = spki(&PublicKey::from(&secret));
        KeyPair { secret, public }
    }

    /// The public key as the provider's last argument: SPKI DER, base64.
    pub(crate) fn public(&self) -> &str {
        &self.public
    }

    /// `unseal(privateKey, sealed)`. `None` wherever Node would throw (a missing or wrong-typed field, bad
    /// base64, a wrong key, a failed tag, a payload that is not JSON): the caller answers `refused`.
    /// phantab is stricter than Node's lenient `Buffer.from(x,'base64')`: standard padded base64 only, a
    /// 12-byte IV and a 16-byte tag, the sizes [`seal`] writes.
    pub(crate) fn unseal(&self, sealed: &Value) -> Option<Scrubbed> {
        let field = |name: &str| sealed.get(name).and_then(Value::as_str);
        let peer = parse_spki(field("epk")?)?;
        let key = aes_key(&self.secret, &peer)?;
        let iv = STANDARD.decode(field("iv")?).ok()?;
        let tag = STANDARD.decode(field("tag")?).ok()?;
        if iv.len() != 12 || tag.len() != 16 {
            return None;
        }
        let mut data = Zeroizing::new(STANDARD.decode(field("data")?).ok()?);
        data.extend_from_slice(&tag);
        let cipher = Aes256Gcm::new_from_slice(&key[..]).ok()?;
        let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(&iv[..]).ok()?;
        let plain = Zeroizing::new(cipher.decrypt(&nonce, &data[..]).ok()?);
        serde_json::from_slice::<Value>(&plain).ok().map(Scrubbed)
    }
}

/// `seal(publicKey, payload)`, the provider's side, for test providers (the fake provider binary).
///
/// # Errors
/// The public key is not an X25519 SPKI key, or the system has no randomness.
#[cfg(any(test, feature = "test-seams"))]
pub fn seal(public_key: &str, payload: &Value) -> std::io::Result<Value> {
    let bad = || std::io::Error::other("bad public key");
    let peer = parse_spki(public_key).ok_or_else(bad)?;
    let mine = random_secret()?;
    let key = aes_key(&mine, &peer).ok_or_else(bad)?;
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).map_err(std::io::Error::other)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| bad())?;
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::from(iv);
    let plain = Zeroizing::new(serde_json::to_vec(payload)?);
    let mut out = cipher.encrypt(&nonce, &plain[..]).map_err(|_| bad())?;
    let tag = out.split_off(out.len() - 16);
    Ok(serde_json::json!({
        "epk": spki(&PublicKey::from(&mine)),
        "iv": STANDARD.encode(iv),
        "data": STANDARD.encode(&out),
        "tag": STANDARD.encode(&tag),
    }))
}

/// `requestDigest`, the provider's side, for test providers.
#[cfg(any(test, feature = "test-seams"))]
#[must_use]
pub fn request_digest(request: &Value) -> String {
    let field = |name: &str| request.get(name).cloned().unwrap_or(Value::Null);
    let mut map = serde_json::Map::new();
    for name in ["urls", "account", "accountKey", "want"] {
        // JSON.stringify drops an undefined field; a request always has all four.
        if request.get(name).is_some() {
            map.insert(name.to_owned(), field(name));
        }
    }
    digest(&Value::Object(map).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_round_trip() {
        let pair = KeyPair::generate().unwrap();
        let der = STANDARD.decode(pair.public()).unwrap();
        assert_eq!(der.len(), 44);
        assert_eq!(&der[..12], &SPKI_PREFIX);
        assert!(parse_spki(pair.public()).is_some());
        assert!(parse_spki("AAAA").is_none());
        assert!(!format!("{pair:?}").contains("secret"));
    }

    #[test]
    fn seal_then_unseal() {
        let pair = KeyPair::generate().unwrap();
        let payload =
            serde_json::json!({"digest": "d", "accountKey": "k", "values": {"password": "S3ntinel pw+/=!"}});
        let sealed = seal(pair.public(), &payload).unwrap();
        assert_eq!(pair.unseal(&sealed).map(|s| s.0.clone()), Some(payload.clone()));
        // Another key pair cannot open it.
        assert!(KeyPair::generate().unwrap().unseal(&sealed).is_none());
        // A flipped bit anywhere fails the tag.
        for field in ["data", "tag", "iv"] {
            let mut bent = sealed.clone();
            let mut bytes = STANDARD.decode(bent[field].as_str().unwrap()).unwrap();
            bytes[0] ^= 1;
            bent[field] = STANDARD.encode(&bytes).into();
            assert!(pair.unseal(&bent).is_none(), "{field}");
        }
        for (field, value) in
            [("epk", Value::from(5)), ("iv", "AAAA".into()), ("tag", Value::Null), ("data", "!!".into())]
        {
            let mut bent = sealed.clone();
            bent[field] = value;
            assert!(pair.unseal(&bent).is_none(), "{field}");
        }
        assert!(pair.unseal(&Value::Null).is_none());
        // A low-order peer key (all zero) gives an all-zero shared secret: refused, as OpenSSL does.
        let mut zero = sealed;
        let mut der = SPKI_PREFIX.to_vec();
        der.extend([0u8; 32]);
        zero["epk"] = STANDARD.encode(der).into();
        assert!(pair.unseal(&zero).is_none());
    }

    #[test]
    fn request_json_is_node_json() {
        let r = Request {
            urls: vec!["https://a.test/x".into(), "https://b.test/\u{2028}\u{7f}é/\"\\".into()],
            account: Some("a\u{1}\u{8}\u{c}\n\r\t\u{1f}b".into()),
            account_key: None,
            want: vec!["username", "password"],
        };
        // Node 22: JSON.stringify({urls:[...],account:'a\x01\b\f\n\r\t\x1fb',accountKey:null,want:[...]}).
        assert_eq!(
            r.to_json(),
            "{\"urls\":[\"https://a.test/x\",\"https://b.test/\u{2028}\u{7f}é/\\\"\\\\\"],\"account\":\"a\\u0001\\b\\f\\n\\r\\t\\u001fb\",\"accountKey\":null,\"want\":[\"username\",\"password\"]}"
        );
        let v: Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(request_digest(&v), digest(&r.to_json()));
        // sha256 of the empty request as Node writes it.
        let empty = Request { urls: vec![], account: None, account_key: None, want: vec![] };
        assert_eq!(empty.to_json(), r#"{"urls":[],"account":null,"accountKey":null,"want":[]}"#);
    }

    /// Made by an independent `node:crypto` seal (Node 25: X25519, HKDF-SHA256 with info
    /// `phantab-sign-in-seal-1`, AES-256-GCM) for a fixed service key, ephemeral key and IV: Rust opens
    /// what Node seals.
    const KAT_PRIVATE: &str = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc";
    const KAT_PUBLIC: &str = "MCowBQYDK2VuAyEAu1D/noKldM+/gg6X9g+5wUPsdBXPUU+M/Zjv9Z4FlhQ=";
    const KAT_DIGEST: &str = "829acce8ffe2b4a848a4d3f8d842a6b0f121714ef1a64189a309b79aace7b8dc";
    const KAT_SEALED: &str = r#"{"epk":"MCowBQYDK2VuAyEAh5aMHBZCvQYA9q2Gm4j5LJYj0N/ETwHe/+Icmt09yl8=","iv":"AAECAwQFBgcICQoL","data":"5JAlbVQpjUKZVW4LErDcmf9A41t66Rqv0wQveU+F4ay4PLZWtn/HaWvMxjCcn/FLHnrszT1NCnX1dY/Do2+ZS0C5NXYnshNKV4NrugR2I7qxvOGWD9ZvHAykD7VzKeABlXLQOduTwqy2I4bHrz+0BMJjCy83GDQ1/nSYVKTr0m6eD/aoCiLr4C0kOmCWRCj7mUgK/xSUjleuhVPubA5Q","tag":"CdUEDq+TsvKpT2xxEhdfnA=="}"#;

    fn kat_pair(hex: &str) -> KeyPair {
        let bytes: Vec<u8> =
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        let key: [u8; 32] = bytes.try_into().unwrap();
        KeyPair::from_secret(StaticSecret::from(key))
    }

    fn kat_request() -> Request {
        Request {
            urls: vec!["https://kat.test/login".into()],
            account: None,
            account_key: None,
            want: vec!["username", "password"],
        }
    }

    #[test]
    fn node_seal_known_answer() {
        let pair = kat_pair(KAT_PRIVATE);
        assert_eq!(pair.public(), KAT_PUBLIC, "SPKI export matches Node's");
        let request = kat_request();
        assert_eq!(digest(&request.to_json()), KAT_DIGEST, "request digest matches Node's");
        let sealed: Value = serde_json::from_str(KAT_SEALED).unwrap();
        let opened = pair.unseal(&sealed).unwrap();
        assert_eq!(
            opened.0,
            serde_json::json!({"digest": KAT_DIGEST, "accountKey": "kat-account", "values": {"username": "kat-user", "password": "kat-pass"}})
        );
        let answer = super::super::provider::open_answer(
            &pair,
            &request.to_json(),
            &request.want,
            &serde_json::json!({"status": "ok", "sealed": sealed}),
        );
        assert!(
            matches!(answer, super::super::provider::Answer::Ok { ref account_key, .. } if account_key == "kat-account")
        );
    }

    /// The same check against a fresh vector, when node is here: Node seals to a fixed key with its own
    /// `node:crypto` (a fresh ephemeral key and IV each run), and Rust opens it.
    #[test]
    fn node_seal_live() {
        let script = r"import crypto from 'node:crypto';
const der=(h)=>crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'),Buffer.from(h,'hex')]),format:'der',type:'pkcs8'});
const pub=crypto.createPublicKey(der(process.argv[2])).export({format:'der',type:'spki'}).toString('base64');
const request={urls:['https://kat.test/login'],account:null,accountKey:null,want:['username','password']};
const digest=crypto.createHash('sha256').update(JSON.stringify(request)).digest('hex');
const {publicKey:ephPub,privateKey:eph}=crypto.generateKeyPairSync('x25519');
const shared=crypto.diffieHellman({privateKey:eph,publicKey:crypto.createPublicKey({key:Buffer.from(pub,'base64'),format:'der',type:'spki'})});
const key=Buffer.from(crypto.hkdfSync('sha256',shared,Buffer.alloc(0),Buffer.from('phantab-sign-in-seal-1'),32));
const iv=crypto.randomBytes(12);const c=crypto.createCipheriv('aes-256-gcm',key,iv);
const data=Buffer.concat([c.update(JSON.stringify({digest,accountKey:'live',values:{username:'u',password:'p'}}),'utf8'),c.final()]);
const sealed={epk:ephPub.export({format:'der',type:'spki'}).toString('base64'),iv:iv.toString('base64'),data:data.toString('base64'),tag:c.getAuthTag().toString('base64')};
console.log(JSON.stringify({pub,sealed}));process.exit(0);";
        let dir = std::env::temp_dir().join(format!("phantab-kat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("kat.mjs");
        std::fs::write(&file, script).unwrap();
        let hex = "a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
        let out = std::process::Command::new("node").arg(&file).arg(hex).output();
        let _ = std::fs::remove_dir_all(&dir);
        let Ok(out) = out.map_err(|e| eprintln!("skipped: no node ({e})")) else { return };
        assert!(out.status.success(), "node failed");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        let pair = kat_pair(hex);
        assert_eq!(v["pub"], pair.public());
        let opened = pair.unseal(&v["sealed"]).unwrap();
        assert_eq!(opened.0["digest"], digest(&kat_request().to_json()));
        assert_eq!(opened.0["values"]["password"], "p");
    }
}
