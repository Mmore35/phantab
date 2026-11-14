//! Where the Bitwarden CLI session key waits between calls (docs/BITWARDEN.md § Session storage,
//! THREAT-MODEL SR-62). The key unlocks the CLI's local vault copy until the owner locks or disconnects;
//! the master password is never stored anywhere.
//!
//! - Windows: a DPAPI (`CurrentUser`) blob in `<runtime>/bitwarden/session.dpapi`, in the owner-only
//!   folder, with a fixed entropy so a casual `CryptUnprotectData` from another tool does not open it.
//! - macOS: a generic-password item in the login Keychain, service [`KEYCHAIN_SERVICE`], account the
//!   folder's path (so two runtimes keep two keys).
//! - Elsewhere: no protection is available, so nothing is stored and `connect` refuses.
//!
//! What is stored is a record: the line [`RECORD_HEADER`], the key's [`Pin`] as JSON on one line (the
//! `bw` command and file hashes it was made with), then the key. A store from an earlier phantab holds
//! the bare key: it loads with no pin, so it is never handed to a `bw` until `connect` runs again.

use std::fmt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::pin::Pin;

/// The longest key accepted. A Bitwarden CLI session key is 64 random bytes in base64 (88 characters).
const MAX_KEY: usize = 512;

/// DPAPI entropy for the session file. A constant, not a secret: it only stops another program that
/// does not know it from opening the blob with a bare `CryptUnprotectData`. Test builds (unit tests, and
/// the binary integration tests run) use an entropy and a file name ([`SESSION_FILE`]) of their own, so
/// no test opens, replaces or deletes the owner's blob, even in the owner's runtime folder.
#[cfg(not(any(test, feature = "test-seams")))]
#[cfg_attr(not(windows), allow(dead_code, reason = "the DPAPI vault is Windows only"))]
const DPAPI_ENTROPY: &[u8] = b"dev.phantab.bitwarden-session-1";
#[cfg(any(test, feature = "test-seams"))]
#[cfg_attr(not(windows), allow(dead_code, reason = "the DPAPI vault is Windows only"))]
const DPAPI_ENTROPY: &[u8] = b"dev.phantab.test.bitwarden-session-1";

/// The Keychain service name of the stored key. Test builds (unit tests, and the binary integration
/// tests run) use a name of their own, so no test ever reads, writes or deletes the owner's item.
#[cfg(not(any(test, feature = "test-seams")))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code, reason = "the Keychain vault is macOS only"))]
pub(crate) const KEYCHAIN_SERVICE: &str = "dev.phantab.bitwarden";
#[cfg(any(test, feature = "test-seams"))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code, reason = "the Keychain vault is macOS only"))]
pub(crate) const KEYCHAIN_SERVICE: &str = "dev.phantab.test.bitwarden";

/// The first line of a stored record. A store without it is an earlier phantab's bare key.
const RECORD_HEADER: &str = "phantab-bw-session-2";

/// The session file under the bitwarden folder (Windows). Test builds use a name of their own
/// ([`DPAPI_ENTROPY`]).
#[cfg(not(any(test, feature = "test-seams")))]
#[cfg_attr(not(windows), allow(dead_code, reason = "the DPAPI vault is Windows only"))]
pub(crate) const SESSION_FILE: &str = "session.dpapi";
#[cfg(any(test, feature = "test-seams"))]
#[cfg_attr(not(windows), allow(dead_code, reason = "the DPAPI vault is Windows only"))]
pub(crate) const SESSION_FILE: &str = "session.test.dpapi";

/// A Bitwarden CLI session key: zeroized on drop, `[redacted]` in `Debug`, and only ever placed in the
/// `BW_SESSION` variable of a `bw` child, and only while its [`Pin`] holds (`cli::run`).
pub(crate) struct SessionKey {
    key: Zeroizing<String>,
    /// The `bw` it was made with; `None` for a key an earlier phantab stored, which no child gets.
    pin: Option<Pin>,
}

impl SessionKey {
    /// Accepts what `bw unlock --raw` prints: base64 text, trimmed, of a sane length. Anything else
    /// (an error message on stdout, a prompt) is refused, so it never lands in a child's environment.
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?.trim();
        let ok = !text.is_empty()
            && text.len() <= MAX_KEY
            && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        ok.then(|| SessionKey { key: Zeroizing::new(text.to_owned()), pin: None })
    }

    pub(crate) fn expose(&self) -> &str {
        &self.key
    }

    pub(crate) fn pin(&self) -> Option<&Pin> {
        self.pin.as_ref()
    }

    /// The key, pinned to the `bw` that made it.
    pub(crate) fn pinned(mut self, pin: Pin) -> Self {
        self.pin = Some(pin);
        self
    }

    /// What the store keeps: the header, the pin (`null` when there is none), the key. One buffer, sized
    /// first, so it never grows and leaves a copy behind.
    ///
    /// # Errors
    /// The pin does not serialize (it always does).
    pub(crate) fn record(&self) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let pin = serde_json::to_string(&self.pin).map_err(std::io::Error::other)?;
        let mut out =
            Zeroizing::new(Vec::with_capacity(RECORD_HEADER.len() + pin.len() + self.key.len() + 2));
        out.extend_from_slice(RECORD_HEADER.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(pin.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.key.as_bytes());
        Ok(out)
    }

    /// A stored record, or an earlier phantab's bare key (no pin). `None` when it is neither.
    pub(crate) fn from_record(raw: &[u8]) -> Option<Self> {
        let Some(rest) = raw.strip_prefix(RECORD_HEADER.as_bytes()).and_then(|r| r.strip_prefix(b"\n"))
        else {
            return SessionKey::parse(raw);
        };
        let at = rest.iter().position(|&b| b == b'\n')?;
        let pin: Option<Pin> = serde_json::from_slice(&rest[..at]).ok()?;
        Some(SessionKey { pin, ..SessionKey::parse(&rest[at + 1..])? })
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey([redacted])")
    }
}

/// Keeps one session key at rest.
pub(crate) trait SessionVault: Send + Sync {
    /// The stored key, or `None` when there is none.
    ///
    /// # Errors
    /// The store exists but cannot be read or opened (another account's blob, a damaged file, a refused
    /// Keychain): the caller answers `provider-failed`, never `locked`, so it is looked at.
    fn load(&self) -> std::io::Result<Option<SessionKey>>;
    /// Replaces the stored key.
    ///
    /// # Errors
    /// The store refused, or this platform has none.
    fn store(&self, key: &SessionKey) -> std::io::Result<()>;
    /// Removes the stored key. `Ok(false)` when there was none.
    ///
    /// # Errors
    /// The store refused.
    fn clear(&self) -> std::io::Result<bool>;
    /// How the key is protected, for `phantab bitwarden status`.
    fn protection(&self) -> &'static str;
}

/// The platform's vault for the bitwarden folder `dir` (`<runtime>/bitwarden`).
pub(crate) struct OsVault {
    dir: PathBuf,
}

impl OsVault {
    pub(crate) fn new(dir: &Path) -> Self {
        OsVault { dir: dir.to_path_buf() }
    }
}

#[cfg(windows)]
impl SessionVault for OsVault {
    fn load(&self) -> std::io::Result<Option<SessionKey>> {
        let blob = match std::fs::read(self.dir.join(SESSION_FILE)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let plain = phantab_window::secret_store::unprotect(&blob, DPAPI_ENTROPY)?;
        SessionKey::from_record(&plain)
            .map(Some)
            .ok_or_else(|| std::io::Error::other("the stored session is damaged"))
    }

    fn store(&self, key: &SessionKey) -> std::io::Result<()> {
        phantab_window::secure_dir::lock_down(&self.dir).map_err(std::io::Error::other)?;
        let blob = phantab_window::secret_store::protect(&key.record()?, DPAPI_ENTROPY)?;
        write_new_then_rename(&self.dir.join(SESSION_FILE), &blob)
    }

    fn clear(&self) -> std::io::Result<bool> {
        match std::fs::remove_file(self.dir.join(SESSION_FILE)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn protection(&self) -> &'static str {
        "dpapi"
    }
}

#[cfg(target_os = "macos")]
impl OsVault {
    fn account(&self) -> String {
        self.dir.to_string_lossy().into_owned()
    }
}

#[cfg(target_os = "macos")]
impl SessionVault for OsVault {
    fn load(&self) -> std::io::Result<Option<SessionKey>> {
        match phantab_window::secret_store::keychain_get(KEYCHAIN_SERVICE, &self.account())? {
            None => Ok(None),
            Some(plain) => SessionKey::from_record(&plain)
                .map(Some)
                .ok_or_else(|| std::io::Error::other("the stored session is damaged")),
        }
    }

    fn store(&self, key: &SessionKey) -> std::io::Result<()> {
        phantab_window::secret_store::keychain_set(KEYCHAIN_SERVICE, &self.account(), &key.record()?)
    }

    fn clear(&self) -> std::io::Result<bool> {
        phantab_window::secret_store::keychain_delete(KEYCHAIN_SERVICE, &self.account())
    }

    fn protection(&self) -> &'static str {
        "keychain"
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
impl SessionVault for OsVault {
    fn load(&self) -> std::io::Result<Option<SessionKey>> {
        let _ = &self.dir;
        Err(std::io::ErrorKind::Unsupported.into())
    }

    fn store(&self, _key: &SessionKey) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    fn clear(&self) -> std::io::Result<bool> {
        Ok(false)
    }

    fn protection(&self) -> &'static str {
        "unsupported"
    }
}

/// Writes `bytes` through a new owner-only temp file, synced, then renamed in place (as the guard file
/// is written). A stale temp file is removed first, so a planted link is never followed.
#[cfg(windows)]
fn write_new_then_rename(file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, file).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// A vault in memory, for tests: it shows what was stored without any OS store. It holds the record as
/// text (header, pin, key), as an OS store would.
#[cfg(any(test, feature = "test-seams"))]
#[derive(Default)]
pub(crate) struct MemoryVault {
    key: std::sync::Mutex<Option<Zeroizing<String>>>,
    /// `load` fails, as a damaged blob would.
    pub(crate) broken: bool,
}

#[cfg(any(test, feature = "test-seams"))]
impl MemoryVault {
    pub(crate) fn holding(key: Option<&str>) -> Self {
        MemoryVault { key: std::sync::Mutex::new(key.map(|k| Zeroizing::new(k.to_owned()))), broken: false }
    }

    pub(crate) fn stored(&self) -> Option<String> {
        self.key.lock().ok().and_then(|k| k.as_ref().map(|k| k.as_str().to_owned()))
    }
}

#[cfg(any(test, feature = "test-seams"))]
impl SessionVault for MemoryVault {
    fn load(&self) -> std::io::Result<Option<SessionKey>> {
        if self.broken {
            return Err(std::io::Error::other("broken on purpose"));
        }
        let key = self.key.lock().map_err(|_| std::io::Error::other("poisoned"))?;
        match key.as_ref() {
            None => Ok(None),
            Some(k) => SessionKey::from_record(k.as_bytes())
                .map(Some)
                .ok_or_else(|| std::io::Error::other("the stored session is damaged")),
        }
    }

    fn store(&self, key: &SessionKey) -> std::io::Result<()> {
        let record = key.record()?;
        let text = std::str::from_utf8(&record).map_err(std::io::Error::other)?;
        *self.key.lock().map_err(|_| std::io::Error::other("poisoned"))? =
            Some(Zeroizing::new(text.to_owned()));
        Ok(())
    }

    fn clear(&self) -> std::io::Result<bool> {
        Ok(self.key.lock().map_err(|_| std::io::Error::other("poisoned"))?.take().is_some())
    }

    fn protection(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_checked_and_never_printed() {
        let key = SessionKey::parse(b"  QUJD+/=\n").unwrap();
        assert_eq!(key.expose(), "QUJD+/=");
        assert_eq!(format!("{key:?}"), "SessionKey([redacted])");
        for bad in [&b""[..], b"   ", b"? Master password:", b"not base64!", b"a\0b", &[0xff, 0xfe][..]] {
            assert!(SessionKey::parse(bad).is_none(), "{bad:?}");
        }
        assert!(SessionKey::parse("A".repeat(MAX_KEY + 1).as_bytes()).is_none());
    }

    #[test]
    fn the_memory_vault_round_trips() {
        let v = MemoryVault::default();
        assert!(v.load().unwrap().is_none());
        v.store(&SessionKey::parse(b"S2V5").unwrap()).unwrap();
        assert_eq!(v.load().unwrap().unwrap().expose(), "S2V5");
        assert!(v.clear().unwrap());
        assert!(!v.clear().unwrap());
    }

    #[test]
    fn a_record_keeps_the_pin_and_a_bare_key_has_none() {
        let pin: Pin = serde_json::from_value(
            serde_json::json!({"command": ["/opt/bw"], "files": [{"path": "/opt/bw", "sha256": "ab"}]}),
        )
        .unwrap();
        let key = SessionKey::parse(b"S2V5").unwrap().pinned(pin.clone());
        let record = key.record().unwrap();
        assert_eq!(
            std::str::from_utf8(&record).unwrap(),
            "phantab-bw-session-2\n{\"command\":[\"/opt/bw\"],\"files\":[{\"path\":\"/opt/bw\",\"sha256\":\"ab\"}]}\nS2V5"
        );
        let back = SessionKey::from_record(&record).unwrap();
        assert_eq!((back.expose(), back.pin()), ("S2V5", Some(&pin)));
        assert_eq!(format!("{back:?}"), "SessionKey([redacted])");
        // An earlier phantab's store: the bare key, with no pin.
        let legacy = SessionKey::from_record(b"S2V5").unwrap();
        assert_eq!((legacy.expose(), legacy.pin()), ("S2V5", None));
        for bad in [
            &b"phantab-bw-session-2\n"[..],
            b"phantab-bw-session-2\nnot json\nS2V5",
            b"phantab-bw-session-2\n{\"command\":[]}\nS2V5",
            b"phantab-bw-session-2\nnull\nnot base64!",
            b"phantab-bw-session-2\nnull",
        ] {
            assert!(SessionKey::from_record(bad).is_none(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn tests_never_use_the_owners_keychain_item() {
        assert_eq!(KEYCHAIN_SERVICE, "dev.phantab.test.bitwarden");
    }

    #[cfg(windows)]
    #[test]
    fn the_dpapi_vault_keeps_only_a_blob() {
        let dir = tempfile::tempdir().unwrap();
        let bw = dir.path().join("bitwarden");
        let v = OsVault::new(&bw);
        assert!(v.load().unwrap().is_none());
        v.store(&SessionKey::parse(b"bm90LWEtcmVhbC1zZXNzaW9u").unwrap()).unwrap();
        let sealed = std::fs::read(bw.join(SESSION_FILE)).unwrap();
        let plain = phantab_window::secret_store::unprotect(&sealed, DPAPI_ENTROPY).unwrap();
        assert!(plain.starts_with(b"phantab-bw-session-2\n"), "a record, header first");
        let blob = std::fs::read(bw.join(SESSION_FILE)).unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("bm90LWEtcmVhbC1zZXNzaW9u"));
        assert_eq!(v.load().unwrap().unwrap().expose(), "bm90LWEtcmVhbC1zZXNzaW9u");
        // A damaged blob is an error, never "no session".
        std::fs::write(bw.join(SESSION_FILE), b"damaged").unwrap();
        assert!(v.load().is_err());
        assert!(v.clear().unwrap());
        assert!(v.load().unwrap().is_none());
    }
}
