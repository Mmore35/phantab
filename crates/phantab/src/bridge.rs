//! The service end of the phantab bridge extension (`extension/src/background.ts`).
//! Frames are Chrome native messaging's: 4-byte little-endian length, then JSON. The native host
//! (`host.rs`) pipes them unchanged between Chrome and this service.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine as _;
use bytes::{Buf, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::AbortHandle;

use crate::paths::BRIDGE_PROTOCOL;
use crate::util::{js_seconds, js_string, lock, truthy};

/// Chrome refuses larger host-to-extension messages.
pub const TO_CHROME_LIMIT: usize = 1024 * 1024;
/// Chrome's own cap on an extension-to-host message. A length past this can
/// only be a broken peer, and buffering it would be unbounded.
pub const FROM_CHROME_LIMIT: usize = 64 * 1024 * 1024;
/// The reply deadline of every op without its own.
pub const DEFAULT_OP_TIMEOUT: Duration = Duration::from_secs(15);
/// `send` (a CDP command) has longer: puppeteer's protocol timeout sits under it.
pub const SEND_OP_TIMEOUT: Duration = Duration::from_secs(30);
/// A link that has not said hello by then is dropped.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a current link has to answer before a different instance replaces it.
const PING_TIMEOUT: Duration = Duration::from_secs(2);
/// Broadcast depth. CDP events of every attached tab share it; a receiver that falls this far behind
/// gets `RecvError::Lagged` and has lost events, which a CDP transport must treat as its link failing.
const EVENT_CAPACITY: usize = 16_384;

pub type TabId = i64;

/// The Chrome profile a link serves, by the label its hello carries: [`USUAL`] for the usual profile
/// (`config.json`'s `profileDirectory`, whose copy of the extension has no label), else the profile
/// folder named in an extra copy's `profile.json` (`otherProfiles`, THREAT-MODEL SR-76). Shared, so an
/// event carries it without a copy.
pub type Profile = Arc<str>;

/// The usual profile's label: none.
pub const USUAL: &str = "";

/// The reply deadline for `op` when the caller names none: the longer `send` deadline for a CDP
/// command, the usual one for everything else.
#[must_use]
pub fn op_timeout(op: &str) -> Duration {
    if op == "send" { SEND_OP_TIMEOUT } else { DEFAULT_OP_TIMEOUT }
}

/// What the bridge reports. Every subscriber sees every event, in arrival order.
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    /// An extension said hello and was welcomed; it is now its profile's link.
    Connect { profile: Profile, version: Option<String>, instance: String },
    /// A connection was refused (protocol mismatch, a second live profile). The text is for the owner.
    /// `profile` is the allowed profile the refused copy claimed, when it named one (a second live copy).
    Refused { profile: Option<Profile>, reason: String },
    /// A profile's link ended. Every op pending on it has already failed with [`BridgeError::Disconnected`].
    Disconnect { profile: Profile, reason: String },
    /// Chrome detached the debugger from a tab (`reason` is chrome.debugger's, possibly absent), or the
    /// tab was removed (`reason` is `"removed"`). `tab_open` and `foreign` come from bridge 1.1.0; an
    /// older extension sends neither.
    TabEnded {
        profile: Profile,
        tab_id: TabId,
        reason: Option<String>,
        tab_open: Option<bool>,
        foreign: Option<ForeignPage>,
    },
    /// A CDP event from an attached tab, only one phantab reads ([`phantab_cdp::EVENTS`]). Shared, so a
    /// broadcast to many subscribers copies nothing.
    Cdp(Arc<CdpEvent>),
}

/// A CDP event as chrome.debugger delivered it. `session_id` is set for child targets (OOPIFs);
/// `params` is the event's JSON exactly as the extension sent it, parsed by whoever needs it.
#[derive(Debug)]
pub struct CdpEvent {
    pub profile: Profile,
    pub tab_id: TabId,
    pub session_id: Option<String>,
    pub method: String,
    pub params: Option<Box<RawValue>>,
}

/// Another extension's page that appeared in a tab just before Chrome detached it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ForeignPage {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    #[error("The phantab bridge is not connected.")]
    NotConnected,
    #[error("The phantab bridge disconnected.")]
    Disconnected,
    #[error("Browser request exceeds Chrome's 1 MB native-messaging limit.")]
    TooLarge,
    #[error("The phantab bridge did not answer {op} in {} s.", js_seconds(*.timeout))]
    Timeout { op: String, timeout: Duration },
    /// The extension's own error text for the op (e.g. `Unknown bridge operation: x`).
    #[error("{0}")]
    Remote(String),
    #[error("Browser request could not be encoded: {0}")]
    Encode(String),
    /// A `send` whose CDP method is not on the allow-list (THREAT-MODEL SR-20); it never reached Chrome.
    #[error("phantab does not relay the CDP method {0}.")]
    MethodNotAllowed(String),
}

/// A native-messaging frame: 4-byte little-endian length, then the JSON.
///
/// # Errors
/// The value does not serialize.
pub fn frame<T: Serialize + ?Sized>(value: &T) -> Result<Bytes, serde_json::Error> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&[0; 4]);
    serde_json::to_writer(&mut out, value)?;
    let n = u32::try_from(out.len() - 4).unwrap_or(u32::MAX);
    out[..4].copy_from_slice(&n.to_le_bytes());
    Ok(Bytes::from(out))
}

/// Splits a byte stream into frame bodies, across any chunking.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// The next complete frame body, if one has arrived.
    ///
    /// # Errors
    /// The peer announced a frame past [`FROM_CHROME_LIMIT`].
    pub fn next_frame(&mut self) -> Result<Option<Bytes>, FrameTooLarge> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if n > FROM_CHROME_LIMIT {
            return Err(FrameTooLarge(n));
        }
        if self.buf.len() < 4 + n {
            return Ok(None);
        }
        self.buf.advance(4);
        Ok(Some(self.buf.split_to(n).freeze()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("a {0}-byte frame is past Chrome's native-messaging limit")]
pub struct FrameTooLarge(pub usize);

/// Follows frame boundaries in a byte stream that is passed on unchanged, without buffering it, and
/// refuses the first header past `limit` (THREAT-MODEL SR-17). The native host pipes both ways through
/// one of these: Chrome to service under [`FROM_CHROME_LIMIT`], service to Chrome under
/// [`TO_CHROME_LIMIT`].
#[derive(Debug)]
pub struct FrameGuard {
    limit: usize,
    header: [u8; 4],
    have: usize,
    body_left: usize,
}

impl FrameGuard {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self { limit, header: [0; 4], have: 0, body_left: 0 }
    }

    /// Checks the next chunk of the stream. Holds at most a 4-byte header, whatever the chunk.
    ///
    /// # Errors
    /// A header in this chunk announced a frame past the limit; the link must close.
    pub fn check(&mut self, mut chunk: &[u8]) -> Result<(), FrameTooLarge> {
        while !chunk.is_empty() {
            if self.body_left > 0 {
                let n = self.body_left.min(chunk.len());
                self.body_left -= n;
                chunk = &chunk[n..];
                continue;
            }
            let n = (4 - self.have).min(chunk.len());
            self.header[self.have..self.have + n].copy_from_slice(&chunk[..n]);
            self.have += n;
            chunk = &chunk[n..];
            if self.have == 4 {
                self.have = 0;
                let len = u32::from_le_bytes(self.header) as usize;
                if len > self.limit {
                    return Err(FrameTooLarge(len));
                }
                self.body_left = len;
            }
        }
        Ok(())
    }
}

// ---- Profile check -------------------------------------------------------------------------------

/// The bridge extension's ID, from its manifest key.
pub static EXTENSION_ID: LazyLock<String> = LazyLock::new(|| {
    let manifest: Value =
        serde_json::from_str(include_str!("../../../extension/manifest.json")).unwrap_or(Value::Null);
    manifest.get("key").and_then(Value::as_str).and_then(extension_id).unwrap_or_default()
});

/// Chrome derives an extension ID from its manifest key: sha256, first 32 hex digits as a-p.
#[must_use]
pub fn extension_id(key: &str) -> Option<String> {
    let der = base64::engine::general_purpose::STANDARD.decode(key).ok()?;
    let digest = Sha256::digest(der);
    Some(digest.iter().take(16).flat_map(|b| [b >> 4, b & 0x0f]).map(|h| char::from(b'a' + h)).collect())
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// A file's `extensions.settings[id]`, by the SHA-256 of the bytes it came from.
type SettingCache = HashMap<(std::path::PathBuf, String), ([u8; 32], Option<Value>)>;
static SETTING_CACHE: LazyLock<Mutex<SettingCache>> = LazyLock::new(Mutex::default);
/// Profiles a check may meet; past this the cache starts over rather than grow.
const SETTING_CACHE_LIMIT: usize = 64;

/// `extensions.settings[id]` of one (Secure) Preferences file: `None` when it is missing, does not
/// parse or has none. The file is read on every call. Only its parse is reused, and only for bytes
/// whose SHA-256 equals the cached one, so a changed file is always parsed again (THREAT-MODEL
/// SR-19). Modification time, size and file identity are not used: a writer can set them back.
fn file_setting(path: &Path, id: &str) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let key = (path.to_path_buf(), id.to_owned());
    if let Some((d, v)) = lock(&SETTING_CACHE).get(&key)
        && *d == digest
    {
        return v.clone();
    }
    let v = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|mut prefs| prefs.get_mut("extensions")?.get_mut("settings")?.get_mut(id).map(Value::take));
    let mut cache = lock(&SETTING_CACHE);
    if cache.len() >= SETTING_CACHE_LIMIT {
        cache.clear();
    }
    cache.insert(key, (digest, v.clone()));
    v
}

/// Installed extensions are listed in the profile's (Secure) Preferences. Chrome writes them on a
/// timer, so a just-installed bridge may not be listed for ~10 s.
fn settings(user_data_dir: &Path, dir: &str, id: &str) -> Vec<Value> {
    ["Secure Preferences", "Preferences"]
        .iter()
        .filter_map(|f| file_setting(&user_data_dir.join(dir).join(f), id))
        .filter(truthy)
        .collect()
}

/// Whether profile `dir` lists extension `id` at all (its Secure Preferences or Preferences): the owner
/// loaded it there. The same read [`profiles_check`] makes, so a profile this says has no bridge is one
/// whose copy the check would not find either. It says nothing about where the copy was loaded from;
/// that is [`profiles_check`]'s job once its link is up.
#[must_use]
pub fn lists_extension(user_data_dir: &Path, dir: &str, id: &str) -> bool {
    !settings(user_data_dir, dir, id).is_empty()
}

/// An extension's display name: its manifest name, or the `__MSG_x__` message it names in
/// `_locales/<default_locale>`. `path` is relative to `<profile>/Extensions` for store installs and
/// absolute for unpacked ones. The ID when nothing resolves.
#[must_use]
pub fn extension_name(user_data_dir: &Path, profile_directory: &str, id: &str) -> String {
    for s in settings(user_data_dir, profile_directory, id) {
        if let Some(name) = name_from_setting(user_data_dir, profile_directory, &s) {
            return name;
        }
    }
    id.to_owned()
}

/// Chrome's name for each profile folder that has one (`Local State` `profile.info_cache.<folder>.name`,
/// what its profile menu shows), as `(folder, name)`. Empty when `Local State` cannot be read.
#[must_use]
pub fn profile_names(user_data_dir: &Path) -> Vec<(String, String)> {
    let Some(state) = read_json(&user_data_dir.join("Local State")) else { return Vec::new() };
    let Some(cache) = state.pointer("/profile/info_cache").and_then(Value::as_object) else {
        return Vec::new();
    };
    cache
        .iter()
        .filter_map(|(folder, info)| {
            let name = info.get("name").and_then(Value::as_str).filter(|n| !n.is_empty())?;
            Some((folder.clone(), name.to_owned()))
        })
        .collect()
}

/// The folder among `allowed` (the usual profile first) that `arg` names: a folder, or Chrome's name for
/// one from [`profile_names`], either in any case. A folder wins over a name, so `Profile 1` is always
/// that folder. The error lists the profiles `arg` could have named.
///
/// # Errors
/// `arg` names none of `allowed`, or Chrome gives two of them that name.
pub fn resolve_profile(names: &[(String, String)], allowed: &[&str], arg: &str) -> Result<String, String> {
    let name_of = |folder: &str| names.iter().find(|(f, _)| f == folder).map(|(_, n)| n.as_str());
    let want = arg.trim().to_lowercase();
    if let Some(folder) = allowed.iter().find(|f| f.to_lowercase() == want) {
        return Ok((*folder).to_owned());
    }
    let by_name: Vec<&str> =
        allowed.iter().copied().filter(|f| name_of(f).is_some_and(|n| n.to_lowercase() == want)).collect();
    if let [folder] = by_name.as_slice() {
        return Ok((*folder).to_owned());
    }
    let list = allowed
        .iter()
        .map(|f| match name_of(f) {
            Some(n) => format!("{n} ({f})"),
            None => (*f).to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let arg = cut_label(arg);
    if by_name.is_empty() {
        Err(format!("Unknown Chrome profile {arg}. Allowed: {list}."))
    } else {
        Err(format!("More than one allowed Chrome profile is named {arg}; name its folder. Allowed: {list}."))
    }
}

fn name_from_setting(user_data_dir: &Path, profile_directory: &str, s: &Value) -> Option<String> {
    let folder = s.get("path").and_then(Value::as_str).filter(|p| !p.is_empty()).map(|p| {
        let p = Path::new(p);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            user_data_dir.join(profile_directory).join("Extensions").join(p)
        }
    });
    let manifest = match s.get("manifest").filter(|m| truthy(m)) {
        Some(m) => m.clone(),
        None => read_json(&folder.as_ref()?.join("manifest.json"))?,
    };
    let name = manifest.get("name").and_then(Value::as_str).unwrap_or("");
    let key = name.strip_prefix("__MSG_").and_then(|r| r.strip_suffix("__")).filter(|k| !k.is_empty());
    let Some(key) = key else {
        return (!name.is_empty()).then(|| name.to_owned());
    };
    let locale =
        manifest.get("default_locale").and_then(Value::as_str).filter(|l| !l.is_empty()).unwrap_or("en");
    let messages = read_json(&folder?.join("_locales").join(locale).join("messages.json"))?;
    let key = key.to_lowercase();
    let (_, found) = messages.as_object()?.iter().find(|(k, _)| k.to_lowercase() == key)?;
    found.get("message").and_then(Value::as_str).filter(|m| !m.is_empty()).map(str::to_owned)
}

/// The profile check's answer. `final_` means waiting will not fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileCheck {
    Ok,
    Failed { final_: bool, error: String },
}

/// Agents must reach only the usual profile: the bridge listed there and in no other profile folder,
/// unpacked from the installed extension folder ([`crate::paths::extension_dir`]).
///
/// # Errors
/// The user data folder cannot be listed.
pub fn profile_check(
    user_data_dir: &Path,
    profile_directory: &str,
    id: &str,
    record_required: bool,
) -> std::io::Result<ProfileCheck> {
    profile_check_at(user_data_dir, profile_directory, id, &crate::paths::extension_dir(), record_required)
}

/// [`profile_check`] against `extension_dir`, with no other profile allowed.
///
/// # Errors
/// The user data folder cannot be listed.
pub fn profile_check_at(
    user_data_dir: &Path,
    profile_directory: &str,
    id: &str,
    extension_dir: &Path,
    record_required: bool,
) -> std::io::Result<ProfileCheck> {
    let allowed = [Allowed { folder: profile_directory, extension_dir }];
    profiles_check(user_data_dir, &allowed, profile_directory, id, record_required)
}

/// A Chrome profile agents may reach, and the one folder its copy of the bridge must be loaded from: the
/// usual profile's is [`crate::paths::extension_dir`], each of `otherProfiles` has its own
/// ([`crate::paths::profile_extension_dir`]).
#[derive(Debug, Clone, Copy)]
pub struct Allowed<'a> {
    pub folder: &'a str,
    pub extension_dir: &'a Path,
}

/// The check before a link of profile `which` (one of `allowed`, the usual profile first) is used. Every
/// allowed profile that lists the bridge must have loaded it from exactly its own folder, and no other
/// profile folder may list it, so a profile's link is that profile's and no other (SR-19, SR-76): a same-ID
/// extension (anyone can reuse the public manifest `key`) loaded from any other folder, the usual copy in
/// an extra profile (which would claim to be the usual profile), or one extra profile's copy in another,
/// is refused with a final error. `which` must list the bridge. SR-74: every loaded copy's folder, not only
/// `which`'s (the profile is the worker's own claim), is refused too once a file install recorded there
/// changed (a swapped `background.js`) or one it did not record appears (a planted page), and, with
/// `record_required` (`config.json` has [`crate::extension_files::MARKER`]), once the record is gone.
///
/// # Errors
/// The user data folder cannot be listed.
pub fn profiles_check(
    user_data_dir: &Path,
    allowed: &[Allowed<'_>],
    which: &str,
    id: &str,
    record_required: bool,
) -> std::io::Result<ProfileCheck> {
    let usual = allowed.first().is_some_and(|a| a.folder == which);
    let named = |folder: &str| {
        if allowed.first().is_some_and(|a| a.folder == folder) {
            "The usual Chrome profile".to_owned()
        } else {
            format!("Chrome profile folder {folder}")
        }
    };
    let Some(mine) = allowed.iter().find(|a| a.folder == which) else {
        return Ok(ProfileCheck::Failed {
            final_: true,
            error: format!("Chrome profile folder {which} is not one phantab install allowed."),
        });
    };
    let mut others = Vec::new();
    for entry in std::fs::read_dir(user_data_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type()?.is_dir()
            && !allowed.iter().any(|a| a.folder == name)
            && !settings(user_data_dir, &name, id).is_empty()
        {
            others.push(name);
        }
    }
    if !others.is_empty() {
        let only =
            if allowed.len() > 1 { "the profiles phantab install allowed" } else { "the usual profile" };
        return Ok(ProfileCheck::Failed {
            final_: true,
            error: format!(
                "The phantab bridge is also installed in Chrome profile folder {}. Remove it there (chrome://extensions) so agents reach only {only}.",
                crate::extension_files::listed(&others)
            ),
        });
    }
    // Every allowed profile's entries, `which` last so a wrong copy elsewhere is named first.
    let mut loaded = Vec::new();
    for a in allowed.iter().filter(|a| a.folder != which).chain([mine]) {
        let entries = settings(user_data_dir, a.folder, id);
        let here = a.folder == which;
        if entries.is_empty() {
            if !here {
                continue;
            }
            let error = if usual {
                "The phantab bridge connected, but the usual Chrome profile does not list it. Install it in the usual profile only, or wait a few seconds after installing.".to_owned()
            } else {
                format!(
                    "The phantab bridge connected for Chrome profile folder {which}, but that profile does not list it. Load {} there at chrome://extensions, or wait a few seconds after installing.",
                    a.extension_dir.display()
                )
            };
            return Ok(ProfileCheck::Failed { final_: false, error });
        }
        match installed_from(&entries, a.extension_dir) {
            Installed::NoPath if here => {
                return Ok(ProfileCheck::Failed {
                    final_: false,
                    error: format!(
                        "{} lists the phantab bridge without its folder yet. Wait a few seconds after installing.",
                        named(a.folder)
                    ),
                });
            }
            Installed::Here | Installed::NoPath => loaded.push(a),
            Installed::Elsewhere => {
                return Ok(ProfileCheck::Failed {
                    final_: true,
                    error: format!(
                        "{} has an extension with the phantab bridge's ID that was not loaded from {}. Remove it (chrome://extensions) and run phantab install.",
                        named(a.folder),
                        a.extension_dir.display()
                    ),
                });
            }
        }
    }
    // Every loaded copy, not only `which`'s: the label is the worker's own claim, so a changed usual copy
    // claiming an extra profile is caught by its own files (review round 2).
    for a in loaded {
        match files_check(a.extension_dir, record_required) {
            ProfileCheck::Failed { final_, error } if a.folder != which => {
                let error = format!(
                    "{} loaded a copy of the phantab bridge that fails its check, so the bridge is refused in every profile. {error}",
                    named(a.folder)
                );
                return Ok(ProfileCheck::Failed { final_, error });
            }
            ProfileCheck::Ok => {}
            failed @ ProfileCheck::Failed { .. } => return Ok(failed),
        }
    }
    Ok(ProfileCheck::Ok)
}

/// SR-74: the installed folder against the record install wrote beside it. Without a record and without
/// `record_required` (an install from before SR-74, a test runtime) there is nothing to compare, as
/// before; with it, the record was deleted, which must not turn the check off. A mismatch is final:
/// waiting will not put the files back.
fn files_check(extension_dir: &Path, record_required: bool) -> ProfileCheck {
    use crate::extension_files::{Verdict, check, record_path};
    let what = match check(extension_dir) {
        Verdict::Unrecorded if record_required => {
            format!("record of its files ({}) is missing", record_path(extension_dir).display())
        }
        Verdict::Unrecorded | Verdict::Intact => return ProfileCheck::Ok,
        Verdict::Changed(files) => {
            format!(
                "files changed since phantab install wrote them ({})",
                crate::extension_files::listed(&files)
            )
        }
        // A hard link, a placeholder or a mount lets another program change what Chrome loads unseen.
        Verdict::Refused(found) => {
            format!(
                "files are not the plain files phantab install wrote ({})",
                crate::extension_files::explained(&found)
            )
        }
        Verdict::Damaged => {
            format!("record of its files ({}) cannot be read", record_path(extension_dir).display())
        }
        // Review r8 R8-1: the check could not vouch for the folder; the text says why and what to do.
        Verdict::Unverifiable(why) => {
            return ProfileCheck::Failed {
                final_: true,
                error: format!(
                    "The installed phantab extension's files cannot be checked, so the bridge is refused: \
                     {why}."
                ),
            };
        }
    };
    ProfileCheck::Failed {
        final_: true,
        error: format!(
            "The installed phantab extension's {what}, so the bridge is refused. Run phantab install again from \
             the release's extension, then click the extension's reload button at chrome://extensions."
        ),
    }
}

enum Installed {
    Here,
    NoPath,
    Elsewhere,
}

/// Where the profile's entries for the bridge were loaded from. Every entry that names a folder must
/// name `extension_dir` as an absolute path (an unpacked install; store installs are relative), both
/// canonicalised; one other folder, or one that no longer resolves, is an impostor.
fn installed_from(entries: &[Value], extension_dir: &Path) -> Installed {
    let paths: Vec<&str> =
        entries.iter().filter_map(|s| s.get("path")?.as_str()).filter(|p| !p.is_empty()).collect();
    if paths.is_empty() {
        return Installed::NoPath;
    }
    let Ok(want) = std::fs::canonicalize(extension_dir) else { return Installed::Elsewhere };
    let here = |p: &&str| {
        let p = Path::new(p);
        p.is_absolute() && std::fs::canonicalize(p).is_ok_and(|p| p == want)
    };
    if paths.iter().all(here) { Installed::Here } else { Installed::Elsewhere }
}

// ---- The bridge ----------------------------------------------------------------------------------

enum Out {
    Frame(Bytes),
    /// Write what is queued, then half-close (`socket.end`).
    End,
}

/// One accepted socket, current link or not.
struct Conn {
    id: u64,
    out: mpsc::UnboundedSender<Out>,
    tasks: Mutex<Vec<AbortHandle>>,
}

impl Conn {
    fn send(&self, data: Bytes) {
        let _ = self.out.send(Out::Frame(data));
    }

    /// `socket.destroy()`: nothing more is written or read, and the stream closes.
    fn destroy(&self) {
        for t in lock(&self.tasks).drain(..) {
            t.abort();
        }
    }
}

struct Link {
    conn: Arc<Conn>,
    instance: String,
}

type Reply = Result<Option<Box<RawValue>>, BridgeError>;

#[derive(Default)]
struct State {
    /// At most one link per profile.
    links: HashMap<Profile, Link>,
    /// Each op waits on the link of the profile it was sent to; only that link's reply or end settles it.
    pending: HashMap<u64, (Profile, oneshot::Sender<Reply>)>,
    last_error: Option<String>,
}

/// The service end of the bridge: at most one extension link per Chrome profile (the usual one, and each
/// of `otherProfiles`), ops with ids and deadlines, and a broadcast of what the extensions report.
pub struct Bridge {
    state: Mutex<State>,
    events: broadcast::Sender<BridgeEvent>,
    /// The profiles with a link.
    connected: watch::Sender<BTreeSet<Profile>>,
    seq: AtomicU64,
    conns: AtomicU64,
    /// The labels a hello may carry besides none (`otherProfiles`). Any other is refused.
    allowed: Vec<String>,
    /// `devTools` (SR-90): whether the developer-tools commands are relayed, their events kept, and the
    /// welcome declares them to the extension.
    dev_tools: bool,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge").field("connected", &self.connected()).finish_non_exhaustive()
    }
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
struct Incoming<'a> {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
    #[serde(default)]
    result: Option<Box<RawValue>>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default, rename = "tabId")]
    tab_id: Option<Value>,
    #[serde(default, rename = "sessionId")]
    session_id: Option<String>,
    #[serde(default)]
    method: Option<String>,
    /// Borrowed from the frame: an event `receive` drops is never copied (perf-data-3).
    #[serde(default, borrow)]
    params: Option<&'a RawValue>,
    #[serde(default)]
    reason: Option<Value>,
    #[serde(default, rename = "tabOpen")]
    tab_open: Option<Value>,
    #[serde(default)]
    foreign: Option<Value>,
}

impl Bridge {
    /// A bridge for the usual profile only.
    #[must_use]
    pub fn new() -> Self {
        Self::with_profiles(Vec::new())
    }

    /// A bridge that also takes the extra copies labelled with these profile folders (`otherProfiles`).
    #[must_use]
    pub fn with_profiles(allowed: Vec<String>) -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            state: Mutex::new(State::default()),
            events,
            connected: watch::Sender::new(BTreeSet::new()),
            seq: AtomicU64::new(0),
            conns: AtomicU64::new(0),
            allowed,
            dev_tools: false,
        }
    }

    /// The same bridge with the developer tools (SR-90) on or off; off unless `devTools` is set.
    #[must_use]
    pub fn with_dev_tools(mut self, on: bool) -> Self {
        self.dev_tools = on;
        self
    }

    /// Every event from now on. Subscribe before anything can connect to miss none.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<BridgeEvent> {
        self.events.subscribe()
    }

    /// Whether the usual profile has a link.
    #[must_use]
    pub fn connected(&self) -> bool {
        self.connected_in(USUAL)
    }

    /// Whether `profile` has a link.
    #[must_use]
    pub fn connected_in(&self, profile: &str) -> bool {
        lock(&self.state).links.contains_key(profile)
    }

    /// The last refusal's text, for status. `None` until a connection was refused.
    #[must_use]
    pub fn last_error(&self) -> Option<String> {
        lock(&self.state).last_error.clone()
    }

    fn emit(&self, e: BridgeEvent) {
        let _ = self.events.send(e);
    }

    /// True once the usual profile's link is up, waiting up to `within` for one.
    pub async fn wait_connected(&self, within: Duration) -> bool {
        self.wait_connected_in(USUAL, within).await
    }

    /// True once `profile`'s link is up, waiting up to `within` for one.
    pub async fn wait_connected_in(&self, profile: &str, within: Duration) -> bool {
        let mut rx = self.connected.subscribe();
        if self.connected_in(profile) {
            return true;
        }
        tokio::time::timeout(within, rx.wait_for(|c| c.contains(profile))).await.is_ok_and(|r| r.is_ok())
    }

    /// The id of `profile`'s link now, `None` when it has none. Each connection gets a new id, so a link
    /// that replaced another has a different one.
    #[must_use]
    pub fn link_id_in(&self, profile: &str) -> Option<u64> {
        lock(&self.state).links.get(profile).map(|link| link.conn.id)
    }

    /// True once `profile` has a link other than `before` (an id [`Self::link_id_in`] gave earlier),
    /// waiting up to `within`. The link that was up before a restart is not a reconnect, however long it
    /// takes to drop.
    pub async fn wait_new_link_in(&self, profile: &str, before: Option<u64>, within: Duration) -> bool {
        let mut rx = self.connected.subscribe();
        let fresh = || self.link_id_in(profile).is_some_and(|id| Some(id) != before);
        if fresh() {
            return true;
        }
        // Every link added or dropped notifies `connected`, a replacement twice.
        tokio::time::timeout(within, async {
            while rx.changed().await.is_ok() {
                if fresh() {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false)
    }

    /// Takes a new connection from the native host (the upgraded `/bridge` socket). It becomes the link
    /// once its hello is accepted.
    pub fn accept<S>(self: &Arc<Self>, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::unbounded_channel::<Out>();
        let conn = Arc::new(Conn {
            id: self.conns.fetch_add(1, Ordering::Relaxed) + 1,
            out: tx,
            tasks: Mutex::new(Vec::new()),
        });
        let writer = tokio::spawn(async move {
            while let Some(out) = rx.recv().await {
                match out {
                    Out::Frame(data) => {
                        if wr.write_all(&data).await.is_err() || wr.flush().await.is_err() {
                            break;
                        }
                    }
                    Out::End => {
                        let _ = wr.shutdown().await;
                        break;
                    }
                }
            }
        });
        let bridge = Arc::clone(self);
        let reader_conn = Arc::clone(&conn);
        let reader = tokio::spawn(async move {
            bridge.read_loop(&reader_conn, &mut rd).await;
        });
        let mut tasks = lock(&conn.tasks);
        tasks.push(writer.abort_handle());
        tasks.push(reader.abort_handle());
    }

    async fn read_loop<R: AsyncRead + Unpin>(self: &Arc<Self>, conn: &Arc<Conn>, rd: &mut R) {
        let mut decoder = FrameDecoder::default();
        let mut buf = vec![0u8; 64 * 1024];
        let mut hello = false;
        let deadline = tokio::time::Instant::now() + HELLO_TIMEOUT;
        loop {
            let frame = match decoder.next_frame() {
                Ok(Some(f)) => Some(f),
                Ok(None) => None,
                Err(_) => break,
            };
            if let Some(body) = frame {
                if hello {
                    if let Some(profile) = self.link_of(conn) {
                        // A frame that is not JSON can only come from a broken peer, so the link is
                        // dropped.
                        let Ok(m) = serde_json::from_slice::<Incoming>(&body) else { break };
                        self.receive(&profile, m);
                    }
                } else {
                    hello = true;
                    let Ok(m) = serde_json::from_slice::<Value>(&body) else { break };
                    if self.greet(conn, m.get("hello")).await.is_err() {
                        break;
                    }
                }
                continue;
            }
            let read = if hello {
                rd.read(&mut buf).await
            } else {
                match tokio::time::timeout_at(deadline, rd.read(&mut buf)).await {
                    Ok(r) => r,
                    Err(_) => break,
                }
            };
            match read {
                Ok(0) | Err(_) => break,
                Ok(n) => decoder.push(&buf[..n]),
            }
        }
        // HTTP servers keep upgraded sockets half-open: the host ending its side (Chrome exited) must
        // close the link.
        if let Some(profile) = self.link_of(conn) {
            self.drop_link(&profile, "the extension or its native host closed the connection");
        }
        conn.destroy();
    }

    /// The profile `conn` is the link of, if it is one.
    fn link_of(&self, conn: &Conn) -> Option<Profile> {
        lock(&self.state).links.iter().find(|(_, l)| l.conn.id == conn.id).map(|(p, _)| Arc::clone(p))
    }

    fn refuse(&self, conn: &Conn, profile: Option<Profile>, message: String) {
        if let Ok(data) = frame(&json!({ "refused": message })) {
            conn.send(data);
        }
        let _ = conn.out.send(Out::End);
        lock(&self.state).last_error = Some(message.clone());
        self.emit(BridgeEvent::Refused { profile, reason: message });
    }

    /// `Err` destroys the connection.
    async fn greet(&self, conn: &Arc<Conn>, hello: Option<&Value>) -> Result<(), ()> {
        let Some(hello) = hello.filter(|h| truthy(h)) else { return Err(()) };
        let Some(instance) = hello.get("instance").and_then(Value::as_str) else { return Err(()) };
        let protocol = hello.get("protocol");
        if protocol.and_then(Value::as_u64) != Some(BRIDGE_PROTOCOL) {
            self.refuse(
                conn,
                None,
                format!(
                    "The phantab bridge extension speaks protocol {}; this service needs {BRIDGE_PROTOCOL}. Reload it at chrome://extensions after updating.",
                    js_string(protocol)
                ),
            );
            return Ok(());
        }
        // The label names the profile this copy was installed for (SR-76): none is the usual profile, and
        // only the configured `otherProfiles` are taken. The engine's profile check then confirms that
        // profile lists exactly this copy's folder before any agent uses the link.
        let profile: Profile = match hello.get("profile") {
            None | Some(Value::Null) => USUAL.into(),
            Some(Value::String(p)) if p.is_empty() => USUAL.into(),
            Some(Value::String(p)) if self.allowed.iter().any(|a| a == p) => p.as_str().into(),
            Some(other) => {
                self.refuse(
                    conn,
                    None,
                    format!(
                        "A phantab bridge copy for Chrome profile folder {} connected, but config.json's otherProfiles does not name it. Run phantab install to allow it (it allows every profile but those left out, and --add-profile brings back one left out), then restart only the phantab service; or remove that copy at chrome://extensions.",
                        cut_label(&js_string(Some(other)))
                    ),
                );
                return Ok(());
            }
        };
        // A worker that restarted reuses nothing: same instance means a reconnect.
        // A different live instance of the same copy answering ping is a second profile loading it.
        let other = lock(&self.state).links.get(&profile).is_some_and(|l| l.instance != instance);
        if other && self.op_with_timeout_in(&profile, "ping", json!({}), PING_TIMEOUT).await.is_ok() {
            let reason = if profile.is_empty() {
                "The phantab bridge is installed in more than one Chrome profile; remove it from all but the usual profile.".to_owned()
            } else {
                format!(
                    "The phantab bridge copy for Chrome profile folder {profile} is loaded in more than one Chrome profile; remove it from all but {profile}."
                )
            };
            self.refuse(conn, Some(Arc::clone(&profile)), reason);
            return Ok(());
        }
        if self.connected_in(&profile) {
            self.drop_link(&profile, "replaced by a newer bridge connection");
        }
        lock(&self.state)
            .links
            .insert(Arc::clone(&profile), Link { conn: Arc::clone(conn), instance: instance.to_owned() });
        // `events`: the CDP events to forward (perf-data-3). An extension that predates the list ignores it
        // and forwards every event, which `receive` then drops; one that reads it forwards only these.
        // `devTools` (SR-90): declared only while the setting is on; without it the extension refuses the
        // developer-tools commands and forwards none of their events.
        let mut welcome = json!({ "welcome": true, "events": phantab_cdp::EVENTS });
        if self.dev_tools {
            welcome["devTools"] = Value::Bool(true);
        }
        if let Ok(data) = frame(&welcome) {
            conn.send(data);
        }
        self.connected.send_modify(|c| {
            c.insert(Arc::clone(&profile));
        });
        self.emit(BridgeEvent::Connect {
            profile,
            version: hello.get("version").and_then(Value::as_str).map(str::to_owned),
            instance: instance.to_owned(),
        });
        Ok(())
    }

    /// A frame from `profile`'s link.
    fn receive(&self, profile: &Profile, m: Incoming<'_>) {
        if let Some(id) = m.id {
            let Some(id) = id.as_u64() else { return };
            // Only the link an op was sent to answers it.
            let tx = {
                let mut st = lock(&self.state);
                if st.pending.get(&id).is_none_or(|(p, _)| p != profile) {
                    return;
                }
                st.pending.remove(&id).map(|(_, tx)| tx)
            };
            let Some(tx) = tx else { return };
            let reply = match m.error {
                Some(e) => Err(BridgeError::Remote(js_string(Some(&e)))),
                None => Ok(m.result),
            };
            let _ = tx.send(reply);
            return;
        }
        let tab_id = m.tab_id.as_ref().and_then(Value::as_i64);
        match (m.event.as_deref(), tab_id) {
            // An event nobody reads (from an extension with no list) ends here: the frame was parsed,
            // but its params are not copied, broadcast or parsed by a page.
            (Some("cdp"), Some(tab_id)) => {
                let method = m.method.unwrap_or_default();
                // SR-90: a developer-tools event only while the setting is on; never an `...ExtraInfo` one,
                // which neither list holds.
                if phantab_cdp::reads_event(&method)
                    || (self.dev_tools && phantab_cdp::reads_devtools_event(&method))
                {
                    self.emit(BridgeEvent::Cdp(Arc::new(CdpEvent {
                        profile: Arc::clone(profile),
                        tab_id,
                        session_id: m.session_id,
                        method,
                        params: m.params.map(ToOwned::to_owned),
                    })));
                }
            }
            (Some(event @ ("detach" | "removed")), Some(tab_id)) => {
                let reason = if event == "detach" {
                    m.reason.as_ref().and_then(Value::as_str).map(str::to_owned)
                } else {
                    Some("removed".to_owned())
                };
                let foreign = m.foreign.filter(truthy).and_then(|f| serde_json::from_value(f).ok());
                self.emit(BridgeEvent::TabEnded {
                    profile: Arc::clone(profile),
                    tab_id,
                    reason,
                    tab_open: m.tab_open.as_ref().and_then(Value::as_bool),
                    foreign,
                });
            }
            _ => {}
        }
    }

    /// Ends `profile`'s link, failing only the ops sent to it.
    fn drop_link(&self, profile: &str, reason: &str) {
        let (profile, link, pending) = {
            let mut st = lock(&self.state);
            let Some((profile, link)) = st.links.remove_entry(profile) else { return };
            let ids: Vec<u64> =
                st.pending.iter().filter(|(_, (p, _))| *p == profile).map(|(id, _)| *id).collect();
            let pending: Vec<_> = ids.iter().filter_map(|id| st.pending.remove(id)).collect();
            (profile, link, pending)
        };
        self.connected.send_modify(|c| {
            c.remove(&profile);
        });
        link.conn.destroy();
        for (_, tx) in pending {
            let _ = tx.send(Err(BridgeError::Disconnected));
        }
        self.emit(BridgeEvent::Disconnect { profile, reason: reason.to_owned() });
    }

    /// Runs a bridge op in the usual profile with the default deadline for its name ([`op_timeout`]).
    pub async fn op(&self, name: &str, args: Value) -> Result<Value, BridgeError> {
        self.op_in(USUAL, name, args).await
    }

    /// Runs a bridge op in `profile` with the default deadline for its name ([`op_timeout`]).
    pub async fn op_in(&self, profile: &str, name: &str, args: Value) -> Result<Value, BridgeError> {
        self.op_with_timeout_in(profile, name, args, op_timeout(name)).await
    }

    pub async fn op_with_timeout(
        &self,
        name: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Value, BridgeError> {
        self.op_with_timeout_in(USUAL, name, args, timeout).await
    }

    pub async fn op_with_timeout_in(
        &self,
        profile: &str,
        name: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Value, BridgeError> {
        let raw = self.op_raw_in(profile, name, &args, timeout).await?;
        Ok(raw.and_then(|r| serde_json::from_str(r.get()).ok()).unwrap_or(Value::Null))
    }

    /// [`Self::op_raw_in`] in the usual profile.
    pub async fn op_raw<A: Serialize + ?Sized>(
        &self,
        name: &str,
        args: &A,
        timeout: Duration,
    ) -> Result<Option<Box<RawValue>>, BridgeError> {
        self.op_raw_in(USUAL, name, args, timeout).await
    }

    /// The op, sent to `profile`'s link, with borrowed arguments and the reply's JSON left unparsed
    /// (`None` when the extension sent no result). The CDP relay's path: `send` args serialize straight
    /// into the frame.
    pub async fn op_raw_in<A: Serialize + ?Sized>(
        &self,
        profile: &str,
        name: &str,
        args: &A,
        timeout: Duration,
    ) -> Result<Option<Box<RawValue>>, BridgeError> {
        #[derive(Serialize)]
        struct Request<'a, A: ?Sized> {
            id: u64,
            op: &'a str,
            args: &'a A,
        }
        if !self.connected_in(profile) {
            return Err(BridgeError::NotConnected);
        }
        let id = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let data = frame(&Request { id, op: name, args }).map_err(|e| BridgeError::Encode(e.to_string()))?;
        if data.len() > TO_CHROME_LIMIT {
            return Err(BridgeError::TooLarge);
        }
        if name == "send" {
            check_send(&data[4..], self.dev_tools)?;
        }
        let (tx, rx) = oneshot::channel();
        {
            let mut st = lock(&self.state);
            let Some((key, link)) = st.links.get_key_value(profile) else {
                return Err(BridgeError::NotConnected);
            };
            let (key, conn) = (Arc::clone(key), Arc::clone(&link.conn));
            st.pending.insert(id, (key, tx));
            conn.send(data);
        }
        let _forget = Forget { bridge: self, id };
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => Err(BridgeError::Disconnected),
            Err(_) => Err(BridgeError::Timeout { op: name.to_owned(), timeout }),
        }
    }

    /// Drops every link (`browser service stopped`).
    pub fn close(&self) {
        let profiles: Vec<Profile> = lock(&self.state).links.keys().cloned().collect();
        for p in profiles {
            self.drop_link(&p, "browser service stopped");
        }
    }
}

/// A label from a hello, as an error names it: at most 100 characters.
fn cut_label(label: &str) -> String {
    label.chars().take(100).collect()
}

/// SR-20: a `send` relays only a listed CDP method, and a developer-tools one only while `devTools` is on
/// (SR-90). Read back from the encoded frame, so the check sees exactly what the extension would
/// receive, whatever type the caller serialized.
fn check_send(body: &[u8], dev_tools: bool) -> Result<(), BridgeError> {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        args: Option<ProbeArgs>,
    }
    #[derive(Deserialize)]
    struct ProbeArgs {
        #[serde(default)]
        method: Option<Value>,
        #[serde(default)]
        params: Option<ProbeParams>,
    }
    // `Page.createIsolatedWorld` is listed for phantab's own world, which never asks for universal
    // access (Chrome's spelling): a world with it reads any origin's pages with the owner's cookies.
    #[derive(Deserialize)]
    struct ProbeParams {
        #[serde(default, rename = "grantUniveralAccess")]
        universal: Option<Value>,
    }
    let args = serde_json::from_slice::<Probe>(body).ok().and_then(|p| p.args);
    let (method, universal) = args.map_or((None, None), |a| (a.method, a.params.and_then(|p| p.universal)));
    match method.as_ref().and_then(Value::as_str) {
        Some(m) if universal.as_ref().is_some_and(|u| *u != Value::Bool(false)) => {
            Err(BridgeError::MethodNotAllowed(format!("{m} with grantUniveralAccess")))
        }
        Some(m) if crate::cdp_methods::allowed(m) => Ok(()),
        Some(m) if crate::cdp_methods::devtools(m) && dev_tools => Ok(()),
        Some(m) if crate::cdp_methods::devtools(m) => Err(BridgeError::MethodNotAllowed(format!(
            "{m}: it is a developer tool, off unless \"devTools\": true is set in config.json"
        ))),
        Some(m) => Err(BridgeError::MethodNotAllowed(m.to_owned())),
        None => Err(BridgeError::MethodNotAllowed(js_string(method.as_ref()))),
    }
}

/// Removes an op's pending entry however its wait ends, including the caller dropping it.
struct Forget<'a> {
    bridge: &'a Bridge,
    id: u64,
}

impl Drop for Forget<'_> {
    fn drop(&mut self) {
        lock(&self.bridge.state).pending.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_id_matches_the_shipped_manifest() {
        let shipped = include_str!("../../../extension/extension-id.txt").trim();
        assert_eq!(EXTENSION_ID.as_str(), shipped);
    }

    /// SR-76: Chrome's names come from Local State; a folder wins over a name and matches in any case, a
    /// name must be unique among the allowed ones, and an error lists what could have been named.
    #[test]
    fn profiles_resolve_by_folder_then_by_a_unique_name() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(profile_names(dir.path()), Vec::<(String, String)>::new(), "no Local State");
        let state = json!({ "profile": { "info_cache": {
            "Default": { "name": "Person 1" },
            "Profile 1": { "name": "Work" },
            "Profile 2": { "name": "Profile 1" },
            "Profile 3": { "name": "Twin" },
            "Profile 4": { "name": "Twin" },
            "Profile 5": { "name": "" },
        } } });
        std::fs::write(dir.path().join("Local State"), state.to_string()).unwrap();
        let mut names = profile_names(dir.path());
        names.sort();
        assert_eq!(names.len(), 5, "an empty name is none: {names:?}");
        let allowed = ["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"];
        let resolve = |arg: &str| resolve_profile(&names, &allowed, arg);
        assert_eq!(resolve("work").unwrap(), "Profile 1");
        assert_eq!(resolve(" profile 1 ").unwrap(), "Profile 1", "the folder, not Profile 2's name");
        assert_eq!(resolve("Person 1").unwrap(), "Default");
        assert_eq!(resolve("PROFILE 5").unwrap(), "Profile 5");
        let twin = resolve("Twin").unwrap_err();
        assert!(
            twin.starts_with("More than one allowed Chrome profile is named Twin; name its folder."),
            "{twin}"
        );
        let unknown = resolve_profile(&names, &["Profile 1", "Profile 5"], "Other").unwrap_err();
        assert_eq!(unknown, "Unknown Chrome profile Other. Allowed: Work (Profile 1), Profile 5.");
        assert!(resolve_profile(&names, &["Profile 1"], "Twin").unwrap_err().starts_with("Unknown"));
    }

    #[test]
    fn decoder_rejects_oversized_lengths() {
        let mut d = FrameDecoder::default();
        d.push(&u32::MAX.to_le_bytes());
        assert!(d.next_frame().is_err());
    }

    /// SR-17, L1: a header claiming 64 MiB + 1 is refused from its four bytes alone, before any body
    /// is buffered; exactly 64 MiB is a frame.
    #[test]
    fn a_header_past_64_mib_is_refused_before_its_body() {
        let over = u32::try_from(FROM_CHROME_LIMIT + 1).unwrap().to_le_bytes();
        let mut d = FrameDecoder::default();
        d.push(&over);
        assert!(matches!(d.next_frame(), Err(FrameTooLarge(n)) if n == FROM_CHROME_LIMIT + 1));
        assert_eq!(d.buf.len(), 4, "nothing past the header was taken in");
        let exact = u32::try_from(FROM_CHROME_LIMIT).unwrap().to_le_bytes();
        let mut d = FrameDecoder::default();
        d.push(&exact);
        assert!(matches!(d.next_frame(), Ok(None)));
        assert!(FrameGuard::new(FROM_CHROME_LIMIT).check(&over).is_err());
        assert!(FrameGuard::new(FROM_CHROME_LIMIT).check(&exact).is_ok());
    }

    #[test]
    fn the_guard_follows_frames_across_any_chunking() {
        let mut stream = Vec::new();
        for body in [&b"{}"[..], &[b' '; 300], b"[1]"] {
            stream.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            stream.extend_from_slice(body);
        }
        for size in [1, 2, 3, 5, 7, 64, stream.len()] {
            let mut g = FrameGuard::new(300);
            for chunk in stream.chunks(size) {
                g.check(chunk).unwrap();
            }
            assert_eq!((g.have, g.body_left), (0, 0), "chunk {size}");
        }
        // The fourth frame announces 301 bytes: refused even when its header arrives split.
        stream.extend_from_slice(&301u32.to_le_bytes());
        let mut g = FrameGuard::new(300);
        let refused = stream.chunks(3).map(|c| g.check(c)).find(Result::is_err);
        assert!(matches!(refused, Some(Err(FrameTooLarge(301)))));
        // Service to Chrome: under 1 MiB.
        let big = u32::try_from(TO_CHROME_LIMIT + 1).unwrap().to_le_bytes();
        assert!(FrameGuard::new(TO_CHROME_LIMIT).check(&big).is_err());
    }
}
