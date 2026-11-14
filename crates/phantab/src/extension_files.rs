//! The installed extension's files, as install wrote them (THREAT-MODEL SR-74). Chrome never checks an
//! unpacked extension's contents, so install records each file's SHA-256 in `extension-files.json`
//! beside the folder, and then sets [`MARKER`] in `config.json`. The service's profile check, run at
//! bridge connect and again before every agent call that needs the browser, and `doctor` compare the
//! folder with the record: every recorded file must be there unchanged, and nothing else may be: no
//! file the record does not name, no recorded file with a second name (a hard link), no file or folder
//! whose bytes or entries a provider serves (a reparse point that is not a link on Windows, a dataless
//! one on macOS), no other file system mounted there (macOS and Linux), and on Windows no named NTFS
//! stream on any file or folder there; and the runtime folder they are all held to must be on a file
//! system the check can vouch for (a local disk's, never a FUSE one).
//!
//! This detects a swap; it does not prevent one. A same-user program that can rewrite the folder can
//! rewrite this record, or `config.json`, too (R1). The record is its own file, not part of
//! `registration-v2.json`, so the service never reads the install record and the client config contents
//! it holds.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};

use phantab_window::streams::FileSystem;
use serde_json::{Value, json};
use sha2::Digest as _;

/// The record's file name, beside the extension folder (`<runtime>/extension-files.json`).
pub const RECORD: &str = "extension-files.json";

/// The `config.json` key install sets to `true` once it has written a record and checked the folder
/// against it. With it set, a missing record is refused like a changed file: deleting the record must not
/// turn the check off. An install from before SR-74 has neither, and is accepted as before.
pub const MARKER: &str = "extensionFilesRecorded";

/// The largest extension file install records or the check reads (the shipped files are about 40 KB).
pub const MAX_FILE: u64 = 8 << 20;

/// The largest record the check reads.
pub const MAX_RECORD: u64 = 1 << 20;

/// The most bytes install holds for one extension: it keeps what it hashed, to write exactly that.
pub const MAX_TOTAL: u64 = 64 << 20;

/// The deepest folder and the most entries a walk visits, so a planted tree cannot stall the service.
const MAX_DEPTH: usize = 32;
const MAX_ENTRIES: usize = 4096;

/// The record for `extension_dir`: a sibling of the folder.
#[must_use]
pub fn record_path(extension_dir: &Path) -> PathBuf {
    extension_dir.parent().unwrap_or(extension_dir).join(RECORD)
}

/// What [`check`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No record beside the folder: an install from before SR-74, a test runtime, or a deleted record
    /// (which the caller refuses when `config.json` has [`MARKER`]). Nothing to compare with.
    Unrecorded,
    /// Every recorded file is there, a regular file with its recorded SHA-256, and nothing else is (no
    /// unrecorded file, and on Windows no named stream on any file or folder there).
    Intact,
    /// These paths in the folder (`/`-separated) differ from the record. First, sorted, each recorded
    /// file that changed, is missing, or is no longer a regular file of at most [`MAX_FILE`] bytes; then,
    /// sorted, everything the record does not name (a file, a link, a FIFO, a name a record cannot hold,
    /// a folder that cannot be read or is too deep or too full, a named stream as `<path>:<stream>`, and
    /// `.` for the folder itself when it is a link), so planted names cannot push the recorded ones out of
    /// a shortened list. The names are the folder's own, so show them with [`listed`].
    Changed(Vec<String>),
    /// These paths in the folder are refused for what they are, not for their bytes, each with why: first,
    /// sorted, the recorded paths, then, sorted, the rest, so planted names cannot push a recorded file's
    /// out of a shortened list. Each is a recorded file with more than one name ([`LINKED`]: a hard link,
    /// which can be outside the folder), a file or folder (`.` for the folder itself) whose bytes or
    /// entries a provider serves, or one on another file system ([`MOUNTED`]). A provider's is, on Windows,
    /// a reparse point that is not a link: a cloud-file placeholder ([`CLOUD`], or [`CLOUD_CORRUPT`] when
    /// its cloud data is unreadable) or any other tag ([`REPARSE`]: `ProjFS`, WCI, dedup, ...); on macOS
    /// one with `SF_DATALESS` set ([`CLOUD`], a File Provider's). Such a provider, or a file system mounted
    /// over the folder or a folder in it (a macFUSE one, which sees which process asks), can serve the
    /// check one set of bytes and Chrome another, so neither is read or walked, only named. The record
    /// beside the folder is named `../extension-files.json` when it is one of these. Install writes none
    /// of these, so a folder with one is refused as this, whatever else in it differs. Show the names
    /// with [`explained`].
    Refused(Vec<(String, &'static str)>),
    /// The check cannot vouch for the folder, whatever is in it, so it is refused, and the text says why
    /// and what to do, for the owner: the runtime folder is on a file system the check does not trust
    /// (one that sees which process reads, an `FSKit` one or a network one, review r8 R8-1) or whose file
    /// system could not be read (review r9 R9-3), or the check could not pin its thread's placeholder
    /// handling ([`UNPINNED`]). Nothing in the folder was read.
    Unverifiable(String),
    /// The record exists but cannot be read, is larger than [`MAX_RECORD`], is not one this version
    /// writes, or names no `manifest.json`.
    Damaged,
}

/// Why [`Verdict::Refused`] names a recorded file with a second name.
pub const LINKED: &str = "has other hard links";
/// Why [`Verdict::Refused`] names a cloud-file placeholder (a Cloud Files reparse tag on Windows,
/// `SF_DATALESS` on macOS).
pub const CLOUD: &str = "is a cloud placeholder";
/// Why [`Verdict::Refused`] names a Cloud Files placeholder whose cloud data is corrupt, so the cloud
/// filter fails every open of it, even as itself (`ERROR_CLOUD_FILE_METADATA_CORRUPT`, Windows).
pub const CLOUD_CORRUPT: &str = "is a cloud placeholder whose data is corrupt, so nothing can open it";
/// Why [`Verdict::Refused`] names any other reparse point that is not a link (Windows).
pub const REPARSE: &str = "is a reparse point";
/// Why [`Verdict::Refused`] names a file or folder whose device is not the runtime folder's (`st_dev`,
/// macOS and Linux): a file system mounted over the folder or a folder in it. On Windows such a mount is
/// a mount point, a link, refused as one.
pub const MOUNTED: &str = "is another file system mounted here";
/// Why [`Verdict::Unverifiable`], when the check cannot pin its thread's placeholder handling
/// (`phantab_window::streams::placeholders_pinned`): it fails closed. Followed by the OS's error.
pub const UNPINNED: &str = "the OS would not stop cloud placeholders being hidden from the check or \
                            fetched for it, which needs Windows 10 1709 or macOS 10.15 or later";

/// An extension folder as install read it: each file's bytes and SHA-256, by `/`-separated path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Files {
    /// The record install writes: SHA-256 in lowercase hex.
    pub sha256: BTreeMap<String, String>,
    /// The bytes those hashes are of, which install writes and nothing else.
    pub contents: BTreeMap<String, Vec<u8>>,
}

/// The SHA-256 of every file under `dir` (see [`read`]).
///
/// # Errors
/// As [`read`].
pub fn hashes(dir: &Path) -> std::io::Result<BTreeMap<String, String>> {
    read(dir).map(|files| files.sha256)
}

/// Every file under `dir` but the few the OS writes on its own ([`skipped`]): Chrome serves any file in
/// an unpacked extension's folder as an extension page, so each one is recorded and the check refuses
/// any it does not name. Install calls this on the source before it writes anything, so each refusal
/// below comes before the first write, and then writes exactly these bytes.
///
/// # Errors
/// `dir` itself is a link; a folder or file cannot be read; an entry is a link (install writes files, so
/// the installed folder never holds one) or not a regular file or folder; a file is larger than
/// [`MAX_FILE`], or all of them together than [`MAX_TOTAL`]; the tree is deeper than 32 folders or holds
/// more than 4096 entries; a name is not one a record holds on every system (`plain_name`); two names
/// are one file on Windows or macOS; there is no `manifest.json`; or the record would not read back as
/// these files.
///
/// Named NTFS streams in `dir` are not looked at: a downloaded release carries `Zone.Identifier` ones,
/// and install writes only these bytes, so the installed folder has none ([`check`] refuses one there).
pub fn read(dir: &Path) -> std::io::Result<Files> {
    let (dir, link) = anchored(dir);
    let dir = &dir;
    if link {
        return Err(refused(dir, "is a link; install reads a folder itself, never one a link names"));
    }
    let survey = survey(dir, None)?;
    if let Some(odd) = survey.odd.first() {
        return Err(refused(&odd.path, odd.why));
    }
    if let Some((first, second)) = collision(&survey) {
        let why = if first == second {
            format!("holds a name whose case does not settle in {FOLDS} folds: {}", shown(first))
        } else {
            format!(
                "holds two names that are one file on Windows or macOS, which ignore case (and macOS \
                 Unicode normalization): {} and {}",
                shown(first),
                shown(second)
            )
        };
        return Err(refused(dir, &why));
    }
    let mut files = Files::default();
    let mut total = 0u64;
    for (rel, path) in survey.files {
        let (bytes, _) = read_regular(dir, &path, MAX_FILE, None)?;
        total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if total > MAX_TOTAL {
            return Err(refused(dir, "holds more than 64 MiB of files"));
        }
        files.sha256.insert(rel.clone(), sha256_hex(&bytes));
        files.contents.insert(rel, bytes);
    }
    if !files.sha256.contains_key("manifest.json") {
        return Err(refused(dir, "has no manifest.json"));
    }
    // What install writes must be what the check accepts, or an honest install would be refused for good.
    let rendered = render(&files.sha256);
    let fits = u64::try_from(rendered.len()).is_ok_and(|len| len <= MAX_RECORD);
    if !fits || parse(&String::from_utf8_lossy(&rendered)).as_ref() != Some(&files.sha256) {
        return Err(refused(dir, "cannot be recorded so that the record reads back as its files"));
    }
    Ok(files)
}

fn refused(path: &Path, why: &str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, format!("{} {why}", shown_path(path)))
}

/// What a strict read refused a file for, kept as itself in the error, so [`check`] names the file in
/// [`Verdict::Refused`] with why rather than as changed (review r8 R8-4). Shown as [`refused`] shows one.
#[derive(Debug)]
struct Refusal {
    path: String,
    why: &'static str,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.path, self.why)
    }
}

impl std::error::Error for Refusal {}

fn refusal(path: &Path, why: &'static str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, Refusal { path: shown_path(path), why })
}

/// Why a strict read refused what it opened ([`Refusal`]), if that is what `e` is.
fn refusal_of(e: &std::io::Error) -> Option<&'static str> {
    e.get_ref()?.downcast_ref::<Refusal>().map(|refusal| refusal.why)
}

/// A path for an error, [`shown`]. On Windows the walk's paths come from a handle in the `\\?\` form,
/// whose `\\` reads like an escape there (a `\` is not escaped on Windows), so `\\?\C:\` is shown as
/// `C:\` and `\\?\UNC\host\` as `\\host\`; any other `\\?\` path (`\\?\GLOBALROOT\Device\...`) is shown
/// whole, as it has no shorter form.
fn shown_path(path: &Path) -> String {
    let text = path.display().to_string();
    if cfg!(windows)
        && let Some(rest) = text.strip_prefix(r"\\?\")
    {
        if let Some(share) = rest.strip_prefix(r"UNC\") {
            return shown(&format!(r"\\{share}"));
        }
        let drive = rest.as_bytes();
        if drive.first().is_some_and(u8::is_ascii_alphabetic) && drive.get(1) == Some(&b':') {
            return shown(rest);
        }
    }
    shown(&text)
}

/// The most names [`listed`] shows before it says how many more there are.
const SHOWN: usize = 10;

/// The most characters [`shown`] gives for one name, its quotes and escapes included: one planted path
/// can be thousands of characters, and ten of them would fill every bridge error.
const SHOWN_LEN: usize = 120;

/// A name from the folder, safe to show: a planted name is text its planter chose, and it reaches the
/// agent in phantab's own error and the owner's terminal through `doctor`. So it is shown in double
/// quotes, with a `"` inside it as `\"`, so no name can fake where it ends and another begins; a newline,
/// carriage return and tab as `\n`, `\r` and `\t`; and every other character that shows nothing or
/// changes how the text around it shows ([`hidden`], picked by Unicode property, not by a list) as an
/// escape such as `\u{1b}`. So is every character a person could read as one of these quotes or as the
/// cut ([`lookalike`]), and a combining mark (Mn, Me) at the start of the name or right after an escape,
/// which would draw over the opening quote or the escape. A `\` is left as it is on Windows, where it is
/// only ever a separator, so a path reads as itself; elsewhere it can be part of a planted name, and is
/// shown as `\\`. A name longer than 120 characters so escaped keeps its start and its end, around a
/// `…`, never cutting an escape.
#[must_use]
pub fn shown(name: &str) -> String {
    use icu_properties::CodePointMapData;
    use icu_properties::props::GeneralCategory;
    // The quotes and the `…` take three of SHOWN_LEN; the start keeps about two thirds of the rest.
    const HEAD: usize = 77;
    const TAIL: usize = SHOWN_LEN - 3 - HEAD;
    let category = CodePointMapData::<GeneralCategory>::new();
    let mark =
        |c: char| matches!(category.get(c), GeneralCategory::NonspacingMark | GeneralCategory::EnclosingMark);
    // The opening quote counts as an escape: nothing may draw over it.
    let mut after_escape = true;
    let pieces: Vec<String> = name
        .chars()
        .map(|c| {
            let escaped = match c {
                '"' => Some("\\\"".to_owned()),
                '\\' if !cfg!(windows) => Some("\\\\".to_owned()),
                '\n' => Some("\\n".to_owned()),
                '\r' => Some("\\r".to_owned()),
                '\t' => Some("\\t".to_owned()),
                c if hidden(c) || lookalike(c) || (after_escape && mark(c)) => {
                    Some(c.escape_unicode().to_string())
                }
                _ => None,
            };
            after_escape = escaped.is_some();
            escaped.unwrap_or_else(|| c.to_string())
        })
        .collect();
    let width = |piece: &String| piece.chars().count();
    let body = if pieces.iter().map(width).sum::<usize>() + 2 <= SHOWN_LEN {
        pieces.concat()
    } else {
        let (mut head, mut used) = (0, 0);
        while head < pieces.len() && used + width(&pieces[head]) <= HEAD {
            used += width(&pieces[head]);
            head += 1;
        }
        let (mut tail, mut used) = (pieces.len(), 0);
        while tail > head && used + width(&pieces[tail - 1]) <= TAIL {
            used += width(&pieces[tail - 1]);
            tail -= 1;
        }
        format!("{}…{}", pieces[..head].concat(), pieces[tail..].concat())
    };
    format!("\"{body}\"")
}

/// A character that shows nothing, or changes how the text around it shows, by its Unicode properties:
/// general category Cc (controls: ESC, DEL, C1), Cf (format: the bidi marks, embeddings, overrides and
/// isolates, ALM U+061C, the zero-width characters, U+180E, and the tag characters U+E0000-E007F, which
/// an LLM reads as hidden ASCII), Zl and Zp (U+2028 and U+2029, which some renderers break a line on), Co
/// (private use) and Cn (unassigned); a space separator other than the ASCII space; and every
/// `Default_Ignorable_Code_Point` (variation selectors, the Hangul fillers, U+034F) or `Bidi_Control`.
fn hidden(c: char) -> bool {
    use icu_properties::props::{BidiControl, DefaultIgnorableCodePoint, GeneralCategory};
    use icu_properties::{CodePointMapData, CodePointSetData};
    let category = CodePointMapData::<GeneralCategory>::new().get(c);
    matches!(
        category,
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
    ) || (category == GeneralCategory::SpaceSeparator && c != ' ')
        || CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
        || CodePointSetData::new::<BidiControl>().contains(c)
}

/// A character [`shown`] escapes though it shows, because a person could read it as part of the
/// quoting: every `Quotation_Mark` but the ASCII `'` (which cannot close a `"`, and is common in names;
/// the ASCII `"` is escaped as `\"`), such as `＂` U+FF02 and `“` `”`; the primes and marks drawn as a
/// double quote (U+02BA, U+02DD, U+02EE, U+05F4, `″` U+2033, U+2036, U+3003); `…` U+2026, which looks like
/// the cut of a long name; and U+2800, a Braille cell with no dots, which shows as a space.
fn lookalike(c: char) -> bool {
    use icu_properties::CodePointSetData;
    use icu_properties::props::QuotationMark;
    (c != '\'' && CodePointSetData::new::<QuotationMark>().contains(c))
        || matches!(
            c,
            '\u{2ba}'
                | '\u{2dd}'
                | '\u{2ee}'
                | '\u{5f4}'
                | '\u{2033}'
                | '\u{2036}'
                | '\u{3003}'
                | '\u{2026}'
                | '\u{2800}'
        )
}

/// `names`, each [`shown`] (so each quoted), `, `-separated: at most ten of them, then `and N more`.
#[must_use]
pub fn listed(names: &[String]) -> String {
    let out = names.iter().take(SHOWN).map(|name| shown(name)).collect::<Vec<_>>().join(", ");
    if names.len() > SHOWN { format!("{out} and {} more", names.len() - SHOWN) } else { out }
}

/// [`Verdict::Refused`]'s names, each [`shown`] and followed by why (`"a.js" has other hard links`),
/// `, `-separated: at most ten of them, then `and N more`.
#[must_use]
pub fn explained(found: &[(String, &'static str)]) -> String {
    let out = found
        .iter()
        .take(SHOWN)
        .map(|(name, why)| format!("{} {why}", shown(name)))
        .collect::<Vec<_>>()
        .join(", ");
    if found.len() > SHOWN { format!("{out} and {} more", found.len() - SHOWN) } else { out }
}

/// `dir` as the walk and every read use it, and whether `dir` is itself a link, which [`read`] and
/// [`check`] refuse on every OS: Chrome loads the folder through the link, so a check that followed it
/// would vouch for wherever it points.
///
/// The links above `dir` are resolved once (its parent made canonical). The folders above it are the
/// owner's (the runtime is owner-only, SR-48); what each read then confirms is that no link was swapped
/// in below that, between the walk and the read. On macOS every path a walk derives holds no link, so
/// [`read_regular`] opens it with `O_NOFOLLOW_ANY`, which refuses a link anywhere in the path (`/var`,
/// above every temp folder, is one). On Windows `dir` is opened without following a link at its end and
/// its path is taken from that handle (`GetFinalPathNameByHandleW`, the `\\?\C:\...` form, so no path
/// below it is cut at `MAX_PATH`; on a volume with no drive name, the `\\?\GLOBALROOT\Device\...` form,
/// which every handle on it gives too). Before each open no folder or file below `dir` on the way may
/// be a link ([`no_link_below`]), and after it the path the handle is at must be the one the walk named
/// ([`opened_as_named`]), so a link swapped in above a file is refused there too.
fn anchored(dir: &Path) -> (PathBuf, bool) {
    #[cfg(windows)]
    if let Ok(file) = open_unfollowed(dir)
        && let Ok(path) = phantab_window::streams::final_path(&file)
    {
        return (path, file.metadata().is_ok_and(|meta| meta.file_type().is_symlink()));
    }
    // Not there (whatever reads it next says so), or not Windows.
    let path = match (dir.parent(), dir.file_name()) {
        (Some(parent), Some(name)) => {
            parent.canonicalize().map_or_else(|_| dir.to_path_buf(), |p| p.join(name))
        }
        _ => dir.to_path_buf(),
    };
    let link = std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink());
    (path, link)
}

/// The first two paths in the walk that are one file where names ignore case (NTFS, and APFS or HFS+ as
/// macOS formats them) or Unicode normalization (APFS, HFS+): install would write both to one file and
/// then refuse its own copy, after it had written the runtime. Each character is folded on its own,
/// upper case then lower, with no context (`str::to_lowercase` turns a final `Σ` into `ς`, which NTFS
/// keeps one file with `σ`), in NFC, and folded again until the path stops changing (`ẞ` lowers to `ß`,
/// which only a second fold takes through `SS` to `ss`, as APFS folds both): so `Σ`, `σ` and `ς` are
/// one, as are `ſ` and `s`, `µ` and `μ`, `ẞ`, `ß` and `ss`, and NFC and NFD forms. That is stricter than
/// NTFS for a few pairs (`ı` and `I`, `ẞ` and `ß`), which can only refuse a source, never pass a
/// collision. Two folders `A` and `a` collide too. A path that has not stopped changing after [`FOLDS`]
/// folds is given as both of the pair (`(rel, rel)`), so [`read`] refuses it rather than compare a name
/// it has not finished folding.
fn collision(survey: &Survey) -> Option<(&str, &str)> {
    let mut seen = BTreeMap::new();
    for rel in survey.files.keys().chain(survey.dirs.iter().map(|(rel, _)| rel)) {
        let Some(key) = folded(rel, FOLDS) else { return Some((rel.as_str(), rel.as_str())) };
        if let Some(first) = seen.insert(key, rel.as_str()) {
            return Some((first, rel.as_str()));
        }
    }
    None
}

/// The most folds [`collision`] takes. Two settle every character Unicode has today (the second only
/// confirms but for `ẞ`, which takes a third); the bound only keeps a loop a loop.
const FOLDS: usize = 8;

/// `rel` in NFC, each character upper- then lower-cased on its own, then in NFC again, until a fold
/// changes nothing; `None` when `passes` folds have not got there.
fn folded(rel: &str, passes: usize) -> Option<String> {
    let nfc = icu_normalizer::ComposingNormalizerBorrowed::new_nfc();
    let mut text = nfc.normalize(rel).into_owned();
    for _ in 0..passes {
        let cased: String = text.chars().flat_map(char::to_uppercase).flat_map(char::to_lowercase).collect();
        let cased = nfc.normalize(&cased).into_owned();
        if cased == text {
            return Some(text);
        }
        text = cased;
    }
    None
}

/// A regular file the OS may write into any folder on its own, by its exact name: a Finder `.DS_Store`
/// or `Icon\r`, an Explorer `desktop.ini` or `Thumbs.db` (any case, as Windows matches them). Only these,
/// and only as regular files: a folder or link of the same name is walked or refused like any other.
/// They are neither recorded nor compared, which is safe only because what Chrome runs is recorded:
/// `manifest.json` and the code it names are, so no page or script names a skipped file unless a recorded
/// file changes to. None of them has an extension Chrome serves as a page. A named NTFS stream on one
/// (`desktop.ini:x.html`) does, and is typed as a URL, so [`check`] still lists every skipped file's
/// streams like any other file's.
fn skipped(name: &str) -> bool {
    name == ".DS_Store"
        || name == "Icon\r"
        || name.eq_ignore_ascii_case("desktop.ini")
        || name.eq_ignore_ascii_case("thumbs.db")
}

/// An entry a record cannot hold.
struct Odd {
    rel: String,
    path: PathBuf,
    why: &'static str,
}

/// One walk of a folder: its regular files by `/`-separated path, the folders it walked, the [`skipped`]
/// OS files (never hashed or recorded, but their streams are checked), and everything else it found.
/// A [`Strict`] walk (the installed folder's, in [`check`]) also names, in `served`, each file or folder a
/// provider serves or on another file system ([`served_entry`]), before it is opened or walked, and goes
/// no further into it.
#[derive(Default)]
struct Survey {
    files: BTreeMap<String, PathBuf>,
    dirs: Vec<(String, PathBuf)>,
    skipped: Vec<(String, PathBuf)>,
    odd: Vec<Odd>,
    served: Vec<(String, &'static str)>,
    strict: Option<Strict>,
    entries: usize,
}

/// What a strict read (the installed folder's, in [`check`]) holds each file and folder to. On Unix it is
/// the device (`st_dev`) of the runtime folder, which the installed folder, every entry its walk lists
/// (`lstat`) and every handle it reads (`fstat`) must be on: a file system mounted over any of them has
/// its own, which the kernel gives from the mount, so a FUSE daemon cannot fake it ([`MOUNTED`], review
/// r7 R7-1). Asking for it still asks the mounted file system once for the mount point's attributes, so
/// a stalling one can hold a check, but never pass one. On Windows a mount is a link, refused as one.
/// The runtime folder itself is held to a file system the check trusts ([`trusted`]), as nothing above
/// it has a device to compare with.
#[derive(Clone, Copy)]
struct Strict {
    #[cfg(unix)]
    dev: u64,
    /// Linux: the runtime folder is on overlayfs, where a file can carry the device of the layer it is
    /// on rather than the overlay's (review r8 R8-6).
    #[cfg(target_os = "linux")]
    overlay: bool,
}

/// [`FileSystem::name`] of an overlayfs one (Linux).
#[cfg(target_os = "linux")]
const OVERLAY: &str = "overlay";

/// The runtime folder at `path` as a strict read holds everything to ([`Strict`]), and the file system
/// it is on, both from one handle opened at it without following a link. A file system that cannot be
/// read is an [`Unread`] error, every error, `NotFound` included: the folder was opened, so a
/// `NotFound` here is the file system's word, not proof that it is gone, and a removed folder still
/// answers on the open handle (review r11 R11-1).
fn runtime_anchor(path: &Path) -> std::io::Result<(Strict, FileSystem)> {
    runtime_anchor_with(path, phantab_window::streams::file_system)
}

/// [`runtime_anchor`], with the file system asked of `file_system`, so a test can make it fail.
fn runtime_anchor_with(
    path: &Path,
    file_system: impl FnOnce(&std::fs::File) -> std::io::Result<FileSystem>,
) -> std::io::Result<(Strict, FileSystem)> {
    let file = open_unfollowed(path)?;
    let fs = file_system(&file).map_err(|e| std::io::Error::other(Unread(e)))?;
    #[cfg(unix)]
    let strict = {
        use std::os::unix::fs::MetadataExt as _;
        Strict {
            dev: file.metadata()?.dev(),
            #[cfg(target_os = "linux")]
            overlay: fs.name == OVERLAY,
        }
    };
    #[cfg(not(unix))]
    let strict = Strict {};
    Ok((strict, fs))
}

/// The runtime folder's file system could not be read ([`runtime_anchor`]), kept as itself in the error
/// so [`check`] says so ([`Verdict::Unverifiable`]) rather than calling the record damaged, whose advice
/// would not help (review r9 R9-3).
#[derive(Debug)]
struct Unread(std::io::Error);

impl std::fmt::Display for Unread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for Unread {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// What [`check`] makes of a runtime folder [`runtime_anchor`] could not read: [`Verdict::Unverifiable`]
/// when its file system could not be read ([`Unread`]), [`Verdict::Unrecorded`] when it is not there,
/// else [`Verdict::Damaged`].
fn unanchored(runtime: &Path, e: &std::io::Error) -> Verdict {
    if let Some(Unread(e)) = e.get_ref().and_then(|inner| inner.downcast_ref::<Unread>()) {
        Verdict::Unverifiable(format!(
            "the file system of the runtime folder {} could not be read ({e}), so the check cannot tell \
             whether it is {TRUSTED}, which is all it vouches for. Put the runtime on this computer's own \
             disk ({} names another folder) and run phantab install again",
            shown_path(runtime),
            crate::paths::RUNTIME_ENV
        ))
    } else if e.kind() == ErrorKind::NotFound {
        Verdict::Unrecorded
    } else {
        Verdict::Damaged
    }
}

impl Strict {
    /// [`MOUNTED`] when `meta` is on another device than this one. On Linux, when the runtime folder is
    /// on overlayfs, a file whose own file system (`on`, asked only then) is overlayfs too is not
    /// refused for its device: overlayfs gives a file the device of the layer it is on when the layers
    /// are on different file systems and `xino` is off (review r8 R8-6), and every reader gets the same
    /// bytes from it. A FUSE mount there is still refused, as its file system is FUSE.
    fn mounted(
        self,
        meta: &std::fs::Metadata,
        on: impl FnOnce() -> std::io::Result<FileSystem>,
    ) -> Option<&'static str> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if meta.dev() == self.dev {
                return None;
            }
            #[cfg(target_os = "linux")]
            if self.overlay && on().is_ok_and(|fs| fs.name == OVERLAY) {
                return None;
            }
            #[cfg(not(target_os = "linux"))]
            let _ = on;
            Some(MOUNTED)
        }
        #[cfg(not(unix))]
        {
            let _ = (self, meta, on);
            None
        }
    }
}

/// Whether the check can vouch for a folder on this file system (review r8 R8-1). Every entry is held
/// to the runtime folder's device ([`Strict`]), so a file system mounted at or above the runtime folder
/// gives them all one device, and one that sees which process reads (macFUSE, FUSE, `WinFsp`, `Dokan`)
/// could serve the check the recorded bytes and Chrome others. On macOS only a local disk's, APFS or
/// HFS+ (`f_fstypename` `apfs` or `hfs`), and not an `FSKit` mount ([`FileSystem::fskit`]): the name is
/// the one the kext or `FSKit` module that mounted it gives, and while macFUSE's kext prefixes
/// `macfuse_`, an `FSKit` module may call itself `apfs`, so an `FSKit` mount is refused by the flag the
/// kernel sets on it (review r9 R9-2), and a network or other one by its name. On Linux any but FUSE
/// (overlayfs included, R8-6). On Windows NTFS or `ReFS` on a partition of a local disk (an NT device
/// `\Device\HarddiskVolume<n>`): a kernel driver names the device, so a user-mode file system cannot
/// (a `WinFsp` or `Dokan` volume is `\Device\Volume{GUID}` and may call itself NTFS), a share is under
/// `\Device\Mup`, and a RAM disk or `VeraCrypt` volume whose driver names its own device (`ImDisk`'s
/// `\Device\ImDisk0`, `\Device\VeraCryptVolume<L>`) is refused too (review r9 R9-5). On macOS an APFS
/// or HFS+ RAM disk or `VeraCrypt` volume passes: the kernel's own APFS or HFS+ serves it, the same
/// bytes to every reader.
fn trusted(fs: &FileSystem) -> bool {
    #[cfg(target_os = "macos")]
    {
        (fs.name == "apfs" || fs.name == "hfs") && !fs.fskit
    }
    #[cfg(target_os = "linux")]
    {
        fs.name != "fuse"
    }
    #[cfg(windows)]
    {
        let partition = fs
            .device
            .strip_prefix(r"\Device\HarddiskVolume")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        (fs.name == "NTFS" || fs.name == "ReFS") && partition
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = fs;
        true
    }
}

/// What the check vouches for a folder on, for [`foreign`]'s message.
#[cfg(target_os = "macos")]
const TRUSTED: &str = "a local disk's APFS or HFS+, not mounted through FSKit";
#[cfg(target_os = "linux")]
const TRUSTED: &str = "a file system that is not FUSE";
#[cfg(windows)]
const TRUSTED: &str = "NTFS or ReFS on a partition of a local disk (\\Device\\HarddiskVolume<n>)";
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
const TRUSTED: &str = "a local disk's";

/// Honest setups [`trusted`] refuses on this OS, for [`foreign`]'s text (review r11 R11-5).
#[cfg(not(target_os = "linux"))]
const HONEST: &str = "such as a FAT or exFAT disk or a network home";
#[cfg(target_os = "linux")]
const HONEST: &str = "such as a FUSE home (sshfs, gocryptfs)";

/// [`Verdict::Unverifiable`]'s text for a runtime folder on a file system the check does not trust.
fn foreign(runtime: &Path, fs: &FileSystem) -> String {
    let on = if fs.fskit {
        format!("a {} file system mounted through FSKit", shown(&fs.name))
    } else if fs.device.is_empty() {
        format!("a {} file system", shown(&fs.name))
    } else {
        format!("{} on {}", shown(&fs.name), shown(&fs.device))
    };
    format!(
        "the runtime folder {} is on {on}, and the check vouches only for a folder on {TRUSTED}: another (a \
         FUSE one such as macFUSE, WinFsp or Dokan, an FSKit one, a network share) can serve the check one \
         set of bytes and Chrome another, and the check cannot tell an honest one, {HONEST}, from \
         those. \
         Put the runtime on this computer's own disk ({} names another folder) and run phantab install \
         again",
        shown_path(runtime),
        crate::paths::RUNTIME_ENV
    )
}

const NAME_WHY: &str = "has a name a record cannot hold on every system (a \\ : < > \" | ? * or control \
                        character, a trailing dot or space, or a device name such as CON)";

/// Walks `dir` without following a link. Only `dir` itself unreadable is an error; anything below it a
/// record cannot hold is listed in `odd`, so [`read`] refuses it and [`check`] names it.
fn survey(dir: &Path, strict: Option<Strict>) -> std::io::Result<Survey> {
    let mut survey = Survey { strict, ..Survey::default() };
    scan(std::fs::read_dir(dir)?, dir, "", 0, &mut survey);
    Ok(survey)
}

fn scan(entries: std::fs::ReadDir, dir: &Path, prefix: &str, depth: usize, out: &mut Survey) {
    let here = || if prefix.is_empty() { ".".to_owned() } else { prefix.trim_end_matches('/').to_owned() };
    for entry in entries {
        out.entries += 1;
        if out.entries > MAX_ENTRIES {
            out.odd.push(Odd { rel: here(), path: dir.to_path_buf(), why: "holds more than 4096 entries" });
            return;
        }
        let Ok(entry) = entry else {
            out.odd.push(Odd { rel: here(), path: dir.to_path_buf(), why: "cannot be read" });
            return;
        };
        let path = entry.path();
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            let rel = format!("{prefix}{}", file_name.to_string_lossy());
            out.odd.push(Odd { rel, path, why: "has a name that is not UTF-8" });
            continue;
        };
        let rel = format!("{prefix}{name}");
        let Ok(kind) = entry.file_type() else {
            out.odd.push(Odd { rel, path, why: "cannot be read" });
            continue;
        };
        // SR-74 (review r6 R6-1, r7 R7-1): in the installed folder a placeholder or a mount is named before
        // anything opens, reads or walks it, so its provider is never asked for its bytes or entries; a
        // link is refused below.
        if let Some(strict) = out.strict
            && !kind.is_symlink()
        {
            match served_entry(&entry, strict) {
                Ok(None) => {}
                Ok(Some(why)) => {
                    out.served.push((rel, why));
                    continue;
                }
                Err(_) => {
                    out.odd.push(Odd { rel, path, why: "cannot be read" });
                    continue;
                }
            }
        }
        if kind.is_file() && skipped(name) {
            out.skipped.push((rel, path));
            continue;
        }
        if !plain_name(name) {
            out.odd.push(Odd { rel, path, why: NAME_WHY });
        } else if kind.is_symlink() {
            // On Windows a junction is a link here too (std reports a name-surrogate reparse point so).
            out.odd.push(Odd { rel, path, why: "is a link" });
        } else if kind.is_dir() {
            if depth >= MAX_DEPTH {
                out.odd.push(Odd { rel, path, why: "is more than 32 folders deep" });
            } else if let Ok(inner) = std::fs::read_dir(&path) {
                scan(inner, &path, &format!("{rel}/"), depth + 1, out);
                out.dirs.push((rel, path));
            } else {
                out.odd.push(Odd { rel, path, why: "cannot be read" });
            }
        } else if kind.is_file() {
            out.files.insert(rel, path);
        } else {
            out.odd.push(Odd { rel, path, why: "is not a regular file" });
        }
        if out.entries > MAX_ENTRIES {
            return;
        }
    }
}

/// A regular file's bytes, at most `cap` of them, opened without following a link or waiting on a FIFO
/// and checked as opened, so a swap between a walk and the read cannot make it read something else. On
/// Unix: `O_NOFOLLOW | O_NONBLOCK` (on macOS `O_NOFOLLOW_ANY` instead, see [`anchored`]), then `fstat`. On
/// Windows: `FILE_FLAG_OPEN_REPARSE_POINT`, so a link or junction opens as itself, then the handle's own
/// metadata (`GetFileInformationByHandle`, which only a file on disk answers), which names a link or
/// junction as a link, never a regular file. A link swapped in for a folder between `root` (the
/// [`anchored`] folder `path` is in) and the file is refused before the open by [`no_link_below`] and,
/// if swapped in after that, by the path the handle is at ([`opened_as_named`]), as on macOS.
///
/// Gives the bytes and how many names the file has (`st_nlink`, `nNumberOfLinks`), from the same handle.
/// When [`Strict`] (the installed folder, in [`check`]), a file a provider serves ([`served`]) or on
/// another file system ([`Strict::mounted`]), both from the handle, is refused before a byte is read (as
/// a [`Refusal`]), and the handle opened as itself is the one read, so no filter is asked for its bytes
/// even if a tag lands after that look. Otherwise (a source, which may be in `OneDrive`) a reparse point
/// that is not a link is opened again to read what its filter serves ([`past_placeholder`]).
fn read_regular(
    root: &Path,
    path: &Path,
    cap: u64,
    strict: Option<Strict>,
) -> std::io::Result<(Vec<u8>, u64)> {
    let could_not = |e: std::io::Error| {
        std::io::Error::new(e.kind(), format!("{} cannot be read: {e}", shown_path(path)))
    };
    #[cfg(windows)]
    no_link_below(root, path)
        .map_err(|e| if e.kind() == ErrorKind::InvalidData { e } else { could_not(e) })?;
    #[cfg(not(windows))]
    let _ = root;
    let file = open_unfollowed(path).map_err(could_not)?;
    if let Some(strict) = strict {
        let why = if let Some(why) = served(&file).map_err(could_not)? {
            Some(why)
        } else {
            let meta = file.metadata().map_err(could_not)?;
            strict.mounted(&meta, || phantab_window::streams::file_system(&file))
        };
        if let Some(why) = why {
            return Err(refusal(path, why));
        }
    }
    // Review r7 R7-2: never in a strict read, so the check never reads through a filter.
    #[cfg(windows)]
    let file = if strict.is_some() { file } else { past_placeholder(path, file).map_err(could_not)? };
    #[cfg(windows)]
    opened_as_named(path, &file)?;
    let meta = file.metadata().map_err(could_not)?;
    if !meta.is_file() {
        return Err(refused(path, "is not a regular file"));
    }
    let large = || refused(path, &format!("is larger than {} MiB", cap >> 20));
    if meta.len() > cap {
        return Err(large());
    }
    let names = phantab_window::streams::links(&file).map_err(could_not)?;
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes).map_err(could_not)?;
    if u64::try_from(bytes.len()).is_ok_and(|len| len > cap) {
        return Err(large());
    }
    Ok((bytes, names))
}

/// Windows' nearest match, before the open, for macOS's `O_NOFOLLOW_ANY`: no folder or file from below
/// `root` down to `path` is a link now (`symlink_metadata`, which opens each one as itself). A link or
/// junction counts (std's `is_symlink`, a name-surrogate reparse point); another reparse point, such as a
/// cloud-file placeholder, does not, as it names no other place and an honest source may be one (the
/// check refuses one in the installed folder for its provider instead, [`served`]). A link swapped in
/// between this and the open is still followed by the open, which then refuses it
/// ([`opened_as_named`]): in the installed folder only that window is left for a stalling share or
/// provider to hold a check, while a source's placeholder may hold an install's read (R1).
#[cfg(windows)]
fn no_link_below(root: &Path, path: &Path) -> std::io::Result<()> {
    // Every caller passes a path the walk derived from `root`; anything else is left to the open's check.
    let Ok(rel) = path.strip_prefix(root) else { return Ok(()) };
    let mut at = root.to_path_buf();
    for part in rel.components() {
        at.push(part);
        if std::fs::symlink_metadata(&at)?.file_type().is_symlink() {
            return Err(refused(&at, "is a link (a folder on the path was swapped for one after the walk)"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_unfollowed(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // macOS 11+ (libc 0.2 exports it for Apple targets): a link swapped in for a folder anywhere on the
    // path is refused too, not only one at the end. A file system mounted on a folder there is no link,
    // so this flag passes it; a strict read refuses it by its device instead ([`Strict`], review r7 R7-1),
    // though the open has then asked it once, so a stalling SMB or macFUSE mount can hold a check, never
    // pass one. Linux has no such flag: a link swapped onto the path is followed there, and only the
    // device and the hash stand behind it.
    // `O_NOFOLLOW_ANY` alone, never with `O_NOFOLLOW`: macOS 15.8.1 fails `open(2)` with EINVAL when both
    // are set, even on a path with no link, which refused every read (PR #12, a macOS run at 801676a). It
    // gives ELOOP for a link anywhere on the path, the last part included, so `O_NOFOLLOW` adds nothing.
    #[cfg(target_os = "macos")]
    let flags = libc::O_NOFOLLOW_ANY | libc::O_NONBLOCK;
    #[cfg(not(target_os = "macos"))]
    let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
    std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path)
}

/// A file or folder as itself: `FILE_FLAG_OPEN_REPARSE_POINT`, so a link or junction at the end of the
/// path opens as the link, and `FILE_FLAG_BACKUP_SEMANTICS`, which a folder needs to open at all.
#[cfg(windows)]
fn open_unfollowed(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path)
}

/// A reparse point that is not a link (a cloud-file placeholder, a deduplicated file) opens as a file,
/// but only a normal open reads the bytes its filter serves, so it is opened again. A link swapped in
/// between the two opens would be followed, so the caller confirms where this handle is too. Only a
/// source's read ([`read`]) gets here: a strict read (the check's) never does, so it never reads
/// through a filter, even when a tag lands after [`served`] looked (review r7 R7-2).
#[cfg(windows)]
fn past_placeholder(path: &Path, file: std::fs::File) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let meta = file.metadata()?;
    if meta.is_file() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return std::fs::File::open(path);
    }
    Ok(file)
}

/// Windows' match for macOS's `O_NOFOLLOW_ANY`: `path` was derived from the [`anchored`] folder, whose
/// path came from its own handle, so the handle opened at `path` must be at exactly `path`
/// (`GetFinalPathNameByHandleW` resolves every link). A folder on the way swapped for a link or
/// junction after the walk puts the handle somewhere else, and is refused.
#[cfg(windows)]
fn opened_as_named(path: &Path, file: &std::fs::File) -> std::io::Result<()> {
    match phantab_window::streams::final_path(file) {
        Ok(at) if at == path => Ok(()),
        Ok(_) => Err(refused(path, "is not where the walk found it (a link was swapped in on its path)")),
        Err(e) => Err(std::io::Error::new(e.kind(), format!("{} cannot be read: {e}", shown_path(path)))),
    }
}

#[cfg(not(any(unix, windows)))]
fn open_unfollowed(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Why the open file or folder is one a provider serves ([`Verdict::Refused`]), from its own handle: on
/// Windows its reparse tag (it was opened as itself, so no filter was asked for its bytes), on macOS
/// `SF_DATALESS` in its `st_flags`. `None` for a plain one, and for a link, which is refused as one.
/// Windows may disguise a placeholder as a plain file for some programs, so [`check`] pins its thread's
/// mode to exposed while it runs, and on macOS to never fetching a dataless file
/// (`phantab_window::streams::placeholders_pinned`, review r7 R7-3).
#[cfg(windows)]
fn served(file: &std::fs::File) -> std::io::Result<Option<&'static str>> {
    Ok(phantab_window::streams::reparse_tag(file)?.and_then(reparse_kind))
}

#[cfg(target_os = "macos")]
fn served(file: &std::fs::File) -> std::io::Result<Option<&'static str>> {
    use std::os::macos::fs::MetadataExt as _;
    Ok(dataless(file.metadata()?.st_flags()))
}

#[cfg(not(any(windows, target_os = "macos")))]
#[expect(clippy::unnecessary_wraps, reason = "the Windows and macOS versions can fail")]
fn served(_file: &std::fs::File) -> std::io::Result<Option<&'static str>> {
    Ok(None)
}

/// [`served`] and [`Strict::mounted`] for an entry a walk listed, before it is opened or walked. On
/// Windows the listing's own attributes say whether it is a reparse point at all, so only one that is
/// opened, as itself, for its tag (one whose tag cannot be read is refused all the same); on Unix
/// `lstat`'s device and, on macOS, its flags, which no File Provider is asked for.
#[cfg(windows)]
fn served_entry(entry: &std::fs::DirEntry, _strict: Strict) -> std::io::Result<Option<&'static str>> {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if entry.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return Ok(None);
    }
    Ok(served_at(&entry.path()).unwrap_or(Some(REPARSE)))
}

#[cfg(unix)]
fn served_entry(entry: &std::fs::DirEntry, strict: Strict) -> std::io::Result<Option<&'static str>> {
    let meta = entry.metadata()?;
    let why =
        strict.mounted(&meta, || phantab_window::streams::file_system(&open_unfollowed(&entry.path())?));
    #[cfg(target_os = "macos")]
    let why = why.or_else(|| {
        use std::os::macos::fs::MetadataExt as _;
        dataless(meta.st_flags())
    });
    Ok(why)
}

#[cfg(not(any(windows, unix)))]
#[expect(clippy::unnecessary_wraps, reason = "the Windows and Unix versions can fail")]
fn served_entry(_entry: &std::fs::DirEntry, _strict: Strict) -> std::io::Result<Option<&'static str>> {
    Ok(None)
}

/// [`served`] for the folder itself: on Windows from a handle opened as itself (a cloud placeholder whose
/// data is corrupt fails that open, and is named for it, [`CLOUD_CORRUPT`]), on macOS from `lstat`.
#[cfg(windows)]
fn served_at(path: &Path) -> std::io::Result<Option<&'static str>> {
    const ERROR_CLOUD_FILE_METADATA_CORRUPT: i32 = 363;
    match open_unfollowed(path) {
        Ok(file) => served(&file),
        Err(e) if e.raw_os_error() == Some(ERROR_CLOUD_FILE_METADATA_CORRUPT) => Ok(Some(CLOUD_CORRUPT)),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "macos")]
fn served_at(path: &Path) -> std::io::Result<Option<&'static str>> {
    use std::os::macos::fs::MetadataExt as _;
    Ok(dataless(std::fs::symlink_metadata(path)?.st_flags()))
}

#[cfg(not(any(windows, target_os = "macos")))]
#[expect(clippy::unnecessary_wraps, reason = "the Windows and macOS versions can fail")]
fn served_at(_path: &Path) -> std::io::Result<Option<&'static str>> {
    Ok(None)
}

/// [`Strict::mounted`] for the file or folder at `path`, from a handle opened at it as itself (Unix; on
/// Windows a mount is a link, so nothing is opened).
#[cfg_attr(not(unix), expect(clippy::unnecessary_wraps, reason = "the Unix version can fail"))]
fn mounted_at(path: &Path, strict: Strict) -> std::io::Result<Option<&'static str>> {
    #[cfg(unix)]
    {
        let file = open_unfollowed(path)?;
        Ok(strict.mounted(&file.metadata()?, || phantab_window::streams::file_system(&file)))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, strict);
        Ok(None)
    }
}

/// Why the record, which a strict read could not read with `e`, is refused for what it is, if it is: the
/// read's own refusal ([`Refusal`], which may be seen only on its handle, review r8 R8-4) first, else
/// what `at` ([`refused_at`]) finds at its path. A function so a test can reach it (review r9 R9-4).
fn record_refused(e: &std::io::Error, at: impl FnOnce() -> Option<&'static str>) -> Option<&'static str> {
    refusal_of(e).or_else(at)
}

/// What a recorded file's strict read ([`read_regular`]) makes it in [`check`] (review r9 R9-4).
#[derive(Debug, PartialEq, Eq)]
enum Judged {
    /// Refused for what it is: a second name ([`LINKED`]), or the read's own refusal ([`Refusal`]: a
    /// placeholder or mount seen only on the handle, review r8 R8-4).
    Refused(&'static str),
    /// It could not be read for another reason.
    Changed,
    /// Its bytes, to count and hash.
    Bytes(Vec<u8>),
}

fn judged(read: std::io::Result<(Vec<u8>, u64)>) -> Judged {
    match read {
        Ok((_, names)) if names > 1 => Judged::Refused(LINKED),
        Ok((bytes, _)) => Judged::Bytes(bytes),
        Err(e) => refusal_of(&e).map_or(Judged::Changed, Judged::Refused),
    }
}

/// Why the file at `path`, which a strict read could not read, is refused for what it is, if it is
/// ([`served_at`], [`mounted_at`]), so the record is named as such rather than as damaged (review r7
/// R7-8). For the message only: the read has refused it already.
fn refused_at(path: &Path, strict: Strict) -> Option<&'static str> {
    match served_at(path) {
        Ok(Some(why)) => Some(why),
        _ => mounted_at(path, strict).ok().flatten(),
    }
}

/// What a reparse tag makes a file or folder: `None` for a name surrogate (bit 29: a link, junction or
/// mount point, which std reports as a link and the walk refuses as one); [`CLOUD`] for
/// `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) and `CLOUD_1` to `CLOUD_F` (`0x9000101A` to `0x9000F01A`); and
/// [`REPARSE`] for every other tag, so a tag no one has named yet is refused too.
#[cfg(windows)]
fn reparse_kind(tag: u32) -> Option<&'static str> {
    const NAME_SURROGATE: u32 = 0x2000_0000;
    if tag & NAME_SURROGATE != 0 {
        None
    } else if tag & 0xFFFF_0FFF == 0x9000_001A {
        Some(CLOUD)
    } else {
        Some(REPARSE)
    }
}

/// `SF_DATALESS` (sys/stat.h; libc 0.2 does not export it): a file or folder whose bytes or entries a
/// File Provider fetches when it is read.
#[cfg(target_os = "macos")]
const SF_DATALESS: u32 = 0x4000_0000;

/// [`CLOUD`] when `st_flags` has [`SF_DATALESS`].
#[cfg(target_os = "macos")]
fn dataless(flags: u32) -> Option<&'static str> {
    (flags & SF_DATALESS != 0).then_some(CLOUD)
}

/// The named NTFS streams of a file or folder the walk found under `root`, read from a handle opened at
/// its path with no link on the way ([`no_link_below`]) and confirmed to be there ([`opened_as_named`]),
/// so neither a late link nor a long path makes the list another file's or fail; one that became a
/// placeholder after the walk ([`served`]) is an error too. Off Windows there are none
/// (`phantab_window::streams`), and nothing is opened.
#[cfg(windows)]
fn streams_at(root: &Path, path: &Path) -> std::io::Result<Vec<String>> {
    no_link_below(root, path)?;
    let file = open_unfollowed(path)?;
    opened_as_named(path, &file)?;
    if let Some(why) = served(&file)? {
        return Err(refused(path, why));
    }
    phantab_window::streams::named_streams(&file)
}

#[cfg(not(windows))]
#[expect(clippy::unnecessary_wraps, reason = "the Windows version can fail")]
fn streams_at(_root: &Path, _path: &Path) -> std::io::Result<Vec<String>> {
    Ok(Vec::new())
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::util::hex(&sha2::Sha256::digest(bytes))
}

/// The record's bytes for these hashes (pretty JSON, keys in order, a final newline).
#[must_use]
pub fn render(hashes: &BTreeMap<String, String>) -> Vec<u8> {
    let record = json!({ "sha256": hashes });
    (serde_json::to_string_pretty(&record).unwrap_or_default() + "\n").into_bytes()
}

/// Compares `extension_dir` with its record. Every recorded file must be a regular file (no link, no
/// FIFO a read would wait on) of at most [`MAX_FILE`] bytes with its recorded SHA-256, and nothing but
/// [`skipped`] OS files may be there besides: Chrome serves any file in the folder as an extension page
/// with the extension's permissions (a typed or command-line `chrome-extension://` URL is not limited
/// by `web_accessible_resources`), so an unrecorded `x.html` would run unseen. The folder itself must
/// not be a link (named `.`), and no recorded file may have a second name (a hard link, which could be
/// outside the folder): install writes each file new, so it has one, and a file with two is refused as
/// [`LINKED`]. A source may hold hard links ([`read`] does not look), as install copies their bytes.
///
/// No file or folder there, the folder itself included, may be one a provider serves ([`served`]): on
/// Windows a reparse point that is not a link, whatever its tag (Cloud Files, `ProjFS`, WCI, ...), and on
/// macOS a dataless one. Its provider could give the check the recorded bytes and Chrome others, or
/// stall the check; install writes none, and the runtime folders are in no synced folder. Each is named
/// from the walk's listing before anything opens, reads or walks it, so the provider is never asked, and
/// confirmed on each handle the check opens. A source may be one ([`read`] reads it as its filter serves
/// it): install writes the bytes it read, as plain files. While the check runs, its thread sees every
/// placeholder as one on Windows and has none fetched on macOS
/// (`phantab_window::streams::placeholders_pinned`); on Windows none is fetched because each file is
/// opened as itself and a placeholder refused before a byte is read. If the pin cannot be set, the
/// folder is [`Verdict::Unverifiable`] ([`UNPINNED`]).
///
/// On macOS and Linux nothing there, the folder itself included, may be on another file system than the
/// runtime folder ([`Strict`], [`MOUNTED`]): a macFUSE mount over the folder or a folder in it (which
/// any user can make once macFUSE is installed) sees which process reads, so it could serve the check
/// the recorded bytes and Chrome others. Install writes the folder in the runtime folder, so an honest
/// one is on its device. A mount at or above the runtime folder gives all of them one device, so the
/// runtime folder must be on a file system the check trusts ([`trusted`]: a local disk's, on Windows
/// too), or the folder is [`Verdict::Unverifiable`] before anything in it is read (review r8 R8-1).
///
/// On Windows no file or folder the walk found, the folder itself and the skipped OS files included,
/// may hold a named NTFS stream either: Chrome serves `background.js:x.html` or `desktop.ini:x.html` as
/// a page of its own, and no folder listing shows it. Install writes only the bytes it hashed, so an
/// honest folder has none, and Explorer writes its own files with none. The files read stop once
/// [`MAX_TOTAL`] is passed, as in [`read`]; any recorded file past it is named.
#[must_use]
pub fn check(extension_dir: &Path) -> Verdict {
    // Review r7 R7-3: held for the whole check, on this thread, and put back when it ends.
    let _pinned = match phantab_window::streams::placeholders_pinned() {
        Ok(pinned) => pinned,
        Err(e) => return Verdict::Unverifiable(format!("{UNPINNED} ({e})")),
    };
    check_with(extension_dir, MAX_TOTAL)
}

/// [`check`], with the most it reads in all as `max_total`, so a test can pass the cap cheaply.
fn check_with(extension_dir: &Path, max_total: u64) -> Verdict {
    check_from(extension_dir, max_total, runtime_anchor)
}

/// [`check_with`], with what the runtime folder is ([`runtime_anchor`]) asked of `anchor`, so a test can
/// stand in a device or a file system for it and see which folder it was asked for (review r8 R8-1,
/// R8-3).
fn check_from(
    extension_dir: &Path,
    max_total: u64,
    anchor: impl FnOnce(&Path) -> std::io::Result<(Strict, FileSystem)>,
) -> Verdict {
    let (extension_dir, link) = anchored(extension_dir);
    let extension_dir = &extension_dir;
    let beside = extension_dir.parent().unwrap_or(extension_dir.as_path());
    // The runtime folder's device, which the record, the folder and everything in it must be on, never
    // the folder's own (a mount over the folder would give it and all in it one device, R8-3); and its
    // file system, which must be one the check can vouch for, as a mount at or above it gives the
    // runtime folder and all in it one device too (R8-1).
    let strict = match anchor(beside) {
        Ok((_, fs)) if !trusted(&fs) => return Verdict::Unverifiable(foreign(beside, &fs)),
        Ok((strict, _)) => strict,
        Err(e) => return unanchored(beside, &e),
    };
    let record = record_path(extension_dir);
    let recorded = match read_regular(beside, &record, MAX_RECORD, Some(strict)) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Verdict::Unrecorded,
        Ok((bytes, _)) => String::from_utf8(bytes).ok().as_deref().and_then(parse),
        Err(e) => {
            if let Some(why) = record_refused(&e, || refused_at(&record, strict)) {
                return Verdict::Refused(vec![(format!("../{RECORD}"), why)]);
            }
            None
        }
    };
    let Some(recorded) = recorded else { return Verdict::Damaged };
    if link {
        return Verdict::Changed(vec![".".to_owned()]);
    }
    // Review r7 R7-1: a file system mounted over the folder itself is the swap a walk can never see.
    match mounted_at(extension_dir, strict) {
        Ok(None) => {}
        Ok(Some(why)) => return Verdict::Refused(vec![(".".to_owned(), why)]),
        Err(_) => return Verdict::Changed(recorded.into_keys().collect()),
    }
    if let Ok(Some(why)) = served_at(extension_dir) {
        return Verdict::Refused(vec![(".".to_owned(), why)]);
    }
    let Ok(mut found) = survey(extension_dir, Some(strict)) else {
        return Verdict::Changed(recorded.into_keys().collect());
    };
    let mut refusals = std::mem::take(&mut found.served);
    let mut changed = Vec::new();
    let mut total = 0u64;
    for (rel, sha256) in &recorded {
        let Some(path) = found.files.get(rel).filter(|_| total <= max_total) else {
            changed.push(rel.clone());
            continue;
        };
        match judged(read_regular(extension_dir, path, MAX_FILE, Some(strict))) {
            Judged::Refused(why) => refusals.push((rel.clone(), why)),
            Judged::Changed => changed.push(rel.clone()),
            Judged::Bytes(bytes) => {
                total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                if total > max_total || sha256_hex(&bytes) != *sha256 {
                    changed.push(rel.clone());
                }
            }
        }
    }
    if !refusals.is_empty() {
        return Verdict::Refused(recorded_first(refusals, &recorded, |(rel, _)| rel));
    }
    let mut extras = Vec::new();
    let walked = std::iter::once((".", extension_dir.as_path()))
        .chain(found.dirs.iter().map(|(rel, path)| (rel.as_str(), path.as_path())))
        .chain(found.files.iter().map(|(rel, path)| (rel.as_str(), path.as_path())))
        .chain(found.skipped.iter().map(|(rel, path)| (rel.as_str(), path.as_path())));
    for (rel, path) in walked {
        match streams_at(extension_dir, path) {
            Ok(streams) => extras.extend(
                streams
                    .iter()
                    .map(|stream| format!("{rel}{}", stream.strip_suffix(":$DATA").unwrap_or(stream))),
            ),
            Err(_) => extras.push(rel.to_owned()),
        }
    }
    extras.extend(found.files.into_keys().filter(|rel| !recorded.contains_key(rel)));
    extras.extend(found.odd.into_iter().map(|odd| odd.rel));
    changed.append(&mut extras);
    let changed = recorded_first(changed, &recorded, |rel| rel);
    if changed.is_empty() { Verdict::Intact } else { Verdict::Changed(changed) }
}

/// `found` with the recorded paths first, then the rest, each part sorted and with no repeats, so however
/// many names are planted, a shortened list shows the recorded ones (r4; for `Refused`, review r7 R7-6).
fn recorded_first<T: Ord>(
    found: Vec<T>,
    recorded: &BTreeMap<String, String>,
    rel: impl Fn(&T) -> &String,
) -> Vec<T> {
    let (mut ours, mut planted): (Vec<T>, Vec<T>) =
        found.into_iter().partition(|item| recorded.contains_key(rel(item)));
    ours.sort();
    ours.dedup();
    planted.sort();
    planted.dedup();
    ours.append(&mut planted);
    ours
}

/// The record's `{path: sha256}`, or `None` when it is not one [`render`] writes: every path relative,
/// `/`-separated and inside the folder, every hash 64 lowercase hex digits, `manifest.json` among them.
fn parse(text: &str) -> Option<BTreeMap<String, String>> {
    let value: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let files = value.get("sha256")?.as_object()?;
    let mut out = BTreeMap::new();
    for (rel, sha256) in files {
        let sha256 = sha256.as_str()?;
        let hex =
            sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex || !inside(rel) {
            return None;
        }
        out.insert(rel.clone(), sha256.to_owned());
    }
    out.contains_key("manifest.json").then_some(out)
}

/// A path [`read`] could have recorded: [`plain_name`]s joined by `/`, so nothing that leaves the folder.
fn inside(rel: &str) -> bool {
    !rel.is_empty() && rel.split('/').all(plain_name)
}

/// One file or folder name that means the same file on Windows and macOS: not empty, `.` or `..`; no
/// `\` or `/`; no `:` (a Windows drive or stream); none of `< > " | ? *` or a control character, which
/// Windows refuses; no trailing dot or space, which Windows drops; and no device name, which Windows
/// opens as the device. The same rule on every OS, so a folder installs on both or on neither.
///
/// Device names follow Microsoft's "Naming Files, Paths, and Namespaces" list, which is wider than what
/// `RtlIsDosDeviceName_U` matches today: `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, and `COM` or
/// `LPT` with one digit `0`-`9` or a superscript `¹ ² ³`; in any case, with any extension, and with
/// spaces before the extension (`CON .js`), which older Windows drops when it matches one.
fn plain_name(name: &str) -> bool {
    const DEVICES: [&str; 6] = ["con", "prn", "aux", "nul", "conin$", "conout$"];
    let stem = name.split('.').next().unwrap_or_default().trim_end_matches(' ').to_ascii_lowercase();
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            let mut digits = n.chars();
            digits.next().is_some_and(|d| d.is_ascii_digit() || "¹²³".contains(d)) && digits.next().is_none()
        })
    };
    let device = DEVICES.contains(&stem.as_str()) || numbered("com") || numbered("lpt");
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && !name.chars().any(|c| c.is_control() || "\\/:<>\"|?*".contains(c))
        && !device
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        // The path `anchored` gives: macOS's temp folder is under the `/var` link, which `read_regular`'s
        // `O_NOFOLLOW_ANY` refuses, and on Windows `read_regular` wants the `\\?\` path its handle is at.
        // `check` and `read` resolve it themselves; the tests that call `read_regular` need it.
        let ext = dir.path().canonicalize().unwrap().join("extension");
        std::fs::create_dir_all(ext.join("icons")).unwrap();
        std::fs::write(ext.join("manifest.json"), b"{}").unwrap();
        std::fs::write(ext.join("background.js"), b"code").unwrap();
        std::fs::write(ext.join("icons").join("a.png"), b"png").unwrap();
        (dir, ext)
    }

    fn record(ext: &Path) {
        std::fs::write(record_path(ext), render(&hashes(ext).unwrap())).unwrap();
    }

    #[test]
    fn hashes_name_every_file_by_its_slash_path() {
        let (_dir, ext) = folder();
        let files = read(&ext).unwrap();
        assert_eq!(
            files.sha256.keys().collect::<Vec<_>>(),
            ["background.js", "icons/a.png", "manifest.json"]
        );
        assert_eq!(files.sha256["background.js"], crate::util::hex(&sha2::Sha256::digest(b"code")));
        assert_eq!(files.contents["icons/a.png"], b"png");
        assert_eq!(files.contents.keys().collect::<Vec<_>>(), files.sha256.keys().collect::<Vec<_>>());
    }

    /// SR-74, L1: no record is not a refusal here (the caller decides); a recorded folder is intact
    /// until a recorded file changes, goes, or stops being a regular file.
    #[test]
    fn a_changed_or_missing_file_is_named() {
        let (_dir, ext) = folder();
        assert_eq!(check(&ext), Verdict::Unrecorded);
        record(&ext);
        assert_eq!(check(&ext), Verdict::Intact);
        std::fs::write(ext.join(".DS_Store"), b"finder").unwrap();
        assert_eq!(check(&ext), Verdict::Intact, "a file the OS writes is not compared");
        std::fs::write(ext.join("background.js"), b"code, swapped").unwrap();
        std::fs::remove_file(ext.join("icons").join("a.png")).unwrap();
        std::fs::create_dir(ext.join("icons").join("a.png")).unwrap();
        assert_eq!(check(&ext), Verdict::Changed(vec!["background.js".into(), "icons/a.png".into()]));
    }

    /// SR-74 (review r2 R2-1), L1: Chrome opens any file in the folder as an extension page, so a file the
    /// record does not name is refused wherever it is and whatever its name, a dotfile included.
    #[test]
    fn a_file_the_record_does_not_name_is_refused() {
        for extra in ["x.html", ".x.js", "icons/extra.js", ".cache/x.html", "_metadata/x.html"] {
            let (_dir, ext) = folder();
            record(&ext);
            let path = ext.join(extra);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"<script src=x.js></script>").unwrap();
            assert_eq!(check(&ext), Verdict::Changed(vec![extra.to_owned()]), "{extra}");
            assert!(hashes(&ext).unwrap().contains_key(extra), "install records it like any file: {extra}");
        }
    }

    /// SR-74 (review F2, r2 R2-1), L1: only the exact names the OS writes on its own, as files, are never
    /// recorded, so their later rewrite is never a refusal; anything else is recorded or refused.
    #[test]
    fn files_the_os_writes_are_never_recorded() {
        let (_dir, ext) = folder();
        for name in [".DS_Store", "desktop.ini", "Thumbs.db", "THUMBS.DB"] {
            std::fs::write(ext.join(name), b"os").unwrap();
            std::fs::write(ext.join("icons").join(name), b"os").unwrap();
        }
        assert_eq!(
            hashes(&ext).unwrap().keys().collect::<Vec<_>>(),
            ["background.js", "icons/a.png", "manifest.json"]
        );
        record(&ext);
        std::fs::write(ext.join(".DS_Store"), b"rewritten").unwrap();
        std::fs::write(ext.join("desktop.ini"), b"rewritten").unwrap();
        assert_eq!(check(&ext), Verdict::Intact);

        std::fs::remove_file(ext.join("desktop.ini")).unwrap();
        std::fs::create_dir(ext.join("desktop.ini")).unwrap();
        std::fs::write(ext.join("desktop.ini").join("x.html"), b"page").unwrap();
        assert_eq!(check(&ext), Verdict::Changed(vec!["desktop.ini/x.html".into()]), "a folder is walked");
        for name in [".git", ".cache", ".DS_Store.html", "._background.js", "Thumbs.db.js", ".ds_store"] {
            assert!(!skipped(name), "{name}");
        }
    }

    /// SR-74 (review F2, r2 R2-4), L1: a name a record could not hold on both systems, every name that
    /// passes reads back, and the record's own check uses the same rule.
    #[test]
    fn only_names_that_read_back_on_every_system_are_plain() {
        for good in ["a.js", "cdp-methods.js", "icon 16.png", "_locales", "conf.js", "com10", "lpt", "x.y.z"]
        {
            assert!(plain_name(good), "{good}");
            let map =
                BTreeMap::from([(good.to_owned(), "0".repeat(64)), ("manifest.json".into(), "0".repeat(64))]);
            assert_eq!(parse(&String::from_utf8(render(&map)).unwrap()), Some(map), "{good}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a\\b",
            "a:b",
            "a/b",
            "a<b",
            "a>b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            "a\rb",
            "a\u{7f}",
            "a.",
            "a ",
            "CON",
            "con.js",
            "Nul.txt",
            "aux",
            "PRN.x",
            "COM1",
            "lpt9.js",
            "com0",
            "LPT0.js",
            "COM\u{b9}",
            "lpt\u{b2}.js",
            "com\u{b3}",
            "CONIN$",
            "conout$.js",
            "CON .js",
            "nul  .txt",
        ] {
            assert!(!plain_name(bad), "{bad:?}");
        }
    }

    /// SR-74 (review F2), L1: install refuses such a name rather than write a record its check rejects,
    /// and the check names one it finds. macOS allows `:` and `\` in a file name; Windows cannot create
    /// one, so it checks a non-UTF-8 name.
    #[test]
    fn a_name_the_record_cannot_hold_is_refused_before_recording() {
        let (_dir, ext) = folder();
        record(&ext);
        #[cfg(unix)]
        let bad = [ext.join("a:b.js"), ext.join("a\\b.js"), ext.join("con.js"), ext.join("COM\u{b9}.js")];
        #[cfg(windows)]
        let bad = {
            use std::os::windows::ffi::OsStringExt as _;
            [ext.join(std::ffi::OsString::from_wide(&[0xD800, u16::from(b'x')]))]
        };
        for path in bad {
            std::fs::write(&path, b"x").unwrap();
            let error = hashes(&ext).unwrap_err().to_string();
            assert!(error.contains("name"), "{error}");
            assert!(matches!(check(&ext), Verdict::Changed(names) if names.len() == 1), "{}", path.display());
            std::fs::remove_file(&path).unwrap();
        }
        hashes(&ext).unwrap();
        assert_eq!(check(&ext), Verdict::Intact);
    }

    /// SR-74 (review F5), L1: no file is read past the cap, and a link is never followed.
    #[test]
    fn a_large_file_or_a_link_is_refused_and_a_large_record_is_damaged() {
        let (_dir, ext) = folder();
        record(&ext);
        let big = vec![b'x'; usize::try_from(MAX_FILE).unwrap() + 1];
        std::fs::write(ext.join("background.js"), &big).unwrap();
        assert!(hashes(&ext).unwrap_err().to_string().contains("larger than 8 MiB"));
        assert_eq!(check(&ext), Verdict::Changed(vec!["background.js".into()]));
        std::fs::write(ext.join("background.js"), b"code").unwrap();
        assert_eq!(check(&ext), Verdict::Intact);

        let mut text = String::from_utf8(render(&hashes(&ext).unwrap())).unwrap();
        text.push_str(&" ".repeat(usize::try_from(MAX_RECORD).unwrap()));
        std::fs::write(record_path(&ext), &text).unwrap();
        assert_eq!(check(&ext), Verdict::Damaged, "a record over 1 MiB is not read");
        record(&ext);

        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(ext.join("manifest.json"), ext.join("link.js"));
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(ext.join("manifest.json"), ext.join("link.js"));
        match linked {
            Ok(()) => {
                assert!(hashes(&ext).unwrap_err().to_string().contains("is a link"));
                assert_eq!(check(&ext), Verdict::Changed(vec!["link.js".into()]));
                assert!(read_regular(&ext, &ext.join("link.js"), MAX_FILE, None).is_err(), "never followed");
            }
            Err(e) => eprintln!("skip: cannot create a file link here ({e})"),
        }
    }

    /// SR-74, L1 (a macOS run at 801676a): macOS 15.8.1 refuses `O_NOFOLLOW` with `O_NOFOLLOW_ANY` (EINVAL),
    /// so the open uses `O_NOFOLLOW_ANY` alone: a plain file on a path with no link opens and reads, and
    /// a link at the end of the path is still refused (ELOOP), not followed.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_plain_file_on_a_path_with_no_link_opens_on_macos() {
        let (_dir, ext) = folder();
        assert!(open_unfollowed(&ext.join("manifest.json")).unwrap().metadata().unwrap().is_file());
        assert_eq!(
            read_regular(&ext, &ext.join("manifest.json"), MAX_FILE, None).unwrap(),
            (b"{}".to_vec(), 1)
        );
        std::os::unix::fs::symlink(ext.join("manifest.json"), ext.join("link.json")).unwrap();
        let error = open_unfollowed(&ext.join("link.json")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP), "{error}");
    }

    /// SR-74 (review r2 R2-6), L1: a FIFO is never waited on, in the source or at a recorded path.
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_waiting_on_it() {
        let mkfifo = |path: &Path| {
            let status = std::process::Command::new("mkfifo").arg(path).status().unwrap();
            assert!(status.success(), "mkfifo {}", path.display());
        };
        let (_dir, ext) = folder();
        mkfifo(&ext.join("pipe.js"));
        assert!(hashes(&ext).unwrap_err().to_string().contains("is not a regular file"));
        std::fs::remove_file(ext.join("pipe.js")).unwrap();
        record(&ext);
        std::fs::remove_file(ext.join("background.js")).unwrap();
        mkfifo(&ext.join("background.js"));
        assert_eq!(check(&ext), Verdict::Changed(vec!["background.js".into()]));
        let error = read_regular(&ext, &ext.join("background.js"), MAX_FILE, None).unwrap_err().to_string();
        assert!(error.contains("is not a regular file"), "opened without blocking, then refused: {error}");
        std::fs::remove_file(record_path(&ext)).unwrap();
        mkfifo(&record_path(&ext));
        assert_eq!(check(&ext), Verdict::Damaged, "a FIFO where the record should be");
    }

    /// SR-74 (review r2 R2-6), L1: a junction, the link any Windows user can make, is refused in the source
    /// and named at a recorded folder's path.
    #[cfg(windows)]
    #[test]
    fn a_junction_is_refused_in_the_source_and_at_a_recorded_path() {
        let (dir, ext) = folder();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("a.png"), b"png").unwrap();
        junction(&ext.join("more"), &elsewhere);
        assert!(hashes(&ext).unwrap_err().to_string().contains("is a link"));
        std::fs::remove_dir(ext.join("more")).unwrap();
        record(&ext);
        std::fs::remove_dir_all(ext.join("icons")).unwrap();
        junction(&ext.join("icons"), &elsewhere);
        assert_eq!(
            check(&ext),
            Verdict::Changed(vec!["icons/a.png".into(), "icons".into()]),
            "the recorded file first"
        );
        assert!(elsewhere.join("a.png").exists(), "the junction's target is left alone");
        std::fs::remove_dir(ext.join("icons")).unwrap();
    }

    /// `mklink /J link target`: the link any Windows user can make. cmd takes neither path in the `\\?\`
    /// form `canonicalize` gives, so that prefix is dropped (the test paths are short).
    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        let plain = |path: &Path| {
            let path = path.display().to_string();
            path.strip_prefix(r"\\?\").map_or_else(|| path.clone(), str::to_owned)
        };
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(plain(link))
            .arg(plain(target))
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J {}", link.display());
    }

    /// A link to a folder: a symlink on Unix, a junction on Windows.
    fn folder_link(link: &Path, target: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        junction(link, target);
    }

    /// SR-74 (review r4, parity), L1: the extension folder that is itself a link (a junction on Windows,
    /// a symlink on macOS) is refused by `read` and named `.` by `check`, on every OS; following it would
    /// vouch for wherever it points.
    #[test]
    fn a_folder_that_is_itself_a_link_is_refused() {
        let (dir, ext) = folder();
        record(&ext);
        let linked = dir.path().canonicalize().unwrap().join("linked");
        folder_link(&linked, &ext);
        assert_eq!(record_path(&linked), record_path(&ext), "one record, beside both");
        assert_eq!(check(&ext), Verdict::Intact);
        assert_eq!(check(&linked), Verdict::Changed(vec![".".into()]));
        let error = read(&linked).unwrap_err().to_string();
        assert!(error.contains("is a link"), "{error}");
        assert!(ext.join("manifest.json").exists(), "the link's target is left alone");
    }

    /// SR-74 (review r4, r5 R5-6, parity), L1: a folder on a file's path that is a link by the time the
    /// file is read (here, read through one) is refused, not followed: by `O_NOFOLLOW_ANY` on macOS, and
    /// on Windows before the open by a look at each folder on the way, for the hashing read and for the
    /// stream list alike, and after it by the path the opened handle is at.
    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn a_link_on_the_path_to_a_file_is_refused() {
        let (_dir, ext) = folder();
        folder_link(&ext.join("linked"), &ext.join("icons"));
        let through = ext.join("linked").join("a.png");
        assert_eq!(std::fs::read(&through).unwrap(), b"png", "a plain read follows it");
        let error = read_regular(&ext, &through, MAX_FILE, None).unwrap_err();
        assert!(read_regular(&ext, &ext.join("icons").join("a.png"), MAX_FILE, None).is_ok(), "{error}");
        #[cfg(windows)]
        {
            assert!(
                error.to_string().contains("is a link (a folder on the path"),
                "before the open: {error}"
            );
            assert!(streams_at(&ext, &through).is_err());
            assert_eq!(streams_at(&ext, &ext.join("icons").join("a.png")).unwrap(), Vec::<String>::new());
            // A link swapped in after that look: the open follows it, and its handle is elsewhere.
            let error = opened_as_named(&through, &std::fs::File::open(&through).unwrap()).unwrap_err();
            assert!(error.to_string().contains("a link was swapped in on its path"), "{error}");
        }
    }

    /// SR-74 (review r5 R5-5, parity; r6 R6-2), L1: a recorded file with a second name, which can be
    /// outside the folder, is refused on every OS (`st_nlink`, `nNumberOfLinks`) as having other hard
    /// links, not as changed; a source may hold one, as install writes each file new.
    #[test]
    fn a_recorded_file_with_a_second_name_is_refused() {
        let (dir, ext) = folder();
        record(&ext);
        let outside = dir.path().join("outside.js");
        std::fs::hard_link(ext.join("background.js"), &outside).unwrap();
        assert_eq!(check(&ext), Verdict::Refused(vec![("background.js".into(), LINKED)]));
        assert_eq!(
            explained(&[("background.js".into(), LINKED), ("x\n.js".into(), CLOUD)]),
            r#""background.js" has other hard links, "x\n.js" is a cloud placeholder"#
        );
        assert!(hashes(&ext).is_ok(), "the source is not refused for it");
        std::fs::remove_file(&outside).unwrap();
        assert_eq!(check(&ext), Verdict::Intact);
    }

    /// SR-74 (review r6 R6-1), L1: a file or folder in the installed folder that is a reparse point but
    /// not a link is refused by its kind, whatever its tag, before it is read or walked, and the folder
    /// itself too. The tags are set with no data, as any user can (`FSCTL_SET_REPARSE_POINT`), and taken
    /// off again before the folder goes. Only tags no filter owns are set: Microsoft's app exec link and
    /// dedup ones on files, and on folders, which NTFS tags only with a tag whose directory bit
    /// (`0x1000_0000`) is set, a made-up one that is not Microsoft's. A dataless cloud tag makes the cloud
    /// filter fail every later open of the file, removing it too ("The cloud file metadata is corrupt"),
    /// so a cloud tag's kind is checked from the tag alone, and so are the `ProjFS` and WCI ones, whose
    /// filters may be loaded.
    #[cfg(windows)]
    #[test]
    fn a_reparse_point_or_cloud_placeholder_is_refused() {
        use phantab_window::streams::test_seams::{delete_reparse_tag, set_reparse_tag};
        const APPEXECLINK: u32 = 0x8000_001B;
        const DEDUP: u32 = 0x8000_0013;
        const FOLDER: u32 = 0x1000_7A9B;
        let (_dir, ext) = folder();
        record(&ext);
        std::fs::write(ext.join("desktop.ini"), b"[.ShellClassInfo]").unwrap();
        let cases = [
            (ext.join("background.js"), APPEXECLINK, "background.js"),
            (ext.join("manifest.json"), DEDUP, "manifest.json"),
            (ext.join("icons"), FOLDER, "icons"),
            (ext.join("desktop.ini"), DEDUP, "desktop.ini"),
            (ext.clone(), FOLDER, "."),
            (record_path(&ext), DEDUP, "../extension-files.json"),
        ];
        for (on, tag, name) in cases {
            set_reparse_tag(&on, tag).unwrap();
            let verdict = check(&ext);
            delete_reparse_tag(&on, tag).unwrap();
            assert_eq!(verdict, Verdict::Refused(vec![(name.to_owned(), REPARSE)]), "{name}");
            assert_eq!(check(&ext), Verdict::Intact, "{name} untagged");
        }
        assert_eq!(reparse_kind(0x9000_001A), Some(CLOUD), "CLOUD");
        assert_eq!(reparse_kind(0x9000_F01A), Some(CLOUD), "CLOUD_F");
        assert_eq!(reparse_kind(0x8000_0013), Some(REPARSE), "dedup");
        assert_eq!(reparse_kind(0x9000_001C), Some(REPARSE), "ProjFS");
        assert_eq!(reparse_kind(0x8000_0018), Some(REPARSE), "WCI");
        assert_eq!(reparse_kind(FOLDER), Some(REPARSE), "not Microsoft's");
        assert_eq!(reparse_kind(0xA000_000C), None, "a symlink is a link");
        assert_eq!(reparse_kind(0xA000_0003), None, "a junction is a link");
    }

    /// SR-74 (review r6 R6-1, parity), L1: on macOS a dataless file or folder (a File Provider's
    /// placeholder) is a cloud placeholder; no other flag is.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_dataless_file_is_a_cloud_placeholder_on_macos() {
        assert_eq!(dataless(0x4000_0000), Some(CLOUD));
        assert_eq!(dataless(0x4000_0020), Some(CLOUD), "with UF_COMPRESSED");
        assert_eq!(dataless(0), None);
        assert_eq!(dataless(0x0000_8020), None, "UF_HIDDEN and UF_COMPRESSED");
        let (_dir, ext) = folder();
        record(&ext);
        assert_eq!(check(&ext), Verdict::Intact, "a plain folder has no SF_DATALESS");
    }

    /// SR-74 (review r7 R7-5), L1: a placeholder is refused from the handle too, not only from the walk's
    /// listing, so one made between the two is refused: a strict read of a tagged file, and the streams of
    /// a tagged folder, are refused as reparse points rather than read through the handle.
    #[cfg(windows)]
    #[test]
    fn a_placeholder_made_after_the_walk_is_refused_on_its_handle() {
        use phantab_window::streams::test_seams::{delete_reparse_tag, set_reparse_tag};
        const APPEXECLINK: u32 = 0x8000_001B;
        const FOLDER: u32 = 0x1000_7A9B;
        let (_dir, ext) = folder();
        let (ext, _) = anchored(&ext);
        let (strict, _) = runtime_anchor(ext.parent().unwrap()).unwrap();
        let file = ext.join("background.js");
        let icons = ext.join("icons");
        set_reparse_tag(&file, APPEXECLINK).unwrap();
        let read = read_regular(&ext, &file, MAX_FILE, Some(strict)).map(|_| ());
        delete_reparse_tag(&file, APPEXECLINK).unwrap();
        set_reparse_tag(&icons, FOLDER).unwrap();
        let streams = streams_at(&ext, &icons);
        delete_reparse_tag(&icons, FOLDER).unwrap();
        let read = read.unwrap_err();
        assert_eq!(refusal_of(&read), Some(REPARSE), "review r8 R8-4: refused as itself, not changed");
        let error = read.to_string();
        assert!(error.ends_with(REPARSE), "{error}");
        let error = streams.unwrap_err().to_string();
        assert!(error.ends_with(REPARSE), "{error}");
        assert!(read_regular(&ext, &file, MAX_FILE, Some(strict)).is_ok(), "untagged");
        assert_eq!(streams_at(&ext, &icons).unwrap(), Vec::<String>::new(), "untagged");
    }

    /// SR-74 (review r7 R7-1, R7-5, parity), L1: on macOS and Linux a file or folder on another device
    /// than the runtime folder is refused as [`MOUNTED`]: from the walk's listing, from the handle a read
    /// opens, and for the folder itself (the compare `check` makes of it with the runtime folder). Mounting
    /// a file system needs macFUSE or a disk image, so the runtime folder's device is stood in for by
    /// another number; on the real one nothing is refused.
    #[cfg(unix)]
    #[test]
    fn a_file_system_mounted_in_the_folder_is_refused() {
        let (_dir, ext) = folder();
        let (same, _) = runtime_anchor(ext.parent().unwrap()).unwrap();
        let mut other = same;
        other.dev = same.dev.wrapping_add(1);
        let file = ext.join("background.js");
        assert!(read_regular(&ext, &file, MAX_FILE, Some(same)).is_ok());
        let error = read_regular(&ext, &file, MAX_FILE, Some(other)).unwrap_err();
        assert_eq!(refusal_of(&error), Some(MOUNTED), "review r8 R8-4: refused as itself, not changed");
        let error = error.to_string();
        assert!(error.ends_with(MOUNTED), "{error}");
        assert_eq!(mounted_at(&ext, same).unwrap(), None);
        assert_eq!(mounted_at(&ext, other).unwrap(), Some(MOUNTED));
        assert_eq!(refused_at(&file, other), Some(MOUNTED), "the record's message");
        assert_eq!(survey(&ext, Some(same)).unwrap().served, Vec::new());
        let mut served = survey(&ext, Some(other)).unwrap().served;
        served.sort_unstable();
        let names = ["background.js", "icons", "manifest.json"];
        assert_eq!(served, names.map(|name| (name.to_owned(), MOUNTED)).to_vec());
        record(&ext);
        assert_eq!(check(&ext), Verdict::Intact, "an honest folder is on the runtime folder's device");
    }

    /// SR-74 (review r8 R8-3), L1: the device everything is held to is the runtime folder's, asked of
    /// it, never the installed folder's: a mount over the installed folder gives it and all in it one
    /// device, which would then pass. The anchor is stood in for so the runtime folder is on another
    /// device than the installed folder (as under such a mount); taking the device from the installed
    /// folder instead finds nothing to refuse and fails this.
    #[test]
    fn the_device_is_the_runtime_folders_not_the_installed_folders() {
        let (_dir, ext) = folder();
        record(&ext);
        let runtime = anchored(&ext).0.parent().unwrap().to_path_buf();
        let mut asked = Vec::new();
        let verdict = check_from(&ext, MAX_TOTAL, |path| {
            asked.push(path.to_path_buf());
            #[cfg_attr(not(unix), expect(unused_mut, reason = "only Unix has a device to stand in"))]
            let (mut strict, fs) = runtime_anchor(path)?;
            #[cfg(unix)]
            if path == runtime {
                strict.dev = strict.dev.wrapping_add(1);
            }
            Ok((strict, fs))
        });
        assert_eq!(asked, vec![runtime], "asked of the runtime folder, once");
        #[cfg(unix)]
        assert!(
            matches!(&verdict, Verdict::Refused(names) if names.iter().any(|(_, why)| *why == MOUNTED)),
            "{verdict:?}"
        );
        #[cfg(not(unix))]
        assert_eq!(verdict, Verdict::Intact);
    }

    /// SR-74 (review r8 R8-1), L1: which file systems the check vouches for. On macOS the name is the
    /// kext's or `FSKit` module's, so an `FSKit` mount is refused by its kernel flag whatever it calls
    /// itself (review r9 R9-2); on Linux the magic is the kernel driver's; on Windows the NT device, which
    /// a kernel driver names, settles it, whatever name the file system gives itself.
    #[test]
    fn only_a_local_disks_file_system_is_trusted() {
        let fs = |name: &str, device: &str| FileSystem {
            name: name.to_owned(),
            device: device.to_owned(),
            fskit: false,
        };
        #[cfg(target_os = "macos")]
        {
            assert!(trusted(&fs("apfs", "")));
            assert!(trusted(&fs("hfs", "")));
            for name in ["macfuse_loop", "macfuse", "osxfuse", "smbfs", "nfs", "afpfs", "webdav", "msdos", ""]
            {
                assert!(!trusted(&fs(name, "")), "{name}");
            }
            for name in ["apfs", "hfs", "passthrough"] {
                assert!(!trusted(&FileSystem { fskit: true, ..fs(name, "") }), "FSKit {name}");
            }
        }
        #[cfg(target_os = "linux")]
        {
            assert!(trusted(&fs("0xef53", "")), "ext4");
            assert!(trusted(&fs(OVERLAY, "")), "review r8 R8-6");
            assert!(!trusted(&fs("fuse", "")));
        }
        #[cfg(windows)]
        {
            assert!(trusted(&fs("NTFS", r"\Device\HarddiskVolume5")));
            assert!(trusted(&fs("ReFS", r"\Device\HarddiskVolume12")));
            for (name, device) in [
                ("NTFS", r"\Device\Volume{d6cc17c5-1734-4085-bce7-964f1e9f5de9}"),
                ("NTFS", r"\Device\Mup"),
                ("NTFS", r"\Device\ImDisk0"),
                ("NTFS", r"\Device\HarddiskVolume"),
                ("NTFS", r"\Device\HarddiskVolume5x"),
                ("NTFS", r"\Device\HarddiskVolumeShadowCopy3"),
                ("FAT32", r"\Device\HarddiskVolume5"),
                ("exFAT", r"\Device\HarddiskVolume5"),
                ("ntfs", r"\Device\HarddiskVolume5"),
            ] {
                assert!(!trusted(&fs(name, device)), "{name} {device}");
            }
        }
        let _ = fs;
    }

    /// SR-74 (review r8 R8-1), L1: a runtime folder on a file system the check does not vouch for is
    /// refused before anything in it is read, saying what it is on and what to do. The file system is
    /// stood in for, as making a FUSE one needs it installed.
    #[test]
    fn a_runtime_folder_on_an_untrusted_file_system_is_unverifiable() {
        let (_dir, ext) = folder();
        record(&ext);
        // macOS: review r9 R9-2's `FSKit` mount that calls itself `apfs`.
        #[cfg(target_os = "macos")]
        let foreign_fs = [("macfuse_loop", "", false), ("smbfs", "", false), ("apfs", "", true)];
        #[cfg(target_os = "linux")]
        let foreign_fs = [("fuse", "", false)];
        #[cfg(windows)]
        let foreign_fs = [
            ("NTFS", r"\Device\Volume{d6cc17c5-1734-4085-bce7-964f1e9f5de9}", false),
            ("NTFS", r"\Device\Mup", false),
            ("FAT32", r"\Device\HarddiskVolume5", false),
        ];
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        let foreign_fs: [(&str, &str, bool); 0] = [];
        for (name, device, fskit) in foreign_fs {
            let verdict = check_from(&ext, MAX_TOTAL, |path| {
                let (strict, _) = runtime_anchor(path)?;
                Ok((strict, FileSystem { name: name.to_owned(), device: device.to_owned(), fskit }))
            });
            let Verdict::Unverifiable(why) = verdict else { panic!("{name} {device}: {verdict:?}") };
            assert!(why.contains(&shown(name)), "{why}");
            assert!(device.is_empty() || why.contains(&shown(device)), "{why}");
            assert!(!fskit || why.contains("mounted through FSKit"), "{why}");
            assert!(why.contains(crate::paths::RUNTIME_ENV), "{why}");
        }
        assert_eq!(check(&ext), Verdict::Intact, "the real one is a local disk's");
    }

    /// SR-74 (review r9 R9-3), L1: a runtime folder whose file system cannot be read is
    /// [`Verdict::Unverifiable`], saying so and what to do, not a damaged record. The read is made to
    /// fail, as no real folder's does, and a `NotFound` from it about a folder that is there is
    /// unverifiable too, not unrecorded (review r11 R11-1); a runtime folder that is not there is still
    /// unrecorded.
    #[test]
    fn a_runtime_folder_whose_file_system_cannot_be_read_is_unverifiable() {
        let (_dir, ext) = folder();
        record(&ext);
        let verdict = check_from(&ext, MAX_TOTAL, |path| {
            runtime_anchor_with(path, |_| Err(std::io::Error::other("stand-in error")))
        });
        let Verdict::Unverifiable(why) = verdict else { panic!("{verdict:?}") };
        assert!(why.contains("could not be read (stand-in error)"), "{why}");
        assert!(why.contains(crate::paths::RUNTIME_ENV), "{why}");
        let gone = ext.parent().unwrap().join("gone");
        let verdict = check_from(&gone.join("extension"), MAX_TOTAL, runtime_anchor);
        assert_eq!(verdict, Verdict::Unrecorded);
        let not_found = check_from(&ext, MAX_TOTAL, |path| {
            runtime_anchor_with(path, |_| Err(std::io::Error::from(ErrorKind::NotFound)))
        });
        let Verdict::Unverifiable(why) = not_found else {
            panic!("a NotFound about a folder that is there: {not_found:?}")
        };
        assert!(why.contains("could not be read"), "{why}");
        let other = check_from(&ext, MAX_TOTAL, |_| Err(std::io::Error::other("not the file system")));
        assert_eq!(other, Verdict::Damaged, "only the file system's read is Unverifiable");
    }

    /// SR-74 (review r9 R9-4, for r8 R8-4), L1: a recorded file whose strict read refused it for what
    /// it is (a placeholder or mount seen only on the handle) is refused as that, not changed, and so is
    /// the record, even where nothing at its path says so any more. The walk refuses a stand-in device
    /// first and a handle-only tag needs a race, so `check` cannot reach these; the decisions are tested
    /// as themselves. Each fails if its `Refusal` arm is made "changed" or left to `refused_at`.
    #[test]
    fn a_refusal_seen_only_on_the_handle_is_refused_as_itself() {
        let path = Path::new("background.js");
        assert_eq!(judged(Err(refusal(path, CLOUD))), Judged::Refused(CLOUD));
        assert_eq!(judged(Err(refusal(path, MOUNTED))), Judged::Refused(MOUNTED));
        assert_eq!(judged(Err(std::io::Error::other("gone"))), Judged::Changed);
        assert_eq!(judged(Ok((b"x".to_vec(), 2))), Judged::Refused(LINKED));
        assert_eq!(judged(Ok((b"x".to_vec(), 1))), Judged::Bytes(b"x".to_vec()));
        assert_eq!(record_refused(&refusal(path, CLOUD), || None), Some(CLOUD), "the handle's own");
        assert_eq!(record_refused(&refusal(path, CLOUD), || Some(MOUNTED)), Some(CLOUD), "first");
        assert_eq!(record_refused(&std::io::Error::other("gone"), || Some(MOUNTED)), Some(MOUNTED));
        assert_eq!(record_refused(&std::io::Error::other("gone"), || None), None);
    }

    /// SR-74 (review r8 R8-6), L1: on Linux, with the runtime folder on overlayfs, a file on another
    /// device is not refused for it when its own file system is overlayfs too (a lower layer's device),
    /// and is when it is FUSE, cannot be read, or the runtime folder is not on overlayfs.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_overlay_layers_device_is_not_a_mount() {
        use std::os::unix::fs::MetadataExt as _;
        let (_dir, ext) = folder();
        let meta = std::fs::metadata(ext.join("background.js")).unwrap();
        let overlay = Strict { dev: meta.dev().wrapping_add(1), overlay: true };
        let plain = Strict { overlay: false, ..overlay };
        let on = |name: &str| {
            let name = name.to_owned();
            move || Ok(FileSystem { name, device: String::new(), fskit: false })
        };
        assert_eq!(overlay.mounted(&meta, on(OVERLAY)), None);
        assert_eq!(overlay.mounted(&meta, on("fuse")), Some(MOUNTED));
        assert_eq!(overlay.mounted(&meta, || Err(std::io::Error::other("gone"))), Some(MOUNTED));
        assert_eq!(plain.mounted(&meta, on(OVERLAY)), Some(MOUNTED));
        assert_eq!(Strict { dev: meta.dev(), ..plain }.mounted(&meta, on("fuse")), None);
    }

    /// SR-74 (review r7 R7-6), L1: a recorded file's refusal comes before any planted name's, however
    /// many sort ahead of it, so a shortened list still shows it.
    #[test]
    fn a_recorded_file_is_named_before_planted_ones() {
        let recorded: BTreeMap<String, String> =
            ["background.js", "manifest.json"].map(|rel| (rel.to_owned(), String::new())).into();
        let mut found: Vec<(String, &'static str)> = (0..12).map(|n| (format!("{n:02}.js"), CLOUD)).collect();
        found.push(("background.js".to_owned(), LINKED));
        found.push(("00.js".to_owned(), CLOUD));
        let ordered = recorded_first(found, &recorded, |(rel, _)| rel);
        assert_eq!(ordered[0], ("background.js".to_owned(), LINKED));
        assert_eq!(ordered[1], ("00.js".to_owned(), CLOUD));
        assert_eq!(ordered.len(), 13, "no repeats");
        assert!(explained(&ordered).starts_with("\"background.js\" has other hard links"));
    }

    /// SR-74 (review r2 R2-1), L1: a planted tree cannot make a walk run long: depth and entries are capped.
    #[test]
    fn a_deep_or_full_tree_is_refused() {
        let (_dir, ext) = folder();
        record(&ext);
        let mut deep = ext.join("d");
        for _ in 0..MAX_DEPTH {
            deep = deep.join("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        assert!(hashes(&ext).unwrap_err().to_string().contains("more than 32 folders deep"));
        assert!(matches!(check(&ext), Verdict::Changed(names) if names.len() == 1));
        std::fs::remove_dir_all(ext.join("d")).unwrap();
        std::fs::create_dir(ext.join("many")).unwrap();
        for n in 0..MAX_ENTRIES {
            std::fs::write(ext.join("many").join(format!("{n}.png")), b"").unwrap();
        }
        assert!(hashes(&ext).unwrap_err().to_string().contains("more than 4096 entries"));
        assert!(matches!(check(&ext), Verdict::Changed(names) if names.contains(&"many".to_owned())));
    }

    /// SR-74 (review r3 R3-1, r4 R4-1), L1: Chrome serves a named NTFS stream of any file or folder in
    /// the extension as a page of its own (`background.js:x.html`, `desktop.ini:x.html`), and no folder
    /// listing shows one, so the check refuses any stream there, a skipped OS file's included, never
    /// Intact; the source's streams (a download's `Zone.Identifier`) are ignored.
    #[cfg(windows)]
    #[test]
    fn a_named_stream_on_any_file_or_folder_is_refused() {
        let stream = |path: &Path, name: &str| {
            let mut path = path.to_path_buf().into_os_string();
            path.push(name);
            PathBuf::from(path)
        };
        let (_dir, ext) = folder();
        std::fs::write(stream(&ext.join("manifest.json"), ":Zone.Identifier"), b"[ZoneTransfer]").unwrap();
        let files = read(&ext).unwrap();
        assert_eq!(files.contents["manifest.json"], b"{}", "the source's streams are not read or recorded");
        std::fs::remove_file(stream(&ext.join("manifest.json"), ":Zone.Identifier")).unwrap();
        record(&ext);
        std::fs::write(ext.join("desktop.ini"), b"[.ShellClassInfo]").unwrap();
        std::fs::write(ext.join("icons").join("Thumbs.db"), b"thumbs").unwrap();
        assert_eq!(check(&ext), Verdict::Intact, "the OS files alone are not compared");
        for (on, name, named) in [
            (ext.join("background.js"), ":x.html", "background.js:x.html"),
            (ext.join("icons"), ":x.html", "icons:x.html"),
            (ext.clone(), ":x.html", ".:x.html"),
            (ext.join("desktop.ini"), ":x.html", "desktop.ini:x.html"),
            (ext.join("icons").join("Thumbs.db"), ":x.js", "icons/Thumbs.db:x.js"),
        ] {
            std::fs::write(stream(&on, name), b"<script src=x.js></script>").unwrap();
            assert_eq!(check(&ext), Verdict::Changed(vec![named.to_owned()]), "{named}");
            std::fs::remove_file(stream(&on, name)).unwrap();
            assert_eq!(check(&ext), Verdict::Intact);
        }
    }

    /// SR-74 (review r3 R3-2, r4 R4-2, R4-3), L1: a name from the folder is shown quoted, with every
    /// character that shows nothing or changes the text around it escaped by Unicode property (a
    /// control, a bidi override, tag characters an LLM reads as text, a line separator, U+180E), so a
    /// planted name cannot clear a terminal, start a line of its own, hide text, close its quotes or fake
    /// the list; a long name keeps its two ends; a long list is cut at ten, and a changed recorded file
    /// comes before every planted name.
    #[test]
    fn a_planted_name_is_shown_escaped_and_a_long_list_is_cut() {
        let planted = "x\u{1b}[2J\nThe bridge is fine\u{202e}.js";
        let escaped = r#""x\u{1b}[2J\nThe bridge is fine\u{202e}.js""#;
        assert_eq!(shown(planted), escaped);
        // "Ig" in tag characters, which show nothing; U+2028; U+180E; ALM; a variation selector; a Hangul
        // filler; a no-break space; a private-use character; an unassigned one.
        assert_eq!(
            shown("a\u{e0049}\u{e0067}\u{2028}\u{180e}\u{61c}\u{fe0f}\u{3164}\u{a0}\u{e000}\u{50000}.js"),
            r#""a\u{e0049}\u{e0067}\u{2028}\u{180e}\u{61c}\u{fe0f}\u{3164}\u{a0}\u{e000}\u{50000}.js""#
        );
        assert_eq!(
            shown("caf\u{e9} \u{4e2d}.js"),
            "\"caf\u{e9} \u{4e2d}.js\"",
            "letters and a space are kept"
        );
        assert_eq!(shown(r#"a", "b"#), r#""a\", \"b""#, "a name cannot close its quotes");
        // Review r5 R5-4: quotes a person reads as `"`, a planted cut, a blank Braille cell, a mark that
        // would draw over the opening quote or an escape; a mark on a letter and an ASCII `'` are kept.
        assert_eq!(
            shown("a.js\u{ff02}, \u{201c}b\u{201d}\u{2033}\u{2026}\u{2800}.html"),
            r#""a.js\u{ff02}, \u{201c}b\u{201d}\u{2033}\u{2026}\u{2800}.html""#
        );
        assert_eq!(shown("\u{338}a.js"), r#""\u{338}a.js""#);
        assert_eq!(
            shown("\u{20dd}\u{301}a.js"),
            r#""\u{20dd}\u{301}a.js""#,
            "an enclosing mark, then one more"
        );
        assert_eq!(shown("a\u{1b}\u{338}.js"), r#""a\u{1b}\u{338}.js""#);
        assert_eq!(shown("cafe\u{301}'s.js"), "\"cafe\u{301}'s.js\"");
        #[cfg(windows)]
        {
            let path = |text: &str| shown_path(Path::new(text));
            assert_eq!(path(r"\\?\C:\rt\a.js"), r#""C:\rt\a.js""#, "the verbatim prefix is not shown");
            assert_eq!(path(r"\\?\UNC\host\share\a.js"), r#""\\host\share\a.js""#);
            assert_eq!(
                path(r"\\?\GLOBALROOT\Device\ImDisk0\a.js"),
                r#""\\?\GLOBALROOT\Device\ImDisk0\a.js""#
            );
            assert_eq!(path(r"C:\rt\a.js"), r#""C:\rt\a.js""#);
        }
        #[cfg(not(windows))]
        assert_eq!(shown_path(Path::new(r"\\?\C:\x")), r#""\\\\?\\C:\\x""#, "a name, not a prefix");
        #[cfg(windows)]
        assert_eq!(shown(r"C:\rt\extension"), r#""C:\rt\extension""#, "a path reads as itself");
        #[cfg(not(windows))]
        assert_eq!(shown(r"x\u{1b}"), r#""x\\u{1b}""#, "a planted backslash is not an escape");
        let cut = shown(&format!("{}.js", "a".repeat(300)));
        assert_eq!(cut.chars().count(), SHOWN_LEN, "{cut}");
        assert!(cut.starts_with("\"aaa") && cut.ends_with("aa.js\"") && cut.contains('…'), "{cut}");
        let cut = shown(&"\u{e0041}".repeat(100));
        assert!(cut.chars().count() <= SHOWN_LEN, "{cut}");
        assert!(
            cut.trim_matches('"').split('…').all(|end| end.len() % 9 == 0),
            "no escape cut in two: {cut}"
        );

        let many: Vec<String> = (0..13).map(|n| format!("{n}.js")).collect();
        assert_eq!(listed(&many[..2]), r#""0.js", "1.js""#);
        assert_eq!(
            listed(&many),
            r#""0.js", "1.js", "2.js", "3.js", "4.js", "5.js", "6.js", "7.js", "8.js", "9.js" and 3 more"#
        );
        let (_dir, ext) = folder();
        record(&ext);
        std::fs::write(ext.join("manifest.json"), b"{\"swapped\": true}").unwrap();
        for n in 0..12 {
            std::fs::write(ext.join(format!("!{n}.html")), b"x").unwrap();
        }
        let Verdict::Changed(names) = check(&ext) else { panic!("a changed folder passed") };
        assert_eq!((names.len(), names[0].as_str()), (13, "manifest.json"), "{names:?}");
        assert!(listed(&names).starts_with(r#""manifest.json", "!0.html""#));
        // Windows refuses a control character in a file name; macOS and Linux take one.
        #[cfg(unix)]
        {
            let (_dir, ext) = folder();
            record(&ext);
            std::fs::write(ext.join(planted), b"x").unwrap();
            let Verdict::Changed(names) = check(&ext) else { panic!("a planted name is Changed") };
            assert_eq!(listed(&names), escaped);
            assert!(!hashes(&ext).unwrap_err().to_string().contains(['\u{1b}', '\n']));
        }
    }

    /// SR-74 (review r3 R3-5, r4 R4-4, r5 R5-3), L1: two source names that are one file where case and
    /// Unicode normalization are ignored are refused by `read`, before install writes anything; each
    /// character is folded on its own until the name stops changing, so a final sigma, a long s and a
    /// capital sharp s fold as NTFS and APFS fold them.
    #[test]
    fn names_that_are_one_file_on_windows_or_macos_are_refused() {
        let survey = |files: &[&str], dirs: &[&str]| Survey {
            files: files.iter().map(|rel| ((*rel).to_owned(), PathBuf::new())).collect(),
            dirs: dirs.iter().map(|rel| ((*rel).to_owned(), PathBuf::new())).collect(),
            ..Survey::default()
        };
        assert_eq!(collision(&survey(&["A.js", "a.js"], &[])), Some(("A.js", "a.js")));
        assert!(collision(&survey(&["caf\u{e9}.js", "cafe\u{301}.js"], &[])).is_some());
        assert!(collision(&survey(&["CAF\u{c9}.js", "cafe\u{301}.js"], &[])).is_some());
        assert!(collision(&survey(&["Icons/a.png", "icons/b.png"], &["Icons", "icons"])).is_some());
        assert!(collision(&survey(&["ΑΣ-1.js", "ασ-1.js"], &[])).is_some(), "a final sigma");
        assert!(collision(&survey(&["ſ.js", "s.js"], &[])).is_some(), "a long s");
        assert!(collision(&survey(&["ς.js", "σ.js"], &[])).is_some());
        // Review r5 R5-3: `ẞ` folds to `ß` and only a second fold takes that to `ss`, as APFS folds both.
        assert!(collision(&survey(&["ẞ.js", "ß.js"], &[])).is_some(), "a capital sharp s");
        assert!(collision(&survey(&["ẞ.js", "ss.js"], &[])).is_some());
        assert!(collision(&survey(&["ß.js", "SS.js"], &[])).is_some());
        assert_eq!(collision(&survey(&["a.js", "b.js", "icons/a.js", "ασ.js"], &["icons"])), None);
        // Review r6 R6-5: a path that has not settled within the cap is refused, as both of a pair.
        assert_eq!(folded("ẞ.js", 2), None);
        assert_eq!(folded("ẞ.js", 3).as_deref(), Some("ss.js"));
        assert_eq!(folded("A.js", 1), None, "one fold changes it; a second confirms");
        assert_eq!(folded("a.js", 1).as_deref(), Some("a.js"));
        // NTFS keeps both normalizations of a name (APFS keeps one), so Windows builds the real case.
        #[cfg(windows)]
        {
            let (_dir, ext) = folder();
            std::fs::write(ext.join("caf\u{e9}.js"), b"1").unwrap();
            std::fs::write(ext.join("cafe\u{301}.js"), b"2").unwrap();
            let error = read(&ext).unwrap_err().to_string();
            assert!(error.contains("two names that are one file"), "{error}");
        }
    }

    /// SR-74 (review r3 R3-4, r4 R4-6), L1: the check stops reading once the files it read pass the cap
    /// in all (64 MiB in `check`, a few bytes here), and names every recorded file past it rather than
    /// pass it unread.
    #[test]
    fn the_check_stops_at_its_total_cap() {
        let (_dir, ext) = folder();
        record(&ext);
        let all: Vec<String> = ["background.js", "icons/a.png", "manifest.json"].map(str::to_owned).into();
        // Read in that order: 4, 3 and 2 bytes.
        assert_eq!(check_with(&ext, 9), Verdict::Intact);
        assert_eq!(check_with(&ext, 5), Verdict::Changed(all[1..].to_vec()));
        assert_eq!(check_with(&ext, 0), Verdict::Changed(all));
    }

    /// SR-74 (review r4 R4-5, r5 R5-2), L1: a folder whose paths pass Windows' 260-character `MAX_PATH`
    /// is read, recorded and checked like any other, its streams included, though it is named by a plain
    /// path (`C:\...`, as install and the service get it): `anchored` gives every path in the `\\?\` form,
    /// and the streams are read by handle.
    #[test]
    fn a_folder_past_max_path_is_checked() {
        let dir = tempfile::tempdir().unwrap();
        // `canonicalize` gives `\\?\C:\...` on Windows, which the setup below uses to make the folder.
        let mut long = dir.path().canonicalize().unwrap();
        for _ in 0..3 {
            long = long.join("x".repeat(100));
        }
        let long = long.join("extension");
        std::fs::create_dir_all(long.join("icons")).unwrap();
        std::fs::write(long.join("manifest.json"), b"{}").unwrap();
        std::fs::write(long.join("background.js"), b"code").unwrap();
        let text = long.to_str().unwrap();
        let ext = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(text));
        assert!(ext.join("background.js").as_os_str().len() > 320);
        #[cfg(windows)]
        assert!(!ext.as_os_str().to_string_lossy().starts_with(r"\\"), "a plain path: {}", ext.display());
        record(&ext);
        assert_eq!(check(&ext), Verdict::Intact);
        #[cfg(windows)]
        {
            let mut stream = long.join("background.js").into_os_string();
            stream.push(":x.html");
            std::fs::write(&stream, b"<p>").unwrap();
            assert_eq!(check(&ext), Verdict::Changed(vec!["background.js:x.html".into()]));
        }
    }

    /// SR-74, L1: a record this version would not write is damaged, never trusted, never followed out.
    #[test]
    fn a_record_that_is_not_ours_is_damaged() {
        let (_dir, ext) = folder();
        std::fs::remove_file(ext.join("background.js")).unwrap();
        std::fs::remove_dir_all(ext.join("icons")).unwrap();
        let sha = crate::util::hex(&sha2::Sha256::digest(b"{}"));
        let path = record_path(&ext);
        for bad in [
            "not json".to_owned(),
            json!({ "files": {} }).to_string(),
            json!({ "sha256": {} }).to_string(),
            json!({ "sha256": { "background.js": sha } }).to_string(),
            json!({ "sha256": { "manifest.json": "ABC" } }).to_string(),
            json!({ "sha256": { "manifest.json": sha, "../config.json": sha } }).to_string(),
            json!({ "sha256": { "manifest.json": sha, "icons\\a.png": sha } }).to_string(),
            json!({ "sha256": { "manifest.json": sha, "icons//a.png": sha } }).to_string(),
            json!({ "sha256": { "manifest.json": sha, "./a.png": sha } }).to_string(),
            json!({ "sha256": { "manifest.json": sha, "/etc/hosts": sha } }).to_string(),
            json!({ "sha256": { "manifest.json": sha, "C:a.png": sha } }).to_string(),
            json!({ "sha256": { "manifest.json": sha, "NUL": sha } }).to_string(),
        ] {
            std::fs::write(&path, &bad).unwrap();
            assert_eq!(check(&ext), Verdict::Damaged, "{bad}");
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(check(&ext), Verdict::Damaged, "a folder where the record should be");
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, json!({ "sha256": { "manifest.json": sha } }).to_string()).unwrap();
        assert_eq!(check(&ext), Verdict::Intact);
        #[cfg(unix)]
        {
            let real = ext.parent().unwrap().join("real-record.json");
            std::fs::rename(&path, &real).unwrap();
            std::os::unix::fs::symlink(&real, &path).unwrap();
            assert_eq!(check(&ext), Verdict::Damaged, "a record behind a link is not followed");
        }
    }
}
