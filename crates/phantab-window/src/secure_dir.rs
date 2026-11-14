//! Owner-only folders (THREAT-MODEL SR-10, SR-11, SR-48): the runtime dir that holds the endpoint token,
//! set and checked at every service start.
//!
//! Windows: a protected DACL (inheritance off) granting full control to the current user's SID and
//! `S-1-5-18` (SYSTEM) only, inherited by everything inside, and a Medium mandatory label that refuses
//! read, write and execute to a lower-integrity process of the same user (a sandboxed renderer, say),
//! which the DACL alone would let in. macOS: mode `0700`, owned by the current
//! uid. A folder made here has that from the create call on (R15); an existing one is restricted. A
//! symlink, junction or other reparse point, or a folder owned by someone else, is refused before
//! anything is changed. The OS calls live in `secure_win32` and `secure_unix`; this module is the safe
//! surface and the checks that need no OS call, so they are linted and tested on every OS.

use std::path::{Path, PathBuf};

/// Why a folder cannot be made owner-only. Every message names the path and nothing else.
#[derive(Debug, thiserror::Error)]
pub enum SecureDirError {
    #[error("{0} is a link (symlink, junction or reparse point); phantab will not use it")]
    Link(PathBuf),
    #[error("{0} is not a folder")]
    NotADir(PathBuf),
    #[error("{0} is not a plain file")]
    NotAFile(PathBuf),
    #[error("{0} has more than one name (a hard link); phantab will not use it")]
    HardLink(PathBuf),
    #[error("{path} belongs to another account ({owner}); phantab will not use it")]
    ForeignOwner { path: PathBuf, owner: String },
    #[error("{path} is still open to other accounts after phantab restricted it")]
    StillOpen { path: PathBuf },
    #[error("{context} for {path}: {message}")]
    Os { context: &'static str, path: PathBuf, message: String },
    #[error("owner-only folders are not supported on this OS")]
    Unsupported,
}

/// What [`inspect`] found, without changing anything.
#[allow(clippy::struct_excessive_bools, reason = "independent facts the OS reports, read one by one")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// The owner, as the OS names it (a SID on Windows, a uid on macOS).
    pub owner: String,
    /// The owner is this account (or, on Windows, SYSTEM, Administrators, or this token's default owner).
    pub owned_by_me: bool,
    /// Only this account and SYSTEM (Windows) or only the owner (macOS) have any access.
    pub owner_only: bool,
    /// Windows: the DACL is protected, so nothing above can add an entry. Always true on macOS.
    pub protected: bool,
    /// Windows: a mandatory label of Medium or higher refuses read, write and execute up, inherited by
    /// everything inside when `path` is a folder ([`WINDOWS_LABEL_SDDL`]); false when the label cannot be
    /// read. Always true on macOS, which has no such levels.
    pub labeled: bool,
}

/// Creates `path` if missing (owner-only from the create call, [`create_owner_only`]), refuses a link or a
/// foreign owner, and makes an existing folder owner-only.
///
/// # Errors
/// A [`SecureDirError`] naming the path; the folder is unchanged unless the error is `StillOpen`.
pub fn lock_down(path: &Path) -> Result<(), SecureDirError> {
    // A folder made here already reads owner-only and protected, so the restrict and the walk below are
    // for a folder that existed before this call.
    create_owner_only(path).map_err(|e| os("Could not create the folder", path, &e))?;
    refuse_link(path)?;
    let before = inspect(path)?;
    if !before.owned_by_me {
        return Err(SecureDirError::ForeignOwner { path: path.to_path_buf(), owner: before.owner });
    }
    if !(before.owner_only && before.protected) {
        restrict(path)?;
        let after = inspect(path)?;
        if !(after.owner_only && after.protected) {
            return Err(SecureDirError::StillOpen { path: path.to_path_buf() });
        }
        // While it was open, another account could have put something inside (a `config.json` naming a
        // sign-in provider, say). Restricted now, nothing new can arrive, so one walk settles it.
        refuse_foreign_inside(path)?;
    } else if !before.labeled {
        // Owner-only already (a folder from before the label, SR-10): no other account could get in, so
        // there is nothing to walk; only the label is added, and it reaches everything inside.
        label(path);
    }
    Ok(())
}

/// Puts [`WINDOWS_LABEL_SDDL`] on `path`, best effort: the label only narrows what this user's own
/// lower-integrity processes may do, the DACL already keeps every other account out, so a refusal (a
/// file system without labels, a process running below Medium) leaves the folder as usable as before
/// rather than failing the start. Nothing on macOS.
fn label(path: &Path) {
    #[cfg(windows)]
    {
        let _ = crate::secure_win32::set_label(path, WINDOWS_LABEL_SDDL);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
}

/// Creates the folder `path` owner-only in the create call itself, so it is never open to another
/// account, not even until a restrict (THREAT-MODEL R15): on Windows `CreateDirectoryW` gets the DACL
/// [`lock_down`] writes (protected, so nothing is inherited); on macOS `mkdir` gets mode `0700`. Missing
/// parents are made as `create_dir_all` makes them. `Ok(false)` when `path` is already a folder (or a link
/// to one); it is left as it is, for [`lock_down`]'s checks.
///
/// # Errors
/// The folder or a parent cannot be created, or `path` exists and is not a folder.
pub fn create_owner_only(path: &Path) -> std::io::Result<bool> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    match create_leaf(path) {
        Ok(()) => Ok(true),
        // As `create_dir_all`: an existing folder, or one another process made just now, is fine.
        Err(_) if path.is_dir() => Ok(false),
        Err(e) => Err(e),
    }
}

fn create_leaf(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let (user, _) = crate::secure_win32::token_sids(path).map_err(std::io::Error::other)?;
        let dacl = windows_owner_only_sddl(&user);
        match crate::secure_win32::create_dir_with(path, &format!("{dacl}{WINDOWS_LABEL_SDDL}")) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                // The label was refused (a process below Medium may not set it): the owner-only DACL is
                // what must come with the create call; the label follows, best effort.
                crate::secure_win32::create_dir_with(path, &dacl)?;
                label(path);
                Ok(())
            }
            made => made,
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        // The umask can only take bits away from 0700.
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// Every entry under `dir` (a folder just made owner-only) is this account's and none is a link, else
/// the first one that is not is refused by name. THREAT-MODEL R15.
fn refuse_foreign_inside(dir: &Path) -> Result<(), SecureDirError> {
    let mut folders = vec![dir.to_path_buf()];
    while let Some(folder) = folders.pop() {
        let entries = std::fs::read_dir(&folder).map_err(|e| os("Could not list the folder", &folder, &e))?;
        for entry in entries {
            let entry = entry.map_err(|e| os("Could not list the folder", &folder, &e))?;
            let path = entry.path();
            let seen = inspect(&path)?;
            if !seen.owned_by_me {
                return Err(SecureDirError::ForeignOwner { path, owner: seen.owner });
            }
            refuse_hard_link(&path)?;
            if entry.file_type().map_err(|e| os("Could not read the folder", &path, &e))?.is_dir() {
                folders.push(path);
            }
        }
    }
    Ok(())
}

/// Reads `path`'s owner and access, refusing a link. Works on files too (for SR-11's endpoint file).
///
/// # Errors
/// A [`SecureDirError`] naming the path.
pub fn inspect(path: &Path) -> Result<Inspection, SecureDirError> {
    refuse_link(path)?;
    #[cfg(windows)]
    {
        let (user, default_owner) = crate::secure_win32::token_sids(path)?;
        let (owner, dacl) = crate::secure_win32::owner_and_dacl(path)?;
        let alias = crate::secure_win32::sddl_name(&user, path)?;
        // An unreadable label reads as missing: lock_down then tries to set it, best effort.
        let labeled =
            crate::secure_win32::label_sddl(path).is_ok_and(|l| windows_label_ok(&l, path.is_dir()));
        Ok(Inspection {
            owned_by_me: windows_owner_trusted(&owner, &user, &default_owner),
            owner_only: windows_dacl_owner_only(&dacl, &[&user, &alias]),
            protected: windows_dacl_protected(&dacl),
            labeled,
            owner,
        })
    }
    #[cfg(unix)]
    {
        let (uid, mode) = crate::secure_unix::owner_and_mode(path)?;
        Ok(Inspection {
            owner: uid.to_string(),
            owned_by_me: uid == crate::secure_unix::effective_uid(),
            // No group or other bit: `mode & 0o077 == 0`.
            owner_only: mode.trailing_zeros() >= 6,
            protected: true,
            labeled: true,
        })
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        Err(SecureDirError::Unsupported)
    }
}

fn restrict(path: &Path) -> Result<(), SecureDirError> {
    #[cfg(windows)]
    {
        let (user, _) = crate::secure_win32::token_sids(path)?;
        crate::secure_win32::set_dacl(path, &windows_owner_only_sddl(&user), true)?;
        label(path);
        Ok(())
    }
    #[cfg(unix)]
    {
        crate::secure_unix::set_mode_700(path)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        Err(SecureDirError::Unsupported)
    }
}

/// A symlink, junction or any other reparse point is refused: the owner-only check would read the
/// link's target, which someone else may control.
fn refuse_link(path: &Path) -> Result<(), SecureDirError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| os("Could not read the folder", path, &e))?;
    if meta.file_type().is_symlink() || is_reparse_point(&meta) {
        return Err(SecureDirError::Link(path.to_path_buf()));
    }
    if !meta.is_dir() && !meta.is_file() {
        return Err(SecureDirError::NotADir(path.to_path_buf()));
    }
    Ok(())
}

/// A file with a second name is refused (Unix). Another account may link any file it can see, even one
/// it cannot read, into a folder it could write to, so while the runtime was open one could have
/// linked, say, `service.lock` to this user's `~/.zshrc`: the owner check passes (the file is this
/// user's), and a later write through that name would change the user's file. Windows needs write
/// access to the file to link it, which no other account has to this user's files.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps, reason = "it can refuse only on Unix"))]
fn refuse_hard_link(path: &Path) -> Result<(), SecureDirError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::symlink_metadata(path).map_err(|e| os("Could not read the file", path, &e))?;
        if meta.is_file() && meta.nlink() > 1 {
            return Err(SecureDirError::HardLink(path.to_path_buf()));
        }
    }
    let _ = path;
    Ok(())
}

/// Opens the service lock file at `path` for reading and writing, creating it if missing (mode `0600`
/// on Unix), and refuses, rather than follows, a link at `path`: a symlink (`O_NOFOLLOW`), a junction or
/// other reparse point (Windows, opened as itself), a hard link (Unix), or anything but a plain file.
/// So taking the lock never truncates or writes a file somewhere else. SR-12.
///
/// # Errors
/// A [`SecureDirError`] naming the path.
pub fn open_lock_file(path: &Path) -> Result<std::fs::File, SecureDirError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NONBLOCK: a FIFO planted at `path` must not hang the open; it is refused below.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|e| {
        #[cfg(unix)]
        if e.raw_os_error() == Some(libc::ELOOP) {
            return SecureDirError::Link(path.to_path_buf());
        }
        os("Could not open the file", path, &e)
    })?;
    // The opened file's own metadata, so nothing swapped in after the open can answer for it.
    let meta = file.metadata().map_err(|e| os("Could not read the file", path, &e))?;
    if meta.file_type().is_symlink() || is_reparse_point(&meta) {
        return Err(SecureDirError::Link(path.to_path_buf()));
    }
    if !meta.is_file() {
        return Err(SecureDirError::NotAFile(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.nlink() > 1 {
            return Err(SecureDirError::HardLink(path.to_path_buf()));
        }
    }
    Ok(file)
}

#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_meta: &std::fs::Metadata) -> bool {
    false
}

pub(crate) fn os(context: &'static str, path: &Path, e: &dyn std::fmt::Display) -> SecureDirError {
    SecureDirError::Os { context, path: path.to_path_buf(), message: e.to_string() }
}

const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// The DACL [`lock_down`] writes on Windows, in SDDL: protected, full control for `user` and SYSTEM,
/// inherited by files and folders inside.
#[must_use]
pub fn windows_owner_only_sddl(user: &str) -> String {
    format!("D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)")
}

/// The mandatory label [`lock_down`] puts on a folder on Windows, in SDDL: Medium, refusing a lower level
/// read (`NR`), write (`NW`) and execute or traverse (`NX`), inherited by files (`OI`) and folders (`CI`).
/// A folder without one counts as Medium with only write-up refused, so a Low process of the same user
/// could read the endpoint token through the user's own DACL entry.
pub const WINDOWS_LABEL_SDDL: &str = "S:(ML;OICI;NRNWNX;;;ME)";

/// Whether an SDDL label (`S:(ML;OICI;NRNWNX;;;ME)`) is at Medium or above and refuses read, write and
/// execute up; for a folder (`container`) it must also apply to the folder itself and reach the files and
/// folders inside. No label, or text that does not parse, is not labeled.
#[must_use]
pub fn windows_label_ok(sddl: &str, container: bool) -> bool {
    let pairs = |s: &str, want: &str| s.as_bytes().chunks(2).any(|c| c == want.as_bytes());
    let Some(rest) = sddl.strip_prefix("S:") else { return false };
    let Some(open) = rest.find('(') else { return false };
    let aces = &rest[open..];
    if !aces.ends_with(')') {
        return false;
    }
    aces[1..aces.len() - 1].split(")(").any(|ace| {
        let fields: Vec<&str> = ace.split(';').collect();
        let ["ML", flags, rights, "", "", level] = fields.as_slice() else { return false };
        let rights_ok = match rights.strip_prefix("0x") {
            // SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | NO_READ_UP | NO_EXECUTE_UP.
            Some(hex) => u32::from_str_radix(hex, 16).is_ok_and(|bits| bits & 0x7 == 0x7),
            None => ["NR", "NW", "NX"].iter().all(|r| pairs(rights, r)),
        };
        let level_ok = match *level {
            "ME" | "MP" | "HI" | "SI" => true,
            // SECURITY_MANDATORY_MEDIUM_RID is 0x2000.
            other => {
                other.strip_prefix("S-1-16-").and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| n >= 0x2000)
            }
        };
        let reaches_inside = !container
            || (pairs(flags, "OI") && pairs(flags, "CI") && !pairs(flags, "IO") && !pairs(flags, "NP"));
        rights_ok && level_ok && reaches_inside
    })
}

/// A folder owned by this account, its token's default owner (Administrators when elevated), SYSTEM or
/// Administrators is ours; anyone else's is foreign.
#[must_use]
pub fn windows_owner_trusted(owner: &str, user: &str, default_owner: &str) -> bool {
    [user, default_owner, SYSTEM_SID, ADMINISTRATORS_SID].contains(&owner)
}

/// Whether an SDDL DACL (`D:P(A;OICI;FA;;;S-1-5-21-…)(A;OICI;FA;;;SY)`) has the protected flag.
#[must_use]
pub fn windows_dacl_protected(sddl: &str) -> bool {
    sddl.strip_prefix("D:").is_some_and(|rest| rest.split('(').next().unwrap_or_default().contains('P'))
}

/// Whether every entry of an SDDL DACL allows only this user or SYSTEM, and the user has one. `user`
/// lists the names SDDL may give this account: its `S-1-…` SID and the alias the OS writes for it (`LA`
/// when it is the machine's built-in Administrator, as on CI runners). A deny entry, an audit entry, a
/// conditional entry or any other trustee makes it open.
#[must_use]
pub fn windows_dacl_owner_only(sddl: &str, user: &[&str]) -> bool {
    let Some(rest) = sddl.strip_prefix("D:") else { return false };
    let Some(open) = rest.find('(') else { return false };
    let aces = &rest[open..];
    if !aces.ends_with(')') {
        return false;
    }
    let mut user_has_one = false;
    for ace in aces[1..aces.len() - 1].split(")(") {
        let fields: Vec<&str> = ace.split(';').collect();
        let [kind, _flags, _rights, "", "", trustee] = fields.as_slice() else { return false };
        if *kind != "A" {
            return false;
        }
        let is_user = user.contains(trustee) || (user.contains(&SYSTEM_SID) && *trustee == "SY");
        if !(is_user || *trustee == "SY" || *trustee == SYSTEM_SID) {
            return false;
        }
        user_has_one |= is_user;
    }
    user_has_one
}

/// A file's own access rules (THREAT-MODEL SR-50), read before a rewrite and put back on the replacement,
/// so an atomic write (temp file, then rename) keeps a mode, owner or explicit DACL the owner set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSecurity {
    /// Windows: the DACL's explicit entries as SDDL, and whether it is protected; `None` when the file
    /// only inherits (a new file in the same folder inherits the same).
    #[cfg(windows)]
    dacl: Option<(String, bool)>,
    /// macOS: permission bits, uid and gid.
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
}

/// Reads `path`'s [`FileSecurity`], following a link as a write through it would.
///
/// # Errors
/// The file or its security cannot be read.
pub fn file_security(path: &Path) -> Result<FileSecurity, SecureDirError> {
    #[cfg(windows)]
    {
        let (_, dacl) = crate::secure_win32::owner_and_dacl(path)?;
        Ok(FileSecurity { dacl: windows_explicit_dacl(&dacl) })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(path).map_err(|e| os("Could not read the file", path, &e))?;
        Ok(FileSecurity { mode: meta.mode() & 0o7777, uid: meta.uid(), gid: meta.gid() })
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        Err(SecureDirError::Unsupported)
    }
}

/// Puts `security` on `path` (the replacement, before it is renamed in).
///
/// # Errors
/// The OS refused; on macOS that includes an owner this account may not give the file.
pub fn apply_file_security(path: &Path, security: &FileSecurity) -> Result<(), SecureDirError> {
    #[cfg(windows)]
    {
        match &security.dacl {
            Some((sddl, protected)) => crate::secure_win32::set_dacl(path, sddl, *protected),
            None => Ok(()),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let meta = std::fs::metadata(path).map_err(|e| os("Could not read the file", path, &e))?;
        if (meta.uid(), meta.gid()) != (security.uid, security.gid) {
            std::os::unix::fs::chown(path, Some(security.uid), Some(security.gid))
                .map_err(|e| os("Could not keep the file's owner", path, &e))?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(security.mode))
            .map_err(|e| os("Could not keep the file's mode", path, &e))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (path, security);
        Err(SecureDirError::Unsupported)
    }
}

/// The part of an SDDL DACL a replacement file would not inherit: its explicit entries (no `ID` flag),
/// and whether it is protected. `None` when there is nothing to carry over: an unprotected DACL of
/// inherited entries only, a NULL DACL, or text that does not parse.
#[must_use]
pub fn windows_explicit_dacl(sddl: &str) -> Option<(String, bool)> {
    let rest = sddl.strip_prefix("D:")?;
    let open = rest.find('(').unwrap_or(rest.len());
    let flags = &rest[..open];
    if flags.contains("NO_ACCESS_CONTROL") {
        return None;
    }
    let protected = windows_dacl_protected(sddl);
    let mut explicit = String::new();
    let mut depth = 0usize;
    let mut start = open;
    for (i, c) in rest.char_indices().skip_while(|&(i, _)| i < open) {
        match c {
            '(' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let ace = &rest[start..=i];
                    let inherited = ace[1..].split(';').nth(1).is_some_and(|f| f.contains("ID"));
                    if !inherited {
                        explicit.push_str(ace);
                    }
                }
            }
            _ if depth == 0 => return None,
            _ => {}
        }
    }
    if depth != 0 || (!protected && explicit.is_empty()) {
        return None;
    }
    Some((format!("D:{}{explicit}", if protected { "P" } else { "" }), protected))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "S-1-5-21-1-2-3-1001";

    /// SR-50: what a rewrite must carry over is the explicit part of the DACL and its protection.
    #[test]
    fn only_explicit_entries_and_the_protection_carry_over() {
        assert_eq!(windows_explicit_dacl("D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)"), None, "inherits only");
        assert_eq!(
            windows_explicit_dacl(&format!("D:PAI(A;;FA;;;{ME})(A;;FA;;;SY)")),
            Some((format!("D:P(A;;FA;;;{ME})(A;;FA;;;SY)"), true))
        );
        assert_eq!(
            windows_explicit_dacl(&format!("D:AI(D;;FW;;;WD)(A;ID;FA;;;{ME})")),
            Some(("D:(D;;FW;;;WD)".to_owned(), false)),
            "an explicit deny stays, the inherited entry is left to inheritance"
        );
        assert_eq!(windows_explicit_dacl("D:P"), Some(("D:P".to_owned(), true)), "protected and empty");
        assert_eq!(
            windows_explicit_dacl("D:(XA;;FX;;;WD;(Member_of {SID(BA)}))"),
            Some(("D:(XA;;FX;;;WD;(Member_of {SID(BA)}))".to_owned(), false)),
            "a conditional entry's parentheses stay inside it"
        );
        for broken in ["D:NO_ACCESS_CONTROL", "O:BA", "D:(A;;FA;;;SY", "D:(A;;FA;;;SY)x", ""] {
            assert_eq!(windows_explicit_dacl(broken), None, "{broken}");
        }
    }

    /// SR-50 on the OS: a file's own rules move onto its replacement.
    #[test]
    fn file_security_moves_onto_a_replacement() {
        let dir = scratch("file-security");
        std::fs::create_dir_all(&dir).unwrap();
        let (old, new) = (dir.join("config"), dir.join("config.tmp"));
        std::fs::write(&old, b"a").unwrap();
        std::fs::write(&new, b"b").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(windows)]
        {
            let (user, _) = crate::secure_win32::token_sids(&old).unwrap();
            crate::secure_win32::set_dacl(&old, &format!("D:P(A;;FA;;;{user})(A;;FA;;;SY)"), true).unwrap();
            assert!(!inspect(&new).unwrap().protected, "a new temp file inherits");
        }
        let security = file_security(&old).unwrap();
        apply_file_security(&new, &security).unwrap();
        assert_eq!(file_security(&new).unwrap(), security);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&new).unwrap().permissions().mode() & 0o7777, 0o600);
        }
        #[cfg(windows)]
        {
            let after = inspect(&new).unwrap();
            let read = crate::secure_win32::owner_and_dacl(&new).unwrap();
            assert!(after.protected && after.owner_only, "{after:?} {read:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_written_dacl_reads_back_as_owner_only_and_protected() {
        let sddl = windows_owner_only_sddl(ME);
        assert!(windows_dacl_protected(&sddl));
        assert!(windows_dacl_owner_only(&sddl, &[ME]));
        assert!(windows_dacl_protected("D:PAI(A;OICI;FA;;;SY)"));
        assert!(!windows_dacl_protected("D:AI(A;OICI;FA;;;SY)"));
        assert!(!windows_dacl_protected("D:(A;;FA;;;P)"), "a P in an entry is not the flag");
    }

    #[test]
    fn any_other_trustee_or_entry_kind_is_open() {
        assert!(windows_dacl_owner_only(&format!("D:AI(A;ID;FA;;;{ME})(A;ID;FA;;;SY)"), &[ME]));
        // The built-in Administrator reads back as `LA`; any other alias stays foreign.
        assert!(windows_dacl_owner_only("D:P(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)", &[ME, "LA"]));
        assert!(!windows_dacl_owner_only("D:P(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)", &[ME, ME]));
        for open in [
            format!("D:P(A;OICI;FA;;;{ME})(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;WD)"),
            format!("D:P(A;OICI;FA;;;{ME})(A;OICI;FA;;;BA)"),
            format!("D:P(A;OICI;FA;;;{ME})(D;OICI;FA;;;SY)"),
            format!("D:P(XA;OICI;FA;;;{ME};(x))"),
            "D:P(A;OICI;FA;;;SY)".to_owned(),
            "D:P".to_owned(),
            "D:NO_ACCESS_CONTROL".to_owned(),
            String::new(),
        ] {
            assert!(!windows_dacl_owner_only(&open, &[ME]), "{open}");
        }
    }

    /// SR-10: only a label at Medium or above that refuses all three kinds of access up counts, and a
    /// folder's must reach inside.
    #[test]
    fn a_label_counts_at_medium_or_above_refusing_read_write_and_execute_up() {
        assert!(windows_label_ok(WINDOWS_LABEL_SDDL, true));
        assert!(windows_label_ok("S:AI(ML;OICIID;NWNRNX;;;ME)", true), "inherited, in the OS's order");
        assert!(windows_label_ok("S:(ML;ID;NWNRNX;;;ME)", false), "a file inside inherits it");
        assert!(windows_label_ok("S:(ML;OICI;0x7;;;HI)", true));
        assert!(windows_label_ok("S:(ML;OICI;NRNWNX;;;S-1-16-12288)", true));
        for (not, container) in [
            ("S:(ML;ID;NWNRNX;;;ME)", true),
            ("S:(ML;OICI;NW;;;ME)", true),
            ("S:(ML;OICI;0x1;;;ME)", true),
            ("S:(ML;OICI;NRNWNX;;;LW)", true),
            ("S:(ML;OICI;NRNWNX;;;S-1-16-4096)", true),
            ("S:(ML;OICIIO;NRNWNX;;;ME)", true),
            ("S:(ML;OICINP;NRNWNX;;;ME)", true),
            ("S:(AU;SA;FA;;;WD)", false),
            ("D:P(A;OICI;FA;;;SY)", false),
            ("S:", false),
            ("", false),
        ] {
            assert!(!windows_label_ok(not, container), "{not}");
        }
    }

    /// SR-10 on the OS: a folder that is owner-only from before the label gets it, the DACL is left
    /// as it was, and it reaches the file already inside and a file made after.
    #[cfg(windows)]
    #[test]
    fn an_owner_only_folder_from_before_the_label_is_labeled() {
        let dir = scratch("relabel");
        std::fs::create_dir_all(&dir).unwrap();
        let (user, _) = crate::secure_win32::token_sids(&dir).unwrap();
        crate::secure_win32::set_dacl(&dir, &windows_owner_only_sddl(&user), true).unwrap();
        let old = dir.join("endpoint.json");
        std::fs::write(&old, b"{}").unwrap();
        let before = inspect(&dir).unwrap();
        assert!(before.owner_only && before.protected && !before.labeled, "{before:?}");
        let dacl = state(&dir);
        lock_down(&dir).unwrap();
        let label = crate::secure_win32::label_sddl(&dir).unwrap();
        assert!(inspect(&dir).unwrap().labeled, "{label}");
        assert_eq!(state(&dir), dacl, "the DACL is left as it was");
        let inside = crate::secure_win32::label_sddl(&old).unwrap();
        assert!(inspect(&old).unwrap().labeled, "the file already inside: {inside}");
        let new = dir.join("service.lock");
        std::fs::write(&new, b"1").unwrap();
        assert!(inspect(&new).unwrap().labeled, "a file made after");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SR-10, L1: the label is what keeps a lower-integrity process of this same user (a sandboxed
    /// renderer, say) from reading inside; the DACL's entry for the user would let it in. This user's own
    /// Medium processes read as before.
    #[cfg(windows)]
    #[test]
    fn a_lower_integrity_process_of_this_user_cannot_read_inside() {
        let system32 = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
        let tools = scratch("low-tools");
        std::fs::create_dir_all(&tools).unwrap();
        // A process started from an exe labeled Low runs at Low.
        let low_cmd = tools.join("cmd-low.exe");
        std::fs::copy(system32.join("cmd.exe"), &low_cmd).unwrap();
        let status = std::process::Command::new(system32.join("icacls.exe"))
            .arg(&low_cmd)
            .args(["/setintegritylevel", "low"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let reads = |cmd: &Path, file: &Path| {
            std::process::Command::new(cmd)
                .args(["/C", "type"])
                .arg(file)
                .current_dir(&tools)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        };
        let open = scratch("low-open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::write(open.join("token"), b"x").unwrap();
        assert!(reads(&low_cmd, &open.join("token")), "the fixture's Low process reads an unlabeled folder");
        let locked = scratch("low-locked");
        lock_down(&locked).unwrap();
        std::fs::write(locked.join("token"), b"x").unwrap();
        assert!(!reads(&low_cmd, &locked.join("token")), "a Low process read inside a locked folder");
        assert!(
            reads(&system32.join("cmd.exe"), &locked.join("token")),
            "this user's own processes still read"
        );
        for dir in [tools, open, locked] {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn a_folder_owned_by_another_account_is_foreign() {
        assert!(windows_owner_trusted(ME, ME, ME));
        assert!(windows_owner_trusted("S-1-5-32-544", ME, ME));
        assert!(windows_owner_trusted("S-1-5-18", ME, ME));
        // TrustedInstaller, another user.
        assert!(!windows_owner_trusted(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            ME,
            ME
        ));
        assert!(!windows_owner_trusted("S-1-5-21-1-2-3-1002", ME, ME));
    }

    /// The OS names well-known accounts by alias in SDDL; every other SID keeps its `S-1-…` form.
    #[cfg(windows)]
    #[test]
    fn sddl_names_come_from_the_os() {
        let here = Path::new(".");
        assert_eq!(crate::secure_win32::sddl_name(SYSTEM_SID, here).unwrap(), "SY");
        assert_eq!(crate::secure_win32::sddl_name(ADMINISTRATORS_SID, here).unwrap(), "BA");
        assert_eq!(crate::secure_win32::sddl_name(ME, here).unwrap(), ME);
        let (user, _) = crate::secure_win32::token_sids(here).unwrap();
        let alias = crate::secure_win32::sddl_name(&user, here).unwrap();
        assert!(alias == user || alias.len() == 2, "{user} -> {alias}");
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("phantab-secure-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// SR-10, L1: an open folder is fixed. On Windows a file made inside afterwards inherits owner-only
    /// too; a Unix folder's mode does not pass to new files (the umask decides), so there the 0700
    /// folder is what keeps others out, and the files that matter are written 0600 themselves.
    #[test]
    fn an_open_folder_is_made_owner_only() {
        let dir = scratch("open");
        std::fs::create_dir_all(&dir).unwrap();
        open_up(&dir);
        let before = inspect(&dir).unwrap();
        assert!(before.owned_by_me, "{before:?}");
        assert!(!(before.owner_only && before.protected), "the fixture did not open the folder: {before:?}");
        lock_down(&dir).unwrap();
        let after = inspect(&dir).unwrap();
        assert!(after.owner_only && after.protected && after.labeled, "{after:?}");
        let file = dir.join("endpoint.json");
        std::fs::write(&file, b"{}").unwrap();
        #[cfg(windows)]
        assert!(inspect(&file).unwrap().owner_only);
        lock_down(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    fn open_up(dir: &Path) {
        let system32 = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
        let status = std::process::Command::new(system32.join("icacls.exe"))
            .arg(dir)
            .args(["/grant", "*S-1-1-0:(OI)(CI)RX"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(unix)]
    fn open_up(dir: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// R15, L1: a folder phantab creates is owner-only from the create call, even under a parent that
    /// hands every account access: read straight back, before any restrict could run, its DACL is exactly
    /// the user's and SYSTEM's entries, protected, with nothing inherited (macOS: mode 0700). A folder
    /// that already exists is left as it is, for `lock_down` to restrict and walk as before.
    #[test]
    fn a_new_folder_is_owner_only_from_the_create_call() {
        let parent = scratch("create");
        std::fs::create_dir_all(&parent).unwrap();
        open_up(&parent);
        let existing = parent.join("existing");
        std::fs::create_dir(&existing).unwrap();
        #[cfg(windows)]
        assert!(!inspect(&existing).unwrap().owner_only, "the fixture's parent is not open");
        let before = state(&existing);
        assert!(!create_owner_only(&existing).unwrap(), "an existing folder is not made again");
        assert_eq!(state(&existing), before, "an existing folder is left as it is");

        // A missing parent is made as create_dir_all makes it; the folder asked for is owner-only.
        let made = parent.join("runtime").join("bin");
        assert!(create_owner_only(&made).unwrap());
        #[cfg(windows)]
        {
            let (user, _) = crate::secure_win32::token_sids(&made).unwrap();
            let me = crate::secure_win32::sddl_name(&user, &made).unwrap();
            let dacl = state(&made);
            assert_eq!(dacl, format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)"), "exactly these entries");
            assert_eq!(dacl, windows_owner_only_sddl(&me), "the DACL a restrict writes, no more");
            assert!(!dacl.contains("ID"), "nothing inherited: {dacl}");
        }
        #[cfg(unix)]
        assert_eq!(state(&made), "700");
        let seen = inspect(&made).unwrap();
        assert!(seen.owned_by_me && seen.owner_only && seen.protected && seen.labeled, "{seen:?}");
        let made_state = state(&made);
        lock_down(&made).unwrap();
        assert_eq!(state(&made), made_state, "lock_down had nothing left to change");

        // lock_down on a missing folder creates it the same way.
        let runtime = parent.join("fresh");
        lock_down(&runtime).unwrap();
        assert_eq!(state(&runtime), made_state);
        std::fs::remove_dir_all(&parent).unwrap();
    }

    /// A folder's access as the OS reports it: its DACL in SDDL (Windows), its mode in octal (macOS).
    #[cfg(windows)]
    fn state(dir: &Path) -> String {
        crate::secure_win32::owner_and_dacl(dir).unwrap().1
    }

    #[cfg(unix)]
    fn state(dir: &Path) -> String {
        use std::os::unix::fs::PermissionsExt as _;
        format!("{:o}", std::fs::metadata(dir).unwrap().permissions().mode() & 0o7777)
    }

    /// SR-10, L1: a junction (Windows) or symlink (macOS) is refused, and its target is left alone.
    #[test]
    fn a_link_is_refused_and_its_target_untouched() {
        let target = scratch("target");
        std::fs::create_dir_all(&target).unwrap();
        open_up(&target);
        let link = scratch("link");
        make_link(&target, &link);
        assert!(matches!(lock_down(&link), Err(SecureDirError::Link(_))));
        assert!(matches!(inspect(&link), Err(SecureDirError::Link(_))));
        let untouched = inspect(&target).unwrap();
        assert!(!(untouched.owner_only && untouched.protected), "{untouched:?}");
        remove_link(&link);
        std::fs::remove_dir_all(&target).unwrap();
    }

    /// R15: a link left inside a folder while it was open is refused once the folder is restricted.
    #[test]
    fn a_link_inside_an_open_folder_is_refused() {
        let dir = scratch("inner");
        let target = scratch("inner-target");
        std::fs::create_dir_all(dir.join("logs")).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(dir.join("logs").join("a.log"), b"").unwrap();
        open_up(&dir);
        let inner = dir.join("logs").join("planted");
        make_link(&target, &inner);
        let Err(SecureDirError::Link(refused)) = lock_down(&dir) else { panic!("the link was accepted") };
        assert_eq!(refused, inner);
        remove_link(&inner);
        open_up(&dir);
        lock_down(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&target).unwrap();
    }

    /// R15, L1 (macOS): a hard link left inside a folder while it was open is refused once the folder is
    /// restricted, even though the file it names is this user's.
    #[cfg(unix)]
    #[test]
    fn a_hard_link_inside_an_open_folder_is_refused() {
        let dir = scratch("hardlink");
        let elsewhere = scratch("hardlink-target");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("profile"), b"the user's own file").unwrap();
        open_up(&dir);
        let planted = dir.join("service.lock");
        std::fs::hard_link(elsewhere.join("profile"), &planted).unwrap();
        let Err(SecureDirError::HardLink(refused)) = lock_down(&dir) else {
            panic!("the hard link was accepted")
        };
        assert_eq!(refused, planted);
        std::fs::remove_file(&planted).unwrap();
        open_up(&dir);
        lock_down(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&elsewhere).unwrap();
    }

    /// SR-12, L1: the lock file opens as a plain file only. A new or existing one opens (macOS: created
    /// `0600`); a link at its name, whether a symlink or hard link (macOS) or a junction (Windows), is
    /// refused and the file it points to keeps its bytes.
    #[test]
    fn the_lock_file_opens_only_as_a_plain_file() {
        let dir = scratch("lockfile");
        let elsewhere = scratch("lockfile-target");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let lock = dir.join("service.lock");
        drop(open_lock_file(&lock).unwrap());
        assert!(std::fs::symlink_metadata(&lock).unwrap().is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777, 0o600);
        }
        drop(open_lock_file(&lock).unwrap());

        let linked = dir.join("linked.lock");
        #[cfg(unix)]
        {
            let target = elsewhere.join("profile");
            std::fs::write(&target, b"keep").unwrap();
            make_link(&target, &linked);
            assert!(matches!(open_lock_file(&linked), Err(SecureDirError::Link(_))));
            std::fs::remove_file(&linked).unwrap();
            std::fs::hard_link(&target, &linked).unwrap();
            assert!(matches!(open_lock_file(&linked), Err(SecureDirError::HardLink(_))));
            std::fs::remove_file(&linked).unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        }
        #[cfg(windows)]
        {
            make_link(&elsewhere, &linked);
            assert!(open_lock_file(&linked).is_err(), "a junction opened as the lock file");
            remove_link(&linked);
        }
        let folder = dir.join("folder.lock");
        std::fs::create_dir_all(&folder).unwrap();
        assert!(open_lock_file(&folder).is_err(), "a folder opened as the lock file");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&elsewhere).unwrap();
    }

    #[cfg(windows)]
    fn make_link(target: &Path, link: &Path) {
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("cmd.exe");
        let status = std::process::Command::new(cmd)
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(unix)]
    fn make_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    fn remove_link(link: &Path) {
        // A junction is removed as a folder, a symlink as a file; neither touches the target.
        if std::fs::remove_dir(link).is_err() {
            std::fs::remove_file(link).unwrap();
        }
    }

    /// SR-10, L1: a folder another account owns is refused before anything is changed. Read-only: the
    /// OS folder is only inspected, and `lock_down` refuses it before writing (it could not anyway).
    #[test]
    fn a_foreign_owned_folder_is_refused() {
        #[cfg(windows)]
        let foreign = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("drivers");
        #[cfg(unix)]
        let foreign = PathBuf::from("/usr/bin");
        let seen = inspect(&foreign).unwrap();
        // TrustedInstaller owns it on every Windows install.
        #[cfg(windows)]
        assert!(!seen.owned_by_me, "{seen:?}");
        if seen.owned_by_me {
            // Running as the folder's owner (root on a macOS runner, say): nothing to show here.
            return;
        }
        let Err(SecureDirError::ForeignOwner { owner, .. }) = lock_down(&foreign) else {
            panic!("a foreign folder was accepted");
        };
        assert_eq!(owner, seen.owner);
    }
}
