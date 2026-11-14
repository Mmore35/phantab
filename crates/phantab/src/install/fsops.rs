//! File operations the installer shares: path resolution, atomic writes, copies, permissions.

use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use phantab_window::secure_dir;
use sha2::Digest as _;

/// Suffix of the temporary file an atomic write renames into place.
const TEMP_SUFFIX: &str = ".phantab.tmp";

/// Python's `Path.resolve()` (non-strict): the longest existing ancestor with links resolved, then the rest
/// of the path as given. Unlike `fs::canonicalize` it accepts a path that does not exist yet, and on Windows
/// it gives `C:\…`, not `\\?\C:\…`, so recovery-record keys stay the paths a person types.
pub(crate) fn resolve(path: &Path) -> PathBuf {
    let absolute = normalize(&std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()));
    let mut existing = absolute.as_path();
    let mut tail = Vec::new();
    loop {
        if let Ok(real) = fs::canonicalize(existing) {
            let mut out = simplify(real);
            out.extend(tail.iter().rev());
            return out;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_owned());
                existing = parent;
            }
            _ => return absolute,
        }
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `\\?\C:\x` → `C:\x` and `\\?\UNC\host\share` → `\\host\share`; anything else unchanged.
fn simplify(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else { return path };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\")
        && rest.as_bytes().get(1) == Some(&b':')
    {
        return PathBuf::from(rest);
    }
    path
}

/// Whether two resolved paths name the same file, as the OS compares them (case-insensitively on Windows).
pub(crate) fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.as_os_str().to_string_lossy().to_lowercase() == b.as_os_str().to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

/// Writes `data` to `path` atomically: refuses when `expected` is given and the file no longer holds it; does nothing when
/// the file already holds `data`; otherwise writes a sibling temp file and renames it over the target.
/// SR-50: a file that exists keeps its mode and owner (macOS) or explicit DACL (Windows); the temp file is
/// created `0600` on macOS, so its bytes are never readable by others on the way.
pub(crate) fn atomic(path: &Path, data: &[u8], expected: Option<&[u8]>) -> Result<()> {
    let current = match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("Could not read {}", path.display())),
    };
    if let Some(expected) = expected
        && current.as_deref() != Some(expected)
    {
        bail!("Configuration changed concurrently: {}", path.display());
    }
    if current.as_deref() == Some(data) {
        return Ok(());
    }
    let security = match current {
        Some(_) => Some(
            secure_dir::file_security(path).with_context(|| format!("Could not read {}", path.display()))?,
        ),
        None => None,
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;
    }
    let temp = sibling(path, TEMP_SUFFIX);
    write_private(&temp, data).with_context(|| format!("Could not write {}", temp.display()))?;
    if let Some(security) = &security
        && let Err(e) = secure_dir::apply_file_security(&temp, security)
    {
        let _ = fs::remove_file(&temp);
        return Err(e).with_context(|| format!("Could not keep the access rules of {}", path.display()));
    }
    fs::rename(&temp, path).with_context(|| format!("Could not replace {}", path.display()))
}

/// A fresh file holding `data`, mode `0600` on unix (Windows: the folder's inherited DACL).
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let _ = fs::remove_file(path);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(suffix);
    path.with_file_name(name)
}

/// SR-51: replaces `dst` with a copy of `src`, whole. The copy is made in a sibling folder, the old folder
/// is renamed aside, the copy renamed in, and the old one removed, so no file of an earlier version stays.
pub(crate) fn replace_tree(src: &Path, dst: &Path) -> Result<()> {
    let fresh = sibling(dst, ".phantab-new");
    let old = sibling(dst, ".phantab-old");
    for leftover in [&fresh, &old] {
        remove_tree(leftover)?;
    }
    copy_tree(src, &fresh)?;
    let had_old = match fs::symlink_metadata(dst) {
        Ok(_) => {
            fs::rename(dst, &old).with_context(|| format!("Could not move {} aside", dst.display()))?;
            true
        }
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(e) => return Err(e).with_context(|| format!("Could not read {}", dst.display())),
    };
    if let Err(e) = fs::rename(&fresh, dst) {
        if had_old {
            let _ = fs::rename(&old, dst);
        }
        return Err(e).with_context(|| format!("Could not replace {}", dst.display()));
    }
    // A file Chrome still holds open can block this on Windows; the next install removes it.
    let _ = remove_tree(&old);
    Ok(())
}

/// Removes `path` whether it is a folder, a file or a link (a link itself, never its target).
fn remove_tree(path: &Path) -> Result<()> {
    let result = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => Err(e),
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => fs::remove_dir_all(path),
        Ok(meta) if meta.is_dir() => fs::remove_dir(path),
        Ok(_) => fs::remove_file(path),
    };
    result.with_context(|| format!("Could not remove {}", path.display()))
}

/// `shutil.copytree(src, dst, dirs_exist_ok=True)`: copies every file over, keeps files only `dst` has.
/// Only plain files and folders: a symlink or junction inside `src` is refused, not followed, so the copy
/// never takes in a file from outside the folder named (a link to `~/.ssh`, say).
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("Could not create {}", dst.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("Could not read {}", src.display()))? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // The entry's own type as listed: a link reads as a link here (a junction too), never as its target.
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&from, &to)?;
        } else if kind.is_file() {
            let data = fs::read(&from).with_context(|| format!("Could not read {}", from.display()))?;
            atomic(&to, &data, None)?;
        } else {
            bail!(
                "{} is a link or not a plain file; phantab copies only plain files and folders",
                from.display()
            );
        }
    }
    Ok(())
}

/// Puts `data`, the running binary `src` as read once by the caller, at `dest`: the bytes the install
/// hashed for its record are the bytes installed, even if `src` changes meanwhile (SR-53). Windows refuses to replace an executable that is running (the service
/// or an MCP server started from `dest`), but lets it be renamed, so a busy `dest` is moved aside first; the
/// moved copies are deleted on a later install, once nothing runs them.
pub(crate) fn install_binary(src: &Path, data: &[u8], dest: &Path) -> Result<()> {
    if same_path(&resolve(src), &resolve(dest)) {
        return Ok(());
    }
    let dir = dest.parent().context("binary destination has no folder")?;
    fs::create_dir_all(dir).with_context(|| format!("Could not create {}", dir.display()))?;
    remove_moved_aside(dest);
    if fs::read(dest).is_ok_and(|current| current == data) {
        return Ok(());
    }
    let temp = sibling(dest, TEMP_SUFFIX);
    fs::write(&temp, data).with_context(|| format!("Could not write {}", temp.display()))?;
    // SR-54: the copy must be the bytes read, by size and SHA-256, before it replaces anything.
    let written = fs::read(&temp).unwrap_or_default();
    if written.len() != data.len() || sha2::Sha256::digest(&written) != sha2::Sha256::digest(data) {
        let _ = fs::remove_file(&temp);
        bail!("The new binary at {} did not verify (size or SHA-256)", temp.display());
    }
    set_executable(&temp)?;
    if fs::rename(&temp, dest).is_err() && dest.exists() {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let aside = sibling(dest, &format!(".old-{}-{nanos}", std::process::id()));
        fs::rename(dest, &aside).with_context(|| format!("Could not move {} aside", dest.display()))?;
        if let Err(e) = fs::rename(&temp, dest) {
            let _ = fs::rename(&aside, dest);
            return Err(e).with_context(|| format!("Could not replace {}", dest.display()));
        }
    }
    Ok(())
}

fn remove_moved_aside(dest: &Path) {
    let (Some(dir), Some(name)) = (dest.parent(), dest.file_name().and_then(|n| n.to_str())) else { return };
    let prefix = format!("{name}.old-");
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if entry.file_name().to_str().is_some_and(|n| n.starts_with(&prefix)) {
            // Still running: it stays until the next install.
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("Could not mark {} executable", path.display()))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Locks the runtime to the current user (SR-10, SR-48): a protected DACL for the user's SID and SYSTEM
/// (Windows) or mode 700 (macOS), given in the create call when the folder is new (R15), refusing a link
/// or a foreign owner, and checked after. The same check
/// runs at every service start. Install and service start lock the binary's folder (`<runtime>/bin`) too.
pub(crate) fn lock_down(runtime: &Path) -> Result<()> {
    secure_dir::lock_down(runtime)
        .with_context(|| format!("Could not restrict {} to this user", runtime.display()))
}

/// A tool from System32, by full path, so a same-named program earlier on PATH is never run.
#[cfg(all(windows, test))]
fn system32(tool: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join("System32")
        .join(tool)
}

/// The current user's SID (`whoami /user /fo csv /nh` → `"name","S-1-5-…"`).
#[cfg(all(windows, test))]
pub(crate) fn current_user_sid() -> Result<String> {
    let output = std::process::Command::new(system32("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .context("Could not run whoami")?;
    if !output.status.success() {
        bail!("whoami could not name the current user");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let sid = text.trim().rsplit(',').next().unwrap_or_default().trim_matches('"');
    if !sid.starts_with("S-") {
        bail!("whoami did not give a SID");
    }
    Ok(sid.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_accepts_missing_tails_and_collapses_dots() {
        let dir = tempfile::tempdir().unwrap();
        let real = resolve(dir.path());
        let missing = resolve(&dir.path().join("a").join("..").join("b").join("c"));
        assert_eq!(missing, real.join("b").join("c"));
        assert!(!real.to_string_lossy().starts_with(r"\\?\"));
    }

    #[test]
    fn atomic_refuses_a_concurrent_change_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config");
        fs::write(&p, b"newer").unwrap();
        let err = atomic(&p, b"ours", Some(b"old")).unwrap_err();
        assert!(err.to_string().contains("concurrently"), "{err}");
        assert_eq!(fs::read(&p).unwrap(), b"newer");
        atomic(&p, b"ours", Some(b"newer")).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"ours");
        assert!(!sibling(&p, TEMP_SUFFIX).exists());
    }

    #[test]
    fn install_binary_copies_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        fs::write(&src, b"one").unwrap();
        let dest = dir.path().join("bin").join("phantab");
        install_binary(&src, b"one", &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"one");
        fs::write(&src, b"two").unwrap();
        install_binary(&src, b"two", &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"two");
        install_binary(&dest, b"two", &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"two");
    }

    /// SR-53, SR-54: what lands in `bin` is the bytes the install read and hashed for its record, not
    /// whatever the source holds by the time of the copy.
    #[test]
    fn install_binary_copies_the_bytes_read_not_the_source_now() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        fs::write(&src, b"swapped in after the read").unwrap();
        let dest = dir.path().join("bin").join("phantab");
        install_binary(&src, b"read and hashed", &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"read and hashed");
    }

    /// A link inside the extension source (a symlink; on Windows a junction, which needs no privilege) is
    /// refused, not followed, and the installed folder is left as it was.
    #[test]
    fn replace_tree_refuses_a_link_inside_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let (src, dst, outside) =
            (dir.path().join("dist"), dir.path().join("extension"), dir.path().join("outside"));
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(src.join("manifest.json"), b"{}").unwrap();
        fs::write(outside.join("secret"), b"not for the copy").unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(dst.join("manifest.json"), b"installed").unwrap();
        let link = src.join("linked");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.join("secret"), &link).unwrap();
        #[cfg(windows)]
        {
            let status = std::process::Command::new(system32("cmd.exe"))
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&outside)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success());
        }
        let err = replace_tree(&src, &dst).unwrap_err();
        assert!(format!("{err:#}").contains("is a link"), "{err:#}");
        assert_eq!(
            fs::read(dst.join("manifest.json")).unwrap(),
            b"installed",
            "the installed folder is untouched"
        );
        assert!(!dst.join("linked").exists());
        // Remove the junction itself before the temp dir goes, so its cleanup never walks through it.
        #[cfg(windows)]
        fs::remove_dir(&link).unwrap();
    }

    /// SR-50, L1: a rewrite keeps the file's own access rules (a `0600` config stays `0600`; on Windows
    /// a protected owner-only DACL stays).
    #[test]
    fn atomic_keeps_the_files_access_rules() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.json");
        fs::write(&p, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        {
            let sid = current_user_sid().unwrap();
            let status = std::process::Command::new(system32("icacls.exe"))
                .arg(&p)
                .args(["/inheritance:r", "/grant:r"])
                .arg(format!("*{sid}:F"))
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success());
            assert!(secure_dir::inspect(&p).unwrap().protected);
        }
        let before = secure_dir::file_security(&p).unwrap();
        #[cfg(windows)]
        let inspected = secure_dir::inspect(&p).unwrap();
        atomic(&p, b"new", Some(b"old")).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new");
        assert_eq!(secure_dir::file_security(&p).unwrap(), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // The same owner and access as before, not an absolute "owner only": on an elevated CI runner the
        // file is owned by Administrators and the fixture's DACL does not read as owner-only.
        #[cfg(windows)]
        assert_eq!(secure_dir::inspect(&p).unwrap(), inspected);
    }

    /// SR-51, L1: a file only the old extension folder had is gone after install.
    #[test]
    fn replace_tree_leaves_no_stale_file() {
        let dir = tempfile::tempdir().unwrap();
        let (src, dst) = (dir.path().join("dist"), dir.path().join("extension"));
        fs::create_dir_all(src.join("icons")).unwrap();
        fs::write(src.join("manifest.json"), b"{}").unwrap();
        fs::write(src.join("icons").join("a.png"), b"png").unwrap();
        fs::create_dir_all(dst.join("old")).unwrap();
        fs::write(dst.join("stale.js"), b"old code").unwrap();
        fs::write(dst.join("old").join("x.js"), b"old code").unwrap();
        replace_tree(&src, &dst).unwrap();
        assert!(!dst.join("stale.js").exists() && !dst.join("old").exists());
        assert_eq!(fs::read(dst.join("icons").join("a.png")).unwrap(), b"png");
        let mut names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["dist", "extension"], "no new or old folder left beside it");
        // Again, over itself: still whole.
        replace_tree(&src, &dst).unwrap();
        assert_eq!(fs::read(dst.join("manifest.json")).unwrap(), b"{}");
    }
}
