//! A file held open so it stays the file that was read, and what identifies its content cheaply: for
//! the Bitwarden pin (THREAT-MODEL SR-64).
//!
//! [`HeldFile`] opens a file to read. On Windows it shares reading only, so while it is open no one can
//! open the file for writing, rename it or delete it; the loader's and Node's own opens, which read,
//! still succeed. It holds the file, not the path: a link or junction on the way can still be repointed,
//! so [`HeldFile::final_path`] gives the path with every link resolved, for a child to be started by.
//! A writable mapping someone made before the open is not stopped by it.
//!
//! On Windows a same-user writer can set a file's size-preserving content and every one of its times
//! back (`SetFileTime`), so metadata alone cannot say a file is unchanged. Its update sequence number
//! can: NTFS and `ReFS` move it on to a new value at every change to the file (data, size, times,
//! name) while the volume's change journal is active, and user-mode code cannot set it back. Turning
//! the journal off needs an administrator. The volume and the 128-bit file ID name the file itself, so
//! a replacement renamed into place has another identity.

use std::fs::File;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

/// A file open to read; on Windows shut against writes, renames and deletes until it is dropped.
#[derive(Debug)]
pub struct HeldFile {
    /// Opened for synchronous I/O, never `FILE_FLAG_OVERLAPPED`: [`HeldFile::change_stamp`] relies on it.
    file: File,
}

impl HeldFile {
    /// Opens `path` (a link followed) to read.
    ///
    /// # Errors
    /// The file cannot be opened; on Windows also when someone has it open for writing or deleting.
    pub fn open(path: &Path) -> std::io::Result<HeldFile> {
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt as _;
            /// `FILE_SHARE_READ`.
            const SHARE_READ: u32 = 0x1;
            // No custom flags: the handle is synchronous.
            std::fs::OpenOptions::new().read(true).share_mode(SHARE_READ).open(path)?
        };
        #[cfg(not(windows))]
        let file = File::open(path)?;
        Ok(HeldFile { file })
    }

    /// The open file, to read and to read metadata from.
    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// The file's `(volume serial, file ID, USN)` on Windows, or `None` where it cannot be read (a file
    /// system without file IDs or USNs, such as FAT or a network share) or where no change was ever
    /// journaled (a USN of 0, a volume with no active journal): then a caller must not trust a cached
    /// hash.
    #[cfg(windows)]
    #[must_use]
    pub fn change_stamp(&self) -> Option<(u64, u128, i64)> {
        // SAFETY: `HeldFile::open` opens every handle for synchronous I/O, as `change_stamp` requires,
        // and a handle's mode cannot change after it is opened.
        #[allow(unsafe_code)]
        let stamp = unsafe { crate::file_win32::change_stamp(&self.file) };
        stamp.filter(|(_, _, usn)| *usn != 0)
    }

    /// The path of the file this handle holds, with every link and junction resolved: while the handle
    /// is open no folder on it can be renamed or deleted, so it opens this same file. A plain drive or
    /// share path where that names the file unchanged, else the `\\?\` form. `None` when Windows cannot
    /// give one.
    #[cfg(windows)]
    #[must_use]
    pub fn final_path(&self) -> Option<PathBuf> {
        crate::file_win32::final_path(&self.file).map(|p| plain(&p))
    }
}

/// `\\?\C:\a\b` as `C:\a\b`, and `\\?\UNC\server\share\a` as `\\server\share\a`, when Windows would read
/// the plain form as the same path: no part ends in a dot or a space (which it drops) and it is short of
/// `MAX_PATH`. Anything else is kept as given.
#[cfg(windows)]
fn plain(verbatim: &Path) -> PathBuf {
    let Some(text) = verbatim.to_str() else { return verbatim.to_path_buf() };
    let plain = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\")
        && rest.as_bytes().get(1..3) == Some(b":\\")
        && rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
    {
        rest.to_owned()
    } else {
        return verbatim.to_path_buf();
    };
    let unchanged = plain.len() < 260 && plain.split('\\').all(|part| !part.ends_with(['.', ' ']));
    if unchanged { PathBuf::from(plain) } else { verbatim.to_path_buf() }
}

#[cfg(all(test, windows))]
mod tests {
    use std::io::Write as _;
    use std::os::windows::fs::FileTimesExt as _;

    use super::*;

    /// A folder of this test's own under the temp folder (no tempfile here: not a dependency of this
    /// crate), removed by the test.
    fn scratch(name: &str) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("phantab-file-identity-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn a_rewrite_with_its_times_put_back_moves_the_stamp() {
        let dir = scratch("usn").unwrap();
        let path = dir.join("bw.exe");
        std::fs::write(&path, b"one!").unwrap();
        let read = || HeldFile::open(&path).unwrap().change_stamp();
        let first = read().expect("the temp folder's volume keeps a change journal, as C: does");
        assert_eq!(read(), Some(first), "reading changes nothing");
        let times = std::fs::metadata(&path).unwrap();
        let (modified, created) = (times.modified().unwrap(), times.created().unwrap());
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all(b"two!").unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified).set_created(created)).unwrap();
        drop(file);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (after.len(), after.modified().unwrap(), after.created().unwrap()),
            (4, modified, created)
        );
        let second = read().unwrap();
        assert_eq!((second.0, second.1), (first.0, first.1), "the same file");
        std::fs::remove_dir_all(&dir).unwrap();
        assert_ne!(second.2, first.2, "a new USN");
    }

    #[test]
    fn a_held_file_names_its_path_past_a_junction_that_can_still_move() {
        let dir = scratch("junction").unwrap();
        let real = dir.join("real");
        std::fs::create_dir_all(real.join("bin")).unwrap();
        std::fs::write(real.join("bin").join("bw.exe"), b"MZ").unwrap();
        let link = dir.join("link");
        // A junction needs no privilege, unlike a symbolic link.
        let made = std::process::Command::new("cmd")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(&link)
            .arg(&real)
            .output()
            .unwrap();
        assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
        let held = HeldFile::open(&link.join("bin").join("bw.exe")).unwrap();
        let shown = held.final_path().unwrap();
        assert_eq!(shown, plain(&std::fs::canonicalize(real.join("bin").join("bw.exe")).unwrap()));
        assert!(!shown.to_string_lossy().starts_with(r"\\?\"), "{}", shown.display());
        assert!(!shown.to_string_lossy().contains("link"), "{}", shown.display());
        // No folder on its resolved path can move while it is held, its own or one above it; the junction
        // to them can.
        assert!(
            std::fs::rename(real.join("bin"), real.join("moved")).is_err(),
            "a held file's folder renamed"
        );
        assert!(std::fs::rename(&real, dir.join("moved")).is_err(), "a held file's grandparent renamed");
        std::fs::remove_dir(&link).unwrap();
        assert_eq!(std::fs::read(&shown).unwrap(), b"MZ", "the final path still opens it");
        drop(held);
        std::fs::rename(&real, dir.join("moved")).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_verbatim_path_is_made_plain_only_when_it_reads_the_same() {
        let p = |s: &str| plain(Path::new(s));
        assert_eq!(p(r"\\?\C:\Tools\bw.exe"), PathBuf::from(r"C:\Tools\bw.exe"));
        assert_eq!(p(r"\\?\UNC\server\share\bw.exe"), PathBuf::from(r"\\server\share\bw.exe"));
        for kept in [r"\\?\C:\Tools.\bw.exe", r"\\?\C:\Tools \bw.exe", r"\\?\Volume{x}\bw.exe"] {
            assert_eq!(p(kept), PathBuf::from(kept));
        }
        let long = format!(r"\\?\C:\{}\bw.exe", "a".repeat(300));
        assert_eq!(p(&long), PathBuf::from(&long));
    }
}
