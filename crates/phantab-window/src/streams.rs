//! Named NTFS data streams (THREAT-MODEL SR-74). On Windows a file or folder can hold more data streams
//! than the one a read sees (`background.js:x.html`), and Chrome serves such a stream at
//! `chrome-extension://<id>/background.js:x.html` with the extension's permissions; a folder listing
//! never shows it. phantab's check of the installed extension folder opens every file and folder it
//! walked, confirms with [`final_path`] that the handle is the one the walk named, and asks
//! [`named_streams`] for its streams, refusing any but the file's own, asks [`links`] how many names a
//! recorded file has, on Windows [`reparse_tag`] whether a provider serves it, and [`file_system`] what
//! the runtime folder is on. All work on the open handle, so nothing is looked up again by path. While it
//! runs, [`placeholders_pinned`] keeps the check's thread from having a placeholder hidden from it (and
//! on macOS fetched for it). The Windows OS calls live in `streams_win32`, the macOS ones in
//! `streams_mac`, and the ones macOS and Linux share in `streams_unix`.

use std::fs::File;

/// The named data streams of the open file or folder, as the OS names them (`:x.html:$DATA`). A file's
/// own unnamed stream (`::$DATA`) is not listed, so an ordinary file or folder gives none, and so does
/// any file on a file system without named streams (FAT, exFAT).
///
/// Off Windows this is always empty: macOS and Linux have no named data streams a path can reach (a
/// macOS resource fork has no page extension and extended attributes have no path), so there is nothing
/// to list.
///
/// # Errors
/// The OS error when the streams cannot be listed (on Windows, open the file with
/// `FILE_FLAG_BACKUP_SEMANTICS` to pass a folder).
pub fn named_streams(file: &File) -> std::io::Result<Vec<String>> {
    #[cfg(windows)]
    return crate::streams_win32::named_streams(file);
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(Vec::new())
    }
}

/// The path the OS holds for the open file or folder: every link resolved, in the `\\?\C:\...` form
/// (`std::fs::canonicalize` gives the same). A file opened through a path a link was swapped into gives
/// the link's target here, not the path it was opened by. On a volume the Mount Manager names no drive
/// for (an `ImDisk` RAM disk), where `canonicalize` fails, it is the NT device path in a form Win32 opens
/// (`\\?\GLOBALROOT\Device\ImDisk0\...`), so a folder there walks and compares the same way.
///
/// # Errors
/// The OS error when the path cannot be had in either form, saying so.
#[cfg(windows)]
pub fn final_path(file: &File) -> std::io::Result<std::path::PathBuf> {
    crate::streams_win32::final_path(file)
}

/// The reparse tag of the open file or folder when it is a reparse point (`FILE_ATTRIBUTE_REPARSE_POINT`
/// and `ReparseTag` from `GetFileInformationByHandleEx(FileAttributeTagInfo)`), `None` when it is not.
/// Open it with `FILE_FLAG_OPEN_REPARSE_POINT`, so the tag is its own and no filter (a cloud provider)
/// is asked for its bytes.
///
/// # Errors
/// The OS error when the file's information cannot be read.
#[cfg(windows)]
pub fn reparse_tag(file: &File) -> std::io::Result<Option<u32>> {
    crate::streams_win32::reparse_tag(file)
}

/// The file system an open file or folder is on, as the OS names it ([`file_system`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSystem {
    /// Its type. macOS: `f_fstypename` from `fstatfs` (`apfs`, `hfs`, `smbfs`, `macfuse_<name>`), the name
    /// the kext or `FSKit` module that mounted it gives: macFUSE's kext prefixes `macfuse_`, but an `FSKit`
    /// module may call itself `apfs`, so on its own it does not prove a kext's ([`FileSystem::fskit`]
    /// does, review r9 R9-2). Linux: `fuse` or `overlay` for `fstatfs`'s `f_type` of `FUSE_SUPER_MAGIC` or
    /// `OVERLAYFS_SUPER_MAGIC`, else that `f_type` in hex. Windows: the file system name
    /// `GetVolumeInformationByHandleW` gives (`NTFS`, `ReFS`, `FAT32`), which a user-mode file system
    /// (`WinFsp`, `Dokan`) chooses itself, so on its own it proves nothing. Elsewhere empty.
    pub name: String,
    /// Windows: the NT device the handle's volume is, from `GetFinalPathNameByHandleW(VOLUME_NAME_NT)`
    /// (`\Device\HarddiskVolume5` for a partition of a local disk, `\Device\Mup` for a network share,
    /// `\Device\Volume{GUID}` for a `WinFsp` or `Dokan` volume). The kernel driver that made the device named
    /// it, so a user-mode file system cannot choose it. Elsewhere empty.
    pub device: String,
    /// macOS: an `FSKit` mount, whatever it calls itself (`MNT_EXT_FSKIT` in `fstatfs`'s `f_flags_ext`,
    /// which the kernel sets for every `FSKit` mount, from macOS 15.4, review r9 R9-2). Elsewhere false.
    pub fskit: bool,
}

/// The file system the open file or folder is on ([`FileSystem`]), from its own handle, so nothing is
/// looked up again by path.
///
/// # Errors
/// The OS error when the handle's file system cannot be read.
pub fn file_system(file: &File) -> std::io::Result<FileSystem> {
    #[cfg(windows)]
    {
        let (name, device) = crate::streams_win32::file_system(file)?;
        Ok(FileSystem { name, device, fskit: false })
    }
    #[cfg(unix)]
    {
        let (name, fskit) = crate::streams_unix::file_system(file)?;
        Ok(FileSystem { name, device: String::new(), fskit })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(FileSystem { name: String::new(), device: String::new(), fskit: false })
    }
}

/// While held, this thread sees every cloud placeholder as one, and on macOS has none fetched. On Windows
/// its placeholder compatibility mode is exposed (`RtlSetThreadPlaceholderCompatibilityMode(
/// PHCM_EXPOSE_PLACEHOLDERS)`, looked up in ntdll, which has it from Windows 10 1709), so Windows cannot
/// disguise a cloud placeholder as a plain file for it, as it may for some programs; that is all it does
/// there: a placeholder is still fetched when it is opened normally, so a caller that must not have one
/// fetched opens each file as itself (`FILE_FLAG_OPEN_REPARSE_POINT`) and refuses a placeholder before it
/// reads a byte, as phantab's check does. On macOS
/// its dataless-file policy is off (`setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
/// IOPOL_SCOPE_THREAD, IOPOL_MATERIALIZE_DATALESS_FILES_OFF)`), so no File Provider is asked to fetch a
/// file or folder this thread opens or reads. Dropping it puts back what the thread had. Both are this
/// thread's alone, so it is neither `Send` nor `Sync`: hold it across work that stays on one thread.
/// Elsewhere it does nothing.
#[derive(Debug)]
#[must_use = "the pin lasts only while it is held"]
pub struct PlaceholdersPinned {
    #[cfg(windows)]
    previous: i8,
    #[cfg(target_os = "macos")]
    previous: std::ffi::c_int,
    _thread: std::marker::PhantomData<*const ()>,
}

/// Pins this thread's placeholder handling ([`PlaceholdersPinned`]) until the guard is dropped.
///
/// # Errors
/// The OS error when the mode or policy cannot be set (neither call fails for these values on Windows
/// 10 1709 or macOS 10.15 and later), and on a Windows before 1709, which has no such call, an error
/// that says so (`Unsupported`): looked up when first needed, not imported, so this call no longer stops
/// phantab starting there, and only what needs the pin is refused.
pub fn placeholders_pinned() -> std::io::Result<PlaceholdersPinned> {
    Ok(PlaceholdersPinned {
        #[cfg(windows)]
        previous: crate::streams_win32::expose_placeholders()?,
        #[cfg(target_os = "macos")]
        previous: crate::streams_mac::no_materializing()?,
        _thread: std::marker::PhantomData,
    })
}

impl Drop for PlaceholdersPinned {
    fn drop(&mut self) {
        #[cfg(windows)]
        crate::streams_win32::restore_placeholders(self.previous);
        #[cfg(target_os = "macos")]
        crate::streams_mac::restore_materializing(self.previous);
    }
}

/// Test builds only (the `test-seams` feature, which no release build turns on): put a reparse tag with
/// no data on a file or folder, or take it off, as any user can on NTFS, so a test can make what a cloud
/// or projected-file provider leaves behind.
#[cfg(all(windows, feature = "test-seams"))]
pub mod test_seams {
    use std::path::Path;

    /// `FSCTL_SET_REPARSE_POINT` with `tag` and no data.
    ///
    /// # Errors
    /// The OS error (a folder that holds files takes only some tags).
    pub fn set_reparse_tag(path: &Path, tag: u32) -> std::io::Result<()> {
        crate::streams_win32::seams::set_reparse_tag(path, tag)
    }

    /// `FSCTL_DELETE_REPARSE_POINT` for `tag`.
    ///
    /// # Errors
    /// The OS error.
    pub fn delete_reparse_tag(path: &Path, tag: u32) -> std::io::Result<()> {
        crate::streams_win32::seams::delete_reparse_tag(path, tag)
    }
}

/// How many names (hard links) the open file has: `nNumberOfLinks` from `GetFileInformationByHandle` on
/// Windows, `st_nlink` from `fstat` on Unix. A file install wrote has one.
///
/// # Errors
/// The OS error when the file's information cannot be read.
pub fn links(file: &File) -> std::io::Result<u64> {
    #[cfg(windows)]
    return crate::streams_win32::links(file);
    #[cfg(unix)]
    return Ok(std::os::unix::fs::MetadataExt::nlink(&file.metadata()?));
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(path: &std::path::Path) -> File {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        }
        options.open(path).unwrap()
    }

    #[test]
    fn a_plain_file_and_folder_have_no_named_stream() {
        let dir = std::env::temp_dir().join(format!("phantab-streams-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.js");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(named_streams(&open(&file)).unwrap(), Vec::<String>::new());
        assert_eq!(named_streams(&open(&dir)).unwrap(), Vec::<String>::new());
        assert_eq!(links(&open(&file)).unwrap(), 1);
        std::fs::hard_link(&file, dir.join("b.js")).unwrap();
        assert_eq!(links(&open(&file)).unwrap(), 2, "a second name");
        std::fs::remove_file(dir.join("b.js")).unwrap();
        #[cfg(windows)]
        {
            std::fs::write(dir.join("a.js:x.html"), b"<p>").unwrap();
            let mut on_dir = dir.clone().into_os_string();
            on_dir.push(":y.html");
            std::fs::write(&on_dir, b"<p>").unwrap();
            assert_eq!(named_streams(&open(&file)).unwrap(), vec![":x.html:$DATA".to_owned()]);
            assert_eq!(named_streams(&open(&dir)).unwrap(), vec![":y.html:$DATA".to_owned()]);
            assert_eq!(std::fs::read(&file).unwrap(), b"x");
            assert_eq!(final_path(&open(&file)).unwrap(), std::fs::canonicalize(&file).unwrap());
            assert_eq!(final_path(&open(&dir)).unwrap(), std::fs::canonicalize(&dir).unwrap());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
