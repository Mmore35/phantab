//! Windows OS calls for [`crate::streams`], on a handle the caller already opened, so nothing is looked
//! up again by path (no late link is followed, and no `MAX_PATH` applies): the named NTFS data streams
//! of a file or folder (`GetFileInformationByHandleEx(FileStreamInfo)`), the path the OS holds for the
//! handle (`GetFinalPathNameByHandleW`), the file's hard link count (`GetFileInformationByHandle`), and
//! its reparse tag (`GetFileInformationByHandleEx(FileAttributeTagInfo)`), and the file system and
//! device of its volume (`GetVolumeInformationByHandleW`, `GetFinalPathNameByHandleW(VOLUME_NAME_NT)`);
//! and this thread's placeholder compatibility mode (`RtlSetThreadPlaceholderCompatibilityMode`, looked
//! up in ntdll).
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::PathBuf;
use std::sync::OnceLock;

use windows::Win32::Foundation::{ERROR_BAD_LENGTH, ERROR_HANDLE_EOF, ERROR_MORE_DATA, HANDLE};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_NAME_NORMALIZED,
    FileAttributeTagInfo, FileStreamInfo, GETFINALPATHNAMEBYHANDLE_FLAGS, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, VOLUME_NAME_DOS,
    VOLUME_NAME_NT,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::core::{HRESULT, s, w};

/// `GetVolumeInformationByHandleW`'s flag for a file system with named streams (winnt.h; the windows
/// crate has it under `Win32_System_SystemServices`, which nothing else here needs).
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;

/// The largest stream list read, in 8-byte words (4 MiB): about 16,000 streams of the longest name. A
/// file with more is an error, so the check refuses it.
const MAX_WORDS: usize = 1 << 19;

/// The first stream list buffer, in 8-byte words (8 KiB): an honest file's list (`::$DATA` alone, or a
/// download's `Zone.Identifier`) fits many times over.
const FIRST_WORDS: usize = 1024;

/// Where a `FILE_STREAM_INFO` entry's name starts: after `NextEntryOffset` and `StreamNameLength` (two
/// `u32`), then `StreamSize` and `StreamAllocationSize` (two `i64`).
const NAME_AT: usize = 24;

/// The prefix that makes an NT device path (`\Device\HarddiskVolume3\...`) one a Win32 call opens.
const GLOBALROOT: &str = r"\\?\GLOBALROOT";

fn is(e: &windows::core::Error, code: windows::Win32::Foundation::WIN32_ERROR) -> bool {
    e.code() == HRESULT::from_win32(code.0)
}

pub(crate) fn named_streams(file: &File) -> std::io::Result<Vec<String>> {
    named_streams_from(file, FIRST_WORDS)
}

/// [`named_streams`], with the first buffer's size as `first_words`, so a test can make it grow.
fn named_streams_from(file: &File, first_words: usize) -> std::io::Result<Vec<String>> {
    let handle = HANDLE(file.as_raw_handle());
    let mut flags = 0u32;
    // SAFETY: `handle` is `file`'s, open for the whole call; `flags` is a u32 that outlives it; the
    // buffers not asked for are None.
    unsafe { GetVolumeInformationByHandleW(handle, None, None, None, Some(&raw mut flags), None) }?;
    // Only a file system that has no named streams at all clears this flag (FAT and exFAT, for two), so
    // nothing there can hold one. NTFS and ReFS set it, so they always take the query below, where every
    // error is an error, never "none": an unsupported query is never read as an empty list.
    if flags & FILE_NAMED_STREAMS == 0 {
        return Ok(Vec::new());
    }
    // u64 words: the entries hold i64s, and the call wants its buffer 8-byte aligned.
    let mut words = vec![0u64; first_words.max(1)];
    loop {
        let bytes = u32::try_from(words.len() * 8).unwrap_or(u32::MAX);
        // SAFETY: `words` is writable for `bytes` bytes, 8-byte aligned, and outlives the call;
        // FileStreamInfo writes FILE_STREAM_INFO entries into it and nothing past `bytes`.
        match unsafe {
            GetFileInformationByHandleEx(handle, FileStreamInfo, words.as_mut_ptr().cast(), bytes)
        } {
            Ok(()) => break,
            // A folder with no stream at all.
            Err(e) if is(&e, ERROR_HANDLE_EOF) => return Ok(Vec::new()),
            // NTFS answers a buffer too small for the whole list with ERROR_MORE_DATA (an entry may be
            // half written, so the buffer is thrown away), and one too small for a single entry with
            // ERROR_BAD_LENGTH (24), not ERROR_INSUFFICIENT_BUFFER (probed on Windows 11). Only a test's
            // one-word first buffer meets that: one entry is at most about 546 bytes, far under 8 KiB.
            Err(e) if (is(&e, ERROR_MORE_DATA) || is(&e, ERROR_BAD_LENGTH)) && words.len() < MAX_WORDS => {
                words = vec![0u64; words.len() * 2];
            }
            Err(e) => return Err(e.into()),
        }
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    entries(&bytes)
}

/// The names in a `FileStreamInfo` buffer but the file's own `::$DATA`. The buffer starts zeroed, so a
/// call that wrote no entry reads as one with an empty name: none. Every offset is bounds-checked, so a
/// malformed buffer is an error, never a read past it.
fn entries(bytes: &[u8]) -> std::io::Result<Vec<String>> {
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "a malformed stream list");
    let u32_at = |at: usize| -> std::io::Result<usize> {
        let word: [u8; 4] = bytes.get(at..at + 4).and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
        usize::try_from(u32::from_ne_bytes(word)).map_err(|_| bad())
    };
    let mut found = Vec::new();
    let mut at = 0usize;
    loop {
        let next = u32_at(at)?;
        let len = u32_at(at + 4)?;
        if len == 0 {
            return Ok(found);
        }
        let start = at + NAME_AT;
        let name = bytes.get(start..start + len).ok_or_else(bad)?;
        let units: Vec<u16> = name.as_chunks::<2>().0.iter().map(|pair| u16::from_ne_bytes(*pair)).collect();
        let stream = String::from_utf16_lossy(&units);
        if stream != "::$DATA" {
            found.push(stream);
        }
        if next == 0 {
            return Ok(found);
        }
        at += next;
    }
}

/// The handle's path in the DOS form (`\\?\C:\...`), or, on a volume the Mount Manager gives no DOS
/// name for the handle (an `ImDisk` RAM disk; rust-lang/rust#59117), its NT device path made one a Win32
/// call opens (`\\?\GLOBALROOT\Device\ImDisk0\...`). A path from here walks and reads like any other, so
/// a walk rooted at one and a handle opened below it give the same form, on such a volume and on any
/// other.
pub(crate) fn final_path(file: &File) -> std::io::Result<PathBuf> {
    let handle = HANDLE(file.as_raw_handle());
    either(path_of(handle, VOLUME_NAME_DOS), || path_of(handle, VOLUME_NAME_NT))
}

/// The DOS form if there is one, else the NT form under [`GLOBALROOT`]; with neither, an error that says
/// why, since it refuses an install the owner meant.
fn either(
    dos: std::io::Result<Vec<u16>>,
    nt: impl FnOnce() -> std::io::Result<Vec<u16>>,
) -> std::io::Result<PathBuf> {
    let dos = match dos {
        Ok(units) => return Ok(PathBuf::from(OsString::from_wide(&units))),
        Err(e) => e,
    };
    match nt() {
        Ok(units) if units.first() == Some(&u16::from(b'\\')) => {
            let mut path = OsString::from(GLOBALROOT);
            path.push(OsString::from_wide(&units));
            Ok(PathBuf::from(path))
        }
        Ok(_) => Err(no_path(&dos, "not a device path")),
        Err(nt) => Err(no_path(&dos, &nt.to_string())),
    }
}

fn no_path(dos: &std::io::Error, nt: &str) -> std::io::Error {
    std::io::Error::new(
        dos.kind(),
        format!(
            "its volume gives no path for an open file (DOS form: {dos}; NT form: {nt}), so it cannot be \
             checked; put it in a folder on an NTFS drive"
        ),
    )
}

fn path_of(handle: HANDLE, volume: GETFINALPATHNAMEBYHANDLE_FLAGS) -> std::io::Result<Vec<u16>> {
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | volume.0);
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `handle` is open for the whole call (the caller's `file`); the call writes at most
        // `buf.len()` units into `buf`, which outlives it.
        let n = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, flags) };
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        if n == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Success gives the length without the NUL; a buffer too small gives the size it needs, NUL
        // included, so always more than `buf.len()`.
        if n < buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        if n > 1 << 16 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "a path over 64K units"));
        }
        buf = vec![0u16; n];
    }
}

pub(crate) fn links(file: &File) -> std::io::Result<u64> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is `file`'s, open for the whole call; `info` is a BY_HANDLE_FILE_INFORMATION
    // that outlives it, and the call writes only that struct.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut info) }?;
    Ok(u64::from(info.nNumberOfLinks))
}

pub(crate) fn reparse_tag(file: &File) -> std::io::Result<Option<u32>> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    let size = u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).map_err(std::io::Error::other)?;
    // SAFETY: the handle is `file`'s, open for the whole call; `info` is a FILE_ATTRIBUTE_TAG_INFO that
    // outlives it, `size` is its size, and FileAttributeTagInfo writes only that struct.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            size,
        )
    }?;
    Ok((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0).then_some(info.ReparseTag))
}

/// ntifs.h's `PHCM_EXPOSE_PLACEHOLDERS` (the windows crate does not have the `PHCM_*` values).
const PHCM_EXPOSE_PLACEHOLDERS: i8 = 2;

/// ntifs.h's `CHAR NTAPI RtlSetThreadPlaceholderCompatibilityMode(CHAR Mode)`.
type SetMode = unsafe extern "system" fn(i8) -> i8;

/// `RtlSetThreadPlaceholderCompatibilityMode`, looked up in ntdll the first time it is needed rather
/// than imported (review r8 R8-7). Windows 10 before 1709 has no such export, and an import of it would
/// stop phantab starting there at all; looked up, only what needs the pin fails, saying why.
fn set_mode() -> std::io::Result<SetMode> {
    static FOUND: OnceLock<Option<SetMode>> = OnceLock::new();
    let found = *FOUND.get_or_init(|| {
        #[cfg(test)]
        LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: the name is a NUL-terminated wide literal; ntdll is in every process from its start
        // and is never unloaded, so the handle, which this does not count, stays good.
        let ntdll = unsafe { GetModuleHandleW(w!("ntdll.dll")) }.ok()?;
        // SAFETY: `ntdll` is a loaded module's handle and the name a NUL-terminated literal.
        let found = unsafe { GetProcAddress(ntdll, s!("RtlSetThreadPlaceholderCompatibilityMode")) }?;
        // SAFETY: the export of that name has ntifs.h's prototype, `SetMode`'s, in the system ABI; ntdll
        // is never unloaded, so the pointer stays good.
        Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, SetMode>(found) })
    });
    supported(found)
}

/// How many times [`set_mode`] has looked the call up in this test process (review r9 R9-4).
#[cfg(test)]
static LOOKUPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The call [`set_mode`] found, or an `Unsupported` error saying this Windows has none. The version it
/// came in is named once, by the caller's message (phantab's `UNPINNED`, review r9 R9-5).
fn supported(found: Option<SetMode>) -> std::io::Result<SetMode> {
    found.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this Windows has no RtlSetThreadPlaceholderCompatibilityMode",
        )
    })
}

/// Sets this thread's placeholder compatibility mode to exposed, so a placeholder's reparse attribute
/// and tag show in listings and on handles, and gives the mode it had (0, the application's default, or
/// 1 or 2). A negative return is the call's error: an invalid mode or no thread block, neither of which a
/// running thread passing 2 meets. On a Windows before 1709, which has no such call, an `Unsupported`
/// error says so.
pub(crate) fn expose_placeholders() -> std::io::Result<i8> {
    let set = set_mode()?;
    // SAFETY: the call takes a mode by value and writes only this thread's own block; no memory of ours.
    let previous = unsafe { set(PHCM_EXPOSE_PLACEHOLDERS) };
    if previous < 0 {
        return Err(std::io::Error::other(format!(
            "RtlSetThreadPlaceholderCompatibilityMode failed ({previous})"
        )));
    }
    Ok(previous)
}

/// Puts back the mode [`expose_placeholders`] gave. Only a pin [`expose_placeholders`] made is put back,
/// so the call was found then.
pub(crate) fn restore_placeholders(previous: i8) {
    if let Ok(set) = set_mode() {
        // SAFETY: as in `expose_placeholders`; `previous` is a mode the same call gave, so a valid one.
        unsafe { set(previous) };
    }
}

/// The file system name of the handle's volume (`NTFS`, `ReFS`, `FAT32`; a user-mode file system chooses
/// its own) and the NT device it is on (`\Device\HarddiskVolume5`, `\Device\Mup`): the first two parts of
/// the handle's path in the NT form, which the kernel driver that made the device named.
pub(crate) fn file_system(file: &File) -> std::io::Result<(String, String)> {
    let handle = HANDLE(file.as_raw_handle());
    // MAX_PATH + 1, the size the call's documentation asks for.
    let mut name = [0u16; 261];
    // SAFETY: `handle` is `file`'s, open for the whole call; `name` is writable for its length, which
    // the call is given with it, and outlives it; the buffers not asked for are None.
    unsafe { GetVolumeInformationByHandleW(handle, None, None, None, None, Some(&mut name)) }?;
    let len = name.iter().position(|unit| *unit == 0).unwrap_or(name.len());
    let name = String::from_utf16_lossy(&name[..len]);
    Ok((name, device_of(&String::from_utf16_lossy(&path_of(handle, VOLUME_NAME_NT)?))))
}

/// The device in an NT path: `\Device\HarddiskVolume5` of `\Device\HarddiskVolume5\Users\...`, or the
/// whole path when it has no third `\`.
fn device_of(nt: &str) -> String {
    nt.match_indices('\\').nth(2).map_or(nt, |(at, _)| &nt[..at]).to_owned()
}

/// Test builds only (the `test-seams` feature, which no release build turns on): put a reparse tag on a
/// file or folder, or take it off, as any user can on NTFS (`FSCTL_SET_REPARSE_POINT`,
/// `FSCTL_DELETE_REPARSE_POINT`, with no data), so phantab's check can be shown refusing a cloud
/// placeholder or another reparse point without a provider (PR #12 review r6, R6-1).
#[cfg(feature = "test-seams")]
pub(crate) mod seams {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use std::path::Path;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::DeviceIoControl;

    /// winioctl.h (the windows crate has them under `Win32_System_Ioctl`, which nothing else here needs).
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const FSCTL_DELETE_REPARSE_POINT: u32 = 0x0009_00AC;

    fn fsctl(path: &Path, code: u32, tag: u32) -> std::io::Result<()> {
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        // A header with no data: the tag, a data length of 0 and a reserved 0 (`REPARSE_DATA_BUFFER`'s),
        // then for a tag that is not Microsoft's (bit 31 clear) the GUID `REPARSE_GUID_DATA_BUFFER`
        // needs, any fixed one, the same for the set and the delete.
        let mut header = [0u8; 24];
        header[..4].copy_from_slice(&tag.to_le_bytes());
        header[8..].copy_from_slice(b"phantab-r6-tests");
        let len: u32 = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
        let mut returned = 0u32;
        // SAFETY: the handle is `file`'s, open for the whole call; `header` is readable for its 24
        // bytes, at least `len`, and outlives the call; no output buffer is passed, `returned` outlives
        // the call, and the call is synchronous (no OVERLAPPED).
        unsafe {
            DeviceIoControl(
                HANDLE(file.as_raw_handle()),
                code,
                Some(header.as_ptr().cast()),
                len,
                None,
                0,
                Some(&raw mut returned),
                None,
            )
        }?;
        Ok(())
    }

    pub(crate) fn set_reparse_tag(path: &Path, tag: u32) -> std::io::Result<()> {
        fsctl(path, FSCTL_SET_REPARSE_POINT, tag)
    }

    pub(crate) fn delete_reparse_tag(path: &Path, tag: u32) -> std::io::Result<()> {
        fsctl(path, FSCTL_DELETE_REPARSE_POINT, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review r7 R7-3: while pinned the thread's placeholder mode is exposed, and it is put back after.
    #[test]
    fn the_placeholder_mode_is_exposed_and_put_back() {
        let before = expose_placeholders().unwrap();
        assert_eq!(expose_placeholders().unwrap(), PHCM_EXPOSE_PLACEHOLDERS);
        restore_placeholders(before);
        assert_eq!(expose_placeholders().unwrap(), before);
        restore_placeholders(before);
    }

    /// Review r8 R8-7: the call is found in ntdll (it is there from Windows 10 1709), and looked up once
    /// in the process however often it is asked for: the count, not the address (which `GetProcAddress`
    /// gives the same every time), is what fails without the `OnceLock` (review r9 R9-4).
    #[test]
    fn the_placeholder_call_is_looked_up_once() {
        let first = set_mode().unwrap() as usize;
        assert_eq!(set_mode().unwrap() as usize, first);
        expose_placeholders().map(restore_placeholders).unwrap();
        assert_eq!(LOOKUPS.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Review r9 R9-4: a Windows without the call (before 1709) gets an `Unsupported` error that names
    /// it, which `check` reports as `UNPINNED`, rather than a panic or a pin that is not there.
    #[test]
    fn a_windows_without_the_placeholder_call_is_unsupported() {
        let e = supported(None).map(|_| ()).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
        assert!(e.to_string().contains("RtlSetThreadPlaceholderCompatibilityMode"), "{e}");
        assert!(!e.to_string().contains("1709"), "{e}");
    }

    /// Review r8 R8-1: the temp folder's volume is a partition of a local disk with NTFS or `ReFS` on it,
    /// and the device is cut from the NT path at its third `\`.
    #[test]
    fn the_temp_folder_is_on_a_local_disk_volume() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0200_0000)
            .open(std::env::temp_dir())
            .unwrap();
        let (name, device) = file_system(&dir).unwrap();
        assert!(name == "NTFS" || name == "ReFS", "{name}");
        assert!(device.starts_with(r"\Device\HarddiskVolume"), "{device}");
        assert_eq!(device_of(r"\Device\HarddiskVolume5\Users\a"), r"\Device\HarddiskVolume5");
        assert_eq!(device_of(r"\Device\Mup\host\share"), r"\Device\Mup");
        assert_eq!(device_of(r"\Device\Volume{1}"), r"\Device\Volume{1}");
    }

    /// A fresh folder for one test (this crate has no tempfile).
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("phantab-streams-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_stream_list_is_read_within_its_buffer() {
        let entry = |next: u32, name: &str| {
            let units: Vec<u16> = name.encode_utf16().collect();
            let mut out = Vec::new();
            out.extend(next.to_ne_bytes());
            out.extend(u32::try_from(units.len() * 2).unwrap().to_ne_bytes());
            out.extend([0u8; 16]);
            out.extend(units.iter().flat_map(|u| u.to_ne_bytes()));
            out
        };
        let mut two = entry(40, "::$DATA");
        two.resize(40, 0);
        two.extend(entry(0, ":x.html:$DATA"));
        assert_eq!(entries(&two).unwrap(), [":x.html:$DATA"]);
        assert_eq!(entries(&[0u8; 64]).unwrap(), Vec::<String>::new(), "nothing written");
        let mut past = entry(4096, ":x.html:$DATA");
        past.resize(64, 0);
        assert!(entries(&past).is_err(), "an offset past the buffer");
        let mut long = entry(0, ":x.html:$DATA");
        long[4] = 0xff;
        assert!(entries(&long).is_err(), "a name past the buffer");
    }

    /// Review r5 R5-2: a list larger than the first buffer is read whole, from a buffer far too small for
    /// one entry (`ERROR_BAD_LENGTH`) and from the real first buffer (`ERROR_MORE_DATA` past 8 KiB).
    #[test]
    fn a_long_stream_list_grows_its_buffer() {
        let dir = scratch("long");
        let path = dir.join("a.js");
        std::fs::write(&path, b"x").unwrap();
        let mut want = Vec::new();
        for n in 0..40 {
            let name = format!(":{n:02}{}.html", "s".repeat(200));
            let mut stream = path.clone().into_os_string();
            stream.push(&name);
            std::fs::write(&stream, b"<p>").unwrap();
            want.push(format!("{name}:$DATA"));
        }
        assert!(want.iter().map(|name| 24 + 2 * name.len()).sum::<usize>() > FIRST_WORDS * 8);
        let file = File::open(&path).unwrap();
        for first in [1, FIRST_WORDS] {
            let mut got = named_streams_from(&file, first).unwrap();
            got.sort();
            assert_eq!(got, want, "from {first} words");
        }
        drop(file);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Review r6 R6-1: the tag is read from a handle opened as the file itself, and a plain file has none.
    #[test]
    fn a_reparse_tag_is_read_from_the_handle() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let dir = scratch("tag");
        let path = dir.join("a.js");
        std::fs::write(&path, b"x").unwrap();
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(0x0020_0000 | 0x0200_0000)
                .open(&path)
                .unwrap()
        };
        assert_eq!(reparse_tag(&open()).unwrap(), None);
        seams::set_reparse_tag(&path, 0x8000_001B).unwrap();
        let tag = reparse_tag(&open());
        seams::delete_reparse_tag(&path, 0x8000_001B).unwrap();
        assert_eq!(tag.unwrap(), Some(0x8000_001B), "app exec link, which no filter owns");
        assert_eq!(reparse_tag(&open()).unwrap(), None, "taken off");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Review r5 R5-1: with no DOS form (a RAM disk), the NT form is used, under `\\?\GLOBALROOT`, and a
    /// path in that form opens the very file, so a walk rooted there reads and compares as on any volume;
    /// another file has another path, so a swap is still refused. With neither, the error says why.
    #[test]
    fn a_volume_without_a_dos_name_uses_the_nt_form() {
        let units = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        let no_dos = || std::io::Error::from_raw_os_error(1);
        assert_eq!(
            either(Err(no_dos()), || Ok(units(r"\Device\ImDisk0\rt\extension\a.js"))).unwrap(),
            PathBuf::from(r"\\?\GLOBALROOT\Device\ImDisk0\rt\extension\a.js")
        );
        assert_eq!(
            either(Ok(units(r"\\?\C:\a.js")), || panic!("not asked")).unwrap(),
            PathBuf::from(r"\\?\C:\a.js")
        );
        let error = either(Err(no_dos()), || Err(no_dos())).unwrap_err().to_string();
        assert!(error.contains("gives no path for an open file") && error.contains("NTFS drive"), "{error}");

        let dir = scratch("nt");
        let (a, b) = (dir.join("a.js"), dir.join("b.js"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let nt_of = |path: &std::path::Path| {
            let file = File::open(path).unwrap();
            either(Err(no_dos()), || path_of(HANDLE(file.as_raw_handle()), VOLUME_NAME_NT)).unwrap()
        };
        let a_nt = nt_of(&a);
        assert!(a_nt.to_string_lossy().starts_with(r"\\?\GLOBALROOT\Device\"), "{}", a_nt.display());
        assert_eq!(std::fs::read(&a_nt).unwrap(), b"a", "the NT form opens the file");
        assert_eq!(nt_of(&a_nt), a_nt, "and a handle opened by it is at it");
        assert_eq!(final_path(&File::open(&a_nt).unwrap()).unwrap(), std::fs::canonicalize(&a).unwrap());
        assert_ne!(nt_of(&b), a_nt, "another file is elsewhere");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
