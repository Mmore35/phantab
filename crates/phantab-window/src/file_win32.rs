//! Windows OS calls for [`crate::file_identity`]: an open file's volume, 128-bit file ID and update
//! sequence number (USN), and the path its handle resolves to. SR-58: each `unsafe` block says why it is
//! sound.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::PathBuf;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FILE_ID_INFO, FILE_NAME_NORMALIZED, FileIdInfo, GETFINALPATHNAMEBYHANDLE_FLAGS,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{FSCTL_READ_FILE_USN_DATA, READ_FILE_USN_DATA};

/// The file's `(volume serial, file ID, USN)`, or `None` when the file system cannot say.
///
/// # Safety
/// `file` must have been opened for synchronous I/O (without `FILE_FLAG_OVERLAPPED`), as
/// [`crate::file_identity::HeldFile::open`] opens it. On an overlapped handle `DeviceIoControl` with no
/// `OVERLAPPED` may complete later and write this frame's buffers after they are gone.
pub(crate) unsafe fn change_stamp(file: &std::fs::File) -> Option<(u64, u128, i64)> {
    let handle = HANDLE(file.as_raw_handle());
    let mut id = FILE_ID_INFO::default();
    let info_len = u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).ok()?;
    // SAFETY: `handle` is the open handle `file` owns, alive for the call; `id` is a live, writable
    // FILE_ID_INFO and the size passed is its own, as FileIdInfo requires. This call takes no OVERLAPPED
    // and completes before it returns whatever the handle's mode.
    unsafe { GetFileInformationByHandleEx(handle, FileIdInfo, (&raw mut id).cast(), info_len) }.ok()?;
    // A USN_RECORD_V2 or V3 for this file: a fixed header of at most 76 bytes, then the file's name (at
    // most 255 UTF-16 units). 8-byte aligned, as the record's 64-bit fields are.
    let mut record = [0u64; 128];
    let input = READ_FILE_USN_DATA { MinMajorVersion: 2, MaxMajorVersion: 3 };
    let mut got = 0u32;
    let input_len = u32::try_from(std::mem::size_of::<READ_FILE_USN_DATA>()).ok()?;
    let output_len = u32::try_from(std::mem::size_of_val(&record)).ok()?;
    // SAFETY: as above for `handle`, which the caller guarantees is synchronous (this fn's contract), so
    // with no OVERLAPPED the call has completed, and written its output, when it returns. The input is a
    // live READ_FILE_USN_DATA of the size passed; the output is a live, writable buffer of `output_len`
    // bytes; `got` is a live u32.
    unsafe {
        DeviceIoControl(
            handle,
            FSCTL_READ_FILE_USN_DATA,
            Some((&raw const input).cast()),
            input_len,
            Some(record.as_mut_ptr().cast()),
            output_len,
            Some(&raw mut got),
            None,
        )
    }
    .ok()?;
    let bytes: Vec<u8> = record.iter().flat_map(|w| w.to_le_bytes()).collect();
    let got = usize::try_from(got).ok()?.min(bytes.len());
    let field = |at: usize| -> Option<i64> {
        Some(i64::from_le_bytes(bytes.get(at..at + 8).filter(|_| at + 8 <= got)?.try_into().ok()?))
    };
    // USN_RECORD_COMMON_HEADER: RecordLength (u32), MajorVersion (u16), MinorVersion (u16). The USN
    // follows the file and parent references: 8 bytes each in V2, 16 in V3.
    let major = u16::from_le_bytes(bytes.get(4..6)?.try_into().ok()?);
    let usn = match major {
        2 => field(24)?,
        3 => field(40)?,
        _ => return None,
    };
    Some((id.VolumeSerialNumber, u128::from_le_bytes(id.FileId.Identifier), usn))
}

/// The normalized path, with every link and junction on the way resolved, of the file `file`'s handle
/// is open on (`\\?\C:\...`), or `None` when Windows cannot give it.
pub(crate) fn final_path(file: &std::fs::File) -> Option<PathBuf> {
    let handle = HANDLE(file.as_raw_handle());
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `handle` is the open handle `file` owns, alive for the call; `buf` is a live, writable
        // slice whose length the binding passes. The call is synchronous whatever the handle's mode.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                &mut buf,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        };
        let n = usize::try_from(n).ok()?;
        match n {
            0 => return None,
            // It fit: `n` units, without the terminating NUL.
            n if n < buf.len() => return Some(PathBuf::from(OsString::from_wide(&buf[..n]))),
            // Too small: `n` is the size needed, with the NUL. Paths stop at 32 767 units.
            n if n <= 32_768 => buf.resize(n.max(buf.len() + 1), 0),
            _ => return None,
        }
    }
}
