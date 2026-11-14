//! Windows OS calls for [`crate::secure_dir`]: the token's SIDs, a path's owner, DACL and mandatory label
//! as SDDL, writing a protected DACL or a label, and creating a folder with them. Every buffer the OS
//! allocates is freed by [`Local`] on every path.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl,
    GetTokenInformation, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::secure_dir::{SecureDirError, os};

/// A buffer the OS allocated with `LocalAlloc`, freed on drop.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate with LocalAlloc
            // (ConvertSidToStringSidW, GetNamedSecurityInfoW, the SDDL conversions), and is freed once, here.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

/// A token handle, closed on drop.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed once, here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// The NUL-terminated UTF-16 string at `p`, as Rust text.
///
/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string that stays valid for the call.
unsafe fn pwstr_text(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller guarantees a valid NUL-terminated string.
    String::from_utf16_lossy(unsafe { p.as_wide() })
}

fn sid_text(sid: PSID, path: &Path) -> Result<String, SecureDirError> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` points into a buffer that outlives this call (the caller's token buffer or security
    // descriptor); the OS writes a LocalAlloc'd string to `text`, which `Local` frees.
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }
        .map_err(|e| os("Could not read a SID", path, &e))?;
    let _free = Local(text.0.cast());
    // SAFETY: ConvertSidToStringSidW succeeded, so `text` is a NUL-terminated string until `_free` drops.
    Ok(unsafe { pwstr_text(text) })
}

/// The process token's user SID and its default owner SID (Administrators when elevated), as `S-1-…`.
pub(crate) fn token_sids(path: &Path) -> Result<(String, String), SecureDirError> {
    let mut handle = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing; the token handle written
    // to `handle` is closed by `Token`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut handle) }
        .map_err(|e| os("Could not open this process's token", path, &e))?;
    let token = Token(handle);
    let user = token_info(&token, TokenUser, path)?;
    // SAFETY: GetTokenInformation(TokenUser) filled `user` with a TOKEN_USER (u64 storage keeps it
    // aligned) whose SID points inside the same buffer, alive until the end of this function.
    let user_sid = sid_text(unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid }, path)?;
    let owner = token_info(&token, TokenOwner, path)?;
    // SAFETY: as above, a TOKEN_OWNER whose SID points inside `owner`.
    let owner_sid = sid_text(unsafe { (*owner.as_ptr().cast::<TOKEN_OWNER>()).Owner }, path)?;
    Ok((user_sid, owner_sid))
}

/// How SDDL text names `sid`: an alias for a well-known account (`LA` for this machine's built-in
/// Administrator, `SY` for SYSTEM), else the `S-1-…` form. A DACL read back as SDDL uses this name, so the
/// owner-only check compares against it as well as the plain SID.
pub(crate) fn sddl_name(sid: &str, path: &Path) -> Result<String, SecureDirError> {
    let sddl_w: Vec<u16> = format!("O:{sid}").encode_utf16().chain(Some(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl_w` is NUL-terminated and outlives the call; the OS allocates the descriptor, freed by
    // `_sd`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &raw mut sd,
            None,
        )
    }
    .map_err(|e| os("Could not read a SID", path, &e))?;
    let _sd = Local(sd.0);
    let mut text = PWSTR::null();
    // SAFETY: `sd` is the descriptor built above, alive until `_sd` drops; the OS writes a LocalAlloc'd
    // string to `text`, freed by `_text`.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION,
            &raw mut text,
            None,
        )
    }
    .map_err(|e| os("Could not read a SID", path, &e))?;
    let _text = Local(text.0.cast());
    // SAFETY: the conversion succeeded, so `text` is NUL-terminated until `_text` drops.
    let owner = unsafe { pwstr_text(text) };
    Ok(owner.strip_prefix("O:").unwrap_or(&owner).to_owned())
}

fn token_info(
    token: &Token,
    class: TOKEN_INFORMATION_CLASS,
    path: &Path,
) -> Result<Vec<u64>, SecureDirError> {
    let mut needed = 0u32;
    // SAFETY: a size query: no buffer, the OS writes the needed length to `needed`. It reports
    // ERROR_INSUFFICIENT_BUFFER, which is expected here.
    let _ = unsafe { GetTokenInformation(token.0, class, None, 0, &raw mut needed) };
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    let len = u32::try_from(buf.len() * 8).map_err(|e| os("Token information too large", path, &e))?;
    // SAFETY: `buf` is `len` writable bytes, 8-byte aligned, and lives past the call.
    unsafe { GetTokenInformation(token.0, class, Some(buf.as_mut_ptr().cast()), len, &raw mut needed) }
        .map_err(|e| os("Could not read this process's token", path, &e))?;
    Ok(buf)
}

/// `path`'s owner SID (`S-1-…`) and its DACL as SDDL (`D:P(A;OICI;FA;;;…)…`).
pub(crate) fn owner_and_dacl(path: &Path) -> Result<(String, String), SecureDirError> {
    let name = wide(path);
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `name` is NUL-terminated and outlives the call; the OS allocates the descriptor (freed by
    // `_sd`) and points `owner` inside it.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            None,
            None,
            &raw mut sd,
        )
    };
    let _sd = Local(sd.0);
    if status != ERROR_SUCCESS {
        return Err(os("Could not read the folder's security", path, &windows::core::Error::from(status)));
    }
    let owner = sid_text(owner, path)?;
    let mut text = PWSTR::null();
    // SAFETY: `sd` is the descriptor read above, alive until `_sd` drops; the OS writes a LocalAlloc'd
    // string to `text`, freed by `_text`.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &raw mut text,
            None,
        )
    }
    .map_err(|e| os("Could not read the folder's access list", path, &e))?;
    let _text = Local(text.0.cast());
    // SAFETY: the conversion succeeded, so `text` is NUL-terminated until `_text` drops.
    Ok((owner, unsafe { pwstr_text(text) }))
}

/// `path`'s mandatory label as SDDL (`S:(ML;OICI;NRNWNX;;;ME)`), or `""` when it has none. Reading the label
/// needs only `READ_CONTROL`, which the owner always has; no privilege.
pub(crate) fn label_sddl(path: &Path) -> Result<String, SecureDirError> {
    let name = wide(path);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `name` is NUL-terminated and outlives the call; the OS allocates the descriptor, freed by
    // `_sd`. No out-pointer but the descriptor is asked for.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &raw mut sd,
        )
    };
    let _sd = Local(sd.0);
    if status != ERROR_SUCCESS {
        return Err(os(
            "Could not read the folder's integrity label",
            path,
            &windows::core::Error::from(status),
        ));
    }
    let mut text = PWSTR::null();
    // SAFETY: `sd` is the descriptor read above, alive until `_sd` drops; the OS writes a LocalAlloc'd
    // string to `text`, freed by `_text`.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            LABEL_SECURITY_INFORMATION,
            &raw mut text,
            None,
        )
    }
    .map_err(|e| os("Could not read the folder's integrity label", path, &e))?;
    let _text = Local(text.0.cast());
    // SAFETY: the conversion succeeded, so `text` is NUL-terminated until `_text` drops.
    Ok(unsafe { pwstr_text(text) })
}

/// Puts the mandatory label in `sddl` (`S:(ML;…)`) on `path`, propagating its inheritable part to
/// everything inside, as [`set_dacl`] does for a DACL. Only the label is written: `LABEL_SECURITY_INFORMATION`
/// touches no audit entry, so no `SeSecurityPrivilege` is needed. It does need `WRITE_OWNER` on `path`
/// (the owner-only DACL grants the user full control) and a level no higher than this process's own;
/// Medium from a Medium or elevated process is both. Above that the OS refuses (`ERROR_INVALID_LABEL`),
/// and that error is returned, not raised.
pub(crate) fn set_label(path: &Path, sddl: &str) -> Result<(), SecureDirError> {
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl_w` is NUL-terminated and outlives the call; the OS allocates the descriptor, freed by
    // `_sd`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &raw mut sd,
            None,
        )
    }
    .map_err(|e| os("Could not build the integrity label", path, &e))?;
    let _sd = Local(sd.0);
    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    let mut sacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is the descriptor built above; `sacl` is pointed inside it, alive until `_sd` drops.
    unsafe { GetSecurityDescriptorSacl(sd, &raw mut present, &raw mut sacl, &raw mut defaulted) }
        .map_err(|e| os("Could not build the integrity label", path, &e))?;
    if !present.as_bool() || sacl.is_null() {
        return Err(os("Could not build the integrity label", path, &"no label"));
    }
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; `sacl` points into `sd`, alive past the call. Only the label is
    // written (owner, group, DACL and audit entries untouched).
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(sacl.cast_const()),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(os("Could not label the folder", path, &windows::core::Error::from(status)));
    }
    Ok(())
}

/// Creates the folder `path` (its parent must exist) with the DACL in `sddl` given to the create call
/// itself, so the folder never exists with any other access (THREAT-MODEL R15). An `sddl` with `P`
/// takes nothing from the parent. A mandatory label in `sddl` (`S:(ML;…)`) is set by the same call, under
/// the rules [`set_label`] names.
pub(crate) fn create_dir_with(path: &Path, sddl: &str) -> std::io::Result<()> {
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl_w` is NUL-terminated and outlives the call; the OS allocates the descriptor, freed by
    // `_sd`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &raw mut sd,
            None,
        )
    }
    .map_err(|e| io_error(&e))?;
    let _sd = Local(sd.0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(std::io::Error::other)?,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and `attributes` points at `sd`; both outlive the call, which only
    // reads them.
    unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&raw const attributes)) }.map_err(|e| io_error(&e))
}

/// The Win32 code inside `e` as an `io::Error`, so `ErrorKind::AlreadyExists` and the rest still match
/// (the crate's own conversion keeps the HRESULT, which `std` does not decode).
fn io_error(e: &windows::core::Error) -> std::io::Error {
    WIN32_ERROR::from_error(e)
        .and_then(|code| i32::try_from(code.0).ok())
        .map_or_else(|| std::io::Error::other(e.message()), std::io::Error::from_raw_os_error)
}

/// Replaces `path`'s DACL with the one in `sddl`, propagating to everything inside. `protected` turns
/// inheritance off; otherwise the parent's inheritable entries are merged back in.
pub(crate) fn set_dacl(path: &Path, sddl: &str, protected: bool) -> Result<(), SecureDirError> {
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl_w` is NUL-terminated and outlives the call; the OS allocates the descriptor, freed by
    // `_sd`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &raw mut sd,
            None,
        )
    }
    .map_err(|e| os("Could not build the access list", path, &e))?;
    let _sd = Local(sd.0);
    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is the descriptor built above; `dacl` is pointed inside it, alive until `_sd` drops.
    unsafe { GetSecurityDescriptorDacl(sd, &raw mut present, &raw mut dacl, &raw mut defaulted) }
        .map_err(|e| os("Could not build the access list", path, &e))?;
    if !present.as_bool() || dacl.is_null() {
        return Err(os("Could not build the access list", path, &"no DACL"));
    }
    let name = wide(path);
    let inheritance =
        if protected { PROTECTED_DACL_SECURITY_INFORMATION } else { UNPROTECTED_DACL_SECURITY_INFORMATION };
    // SAFETY: `name` is NUL-terminated; `dacl` points into `sd`, alive past the call. Only the DACL is
    // written (owner and group untouched).
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | inheritance,
            None,
            None,
            Some(dacl.cast_const()),
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(os(
            "Could not restrict the folder to this user",
            path,
            &windows::core::Error::from(status),
        ));
    }
    Ok(())
}
