//! macOS OS calls for [`crate::secret_store`]: reading one generic-password item from the login Keychain
//! into a buffer phantab can wipe. SR-58: each `unsafe` block says why it is sound.
//!
//! `SecItemCopyMatching` (security-framework's `get_generic_password`) hands the secret back in a
//! `CFData` that Core Foundation frees unwiped, so a copy of the session key stayed on the heap after
//! every read. `SecKeychainFindGenericPassword` returns it in a buffer the caller owns until
//! `SecKeychainItemFreeContent`: it is copied into a [`Zeroizing`] buffer, then zeroed, then freed. Both
//! calls read the same file-based login Keychain, through the same access list. Apple marks the
//! `SecKeychain*` calls deprecated (macOS 10.10) but still ships and supports them; the item they read
//! is the one `SecItemAdd` wrote.
//!
//! Every call names the keychain it searches (the login keychain `secret_store` opens by path), never
//! the default search list: a same-user program can make its own keychain the default, or put it first
//! in the list, and would then receive the store and answer the read.
#![allow(unsafe_code)]

use std::ffi::c_void;

use core_foundation::base::TCFType as _;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;
use security_framework_sys::keychain::SecKeychainFindGenericPassword;
use security_framework_sys::keychain_item::{SecKeychainItemDelete, SecKeychainItemFreeContent};
use zeroize::{Zeroize as _, Zeroizing};

/// `errSecItemNotFound`.
pub(crate) const ITEM_NOT_FOUND: i32 = -25300;
/// `errSecDuplicateItem`: also what [`delete_generic_passwords`] says when items keep coming back.
pub(crate) const DUPLICATE_ITEM: i32 = -25299;
/// `errSecParam`: a name too long to pass.
const PARAM: i32 = -50;
/// The most items under one name [`delete_generic_passwords`] deletes before it gives up.
const MOST_ITEMS: usize = 64;

/// A buffer the Keychain allocated for a found password: zeroed, then freed, on drop.
struct OsPassword {
    data: *mut c_void,
    len: u32,
}

impl OsPassword {
    fn bytes(&self) -> &[u8] {
        if self.data.is_null() || self.len == 0 {
            return &[];
        }
        // SAFETY: SecKeychainFindGenericPassword set `data` to `len` initialised bytes the caller owns
        // until SecKeychainItemFreeContent in drop; the borrow cannot outlive `self`.
        unsafe { std::slice::from_raw_parts(self.data.cast::<u8>(), self.len as usize) }
    }
}

impl Drop for OsPassword {
    fn drop(&mut self) {
        if self.data.is_null() {
            return;
        }
        if self.len != 0 {
            // SAFETY: as in `bytes`, and `&mut self` means no borrow of the buffer is alive; the buffer is
            // writable memory the Keychain allocated for the caller.
            unsafe { std::slice::from_raw_parts_mut(self.data.cast::<u8>(), self.len as usize) }.zeroize();
        }
        // SAFETY: `data` came from SecKeychainFindGenericPassword and is freed once, here; a null
        // attribute list is allowed when only the data is freed.
        let _ = unsafe { SecKeychainItemFreeContent(std::ptr::null_mut(), self.data) };
        self.data = std::ptr::null_mut();
    }
}

/// The lengths of `service` and `account` as the `SecKeychain*` calls take them.
fn lengths(service: &str, account: &str) -> Result<(u32, u32), i32> {
    Ok((u32::try_from(service.len()).map_err(|_| PARAM)?, u32::try_from(account.len()).map_err(|_| PARAM)?))
}

/// The secret of the generic-password item `service`/`account` in `keychain` only, or `None` when there
/// is none. Errors are the OS status.
pub(crate) fn find_generic_password(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, i32> {
    let (service_len, account_len) = lengths(service, account)?;
    let mut found = OsPassword { data: std::ptr::null_mut(), len: 0 };
    // SAFETY: `keychain` is a live SecKeychain the caller holds for the call. The name pointers are valid
    // for their lengths for the call (the strings outlive it; the call takes lengths, so no NUL is
    // needed). `len` and `data` are out-pointers to live locals; a null item ref asks for no item. On
    // success `data` is the caller's to free, which `OsPassword`'s drop does.
    let status = unsafe {
        SecKeychainFindGenericPassword(
            keychain.as_CFTypeRef(),
            service_len,
            service.as_ptr().cast(),
            account_len,
            account.as_ptr().cast(),
            &raw mut found.len,
            &raw mut found.data,
            std::ptr::null_mut(),
        )
    };
    match status {
        0 => Ok(Some(Zeroizing::new(found.bytes().to_vec()))),
        ITEM_NOT_FOUND => Ok(None),
        other => Err(other),
    }
}

/// Deletes every generic-password item `service`/`account` in `keychain` only, and says how many there
/// were. Finding an item without its data reads no secret. Errors are the OS status, or
/// [`DUPLICATE_ITEM`] when more than [`MOST_ITEMS`] keep turning up.
pub(crate) fn delete_generic_passwords(
    keychain: &SecKeychain,
    service: &str,
    account: &str,
) -> Result<usize, i32> {
    let (service_len, account_len) = lengths(service, account)?;
    for deleted in 0..=MOST_ITEMS {
        let mut item = std::ptr::null_mut();
        // SAFETY: as in `find_generic_password`, except that null length and data pointers ask for no
        // secret, and `item` is an out-pointer to a live local that receives a retained item ref.
        let status = unsafe {
            SecKeychainFindGenericPassword(
                keychain.as_CFTypeRef(),
                service_len,
                service.as_ptr().cast(),
                account_len,
                account.as_ptr().cast(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut item,
            )
        };
        match status {
            0 if !item.is_null() => {}
            ITEM_NOT_FOUND => return Ok(deleted),
            0 => return Err(PARAM),
            other => return Err(other),
        }
        // SAFETY: a found item ref is returned retained (the create rule), so wrapping it here releases it
        // once, when `item` drops.
        let item = unsafe { SecKeychainItem::wrap_under_create_rule(item) };
        // SAFETY: `item` is a live item ref for the call.
        let status = unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) };
        if status != 0 {
            return Err(status);
        }
    }
    Err(DUPLICATE_ITEM)
}

// Deprecated (macOS 10.10) like the other `SecKeychain*` calls, and still shipped; security-framework-sys
// does not declare them.
#[cfg(any(test, feature = "test-seams"))]
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// Deletes a keychain's file (and takes it off the search list, were it on it).
    fn SecKeychainDelete(keychain_or_array: security_framework_sys::base::SecKeychainRef) -> i32;
    /// The search list of one preferences domain, as a new `CFArray` of keychain refs. Read only.
    #[cfg(test)]
    fn SecKeychainCopyDomainSearchList(
        domain: security_framework_sys::keychain::SecPreferencesDomain,
        search_list: *mut core_foundation::array::CFArrayRef,
    ) -> i32;
    /// A keychain's path, into the caller's buffer. `io_path_length` is the buffer's length on the way
    /// in and the path's length, without the NUL, on the way out.
    #[cfg(test)]
    fn SecKeychainGetPath(
        keychain: security_framework_sys::base::SecKeychainRef,
        io_path_length: *mut u32,
        path_name: *mut std::ffi::c_char,
    ) -> i32;
}

/// `errSecNoDefaultKeychain`.
#[cfg(test)]
const NO_DEFAULT_KEYCHAIN: i32 = -25307;

/// Test builds only: deletes the scratch keychain `keychain` ([`crate::secret_store::test_keychain`]), its
/// file. Errors are the OS status.
#[cfg(any(test, feature = "test-seams"))]
pub(crate) fn delete_keychain(keychain: &SecKeychain) -> Result<(), i32> {
    // SAFETY: `keychain` is a live SecKeychain the caller holds for the call. SecKeychainDelete takes a
    // keychain ref (or an array of them) and neither keeps nor releases it.
    match unsafe { SecKeychainDelete(keychain.as_concrete_TypeRef()) } {
        0 => Ok(()),
        status => Err(status),
    }
}

/// The path of the keychain `keychain`, a ref live for the call.
#[cfg(test)]
fn keychain_path(keychain: security_framework_sys::base::SecKeychainRef) -> Result<std::path::PathBuf, i32> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut buf = vec![0u8; 4096];
    let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    // SAFETY: `keychain` is a live keychain ref the caller holds for the call; `buf` is a live, writable
    // buffer of the `len` bytes passed, and `len` a live u32 the call sets. The call keeps neither.
    let status = unsafe { SecKeychainGetPath(keychain, &raw mut len, buf.as_mut_ptr().cast()) };
    if status != 0 {
        return Err(status);
    }
    buf.truncate(usize::try_from(len).unwrap_or(usize::MAX).min(buf.len()));
    Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&buf)))
}

/// Unit tests only: the user domain's keychain search list and its default keychain (`None` when it has
/// none), as paths, so a test can show a scratch keychain changes neither. Read only: it opens no item and
/// sets nothing. Errors are the OS status.
#[cfg(test)]
pub(crate) fn user_search_list_and_default()
-> Result<(Vec<std::path::PathBuf>, Option<std::path::PathBuf>), i32> {
    use core_foundation::array::{CFArray, CFArrayGetValueAtIndex};
    use security_framework_sys::keychain::SecPreferencesDomain;
    let mut list: core_foundation::array::CFArrayRef = std::ptr::null();
    // SAFETY: `list` is a live pointer the call sets to a new CFArray it hands to the caller (the create
    // rule), which `CFArray` takes and releases.
    let status = unsafe { SecKeychainCopyDomainSearchList(SecPreferencesDomain::User, &raw mut list) };
    if status != 0 {
        return Err(status);
    }
    if list.is_null() {
        return Err(PARAM);
    }
    // SAFETY: `list` is the new CFArray the call just returned, owned here from now on.
    let list: CFArray = unsafe { CFArray::wrap_under_create_rule(list) };
    let mut paths = Vec::new();
    for i in 0..list.len() {
        // SAFETY: `i` is below the array's count; the value is a keychain ref the array keeps alive while
        // `list` lives, borrowed (not retained) for the call that follows.
        let keychain = unsafe { CFArrayGetValueAtIndex(list.as_concrete_TypeRef(), i) };
        paths.push(keychain_path(keychain.cast_mut().cast())?);
    }
    let default = match SecKeychain::default_for_domain(SecPreferencesDomain::User) {
        Ok(keychain) => Some(keychain_path(keychain.as_concrete_TypeRef())?),
        Err(e) if e.code() == NO_DEFAULT_KEYCHAIN => None,
        Err(e) => return Err(e.code()),
    };
    Ok((paths, default))
}

/// The home folder of the user this process runs as, from the user database (`getpwuid_r` for the real
/// user ID), never from `$HOME`: a process started with another `HOME` would otherwise open that
/// folder's login keychain, made by whoever set it (THREAT-MODEL SR-63).
pub(crate) fn real_home() -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    // Room for the entry's strings; doubled while the call says it is too small (ERANGE).
    let mut buf = vec![0u8; 4096];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        // SAFETY: `entry` is a live, writable `passwd`; `buf` is a live, writable buffer of the length
        // passed, which holds the strings the entry points to; `found` is a live pointer the call sets to
        // `entry` or to null. getpwuid_r is the reentrant form: it touches nothing else.
        let status = unsafe {
            libc::getpwuid_r(uid, entry.as_mut_ptr(), buf.as_mut_ptr().cast(), buf.len(), &raw mut found)
        };
        if status == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status));
        }
        if found.is_null() {
            return Err(std::io::Error::other("the user database has no entry for this user"));
        }
        // SAFETY: a non-null `found` is `entry`, filled in by the call that just returned 0.
        let dir = unsafe { (*found).pw_dir };
        if dir.is_null() {
            return Err(std::io::Error::other("the user database names no home folder for this user"));
        }
        // SAFETY: a non-null `pw_dir` points to a NUL-terminated string inside `buf`, which is alive and
        // unchanged until this function returns; the bytes are copied out before then.
        let dir = unsafe { std::ffi::CStr::from_ptr(dir) };
        let home = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
        if !home.is_absolute() {
            return Err(std::io::Error::other("the user database names no absolute home folder"));
        }
        return Ok(home);
    }
}

#[cfg(test)]
mod tests {
    /// Set in the child [`the_home_comes_from_the_user_database`] runs itself as.
    const CHILD: &str = "PHANTAB_TEST_HOME_CHILD";
    /// The `HOME` that child is given: a folder that does not exist.
    const NOT_HOME: &str = "/tmp/phantab-not-home";

    #[test]
    fn the_home_comes_from_the_user_database() {
        // Run again with `HOME` set to another folder, so a home read from the environment fails it.
        if std::env::var_os(CHILD).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "secret_mac::tests::the_home_comes_from_the_user_database"])
                .env(CHILD, "1")
                .env("HOME", NOT_HOME)
                .output()
                .unwrap();
            let shown = String::from_utf8_lossy(&out.stdout);
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success() && shown.contains("1 passed"), "{shown}{err}");
            return;
        }
        assert_eq!(std::env::var_os("HOME").as_deref(), Some(std::ffi::OsStr::new(NOT_HOME)));
        let home = super::real_home().unwrap();
        assert!(home.is_absolute() && home.is_dir(), "{}", home.display());
        // The same user database, as `id` reads it: not the environment.
        let out = std::process::Command::new("/usr/bin/id").arg("-P").output().unwrap();
        let entry = String::from_utf8(out.stdout).unwrap();
        // `id -P` prints the passwd entry: name:password:uid:gid:class:change:expire:gecos:home:shell.
        let field = entry.trim().split(':').nth(8).unwrap();
        assert_eq!(home, std::path::Path::new(field));
    }
}
