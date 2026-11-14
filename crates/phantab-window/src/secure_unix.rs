//! Unix OS calls for [`crate::secure_dir`] and [`crate::process`]: the effective uid, a no-follow
//! `chmod 0700`, and the core-dump limit. The only `unsafe` is the libc calls, which take no pointers
//! except the `rlimit` on the stack.
#![allow(unsafe_code)]

use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use crate::secure_dir::{SecureDirError, os};

/// This process's effective uid.
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory of ours.
    unsafe { libc::geteuid() }
}

/// `path`'s owner uid and permission bits, without following a final symlink.
pub(crate) fn owner_and_mode(path: &Path) -> Result<(u32, u32), SecureDirError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| os("Could not read the folder", path, &e))?;
    Ok((meta.uid(), meta.mode() & 0o7777))
}

/// `chmod 0700` on the folder itself: opened with `O_NOFOLLOW | O_DIRECTORY`, then `fchmod`, so a folder
/// swapped for a link after the check is refused rather than followed.
pub(crate) fn set_mode_700(path: &Path) -> Result<(), SecureDirError> {
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|e| os("Could not open the folder", path, &e))?;
    if dir.metadata().map_err(|e| os("Could not read the folder", path, &e))?.uid() != effective_uid() {
        return Err(SecureDirError::ForeignOwner {
            path: path.to_path_buf(),
            owner: "another account".into(),
        });
    }
    dir.set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|e| os("Could not restrict the folder to this user", path, &e))
}

/// `setrlimit(RLIMIT_CORE, 0)`: a crash leaves no core file holding the token or a credential.
pub(crate) fn disable_core_dumps() -> std::io::Result<()> {
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `zero` is a valid rlimit on the stack, read by the call and not kept.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const zero) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
