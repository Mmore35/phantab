//! macOS OS calls for [`crate::streams`]: this thread's policy for dataless files (`getiopolicy_np` and
//! `setiopolicy_np` with `IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES`, sys/resource.h; libc 0.2 has
//! neither the calls nor the values). SR-58: each `unsafe` block says why it is sound.
#![allow(unsafe_code)]

use std::ffi::c_int;

const IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES: c_int = 3;
const IOPOL_SCOPE_THREAD: c_int = 1;
const IOPOL_MATERIALIZE_DATALESS_FILES_OFF: c_int = 1;

// SAFETY: the prototypes are sys/resource.h's: `int getiopolicy_np(int, int)` and
// `int setiopolicy_np(int, int, int)`, in libSystem since macOS 10.5.
unsafe extern "C" {
    fn getiopolicy_np(iotype: c_int, scope: c_int) -> c_int;
    fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int;
}

/// Sets this thread's policy to never materialize a dataless file, so no File Provider is asked to fetch
/// one this thread opens or reads, and gives the policy it had (0, the process's, or 1 or 2).
pub(crate) fn no_materializing() -> std::io::Result<c_int> {
    // SAFETY: both calls take integers by value, set only this thread's I/O policy and touch no memory
    // of ours; a failure is -1 with errno set, read at once.
    let previous = unsafe { getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD) };
    if previous < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    let set = unsafe {
        setiopolicy_np(
            IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
            IOPOL_SCOPE_THREAD,
            IOPOL_MATERIALIZE_DATALESS_FILES_OFF,
        )
    };
    if set != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(previous)
}

/// Puts back the policy [`no_materializing`] gave.
pub(crate) fn restore_materializing(previous: c_int) {
    // SAFETY: as in `no_materializing`; `previous` is a policy getiopolicy_np gave, so a valid one.
    unsafe { setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD, previous) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review r7 R7-3: while pinned the thread's dataless-file policy is off, and it is put back after.
    #[test]
    fn the_dataless_policy_is_off_and_put_back() {
        let before = no_materializing().unwrap();
        assert_eq!(no_materializing().unwrap(), IOPOL_MATERIALIZE_DATALESS_FILES_OFF);
        restore_materializing(before);
        assert_eq!(no_materializing().unwrap(), before);
        restore_materializing(before);
    }
}
