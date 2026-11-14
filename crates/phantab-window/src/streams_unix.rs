//! Unix OS calls for [`crate::streams`]: the file system an open file or folder is on (`fstatfs`). On
//! macOS that is `f_fstypename`, the name the kext or `FSKit` module that mounted it gives (macFUSE's kext
//! prefixes `macfuse_`; an `FSKit` module may give any, `apfs` too), and whether it is an `FSKit` mount
//! ([`MNT_EXT_FSKIT`], which the kernel sets, not the module, review r9 R9-2). On Linux it is `f_type`,
//! the magic of the kernel driver of the file system mounted there. SR-58: the one `unsafe` call says
//! why it is sound.
#![allow(unsafe_code)]

use std::fs::File;
use std::os::fd::AsRawFd as _;

/// linux/magic.h's `FUSE_SUPER_MAGIC` and `OVERLAYFS_SUPER_MAGIC`, as wide as any `f_type` (libc's own
/// are typed per target, `c_long` or `c_uint`).
#[cfg(target_os = "linux")]
const FUSE_SUPER_MAGIC: i128 = 0x6573_5546;
#[cfg(target_os = "linux")]
const OVERLAYFS_SUPER_MAGIC: i128 = 0x794c_7630;

/// `MNT_EXT_FSKIT` (macOS; libc 0.2 does not export it): xnu `bsd/sys/mount.h:108`,
/// `#define MNT_EXT_FSKIT 0x00000002 /* this is an FSKit mount */`. The kernel sets it in `statfs`'s
/// `f_flags_ext` for every `FSKit` mount (`vfs_getextflags` in `bsd/vfs/vfs_subr.c`, from the mount's
/// `MNTK_FSKIT`, which `vfs_setfskit`, a private kernel export (`config/Private.exports`) no
/// third-party kext can call, sets when `FSKit` mounts it; `fstatfs` copies it out in
/// `bsd/vfs/vfs_syscalls.c`), so a module that names itself `apfs` still has it (review r9 R9-2). It
/// comes in the same `fstatfs` reply as the name, so when the name was read the flag was too, and a
/// failed `fstatfs` is an error, never a clear flag. `FSKit` came in macOS 15.4; a macOS before it has
/// no `FSKit` mount to flag.
#[cfg(target_os = "macos")]
const MNT_EXT_FSKIT: u32 = 0x0000_0002;

/// `fstatfs` on `file`'s descriptor. On Intel macOS libc links it to `fstatfs$INODE64`, the `statfs`
/// with `f_flags_ext`, which is the only one on Apple silicon.
fn statfs(file: &File) -> std::io::Result<libc::statfs> {
    let mut out = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: the descriptor is `file`'s, open for the whole call; `out` is a `statfs` that outlives
    // the call, which `fstatfs` fills on success and leaves as it was (all zero) on failure; a `statfs`
    // is integers and byte arrays only, so all zero is a valid one either way, and `assume_init` runs
    // after the call has returned.
    let (rc, out) = unsafe {
        let rc = libc::fstatfs(file.as_raw_fd(), out.as_mut_ptr());
        (rc, out.assume_init())
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(out)
}

/// macOS: `f_fstypename` (`apfs`, `hfs`, `smbfs`, `macfuse_<name>`, or whatever an `FSKit` module
/// calls itself), and whether it is an `FSKit` mount ([`named`]).
#[cfg(target_os = "macos")]
pub(crate) fn file_system(file: &File) -> std::io::Result<(String, bool)> {
    Ok(named(&statfs(file)?))
}

/// The name and the `FSKit` flag ([`MNT_EXT_FSKIT`]) of one `fstatfs` reply, apart from the call so a
/// test can stand one in.
#[cfg(target_os = "macos")]
fn named(out: &libc::statfs) -> (String, bool) {
    let name: Vec<u8> =
        out.f_fstypename.iter().take_while(|c| **c != 0).map(|c| c.to_ne_bytes()[0]).collect();
    (String::from_utf8_lossy(&name).into_owned(), out.f_flags_ext & MNT_EXT_FSKIT != 0)
}

/// Linux: `fuse` or `overlay` for those magics, else `f_type` in hex (`0xef53` for ext4). There is no
/// `FSKit`.
#[cfg(target_os = "linux")]
pub(crate) fn file_system(file: &File) -> std::io::Result<(String, bool)> {
    let magic = i128::from(statfs(file)?.f_type);
    let name = match magic {
        FUSE_SUPER_MAGIC => "fuse".to_owned(),
        OVERLAYFS_SUPER_MAGIC => "overlay".to_owned(),
        other => format!("{other:#x}"),
    };
    Ok((name, false))
}

/// Another Unix: nothing named, which phantab's check does not hold against it.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn file_system(file: &File) -> std::io::Result<(String, bool)> {
    statfs(file).map(|_| (String::new(), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review r8 R8-1: the temp folder is on the computer's own disk, so its file system is named as
    /// one (APFS on macOS, not mounted through `FSKit`, review r9 R9-2) and is not FUSE.
    #[test]
    fn the_temp_folder_is_on_a_local_file_system() {
        let (name, fskit) = file_system(&File::open(std::env::temp_dir()).unwrap()).unwrap();
        #[cfg(target_os = "macos")]
        assert_eq!((name.as_str(), fskit), ("apfs", false));
        #[cfg(target_os = "linux")]
        assert!(name != "fuse" && !fskit);
        let _ = (name, fskit);
    }

    /// Review r9 R9-2: an `FSKit` mount that calls itself `apfs` is named `apfs` but flagged as `FSKit`,
    /// from the kernel's `f_flags_ext` bit alone, and another bit there (`MNT_EXT_ROOT_DATA_VOL`,
    /// `0x1`, the startup disk's Data volume) is not taken for it. The reply is the temp folder's real
    /// one, with its name and flags stood in.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_fskit_mount_is_flagged_whatever_it_calls_itself() {
        let mut out = statfs(&File::open(std::env::temp_dir()).unwrap()).unwrap();
        out.f_fstypename.fill(0);
        for (slot, byte) in out.f_fstypename.iter_mut().zip(b"apfs") {
            *slot = libc::c_char::from_ne_bytes([*byte]);
        }
        out.f_flags_ext = MNT_EXT_FSKIT;
        assert_eq!(named(&out), ("apfs".to_owned(), true));
        out.f_flags_ext = 0x1 | MNT_EXT_FSKIT;
        assert_eq!(named(&out), ("apfs".to_owned(), true));
        out.f_flags_ext = 0x1;
        assert_eq!(named(&out), ("apfs".to_owned(), false));
        out.f_flags_ext = 0;
        assert_eq!(named(&out), ("apfs".to_owned(), false));
    }
}
