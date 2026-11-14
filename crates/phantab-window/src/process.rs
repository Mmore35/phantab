//! Process hardening that needs an OS call (THREAT-MODEL SR-59), kept here so `unsafe` stays in this
//! crate's OS modules (SR-58).

/// Turns core dumps off for this process (macOS and other unix: `RLIMIT_CORE = 0`). Windows writes no
/// core file for a process unless Windows Error Reporting is configured to, so it is a no-op there.
///
/// # Errors
/// The OS refused the limit.
pub fn disable_core_dumps() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        crate::secure_unix::disable_core_dumps()
    }
    #[cfg(not(unix))]
    {
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn the_core_limit_is_zero_afterwards() {
        super::disable_core_dumps().unwrap();
        let mut now = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
        // SAFETY: test-only read of this process's limit into a stack value.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut now) };
        assert_eq!((rc, now.rlim_cur, now.rlim_max), (0, 0, 0));
    }
}
