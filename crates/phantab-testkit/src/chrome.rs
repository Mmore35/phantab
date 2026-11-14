//! Which Chrome a browser test drives, and the names it may register.

use std::ffi::OsString;
use std::path::PathBuf;

/// The variable naming the Chrome executable browser tests run against.
pub const CHROME_ENV: &str = "PHANTAB_TEST_CHROME";

/// The Chrome a browser test should drive, from `PHANTAB_TEST_CHROME`.
///
/// Unset or empty: prints `skip: PHANTAB_TEST_CHROME not set` to stderr and
/// returns `None`, so the test returns early and passes. Browser tests are
/// skipped this way at run time, never `#[ignore]`d (docs/ARCHITECTURE.md).
/// Cargo shows the line with `-- --nocapture`.
///
/// Set to something that is not a file: the test fails. A wrong path is a
/// broken setup, and a silent skip would hide it.
pub fn skip_unless_chrome() -> Option<PathBuf> {
    chrome_from(std::env::var_os(CHROME_ENV))
}

fn chrome_from(value: Option<OsString>) -> Option<PathBuf> {
    match value {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            assert!(path.is_file(), "{CHROME_ENV} is set to {}, which is not a file", path.display());
            Some(path)
        }
        _ => {
            eprintln!("skip: {CHROME_ENV} not set");
            None
        }
    }
}

/// The native-messaging host name a test registers: `dev.phantab.bridge_test_<pid>`.
///
/// Never the real `dev.phantab.bridge`. The registration is per user, so one
/// name per test process keeps two runs from sending each other's Chrome to
/// the wrong service, and the owner's own registration is never read or replaced.
pub fn test_native_host_name() -> String {
    format!("dev.phantab.bridge_test_{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_skips() {
        assert_eq!(chrome_from(None), None);
        assert_eq!(chrome_from(Some(OsString::new())), None);
    }

    #[test]
    fn an_existing_file_is_returned() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(chrome_from(Some(exe.clone().into_os_string())), Some(exe));
    }

    #[test]
    #[should_panic(expected = "which is not a file")]
    fn a_missing_file_fails_the_test() {
        chrome_from(Some(OsString::from("definitely/not/a/chrome.exe")));
    }

    #[test]
    fn host_names_are_test_only() {
        let name = test_native_host_name();
        assert!(name.starts_with("dev.phantab.bridge_test_"));
        assert_ne!(name, "dev.phantab.bridge");
    }
}
