//! Where Google Chrome usually is, for an install that names no `--chrome` or `--user-data-dir`. Only reads:
//! it never opens a profile, only lists the folders that hold a `Preferences` file.

use std::path::{Path, PathBuf};

/// The installed Google Chrome executable, if one is in a standard place.
pub(crate) fn chrome() -> Option<PathBuf> {
    candidates().into_iter().find(|p| p.is_file())
}

#[cfg(windows)]
fn candidates() -> Vec<PathBuf> {
    let tail = Path::new("Google").join("Chrome").join("Application").join("chrome.exe");
    ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
        .into_iter()
        .filter_map(|var| std::env::var_os(var).filter(|v| !v.is_empty()))
        .map(|base| PathBuf::from(base).join(&tail))
        .collect()
}

#[cfg(not(windows))]
fn candidates() -> Vec<PathBuf> {
    let app = Path::new("Google Chrome.app").join("Contents").join("MacOS").join("Google Chrome");
    vec![Path::new("/Applications").join(&app), crate::paths::home().join("Applications").join(&app)]
}

/// Chrome's own user-data dir, when it exists.
pub(crate) fn user_data_dir() -> Option<PathBuf> {
    let dir = if cfg!(windows) {
        PathBuf::from(std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty())?)
            .join("Google")
            .join("Chrome")
            .join("User Data")
    } else {
        crate::paths::home().join("Library").join("Application Support").join("Google").join("Chrome")
    };
    dir.is_dir().then_some(dir)
}

/// Whether `dir` is Chrome's own user-data dir ([`user_data_dir`]), as Chrome compares it (case aside on
/// Windows). A Chrome started with no `--user-data-dir` runs on that one.
pub(crate) fn is_default_user_data_dir(dir: &Path) -> bool {
    user_data_dir().is_some_and(|d| {
        if cfg!(windows) {
            d.as_os_str().to_string_lossy().to_lowercase() == dir.as_os_str().to_string_lossy().to_lowercase()
        } else {
            d == dir
        }
    })
}

/// The profile folders in `user_data_dir` (those with a `Preferences` file), sorted.
pub(crate) fn profiles(user_data_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(user_data_dir) else { return Vec::new() };
    let mut found: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().join("Preferences").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_folders_with_preferences() {
        let dir = tempfile::tempdir().unwrap();
        for (name, prefs) in [("Profile 1", true), ("Default", true), ("Crashpad", false)] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
            if prefs {
                std::fs::write(dir.path().join(name).join("Preferences"), "{}").unwrap();
            }
        }
        std::fs::write(dir.path().join("Local State"), "{}").unwrap();
        assert_eq!(profiles(dir.path()), ["Default", "Profile 1"]);
        assert_eq!(profiles(&dir.path().join("missing")), Vec::<String>::new());
    }
}
