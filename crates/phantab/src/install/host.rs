//! Where Chrome looks up the native host `dev.phantab.bridge`, and what is registered there now.
//!
//! Windows: the default value of an HKCU key names the manifest file. macOS: the manifest itself, in the
//! user-data dir's `NativeMessagingHosts` folder (Chrome reads it from the user-data dir it runs with).
//! The recovery record keeps what was there before and where, so uninstall restores that exact spot.

use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;

use anyhow::Result;
#[cfg(windows)]
use anyhow::bail;

use crate::paths::HOST_NAME;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Site {
    /// The key under HKCU, without the hive.
    #[cfg(windows)]
    Registry(String),
    /// The manifest file.
    #[cfg(not(windows))]
    File(PathBuf),
}

/// The site for this install: `key` (Windows, tests only) or Chrome's own; on macOS the manifest in
/// `user_data_dir`.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn chosen(key: Option<&str>, _user_data_dir: Option<&Path>) -> Result<Site> {
    match key {
        Some(key) => Site::from_location(key),
        None => Ok(Site::Registry(format!(r"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}"))),
    }
}

#[cfg(not(windows))]
pub(crate) fn chosen(key: Option<&str>, user_data_dir: Option<&Path>) -> Result<Site> {
    if key.is_some() {
        anyhow::bail!("--native-host-key is for Windows; on macOS the manifest goes in the user-data dir.");
    }
    let dir = user_data_dir.map_or_else(
        || crate::paths::home().join("Library").join("Application Support").join("Google").join("Chrome"),
        Path::to_path_buf,
    );
    Ok(Site::File(dir.join("NativeMessagingHosts").join(format!("{HOST_NAME}.json"))))
}

impl Site {
    /// A site the recovery record named (`location`).
    #[cfg(windows)]
    pub(crate) fn from_location(location: &str) -> Result<Self> {
        let lower = location.to_ascii_lowercase();
        let mut rest = location;
        for hive in [r"hkey_current_user\", r"hkcu:\", r"hkcu\"] {
            if lower.starts_with(hive) {
                rest = &location[hive.len()..];
                break;
            }
        }
        let rest = rest.trim_matches('\\');
        // Anything still naming a hive (HKLM, HKEY_USERS, …) or a drive is not an HKCU subkey.
        let first = rest.split('\\').next().unwrap_or_default().to_ascii_lowercase();
        if rest.is_empty() || first.starts_with("hk") || first.contains(':') {
            bail!("The native host key must be under HKCU: {location}");
        }
        Ok(Self::Registry(rest.to_owned()))
    }

    #[cfg(not(windows))]
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn from_location(location: &str) -> Result<Self> {
        Ok(Self::File(PathBuf::from(location)))
    }

    /// How the recovery record names this site.
    pub(crate) fn location(&self) -> String {
        match self {
            #[cfg(windows)]
            Self::Registry(key) => format!(r"HKCU\{key}"),
            #[cfg(not(windows))]
            Self::File(path) => path.to_string_lossy().into_owned(),
        }
    }

    /// Whether two record locations name the same site (registry keys ignore case).
    pub(crate) fn same(a: &str, b: &str) -> bool {
        if cfg!(windows) { a.eq_ignore_ascii_case(b) } else { a == b }
    }

    /// What the site holds for Chrome to find, `manifest` written at `manifest_path` on Windows.
    pub(crate) fn value(&self, manifest_path: &Path, manifest: &str) -> String {
        match self {
            #[cfg(windows)]
            Self::Registry(_) => {
                let _ = manifest;
                manifest_path.to_string_lossy().into_owned()
            }
            #[cfg(not(windows))]
            Self::File(_) => {
                let _ = manifest_path;
                manifest.to_owned()
            }
        }
    }

    /// The registration there now: the key's default value, or the manifest file's text.
    pub(crate) fn read(&self) -> Result<Option<String>> {
        match self {
            #[cfg(windows)]
            Self::Registry(key) => registry::read(key),
            #[cfg(not(windows))]
            Self::File(path) => match std::fs::read_to_string(path) {
                Ok(text) => Ok(Some(text)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(anyhow::Error::new(e).context(format!("Could not read {}", path.display()))),
            },
        }
    }

    /// Registers `value`, or removes the registration when `None`.
    pub(crate) fn write(&self, value: Option<&str>) -> Result<()> {
        match self {
            #[cfg(windows)]
            Self::Registry(key) => registry::write(key, value),
            #[cfg(not(windows))]
            Self::File(path) => match value {
                Some(text) => super::fsops::atomic(path, text.as_bytes(), None),
                None => match std::fs::remove_file(path) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        Err(anyhow::Error::new(e).context(format!("Could not remove {}", path.display())))
                    }
                    _ => Ok(()),
                },
            },
        }
    }
}

#[cfg(windows)]
mod registry {
    use anyhow::{Context, Result};
    use windows_registry::CURRENT_USER;

    /// `Ok(None)` for a missing key or value (`ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND`).
    fn found<T>(result: windows_registry::Result<T>) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(e)
                if [0x8007_0002_u32.cast_signed(), 0x8007_0003_u32.cast_signed()].contains(&e.code().0) =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub(super) fn read(key: &str) -> Result<Option<String>> {
        let context = || format!(r"Could not read HKCU\{key}");
        let Some(opened) = found(CURRENT_USER.open(key)).with_context(context)? else { return Ok(None) };
        found(opened.get_string("")).with_context(context)
    }

    /// `None` removes the default value, then the key once nothing is left in it (it never deletes the
    /// key outright, so it never takes a value or subkey someone else put there).
    pub(super) fn write(key: &str, value: Option<&str>) -> Result<()> {
        let context = || format!(r"Could not change HKCU\{key}");
        if let Some(value) = value {
            return CURRENT_USER.create(key).and_then(|k| k.set_string("", value)).with_context(context);
        }
        if found(CURRENT_USER.open(key)).with_context(context)?.is_none() {
            return Ok(());
        }
        let opened = CURRENT_USER.create(key).with_context(context)?;
        found(opened.remove_value("")).with_context(context)?;
        let empty = opened.keys().with_context(context)?.next().is_none()
            && opened.values().with_context(context)?.next().is_none();
        drop(opened);
        if empty {
            CURRENT_USER.remove_tree(key).with_context(context)?;
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn locations_accept_hkcu_prefixes_only() {
        for spec in [r"HKCU\Software\x", r"HKCU:\Software\x", r"HKEY_CURRENT_USER\Software\x", r"Software\x"]
        {
            assert_eq!(
                Site::from_location(spec).unwrap(),
                Site::Registry(r"Software\x".to_owned()),
                "{spec}"
            );
        }
        for bad in [r"HKLM\Software\x", r"HKEY_LOCAL_MACHINE\Software\x", "HKCU\\", r"C:\x"] {
            assert!(Site::from_location(bad).is_err(), "{bad}");
        }
        assert_eq!(Site::Registry(r"Software\x".to_owned()).location(), r"HKCU\Software\x");
        assert!(Site::same(r"HKCU\Software\X", r"hkcu\software\x"));
    }
}
