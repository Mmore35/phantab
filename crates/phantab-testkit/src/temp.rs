//! Scratch folders under the system temp directory.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A folder under the system temp directory, removed (with everything in it) on drop.
///
/// Use one for every runtime folder, Chrome profile, config file and guard file
/// a test writes. Named `phantab-<prefix>-<pid>-<n>-<nanos>`.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
    keep: bool,
}

impl TempDir {
    /// Creates a new, empty folder. `prefix` says what it is for (`runtime`, `profile`).
    pub fn new(prefix: &str) -> io::Result<Self> {
        let base = std::env::temp_dir();
        for _ in 0..100 {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("phantab-{prefix}-{}-{n}-{nanos}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, keep: false }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free temp folder name after 100 tries"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }

    /// Writes a file inside the folder, creating parent folders. Returns its path.
    pub fn write(&self, relative: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<PathBuf> {
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, contents)?;
        Ok(path)
    }

    /// Creates a folder inside this one (and its parents). Returns its path.
    pub fn child_dir(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        let path = self.path.join(relative);
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Keeps the folder after drop (a failing test's evidence) and returns its path.
    pub fn keep(mut self) -> PathBuf {
        self.keep = true;
        self.path.clone()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        // Chrome and its helpers can hold profile files for a moment after they exit.
        let mut last = None;
        for attempt in 0..5 {
            match std::fs::remove_dir_all(&self.path) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return,
                Err(e) => last = Some(e),
            }
            if attempt < 4 {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        if let Some(e) = last {
            eprintln!("note: could not remove {}: {e}", self.path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_on_drop() {
        let dir = TempDir::new("unit").unwrap();
        let file = dir.write("a/b/c.txt", "x").unwrap();
        assert!(file.is_file());
        let path = dir.path().to_path_buf();
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn kept_when_asked() {
        let dir = TempDir::new("unit").unwrap();
        dir.child_dir("profile/Default").unwrap();
        let path = dir.keep();
        assert!(path.join("profile/Default").is_dir());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn names_are_unique() {
        let a = TempDir::new("unit").unwrap();
        let b = TempDir::new("unit").unwrap();
        assert_ne!(a.path(), b.path());
        assert!(a.path().file_name().unwrap().to_string_lossy().starts_with("phantab-unit-"));
    }
}
