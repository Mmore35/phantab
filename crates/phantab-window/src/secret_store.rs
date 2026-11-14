//! OS protection for one small secret at rest (THREAT-MODEL SR-62): the Bitwarden CLI session key that
//! phantab's built-in sign-in source keeps between service starts. Never a master password.
//!
//! - Windows: DPAPI, `CurrentUser` scope ([`protect`], [`unprotect`]). The caller keeps the blob in a file
//!   in its owner-only folder; only this Windows account (or an administrator) can open it.
//! - macOS: a generic-password item in the login Keychain ([`keychain_set`], [`keychain_get`],
//!   [`keychain_delete`]), through the Security framework. The item's access list names the binary that
//!   stored it; after an update the binary's signature differs, so macOS asks the owner once ("Always
//!   Allow" ends it). That is normal Keychain behaviour and kept (docs/BITWARDEN.md § Design decisions).
//!   A store always makes a new item, so its access list is always phantab's own: an item another
//!   program planted under the same name beforehand, with an access list that lets it read, is deleted
//!   first, never updated in place. Every call opens the login keychain by its path and uses it alone,
//!   never the default keychain or the search list, which a same-user program can point at a keychain
//!   of its own.
//!
//! Test builds (this crate's unit tests, and `test-seams`, which a release build cannot turn on) never
//! open the login keychain: every call uses the scratch keychain a test made ([`test_keychain`]), and
//! fails when there is none. This crate's integration tests and doctests link it with `test-seams` too
//! (its own dev-dependency on itself).
//!
//! The OS calls that need `unsafe` live in `secret_win32` and `secret_mac` (SR-58). Every plaintext
//! buffer handed back is [`Zeroizing`], and the copies the OS allocated are wiped before they are freed
//! (on macOS, the buffer a read returns; what the Security framework copies inside its own calls is
//! out of reach).

use zeroize::Zeroizing;

/// DPAPI-protects `plain` for this Windows account. `entropy` is mixed in, so another program calling
/// `CryptUnprotectData` on the blob needs it too (it raises the bar against casual tools, not against
/// code running as the owner: THREAT-MODEL R1).
///
/// # Errors
/// The OS refused (no user profile loaded, say).
#[cfg(windows)]
pub fn protect(plain: &[u8], entropy: &[u8]) -> std::io::Result<Vec<u8>> {
    crate::secret_win32::protect(plain, entropy)
}

/// Opens a blob [`protect`] made with the same `entropy`, for this Windows account only.
///
/// # Errors
/// A blob from another account or machine, another entropy, or a damaged blob.
#[cfg(windows)]
pub fn unprotect(blob: &[u8], entropy: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
    crate::secret_win32::unprotect(blob, entropy)
}

/// The Keychain's "item not found" (`errSecItemNotFound`).
#[cfg(all(test, target_os = "macos"))]
const ITEM_NOT_FOUND: i32 = crate::secret_mac::ITEM_NOT_FOUND;
/// The Keychain's "already exists" (`errSecDuplicateItem`).
#[cfg(target_os = "macos")]
const DUPLICATE_ITEM: i32 = crate::secret_mac::DUPLICATE_ITEM;

/// The owner's login keychain file under `home`.
#[cfg(target_os = "macos")]
fn login_keychain_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join("Library/Keychains/login.keychain-db")
}

/// The owner's login keychain, opened by its path (`~/Library/Keychains/login.keychain-db`): the one
/// keychain every call here uses, so a keychain another program made the default never takes part. The
/// home folder is the user database's for the real user ID, never `$HOME`, which whoever starts phantab
/// can set to a folder holding a keychain of their own.
#[cfg(all(target_os = "macos", not(any(test, feature = "test-seams"))))]
fn login_keychain() -> std::io::Result<security_framework::os::macos::keychain::SecKeychain> {
    let home = crate::secret_mac::real_home()?;
    security_framework::os::macos::keychain::SecKeychain::open(login_keychain_path(&home))
        .map_err(keychain_error)
}

/// Test builds: the scratch keychain a test made ([`test_keychain`]) in place of the login keychain,
/// which a test build never opens.
#[cfg(all(target_os = "macos", any(test, feature = "test-seams")))]
fn login_keychain() -> std::io::Result<security_framework::os::macos::keychain::SecKeychain> {
    test_keychain::current()
}

/// Test builds only (this crate's unit tests, and `test-seams`, which a release build cannot turn on):
/// the scratch keychain that stands in for the login keychain, so no test reads, writes or deletes an
/// item in the owner's. A [`TestKeychain`] serves the thread that made it; [`use_for_process`] serves a
/// whole process (the phantab binary a test runs). With neither, every Keychain call fails. A path that
/// is or may be one of the owner's keychains is refused wherever it comes from ([`refuse_login`]).
///
/// `SecKeychainCreate` puts a keychain on the search list only when its path holds `/login.keychain`
/// (Apple's `StorageManager.cpp`: "Creation of a private keychain should not modify the search list"),
/// so a scratch keychain never joins the user's search list or becomes the default keychain. A test
/// reads both before, during and after one and finds them the same; nothing here sets either.
#[cfg(all(target_os = "macos", any(test, feature = "test-seams")))]
pub mod test_keychain {
    use std::cell::RefCell;
    use std::fmt::Write as _;
    use std::io;
    use std::marker::PhantomData;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use security_framework::os::macos::keychain::{CreateOptions, KeychainSettings, SecKeychain};

    use super::keychain_error;

    /// What [`super::login_keychain`] says when a test made no scratch keychain (`ErrorKind::Other`).
    pub const NONE: &str = "a test build never opens the login keychain, and no test keychain is set";
    /// The end of every refusal of a path that is or may be the owner's ([`refuse_login`]), whose kind
    /// is `ErrorKind::PermissionDenied`.
    pub const REFUSED: &str = "a test never uses it";

    /// A scratch keychain: its file and password.
    #[derive(Clone)]
    struct Scratch {
        path: PathBuf,
        password: String,
    }

    thread_local! {
        static HERE: RefCell<Option<Scratch>> = const { RefCell::new(None) };
    }
    static PROCESS: OnceLock<Scratch> = OnceLock::new();
    /// Keychain calls in a test build never show a dialog (a locked keychain, an access prompt): they
    /// fail instead. Kept off for the life of the process.
    static NO_DIALOG: OnceLock<Option<security_framework::os::macos::keychain::KeychainUserInteractionLock>> =
        OnceLock::new();

    fn no_dialog() {
        NO_DIALOG.get_or_init(|| SecKeychain::disable_user_interaction().ok());
    }

    /// A keychain `SecKeychainCreate` made in a new owner-only folder under the temporary folder, locked
    /// by a random password: the one every Keychain call on the thread that made it uses. Dropping it,
    /// also while a panic unwinds, deletes it (`SecKeychainDelete`) and its folder; [`Self::delete`] does
    /// the same and says whether both went. Not `Send`: it serves the thread that made it, and dropped
    /// on another it would leave this thread's choice naming a deleted keychain.
    pub struct TestKeychain {
        dir: PathBuf,
        scratch: Scratch,
        /// Set once the keychain and its folder are deleted.
        deleted: bool,
        /// Neither `Send` nor `Sync`.
        _thread: PhantomData<*const ()>,
    }

    impl std::fmt::Debug for TestKeychain {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestKeychain").field("path", &self.scratch.path).finish_non_exhaustive()
        }
    }

    impl TestKeychain {
        /// # Errors
        /// The folder or the keychain could not be made, or this thread already has one
        /// (`ErrorKind::AlreadyExists`).
        pub fn create() -> io::Result<Self> {
            if HERE.with_borrow(Option::is_some) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "this thread already has a test keychain",
                ));
            }
            no_dialog();
            let dir = std::env::temp_dir().join(format!("phantab-test-keychain-{}", random(12)?));
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
            let made = Self::create_in(&dir);
            if made.is_err() {
                let _ = std::fs::remove_dir_all(&dir);
            }
            made
        }

        fn create_in(dir: &Path) -> io::Result<Self> {
            let scratch = Scratch { path: dir.join("phantab-test.keychain-db"), password: random(32)? };
            refuse_login(&scratch.path)?;
            let mut keychain = CreateOptions::new()
                .password(&scratch.password)
                .prompt_user(false)
                .create(&scratch.path)
                .map_err(keychain_error)?;
            let made = Self {
                dir: dir.to_path_buf(),
                scratch: scratch.clone(),
                deleted: false,
                _thread: PhantomData,
            };
            // From here on, dropping `made` deletes the keychain.
            let mut settings = KeychainSettings::new();
            settings.set_lock_on_sleep(false);
            settings.set_lock_interval(None);
            keychain.set_settings(&settings).map_err(keychain_error)?;
            HERE.with_borrow_mut(|here| *here = Some(scratch));
            Ok(made)
        }

        /// The keychain's file, to hand to a child ([`use_for_process`]).
        pub fn path(&self) -> &Path {
            &self.scratch.path
        }

        /// The keychain's password, to hand to a child ([`use_for_process`]).
        pub fn password(&self) -> &str {
            &self.scratch.password
        }

        /// Deletes the keychain (`SecKeychainDelete`) and its folder now, as dropping it does.
        ///
        /// # Errors
        /// The keychain could not be opened or deleted, its file is still there after the delete, or
        /// the folder could not be removed. The folder is removed either way.
        pub fn delete(mut self) -> io::Result<()> {
            self.remove()
        }

        fn remove(&mut self) -> io::Result<()> {
            if std::mem::replace(&mut self.deleted, true) {
                return Ok(());
            }
            HERE.with_borrow_mut(|here| {
                if here.as_ref().is_some_and(|s| s.path == self.scratch.path) {
                    *here = None;
                }
            });
            let keychain = SecKeychain::open(&self.scratch.path)
                .map_err(keychain_error)
                .and_then(|k| crate::secret_mac::delete_keychain(&k).map_err(super::os_error));
            let keychain = match keychain {
                Ok(()) if std::fs::symlink_metadata(&self.scratch.path).is_ok() => {
                    Err(io::Error::other("SecKeychainDelete left the keychain's file"))
                }
                done => done,
            };
            let folder = std::fs::remove_dir_all(&self.dir);
            keychain.and(folder)
        }
    }

    impl Drop for TestKeychain {
        fn drop(&mut self) {
            let _ = self.remove();
        }
    }

    /// Makes the keychain at `path`, unlocked with `password`, the one every Keychain call in this
    /// process uses (a thread's own [`TestKeychain`] still comes first). Set once.
    ///
    /// # Errors
    /// The path is not absolute (`ErrorKind::InvalidInput`), is or may be the owner's ([`refuse_login`]),
    /// or one is set already (`ErrorKind::AlreadyExists`).
    pub fn use_for_process(path: &Path, password: &str) -> io::Result<()> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a test keychain is named by an absolute path",
            ));
        }
        refuse_login(path)?;
        no_dialog();
        PROCESS.set(Scratch { path: path.to_path_buf(), password: password.to_owned() }).map_err(|_| {
            io::Error::new(io::ErrorKind::AlreadyExists, "a test keychain is set for this process already")
        })
    }

    /// The scratch keychain for this call, unlocked; never the login keychain.
    ///
    /// The unlock is no defence: while the owner is logged in his login keychain is unlocked, and
    /// securityd then accepts any password (`KeychainDatabase::makeUnlocked` checks it only when the
    /// keychain is locked). [`refuse_login`] is the whole defence. It checks the path, not the file
    /// opened: a same-user process that swaps the path between the check and the call is not stopped.
    /// Nothing here can pin the file, because the open is lazy and the Security framework works by path
    /// and rewrites a keychain by a temporary file and a rename (`AtomicFile.cpp`), so its inode changes
    /// on every write. Such a swap reaches only the test-only service names (`dev.phantab.test.*`),
    /// never `dev.phantab.bitwarden` (THREAT-MODEL R21).
    pub(super) fn current() -> io::Result<SecKeychain> {
        let scratch = chosen(HERE.with_borrow(Clone::clone), PROCESS.get())?;
        refuse_login(&scratch.path)?;
        let mut keychain = SecKeychain::open(&scratch.path).map_err(keychain_error)?;
        keychain.unlock(Some(&scratch.password)).map_err(keychain_error)?;
        Ok(keychain)
    }

    /// The thread's scratch keychain `here`, else the process's, else an error ([`NONE`]): never the
    /// login keychain.
    fn chosen(here: Option<Scratch>, process: Option<&Scratch>) -> io::Result<Scratch> {
        here.or_else(|| process.cloned()).ok_or_else(|| io::Error::other(NONE))
    }

    /// Refuses a path that is or may be one of the owner's keychains, so a test never opens one. It
    /// fails closed: whatever it cannot resolve or read is refused.
    /// - a `.` or `..` in it, or a file named `login.keychain` in any case;
    /// - anything in `~/Library/Keychains` (the home from the user database), in any case, by the path
    ///   as given, by its folder's real path, and (when it exists) by its own real path;
    /// - a path whose folder cannot be resolved;
    /// - a symbolic link, or a file with more than one link (a hard link);
    /// - the same file (device and inode) as any file in `~/Library/Keychains`, its subfolders included.
    ///
    /// # Errors
    /// `ErrorKind::PermissionDenied`, ending in [`REFUSED`], when the path is refused; or the home
    /// folder cannot be read.
    pub fn refuse_login(path: &Path) -> io::Result<()> {
        let login = super::login_keychain_path(&crate::secret_mac::real_home()?);
        refuse_owners(path, login.parent().unwrap_or(&login))
    }

    /// [`refuse_login`] against the owner's keychains folder `keychains`.
    fn refuse_owners(path: &Path, keychains: &Path) -> io::Result<()> {
        let refused = |why: &str| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is or may be the owner's keychain ({why}): {REFUSED}", path.display()),
            )
        };
        if path.as_os_str().as_bytes().split(|&b| b == b'/').any(|c| c == b"." || c == b"..") {
            return Err(refused("a `.` or `..` in it"));
        }
        if path.file_name().is_some_and(|n| n.to_string_lossy().to_lowercase().starts_with("login.keychain"))
        {
            return Err(refused("named login.keychain"));
        }
        let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
        let mut owners = vec![lower(keychains)];
        owners.extend(std::fs::canonicalize(keychains).ok().map(|p| lower(&p)));
        let inside = |p: &Path| {
            let p = lower(p);
            owners.iter().any(|o| p.starts_with(o))
        };
        if inside(path) {
            return Err(refused("in ~/Library/Keychains"));
        }
        let folder =
            path.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| refused("no folder"))?;
        let folder = std::fs::canonicalize(folder).map_err(|_| refused("its folder cannot be resolved"))?;
        if inside(&folder) {
            return Err(refused("its folder is in ~/Library/Keychains"));
        }
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(refused("it cannot be read")),
        };
        if meta.file_type().is_symlink() {
            return Err(refused("a link"));
        }
        if meta.nlink() > 1 {
            return Err(refused("a file with more than one link"));
        }
        let real = std::fs::canonicalize(path).map_err(|_| refused("it cannot be resolved"))?;
        if inside(&real) {
            return Err(refused("it is in ~/Library/Keychains"));
        }
        let mut files = Vec::new();
        files_in(keychains, &mut files).map_err(|_| refused("~/Library/Keychains cannot be read"))?;
        if files.contains(&(meta.dev(), meta.ino())) {
            return Err(refused("the same file as one in ~/Library/Keychains"));
        }
        Ok(())
    }

    /// Adds the device and inode of every file under `dir` to `files`, subfolders included, links not
    /// followed. A folder or entry that is gone holds none: any write to a keychain in the folder (by
    /// any app) makes a temporary `<name>.sb-<hex>-<random>` beside it and renames it over the keychain,
    /// holding a `.fl<hash>` lock file meanwhile (Apple's `AtomicFile.cpp`), so entries vanish between
    /// the listing and the `lstat`. A file that is gone is not the candidate, and one renamed is listed
    /// under its new name or has more than one link. Any other error is returned, and refuses.
    fn files_in(dir: &Path, files: &mut Vec<(u64, u64)>) -> io::Result<()> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        for entry in entries {
            add(&entry?.path(), files)?;
        }
        Ok(())
    }

    /// [`files_in`] for one entry `path`.
    fn add(path: &Path, files: &mut Vec<(u64, u64)>) -> io::Result<()> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if meta.is_dir() {
            files_in(path, files)
        } else {
            files.push((meta.dev(), meta.ino()));
            Ok(())
        }
    }

    /// `bytes` random bytes from the system's generator, in hex.
    fn random(bytes: usize) -> io::Result<String> {
        let mut buf = vec![0u8; bytes];
        security_framework::random::SecRandom::default().copy_bytes(&mut buf)?;
        let mut hex = String::with_capacity(bytes * 2);
        for b in buf {
            let _ = write!(hex, "{b:02x}");
        }
        Ok(hex)
    }

    /// The guard and the choice on their own: a stand-in keychains folder, never the owner's, and no
    /// global state.
    #[cfg(test)]
    mod tests {
        use super::*;

        /// A folder of its own under the temporary folder, by its real path; removed on drop.
        struct Folder(PathBuf);

        impl Folder {
            fn new() -> Self {
                let dir = std::env::temp_dir().join(format!("phantab-test-guard-{}", random(12).unwrap()));
                std::fs::create_dir(&dir).unwrap();
                Self(std::fs::canonicalize(&dir).unwrap())
            }
        }

        impl Drop for Folder {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// Whether `refuse_owners` refuses `path`, checking a refusal's kind and text.
        fn refused(path: &Path, keychains: &Path) -> bool {
            match refuse_owners(path, keychains) {
                Ok(()) => false,
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
                    assert!(e.to_string().ends_with(REFUSED), "{e}");
                    true
                }
            }
        }

        #[test]
        fn with_no_scratch_keychain_none_is_chosen() {
            let mine = Scratch { path: PathBuf::from("/thread.keychain-db"), password: String::new() };
            let process = Scratch { path: PathBuf::from("/process.keychain-db"), password: String::new() };
            let Err(e) = chosen(None, None) else { panic!("a keychain was chosen from none") };
            assert_eq!((e.kind(), e.to_string()), (io::ErrorKind::Other, NONE.to_owned()));
            assert_eq!(chosen(None, Some(&process)).unwrap().path, process.path);
            assert_eq!(chosen(Some(mine.clone()), Some(&process)).unwrap().path, mine.path);
        }

        #[test]
        fn the_guard_refuses_links_dots_unresolved_folders_and_the_owners_files() {
            // A stand-in for ~/Library/Keychains, with a file in a subfolder as the data-protection
            // keychain has.
            let root = Folder::new();
            let keychains = root.0.join("Keychains");
            std::fs::create_dir_all(keychains.join("uuid")).unwrap();
            let deep = keychains.join("uuid").join("keychain-2.db");
            std::fs::write(&deep, b"stand-in").unwrap();
            std::fs::write(keychains.join("other.keychain-db"), b"stand-in").unwrap();
            let out = root.0.join("out");
            std::fs::create_dir(&out).unwrap();
            let plain = out.join("plain.keychain-db");
            std::fs::write(&plain, b"x").unwrap();
            // Accepted: a new path, and a plain file of its own, in a folder outside; also with no
            // keychains folder at all.
            assert!(!refused(&out.join("new.keychain-db"), &keychains));
            assert!(!refused(&plain, &keychains));
            assert!(!refused(&plain, &root.0.join("none")));
            // Every file's device and inode, the subfolder's too.
            let mut files = Vec::new();
            files_in(&keychains, &mut files).unwrap();
            let id = |p: &Path| {
                let m = std::fs::symlink_metadata(p).unwrap();
                (m.dev(), m.ino())
            };
            assert!(files.contains(&id(&deep)) && files.len() == 2, "{files:?}");
            let link = out.join("link.keychain-db");
            std::os::unix::fs::symlink(keychains.join("other.keychain-db"), &link).unwrap();
            let hard = out.join("hard.keychain-db");
            std::fs::hard_link(&deep, &hard).unwrap();
            let folder_link = root.0.join("folder-link");
            std::os::unix::fs::symlink(&keychains, &folder_link).unwrap();
            for path in [
                keychains.join("x.keychain-db"),
                PathBuf::from(keychains.to_string_lossy().to_uppercase()).join("x.keychain-db"),
                out.join("Login.Keychain-db"),
                link,
                hard,
                folder_link.join("x.keychain-db"),
                out.join("..").join("Keychains").join("x.keychain-db"),
                out.join(".").join("x.keychain-db"),
                out.join("missing").join("x.keychain-db"),
                PathBuf::from("x.keychain-db"),
            ] {
                assert!(refused(&path, &keychains), "{}", path.display());
            }
        }

        #[test]
        fn the_scan_skips_what_vanished_but_refuses_what_it_cannot_read() {
            let root = Folder::new();
            let keychains = root.0.join("Keychains");
            std::fs::create_dir(&keychains).unwrap();
            let kept = keychains.join("other.keychain-db");
            std::fs::write(&kept, b"stand-in").unwrap();
            let plain = root.0.join("plain.keychain-db");
            std::fs::write(&plain, b"x").unwrap();
            // A keychain write's temporary and lock files, listed and then gone, and a subfolder gone
            // the same way: none is a file, so the scan goes on and the path is accepted.
            let mut files = Vec::new();
            add(&keychains.join("other.keychain-db.sb-1a2b3c4d-XyZ123"), &mut files).unwrap();
            add(&keychains.join(".fl43E0A1B7"), &mut files).unwrap();
            files_in(&keychains.join("gone-uuid"), &mut files).unwrap();
            assert!(files.is_empty(), "{files:?}");
            add(&kept, &mut files).unwrap();
            assert_eq!(files.len(), 1);
            assert!(!refused(&plain, &keychains));
            // A subfolder that cannot be listed still refuses (unless this user can list it anyway).
            let locked = keychains.join("locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
            let unreadable = std::fs::read_dir(&locked).is_err();
            let refusal = refuse_owners(&plain, &keychains);
            std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
            if unreadable {
                let e = refusal.unwrap_err();
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
                assert!(e.to_string().contains("~/Library/Keychains cannot be read"), "{e}");
            }
        }
    }
}

/// Stores `secret` as the generic-password item `service`/`account` in the login keychain,
/// always as a new item: every existing one under that name is deleted first, then one is added with
/// the default access list (this binary only). security-framework's `set_generic_password` updates an
/// existing item in place instead, which keeps whatever access list it was created with: a same-user
/// program could plant the item first, readable by itself, and read every session stored after
/// (sec-creds-2). An item that is back between the delete and the add is refused, never updated.
///
/// The secret goes to the Security framework in a `CFData` over a [`Zeroizing`] copy, wiped when the
/// framework releases it.
///
/// # Errors
/// The Keychain refused (locked, the owner denied access, or an item it could not delete), or an item
/// appeared under the name again before the add.
#[cfg(target_os = "macos")]
pub fn keychain_set(service: &str, account: &str, secret: &[u8]) -> std::io::Result<()> {
    use core_foundation::data::CFData;
    use security_framework::item::Location;
    use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass};
    let login = login_keychain()?;
    crate::secret_mac::delete_generic_passwords(&login, service, account).map_err(os_error)?;
    let data = CFData::from_arc(std::sync::Arc::new(Zeroizing::new(secret.to_vec())));
    let mut add = ItemAddOptions::new(ItemAddValue::Data { class: ItemClass::generic_password(), data });
    add.set_service(service).set_account_name(account).set_location(Location::FileKeychain(login));
    match add.add() {
        Ok(()) => Ok(()),
        Err(e) if e.code() == DUPLICATE_ITEM => Err(std::io::Error::other(
            "a Keychain item under phantab's name came back while it was being replaced; nothing was stored",
        )),
        Err(e) => Err(keychain_error(e)),
    }
}

/// The item's secret, or `None` when there is no such item. The buffer the Keychain returns it in is
/// wiped before it is freed (`secret_mac`).
///
/// # Errors
/// The Keychain refused (locked, or the owner denied access).
#[cfg(target_os = "macos")]
pub fn keychain_get(service: &str, account: &str) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    crate::secret_mac::find_generic_password(&login_keychain()?, service, account).map_err(os_error)
}

/// Deletes every item under the name in the login keychain. `Ok(false)` when there was none.
///
/// # Errors
/// The Keychain refused.
#[cfg(target_os = "macos")]
pub fn keychain_delete(service: &str, account: &str) -> std::io::Result<bool> {
    crate::secret_mac::delete_generic_passwords(&login_keychain()?, service, account)
        .map(|deleted| deleted > 0)
        .map_err(os_error)
}

/// The OS status only: a Keychain error's text names the item, never its secret, but the code is enough.
#[cfg(target_os = "macos")]
fn keychain_error(e: security_framework::base::Error) -> std::io::Error {
    os_error(e.code())
}

/// An OS status as an error.
#[cfg(target_os = "macos")]
fn os_error(code: i32) -> std::io::Error {
    std::io::Error::other(format!("Keychain error {code}"))
}

/// The Keychain tests, each in a scratch keychain of its own ([`test_keychain::TestKeychain`]), never
/// the login keychain, and under a service name only tests use (never phantab's `dev.phantab.bitwarden`).
#[cfg(all(test, target_os = "macos"))]
mod keychain_tests {
    use security_framework::item::{
        ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Location, SearchResult,
    };

    use super::test_keychain::{NONE, REFUSED, TestKeychain, refuse_login, use_for_process};
    use super::*;

    const SERVICE: &str = "dev.phantab.test.secret-store";

    fn account(name: &str) -> String {
        format!("{name}-{}", std::process::id())
    }

    /// Whether `e` is the error of a call with no scratch keychain.
    fn is_none(e: &std::io::Error) -> bool {
        e.kind() == std::io::ErrorKind::Other && e.to_string() == NONE
    }

    /// Whether `e` is the guard's refusal of a path that is or may be the owner's.
    fn is_refused(e: &std::io::Error) -> bool {
        e.kind() == std::io::ErrorKind::PermissionDenied && e.to_string().ends_with(REFUSED)
    }

    /// Each item under the name in this thread's scratch keychain, as its attributes (`labl` is the
    /// label). It searches that keychain alone.
    fn items(account: &str) -> std::io::Result<Vec<std::collections::HashMap<String, String>>> {
        match ItemSearchOptions::new()
            .keychains(&[login_keychain()?])
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(account)
            .load_attributes(true)
            .limit(Limit::All)
            .search()
        {
            Ok(found) => Ok(found.iter().filter_map(SearchResult::simplify_dict).collect()),
            Err(e) => {
                assert_eq!(e.code(), ITEM_NOT_FOUND, "the Keychain search failed");
                Ok(vec![])
            }
        }
    }

    fn get(account: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(keychain_get(SERVICE, account)?.map(|s| s.to_vec()))
    }

    #[test]
    fn a_test_build_never_opens_the_login_keychain() {
        // No scratch keychain on this thread: every call fails, for that reason. (The rule itself, with
        // no global state, is `test_keychain`'s `with_no_scratch_keychain_none_is_chosen`; nothing in
        // this binary sets one for the process, since `use_for_process` is only ever refused here.)
        let none = account("none");
        for e in [
            keychain_get(SERVICE, &none).unwrap_err(),
            keychain_set(SERVICE, &none, b"x").unwrap_err(),
            keychain_delete(SERVICE, &none).unwrap_err(),
        ] {
            assert!(is_none(&e), "{e}");
        }
        // The owner's keychains are refused by name and by folder, before anything opens them.
        let home = crate::secret_mac::real_home().unwrap();
        let keychains = home.join("Library").join("Keychains");
        for owners in [
            login_keychain_path(&home),
            keychains.join("other.keychain-db"),
            home.join("library").join("KEYCHAINS").join("x.keychain-db"),
            std::env::temp_dir().join("Login.Keychain-db"),
        ] {
            let e = refuse_login(&owners).unwrap_err();
            assert!(is_refused(&e), "{}: {e}", owners.display());
            let e = use_for_process(&owners, "x").unwrap_err();
            assert!(is_refused(&e), "{}: {e}", owners.display());
        }
        let e = use_for_process(std::path::Path::new("relative.keychain-db"), "x").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
        // A scratch keychain is none of them.
        let scratch = TestKeychain::create().unwrap();
        refuse_login(scratch.path()).unwrap();
        assert!(scratch.path().starts_with(std::env::temp_dir()), "{}", scratch.path().display());
        let e = TestKeychain::create().unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "one per thread: {e}");
        // A link to the login keychain, beside the scratch one: refused, and the file it names is never
        // opened (making the link reads nothing of it).
        let link = scratch.path().with_file_name("link.keychain-db");
        std::os::unix::fs::symlink(login_keychain_path(&home), &link).unwrap();
        let e = refuse_login(&link).unwrap_err();
        assert!(is_refused(&e), "{e}");
        let e = use_for_process(&link, "x").unwrap_err();
        assert!(is_refused(&e), "{e}");
        scratch.delete().unwrap();
    }

    #[test]
    fn a_test_keychain_changes_neither_the_search_list_nor_the_default_and_is_deleted() {
        // Read only: the user's keychain search list and default keychain, by path. Nothing here sets
        // either, and a scratch keychain must not change them: before, while it exists, after.
        let before = crate::secret_mac::user_search_list_and_default().unwrap();
        let scratch = TestKeychain::create().unwrap();
        let path = scratch.path().to_path_buf();
        assert!(path.is_file(), "{}", path.display());
        let during = crate::secret_mac::user_search_list_and_default().unwrap();
        assert_eq!(during, before, "while a scratch keychain exists");
        let real = std::fs::canonicalize(&path).unwrap();
        let named = |p: &std::path::PathBuf| *p == path || *p == real;
        assert!(!during.0.iter().any(named) && !during.1.as_ref().is_some_and(named), "{during:?}");
        // The delete itself succeeds (`SecKeychainDelete`, then the folder), and leaves nothing.
        scratch.delete().unwrap();
        assert!(!path.exists() && !path.parent().unwrap().exists(), "{}", path.display());
        let e = keychain_get(SERVICE, &account("dropped")).unwrap_err();
        assert!(is_none(&e), "the thread has none again: {e}");
        // Dropped while a panic unwinds: also gone.
        let (tx, rx) = std::sync::mpsc::channel();
        let panicked = std::thread::spawn(move || {
            let scratch = TestKeychain::create().unwrap();
            tx.send(scratch.path().to_path_buf()).unwrap();
            panic!("a failing test");
        })
        .join();
        assert!(panicked.is_err());
        let path = rx.recv().unwrap();
        assert!(!path.exists() && !path.parent().unwrap().exists(), "{}", path.display());
        let after = crate::secret_mac::user_search_list_and_default().unwrap();
        assert_eq!(after, before, "after both are deleted");
    }

    #[test]
    fn a_store_replaces_a_planted_item_with_a_new_one() {
        let _scratch = TestKeychain::create().unwrap();
        let account = account("planted");
        let _ = keychain_delete(SERVICE, &account);
        // Another program's item under the same name, which that program could read back.
        let data = core_foundation::data::CFData::from_buffer(b"planted value");
        ItemAddOptions::new(ItemAddValue::Data { class: ItemClass::generic_password(), data })
            .set_service(SERVICE)
            .set_account_name(&account)
            .set_label("planted-by-test")
            .set_location(Location::FileKeychain(login_keychain().unwrap()))
            .add()
            .unwrap();
        assert_eq!(items(&account).unwrap().len(), 1);
        keychain_set(SERVICE, &account, b"fresh value").unwrap();
        let after = items(&account).unwrap();
        assert_eq!(after.len(), 1, "one item under the name");
        assert_ne!(after[0].get("labl").map(String::as_str), Some("planted-by-test"), "a new item");
        assert_eq!(get(&account).unwrap().as_deref(), Some(&b"fresh value"[..]));
        assert!(keychain_delete(SERVICE, &account).unwrap());
        assert_eq!(get(&account).unwrap(), None);
        assert!(!keychain_delete(SERVICE, &account).unwrap());
    }

    #[test]
    fn a_second_store_replaces_the_first() {
        let _scratch = TestKeychain::create().unwrap();
        let account = account("twice");
        let _ = keychain_delete(SERVICE, &account);
        keychain_set(SERVICE, &account, b"one").unwrap();
        keychain_set(SERVICE, &account, b"two").unwrap();
        assert_eq!(items(&account).unwrap().len(), 1);
        assert_eq!(get(&account).unwrap().as_deref(), Some(&b"two"[..]));
        keychain_delete(SERVICE, &account).unwrap();
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn a_blob_opens_only_with_its_entropy() {
        let plain = b"not a real session key";
        let blob = protect(plain, b"phantab-test-entropy").unwrap();
        assert!(!blob.windows(plain.len()).any(|w| w == plain), "the blob holds no plaintext");
        assert_eq!(&unprotect(&blob, b"phantab-test-entropy").unwrap()[..], plain);
        assert!(unprotect(&blob, b"other entropy").is_err());
        let mut damaged = blob.clone();
        if let Some(last) = damaged.last_mut() {
            *last ^= 0xff;
        }
        assert!(unprotect(&damaged, b"phantab-test-entropy").is_err());
        assert!(unprotect(&[], b"phantab-test-entropy").is_err());
    }
}
