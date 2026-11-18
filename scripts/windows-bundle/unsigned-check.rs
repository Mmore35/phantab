// unsigned-check: the Windows bundle's harmless test program (docs/INSTALL-WINDOWS.md § 2).
//
// It prints one line and exits 0. It reads nothing, writes nothing and opens no network connection, so
// whether it runs depends only on whether Windows lets an unsigned program run from a user folder
// (AppLocker, WDAC / App Control, Smart App Control, antivirus). It is compiled bare (`rustc`, no
// crates) by scripts/bundle-windows.sh and is unsigned on purpose: that is what it tests.
fn main() {
    println!("unsigned-check: OK, Windows let an unsigned program run from this folder.");
}
