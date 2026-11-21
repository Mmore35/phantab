// run-check: the Windows bundle's harmless test program (docs/INSTALL-WINDOWS.md § 2).
//
// install.ps1 runs it from the bundle folder and from %LOCALAPPDATA% before it installs anything: if
// Windows (AppLocker, WDAC, Smart App Control) refuses a program from those folders, the user learns it
// here, with the reason, instead of after phantab.exe was copied in and Chrome fails to start it.
// It reads nothing, writes nothing and takes no input. Built bare (`rustc`, no crates) by
// scripts/windows-bundle/common.sh. It is signed exactly when phantab.exe is (scripts/sign-windows.sh),
// so what Windows decides about it is what Windows will decide about phantab.exe from the same folder.
fn main() {
    println!("run-check: OK, Windows let this program run from this folder.");
}
