# Source this before cargo:  . scripts/dev-env.sh  (scripts/check.sh and release.sh do, on every platform)
# Everywhere it puts ~/.cargo/bin on PATH, when it exists: a shell that has not loaded rustup's profile
# (macOS's non-login bash, say) then still finds cargo and the cargo-deny/cargo-audit installs there.
# On a Windows machine using the GNU toolchain it also puts WinLibs' bin (dlltool, objdump, gcc) on PATH.
# Why: tokio, getrandom, parking_lot_core and windows-sys link through windows-link's raw-dylib, which on
# x86_64-pc-windows-gnu needs dlltool. WinLibs (winget BrechtSanders.WinLibs.POSIX.MSVCRT, user scope, no
# admin) provides it, but winget does not link dlltool into its Links folder, so its bin goes on PATH here.
# MSVC toolchains and macOS need nothing from that second part. The release workflow's Windows runner
# has no WinLibs: it puts MSYS2's MinGW-w64 bin on PATH itself (.github/workflows/release.yml).
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"
# ${LOCALAPPDATA:-}: scripts/check.sh and release.sh source this under `set -u`, and macOS has no LOCALAPPDATA.
if [ -n "${LOCALAPPDATA:-}" ]; then
  for d in "$(cygpath "$LOCALAPPDATA" 2>/dev/null || echo "$LOCALAPPDATA")"/Microsoft/WinGet/Packages/BrechtSanders.WinLibs.*/mingw64/bin; do
    [ -x "$d/dlltool.exe" ] && PATH="$d:$PATH" && break
  done
fi
export PATH
