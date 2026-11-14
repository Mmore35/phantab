#!/usr/bin/env bash
# Packs the Windows x64 bundle: one zip a Windows user installs from with no Rust, Node or repo access
# (docs/WORK-LAPTOP.md). Run it on Windows x64 (Git Bash) after release.sh has built the tag's half
# with the extension:
#
#   scripts/release.sh [--build-only] --extension <tag>
#   scripts/bundle-windows.sh [--no-test] <tag>
#
# It writes dist/<tag>/phantab-windows-x64-bundle.zip and its .sha256 (so `release.sh upload <tag>` puts
# it in the draft too). The zip holds one folder, phantab-windows-x64/:
#   phantab.exe          release.sh's binary, checked against its .sha256
#   extension/           the unpacked extension Chrome loads; it must zip to release.sh's extension.zip
#   install.ps1          user-level install, uninstall and the unsigned-program check (no admin)
#   unsigned-check.exe   a harmless unsigned test program (scripts/windows-bundle/unsigned-check.rs)
#   WORK-LAPTOP.md       the quickstart
#   LICENSE, NOTICE      phantab's licence and notice, from the repo root (the bundle refuses without them)
#   THIRD-PARTY-LICENSES the licences of the crates linked into phantab.exe (scripts/third-party-licenses.mjs)
#   build-info.txt       release.sh's build-info for the binary: version, commit, toolchain, lockfile
#                        hashes; no path, user or host name
#   SHA256SUMS.txt       every file's hash; install.ps1 checks them first
# Then it runs scripts/windows-bundle/test-bundle.ps1 on the zip (an install and uninstall into a
# throwaway user folder that never touches this machine's own phantab), unless --no-test.
set -euo pipefail

die() { echo "bundle-windows.sh: $*" >&2; exit 1; }
cd "$(dirname "$0")/.."
. scripts/dev-env.sh

test=1 tag=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-test) test=0 ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) [ -z "$tag" ] || die "one tag only"; tag="$1" ;;
  esac
  shift
done
[ -n "$tag" ] || die "usage: scripts/bundle-windows.sh [--no-test] <tag>"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) ;; *) die "the Windows bundle is built on Windows (Git Bash)" ;; esac
for f in LICENSE NOTICE; do
  [ -f "$f" ] || die "no $f at the repo root: the bundle ships phantab's LICENSE and NOTICE, so it is not built without them"
done

out="dist/$tag"
exe="$out/phantab-windows-x64.exe"
for f in "$exe" "$exe.sha256" "$out/extension.zip" "$out/extension.zip.sha256" "$out/build-info-windows-x64.txt"; do
  [ -f "$f" ] || die "no $f: run scripts/release.sh --extension $tag (add --build-only for a test build) first"
done
sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
[ "$(sha256_of "$exe")" = "$(cut -d' ' -f1 "$exe.sha256")" ] || die "$exe does not match its .sha256"

# install.ps1, WORK-LAPTOP.md and unsigned-check.rs come from this checkout, not from release.sh's
# output, so a release bundle needs the checkout to be the commit release.sh built, unchanged. A
# --build-only test build only warns: testing a script change before committing it is its use.
info="$out/build-info-windows-x64.txt"
built_sha="$(sed -n 's/^sha=//p' "$info")"
built_only="$(sed -n 's/^build_only=//p' "$info")"
if [ "$(git rev-parse HEAD)" != "$built_sha" ] || [ -n "$(git status --porcelain)" ]; then
  [ "$built_only" = 1 ] ||
    die "$tag was built from $built_sha; check that commit out, with no local changes, before bundling it"
  echo "bundle-windows.sh: note: the scripts come from this checkout, not from $built_sha as built (a test build)" >&2
fi

# The unpacked extension must be the very files of extension.zip: zip extension/dist the same
# deterministic way and compare. A rebuild since release.sh ran (other sources) fails here.
work="dist/.build/bundle"
rm -rf "$work"
mkdir -p "$work"
node scripts/zip-deterministic.mjs extension/dist "$work/extension-check.zip" >/dev/null
[ "$(sha256_of "$work/extension-check.zip")" = "$(cut -d' ' -f1 "$out/extension.zip.sha256")" ] ||
  die "extension/dist is not what $out/extension.zip holds; run release.sh --extension $tag again"

# unsigned-check.exe: bare rustc, no crates, the release's target, the same path remap as release.sh so
# the build names no local folder. Small and unsigned on purpose. --no-insert-timestamp: GNU ld writes the
# link time into the PE header otherwise, so the bundle's hash would change on every run.
echo "==> unsigned-check.exe"
sysroot="$(rustc --print sysroot)"
rustc --edition 2021 -C opt-level=s -C strip=symbols -C debuginfo=0 -C link-arg=-Wl,--no-insert-timestamp \
  --target x86_64-pc-windows-gnu \
  "--remap-path-prefix=$(cygpath -w "$HOME")=/user-home" "--remap-path-prefix=$(cygpath -w "$sysroot")=/rustup/toolchain" \
  "--remap-path-prefix=$(cygpath -w "$(pwd)")=/phantab" \
  -o "$work/unsigned-check.exe" scripts/windows-bundle/unsigned-check.rs
MSYS2_ARG_CONV_EXCL='*' node scripts/path-gate.mjs "$(cygpath -w "$work/unsigned-check.exe")" \
  --exact '\Users\' --exact /Users/ --exact /home/ --any-case "$(cygpath -w "$HOME")" ||
  die "unsigned-check.exe names a local path"

echo "==> staging phantab-windows-x64/"
stage="$work/zip/phantab-windows-x64"
mkdir -p "$stage"
cp "$exe" "$stage/phantab.exe"
cp -R extension/dist "$stage/extension"
cp scripts/windows-bundle/install.ps1 "$stage/install.ps1"
cp "$work/unsigned-check.exe" "$stage/unsigned-check.exe"
cp docs/WORK-LAPTOP.md "$stage/WORK-LAPTOP.md"
cp LICENSE "$stage/LICENSE"
cp NOTICE "$stage/NOTICE"
node scripts/third-party-licenses.mjs x86_64-pc-windows-gnu "$stage/THIRD-PARTY-LICENSES" ||
  die "could not write THIRD-PARTY-LICENSES (above)"
cp "$out/build-info-windows-x64.txt" "$stage/build-info.txt"
(cd "$stage" && find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | LC_ALL=C sort |
  while IFS= read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done) >"$stage/SHA256SUMS.txt"

zip="$out/phantab-windows-x64-bundle.zip"
node scripts/zip-deterministic.mjs "$work/zip" "$zip"
printf '%s  %s\n' "$(sha256_of "$zip")" phantab-windows-x64-bundle.zip >"$zip.sha256"
cat "$zip.sha256"

if [ "$test" = 1 ]; then
  echo "==> test-bundle.ps1: install from the zip alone into a throwaway user folder, then uninstall"
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w scripts/windows-bundle/test-bundle.ps1)" \
    -Zip "$(cygpath -w "$zip")" || die "the bundle test failed (above); do not ship $zip"
fi
echo "bundle: $zip"
