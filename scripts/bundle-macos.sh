#!/usr/bin/env bash
# Packs the macOS arm64 bundle: one zip a Mac user installs from with no Rust, Node or repo access
# (docs/INSTALL-MAC.md). Run it on a Mac (Apple silicon) after release.sh has built the tag's half with
# the extension:
#
#   scripts/release.sh [--build-only] --extension <tag>
#   scripts/bundle-macos.sh [--no-test] <tag>
#
# It writes dist/<tag>/phantab-macos-arm64-bundle.zip and its .sha256 (so `release.sh upload <tag>` puts
# it in the draft too). The zip holds one folder, phantab-macos-arm64/:
#   phantab           release.sh's binary, checked against its .sha256
#   extension/        the unpacked extension Chrome loads; it must zip to release.sh's extension.zip
#   install.sh        user-level install and uninstall (no admin, no sudo)
#   INSTALL-MAC.md    the quickstart
#   LICENSE, NOTICE   phantab's licence and notice, from the repo root (the bundle refuses without them)
#   THIRD-PARTY-LICENSES  the licences of the crates linked into phantab (scripts/third-party-licenses.mjs)
#   build-info.txt    release.sh's build-info for the binary: version, commit, toolchain, lockfile
#                     hashes; no path, user or host name
#   SHA256SUMS.txt    every file's hash; install.sh checks them first
# Then it runs scripts/macos-bundle/test-bundle.sh on the zip (an install and uninstall under a
# throwaway HOME that never touches this Mac's own phantab or Chrome), unless --no-test.
# The same shape as scripts/bundle-windows.sh; keep the two in step.
set -euo pipefail

die() { echo "bundle-macos.sh: $*" >&2; exit 1; }
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
[ -n "$tag" ] || die "usage: scripts/bundle-macos.sh [--no-test] <tag>"
[ "$(uname -s)/$(uname -m)" = Darwin/arm64 ] || die "the macOS bundle is built on an Apple silicon Mac"
for f in LICENSE NOTICE; do
  [ -f "$f" ] || die "no $f at the repo root: the bundle ships phantab's LICENSE and NOTICE, so it is not built without them"
done

out="dist/$tag"
bin="$out/phantab-macos-arm64"
for f in "$bin" "$bin.sha256" "$out/extension.zip" "$out/extension.zip.sha256" "$out/build-info-macos-arm64.txt"; do
  [ -f "$f" ] || die "no $f: run scripts/release.sh --extension $tag (add --build-only for a test build) first"
done
sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
[ "$(sha256_of "$bin")" = "$(cut -d' ' -f1 "$bin.sha256")" ] || die "$bin does not match its .sha256"

# install.sh and INSTALL-MAC.md come from this checkout, not from release.sh's output, so a release
# bundle needs the checkout to be the commit release.sh built, unchanged. A --build-only test build
# only warns.
info="$out/build-info-macos-arm64.txt"
built_sha="$(sed -n 's/^sha=//p' "$info")"
built_only="$(sed -n 's/^build_only=//p' "$info")"
if [ "$(git rev-parse HEAD)" != "$built_sha" ] || [ -n "$(git status --porcelain)" ]; then
  [ "$built_only" = 1 ] ||
    die "$tag was built from $built_sha; check that commit out, with no local changes, before bundling it"
  echo "bundle-macos.sh: note: the scripts come from this checkout, not from $built_sha as built (a test build)" >&2
fi

# The unpacked extension must be the very files of extension.zip.
work="dist/.build/bundle-macos"
rm -rf "$work"
mkdir -p "$work"
node scripts/zip-deterministic.mjs extension/dist "$work/extension-check.zip" >/dev/null
[ "$(sha256_of "$work/extension-check.zip")" = "$(cut -d' ' -f1 "$out/extension.zip.sha256")" ] ||
  die "extension/dist is not what $out/extension.zip holds; run release.sh --extension $tag again"

echo "==> staging phantab-macos-arm64/"
stage="$work/zip/phantab-macos-arm64"
mkdir -p "$stage"
cp "$bin" "$stage/phantab"
cp -R extension/dist "$stage/extension"
cp scripts/macos-bundle/install.sh "$stage/install.sh"
cp docs/INSTALL-MAC.md "$stage/INSTALL-MAC.md"
cp LICENSE "$stage/LICENSE"
cp NOTICE "$stage/NOTICE"
node scripts/third-party-licenses.mjs aarch64-apple-darwin "$stage/THIRD-PARTY-LICENSES" ||
  die "could not write THIRD-PARTY-LICENSES (above)"
cp "$info" "$stage/build-info.txt"
(cd "$stage" && find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | LC_ALL=C sort |
  while IFS= read -r f; do printf '%s  %s\n' "$(sha256_of "$f")" "$f"; done) >"$stage/SHA256SUMS.txt"

# zip-deterministic.mjs records every file as 0644, so the zip is the same bytes anywhere; install.sh
# makes phantab executable again (it is run as `bash install.sh`, so it needs no mode itself).
zip="$out/phantab-macos-arm64-bundle.zip"
node scripts/zip-deterministic.mjs "$work/zip" "$zip"
printf '%s  %s\n' "$(sha256_of "$zip")" phantab-macos-arm64-bundle.zip >"$zip.sha256"
cat "$zip.sha256"

if [ "$test" = 1 ]; then
  echo "==> test-bundle.sh: install from the zip alone under a throwaway HOME, then uninstall"
  bash scripts/macos-bundle/test-bundle.sh "$zip" || die "the bundle test failed (above); do not ship $zip"
fi
echo "bundle: $zip"
