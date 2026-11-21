#!/usr/bin/env bash
# The two halves of signing the Windows build, around the signing itself. The release workflow
# (.github/workflows/release.yml, job build-signed) runs them on a Windows runner; nothing here holds a
# key or talks to a signing service. Run on Windows x64 (Git Bash):
#
#   scripts/release.sh [--build-only] --extension <tag>
#   scripts/sign-windows.sh stage <tag>
#   ... every .exe and .ps1 in dist/.sign/ is signed in place, with a timestamp ...
#   PHANTAB_SIGNER='<the certificate subject>' scripts/sign-windows.sh seal <tag>
#   scripts/bundle-windows.sh <tag>
#
# stage  empties dist/.sign/ and puts in it what gets signed: phantab.exe (release.sh's
#        dist/<tag>/phantab-windows-x64.exe), run-check.exe (built here) and install.ps1. It records the
#        tag, the file names and each file's hash before signing (staged.txt, unsigned.sha256).
#        PHANTAB_SIGN_SCRIPT=0 leaves install.ps1 out: the programs are signed, the script ships as it
#        is in the checkout. That is the one switch for it; seal and bundle-windows.sh follow what stage
#        recorded.
# seal   refuses unless every staged file now carries a valid signature by exactly PHANTAB_SIGNER, with
#        a timestamp (scripts/windows-bundle/check-signatures.ps1). Then it copies the signed phantab.exe
#        over dist/<tag>/phantab-windows-x64.exe, rewrites its .sha256, and adds to
#        build-info-windows-x64.txt: signed=1, signer=<subject>, signed_files=<names>, and
#        unsigned_sha256=<the program's hash before signing>.
#
# Signing changes a file's bytes, so it comes after release.sh's gates (they ran on the unsigned
# program) and before any hash that ships: the .sha256 rewritten here, and the bundle's SHA256SUMS.txt
# and zip hash that bundle-windows.sh writes afterwards. A build that is never staged stays unsigned, and
# bundle-windows.sh bundles it as before.
set -euo pipefail

die() { echo "sign-windows.sh: $*" >&2; exit 1; }
usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; }
cd "$(dirname "$0")/.."

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  stage|seal) ;;
  *) die "usage: scripts/sign-windows.sh stage|seal <tag>" ;;
esac
cmd="$1"
[ $# -eq 2 ] && [ -n "$2" ] || die "usage: scripts/sign-windows.sh $cmd <tag>"
tag="$2"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) ;; *) die "the Windows build is signed on Windows (Git Bash)" ;; esac
. scripts/dev-env.sh
. scripts/windows-bundle/common.sh

out="dist/$tag"
exe="$out/phantab-windows-x64.exe"
info="$out/build-info-windows-x64.txt"
for f in "$exe" "$exe.sha256" "$info"; do
  [ -f "$f" ] || die "no $f: run scripts/release.sh --extension $tag (add --build-only for a test build) first"
done
[ "$(sha256_of "$exe")" = "$(cut -d' ' -f1 "$exe.sha256")" ] || die "$exe does not match its .sha256"
[ "$(info_value "$info" signed)" != 1 ] ||
  die "$tag is already signed and sealed; to sign again, build it again with release.sh"

stage() {
  require_built_checkout "$info" "$tag" sign-windows.sh
  rm -rf "$sign_dir"
  mkdir -p "$sign_dir"
  cp "$exe" "$sign_dir/phantab.exe"
  build_run_check "$sign_dir/run-check.exe"
  local files="phantab.exe run-check.exe" f
  if [ "${PHANTAB_SIGN_SCRIPT:-1}" = 0 ]; then
    echo "sign-windows.sh: PHANTAB_SIGN_SCRIPT=0: install.ps1 is not staged and ships unsigned"
  else
    cp scripts/windows-bundle/install.ps1 "$sign_dir/install.ps1"
    files="$files install.ps1"
  fi
  # Neither file is an .exe or a .ps1, so the signing step passes them by.
  printf 'tag=%s\nfiles=%s\n' "$tag" "$files" >"$sign_dir/staged.txt"
  for f in $files; do printf '%s  %s\n' "$(sha256_of "$sign_dir/$f")" "$f"; done >"$sign_dir/unsigned.sha256"
  echo "staged in $sign_dir/ for signing: $files"
}

seal() {
  [ -n "${PHANTAB_SIGNER:-}" ] ||
    die "PHANTAB_SIGNER is not set: the signing certificate's subject, exactly as Windows shows it"
  # It goes into build-info.txt, which is key=value lines and holds no path (test-bundle.ps1 checks).
  case "$PHANTAB_SIGNER" in
    *[\\/]*|*$'\n'*|*$'\r'*) die "PHANTAB_SIGNER holds a slash or a line break; a certificate subject has neither" ;;
  esac
  [ -f "$sign_dir/staged.txt" ] && [ -f "$sign_dir/unsigned.sha256" ] ||
    die "nothing is staged in $sign_dir/; run scripts/sign-windows.sh stage $tag first"
  [ "$(info_value "$sign_dir/staged.txt" tag)" = "$tag" ] ||
    die "$sign_dir/ was staged for $(info_value "$sign_dir/staged.txt" tag), not for $tag"
  local files unsigned f
  files="$(info_value "$sign_dir/staged.txt" files)"
  # The staged program must be this build's: dist/<tag>/ still holds the unsigned bytes it was copied from.
  unsigned="$(sed -n 's/  phantab\.exe$//p' "$sign_dir/unsigned.sha256")"
  [ "$(sha256_of "$exe")" = "$unsigned" ] || die "$exe is not the program that was staged; stage $tag again"
  # Only what stage put there: a stray .exe or .ps1 would have been signed with the rest.
  for f in "$sign_dir"/*.exe "$sign_dir"/*.ps1; do
    [ -e "$f" ] || continue
    case " $files " in *" ${f##*/} "*) ;; *) die "$f was not staged; stage $tag again" ;; esac
  done

  echo "==> signatures in $sign_dir/, expected signer: $PHANTAB_SIGNER"
  # shellcheck disable=SC2086 # the names are split on purpose
  check_signatures "$sign_dir" "$PHANTAB_SIGNER" $files ||
    die "a staged file is not signed as expected (above); nothing was changed in $out/"

  # No path gate here: it ran on the unsigned program (release.sh) and on the unsigned run-check.exe
  # (common.sh). A signed file holds the publisher's name in its certificate, and the gate refuses a file
  # that holds this machine's user name, so where the two share a word it would refuse a correct build.
  cp "$sign_dir/phantab.exe" "$exe"
  # The same form as release.sh's: the hash file names the binary as installed.
  printf '%s  %s\n' "$(sha256_of "$exe")" phantab.exe >"$exe.sha256"
  # path_gate, test_build_gate and the import check in this file are about the unsigned bytes, which
  # unsigned_sha256 names: a rebuild from the same commit gives that hash, never the signed one.
  printf 'signed=1\nsigner=%s\nsigned_files=%s\nunsigned_sha256=%s\n' "$PHANTAB_SIGNER" "$files" "$unsigned" >>"$info"
  cat "$exe.sha256"
  echo "sealed: $exe is signed; bundle it with scripts/bundle-windows.sh $tag"
}

"$cmd"
