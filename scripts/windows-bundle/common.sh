# Shared by scripts/bundle-windows.sh and scripts/sign-windows.sh. Sourced from the repo root, never run:
# the caller has sourced scripts/dev-env.sh and defines die().

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
info_value() { sed -n "s/^$2=//p" "$1"; }

# Where the files to sign wait, and come back signed (scripts/sign-windows.sh). Under dist/, which git
# ignores, so it never makes the tree look changed.
sign_dir="dist/.sign"

# install.ps1, INSTALL-WINDOWS.md and run-check.rs come from this checkout, not from release.sh's output,
# so a release needs the checkout to be the commit release.sh built, unchanged. A --build-only test build
# only warns: testing a script change before committing it is its use.
#   require_built_checkout <build-info file> <tag> <script name>
require_built_checkout() {
  local info="$1" tag="$2" who="$3" built_sha
  built_sha="$(info_value "$info" sha)"
  if [ "$(git rev-parse HEAD)" != "$built_sha" ] || [ -n "$(git status --porcelain)" ]; then
    [ "$(info_value "$info" build_only)" = 1 ] ||
      die "$tag was built from $built_sha; check that commit out, with no local changes, first"
    echo "$who: note: the scripts come from this checkout, not from $built_sha as built (a test build)" >&2
  fi
}

# run-check.exe: bare rustc, no crates, the release's target, the same path remap as release.sh so the
# build names no local folder. --no-insert-timestamp: GNU ld writes the link time into the PE header
# otherwise, so the bundle's hash would change on every run.
# The path gate runs here, on the unsigned bytes, and nowhere on a signed file: a signature holds the
# publisher's name, so on a machine whose user name is part of that name the gate would refuse a file
# for its signature alone.
#   build_run_check <output .exe>
build_run_check() {
  local out="$1" sysroot
  echo "==> run-check.exe"
  sysroot="$(rustc --print sysroot)"
  rustc --edition 2021 -C opt-level=s -C strip=symbols -C debuginfo=0 -C link-arg=-Wl,--no-insert-timestamp \
    --target x86_64-pc-windows-gnu \
    "--remap-path-prefix=$(cygpath -w "$HOME")=/user-home" "--remap-path-prefix=$(cygpath -w "$sysroot")=/rustup/toolchain" \
    "--remap-path-prefix=$(cygpath -w "$(pwd)")=/phantab" \
    -o "$out" scripts/windows-bundle/run-check.rs
  MSYS2_ARG_CONV_EXCL='*' node scripts/path-gate.mjs "$(cygpath -w "$out")" \
    --exact '\Users\' --exact /Users/ --exact /home/ --any-case "$(cygpath -w "$HOME")" ||
    die "run-check.exe names a local path"
}

# Fails unless every named file in the folder carries a valid signature of its own by exactly this signer
# (the certificate's subject), with a timestamp. The signer goes through the environment, not the command
# line: a subject holds spaces, commas and equals signs.
#   check_signatures <folder> <signer> <file name>...
check_signatures() {
  local folder="$1" signer="$2"
  shift 2
  PHANTAB_SIGNER="$signer" powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File "$(cygpath -w scripts/windows-bundle/check-signatures.ps1)" -Folder "$(cygpath -w "$folder")" "$@"
}
