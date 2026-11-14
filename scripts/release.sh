#!/usr/bin/env bash
# Builds and uploads phantab's pinned release files. A pushed v* tag
# runs it in GitHub Actions (.github/workflows/release.yml: a Windows and a macOS runner build, one Linux
# job uploads both halves); a Windows x64 and a macOS arm64 machine run the same steps by hand when
# Actions cannot.
#
#   scripts/release.sh [--extension] <tag>               build this machine's half into dist/<tag>/
#   scripts/release.sh --build-only [--extension] <tag>  a test build: no tag or clean-tree check
#   scripts/release.sh --build-only --no-remap <tag>     the path gate's own test: must be refused
#   scripts/release.sh upload <tag>                      put dist/<tag>/ into the tag's DRAFT release
#
# Each machine builds and uploads its own half: Windows x64 phantab-windows-x64.exe, macOS arm64
# phantab-macos-arm64, each with a .sha256 beside it; one of them (either, the bytes are the same) adds
# extension.zip with --extension. The tag must already be pushed (git push origin <tag>).
#
# A build refuses unless HEAD is exactly the tag's commit and the tree is clean; while `cargo deny check`
# (SR-55), `cargo audit --deny warnings` or `npm audit --audit-level=high` (SR-56) fails, or
# cargo-deny or cargo-audit is not installed; with node older than 22; and while anything outside the
# repo could change the build: RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS, CARGO_BUILD_TARGET,
# CARGO_BUILD_RUSTFLAGS, any CARGO_PROFILE_RELEASE_*, a target's RUSTFLAGS or LINKER, a rustc wrapper, or
# a [build], [profile] or [target] table in a cargo config file (.cargo/config.toml up the tree, or
# CARGO_HOME's). It builds in its own target dir, dist/.build, never a shared CARGO_TARGET_DIR.
#
# The binary must name no local path: a shipped program that holds \Users\, /Users/ or /home/ tells
# whoever runs it where, and as whom, it was built. The script sets its own rustflags, --remap-path-prefix for the home dir, the rustup home and
# toolchain, CARGO_HOME (registry and git sources) and the checkout, to neutral names (/user-home,
# /rustup, /cargo, /phantab). Then the path gate (scripts/path-gate.mjs) scans the copied binary, as
# ASCII and UTF-16, for those generic forms, this machine's home, user name and checkout paths in both
# slash directions; a hit fails the build, test builds too. --no-remap (with --build-only only) leaves
# the remap out, so the gate must refuse the result: it tests the gate.
#
# --build-only skips the tag and clean-tree checks, lets a missing tool or one of those settings through
# with a warning, and marks its output so `upload` refuses it. build-info-<platform>.txt records what
# the build ran with (version, commit, target, rustc -vV, the C compiler that links it, the lockfile
# hashes, the gates' results, the names of the settings above) and nothing that names this machine: no
# path, user or host name. The bundles ship it as build-info.txt.
#
# The extension's packages install with `npm ci --ignore-scripts`: no package's install script runs, and
# none needs one. The binary must not be a test-seams build (SR-73): the gate refuses one that holds the
# words of install's test-build refusal, which only that feature compiles in.
#
# `upload` makes the release a draft and only ever a draft. Publishing it is a separate step, by hand.
set -euo pipefail

usage() { sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "release.sh: $*" >&2; exit 1; }

cd "$(dirname "$0")/.."
# Puts ~/.cargo/bin on PATH (cargo, cargo-deny, cargo-audit) on both platforms, and on the GNU Windows
# toolchain WinLibs' bin (dlltool, objdump, gcc) too.
. scripts/dev-env.sh

# The pinned names. Windows is GNU (x86_64-pc-windows-gnu): the toolchain rust-toolchain.toml's builds
# use there, and what the installed phantab has always been (release.yml's MSVC build never shipped).
# Only a build needs one: `upload` runs anywhere (the release workflow's draft job is Linux).
pick_platform() {
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) platform=macos-arm64; exe=phantab; release_triple=aarch64-apple-darwin ;;
    MINGW*/x86_64|MSYS*/x86_64|CYGWIN*/x86_64)
      platform=windows-x64; exe=phantab.exe; release_triple=x86_64-pc-windows-gnu ;;
    *) die "no pinned artifact for $(uname -s) $(uname -m); the pins are windows-x64 and macos-arm64" ;;
  esac
  artifact="phantab-$platform${exe#phantab}"
}

check_tag() {
  case "$1" in
    v*) ;;
    *) die "a release tag starts with v (got '$1')" ;;
  esac
  case "$1" in
    *[!A-Za-z0-9._+-]*) die "tag '$1' has characters outside A-Z a-z 0-9 . _ + -" ;;
  esac
}

# "<hash>  <name>", the sha256sum/shasum text form. sha256sum in Git Bash prints "<hash> *<name>" (binary
# mode); both check with `sha256sum -c`, but one form keeps a file's .sha256 the same bytes on both OSes.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}
sha256_line() { printf '%s  %s\n' "$(sha256_of "$1")" "$2"; }

has_cargo_tool() { cargo "$1" --version >/dev/null 2>&1; }

# "has_line <lines> <line>": whether one line of <lines> is exactly <line>. No grep: `cmd | grep -q`
# under pipefail can fail the pipeline when grep exits early, and a captured value is checked once.
has_line() {
  local nl='
'
  case "$nl$1$nl" in *"$nl$2$nl"*) return 0 ;; esac
  return 1
}

# The extension's tooling needs node 22 or later (an older node may come first on PATH).
check_node() {
  local v major
  v="$(node --version 2>/dev/null)" || die "node is not on PATH; the extension needs node >= 22"
  major="${v#v}"
  major="${major%%.*}"
  case "$major" in ''|*[!0-9]*) die "cannot read node's version ('$v')" ;; esac
  [ "$major" -ge 22 ] || die "node $v is older than 22, which the extension needs (put a newer node first on PATH)"
}

# Settings from outside the repo that would change the binary: the environment names that are set, then
# each cargo config file with a [build], [profile] or [target] table (or a build./profile./target. key).
build_env_overrides() {
  env | sed -n -E 's/^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_TARGET|CARGO_BUILD_RUSTFLAGS|CARGO_BUILD_RUSTC_WRAPPER|RUSTC_WRAPPER|CARGO_PROFILE_RELEASE_[A-Za-z0-9_]+|CARGO_TARGET_[A-Za-z0-9_]+_(RUSTFLAGS|LINKER))=.*/\1/p' | sort -u
}
cargo_config_overrides() {
  local dir f
  dir="$(pwd)"
  while :; do
    for f in "$dir/.cargo/config.toml" "$dir/.cargo/config"; do
      [ -f "$f" ] && config_has_build_tables "$f" && echo "$f"
    done
    [ "$dir" != / ] && [ -n "$dir" ] || break
    dir="$(dirname "$dir")"
  done
  for f in "${CARGO_HOME:-$HOME/.cargo}/config.toml" "${CARGO_HOME:-$HOME/.cargo}/config"; do
    [ -f "$f" ] && config_has_build_tables "$f" && echo "$f"
  done
  return 0
}
config_has_build_tables() {
  local hits
  hits="$(sed -n -E '/^[[:space:]]*(\[(build|profile|target)([].]|[[:space:]])|(build|profile|target)\.)/p' "$1")" ||
    return 0 # an unreadable config counts as one that changes the build
  [ -n "$hits" ]
}

# The first line of the version of the C compiler that links the binary, or "unknown".
linker_version() {
  local c v
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || continue
    v="$("$c" --version 2>/dev/null | sed -n 1p)" || v=""
    [ -z "$v" ] || { echo "$c: $v"; return 0; }
  done
  echo unknown
}

# The GNU exe must run on a bare Windows: Rust links libgcc statically, so today it imports only system
# DLLs (kernel32, ntdll, msvcrt, advapi32, user32, ...). A MinGW runtime DLL (libgcc_s_seh-1,
# libwinpthread-1, libstdc++-6) would be missing on the machines that install it, so it refuses one.
# objdump comes with WinLibs (scripts/dev-env.sh puts it on PATH).
check_windows_imports() {
  local imports
  if ! command -v objdump >/dev/null 2>&1; then
    [ "$2" = 1 ] || die "objdump not on PATH (WinLibs' mingw64/bin, scripts/dev-env.sh): cannot check $1's DLL imports"
    echo "warning: objdump not on PATH; $1's DLL imports are not checked"
    return 0
  fi
  local dump bad
  dump="$(objdump -p "$1")" || die "objdump -p $1 failed"
  imports="$(printf '%s\n' "$dump" | sed -n 's/^[[:space:]]*DLL Name: //p' | sort -fu)"
  [ -n "$imports" ] || die "objdump found no DLL imports in $1; cannot check them"
  echo "DLL imports: $(echo $imports)"
  bad="$(printf '%s\n' "$imports" | sed -n -E '/^([Ll][Ii][Bb]|[Vv][Cc][Rr][Uu][Nn][Tt][Ii][Mm][Ee][0-9]|[Mm][Ss][Vv][Cc][Pp][0-9])/p')"
  [ -z "$bad" ] || die "$1 imports a runtime DLL that is not part of Windows: $(echo $bad); link it statically"
}

# A path as rustc sees it: C:\Users\... on Windows (Git Bash's /c/Users/... is only the shell's), as is
# elsewhere. "mixed" is C:/Users/..., which also turns up (paths built with forward slashes).
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi; }
mixed_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }

# remap_flags: one --remap-path-prefix=<from>=<to> per line, general to specific. rustc applies the
# last one that matches, so the checkout wins over a home it sits in. Every <to> is a neutral name that
# none of the gate's needles match (not /home/..., not /Users/...).
remap_flags() {
  local home cargo_home rustup_home sysroot pair from to form
  home="$HOME"
  cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  rustup_home="$(rustup show home 2>/dev/null)" || rustup_home=""
  [ -n "$rustup_home" ] || rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
  sysroot="$(rustc --print sysroot)"
  for pair in "$home=/user-home" "$rustup_home=/rustup" "$sysroot=/rustup/toolchain" \
    "$cargo_home=/cargo" "$(pwd)=/phantab" "$(pwd -P)=/phantab"; do
    from="${pair%=*}"
    to="${pair##*=}"
    [ -n "$from" ] || continue
    # On Windows both forms, C:\x and C:/x; elsewhere they are the same line, printed once.
    for form in "$(native_path "$from")" "$(mixed_path "$from")"; do
      printf -- '--remap-path-prefix=%s=%s\n' "$form" "$to"
    done
  done | awk '!seen[$0]++'
}

# The gate's needles, as path-gate.mjs arguments, one per line: the three generic home-path forms
# exactly, then this machine's own paths in any case, in every form the shell and rustc spell them.
# Also three that only a test build holds (`test-seams`: main.rs's TEST_SEAMS_MARKER, the test
# keychain's variable, and phantab-window's error when no test keychain is set, `test_keychain::NONE`,
# which a build with only phantab-window's test-seams holds), so a binary with a test seam is never
# released.
path_gate_args() {
  local user p form
  printf '%s\n' --exact '\Users\' --exact /Users/ --exact /home/
  printf '%s\n' --exact phantab-test-seams-build --exact PHANTAB_TEST_KEYCHAIN \
    --exact 'a test build never opens the login keychain'
  user="$(basename "$HOME")"
  for form in "\\Users\\$user" "/Users/$user" "/home/$user"; do
    printf '%s\n' --any-case "$form"
  done
  # pwd -P too: under a symlinked dir (macOS /tmp is /private/tmp) cargo sees the physical path.
  for p in "$HOME" "${CARGO_HOME:-$HOME/.cargo}" "$(pwd)" "$(pwd -P)"; do
    for form in "$p" "$(native_path "$p")" "$(mixed_path "$p")"; do
      printf '%s\n' --any-case "$form"
    done
  done
}

path_gate() {
  local args=() line
  # Each "<flag> <needle>" pair once: off Windows the path forms coincide and $HOME is /Users/<user>,
  # so repeats would count one hit several times.
  while IFS= read -r line; do args+=("$line"); done < <(path_gate_args |
    awk 'NR % 2 { flag = $0; next } !seen[flag "\n" $0]++ { print flag; print $0 }')
  echo "==> path gate: no local path or test seam in $1"
  # MSYS2_ARG_CONV_EXCL: Git Bash rewrites a POSIX-looking argument for a Windows program, so /home/
  # would reach node as C:/Program Files/Git/home/ and never match. (No effect outside Git Bash.)
  # The file is passed in rustc's own form for the same reason.
  local rc=0
  MSYS2_ARG_CONV_EXCL='*' node scripts/path-gate.mjs "$(native_path "$1")" "${args[@]}" || rc=$?
  case "$rc" in
    0) ;;
    1) die "$1 holds a local path or a test seam (above): no release" ;;
    *) die "the path gate could not check $1 (exit $rc); no release" ;;
  esac
}

# SR-73: the words of `phantab install`'s test-build refusal, compiled in only with the test-seams
# feature (crates/phantab/src/install/mod.rs; tests/install.rs checks a test build holds them).
# tests/install.rs runs this function, die and native_path, copied out by sed: keep each one's
# "name() {" line and closing "}" line as they are.
test_build_gate() {
  echo "==> test-build gate: $1 is not a test-seams build"
  local rc=0
  node scripts/path-gate.mjs "$(native_path "$1")" --exact 'built with the test-seams feature' || rc=$?
  case "$rc" in
    0) ;;
    1) die "$1 is a test-seams build (its test overrides are compiled in); no release" ;;
    *) die "the test-build gate could not check $1 (exit $rc); no release" ;;
  esac
}

cmd_build() {
  pick_platform
  local extension=0 build_only=0 remap=1 tag=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --extension) extension=1 ;;
      --build-only) build_only=1 ;;
      --no-remap) remap=0 ;;
      -h|--help) usage; exit 0 ;;
      -*) die "unknown option $1" ;;
      *) [ -z "$tag" ] || die "one tag only"; tag="$1" ;;
    esac
    shift
  done
  [ -n "$tag" ] || { usage >&2; exit 2; }
  check_tag "$tag"
  [ "$remap" = 1 ] || [ "$build_only" = 1 ] || die "--no-remap is the path gate's test: --build-only only"

  local sha tree
  sha="$(git rev-parse HEAD)"
  if [ -z "$(git status --porcelain)" ]; then tree=clean; else tree=dirty; fi
  if [ "$build_only" = 0 ]; then
    local tag_sha
    tag_sha="$(git rev-parse -q --verify "refs/tags/$tag^{commit}")" || die "no tag $tag here (git fetch --tags?)"
    [ "$tag_sha" = "$sha" ] || die "HEAD is $sha, but $tag is $tag_sha; check out the tag first"
    [ "$tree" = clean ] || { git status --short >&2; die "the tree is not clean"; }
  fi

  check_node

  # Nothing from outside the repo may change the build.
  local env_overrides config_overrides
  env_overrides="$(build_env_overrides)"
  config_overrides="$(cargo_config_overrides)"
  if [ -n "$env_overrides$config_overrides" ]; then
    echo "these change the build from outside the repo:" >&2
    [ -z "$env_overrides" ] || echo "$env_overrides" | sed 's/^/  set in the environment: /' >&2
    [ -z "$config_overrides" ] || echo "$config_overrides" | sed 's/^/  [build], [profile] or [target] in: /' >&2
    [ "$build_only" = 1 ] || die "unset them, or move the config aside, for a release build"
    echo "warning: a test build goes on with them; a real release refuses"
  fi

  # SR-55 and SR-56 gates, before anything is built.
  local cargo_deny cargo_audit npm_audit=pass
  if has_cargo_tool deny; then
    echo "==> cargo deny check"
    cargo deny check || die "cargo deny check fails (SR-55): no release"
    cargo_deny=pass
  elif [ "$build_only" = 1 ]; then
    echo "warning: cargo-deny not installed (cargo install cargo-deny --locked); a real release refuses"
    cargo_deny="not run (not installed)"
  else
    die "cargo-deny is not installed (cargo install cargo-deny --locked); SR-55 needs it for a release"
  fi
  if has_cargo_tool audit; then
    echo "==> cargo audit --deny warnings"
    cargo audit --deny warnings || die "cargo audit fails (SR-56): no release"
    cargo_audit=pass
  elif [ "$build_only" = 1 ]; then
    echo "warning: cargo-audit not installed (cargo install cargo-audit --locked); a real release refuses"
    cargo_audit="not run (not installed)"
  else
    die "cargo-audit is not installed (cargo install cargo-audit --locked); SR-56 needs it for a release"
  fi
  # SR-56: every package, dev ones included: the shipped JS is the dev-only compiler's output.
  echo "==> extension: npm ci --ignore-scripts, npm audit --audit-level=high"
  (cd extension && npm ci --ignore-scripts) || die "npm ci failed in extension/"
  (cd extension && npm audit --audit-level=high) || die "npm audit fails (SR-56): no release"

  # Always the pinned target, always in this script's own target dir, so the binary's path is known
  # (<target-dir>/<triple>/release/<exe>) and nothing else's build shares it: never CARGO_TARGET_DIR,
  # which --target-dir overrides. A release starts that dir empty; a test build reuses it. A missing
  # target fails the build (rustup target add <triple>; windows-gnu also needs WinLibs, dev-env.sh).
  local build_dir="dist/.build" bin
  [ "$build_only" = 1 ] || rm -rf "$build_dir"
  # The script's own rustflags, the only ones (an outside RUSTFLAGS is refused above). Passed as
  # CARGO_ENCODED_RUSTFLAGS, split on 0x1f, so a path with a space stays one flag; cargo prefers it to
  # RUSTFLAGS and to any config's rustflags. With an explicit --target they reach only the target's
  # crates, not build scripts or proc macros, which do not ship.
  local flags encoded="" sep flag
  sep="$(printf '\037')"
  if [ "$remap" = 1 ]; then flags="$(remap_flags)"; else flags=""; fi
  while IFS= read -r flag; do
    [ -n "$flag" ] && encoded="${encoded:+$encoded$sep}$flag"
  done <<EOF_FLAGS
$flags
EOF_FLAGS
  [ "$remap" = 1 ] || echo "warning: --no-remap: no --remap-path-prefix, so the path gate must refuse this build"
  echo "==> cargo build --release --locked -p phantab --target $release_triple --target-dir $build_dir"
  [ -z "$flags" ] || printf '%s\n' "$flags" | sed 's/^/    /'
  # MSYS2_ENV_CONV_EXCL: Git Bash would otherwise rewrite a value like x=/cargo in the environment of a
  # Windows program into x=C:/Program Files/Git/cargo.
  MSYS2_ENV_CONV_EXCL=CARGO_ENCODED_RUSTFLAGS CARGO_ENCODED_RUSTFLAGS="$encoded" cargo build --release --locked -p phantab --target "$release_triple" --target-dir "$build_dir" ||
    die "cargo build failed (is the $release_triple target installed? rustup target add $release_triple)"
  bin="$build_dir/$release_triple/release/$exe"
  [ -f "$bin" ] || die "cargo built, but there is no $bin"

  # A fresh folder: a machine only ever holds its own half, and a file left from an earlier build (an
  # extension.zip from a run with --extension, say) would otherwise be uploaded with this one.
  local out="dist/$tag"
  rm -rf "$out"
  mkdir -p "$out"
  cp "$bin" "$out/$artifact"
  # Checked and hashed as copied: the bytes that are uploaded. The path gate refuses test builds too.
  [ "$platform" != windows-x64 ] || check_windows_imports "$out/$artifact" "$build_only"
  path_gate "$out/$artifact"
  test_build_gate "$out/$artifact"
  # The hash file names the binary as installed (phantab.exe / phantab), as release.yml's did; a
  # downloaded file is checked by its hash alone, or renamed first.
  sha256_line "$out/$artifact" "$exe" >"$out/$artifact.sha256"

  if [ "$extension" = 1 ]; then
    echo "==> extension: npm run build, deterministic zip"
    (cd extension && npm run build) || die "extension build failed"
    node scripts/zip-deterministic.mjs extension/dist "$out/extension.zip"
    sha256_line "$out/extension.zip" extension.zip >"$out/extension.zip.sha256"
  fi

  # Read by `upload` (tag, sha, platform, build_only) and the bundle scripts (sha, build_only), which ship
  # it as build-info.txt: so it holds no path, user or host name. Not the rustflags (they hold this
  # machine's paths) nor the config files' paths, only whether the remap was on and how many config
  # files changed the build. Windows links with WinLibs' gcc, macOS with Apple's cc (clang).
  local linker
  if [ "$platform" = windows-x64 ]; then
    linker="$(linker_version x86_64-w64-mingw32-gcc gcc)"
  else
    linker="$(linker_version cc clang)"
  fi
  {
    echo "tag=$tag"
    echo "version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | sed -n 1p)"
    echo "sha=$sha"
    echo "platform=$platform"
    echo "target=$release_triple"
    echo "build_only=$build_only"
    echo "tree=$tree"
    echo "cargo_deny=$cargo_deny"
    echo "cargo_audit=$cargo_audit"
    echo "npm_audit=$npm_audit"
    echo "extension=$extension"
    echo "env_overrides=$(echo $env_overrides)"
    if [ -z "$config_overrides" ]; then
      echo "config_overrides=0"
    else
      echo "config_overrides=$(printf '%s\n' "$config_overrides" | wc -l | tr -d ' ')"
    fi
    if [ "$remap" = 1 ]; then echo "remap=on"; else echo "remap=off (--no-remap)"; fi
    echo "cargo_lock_sha256=$(sha256_of Cargo.lock)"
    echo "extension_lock_sha256=$(sha256_of extension/package-lock.json)"
    echo "path_gate=pass"
    echo "test_build_gate=pass"
    echo "linker=$linker"
    echo "node=$(node --version)"
    rustc -vV | sed -e '1s/^/rustc=/' -e '2,$s/^\([^:]*\): /rustc.\1=/'
  } >"$out/build-info-$platform.txt"

  echo
  echo "built $tag ($sha) for $platform into $out/:"
  cat "$out/$artifact.sha256"
  [ "$extension" = 0 ] || cat "$out/extension.zip.sha256"
  if [ "$build_only" = 1 ]; then
    echo "TEST BUILD (--build-only): upload refuses it"
  else
    echo "next: scripts/release.sh upload $tag"
  fi
}

info_value() { sed -n "s/^$2=//p" "$1"; }

cmd_upload() {
  [ $# -eq 1 ] || die "usage: scripts/release.sh upload <tag>"
  local tag="$1" out="dist/$1"
  check_tag "$tag"
  [ -d "$out" ] || die "no $out; build first"
  command -v gh >/dev/null 2>&1 || die "gh (GitHub CLI) is not on PATH"

  local info sha="" platforms="" files=() nfiles=0 f
  for info in "$out"/build-info-*.txt; do
    [ -f "$info" ] || die "no build-info in $out; build first"
    [ "$(info_value "$info" build_only)" = 0 ] || die "$info is a --build-only test build; rebuild without it"
    [ "$(info_value "$info" tag)" = "$tag" ] || die "$info is for another tag"
    if [ -z "$sha" ]; then sha="$(info_value "$info" sha)"; fi
    [ "$(info_value "$info" sha)" = "$sha" ] || die "$out holds builds from two commits"
    platforms="$platforms $(info_value "$info" platform)"
  done

  # The pushed tag must be the commit these files were built from.
  local remote_sha
  remote_sha="$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}" | sort -k2 | tail -n 1 | cut -f1)" ||
    die "git ls-remote origin failed"
  [ -n "$remote_sha" ] || die "tag $tag is not on origin; git push origin $tag first"
  [ "$remote_sha" = "$sha" ] || die "origin's $tag is $remote_sha, but $out was built from $sha"

  for f in "$out"/*.sha256; do
    [ -f "$f" ] || continue
    local file="${f%.sha256}"
    [ -f "$file" ] || die "$f has no file beside it"
    [ "$(cut -d' ' -f1 "$f")" = "$(sha256_of "$file")" ] || die "$file does not match $f"
    files+=("$file" "$f"); nfiles=$((nfiles + 1))
  done
  [ "$nfiles" -gt 0 ] || die "nothing to upload in $out"

  local view status=0
  view="$(gh release view "$tag" --json isDraft,body,assets 2>&1)" || status=$?
  if [ "$status" != 0 ]; then
    case "$view" in
      *"release not found"*) ;;
      *) die "gh release view $tag failed: $view" ;;
    esac
    # No release yet: a draft. --verify-tag refuses a tag that is not on GitHub.
    local machines
    machines="$(echo "$platforms" | xargs | sed 's/ / and /g')"
    echo "==> gh release create $tag --draft"
    gh release create "$tag" --draft --verify-tag --title "$tag" \
      --notes "Built from $sha on $machines. Hashes beside each file." "${files[@]}"
  else
    [ "$(gh release view "$tag" --json isDraft -q .isDraft)" = true ] ||
      die "$tag is already published; this script never changes a published release"
    local body
    body="$(gh release view "$tag" --json body -q .body)"
    case "$body" in
      *"Built from $sha "*) ;;
      *) die "the $tag draft says another commit: '$body'" ;;
    esac
    local names
    names="$(gh release view "$tag" --json assets -q '.assets[].name')" || die "gh release view $tag failed"
    # Both machines may build the extension; their zips must be the same bytes. A draft zip without its
    # .sha256 cannot be compared, so it is not overwritten either.
    if [ -f "$out/extension.zip" ] && has_line "$names" extension.zip; then
      has_line "$names" extension.zip.sha256 ||
        die "the $tag draft has extension.zip but no extension.zip.sha256: delete the draft's zip by hand, then upload again"
      local theirs
      theirs="$(gh release download "$tag" -p extension.zip.sha256 -O -)" || die "cannot download the draft's extension.zip.sha256"
      theirs="${theirs%% *}"
      [ "$theirs" = "$(sha256_of "$out/extension.zip")" ] ||
        die "the draft's extension.zip ($theirs) differs from this one: the zip is not deterministic across machines"
    fi
    echo "==> gh release upload $tag --clobber"
    gh release upload "$tag" "${files[@]}" --clobber
    # The notes name every machine whose binary the draft now holds.
    local machines=""
    names="$(gh release view "$tag" --json assets -q '.assets[].name')" || die "gh release view $tag failed"
    if has_line "$names" phantab-windows-x64.exe; then machines="windows-x64"; fi
    if has_line "$names" phantab-macos-arm64; then machines="${machines:+$machines and }macos-arm64"; fi
    gh release edit "$tag" --notes "Built from $sha on $machines. Hashes beside each file."
  fi
  echo "draft $tag holds:"
  gh release view "$tag" --json assets -q '.assets[].name'
  echo "It stays a draft. Publishing it is a separate step, by hand."
}

case "${1:-}" in
  upload) shift; cmd_upload "$@" ;;
  ""|-h|--help) usage; [ -n "${1:-}" ] || exit 2 ;;
  *) cmd_build "$@" ;;
esac
