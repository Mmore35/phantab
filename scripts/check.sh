#!/usr/bin/env bash
# The local check, run on a build machine: Git Bash on Windows x64, bash on macOS arm64. It stands in
# for the GitHub Actions ci.yml where Actions cannot run. docs/TESTING.md § 3 says which machine runs
# what.
#
#   scripts/check.sh                    format, lints, SR-58, cargo-deny, cargo-audit, tests, extension,
#                                       the security lane (scripts/security-check.sh)
#   scripts/check.sh --chrome           also the real-Chrome lanes 2 and 3; on Windows, lane 5 as well
#   scripts/check.sh --real-extension   also lane 4, the built extension in Chrome (implies --chrome)
#
# The Chrome flags start real Chrome. Lane 4 shows a window. Lane 5 (window_lane.rs) is Windows-only: on
# Windows --chrome runs it, and it shows and hides real headful Chrome windows; on macOS it passes
# without running. So a macOS arm64 machine runs --chrome --real-extension, and lane 5 needs a spare
# Windows machine or a desktop session where pop-ups are OK: it is opt-in and not run routinely. Never
# pass either flag on a machine someone is using. Without them PHANTAB_TEST_CHROME is cleared, so a
# value left in the shell starts nothing.
#
# Every step runs even after one fails, so one failure does not hide another's result. Exit status:
#   0   PASSED      every step ran and passed, on a clean tree
#   1   FAILED      a step failed (the summary names each one)
#   2   INCOMPLETE  every step that ran passed, but one was skipped (cargo-deny or cargo-audit is not
#                   installed, so SR-55 or SR-56 did not run) or the tree is dirty (DIRTY TREE: the run
#                   checked uncommitted changes, not the commit). Not a pass.
#   64  refused to start: a bad argument, no Chrome for --chrome, node older than 22, or a macOS shell
#       running under Rosetta (x86_64 on Apple Silicon). This script installs nothing.
set -euo pipefail

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; }
refuse() { echo "check.sh: $*" >&2; exit 64; }

chrome=0
real_extension=0
for arg in "$@"; do
  case "$arg" in
    --chrome) chrome=1 ;;
    --real-extension) chrome=1; real_extension=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; refuse "unknown argument: $arg" ;;
  esac
done

cd "$(dirname "$0")/.."
# Puts ~/.cargo/bin on PATH (cargo, cargo-deny, cargo-audit) on both machines, and on the GNU Windows
# toolchain WinLibs' bin (dlltool, objdump, gcc) too.
. scripts/dev-env.sh

os="$(uname -s)"
case "$os" in
  Darwin) platform=macos ;;
  MINGW*|MSYS*|CYGWIN*) platform=windows ;;
  *) platform="$os" ;;
esac
# Under Rosetta (any x86_64 parent on Apple Silicon, such as an Intel python), universal binaries such
# as bash and Chrome run as x86_64, so the real-Chrome lanes would test an Intel Chrome and still pass
# (verified 2026-11-13: five gate heads ran so). Refuse; arch -arm64 runs it natively.
if [ "$platform" = macos ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
  refuse "running under Rosetta (x86_64) on Apple Silicon; re-run natively: arch -arm64 /bin/bash scripts/check.sh $*"
fi

# The extension's tooling needs node 22 or later (an older node may come first on PATH).
node_version="$(node --version 2>/dev/null)" || refuse "node is not on PATH; the extension needs node >= 22"
node_major="${node_version#v}"
node_major="${node_major%%.*}"
case "$node_major" in
  ''|*[!0-9]*) refuse "cannot read node's version ('$node_version'); the extension needs node >= 22" ;;
esac
[ "$node_major" -ge 22 ] || refuse "node $node_version is older than 22, which the extension needs (put a newer node first on PATH)"

# Real-Chrome lanes only when asked. The lanes read PHANTAB_TEST_CHROME, lane 4 also
# PHANTAB_TEST_REAL_EXTENSION: neither may leak in from the shell.
unset PHANTAB_TEST_REAL_EXTENSION
# Nor the runtime folder or a test keychain: a test that forgets its own scratch runtime must not
# inherit the user's (Windows keeps the Bitwarden session blob there).
unset PHANTAB_RUNTIME PHANTAB_TEST_KEYCHAIN PHANTAB_TEST_KEYCHAIN_PASSWORD
if [ "$chrome" = 1 ]; then
  if [ -z "${PHANTAB_TEST_CHROME:-}" ]; then
    case "$platform" in
      macos) PHANTAB_TEST_CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ;;
      windows) PHANTAB_TEST_CHROME='C:\Program Files\Google\Chrome\Application\chrome.exe' ;;
      *) refuse "no standard Chrome path on $os; set PHANTAB_TEST_CHROME" ;;
    esac
  fi
  probe="$PHANTAB_TEST_CHROME"
  if [ "$platform" = windows ] && command -v cygpath >/dev/null 2>&1; then probe="$(cygpath -u "$probe")"; fi
  [ -f "$probe" ] || refuse "no Chrome at $PHANTAB_TEST_CHROME"
  # Only for the log. Never on Windows: chrome.exe --version opens a browser and never returns.
  if [ "$platform" = macos ]; then "$PHANTAB_TEST_CHROME" --version || true; fi
  export PHANTAB_TEST_CHROME
else
  unset PHANTAB_TEST_CHROME
fi

# Counters beside the lists: macOS's /bin/bash is 3.2, where an empty array trips `set -u`.
passed=()
failed=()
skipped=()
npass=0
nfail=0
nskip=0

# step <name> <command...>: runs the command, records pass or fail, never stops the script.
step() {
  local name="$1"
  shift
  printf '\n==> %s\n' "$name"
  if "$@"; then
    passed+=("$name"); npass=$((npass + 1))
  else
    echo "FAIL: $name"
    failed+=("$name"); nfail=$((nfail + 1))
  fi
}

skip() {
  printf '\n==> %s\nskip: %s\n' "$1" "$2"
  skipped+=("$1: $2"); nskip=$((nskip + 1))
}

has_cargo_tool() { cargo "$1" --version >/dev/null 2>&1; }

in_extension() { (cd extension && "$@"); }

# SR-58: `unsafe` only in phantab-window's OS modules. The other crate roots forbid it (so the compiler
# refuses it there); this also catches a root that drops the attribute, and test or bin targets.
# grep's exit 2 (an error: an unreadable file, a bad pattern) fails the check, never passes it.
unsafe_check() {
  local status=0 root nroots=0 rc
  for root in crates/*/src/lib.rs crates/*/src/main.rs; do
    [ -f "$root" ] || continue
    case "$root" in crates/phantab-window/*) continue ;; esac
    nroots=$((nroots + 1))
    rc=0
    grep -q '^#!\[forbid(unsafe_code)\]' "$root" || rc=$?
    case "$rc" in
      0) ;;
      1) echo "$root lacks #![forbid(unsafe_code)]"; status=1 ;;
      *) echo "grep failed (exit $rc) on $root"; status=1 ;;
    esac
  done
  [ "$nroots" -gt 0 ] || { echo "no crate roots found under crates/"; status=1; }
  # ci.yml's '\bunsafe\s*(\{|fn\b|impl\b|extern\b|trait\b)' in POSIX classes: macOS's BSD grep may lack \b, \s.
  # The output is captured first: in a pipeline into `grep -v`, the first grep's error would be lost.
  local w='[^[:alnum:]_]' hits
  rc=0
  hits="$(grep -rnE "(^|$w)unsafe[[:space:]]*(\{|(fn|impl|extern|trait)($w|\$))|allow\(unsafe_code\)" --include=*.rs crates)" || rc=$?
  if [ "$rc" -ge 2 ]; then
    echo "grep failed (exit $rc) searching crates/ for unsafe"; status=1
  elif [ "$rc" = 0 ]; then
    hits="$(printf '%s\n' "$hits" | sed '/^crates\/phantab-window\//d')"
    if [ -n "$hits" ]; then
      printf '%s\n' "$hits"
      echo "unsafe outside phantab-window"; status=1
    fi
  fi
  return $status
}

# SR-73: the build release.sh makes (cargo build --release -p phantab: no dev-dependencies) leaves
# test-seams off. A normal or build dependency, or the default features, naming it would ship the test
# overrides; release.sh's test-build gate refuses such a binary, and this catches it before a release.
# tests/install.rs runs this function, copied out by sed, with a stand-in cargo: keep its
# "name() {" line and closing "}" line as they are.
release_features_check() {
  local tree rc=0
  tree="$(cargo tree -p phantab -e normal,build,features --target all --locked -f '{p} [{f}]')" ||
    { echo "cargo tree failed"; return 1; }
  # The root line names its features: "phantab v0.1.0 (<path>) [default]". grep's exit 2 fails too.
  # Here-strings, not a pipe: under pipefail, grep -q's early exit fails the printf feeding it (SIGPIPE).
  grep -q '^phantab v.*\]$' <<<"$tree" || { echo "cargo tree named no phantab root"; return 1; }
  grep 'test-seams' <<<"$tree" || rc=$?
  case "$rc" in
    1) return 0 ;;
    0) echo "a release build of phantab turns test-seams on"; return 1 ;;
    *) echo "grep failed (exit $rc)"; return 1 ;;
  esac
}

lane4() { PHANTAB_TEST_REAL_EXTENSION=1 cargo test -p phantab --locked --test engine_real_extension -- --nocapture; }

# A dirty tree is checked as it stands, but that is not a check of the commit: the result is INCOMPLETE.
tree_state() {
  local st
  st="$(git status --porcelain 2>/dev/null)" || { echo unknown; return; }
  if [ -z "$st" ]; then echo clean; else echo dirty; fi
}
commit="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
tree_at_start="$(tree_state)"
tree_note=""
[ "$tree_at_start" = clean ] || tree_note=" DIRTY TREE ($tree_at_start)"
echo "phantab check on $platform ($(uname -m)), commit $commit$tree_note"
[ "$tree_at_start" = clean ] || git status --short
# rust-toolchain.toml pins the version; rustup installs it on first use.
rustup show active-toolchain
echo "node $node_version"
if [ "$chrome" = 1 ]; then echo "PHANTAB_TEST_CHROME=$PHANTAB_TEST_CHROME"; else echo "real-Chrome lanes: off (no --chrome)"; fi

step "cargo fmt" cargo fmt --all --check
step "cargo clippy" cargo clippy --workspace --all-targets --locked -- -D warnings
step "SR-58 unsafe stays in phantab-window" unsafe_check
step "SR-73 a release build has no test-seams" release_features_check

# SR-55: there is no weekly scheduled re-check any more, so this run is what catches a new RUSTSEC entry.
if has_cargo_tool deny; then
  step "cargo deny (SR-55)" cargo deny check
else
  skip "cargo deny (SR-55)" "cargo-deny not installed (cargo install cargo-deny --locked)"
fi
# SR-56: RustSec through cargo-audit too, a second reader of the advisory database.
if has_cargo_tool audit; then
  step "cargo audit (SR-56)" cargo audit --deny warnings
else
  skip "cargo audit (SR-56)" "cargo-audit not installed (cargo install cargo-audit --locked)"
fi

# Every test binary runs, so one failing lane does not hide another's result. The phantab self
# dev-dependency turns test-seams on for every test build, so no --all-features run is needed.
# tests/install.rs runs release.sh's and check.sh's own functions in bash. Here they must run, not skip
# (a skipped test reads as passed): PHANTAB_REQUIRE_SCRIPT_TESTS=1 makes a missing bash or node fail
# them, and PHANTAB_SCRIPT_BASH names the bash running this script, as a native path on Windows.
export PHANTAB_REQUIRE_SCRIPT_TESTS=1
if command -v cygpath >/dev/null 2>&1; then PHANTAB_SCRIPT_BASH="$(cygpath -w "$BASH")"; else PHANTAB_SCRIPT_BASH="$BASH"; fi
export PHANTAB_SCRIPT_BASH
step "cargo test" cargo test --workspace --locked --no-fail-fast

# No package's install script runs: none needs one (release.sh installs the same way).
step "extension: npm ci" in_extension npm ci --ignore-scripts
step "extension: npm run check" in_extension npm run check
step "extension: npm test" in_extension npm test
# SR-56: a high or critical advisory in any package fails, dev ones included: every package the
# extension has is a dev one, and the shipped JS is the compiler's output.
step "extension: npm audit (SR-56)" in_extension npm audit --audit-level=high

# The security lane: the hostile-input tests named in scripts/security-tests.txt, each of which must
# itself run and pass. The steps above pass when such a test is deleted, renamed or ignored; this one
# fails. It needs the test build and the npm ci above. The real-Chrome ones run only with --chrome.
if [ "$chrome" = 1 ]; then
  step "security lane" "$BASH" scripts/security-check.sh --chrome
else
  step "security lane" "$BASH" scripts/security-check.sh
fi

# Lane 4: the real extension, built from extension/ (needs the npm ci above), in that Chrome. On macOS it
# also checks the agent window reads minimized, Chrome's own state, which a locked Mac with its lid shut
# reports as well (docs/TESTING.md § 3): the machine need not be open for it.
if [ "$real_extension" = 1 ]; then
  step "lane 4 (real extension)" lane4
fi

printf '\n==== summary (%s) ====\n' "$platform"
[ "$npass" -gt 0 ] && for s in "${passed[@]}"; do echo "pass: $s"; done
[ "$nskip" -gt 0 ] && for s in "${skipped[@]}"; do echo "skip: $s"; done
[ "$nfail" -gt 0 ] && for s in "${failed[@]}"; do echo "FAIL: $s"; done
if [ "$chrome" = 0 ]; then
  echo "not run: real-Chrome lanes (their cases printed skip lines); a macOS arm64 machine runs 2 to 4 with --chrome --real-extension, lane 5 needs a spare Windows machine"
elif [ "$real_extension" = 0 ]; then
  echo "not run: lane 4 (pass --real-extension)"
fi
# Checked again at the end: a step that changes a tracked file or leaves an unignored one counts too.
tree_at_end="$(tree_state)"
dirty=0
if [ "$tree_at_start" != clean ] || [ "$tree_at_end" != clean ]; then
  dirty=1
  echo "DIRTY TREE: commit $commit plus uncommitted changes (at start: $tree_at_start, at end: $tree_at_end); this run did not check the commit alone"
fi
if [ "$nfail" -gt 0 ]; then
  echo "RESULT: FAILED ($nfail step(s))"
  exit 1
elif [ "$nskip" -gt 0 ] || [ "$dirty" = 1 ]; then
  why=""
  [ "$nskip" -eq 0 ] || why="$nskip step(s) did not run (see skip lines)"
  [ "$dirty" = 0 ] || why="${why:+$why; }DIRTY TREE"
  echo "RESULT: INCOMPLETE: every step that ran passed, but $why"
  exit 2
else
  echo "RESULT: PASSED"
fi
