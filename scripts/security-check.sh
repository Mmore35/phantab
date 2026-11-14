#!/usr/bin/env bash
# The security lane: runs the tests listed in scripts/security-tests.txt, each of which feeds phantab
# a hostile input (a web origin calling the local service, a forged or changed extension, a CDP method
# off the allow-list, another session's page, markup that shadows the DOM, a planted password program,
# a changed install) and needs the refusal. docs/TESTING.md § Security lane has the map.
#
#   scripts/security-check.sh            runs every listed test this machine can run
#   scripts/security-check.sh --chrome   also the ones that need real Chrome (set PHANTAB_TEST_CHROME)
#   scripts/security-check.sh --list     prints the list and checks each test is still in the source
#
# A listed test must itself run and pass. One that is renamed, deleted, ignored, skipped or failing
# fails the lane: `cargo test` alone passes when a test is gone. scripts/check.sh runs this as one
# step, so the merge gate holds the list. Never pass --chrome on a machine someone is using: it starts
# real Chrome.
# Without it PHANTAB_TEST_CHROME is cleared. The extension's tests need `npm ci --ignore-scripts` in
# extension/ first (check.sh does it). This script installs nothing.
#
# Exit status: 0 every listed test for this machine ran and passed; 1 one did not; 64 refused to start.
# The last line is "security lane: PASSED" or "security lane: FAILED".
set -euo pipefail

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }
refuse() { echo "security-check.sh: $*" >&2; exit 64; }

chrome=0
list=0
for arg in "$@"; do
  case "$arg" in
    --chrome) chrome=1 ;;
    --list) list=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; refuse "unknown argument: $arg" ;;
  esac
done

cd "$(dirname "$0")/.."
. scripts/dev-env.sh
manifest=scripts/security-tests.txt
[ -f "$manifest" ] || refuse "no $manifest"

case "$(uname -s)" in
  Darwin) platform=macos ;;
  MINGW*|MSYS*|CYGWIN*) platform=windows ;;
  *) platform="$(uname -s)" ;;
esac

# The same rule as check.sh: nothing left in the shell starts Chrome, or points a test at the user's
# runtime folder or keychain.
unset PHANTAB_TEST_REAL_EXTENSION
unset PHANTAB_RUNTIME PHANTAB_TEST_KEYCHAIN PHANTAB_TEST_KEYCHAIN_PASSWORD
if [ "$chrome" = 1 ]; then
  [ -n "${PHANTAB_TEST_CHROME:-}" ] ||
    refuse "--chrome needs PHANTAB_TEST_CHROME (on macOS: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome)"
  export PHANTAB_TEST_CHROME
else
  unset PHANTAB_TEST_CHROME
fi
# tests/install.rs runs the release scripts' own text in bash: here a missing bash or node fails them
# instead of skipping (check.sh sets the same two).
export PHANTAB_REQUIRE_SCRIPT_TESTS=1
if command -v cygpath >/dev/null 2>&1; then PHANTAB_SCRIPT_BASH="$(cygpath -w "$BASH")"; else PHANTAB_SCRIPT_BASH="$BASH"; fi
export PHANTAB_SCRIPT_BASH

# The list, as three parallel arrays (macOS's /bin/bash is 3.2: no associative arrays).
cr="$(printf '\r')"
whens=()
targets=()
names=()
n=0
bad=0
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%"$cr"}"
  case "$line" in '' | '#'*) continue ;; esac
  when=""
  target=""
  name=""
  read -r when target name <<<"$line" || true
  case "$when" in
    all | unix | chrome) ;;
    *)
      echo "bad line in $manifest (the first word is all, unix or chrome): $line"
      bad=1
      continue
      ;;
  esac
  if [ -z "$target" ] || [ -z "$name" ]; then
    echo "bad line in $manifest (<when> <target> <test name>): $line"
    bad=1
    continue
  fi
  whens+=("$when")
  targets+=("$target")
  names+=("$name")
  n=$((n + 1))
done <"$manifest"
[ "$n" -gt 0 ] || refuse "$manifest lists no test"

# Where a target's tests are written, for the source check.
source_of() {
  case "$1" in
    lib) echo crates/phantab/src ;;
    ext:*) echo "extension/test/${1#ext:}.test.mjs" ;;
    *) echo "crates/phantab/tests/$1.rs" ;;
  esac
}

# in_source <target> <name>: the test is still written where the list says. This runs for every line,
# so a test this machine cannot run (unix, chrome) is still held by name on both machines.
in_source() {
  local src rc=0
  src="$(source_of "$1")"
  [ -e "$src" ] || return 1
  case "$1" in
    lib) grep -rqE "fn ${2##*::}\(" "$src" || rc=$? ;;
    ext:*) grep -qF -- "$2" "$src" || rc=$? ;;
    *) grep -qE "fn $2\(" "$src" || rc=$? ;;
  esac
  return $rc
}

# runs_here <when>: 0 run it, 1 not on this platform, 2 needs --chrome.
runs_here() {
  case "$1" in
    all) return 0 ;;
    unix) if [ "$platform" = windows ]; then return 1; else return 0; fi ;;
    *) if [ "$chrome" = 1 ]; then return 0; else return 2; fi ;;
  esac
}

states=()
i=0
while [ "$i" -lt "$n" ]; do
  if ! in_source "${targets[$i]}" "${names[$i]}"; then
    states+=(gone)
  else
    rc=0
    runs_here "${whens[$i]}" || rc=$?
    case "$rc" in
      0) states+=(run) ;;
      1) states+=(elsewhere) ;;
      *) states+=(chrome) ;;
    esac
  fi
  i=$((i + 1))
done

echo "security lane on $platform: $n tests listed in $manifest"

if [ "$list" = 1 ]; then
  i=0
  while [ "$i" -lt "$n" ]; do
    case "${states[$i]}" in
      gone)
        word="GONE     "
        bad=1
        ;;
      run) word="runs     " ;;
      elsewhere) word="unix only" ;;
      *) word="--chrome " ;;
    esac
    echo "$word  ${targets[$i]}  ${names[$i]}"
    i=$((i + 1))
  done
  if [ "$bad" = 1 ]; then
    echo "security lane: FAILED (a listed test is not in the source, or a line is bad)"
    exit 1
  fi
  echo "security lane: list ok (nothing was run)"
  exit 0
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
ext_built=0

# cargo_test_passed <target> <name>: runs that one test alone and says whether it ran and passed.
# The whole output goes to $scratch/out.
#
# One test for each cargo run, judged by cargo's exit status and the run's last "test result:" line,
# never by a "test <name> ... ok" line. Tests run on threads and some start a child that prints to the
# same stdout (signin_provider's the_provider_sees_only_the_allowed_environment runs its own test
# binary again), so in a run of several tests one test's "ok" can land in the middle of another's
# line. A macOS gate run failed that way with every test passing. The last "test result:" line is this
# run's own: a child's comes before it, and "1 passed; 0 failed; 0 ignored" is exactly the one test
# asked for, run and not ignored.
cargo_test_passed() {
  local rc=0 last=""
  case "$1" in
    lib) cargo test -p phantab --locked --lib -- --exact "$2" >"$scratch/out" 2>&1 || rc=$? ;;
    *) cargo test -p phantab --locked --test "$1" -- --exact "$2" >"$scratch/out" 2>&1 || rc=$? ;;
  esac
  [ "$rc" = 0 ] || return 1
  last="$(tr -d '\r' <"$scratch/out" | sed -n '/^test result: /h;${g;p;}')"
  case "$last" in
    "test result: ok. 1 passed; 0 failed; 0 ignored;"*) return 0 ;;
    *) return 1 ;;
  esac
}

# run_target <target>: runs that target's tests for this machine. The names that ran and passed go to
# $scratch/ok, one a line.
run_target() {
  local target="$1" k=0 rc=0 nrun=0
  local run=()
  while [ "$k" -lt "$n" ]; do
    if [ "${targets[$k]}" = "$target" ] && [ "${states[$k]}" = run ]; then
      run+=("${names[$k]}")
      nrun=$((nrun + 1))
    fi
    k=$((k + 1))
  done
  : >"$scratch/out"
  : >"$scratch/ok"
  [ "$nrun" -gt 0 ] || return 0
  printf '\n==> %s (%s)\n' "$target" "$nrun"
  case "$target" in
    ext:*)
      if [ ! -d extension/node_modules ]; then
        echo "extension/node_modules is missing: run npm ci --ignore-scripts in extension/" >"$scratch/out"
        rc=1
      else
        # The tests read the built folder. One build serves every extension file in the list.
        if [ "$ext_built" = 0 ]; then
          (cd extension && npm run build) >"$scratch/out" 2>&1 || rc=$?
          ext_built=1
        fi
        if [ "$rc" = 0 ]; then
          (cd extension && node --test --test-reporter=tap "test/${target#ext:}.test.mjs") >"$scratch/out" 2>&1 || rc=$?
        fi
      fi
      # TAP: "ok 3 - the test's title". A skipped or todo test carries a "# SKIP" tail and does not match.
      # node's runner writes these lines itself, one test at a time, so they are whole.
      tr -d '\r' <"$scratch/out" | sed -n 's/^ *ok [0-9][0-9]* - //p' >"$scratch/ok"
      if [ "$rc" != 0 ]; then
        echo "the run for $target failed (exit $rc); its output:"
        cat "$scratch/out"
      fi
      ;;
    *)
      k=0
      while [ "$k" -lt "$nrun" ]; do
        if cargo_test_passed "$target" "${run[$k]}"; then
          printf '%s\n' "${run[$k]}" >>"$scratch/ok"
        else
          echo "$target ${run[$k]} did not run and pass alone; its output:"
          cat "$scratch/out"
        fi
        k=$((k + 1))
      done
      ;;
  esac
  return 0
}

nok=0
nfail=0
nchrome=0
nother=0
seen=" "
i=0
while [ "$i" -lt "$n" ]; do
  target="${targets[$i]}"
  case "$seen" in
    *" $target "*) ;;
    *)
      seen="$seen$target "
      run_target "$target"
      j=0
      while [ "$j" -lt "$n" ]; do
        if [ "${targets[$j]}" = "$target" ]; then
          case "${states[$j]}" in
            gone)
              echo "NOT OK   $target  ${names[$j]}  (not in $(source_of "$target"): renamed or deleted?)"
              nfail=$((nfail + 1))
              ;;
            elsewhere)
              echo "not here $target  ${names[$j]}  (unix only: macOS runs it)"
              nother=$((nother + 1))
              ;;
            chrome)
              echo "not run  $target  ${names[$j]}  (needs real Chrome: run with --chrome)"
              nchrome=$((nchrome + 1))
              ;;
            *)
              if grep -qFx -- "${names[$j]}" "$scratch/ok"; then
                echo "ok       $target  ${names[$j]}"
                nok=$((nok + 1))
              else
                echo "NOT OK   $target  ${names[$j]}  (did not run and pass: not built here, ignored, skipped or failed)"
                nfail=$((nfail + 1))
              fi
              ;;
          esac
        fi
        j=$((j + 1))
      done
      ;;
  esac
  i=$((i + 1))
done

printf '\nsecurity lane on %s: %s ok, %s not ok, %s need real Chrome, %s unix only\n' \
  "$platform" "$nok" "$nfail" "$nchrome" "$nother"
if [ "$nfail" -gt 0 ] || [ "$bad" = 1 ]; then
  echo "security lane: FAILED"
  exit 1
fi
echo "security lane: PASSED"
