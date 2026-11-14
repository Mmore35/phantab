#!/usr/bin/env bash
# Runs scripts/check.sh at one or more commits, in the order given, as ONE detached job, and returns at
# once. This is the way to run a merge gate from an agent's chat (docs/TESTING.md § 3).
#
#   scripts/gate-heads.sh [--chrome] [--real-extension] [--notify <command>] <commit>...
#
# --chrome and --real-extension pass through to check.sh; a macOS machine's gate is
#   scripts/gate-heads.sh --chrome --real-extension <head>...
# --notify runs `<command> <full sha> <RESULT> <log file>` after each commit (RESULT is PASSED,
# FAILED, INCOMPLETE or REFUSED), then `<command> DONE <summary> <status file>` at the end, or
# `<command> ABORTED "exit <n>" <status file>` if the job itself dies: a way to send a message per
# head, so a stall shows within minutes.
#
# Why it detaches (verified on macOS arm64):
# - A chat harness ends its agent process after each turn, and a job started with the agent's shell
#   tool dies with it, silently. So the job runs in its own session (POSIX setsid), stdin from
#   /dev/null, and outlives the chat that started it.
# - On Apple Silicon, a job whose parent is an x86_64 process (an Intel python, say) runs universal
#   binaries such as bash and Chrome as x86_64 under Rosetta, so the real-Chrome lanes would test an
#   Intel Chrome. The job starts under `arch -arm64` there, and check.sh refuses to run translated.
#
# It checks out each commit in THIS worktree, so the tree must be clean; use a linked worktree, never
# a working tree with changes. Each commit is resolved to its full sha before anything starts. When
# the job ends, it checks out again the branch (or commit) the worktree was on, before it writes DONE
# or ABORTED: a worktree left on a detached HEAD takes the next commit made there off its branch, and
# `git push origin <branch>` then pushes nothing and still succeeds.
# Output goes into the repository's common git dir (`git rev-parse --git-common-dir`), so it never
# dirties the tree and outlives `git worktree remove`. <run> is <UTC time>-<worktree folder name>:
#   <common git dir>/gate-runs/<run>/<sha>.log   check.sh's output, one per commit
#   <common git dir>/gate-runs/<run>/status      "<sha> <RESULT> exit <n>" per commit, then "DONE <summary>"
#   <common git dir>/gate-runs/<run>/runner.log  the job's own output
# It prints that folder and exits 0 once the job has started; read `status` to follow it.
set -euo pipefail

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }
refuse() { echo "gate-heads.sh: $*" >&2; exit 64; }

check_args=()
notify=""
return_to=""
commits=()
run_dir=""
worktree=""
while [ $# -gt 0 ]; do
  case "$1" in
    --chrome|--real-extension) check_args+=("$1") ;;
    --notify) [ $# -ge 2 ] || refuse "--notify needs a command"; notify="$2"; shift ;;
    --return-to) [ $# -ge 2 ] || refuse "--return-to needs a branch or commit"; return_to="$2"; shift ;;
    --run-detached) [ $# -ge 3 ] || refuse "--run-detached needs a folder and a worktree"
      run_dir="$2"; worktree="$3"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; refuse "unknown argument: $1" ;;
    *) commits+=("$1") ;;
  esac
  shift
done
[ "${#commits[@]}" -gt 0 ] || { usage >&2; refuse "name at least one commit"; }
if [ -n "$run_dir" ]; then cd "$worktree"; else cd "$(dirname "$0")/.."; fi

notify_cmd() {
  [ -n "$notify" ] || return 0
  # The notifier's failure must not stop the gate.
  bash -c "$notify \"\$@\"" notify "$@" || echo "gate-heads.sh: --notify failed (exit $?) for $1"
}

if [ -n "$run_dir" ]; then
  # The detached job itself. Every commit runs, even after one fails. An empty array is written
  # ${a[@]+"${a[@]}"}: macOS's bash 3.2 calls a bare "${a[@]}" unbound under set -u.
  status="$run_dir/status"
  restore() {
    [ -n "$return_to" ] || return 0
    git checkout -q "$return_to" || echo "gate-heads.sh: could not check out $return_to again"
    return_to=""
  }
  # If the job dies early, say so in status (and to --notify) instead of going silent.
  # shellcheck disable=SC2154
  trap 'rc=$?; grep -q "^DONE" "$status" 2>/dev/null || { restore;
    echo "ABORTED exit $rc (see runner.log)" >>"$status"; notify_cmd ABORTED "exit $rc" "$status"; }' EXIT
  passed=0
  total=0
  for sha in "${commits[@]}"; do
    total=$((total + 1))
    log="$run_dir/$sha.log"
    if ! git checkout -q --detach "$sha" >"$log" 2>&1; then
      echo "$sha REFUSED exit 64 (git checkout failed)" >>"$status"
      notify_cmd "$sha" REFUSED "$log"
      continue
    fi
    rc=0
    if [ "$(uname -s)" = Darwin ]; then
      # Keeps a shut Mac awake for the run (docs/TESTING.md § 3).
      caffeinate -dimsu scripts/check.sh ${check_args[@]+"${check_args[@]}"} >>"$log" 2>&1 || rc=$?
    else
      scripts/check.sh ${check_args[@]+"${check_args[@]}"} >>"$log" 2>&1 || rc=$?
    fi
    case "$rc" in
      0) result=PASSED; passed=$((passed + 1)) ;;
      1) result=FAILED ;;
      2) result=INCOMPLETE ;;
      *) result=REFUSED ;;
    esac
    echo "$sha $result exit $rc" >>"$status"
    notify_cmd "$sha" "$result" "$log"
  done
  summary="$passed/$total passed"
  restore
  echo "DONE $summary" >>"$status"
  notify_cmd DONE "$summary" "$status"
  exit 0
fi

# The launcher: check, resolve, then start the job detached and return.
[ -z "$(git status --porcelain)" ] || { git status --short >&2; refuse "the tree is not clean"; }
# Where to put the worktree back when the job ends: its branch, else its commit.
return_to="$(git symbolic-ref -q --short HEAD || git rev-parse HEAD)"
full=()
for c in "${commits[@]}"; do
  sha="$(git rev-parse -q --verify "$c^{commit}")" || refuse "no commit $c here (git fetch?)"
  full+=("$sha")
done

# The common git dir, not this worktree's own: removing the worktree after a PASS must not delete
# the evidence.
common_dir="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
run_dir="$common_dir/gate-runs/$(date -u +%Y%m%dT%H%M%SZ)-$(basename "$(pwd)")"
mkdir -p "$run_dir"
# The job runs a copy kept outside the tree: bash reads a script as it runs, and the job checks out
# other commits, which may change this file under it.
cp scripts/gate-heads.sh "$run_dir/gate-heads.sh"

job=(/bin/bash "$run_dir/gate-heads.sh" --run-detached "$run_dir" "$(pwd)")
[ "${#check_args[@]}" -eq 0 ] || job+=("${check_args[@]}")
[ -z "$notify" ] || job+=(--notify "$notify")
job+=(--return-to "$return_to")
job+=("${full[@]}")
if [ "$(uname -s)" = Darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
  job=(arch -arm64 "${job[@]}")
fi

# perl's POSIX::setsid gives the job its own session on macOS (which has no setsid command) and in
# Git Bash alike.
nohup perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV or die "exec: $!"' "${job[@]}" \
  </dev/null >"$run_dir/runner.log" 2>&1 &
echo "gate-heads.sh: started ${#full[@]} run(s) as pid $!, detached"
echo "  follow: cat \"$run_dir/status\""
echo "$run_dir"
