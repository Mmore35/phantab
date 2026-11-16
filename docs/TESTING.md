# Testing phantab

How phantab is tested: six lanes, how to run each, the checks a change must pass, the rules every
test keeps, the shared test kit, and notes on each lane.

Lane names: `docs/ARCHITECTURE.md` § Test lanes. Security requirements (`SR-n`):
`docs/THREAT-MODEL.md`.

## 1. Lanes

| # | Lane | What it drives | Where | Needs | OS |
|---|---|---|---|---|---|
| 1 | unit | pure functions, parsers, state machines; the TS extension against a fake `chrome` | `#[cfg(test)]` in each crate; `extension/test/*.test.mjs` | nothing | any |
| 2 | CDP | `phantab-cdp` against a real headless Chrome on the fixture server, including the `127.0.0.1` vs `localhost` out-of-process frames | `crates/phantab-cdp/tests/chrome.rs` | `PHANTAB_TEST_CHROME` | any |
| 3 | engine | the whole service (HTTP, MCP, CLI, host, bridge, engine) against a fake extension; with Chrome, a CDP-backed fake extension that answers bridge ops from a real headless Chrome | `crates/phantab/tests/*.rs` | nothing; `PHANTAB_TEST_CHROME` for the Chrome-backed cases | any |
| 4 | real-extension | the built TS extension (`npm run build:test`) loaded into Chrome for Testing or branded Chrome with `Extensions.loadUnpacked`, talking to the service through a test native host | `crates/phantab/tests/` (cases gated on Chrome) | `PHANTAB_TEST_CHROME` | Windows, macOS |
| 5 | window | real headful Chrome windows: hide at first show, find, show, hide; the quiet Run-key edit on a scratch key and an empty scratch shortcut folder; the clean quit of the lane's own Chrome by its user-data dir | `crates/phantab-window/tests/window_lane.rs` | `PHANTAB_TEST_CHROME`, a desktop session | Windows only: on macOS it passes without running (Mac window findings: `docs/MAC.md`) |
| 6 | golden files | phantab's wire formats and known-answer vectors (the MCP tool list, the sign-in seal) against golden files checked into the repository (§ 7) | `crates/phantab/tests/mcp.rs`; unit tests in `page_js`, `signin/page.rs`, `signin/seal.rs` | nothing | any |

A Chrome-backed test is a normal `#[test]`, never `#[ignore]`. Without `PHANTAB_TEST_CHROME` it prints
one `skip: <why>` line and passes, so `cargo test` stays green on machines without Chrome. A skip is
not a pass: `scripts/check.sh --chrome --real-extension` on a macOS arm64 machine runs lanes 2 to 4, and lane 5
needs a Windows machine where Chrome windows may pop up (§ 3).

## 2. Running locally

### Windows, Git Bash
Source the dev env first in every shell. It puts cargo and WinLibs' `dlltool` on PATH (the GNU
toolchain needs it for `windows-link`'s raw-dylib).
```sh
cd phantab && . scripts/dev-env.sh
# Use your own target dir when other sessions build at the same time.
export CARGO_TARGET_DIR=target-<yours>
```
PowerShell: `. scripts/dev-env.ps1`.

Each worktree's cargo target dir grows to 7–34 GB: remove it once that branch's work is done.

A copy of the tree (a `git archive` export, a mutation copy) and a worktree that share one target dir
reuse each other's builds, as two worktrees do (`CONTRIBUTING.md`): Cargo keys a workspace crate by its
path inside the workspace and by file mtimes, not by the checkout folder, so a copy whose files are older
than the last build runs the other tree's binary, and a stale build can point `CARGO_MANIFEST_DIR` at a
copy since deleted (a testkit test then fails with `NotFound`). Give each copy its own target dir, or
run `cargo clean -p phantab -p phantab-cdp -p phantab-testkit -p phantab-window` each time you switch
between the trees, before trusting a result: going back is the same trap the other way.

### Commands
| Want | Command |
|---|---|
| Format check | `cargo fmt --all --check` |
| Everything `scripts/check.sh` gates (§ 3) | `scripts/check.sh` (Git Bash or macOS bash) |
| Lints, as `scripts/check.sh` | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| Lanes 1 and 3 (no Chrome) | `cargo test --workspace` |
| One crate | `cargo test -p phantab-testkit` (or `-p phantab-cdp`, `-p phantab-window`, `-p phantab`) |
| One file | `cargo test -p phantab --test bridge` |
| One case | `cargo test -p phantab --test daemon -- routes_headers_and_request_checks --exact` |
| Lanes 2 to 5 | `PHANTAB_TEST_CHROME="/c/Program Files/Google/Chrome/Application/chrome.exe" cargo test --workspace` |
| Window lane only | `PHANTAB_TEST_CHROME=... cargo test -p phantab-window --test window_lane -- --nocapture` |
| Extension unit tests | `cd extension && npm ci --ignore-scripts && npm run check && npm test` |
| Lane 4 (real extension, shows a window) | `PHANTAB_TEST_CHROME=... PHANTAB_TEST_REAL_EXTENSION=1 cargo test -p phantab --test engine_real_extension -- --nocapture` |
| Test build of the extension | `cd extension && npm run build:test -- --host dev.phantab.bridge_test_<pid> [--out <dir>]` |

`PHANTAB_TEST_CHROME` may be branded Chrome, Chrome for Testing or Chromium. Branded Chrome 137+
ignores `--load-extension`, so lane 4 loads the extension with `Extensions.loadUnpacked` over CDP
(needs `--enable-unsafe-extension-debugging`; the test connects over `--remote-debugging-port=0`, no pipe
needed), which works on all three.

`npm run build:test` replaces the line `const HOST = 'dev.phantab.bridge';` in the built worker with
the test name and keeps the manifest key, so the test build has the same extension ID. It refuses a
missing or malformed name. The default output is `extension/dist-test/`; `dist/` is untouched.

Timing a change, four traps. From the workspace root, `cargo build --release --features
phantab/test-seams` (no `-p`) builds the phantab binary without the seams and says nothing (cargo 1.99):
the feature never reaches the package (`cargo tree -e features,no-dev -i phantab` with the same flags
stops with "missing dep graph connection for CLI feature"), and the `required-features` binaries
(`phantab-fake-provider`, `phantab-fake-bw`) are skipped without a message. Use `cargo build --release
-p phantab --features test-seams`. Test builds are not affected: the self dev-dependency turns the seams
on. Comparing two commits, give each its own `CARGO_TARGET_DIR`: two worktrees that share one share
`target/debug/phantab`, the `CARGO_BIN_EXE_phantab` the lanes start as `phantab serve`, and when the
second tree's units are already fresh cargo does not re-link it, so its lanes can silently run the other
commit's service. Time CPU work in a release build: in a debug build SHA-256 is slower than serde's JSON
parse, which turns a cache's gain into a loss. On Windows a tokio sleep shorter than the system timer
tick (about 15.6 ms) takes a whole tick, so a mock's per-command latency measures round trips, not
milliseconds.

Lane 4 registers its test host name only for the run: under HKCU on Windows (deleted after), and on
macOS as a manifest in the temp Chrome user-data dir's `NativeMessagingHosts`, which Chrome reads for a
custom `--user-data-dir`, so nothing outside the temp dir is written. The extension tests need Node 22
or later (`engines` in `extension/package.json`).

### macOS
Same commands without the dev-env step. Chrome:
`PHANTAB_TEST_CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"`. The window lane
is Windows-only and passes without running there; what was found about Mac windows is in `docs/MAC.md`.
Keep a checkout or CARGO_TARGET_DIR that has to last more than a day out of `/tmp`: macOS clears old files
there, and a clone kept in /tmp for days can lose files, its .git HEAD included. Keep the checkout out
of any folder with a `node_modules` above it too, such as a home folder holding a stray `~/node_modules`:
`npm run` puts every parent's `node_modules/.bin` ahead of PATH, so a `node` in one of them
(`~/node_modules/.bin/node`, from an `npm i node@20` there) runs the extension scripts (tsc fails with
`ERR_UNKNOWN_FILE_EXTENSION` and lane 4 panics in `npm run build:test`) while check.sh's Node check still
passes. A folder under `/Users/Shared` avoids both; `chmod 700` it on a Mac with other accounts, which can
otherwise read it. Removing the stray `~/node_modules` also works.

### Environment
| Variable | Read by | Meaning |
|---|---|---|
| `PHANTAB_TEST_CHROME` | lanes 2 to 5 (`phantab_testkit::CHROME_ENV`) | Chrome executable to drive. Unset: those cases skip. |
| `PHANTAB_RUNTIME` | the service; set per test to a temp dir by `crates/phantab/tests/common` | runtime dir |
| `PHANTAB_CLIENT` | the CLI; tests clear it and set it per case | CLI client id |
| `PHANTAB_TEST_*` | test builds only: passed through to a fake sign-in provider (SR-14) | fake provider control |
| `CARGO_TARGET_DIR` | cargo | keep parallel sessions apart |

### Traps
- Building a `git checkout-index` copy in the same CARGO_TARGET_DIR leaves test binaries pointing at
  the copy; after deleting it, `cargo clean -p <workspace crates>` before testing.
- `cargo deny` and `cargo audit` fetch the RustSec advisory database on each run, so a tree that passed
  yesterday can fail today with no change of its own (RUSTSEC-2026-0462 failed every branch at once). Run
  `cargo audit` on main first: if main fails too, the fix is a dependency PR to main, not a branch change.

## 3. Checks
No CI runs the checks on a push or a PR: `scripts/check.sh` runs them by hand, once on Windows and once
on macOS, and a PR merges when both have passed at its head. Releases have a workflow,
`.github/workflows/release.yml`, that runs the same release scripts on GitHub's runners and leaves a
draft release; the scripts also run by hand.

`scripts/check.sh` (POSIX bash: Git Bash on Windows, bash on macOS) runs every step even after one
fails, names each failure, and ends with `RESULT: PASSED` (exit 0), `FAILED`
(exit 1) or `INCOMPLETE` (exit 2). It refuses to start (exit 64) on a bad argument, with `--chrome` and
no Chrome, with node older than 22, or on a Mac shell running under Rosetta. A run from a cold cargo cache
can take over an hour; on a warm cache one head takes about 7 minutes.

**To run a gate in the background, use `scripts/gate-heads.sh`.** It takes check.sh's flags and
one or more commits, starts them as one detached job in its own session, and returns at once. Each
commit gets a log, a line in a status file, and an optional `--notify` command run per head. Two traps
it closes:
- A job started from a tool or terminal that ends its child processes when it exits (an automation
  harness, an editor's task runner) dies part way with nothing reported. A detached job outlives it.
- On Apple silicon, a job whose parent is an x86_64 process (an Intel python, say) runs bash and
  Chrome as x86_64 under Rosetta. The real-Chrome lanes then test an Intel Chrome and still pass; the
  log's first line says `macos (x86_64)`. gate-heads.sh starts the job under `arch -arm64`, and
  check.sh refuses to run translated.

The macOS gate for one or more heads, in a clean linked worktree:
`scripts/gate-heads.sh --chrome --real-extension <head>...`, then read
`<common git dir>/gate-runs/<time>-<worktree>/status` (the folder it prints). The logs live in the
repository's common git dir, so they stay after `git worktree remove`. The table below is what each check.sh run does:

| Step | Command |
|---|---|
| format | `cargo fmt --all --check` |
| lints | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| SR-58 | every crate root outside `phantab-window` has `#![forbid(unsafe_code)]`; no `unsafe` block, fn, impl, extern or trait, and no `allow(unsafe_code)`, outside `phantab-window` |
| SR-73 | `cargo tree -p phantab -e normal,build,features --target all` names no `test-seams`: the release build leaves the feature off |
| SR-55 | `cargo deny check` |
| SR-56 | `cargo audit --deny warnings` |
| tests | `cargo test --workspace --locked --no-fail-fast` (the self dev-dependency turns `test-seams` on, so no `--all-features` run) |
| extension | in `extension/`: `npm ci --ignore-scripts`, `npm run check`, `npm test`, `npm audit --audit-level=high` (SR-56, dev packages included) |
| security lane | `scripts/security-check.sh` (with `--chrome` when check.sh has it): every test named in `scripts/security-tests.txt` ran and passed (§ Security lane below) |
| lane 4 | with `--real-extension` only: `PHANTAB_TEST_REAL_EXTENSION=1 cargo test -p phantab --locked --test engine_real_extension -- --nocapture` |

The script installs nothing. When cargo-deny or cargo-audit is missing it prints
`skip: <tool> not installed (cargo install <tool> --locked)` and the result is `INCOMPLETE`: SR-55 or
SR-56 did not run. A dirty tree (`git status --porcelain` not empty, at the start or the end) is
`INCOMPLETE` too: the commit line and the summary say `DIRTY TREE`, since the run checked uncommitted
changes rather than the commit. An `INCOMPLETE` run is not a pass and does not clear a merge or a
release; a caller can tell it from a pass and a failure by the exit status.

`--chrome` sets `PHANTAB_TEST_CHROME` to the standard Chrome when it is unset
(`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
`C:\Program Files\Google\Chrome\Application\chrome.exe`), so `cargo test` also runs lane 2 and lane 3's
Chrome-backed cases; on Windows it runs lane 5 as well, which shows and hides real headful Chrome
windows. `--real-extension` adds lane 4 (it shows a window) and implies `--chrome`. Both are opt-in.
Without them the script clears `PHANTAB_TEST_CHROME` and `PHANTAB_TEST_REAL_EXTENSION`, so a value
left in the shell starts no Chrome.

Lane 5 (`window_lane.rs`) is Windows-only: on the Mac it prints why and passes without running. It
needs a spare Windows machine, or a Windows desktop session where Chrome windows popping up is fine, so
it and the other real-Chrome lanes on Windows run less often than the rest.

| Machine | Runs | Not there |
|---|---|---|
| A Windows x64 machine | `scripts/check.sh`, no flags: lanes 1, 3 and 6 without Chrome, the static checks, the extension | The real-Chrome lanes, unless Chrome windows popping up on that desktop are fine: lanes 4 and 5 open visible windows. |
| A macOS arm64 machine | `scripts/check.sh --chrome --real-extension`: everything but lane 5, lanes 2 to 4 included. It also runs with the screen locked: lane 4 checks that the agent window reads minimized as Chrome itself reports it, which holds locked too. What no lane sees is whether a window was drawn on screen; only a person watching an unlocked screen does (`docs/MAC.md` § Traps found). | Lane 5: `window_lane.rs` is Windows-only and passes there without running. |
| A spare Windows machine, or a Windows desktop session where pop-ups are OK | `scripts/check.sh --chrome --real-extension`: the Windows real-Chrome lanes, lane 5 (the window lane) included | |

What that means:
- The real-Chrome lanes on **Windows** (lanes 2 to 5) run only where Chrome windows may pop up. Until
  one runs, a Windows-only regression that only those lanes see (Win32 window control, the HKCU native
  host in lane 4) can merge unseen.
- Nothing runs on a schedule. The advisory checks (SR-55, SR-56) run when someone runs
  `scripts/check.sh`. Run it on both platforms before each release, so a RUSTSEC entry published since
  the last change is caught.
- Before merging, `scripts/check.sh` on Windows and `scripts/check.sh --chrome --real-extension` on
  macOS must both end `RESULT: PASSED` at the PR's head. A Mac that goes to sleep stalls the run until
  it wakes; gate-heads.sh runs the job under `caffeinate`, which keeps a Mac awake only on AC power. A
  MacBook on battery with its lid closed still sleeps, waking for about 30 s every 15 to 18 minutes, and a
  gate run then crawls: plug it in before starting one.
- No check sees whether the extension's agent window is drawn on screen: lane 4 reads the state Chrome
  reports, and `trials/mac/observe.mjs` drives Chrome through raw CDP without the extension. After a
  change to the agent window on macOS (the extension's hide, show, keepMinimized or close), watch the
  screen during an unlocked lane 4 run: the window shows for about a second when it is made, and about
  1.5 s when a dialog or a popup restores it (`docs/MAC.md`). That does not hold a merge.

Releases: `scripts/release.sh <tag>`. It refuses unless HEAD is
the tag's commit and the tree is clean; while `cargo deny check` (SR-55), `cargo audit --deny
warnings` or `npm audit --audit-level=high` (SR-56) fails, or cargo-deny or cargo-audit is
missing; with node older than 22; and while a setting from outside the repo could change the build
(`RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_TARGET`, `CARGO_BUILD_RUSTFLAGS`,
`CARGO_PROFILE_RELEASE_*`, a target's `RUSTFLAGS` or `LINKER`, a rustc wrapper, or a `[build]`,
`[profile]` or `[target]` table in a cargo config up the tree or in `CARGO_HOME`). It builds with
`--target <triple> --target-dir dist/.build`, its own dir, emptied for a release, never a shared
`CARGO_TARGET_DIR`; then it checks and hashes the copy in `dist/<tag>/`. `build-info-<platform>.txt`
there records `rustc -vV`, the linking C compiler's version, the version, commit and lockfile hashes,
the names of any such settings and how many cargo config files changed the build. It holds no path,
user or host name, since the bundles ship it as `build-info.txt`. The
binary must name no local path (`\Users\`, `/Users/` or `/home/`), so a published binary says nothing
about the machine that built it:
- **Remap.** The script sets the only rustflags, as `CARGO_ENCODED_RUSTFLAGS`: `--remap-path-prefix`
  for the home dir (`/user-home`), the rustup home and toolchain (`/rustup`, `/rustup/toolchain`),
  `CARGO_HOME`, where the registry and git sources are (`/cargo`), and the checkout (`/phantab`). On
  Windows each is given as both `C:\x` and `C:/x`.
- **Path gate.** `scripts/path-gate.mjs` then scans the copied binary, as ASCII and as UTF-16, for those
  three forms, and for `\Users\<user>`,
  `/Users/<user>`, `/home/<user>` and this machine's home, `CARGO_HOME` and checkout in every spelling
  (`C:\x`, `C:/x`, `/c/x`). A hit fails the build, a test build too. The remap rewrites source paths
  (panic locations, `file!()`), not `env!` values: an `env!("CARGO_MANIFEST_DIR")` in non-test code
  bakes the checkout in, so keep it under `#[cfg(test)]` or `#[cfg(debug_assertions)]`.
- **Gate test.** `scripts/release.sh --build-only --no-remap <tag>` builds without the remap; the gate
  must refuse it. Run it after changing the gate.
- **Test-build gate (SR-73).** The same scan refuses a binary holding `built with the test-seams
  feature`, the words of `phantab install`'s test-build refusal, which only a `test-seams` build has.
  `cargo test` runs this gate and check.sh's SR-73 step from the scripts' own text (`tests/install.rs`,
  in Git Bash on Windows, never WSL's): the gate refuses the test build's binary, and the step fails a
  `cargo tree` that turns `test-seams` on. A plain `cargo test` skips them with no bash (or no node,
  for the gate); check.sh sets `PHANTAB_REQUIRE_SCRIPT_TESTS=1`, which fails them instead, and
  `PHANTAB_SCRIPT_BASH` to the bash running it.

A Windows machine builds
`phantab-windows-x64.exe` (GNU, `x86_64-pc-windows-gnu`), a Mac `phantab-macos-arm64`, either
one `extension.zip` with `--extension` (`scripts/zip-deterministic.mjs`: sorted, stored, fixed times,
so the same source zips to the same bytes on both OSes; `upload` refuses a zip that differs from the one
already in the draft). Each writes a `.sha256` beside its file, into `dist/<tag>/`, then
`scripts/release.sh upload <tag>` adds its half to the tag's **draft** release. Publishing the draft is
a maintainer's step. `--build-only` is a test build with no tag check, which `upload` refuses.

To check a downloaded file, compare the hash value alone; the name inside the `.sha256` is the
installed one (`phantab.exe`, `phantab`, `extension.zip`), so `sha256sum -c` passes only after renaming
the file to it. In Git Bash or a Linux shell:

```
f=phantab-windows-x64.exe
[ "$(cut -d' ' -f1 "$f.sha256")" = "$(sha256sum "$f" | cut -d' ' -f1)" ] && echo OK || echo MISMATCH
```

On the Mac, `shasum -a 256` in place of `sha256sum` (with `f=phantab-macos-arm64`). In PowerShell:
`(Get-FileHash phantab-windows-x64.exe).Hash.ToLower() -eq (Get-Content phantab-windows-x64.exe.sha256).Split(' ')[0]`.
Or rename first (`mv phantab-windows-x64.exe phantab.exe`), then `sha256sum -c phantab-windows-x64.exe.sha256`.

The Windows release is GNU, not MSVC: what phantab's Windows builds have always been. It needs WinLibs on PATH (`scripts/dev-env.sh`). `release.sh` uses WinLibs' `objdump`
to refuse an exe that imports a runtime DLL Windows does not ship (`libgcc_s_seh-1`, `libwinpthread-1`,
`vcruntime*`); today it imports only system DLLs. A Windows machine whose toolchain is MSVC builds it
too once the `x86_64-pc-windows-gnu` target is added (and WinLibs is on PATH); without it the build
fails, `--build-only` included.

The Windows bundle (`scripts/bundle-windows.sh <tag>`, after `release.sh --extension <tag>`) packs
that tag's binary and unpacked extension with `install.ps1`, a tiny unsigned test program and
`SHA256SUMS.txt`, then runs `scripts/windows-bundle/test-bundle.ps1` on the zip. The test unzips it,
cuts PATH to System32 (no cargo, rustc, node, gcc or npm), points `USERPROFILE` and `LOCALAPPDATA` at a
temp folder with a fake Chrome user-data dir (two profiles; `Profile 7` last used), and passes
`-NativeHostKey` so the native host goes under a scratch HKCU key. It checks that a changed file is
refused, then runs `-CheckOnly`, an install, a second install and `-Uninstall -RemoveFiles`, each in a
session lowered to Constrained Language Mode (what AppLocker or WDAC gives an unsigned script; Windows
11 ignores `__PSLockdownPolicy` in a process environment, so the session sets its own mode), and
asserts the binary, extension, registration, profile binding, BOM-less `.claude.json`, MCP and Codex
entries, and their removal. Last it compares this machine's real native host value, runtime state and
client entries with their values before: they must not change. It must print `RESULT: PASSED`; run it
after any change under `scripts/windows-bundle/`. It is safe to run on a machine in use.

The macOS bundle (`scripts/bundle-macos.sh <tag>`, on a Mac after `release.sh --extension <tag>`)
packs the same way with `install.sh` and runs `scripts/macos-bundle/test-bundle.sh` on the zip. It
unzips it, marks `phantab` as downloaded (`com.apple.quarantine`), and runs `install.sh` with `HOME`
pointed at a temp folder holding a fake Chrome user-data dir, PATH cut to macOS's own folders, and a
stand-in Chrome program. It checks the same cases as the Windows test: a changed file refused,
`--check-only` (which must clear the quarantine mark), an install, an update that keeps the bound
profile, `--profile`, `--uninstall` then `--uninstall --remove-files`, and that the Mac's real native
host manifest, runtime state and client entries did not change. It needs node for its JSON checks; the
install itself does not. The release workflow runs both bundle tests on its runners.

### Security lane
`scripts/security-tests.txt` names the tests that feed phantab a hostile input and need the refusal.
`scripts/security-check.sh` runs them, and `scripts/check.sh` runs that as one step, so the merge gate
holds the list. A listed test must itself run and pass: one that is deleted, renamed, ignored, skipped
or failing fails the step. Each Rust test gets a cargo run of its own, so another test's output cannot
hide its result. `cargo test` alone still passes when a test is gone, which is why the list
exists.

| Hostile input | Where the tests are |
|---|---|
| A web page calls the local service: a foreign `Origin`, a rebound `Host`, no token or a near-miss token, a body before the key is known | `daemon` |
| Another user or program on the machine reads the endpoint, the runtime folder or the binary folder, or links the runtime folder elsewhere | `daemon` |
| A program posing as the service, or as our extension, asks the native host for the token | `cli_host` |
| A forged, changed or silent extension reaches the bridge, or asks for a CDP method off the allow-list | `bridge`, `lib`, the extension's `manifest`, `ops` and `frames` tests |
| One agent session reaches another's page; a page's markup hides a sensitive step from the check; a page puts its own words where a message names another extension | `lib`, `engine_chrome` (real Chrome) |
| A page, or a planted program, gets between the owner's passwords and the sign-in form; a site shows the value back on the page; a page holds a password, card number or code in a field a snapshot reads | `signin_provider`, `signin_bitwarden`, `signin_fake_page`, `lib`, `signin_echo` and `engine_chrome` (real Chrome) |
| A changed binary, a test build or a moved workflow action reaches an install or a release | `install`, `lib` |
| An agent, or any shell without the owner at it, restarts the owner's Chrome | `cli_host`, `lib` |

- Run it alone with `scripts/security-check.sh`, about two minutes on a warm build. `--list` prints the
  list and checks each name is still in the source, without building. `--chrome` also runs the lines
  marked `chrome`, with `PHANTAB_TEST_CHROME` set (the macOS gate does).
- A line marked `unix` is not built on Windows, or is ignored there. A line marked `chrome` needs real
  Chrome. Both are still checked by name on every machine, and the Mac's gate runs them.
- Add a line when a test proves a hostile input is refused. Rename the line with the test.
- What the lane cannot hold: a page's text talking the agent into a tool call. That is the agent's
  choice, not a phantab input, so no phantab test can prove it never happens. The lane holds what
  phantab does about it: page text is cut and returned as data, another session's page is refused,
  and a sensitive step waits for `ownerConfirmed` when `guardrails` is `light` or `full`
  (`docs/GUARDRAILS.md`, `docs/THREAT-MODEL.md` T6, R3).

## 4. Safety rules
Every test, in every lane:

1. **Never the owner's Chrome.** A test launches its own Chrome from `PHANTAB_TEST_CHROME` with a fresh
   `--user-data-dir` in a `TempDir`, closes it with `Browser.close`, then kills its own child process.
   It never attaches to, lists, or closes a Chrome it did not start, and never reads the owner's
   profile.
2. **Temp runtime.** `PHANTAB_RUNTIME` is a `TempDir` per test. Nothing writes
   `%LOCALAPPDATA%\phantab` or `~/Library/Application Support/phantab`.
3. **Test native host names only.** `dev.phantab.bridge_test_<pid>`
   (`phantab_testkit::test_native_host_name()`), never `dev.phantab.bridge`.
   - Windows: the host goes in `HKCU\Software\Google\Chrome\NativeMessagingHosts\<test name>`, added at
     start and deleted at the end (in a drop guard, so a failing test removes it too). From Git Bash
     call `reg` through a process API, not the shell: MSYS rewrites `/ve`, `/d` and `/f` as paths.
   - macOS: the manifest goes in `<temp user-data-dir>/NativeMessagingHosts/<test name>.json`, inside
     the test's own profile; nothing in `~/Library`.
4. **Scratch registry.** Installer and window tests use `HKCU\Software\phantab-test-<pid>\<test>`, and
   pass it as the Run key or host key. The `<pid>` key is deleted when the last test under it ends.
   No test reads or writes the real Run key. Quiet debugging's shortcuts and LaunchAgent go the same
   way: tests pass a scratch folder (`--shortcut-dir`, `--launch-agents-dir` in a `TempDir`), and a
   `test-seams` build given none rewrites no shortcut and writes no LaunchAgent.
   `quiet_debugging_round_trip_on_scratch_shortcuts` makes its `.lnk` files through `WScript.Shell`
   and runs install's on, off and uninstall on them. Like `--run-key`, these flags are left out of the
   usage text but not gated behind `test-seams`: each only narrows install to a folder the caller names. No test quits a Chrome
   it did not start.
5. **Never the owner's client configs.** Installer tests write Claude and Codex configs in a `TempDir`
   and pass their paths. No test reads `~/.claude.json`, `~/.claude/` or `~/.codex/`.
6. **No secrets in output.** The fake provider's values are the fixture constants
   (`phantab_testkit::sign_in`). A sign-in test checks every result, error, log line and the service's
   stderr with `find_leak(text, &fixture_leak_forms())`. The endpoint token and viewer tokens are
   never printed; a test that needs them reads them from the temp `endpoint.json`.
7. **Loopback only.** The fixture server binds `127.0.0.1` (and `[::1]` for the twin). Nothing goes to
   the network. `allowLoopback` (plain-HTTP sign-in on `127.0.0.1` and `localhost`) exists only in
   test builds (SR-45).
8. **No OS passkey dialog.** A request that reaches Chrome's own `WebAuthn` with no authenticator of
   its own goes to the OS: Windows draws its passkey dialog on the owner's screen, even for a headless
   Chrome. A test page that asks for a passkey replaces `navigator.credentials.get` (or `.create`)
   with a stand-in (`sign-in/passkey-ask`, `sign-in/passkey-onload`), or a test calls the real one
   only with an
   aborted signal and a CDP virtual authenticator (`WebAuthn.enable`, `addVirtualAuthenticator`) set
   on the page's own session before it loads. Never send `WebAuthn.disable` while the page can still
   call it.

## 5. Test kit: `crates/phantab-testkit`
A dev-dependency of every crate with browser or service tests.

| Item | Use |
|---|---|
| `CHROME_ENV` | `"PHANTAB_TEST_CHROME"` |
| `skip_unless_chrome() -> Option<PathBuf>` | the Chrome to drive, or prints `skip: ...` and gives `None` |
| `test_native_host_name() -> String` | `dev.phantab.bridge_test_<pid>` |
| `TempDir::new(prefix)` | scratch folder, removed on drop; `path()`, `join()`, `write()`, `child_dir()`, `keep()` |
| `FixtureServer::start()` | the fixture pages on two loopback origins (below) |
| `Gate` (from `server.gate(name)`) | holds `/hook/<name>` requests: `arrived(timeout)`, `arrivals()`, `release()`; dropping it releases |
| `RecordedRequest` | `method`, `path`, `url`, `listener` (`Listener::Primary` or `Twin`); `query_param()`, `form()`, `form_pairs()`, `header()`, `contains()` |
| `fixture_paths()`, `fixture_source(key)`, `fixtures_dir()` | the page list and raw templates |
| `foreign_extension_dir()` | an MV3 extension that injects another extension's frame (below) |
| `sign_in::{USERNAME, PASSWORD, CODE}` | `fixture-user@example.test`, `S3ntinel pw+/=!`, `914207` |
| `sign_in::sweep_forms(pw)` | the six forms the leak sweep searches for |
| `sign_in::leak_forms(pw, code)`, `fixture_leak_forms()` | those, plus the real form-post encoding and the code |
| `sign_in::find_leak(text, forms)` | the first form found in `text` |
| `sign_in::{encode_uri_component, encode_uri, form_urlencode}` | encoders equal to JavaScript's `encodeURIComponent`, `encodeURI` and form encoding |

### Fixture server
- Primary: `http://127.0.0.1:<port>`. Twin: `http://localhost:<twin port>` on `127.0.0.1` and, when
  the machine has it, `[::1]`. The two are different sites, so a twin frame inside a primary page is an
  out-of-process frame.
- `server.url(path)`, `server.twin_url(path)`, `origin()`, `twin_origin()`, `port()`, `twin_port()`,
  `twin_has_ipv6()`.
- Every request is recorded: `requests()`, `posts()`, `clear_requests()`, `saw(needle)` (searches
  decoded URLs and bodies), `wait_for_request(pred, timeout)`.
- Pages are templates: `{{PRIMARY}}` and `{{TWIN}}` are the two origins, `{{SELF}}` the serving origin,
  `{{query:NAME}}` a query value, HTML-escaped.
- Every answer has `Content-Length`, `Cache-Control: no-store` and `Connection: close`. Refused:
  chunked bodies (501), bodies over 1 MiB (413), heads over 64 KiB (431), malformed requests (400),
  not HTTP/1.x (505).

| Route | Answer |
|---|---|
| `GET /` | an index linking every page |
| `GET /<key>` or `/<key>.html` | the fixture page |
| `GET /slow?ms=<n>&then=<path>` | waits `n` ms (at most 120000), then serves `then` (or a "Waited n ms" page) |
| `GET /redirect?to=<url>&status=<code>` | a redirect, default 302 to `/engine/basic` |
| `GET /status?code=<n>` | an empty page with that status, default 500 |
| any `/hook/<name>` | `ok`, held while a gate of that name is closed |
| `POST /post/<name>` | recorded as a post; `userstep` answers the password step, `tocode` the code step, `tokey` the security-key step, `wrong` the wrong-password page, `echo` `<title>Oops</title><p>You typed <escaped pass></p>`, `thendetach` the landed page plus a script that fetches `/hook/detach-me` after 500 ms; anything else `<title>Landed</title><p>Welcome back</p>` |
| `GET /post/<name>` | a GET form's submit: recorded as a post, landed page |
| `/captcha-frame/*[?fixture=<key>]` | a stub page for captcha frame URLs, or the fixture page `<key>` there, so a stand-in check can sit at a provider-looking URL |
| anything else | 404 `none` |

### Fixture pages (147)
| Group | Keys |
|---|---|
| engine | `engine/basic`, `engine/dialogs`, `engine/framed-task` (a task form in a frame, inside open shadow roots), `engine/task-form`, `engine/record` (a filled record beside password, card and code fields), `engine/framed-pay` (`engine/clobber-pay` in a frame), `engine/handoff`, `engine/login`, `engine/moves`, `engine/popup`, `engine/wait`, `changes`, `navigates` |
| snapshot | `snapshot/busy`, `snapshot/deep`, `snapshot/inner`, `snapshot/long-text`, `snapshot/many`, `shadow/nested`, `frames/cross-site`, `forms/controls` |
| sign-in, one step | `sign-in/one`, `framed`, `nested`, `crossframe`, `shadow`, `noform`, `outside`, `deep`, `react`, `jsaction`, `actionfield`, `landed` |
| sign-in, steps | `userstep`, `passstep`, `passthencode`, `code`, `passthenkey`, `securitykey`, `codebeside`, `opensframe`, `inertpass`, `aca`, `aca-c` |
| sign-in, refusals | `newpass`, `twopass`, `card`, `cardframe`, `cardonly`, `pay`, `subscribe`, `forgot-password`, `signup`, `blank` |
| sign-in, walls | `passkey`, `passkey-ask`, `passkey-onload`, `captcha`, `captcha-frame`, `captcha-invisible`, `captcha-zero`, `captcha-hidden`, `captcha-offscreen`, `captcha-solved`, `captcha-unsolved`, `captcha-framed-solved`, `captcha-framed-unsolved`, `captcha-other-kind`, `captcha-shadow-solved`, `captcha-scrolled`, `captcha-shadow-scrolled`, `captcha-slotted-scrolled`, `captcha-rtl`, `captcha-inner-rtl`, `captcha-column-reverse`, `captcha-parked-long`, `captcha-parked-fixed`, `code-boxes`, `readonly`, `twobuttons`, `nobutton`, `otherform`, `ignores`, `aimframe`, `closedframe`, `overframe` |
| verification | `verify/box`, `verify/shop`, `verify/wall`, `verify/autoclear`, `verify/never`, `verify/widget`, `verify/challenge-only`, `verify/captcha-word-title`, `verify/hold`, `verify/slider`, `verify/offscreen` |
| sign-in, hazards | `leaves`, `plainhttp`, `getform`, `getshadow`, `echo`, `wrong`, `hides`, `moves`, `detaching`, `landsthendetaches`, `leak-dom`, `leak-hash`, `leak-url`, `clobber-base`, `clobber-id`, `clobber-get`, `clobber-doc`, `tamper`, `leak-clobber`, `unresolved`, `form-button`, `rerender` |
| sign-up | `signup/basic`, `confirm`, `signin`, `change`, `card`, `pay`, `getform`, `elsewhere`, `crossframe`, `framed`, `shadow`, `maxlength`, `shortmax`, `rules`, `copy`, `copytext`, `reveal` |

(The sign-in keys all start `sign-in/`, the sign-up keys `signup/`.) The `verify/*` pages are stand-in checks only: a box, a wall,
a press-and-hold and a slider that clear on a person's input, and pages that look like a check but are
not. No real third-party CAPTCHA is ever loaded.

### Foreign extension
`fixtures/foreign-extension/` is an unpacked MV3 extension. On focus or click in a `127.0.0.1` page it
inserts, in a closed shadow root, an iframe of its own `overlay/menu.html`: the shape of a password
manager's autofill menu, which makes Chrome detach the debugger. Query switches on the page URL:
`?sticky` (the frame comes back after removal), `?reinit` (re-inserts on every mutation),
`?autoclose=<ms>`. Load it next to the bridge with `Extensions.loadUnpacked`.

## 6. Writing a test
- Browser tests: `let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };`
- Runtime: `TempDir::new("phantab-rt")`, write `config.json` into it, start the service with
  `PHANTAB_RUNTIME` set (see `crates/phantab/tests/common/mod.rs`).
- Never sleep for a fixed time to wait for a state. Poll with a deadline, or use a `Gate` or
  `wait_for_request`.
- Shorter sign-in budgets come from the test-only engine options, for example
  `{observeMs:1500, settleMs:1200, findMs:600}`.
- Assert on exact message strings: agents read them, so a changed message is a changed interface.
- A fake extension that sends a CDP event the code does not match sees it dropped by the bridge
  (perf-data-3): an engine test that reads a new event needs it in `phantab_cdp::EVENTS` too, and
  `cdp_methods.rs` says so when the code reads it in a shape its scan knows (`matched` lists them).
  A listed event stays valid while any code literal names it, so an event read in a shape the scan
  does not see is kept on the list rather than filed in `cdp-methods.ts`, where the filter drops it.
  Filing it there fails too: `every_command_the_code_names_is_sent` wants each command name the code
  uses passed straight to a call somewhere (`send(None, "X", ..)`; not `Some(..)`, `.eq(..)`,
  `.contains(..)` and the other `NOT_CALLS`), and an event the code only reads never is. A read
  through a helper call of its own (`is(m, "X")`) would pass as a send.
  The service can read an event only by its exact name: a prefix or a built name cannot be listed,
  and `no_code_reads_an_event_by_prefix` fails on a literal shaped like a domain prefix (`"Page."`),
  a format string that starts with one or with a name (`format!("Page.{e}")`), or a name tested as a
  prefix (`starts_with("Page.frame")`). A name split at its dot (`split_once('.')`) is not seen. Its
  one known non-CDP match, `NOT_A_PREFIX`, is `"Cancelled."` (bitwarden.rs, a message to the owner);
  a new one-word sentence such as `"Done."` fails the same way and goes on that list.
  A fake that checks the welcome compares it with that list (`common::hello`). The CDP-backed fake
  (`common/cdp_extension.rs`) ignores the list and forwards everything, like an extension older than
  it, so lanes 2 and 3 cover the bridge's drop; only lane 4 (`--real-extension`) runs the
  extension's own filter in Chrome.
- `cdp_methods.rs` scans the code for CDP names up to a file's inline `#[cfg(test)] mod <name> {`.
  A bare `#[cfg(test)] mod tests;` (engine/mod.rs) is not where the code ends; cutting there hid the
  rest of that file from the scan. Its lexer (`lex`) reads escapes (`\"`), char literals (`'"'`),
  raw strings (`r#"…"#`, `br"…"`, `cr"…"`) and `//` and nested `/* */` comments, so a quote in any
  of them does not swap code and string, and a quoted name in a comment is not a literal: it neither
  needs listing nor counts as read. Known limit: the scans test a literal's source text, so a name
  spelled with an escape (`"Page.file\x43hooserOpened"`) or split by a `\` line continuation is not
  a name to any of them. Write CDP names plainly.

## 7. Golden files
Lane 6 holds phantab's own fixed outputs to golden files checked into the repository: the MCP
`tools/list` answer the agents see, the sign-in seal's known-answer vector (SR-43), and the other wire
formats that agents, providers and installed configs depend on. A change that alters one fails the
lane until the golden file is updated in the same PR, so every such change shows in review. Update a
golden file only on purpose, and say in the PR why the output changed. The tool list is
`crates/phantab/tests/fixtures/tools-list.json`; rewrite it from the built binary with
`PHANTAB_UPDATE_GOLDEN=1 cargo test -p phantab --test mcp`. The page functions' hashes and the seal's
vectors are constants in their unit tests. The lane needs nothing beyond `cargo test` and runs on every
platform.

## 8. Lane notes
Test files, by the short names used above:
- `bridge` = `crates/phantab/tests/bridge.rs`
- `daemon` = `crates/phantab/tests/daemon.rs`
- `mcp` = `crates/phantab/tests/mcp.rs`
- `cli_host` = `crates/phantab/tests/cli_host.rs`
- `install` = `crates/phantab/tests/install.rs`
- `cdp` = `crates/phantab-cdp/tests/chrome.rs`
- `window` = `crates/phantab-window/tests/window_lane.rs`
- `threads` = `crates/phantab/tests/threads.rs`
- `ext` = `extension/test/*.test.mjs`

- Lane 2: `cdp::real_chrome` (evaluate and handles, forms and keyboard, selectors that reach a
  website frame and open shadow roots (`framed_forms`), the isolated world and covered clicks,
  navigation, out-of-process frames, screenshots, closing). It runs headless at a device scale of 1 (`devicePixelRatio` 1, a 756x469 view on the Mac), where the `0.9px`-padded frame
  (`#xpad`) reads between pixels (`BetweenPixels`); a device scale of 2 has not been run. Its test
  output is hidden by `scripts/check.sh`, so the `#xpad`, `#xfilter`, `#xfixed`, `#xshift` and
  `#xclear` outcomes, and what each refused frame lane said (`sr34-turned.txt`), are also written to
  `"${CARGO_TARGET_DIR:-target}"/tmp/sr34-*.txt`. `#xclear` proves only that phantab does not falsely
  refuse a transparent cover over a card's frame (the card takes the press, no fallback); it does not
  prove whether Chrome presses through such a cover. Its control, a bare press with the cover gone,
  did not reach the frame on the Mac's headless Chrome (fdf4346, 817fcd1), so `sr34-xclear.txt`
  reports it (`control: the frame took the press` or `control: Chrome did not press through (the
  cover result is a non-refusal check only)`) and nothing asserts it. No lane proves pressing through
  a cover into a frame: the lanes that check a frame got no press refuse before any press, so it is a
  residual. Frames that something
  up the flat tree may move by a fraction (`#xslot` and `#xslotc`, slotted into an open and a closed
  shadow root under a translating wrapper; `#xsticky`; `#xscroller`, in a scroller at `left: 0.5px`)
  must click by the box rule with `[Transformed]`, and frames in a `scale(1.5)` (`#xscale`, and
  `#xscalec` through a closed shadow root), mirrored where only the box model's quads show it
  (`#xmirrorc`, a closed root's `scaleX(-1)` wrapper under a host at `translate: 0px`; `#xdetails`,
  a `<details open>` whose `::details-content` is `scaleX(-1)`, skipped on a Chrome without that
  selector) or in a `scale(1.0000001)` (`#xtiny`, which computed style's six digits read as 1) must
  be refused before either check, nothing pressed in them. Frames at a whole offset must get the
  press at the point checked, with no fallback: `#xwhole`, `#xfilter` (under a `filter`, in a
  wrapper at `left: 0.5px`), `#xfixed` (`position: fixed`, the page scrolled by 37 px) and `#xshift`
  (an SVG `feOffset` filter on its wrapper draws it 40 px right: filters move neither layout nor hit
  testing, so the press must land where layout has it, not where it is drawn). A fixture whose handlers set flags the lane reads
  with `evaluate_main` must be built with `evaluate_main` too: built in phantab's isolated world,
  its flags are that world's, and every read is `null`. The flags start `false`, so a "not
  clicked" check fails when it reads the wrong world.
- Lane 3, built-in Bitwarden source: `signin_bitwarden` against `tests/bin/fake_bw.rs` (`phantab-fake-bw`,
  test-seams), a stand-in for the Bitwarden CLI; never a real `bw` (`docs/BITWARDEN.md` § Testing).
- Lane 3, verification hand-off: `verification` against the `verify/*` pages with a fake
  CDP extension and `PHANTAB_TEST_WINDOWS=none` (pop-up and hide are the logged `markShown true` and
  `markShown false`). It proves the grace, the pop-up, the hide, a check that clears by itself never
  popping up, a page the owner holds staying with them, a widget waiting for the agent to ask, the
  viewer's Done and Not now, and the remote listener: only the live view, only through the owner's route, and only with a live link. In
  every case the only input the page gets is the owner's own (relayed) input; Phantab sends none.
- Lane 3, sign-in over a scripted page (no Chrome): `signin_fake_page`, the fake provider and a CDP page
  whose frames answer each in-page function by its source. The cases a real page cannot stage on cue: a shown password or a code in a `tel` field held until blank, a frame that
  kept the password and does not answer, a code shown back in the page, a report the frame tree does not
  match, and a frame the frame tree shows moving while the provider is asked. For sign-up (a
  `MemorySource`): a frame that held a copy of the new password and then stops answering
  holds the page and its screenshots until it goes, a frame that never held one does not, a page that
  puts its copy back after each blank stays held, and a copy in the page's text ends the page.
- Lane 3, echoed values through `phantab serve` (real Chrome): `signin_echo`, on the echo, leak-url,
  leak-dom, leak-hash and leak-clobber pages. The sign-in goes on, every answer is redacted, screenshots
  of the tab are refused, the account is not stopped, and a fresh attach to a tab of your own is still
  redacted.
- Lane 5: `window::window_lane` (hide at first show, find, show, hide; quiet on a scratch Run key; the
  Restart Manager quit of its own browser, which must exit by itself, and nothing then runs on its dir). On
  a kept window, through the `test-seams` view of the keeper and a show log of its own Chrome's
  windows: a popup (`window.open` with features), a new tab and an `alert()` from its page leave it
  hidden (any show undone within 2 s); every window they show is the browser process's, printed with
  its pid and class; Chrome killed outright has its hook dropped within 5 s, and a second Chrome's
  window is then kept as the first's was. Each prints a `timing:` line.
- Lane 1, the Windows keeper (SR-61): `win32.rs` unit `keeper_scope_and_lifetime` on test windows of its
  own: a hook only for the owning process and never for pid 0, a show from this or another process
  undone, no other process's window seen, a released window left shown, and the hook and its thread
  gone with the last kept window. Its shows from the other process are ten show calls
  (`SW_SHOWNOACTIVATE`, `SW_SHOW`, `SW_SHOWNORMAL`, `SW_SHOWMAXIMIZED`, `SW_RESTORE` from maximized and
  from minimized, `SW_MINIMIZE`, `ShowWindowAsync`, `SetWindowPos` with `SWP_SHOWWINDOW`, sync and async).
  A test window answers `WM_GETMINMAXINFO` with 1x1 off screen, so maximized it stays off the owner's
  screen (`a_maximized_test_window_stays_off_screen`). Its neighbours:
  `a_failed_hook_fails_its_own_calls`, `an_ended_process_takes_its_windows_and_hook` (a process that
  exits without destroying its window), `a_held_up_keeper_fails_the_call_but_keeps_the_window`,
  `a_quit_keeper_thread_is_replaced` (a show in the restart's gap is undone by the new hook),
  `a_hook_failed_after_a_restart_hides_its_windows`, `a_failed_wait_hides_the_kept_windows`,
  `a_hook_is_set_only_for_the_process_that_owns_the_window`,
  `a_busy_window_at_its_first_keep_is_answered_before_its_hide`,
  `a_window_let_go_before_the_keepers_hide_stays_shown`,
  `a_window_let_go_during_the_keepers_hide_is_shown_after_it`, and
  `window_calls_leave_the_runtime_workers_free` (hides of a hung thread's windows on a two-worker runtime
  leave it serving). Engine units `a_failed_keep_at_creation_still_hides_the_window_and_answers_the_error`,
  `a_failed_keep_at_a_rehide_still_hides_the_window_and_answers_the_error`,
  `a_failed_resume_marks_its_hidden_window_hidden_and_the_next_show_shows_it` and
  `a_keep_and_a_hide_that_both_fail_answer_the_keeps_error` check the engine's side.
- Extension unit tests: `extension/test/{build-test,connection,events,frames,manifest,ops}.test.mjs`.
- Test kit: `crates/phantab-testkit/tests/server.rs` and its unit tests.
