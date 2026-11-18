# Contributing to phantab

Thanks for helping. phantab drives a person's signed-in browser, so a change is judged first on
whether it keeps their accounts safe, then on whether it keeps the tool light, cheap to run and fast.
Bug reports, fixes, tests and docs are all welcome. Report a security problem privately, never in an
issue: `SECURITY.md`.

## Standards
- `cargo fmt --all --check` is clean.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean. The workspace turns on
  `clippy::pedantic` and denies `unwrap`/`expect`/`panic` outside tests (`Cargo.toml` § lints).
- `unsafe` is denied workspace-wide. The only exception is `phantab-window`'s OS modules: each `unsafe`
  block there carries a `// SAFETY:` comment saying why it holds.
- `cargo deny check` is clean: licences, advisories, sources. New dependencies need a licence on the
  allow-list in `deny.toml`.
- No secret, token or saved-login value goes into a log, an error, a result or a file the service
  writes. The sign-in rules are the requirements SR-38 to SR-47 in `docs/THREAT-MODEL.md`.
- Every behaviour change comes with a test in the lane that can see it (`docs/TESTING.md`).
- The extension is TypeScript, `strict`. `npm run check` (tsc) and `npm test` are clean.
- Releases are pinned and reproducible: `--locked`, the toolchain from `rust-toolchain.toml`, and the
  extension built from `package-lock.json`.
- Comments say why, not what. Record a trap where the next person would fall into it.

## Building
You need the Rust toolchain named in `rust-toolchain.toml` (rustup installs it) and Node.js 22 or later
for the extension.

- macOS, or Windows with the MSVC toolchain: `cargo build`.
- Windows with the GNU toolchain (`x86_64-pc-windows-gnu`, what the Windows release uses): install
  [WinLibs](https://winlibs.com/), then first `. scripts/dev-env.sh` (Git Bash) or
  `. .\scripts\dev-env.ps1` in every shell. That file says why: `dlltool` comes from WinLibs.
- Extension: `cd extension && npm ci --ignore-scripts && npm run build`. That produces `extension/dist/`,
  the unpacked folder Chrome loads. `--ignore-scripts` runs no package's install script; none needs one.
- To try your build in your own Chrome: `phantab install --extension-dir extension/dist ...` as in
  README § Install from source, then reload the unpacked extension.

## Tests and the gate
`cargo test --workspace` runs lanes 1, 3 and 6, with no Chrome. Set `PHANTAB_TEST_CHROME` to a Chrome
executable to run the real-Chrome lanes; without it they skip and say so. Lanes: `docs/TESTING.md`.

`scripts/check.sh` (Git Bash on Windows, bash on macOS) is the merge gate: every standard above, the
SR-58 unsafe check, the SR-73 release-feature check, cargo-deny and cargo-audit, the tests, the
extension and the security lane. It must end `RESULT: PASSED` (exit 0) on a clean tree; `INCOMPLETE`
(exit 2: a skipped tool or a dirty tree) and `FAILED` (exit 1) are not passes. It installs nothing:
add `cargo install cargo-deny cargo-audit --locked` once.

- **Windows:** `scripts/check.sh`, with no flags. `--chrome --real-extension` adds the real-Chrome
  lanes, the window lane among them; they show and hide real Chrome windows on your desktop, so run
  them only where that is fine.
- **macOS (Apple silicon):** `scripts/check.sh --chrome --real-extension`. It needs Google Chrome in
  `/Applications`, a native arm64 shell (not Rosetta) and Node 22 or later. Lane 4 loads the built
  extension into a throwaway Chrome profile; nothing touches your own profile or your native host
  registration.
- In the background, or for several commits at once: `scripts/gate-heads.sh` with the same flags
  (`docs/TESTING.md` § 3).

There is no CI on pushes or PRs. You run the gate on your platform; a maintainer runs the other
platform's gate at the PR's head before merging.

## What a PR should include
- One change, described: what it fixes or adds, and why.
- A test in the lane that sees the change, or a note on why no lane can.
- The docs it affects, updated in the same PR: `README.md` for anything a user sees, `docs/` for the
  rest, and a `CHANGELOG.md` line under the next version.
- A new security rule takes the next free `SR-` number in `docs/THREAT-MODEL.md` (check the file: the
  numbers are not in order), with the lane that proves it.
- The last lines of your `scripts/check.sh` run (`RESULT: PASSED` and the commit it checked), and
  which platform and flags you ran it with.

## Releases
Maintainers push a `v*` tag, and `.github/workflows/release.yml` builds both halves on GitHub's
Windows and macOS runners (`scripts/release.sh --extension <tag>`, then the platform's bundle script
and its test) and puts them in the tag's draft release (`scripts/release.sh upload <tag>`). A
maintainer publishes the draft. A PR that touches the release scripts runs the same builds as test
builds. The same steps also run by hand: `release.sh --extension <tag>` and the bundle script on a
Windows x64 machine and on an Apple silicon Mac, then `release.sh upload <tag>` on each.

- Windows bundle (one zip a Windows user installs from with no Rust, Node or repo access,
  `docs/INSTALL-WINDOWS.md`): after `scripts/release.sh [--build-only] --extension <tag>` on Windows,
  `scripts/bundle-windows.sh <tag>`. It writes `dist/<tag>/phantab-windows-x64-bundle.zip` (so `upload`
  adds it to the draft) and tests it: an install from the zip alone into a throwaway user folder and
  HKCU key, in Constrained Language Mode, then an uninstall. It leaves this machine's phantab alone.
- macOS bundle (`docs/INSTALL-MAC.md`): the same on a Mac with `scripts/bundle-macos.sh <tag>`,
  writing `phantab-macos-arm64-bundle.zip`; its test installs under a throwaway `HOME`.

## Gotchas
- A snapshot shows a field's value only under `guardrails: parity`, and never a password's (THREAT-MODEL
  R8). A test lane that starts in `full` sees none: to check what a field holds there, read it with
  `ext.eval(tab, "document.getElementById('…').value")`.
- A CDP method the service sends must be in `extension/src/cdp-methods.ts`; the extension refuses
  every other one, and the service reads the same file. An installed extension needs a reload after
  the list changes.
- A new MCP tool argument or description change must also go into the golden tool list in the tests
  (`crates/phantab/tests/`), which pins what `tools/list` answers.
- `env!("CARGO_MANIFEST_DIR")` outside tests puts the checkout's absolute path in a release binary;
  `--remap-path-prefix` does not reach it, and `scripts/release.sh`'s path gate refuses the build. Keep
  it under `#[cfg(test)]` or `#[cfg(debug_assertions)]`.
- That path gate runs only in the release build, not in `scripts/check.sh`, and it refuses any
  `\Users\`, `/Users/` or `/home/` in the binary: a tool description or message gives no example path
  under a home folder.
- GNU Windows builds fail with "error calling dlltool 'dlltool.exe': program not found" until WinLibs'
  `mingw64/bin` is on PATH (`scripts/dev-env.sh`).
- Branded Chrome 137+ ignores `--load-extension`. Use Chrome for Testing, or load the extension through
  CDP `Extensions.loadUnpacked` (needs `--enable-unsafe-extension-debugging`).
  It loads into the last-active profile, and the load lasts only for that Chrome run: to load into a
  second profile, make that profile's window the active one first.
- Code under `#[cfg(windows)]` hides dead-code and unused warnings that only a macOS build reports. Before
  pushing from Windows, check the macOS build too:
  `rustup target add aarch64-apple-darwin` once, then
  `cargo clippy --workspace --all-targets --locked --target aarch64-apple-darwin -- -D warnings` (a check
  needs no Mac linker). Silence a platform-only item with `#[cfg_attr(not(windows), allow(dead_code,
  reason = "…"))]`, not `expect`, because the test build may use it.
- `--all-targets` builds the `phantab` and `phantab-cdp` libs with `test-seams` on (each one's self
  dev-dependency), so an item only test-seams code uses (an import, a helper) passes it and still
  fails the release build as unused.
  Also run `cargo clippy --workspace --locked -- -D warnings` (no `--all-targets`) on both targets.
- Two worktrees sharing one `CARGO_TARGET_DIR` overwrite each other's crates (Cargo names a workspace
  member's artifacts without its path), and a newer build from the other tree can look fresh: errors
  name items your tree has (`cannot find function`). `touch` your changed `.rs` files and build again,
  or give each worktree its own target folder.
- Keep `scripts/windows-bundle/*.ps1` ASCII: Windows PowerShell 5.1 reads a BOM-less script in the
  ANSI code page, so one `§` or curly quote breaks it. Write a JSON file a client reads with
  `Set-Content -Encoding Ascii`; 5.1's `-Encoding UTF8` adds a BOM, which Claude Code's parser refuses.
  `ConvertFrom-Json` in 5.1 refuses a real `.claude.json` (project keys differing only in case).
- In a pty test on macOS, keep the pty's session leader alive until the after-check (a wrapper shell
  that waits). If the leader exits first, macOS revokes the slave fd and `tcgetattr` on it fails with
  `ENOTTY`, so the termios-restored check cannot run.
