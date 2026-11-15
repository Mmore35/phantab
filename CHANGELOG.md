# Changelog

What changed in each release. Numbers in brackets are pull requests. Releases are on the repository's
Releases page; `CONTRIBUTING.md` says how one is made.

## Unreleased

### Changed
- Install allows every Chrome profile, not only the ones named with `--add-profile`. Each profile gets
  its own copy of the bridge, and agents can use it once you load that copy there at
  chrome://extensions. `--remove-profile` now leaves a profile out (a leave-out list later installs
  keep), `--add-profile` brings it back, and a profile made later joins at the next install.
  `--all-profiles off` returns to only the profiles you name. An install from before this turns it on
  at its next run. Install now prints the load step only for profiles that have not loaded the bridge,
  a reload step for those that have, and the removal step only for a profile left out that had loaded
  it.

### Added
- phantab no longer starts a closed profile where the bridge was never loaded, nor waits for you to
  open one under `guardrails: full`: the call says how to load it. A call naming a profile that is left
  out, or one made since the last install, says so and names the install command that changes it.
- `browser_sign_up`: an agent can make an account for you. It fills in the sign-up form; phantab makes
  the password, saves it in your Bitwarden and reads it back, then types it into the page. The agent never
  sees it and presses the site's own button. While the password is on the page, a copy the page makes is
  blanked and screenshots of the page are refused. Only the built-in Bitwarden source can save one.

### Fixed
- A stray gap of spaces in the "refused in every profile" error.
- A sign-in is no longer walled by a human check no one can see. Invisible reCAPTCHA, hCaptcha and
  Turnstile widgets load zero-size, hidden or offscreen frames on ordinary sign-in pages; a check is now a
  wall only when it is at least 10 by 10 CSS pixels, visible and not pushed further off the page than a
  person could scroll it back. The owner hand-off pops a page up only for such a check too.
- A check the owner has solved no longer walls the sign-in it was solved for: a shown check whose own
  kind of response field is filled, in the document that holds it, is no wall. Another kind's filled
  field does not count.

## 0.5.0 (2026-11-15)
Faster, cheaper agent tasks, and no "started debugging this browser" bar.

### Changed
- A `browser_act` click, fill or select whose selector matches nothing on a loaded page now fails once
  the page has stopped changing for 1.5 s, instead of after the full 10 s: `#x: not found after 1.6 s,
  and the page had stopped changing`. A page that is still loading or changing keeps the 10 s. In an
  agent benchmark, a guessed selector cost the app and shop tasks about 9 s each.
- A `browser_act` select also matches an option by the label a person sees (`March`), not only by its
  value (`3`), and one that matches no option fails and lists the options; before, it succeeded with
  nothing chosen. A snapshot marks a ticked checkbox or radio `checked` and shows a select's chosen
  option as `selected="March"`; typed values are still never read. In an agent benchmark's sign-up
  task, every run took two screenshots to check what the form held.
- A `browser_act` selector that matches nothing in the document but does match an element in an open
  shadow root, which selectors never reach, now fails saying where: `(an open shadow root has it at
  32,192: click_xy reaches it, a selector does not)`.
- A `browser_act` with `snapshot` true now ends a failed step with the page's snapshot too, so an agent
  whose step failed need not read the page in a call of its own.
- `browser_act`, `browser_snapshot`, `browser_screenshot` and `browser_wait` may leave `pageId` out for
  the page the agent's last call named or opened. In an agent benchmark, wall time followed the agent's
  output tokens, and nearly every call named the one page it had open.

### Added
- `browser_act` takes `steps`, each action written as a list: `[["fill", "#qty", "2"], ["click",
  "#add"]]`. With `steps` the page's snapshot comes unless `snapshot` is false. `action` with its fields
  and `then` still work as before. Each field an agent named cost it about 20 output tokens, and a
  five-step act named `action` and `selector` five times.
- Quiet debugging: install at a terminal asks once, **Hide Chrome's debugging bar?** (Enter is yes),
  and keeps the answer; `--quiet-debugging on|off` answers it without asking. On adds Chrome's
  `--silent-debugger-extension-api` to Chrome's Windows sign-in entry and your own Chrome shortcuts, or
  on macOS installs a LaunchAgent that opens Chrome with it at login. Shared and OneDrive shortcuts are
  named, never changed. The trade-off, which the question states: every extension that uses Chrome's
  debugger then attaches silently. Uninstall takes it off again.
- `phantab chrome restart-quiet`, at a terminal on a typed y: closes the Chrome phantab is set up for as
  a system restart does, its tabs saved, and opens it again with its own switches, the quiet flag and
  its tabs. It refuses while agent pages are open; phantab never restarts Chrome on its own.

### Fixed
- A `browser_act` click given `x` and `y` but no selector clicks at that point, as `click_xy` does; it
  failed with `undefined: not found`. A click, fill or select with neither now says it needs a selector.
  A click whose selector matches only an element in an open shadow root clicks it at its point; a fill or
  select there still fails saying where `click_xy` reaches it, now at once rather than after 1.5 s.
- The release workflow's draft job no longer fails after both builds pass: it copied the two halves in one
  `cp`, which refuses to overwrite the shared `extension.zip` it had just copied. v0.4.0's files were
  uploaded by hand from the same workflow run.

## 0.4.0 (2026-11-14)
The first open-source release.

### Changed
- When a site shows the password or code back on the page, sign-in no longer stops. It goes on to its
  outcome with `echoed: true` and a note; phantab redacts every form of the value from everything the
  agent receives for the rest of the service's life, refuses screenshots of that tab until it closes,
  and stops no account for it. This closes finding 4 of the security audit [54].
- phantab is open source under the Apache License 2.0 (`LICENSE`), with a `NOTICE` for the code ported
  from Puppeteer.
- The documentation is rewritten for anyone installing, using or contributing to phantab.
- The installers' default MCP server name is `phantab`, so the tools appear as
  `mcp__phantab__browser_*`. `--server-name` still picks another name.
- The sign-in wire names are phantab's own: the account key is `sha256("phantab-sign-in:" + id)` and
  the seal's HKDF info is `phantab-sign-in-seal-1`. An external sign-in provider must use the new seal
  label, and guard-file limits start fresh for each account.
- The example Chrome profile in the docs and installer help is `Work`.

### Removed
- The installer's `--instance-root` and `--migrate-from` flags and the setup-intent file.
- The parity tests against an earlier implementation; golden files of phantab's own outputs replace
  them (`docs/TESTING.md` § 7).

## 0.3.1 (2026-11-13)
The release with the security audit's fixes (`docs/SECURITY-AUDIT-2026-11.md`).

### Security
- A page can no longer switch off the sensitive-step check with markup that shadows a form's names
  (SR-77) [47].
- Opening a closed profile in your own Chrome takes the spawn guard, like every other process start
  (R13) [48].
- The release workflow names every action by its full commit, and a test refuses one named by tag or
  branch (SR-56) [49].
- Detach messages never name a page-chosen host, and extension names and scan errors are cut to 300
  characters (SR-32) [51].
- A security lane in the merge gate: `scripts/security-tests.txt` names every hostile-input test, and
  `scripts/security-check.sh` fails when one is missing, skipped or failing [50].
- The install guides compare the download with the hash on the release page, not with a file that
  travels with it [50].

### Added
- `scripts/gate-heads.sh` runs the gate for one or more commits as a detached job, with a log and a
  status line per commit, and puts the worktree back on its branch when it ends [45, 46].

### Changed
- `scripts/check.sh` refuses to run under Rosetta on Apple silicon [45].
- Version 0.3.1 [53].

## 0.3.0 (2026-11-13)
Smaller, cheaper tool results.

### Changed
- MCP snapshots are plain lines, not JSON [37].
- A repeat snapshot of a page shows only what changed [38].
- Page ids are shown short, and unchanged page fields only once [39].
- Snapshot links on the page's own origin are written as paths [36].

### Added
- `browser_act` takes `then` and `snapshot`, so a run of steps and the check after them is one
  call [40].
- `browser_open` takes `snapshot`, and a link to the page itself is shown as its `#part` [41].
- Lane 3 measures what six browser-heavy tasks cost an agent [30].
- Version 0.3.0 [44].

## 0.2.0 (2026-11-13)
Hardening, speed, human checks, passkeys, guardrails and more Chrome profiles.

### Added
- Verification hand-off: a page that meets an "are you human" check pops up for you, and hides again
  once it clears; a remote view lets you do the check from another device [15], and the agent can wait
  on a `wake` command until you have [21].
- Passkeys: a sign-in that meets a passkey request hands the page to you, then resumes [34].
- The `guardrails` setting: `parity` (the default), `light` and `full` [24].
- Other Chrome profiles: `install --add-profile` and `--remove-profile`, a copy of the bridge per
  allowed profile, and a `profile` argument on the tools (SR-76) [35].
- Release bundles for Windows x64 and macOS arm64, with install scripts that check every file, built
  as a draft release [33].

### Security
- Sign-in holds unconfirmed pages until they are clean, catches an echoed code, cross-checks frame
  URLs, and `sign-in-clear` runs only from a terminal [7].
- Local hardening of the runtime folder, the service, the installer and the binary [8].
- The Bitwarden session is pinned to its `bw` binary; Keychain writes delete then add; other
  credential hardening [9].
- Page functions run in an isolated world; a click on a covered element is refused; snapshots are
  capped [10].
- The installed extension's files are recorded and checked; a test build cannot be installed;
  `npm ci --ignore-scripts` everywhere [12].
- rmcp 3.9.0, past RUSTSEC-2026-0462 [22].

### Changed
- Clients keep the connection the service proved itself on [13].
- The bridge forwards only the CDP events phantab reads [14].
- Faster failed calls, fills, reconnects and frame snapshots [16].
- Page calls wait only for calls on the same page [17].
- Idle processes run fewer threads; the Windows window keeper hooks only Chrome, and only while a
  window is kept [18].
- A reused window goes to the new page without waiting for its blank page [27].
- A closed hidden page closes its window, so no "Leave site?" prompt reaches your screen [25, 28, 31].
- The service passes `LANG` and the proxy variables on, so `bw` run from it gets them [20].
- Release builds pin overflow checks off [19].

### Tests
- Lane 3 times open, snapshot, act, wait and close per call [23].
- macOS checks run with the screen locked; lane 4 stays in the merge gate [29].
- Window-keeper tests no longer race the keeper thread [32].
- Testing guide: where a Mac checkout should live [26].

## 0.1.0 (2026-11-05)
First release.

### Added
- One native binary, `phantab`: the stdio MCP server, the local service, the Chrome native messaging
  host, a CLI (`doctor`, `sign-in-clear`, `shutdown`) and the installer.
- The bridge extension, Manifest V3, in strict TypeScript.
- A CDP client: the subset of Puppeteer the engine uses, over any transport.
- Window control: hidden agent windows on Windows (Win32, no PowerShell) and on macOS (minimized,
  with focus emulation so pages keep rendering).
- `browser_sign_in` with an external sign-in provider, and a built-in Bitwarden source driving the
  official `bw` CLI [1, 5].
- The threat model and the test kit.
- A release script that remaps local paths and refuses a binary that still names one [6].

### Changed
- macOS: a minimized agent window stays hidden after a popup or a dialog [2].
- A hidden agent page closes without its "Leave site?" prompt [4].
- Checks run by hand through `scripts/check.sh` on Windows and macOS [3].
