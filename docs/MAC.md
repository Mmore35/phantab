# macOS feasibility trial

Run on 2026-11-03 on an Apple silicon Mac with macOS 15 and its built-in display only, with Google
Chrome 156. Every test used a separate Chrome with its own throwaway `--user-data-dir` (`mktemp -d`).
The Mac's everyday Chrome and profile were not touched. Scripts: `trials/mac/` (how to run them is at the end).

**The screen was locked for the whole trial** (`CGSSessionScreenIsLocked = 1`, loginwindow frontmost).
That is the hardest case for rendering: macOS reports every window as occluded. It is also a real
case, because agents keep working while the owner is away. But nothing on screen could be *seen*.
Where this document says what the owner would see in the Dock, Mission Control or the Window menu,
that comes from macOS's standard behaviour and from the window-server state (`CGWindowListCopyWindowInfo`),
not from looking. `trials/mac/observe.mjs` checks those points in one run on an unlocked screen.

## Recommendation

**Hide by minimizing, and keep `Emulation.setFocusEmulationEnabled(true)` on while hidden.**

- Create the agent window minimized. Through CDP that is `Target.createTarget({newWindow: true,
  windowState: 'minimized'})`: Chrome minimizes it in the same task, before its first frame, so it is
  never seen. **An extension cannot do that** (found by lane 4 and a control on 2026-11-04, Chrome 156):
  `chrome.windows.create({url, state: 'minimized'})` lands normal, on screen, with `focused: false`
  (`ShowInactive` drops the minimized state) and without it (`focused` defaults to true, and the
  activation cancels the asynchronous miniaturize). So the extension creates the window with
  `{url, focused: false}`, which takes no focus from the owner, then calls
  `chrome.windows.update(id, {state: 'minimized'})` and waits until the window reads minimized. **The
  window shows for about a second first** (about 1 to 1.5 s in the control, with the minimize
  animation). Hiding again later is the same `update`.
- **Chrome restores a minimized window when something in it needs the owner**, and the window is then
  on screen until it is minimized again. Seen on the Mac with the window server (lane 4, 2026-11-05,
  Chrome 156.0.8078.80, screen locked):
  - A new tab lands in it (a popup, a link to a new tab): restored for about 1.5 s. The extension
    watches the window for 2 s and minimizes it again.
  - A dialog (alert, confirm, a "Leave site?" on navigation): the extension answers it at once and
    minimizes the window again the same way. It is still on screen for about 1.5 s.
  - A "Leave site?" when the agent closes the page: through `chrome.windows.remove` the window was
    restored and stayed on screen until Chrome had closed it, about 0.5 to 2 s. **Fixed (2026-11-05):**
    the extension closes each tab of a hidden agent window with CDP's `Target.closeTarget` through
    `chrome.debugger`, which closes a page without running its `beforeunload`: no dialog, no restore.
    The page's own `beforeunload` listeners do not run on that close. Chrome takes the command only
    for the tab it is sent to ("Not allowed" for another tab's target), so a tab the extension is not
    attached to, such as a popup, is attached for its close. A tab no debugger may attach to, one
    whose close was refused, or one still open 2 s after its close was sent (a close with no reply in
    2 s counts as sent, since CDP stalls around a minimize) still goes with `chrome.windows.remove`,
    which may ask; its session is kept, and a popup attached for its close has the `Page` domain on,
    so the extension answers that dialog. The tabs close in parallel and each step has a deadline, so
    a stalled CDP holds the close at most about 8 s. Lane 4 checks that the window reads minimized
    all through the close and that no dialog opens. A shown agent window and the owner's own windows
    close as before, and their page may still ask; a window shown while its hidden close runs is left
    open for the owner rather than removed. `cleanup()` (a dropped service link, a worker start)
    closes the hidden windows it finds the same way, and never detaches their tabs before that close
    ends (it detaches any session still left then): detaching first
    left a "Leave site?" that nobody answered, with the window restored and still open 10 s later
    (lane 4, which kills the service to reach it, 2026-11-05), and a close stalled past cleanup's
    2 s wait would have been cut the same way. A trap for such a check: a close during a minimize
    animation, or before a pending restore has started, did not restore the window even on the old
    path, so the check waits for 3 s of minimized reads first.
  - A closed page's window kept for its client's next open (the spare) blanks by
    navigating, which runs the page's `beforeunload`. Lane 4 at a main with the spare read
    `["minimized", "normal"]` through the close, with two "Leave site?" dialogs (2026-11-10, screen
    locked, lid shut). Every phantab call into a page is a user gesture (`userGesture` in
    `Runtime.callFunctionOn`), so any page with a `beforeunload` guard may ask, read or not. So no
    hidden window is kept, on macOS or Windows: the page closes as above. The same holds for an
    agent `navigate` away from such a page in a hidden window: it restores the window for about
    1.5 s, as above.
  - Chrome's browser thread stops answering CDP from about 1 s before each minimize animation until
    the animation ends (about 1.5 to 2 s). A read in that time returns the state after the minimize.
- On a GitHub macOS runner, lane 4's third agent window (after the dialogs page closed) read `normal`
  for 5 s. On the Mac it minimizes every time. The failure message prints the extension's own view to
  find out why.
- Show: `chrome.windows.update(id, {state: 'normal'})`, **wait until the state really is `normal`**,
  then `{state: 'maximized', focused: true}`. CDP refuses to maximize straight from minimized ("To
  maximize a minimized or fullscreen window, restore it to normal state first"). The restore is
  asynchronous, so the second call has to wait for it: poll the window state.
- No OS window code, no permission, no private API. The macOS `WindowControl` can be implemented
  through the extension's `chrome.windows`, with no `phantab-window` OS module, and it needs no
  `PHANTAB-<uuid>` title token to find the window.
- Focus emulation is what keeps the page alive. In this Chrome it holds the page "visible": full-rate
  timers, rAF at 120 Hz, `visibilityState === 'visible'`. That held for every method, including a
  minimized window behind a locked screen. **The screencast keepalive does nothing on macOS**: with it
  alone the page stays `hidden`, rAF stays at 0 and no frames arrive. It can be left off on macOS. It
  is worth checking on Windows too: focus emulation alone may be enough there as well.
- `Page.captureScreenshot` returned a current 1280x900 image in **every** case, hidden or not and with
  or without the keepalives, in 25–60 ms. Screenshots alone need nothing.

What the owner notices with this method (standard macOS behaviour; not observed because the screen was
locked):
- **Dock**: each hidden agent window is a minimized-window thumbnail at the right end of the Dock.
  This Mac has the default Dock setting (`minimize-to-application` unset). With System Settings › Desktop
  & Dock › "Minimize windows into application icon" on, the thumbnails go away, and the windows are
  only listed in Chrome's Dock-icon menu.
- **Chrome's Window menu** lists every open window by page title, minimized ones included. That cannot
  be turned off from outside Chrome.
- **App Exposé** (Chrome's windows only) shows minimized windows in its bottom row. **Mission Control**
  does not show minimized windows, and Cmd-` does not cycle to them.
- A window that was shown and is then hidden again plays the minimize ("genie") animation into the Dock.

No macOS method hides a window of another app completely without a permission or a private API
that macOS refuses (below). Minimizing comes closest, and it is the only one that is clean and needs
nothing.

## Q1: hiding methods

Test: a page with a 100 ms `setInterval` counter, an rAF counter and an `<input>`. Viewport
1280x900 (`Emulation.setDeviceMetricsOverride`, scale 1). Each method was run under four variants:
no keepalive, focus emulation only, screencast only (`Page.startScreencast`, every 60th frame, acked),
and both. The page was red before hiding. While hidden, text was typed into the input
(`Input.insertText`) and the page was turned green. The screenshot had to come back green.
Then the window was shown: overrides cleared, the window restored and maximized. The typed text had to
still be there.

Results (raw JSON in `trials/mac/results/hide-trial.jsonl`):

| Method | (a) Owner sees it | (b) Renders | (c) Show restores + maximizes | (d) Permission |
|---|---|---|---|---|
| CDP `windowState: minimized` after creation | Not on screen (`onscreen: false`). Dock thumbnail, Window menu, App Exposé: standard behaviour | **Yes with focus emulation** (timers 30/3 s, rAF 360/3 s, `visible`). Without it: `hidden`, timers 1 Hz, rAF 0. Screenshot current in all 4 variants | Yes: normal, wait, maximized gives the screen's visible frame (below the menu bar). Input kept | None |
| Created minimized (`Target.createTarget windowState`; the extension's `chrome.windows.create({state:'minimized'})` does not do this, see the recommendation) | Same, and never on screen: the window server has it at alpha 0 while minimized, so there is no flash | Same as above | Same as above | None |
| Off-screen bounds (`left -10000 top 10000`, also `left/top 20000`, at creation or later) | **Yes: clamped.** Chrome/macOS keep 40 px of the window on screen: `-10000,10000` became `-1240,38` and `20000,20000` became `1472,38`. A 40 px strip at the left or right edge, below the menu bar | Same pattern: focus emulation needed | Yes, input kept | None |
| Tiny window (`width 1 height 1`) | **Yes**: clamped to Chrome's minimum size, 500x375 | Same pattern | Yes | None |
| Accessibility (`AXMinimized`, `AXPosition` off-screen) | Not tested: this process is not Accessibility-trusted (`AXIsProcessTrusted() = false`), and the trial does not grant permissions. `AXMinimized` gives the same result as CDP minimize, so it adds nothing. Window managers that move windows off-screen through AX (AeroSpace, for example) report that macOS keeps a sliver visible | (as the matching CDP method) | (as the matching CDP method) | **Accessibility, which the owner must grant** to the phantab binary |
| SkyLight `SLSSetWindowAlpha(main_cid, wid, 0)` on Chrome's window | Returned 0, but the window server still reports alpha 1: no observable effect on another process's window | (unchanged) | n/a | None, but private API |
| SkyLight `SLSOrderWindow(…, out)` | Refused: `1000` (kCGErrorFailure) for another process's window | n/a | n/a | Private API |
| Hide the app (`NSRunningApplication.hide`, Cmd-H) | Not tried: it hides **all** of the owner's Chrome windows, so it cannot hide only the agent's | n/a | n/a | None |
| Another Space / fullscreen window | Not tried. Moving another app's window between Spaces needs private calls that current macOS only allows with SIP off (yabai documents this). A fullscreen window makes its own Space, which shows in Mission Control and can switch the owner's view | n/a | n/a | n/a |

Further findings:
- **Rendering past 5 minutes** (`trials/mac/long-trial.mjs`, two windows created minimized, screen locked):
  without focus emulation the timer ran at 1 Hz for minutes 0–4, then **stopped** (0 ticks in 10 s) from
  minute 5, which is Chrome's intensive throttling. With focus emulation it held 10 Hz (100 per 10 s) for
  all 7 minutes (`trials/mac/results/long-trial.txt`).
- Focus emulation creates no power assertion: `pmset -g assertions` showed none from the trial Chrome,
  so it does not keep the Mac awake.
- A window that is merely behind other windows is occluded too. Without focus emulation, *any* agent
  window behind other windows stops rendering on macOS, not only hidden ones.
- `Target.activateTarget` does not bring Chrome forward. `NSRunningApplication.activate` returned false
  under the lock screen. Whether `chrome.windows.update({focused: true})` activates Chrome for the
  owner on an unlocked screen is the one part of "show" still to confirm (`observe.mjs` records the
  frontmost app before and after).

## Q2: native messaging

`trials/mac/nm/nm-trial.mjs`: branded Chrome 156 on a throwaway profile. The extension was loaded with CDP
`Extensions.loadUnpacked` (`--remote-debugging-pipe --enable-unsafe-extension-debugging`; branded
Chrome ignores `--load-extension`). The host is a plain `sh` script.

- **Chrome launched the host**, and the round trip worked (`{"ok":1}` came back to the extension).
- **argv**, exactly: `argv[0]` = the manifest's `path`, verbatim (spaces work: tested with `/tmp/…/with space/host.sh`);
  `argv[1]` = `chrome-extension://<id>/`. Nothing else: **no `--parent-window` on macOS**. The working
  directory is the host's own directory, with symlinks resolved (`/private/tmp/…`). The parent process is
  the main `Google Chrome` process. stdin is a pipe.
- **Where the user-level manifest is read from: `<user-data-dir>/NativeMessagingHosts/<name>.json`.**
  The directory follows `--user-data-dir`: a Chrome on a custom profile does **not** read
  `~/Library/Application Support/Google/Chrome/NativeMessagingHosts`. A host that exists there
  (another vendor's) answered "Specified native messaging host not found." For the owner's Chrome
  (default user-data dir) that is exactly `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`.
  That directory already exists and holds other vendors' hosts. Consequence for the test lanes: a test
  Chrome on a temp profile needs its test host manifest in `<temp>/NativeMessagingHosts`, so the owner's
  registration is never touched.
- The system-wide directory is `/Library/Google/Chrome/NativeMessagingHosts/`. It is absent here and needs root.
- **Chrome for Testing**: not installed on this Mac, and the trial installs no software, so this was not
  tested. By the rule above it reads `<its user-data-dir>/NativeMessagingHosts`. Its default user-data
  dir is `~/Library/Application Support/Google/Chrome for Testing` (unverified). In tests, pass
  `--user-data-dir` and put the manifest under it; that works whatever the default is.

## Q3: paths

| Thing | macOS |
|---|---|
| Chrome executable | `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`. Find it through LaunchServices (`NSWorkspace.urlForApplication(withBundleIdentifier: "com.google.Chrome")`) rather than hard-coding it: users may install under `~/Applications` |
| User-data dir | `~/Library/Application Support/Google/Chrome` |
| Profiles | `<user-data-dir>/Default`, `<user-data-dir>/Profile N`. Names and the last-used profile: `<user-data-dir>/Local State` (`profile.info_cache`, `profile.last_used`) |
| `extensions.settings[<id>]` | **`<profile>/Secure Preferences`**, not `Preferences` (an unpacked extension had `location: 4` and its `path` there; `Preferences` had no entry) |
| Native host manifest (user) | `<user-data-dir>/NativeMessagingHosts/<name>.json` |
| Running Chrome's command line | `ps -o args= -p <pid>`. Needs no permission (the macOS equivalent of the Windows running-browser check) |

## Q4: quiet debugging (`--silent-debugger-extension-api`)

The switch still exists in Chrome 156 (its name is in the framework binary) and is cross-platform.
The problem on macOS is **getting it onto Chrome's command line**:
- Chrome starts through LaunchServices: Dock, Finder, a link opened from another app, or Chrome's own
  "open at login" Login Item. None of these takes arguments, and there is no per-app arguments
  setting.
- Editing the app bundle (a wrapper `Info.plist`/executable) breaks Chrome's code signature, and
  Chrome's updater replaces the bundle. Not viable.
- What does work: **a LaunchAgent** (`~/Library/LaunchAgents/dev.phantab.chrome.plist`, `RunAtLoad`)
  that runs `/usr/bin/open -a "Google Chrome" --args --silent-debugger-extension-api` at login, with
  Chrome's own "open at login" off. `open --args` reaches Chrome only when Chrome is not yet running.
  If the owner quits Chrome and starts it again from the Dock, the flag is gone until the next login.
  phantab can detect that through `ps -o args=` (above) and say so, as the Windows `quiet` check does.
- So, partially: a login-time flag is possible, but it cannot be made sticky the way the Windows Run-key
  edit is. The trial did not create a LaunchAgent: that would change the owner's machine settings.

**Built (phantab-window `mac.rs`)**, on the owner's install answer or `--quiet-debugging on`:
- `quiet` on writes `~/Library/LaunchAgents/dev.phantab.chrome.plist` (label `dev.phantab.chrome`,
  `RunAtLoad`, `/usr/bin/open -a <the configured Chrome bundle> --args --silent-debugger-extension-api`,
  plus `--user-data-dir=` when it is not Chrome's default), through a `.partial` file renamed into
  place. Off removes it. A file at that path without our label is never changed or removed.
- It does not load the agent into launchd now (that would open Chrome); it takes effect at the next
  login. Install tells the owner to turn Chrome's own "open at login" off.
- `running` comes from `ps -o args=` on the browser process on the configured user-data dir.
- `phantab chrome restart-quiet` quits that one pid with `SIGTERM` (Chrome's normal quit, which saves
  the session), waits for it to exit, and starts Chrome again with the flag and
  `--restore-last-session`.

**Mac-unverified** (unit-tested on any OS, never yet run on a Mac): launchd running the agent at
login, `open --args` reaching a Chrome that is not yet running, `SIGTERM` saving a session that
`--restore-last-session` restores, the `ps` check against a real Chrome, and the install output.

## Q5: toolchain and access

- **Rust** through rustup, at the version in `rust-toolchain.toml`, host `aarch64-apple-darwin`.
  rustup's toolchain is **not on PATH in a non-login shell**: run `. ~/.cargo/env` first. The first
  build has rustup download the pinned `rustfmt` and `clippy` components. The arm64 release needs only
  the `aarch64-apple-darwin` target.
- The workspace builds, tests, lints and formats clean on macOS: `cargo build`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`. `Cargo.lock` is
  committed, so `--locked` works.
- The trial scripts also use the Swift toolchain (Xcode's command line tools) and Node with
  `--experimental-websocket`.
- A Node older than 22 is too old for the extension's `npm test` (tests fail on MockTimers), and
  `scripts/check.sh` refuses it. Install Node 22 or later (with nvm, for example);
  `extension/package.json` asks for it.

## Traps found
- A trial Chrome on its own profile is a second process with the **same bundle id** as the owner's
  Chrome. AppleScript `tell application "Google Chrome"`, `open -a`, and anything else keyed by bundle id
  reaches the owner's Chrome. Target the trial instance by PID.
- When the screen is locked, every window is occluded and loginwindow is frontmost. A rendering test
  that passes then passes the hardest case. An "is it on screen" test needs an unlocked screen; check
  `CGSessionCopyCurrentDictionary()["CGSSessionScreenIsLocked"]` first (`machelper locked`).
- Screenshots are colour-managed (Display P3), so pixels do not match the CSS colour exactly.
  Compare dominant channels, not exact values.
- `osascript … System Events` from a background agent blocks on an Automation permission prompt (it
  timed out after 2 minutes here). Don't use System Events in phantab or its tests.

## Running the trial scripts
Build the helpers with `swiftc -O trials/mac/cgwin.swift -o /tmp/phantab-mac/bin/cgwin` and
`swiftc -O trials/mac/machelper.swift -o /tmp/phantab-mac/bin/machelper`, then from `trials/mac/` run:
- `node --experimental-websocket hide-trial.mjs [method…]`: one JSON line per method x variant.
- `node --experimental-websocket long-trial.mjs [minutes]`: timer rate over time, minimized windows.
- `node nm/nm-trial.mjs`: native messaging round trip and argv (`NM_HOST=<path>` to move the host).
- `node --experimental-websocket observe.mjs`: **unlocked screen only.** Takes desktop and Mission
  Control screenshots into `/tmp/phantab-mac/observe` (Screen Recording needed), and records whether
  creating a window takes focus.

Node 22+ does not need `--experimental-websocket`. `TRIAL_CHROME` selects another Chrome executable.
