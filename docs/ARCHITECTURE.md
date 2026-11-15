# phantab architecture

phantab lets AI agents use the owner's own signed-in Chrome profile, in Chrome windows the owner never
sees. When the owner wants, a window is handed over and handed back.

## Goals
- A stable MCP tool surface (names, arguments, results) that any MCP client can use.
- Generic: no product, person or machine names in names, messages or paths.
- One static binary, no Node, no PowerShell at runtime. Window control calls Win32 directly, so no
  script interpreter starts on an open, show or hide.
- Lean results: an agent pays tokens for every byte phantab returns, so results say only what changed.
- Windows and macOS.
- Tested as a black box (lanes below), on both OSes: `scripts/check.sh` on a Windows machine and a
  macOS arm64 machine (`docs/TESTING.md` § 3; there is no CI).

## Pieces

```
agent ──stdio MCP──> phantab mcp ──HTTP /rpc──> phantab serve (the service) <──bridge socket── phantab (native host) <──native messaging── extension (MV3, TypeScript) ──chrome.debugger──> owner's Chrome tabs
                                                   │
                                                   └── isolated-headless: launches its own headless Chrome over a CDP pipe (no port)
```

| Piece | Where |
|---|---|
| MCP server | `crates/phantab/src/mcp.rs` (rmcp) |
| Client runtime: endpoint, ensure service, RPC | `crates/phantab/src/runtime.rs` |
| Service (HTTP, queue, sweeps) | `crates/phantab/src/service/` |
| Bridge server, framing, profile check | `crates/phantab/src/bridge.rs` |
| Engine (pages, ownership, locks, handoff, recover) | `crates/phantab/src/engine/` |
| Sign-in | `crates/phantab/src/signin/` |
| Built-in Bitwarden source, `phantab bitwarden` | `crates/phantab/src/signin/bitwarden/`, `crates/phantab/src/bitwarden.rs`, `docs/BITWARDEN.md` |
| In-page scripts (readFrame, findSignIn, …) | `crates/phantab/src/page_js/*.js`, `include_str!`'d into the binary |
| Native host | `crates/phantab/src/host.rs` |
| CLI | `crates/phantab/src/cli.rs` |
| Installer | `crates/phantab/src/install/` |
| Installed extension file record (SR-74) | `crates/phantab/src/extension_files.rs` |
| Viewer page | `crates/phantab/assets/viewer.html` |
| Window control | `crates/phantab-window` |
| CDP client (a subset of puppeteer-core 25.11.0) | `crates/phantab-cdp` |
| Extension | `extension/src/background.ts` |

## One binary
`phantab` and its subcommands:
- `phantab mcp`: the MCP stdio server.
- `phantab serve`: the service. Clients start it detached when it is not running (`ensure_service`).
- Native host mode. Chrome starts the manifest's `path` with the caller origin as argv[1]
  (`chrome-extension://<id>/`), plus `--parent-window=<n>` on Windows. When argv[1] starts with
  `chrome-extension://`, the binary runs as the host.
- `phantab <method> ['<json>']`: the CLI. It includes `doctor` and `sign-in-clear <host|all>`.
- `phantab install …` / `phantab uninstall …`: the installer (Windows and macOS).
- `phantab bitwarden connect|status|disconnect`: the built-in Bitwarden source (`docs/BITWARDEN.md`).

### Processes and threads
`phantab::mode` picks each process's tokio runtime. Only `serve` answers many clients at once, so only
it is multi-threaded, with `SERVICE_WORKERS` (2) workers. `mcp`, the native host, `bitwarden` and the
CLI each serve one caller and run on a current-thread runtime. A multi-thread runtime would start one
idle worker per CPU in each of them, and an owner runs one MCP server per agent session. Stdio uses
tokio's blocking pool in every mode; file I/O is small and runs inline, except the check before each
agent call of the installed extension's files (SR-74, up to 64 MiB, which a virus scanner can hold up),
which runs on the blocking pool; the one at each bridge connect stays inline. Windows window calls (`hide`,
`show`, `quiet`) run on the blocking pool too: a show or hide waits on the window's own thread, which a
hung Chrome never pumps, so it holds a pool thread (the pool grows) and not one of `serve`'s two
workers. `install` runs without a runtime.

## Names and constants
| Thing | Value |
|---|---|
| Runtime dir | env `PHANTAB_RUNTIME`; else Windows `%LOCALAPPDATA%\phantab`, macOS `~/Library/Application Support/phantab` |
| Native host name | `dev.phantab.bridge` |
| Bridge HTTP upgrade | `Upgrade: phantab-bridge` on `/bridge` |
| Health | `{service:'phantab',version:<crate version>,protocol:1}` |
| Bridge protocol | 1; the welcome names the events the extension should send (`events`) |
| Window token | `PHANTAB-<uuid>` |
| Extension | its own key and ID (`extension/manifest.json`, `extension/extension-id.txt`) |
| Client id env | `PHANTAB_CLIENT` |
| Seal HKDF info | `phantab-sign-in-seal-1`, the wire contract with sign-in providers |
| MCP server key in client configs | default `phantab` (`install --server-name` picks another); tools are then `mcp__phantab__browser_*` |
| MCP tools | 14: `browser_status`, `browser_connect`, `browser_open`, `browser_pages`, `browser_tabs`, `browser_attach`, `browser_snapshot`, `browser_act`, `browser_wait`, `browser_show`, `browser_resume`, `browser_screenshot`, `browser_close`, `browser_sign_in` |
| Provider env allow-list | includes `PHANTAB_RUNTIME` |

### Keeping results small
Every byte a tool returns costs the agent tokens, so the MCP surface is built to say little:
- `browser_snapshot` gives the page as lines, not JSON, and on a repeat only what changed; `full` asks
  for the whole page again.
- `browser_act` takes `then` (more actions, in order) and `snapshot` (the page after them), so a run of
  steps and its check is one call. `browser_open` takes `snapshot` (the new page, read at once).
- Results show page ids by their first 8 characters and leave out page fields unchanged since the last
  result for that page.
- `browser_wait` and `browser_show` take `verification` (README § When a site asks if you're human);
  `browser_connect`, `browser_open`, `browser_tabs` and `browser_attach` take `profile` (README § Another
  Chrome profile, THREAT-MODEL SR-76). Every result may carry `verification`.

## CDP layer (`phantab-cdp`)
This crate is the subset of puppeteer-core that the engine uses, written for exactly one page and any
transport.

- `Transport`: `send(session: Option<SessionId>, method, params) -> Result<Value>`, plus a stream of
  `TransportEvent::{Event{session, method, params}, Closed(reason)}`.
  - **Extension relay**: the root session is `None` (the tab itself, through `chrome.debugger`). Child
    targets (OOPIF iframes) have flat session ids. Their events arrive tagged with a `sessionId`.
    Only the events phantab reads cross the relay: `phantab_cdp::EVENTS`, which the bridge welcome
    hands the extension and the bridge enforces too. A newly matched event goes on that
    list. A test in `cdp_methods.rs` fails until it does when the code reads it in a shape the scan
    knows (a match arm, a `match` or `let` pattern, `==`/`!=` with the literal on either side or
    with `Some` of it on the right, `matches!`, an inline list's `.contains` or a `const`). Filed as a
    command instead, it fails another test, which wants every command name sent from a call. The
    service can read an event only by its exact name: a prefix literal (`"Page."`,
    `format!("Page.{e}")`, `starts_with("Page.frame")`) fails a test, and a name split at its dot is
    not seen.
  - **`Connection`** (isolated-headless, tests): browser-level connection, over Chrome's debugging pipe
    (`Connection::pipe`, JSON plus a NUL byte each way) or a WebSocket (`Connection::connect`). The
    page's root session is the id that `Target.attachToTarget{flatten:true}` returns.
- `Page::attach(transport, root_session, PageOptions{protocol_timeout: 15 s})` does the following:
  - Enables Page, Runtime and lifecycle events. Network and Audits are **never** enabled, on purpose:
    they are 80–95% of a heavy page's traffic.
  - Turns on auto-attach (flatten, wait-for-debugger), tracks the frame tree, OOPIF child sessions and
    the default execution context per frame.
- The engine uses these methods. Each follows the puppeteer call of the same purpose:
  - `url()`, `main_frame()`, `frames()` (every frame, including OOPIFs, with url, parent and detached state).
  - `evaluate(frame, js_function_source, args)`: `Runtime.callFunctionOn` with returnByValue and
    awaitPromise, in the frame's `phantab` isolated world (`Page.createIsolatedWorld`, kept per frame
    and document; THREAT-MODEL SR-34). It waits for the frame's context the way puppeteer does.
    `evaluate_main` runs in the page's own world, for the documented exceptions and the tests.
  - `evaluate_handle(...) -> JsHandle`, `JsHandle::evaluate(js_fn, args)` (the handle is the first
    argument), `JsHandle::dispose`.
  - `frame_element_box(frame) -> Option<BoundingBox>` in page coordinates (puppeteer
    `frameElement().boundingBox()`).
  - `screenshot_jpeg(quality) -> base64`.
  - `set_viewport(Option<(w, h)>)`: `None` clears the override. `emulate_focus(bool)`.
  - `goto(url, timeout)`: waits for DOMContentLoaded, or same-document navigation; errors like puppeteer.
  - `mouse_click(x, y)`, `mouse_wheel(delta_y)`, `mouse_reset()`, `key_down(key)`, `key_up(key)`,
    `key_press(key)`, `type_text(text)`. These use puppeteer's US keyboard layout table (Apache-2.0,
    attributed).
  - Selector helpers with puppeteer semantics, in the main frame: `click_selector`, `fill`
    (`Locator.fill`), `select` (`page.select`), `eval_on_selector`.
  - `closed()` watch and `close()`.
- `CdpError` classifies errors as `is_timeout()` and `is_navigating()` (context destroyed, cannot find
  context, detached frame, inspected target navigated) instead of matching message text. Display
  strings keep puppeteer's wording where the engine shows them: "… timed out", "Navigation timeout of
  30000 ms exceeded".
- `Browser::launch(LaunchOptions{executable, headless, user_data_dir, args})` uses
  `--remote-debugging-pipe`, so no port is open (THREAT-MODEL R13). On Windows Chrome inherits two pipe
  handles named by `--remote-debugging-io-pipes`; on macOS they are fds 3 and 4. A
  `--remote-debugging-port` in `args` selects the old route (DevToolsActivePort, then a WebSocket).
  `Browser::connect(ws_url)` attaches to a Chrome that is already running. It provides `new_page()`,
  `pages()` and `close()`. It serves isolated-headless and the tests.

## Window control (`phantab-window`)
The `WindowControl` trait: `arm_hide(spec) -> Guard` (`guard.settle() -> Option<Handle>`), `find(token)`,
`hide(h)`, `show(h, maximize)`, `snapshot()`, `quiet(&QuietRequest) -> QuietState`,
`quit_browser(&Browser)`. Implementations:
- **Windows**: Win32 through the `windows` crate, with these parts:
  - The `EVENT_OBJECT_SHOW` WinEvent hook runs on its own thread with a message pump, under per-monitor
    DPI awareness.
  - The window is matched by rect at its DPI and by being a chrome.exe process. The token is confirmed
    in the title. A window that is never confirmed is restored with `SW_SHOWNOACTIVATE`.
  - Show is `SW_MAXIMIZE`/`SW_RESTORE` + `SetForegroundWindow`; hide is `SW_HIDE`.
  - `keep_hidden` (SR-61): a keeper thread holds one `EVENT_OBJECT_DESTROY`..`EVENT_OBJECT_SHOW` hook
    per Chrome process that owns a kept window, scoped to that process, and hides a kept window again at
    its show. A process's hook goes when its last kept window is released or destroyed, or when the
    process ends: the keeper holds each hooked process open with `SYNCHRONIZE` (so its id cannot be
    reused while hooked) and waits on it with its messages. A hook that cannot be set fails only the
    calls for that process. A call the keeper does not answer in 5 s fails, with its window still kept;
    a keeper thread that quits with windows still kept is started again. Each new hook hides its
    process's kept windows shown while it had none, after answering its calls, and a window let go
    unwatched is hidden first. A release waits for a keeper hide of that window under way. The thread
    ends when none is kept. The engine hides the window whatever its keep answers; a hand-back that fails
    with its window hidden marks it hidden, and `show` shows such a window again.
  - `quiet` adds or removes `--silent-debugger-extension-api`, and only that, on the HKCU Run values
    and this user's own `.lnk` shortcuts (the user Start menu, Quick Launch with its `User Pinned`
    folders, the user's Desktop) that start the configured Chrome; on, it changes only those on the
    configured user-data dir. All users' shortcuts (the `ProgramData` Start menu, the Public Desktop) and
    those on a `OneDrive` Desktop are read but never written: `sharedShortcuts` and `syncedShortcuts` list
    the ones not in the asked mode. A shortcut it cannot write is reported (`unwritable`), and tried
    again at each bridge connect while quiet is on. It then reads the running browser's command line:
    `running` is whether the browser on that user-data dir has the flag.
  - `quit_browser` is the Restart Manager's shutdown of that one browser process, registered by pid and
    start time: Chrome is asked to end as at a system restart, saves its session and exits itself.
    Nothing is forced. It returns the pid and the arguments the browser was running with. The shutdown
    and the wait for the exit share one deadline (`QUIT_WAIT`).
- **macOS** (`mac.rs`, compiled everywhere, so its logic is tested on any OS): `quiet` writes or
  removes the `dev.phantab.chrome` LaunchAgent (`RunAtLoad`, `open -a <Chrome> --args <flag>`), never a
  plist without that label, and reads the running browser's arguments with `ps`. `quit_browser` is a
  `SIGTERM` to that one pid, then a wait for it to exit (`docs/MAC.md` Q4).
- **Noop**: for headless test lanes.

### Quiet debugging in the engine
- The answer is install's: `quiet-debugging.on` or `quiet-debugging.off` in the runtime dir. Install
  asks at a terminal (default yes) unless `--quiet-debugging on|off` gives it; with neither, nothing
  changes and install says how to turn it on.
- While on, the engine applies `quiet` again at every bridge connect, so a new Chrome shortcut or an
  updated Run entry gets the flag, and keeps the answer for `status` (`quietDebugging`, with a plain
  `note` while the running Chrome lacks the flag).
- `restart_quiet` (CLI `phantab chrome restart-quiet`, at a terminal on a typed y only; no MCP tool
  reaches it) needs quiet on, `chromeExecutable`, and no agent pages. When the browser on the configured
  user-data dir runs without the flag, it calls `quit_browser`, starts that Chrome again with the
  switches it was running with (`--proxy-server` and the like are kept; positional URLs and the sign-in
  entry's `--no-startup-window` are not), `--user-data-dir` when none was named and it is not Chrome's
  default, the flag and `--restore-last-session`, and waits for a new bridge link (not the one from
  before the quit). The quit, the start and the wait fit one budget inside the CLI's 90 s call timeout.

## Test lanes (`docs/TESTING.md`)
1. Unit tests in every crate. They run offline on any OS.
2. CDP lane: `phantab-cdp` against real Chrome over its debugging pipe, on fixture pages served from a local
   HTTP server. The pages include cross-site iframes on 127.0.0.1 vs localhost, so OOPIFs are covered,
   along with shadow DOM and slow pages.
3. Engine lane: the full service against a **CDP-backed fake extension**, which implements the bridge
   ops on a real Chrome over CDP. It covers engine, service, MCP and CLI end to end, with no extension
   and on any OS.
4. Real-extension lane: Chrome for Testing (or branded Chrome, through `Extensions.loadUnpacked`),
   the built TS extension, and a test-only native host name, so the owner's registration is never
   touched.
5. Window lane: real headful windows, hidden and shown (Windows only; Mac window findings are in
   `docs/MAC.md`).
6. Golden-file lane: phantab's wire formats and known-answer vectors (the MCP tool list, the seal)
   compared with golden files checked in beside the tests.

Tests that need Chrome read `PHANTAB_TEST_CHROME` (an executable path). Without it they **skip at
runtime**, printing why. They are not `#[ignore]`d, so `cargo test` stays one command.
