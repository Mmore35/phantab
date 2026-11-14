# phantab bridge (Chrome extension)

A Manifest V3 extension that lets the local phantab service drive pages in the owner's own Chrome
profile through `chrome.debugger`, without Chrome's remote-debugging approval prompt. It talks only to
the native messaging host `dev.phantab.bridge` (the `phantab` binary in host mode), which pipes its
messages to the service. Nothing in it is reachable from web pages.

While any agent is attached, the toolbar badge reads `PT` and the title says
"phantab: agents working, click to stop". Clicking it takes every tab from the agents at once, the
same as Cancel on Chrome's debugging bar; a hidden agent window already closing finishes its close
quietly, its sessions kept only for that. This is the owner's sign that agents are working, whether
or not Chrome shows its bar.

How it fits with the rest of phantab: `docs/ARCHITECTURE.md`.

## Extension ID

`idmomgkaieogiaanndlgionahoedmlnd`

It comes from the public key in `manifest.json` (`key`): the sha256 of the decoded key, first 32 hex
digits mapped 0-f to a-p. `extension-id.txt` holds the same ID with no trailing newline, so the Rust
side can `include_str!` it as is (the native host manifest's `allowed_origins`). No private key was
kept: loading unpacked needs only the public key, and the Web Store assigns its own.

## Build and load

```
npm ci --ignore-scripts   # no package's install script runs; none needs one
npm run build    # src/*.ts -> dist/, plus manifest.json
npm run check    # tsc --noEmit
npm test         # build, then node --test on the compiled worker with a fake chrome
npm run build:test -- --host dev.phantab.bridge_test_1234   # dist/ plus dist-test/ (below)
```

`dist-test/` is the same extension (same key and ID) talking to another native host. The
real-extension test lane registers that host for its own Chrome, so the owner's `dev.phantab.bridge`
registration is never touched. `--out <dir>` writes the copy elsewhere.

Load it at `chrome://extensions`: turn on Developer mode, click Load unpacked, and pick
`extension/dist`. Branded Chrome 137+ ignores `--load-extension`; for automated runs use Chrome for
Testing or CDP `Extensions.loadUnpacked` (`CONTRIBUTING.md`, Gotchas).

## Protocol (bridge protocol 1)

Native messaging: JSON messages, each way.

- On connect the extension sends `{hello: {version, protocol: 1, instance, profile?}}`. `instance` is a
  fresh UUID per worker, so the service can tell a reconnect from a second instance in the same profile.
  `profile` is the Chrome profile folder named in the extension's own `profile.json`, which
  `phantab install --add-profile` writes into each extra profile's copy
  (`runtime/extension-profiles/<folder>/extension/`); the usual profile's copy has none, and its hello has no
  `profile`. The worker reads it before its first connect, so no hello goes out without it. The service
  trusts it only after checking that profile lists the bridge from exactly that copy's folder.
- The service answers `{welcome: true, events: [...]}` (the reconnect backoff resets to 1 s; `events`
  names the CDP events it reads; a welcomed link that stayed up 10 s is retried once after 100 ms
  when it drops) or `{refused: message}`
  (logged; the next reconnect waits 20 s). After a disconnect the extension retries with a doubling
  delay capped at 20 s, and a `reconnect` alarm every 30 s is the backstop when the worker was
  stopped with its timer.
- Requests are `{id, op, args}`; replies are `{id, result}` or `{id, error}`. Ops:

  | Op | Args | Result |
  |---|---|---|
  | `ping` | | `{}` |
  | `attach` / `detach` | `tabId` | `{}` |
  | `send` | `tabId`, `sessionId?`, `method`, `params` | the CDP result |
  | `keepRendering` | `tabId` | `{}`: a tiny screencast keeps a hidden window painting |
  | `createWindow` | `url`, `left`, `top`, `width`, `height`, `state?` | `{windowId, tabId}`: an unfocused agent window, recorded as hidden. `state: 'minimized'` (macOS, `docs/MAC.md`) creates it minimized and without the bounds, which Chrome refuses together with minimized |
  | `createTab` | `url` | `{windowId, tabId}`: in an owner window, never an agent window |
  | `tabs` | | `[{tabId, windowId, title, url}]` |
  | `tab` | `tabId` | `{tabId, windowId, title, url}` |
  | `closeTab` | `tabId` | `{}` |
  | `focus` | `tabId` | `{}` |
  | `windowState` | `windowId`, `state`: `'normal'` \| `'maximized'` \| `'minimized'` | `{state}` as read back: agent windows only. `normal` and `maximized` focus the window; `maximized` from minimized restores to normal first and waits for it (up to 2 s) |
  | `markShown` | `windowId`, `shown` | `{}`: records an agent window as shown or hidden |
  | `clearForeignFrames` | `tabId` | `{removed, errors}`: only in hidden agent windows |

  Any other op answers `Unknown bridge operation: <op>`.
- Events:
  - `{event: 'cdp', tabId, sessionId, method, params}`: every CDP event the welcome's `events` names,
    except the screencast frames of a kept-rendering tab, which the extension acks itself. Before a
    welcome, or when `events` is missing or not a non-empty list of strings (an older service), every
    event goes. Only a connection's first welcome sets the list. Console messages and exceptions,
    which phantab never reads, stay in Chrome.
  - `{event: 'detach', tabId, reason, tabOpen, foreign}`: 200 ms after Chrome detaches, so a closing
    tab reads as `tabOpen: false`. `foreign` is `{id, url}` when another extension's frame navigated
    in the tab within 1 s before, else `null`.
  - `{event: 'detach', tabId, reason: 'canceled_by_user'}`: the owner clicked the toolbar button.
  - `{event: 'removed', tabId}`: a tab closed.

When the service link drops, and when a fresh worker starts, the extension detaches every tab and
closes the agent windows that were never shown to the owner. Agent windows are kept in
`chrome.storage.session`, which survives a worker restart but not a browser restart.
