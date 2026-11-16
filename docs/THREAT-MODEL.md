# phantab threat model

This document says what phantab protects, from whom, and how each protection is proved. Every
defence is a numbered requirement (§ Requirements), and each requirement names the test lane that
proves it. Lanes are the ones in `docs/ARCHITECTURE.md` § Test lanes:

| Lane | Name | Short form |
|---|---|---|
| 1 | Unit tests, offline, any OS (includes installer tests on temp dirs and the static checks in `scripts/check.sh`) | L1 |
| 2 | CDP lane, real Chrome over its debugging pipe, fixture pages | L2 |
| 3 | Engine lane, full service against the CDP-backed fake extension | L3 |
| 4 | Real-extension lane, Chrome for Testing, the built extension, a test-only host name | L4 |
| 5 | Window lane, real headful windows | L5 |
| 6 | Golden-file lane, phantab's wire formats and known-answer vectors against checked-in golden files | L6 |

"Must" in this document means a release blocker.

## Assets

| # | Asset | Where it lives | Why it matters |
|---|---|---|---|
| A1 | Sessions and cookies | The owner's Chrome profile. phantab never copies them. | Whoever drives a tab acts as the owner on every signed-in site: banking, mail, travel. |
| A2 | Credentials during sign-in | Provider stdout (sealed), service memory, the bridge pipe, the page's input fields. | A leaked password outlives the session. The rule: no agent can read a password. |
| A3 | Page content | CDP results: snapshots, screenshots, evaluate results. | Mail, statements, card numbers shown as text, one-time codes. |
| A4 | Endpoint token | `<runtime>/endpoint.json`, service memory, client memory. | It opens `/rpc` and `/bridge`. Holding it means driving the owner's browser. |
| A5 | Viewer token | Service memory; the fragment of the `/view` URL in the owner's tab. A verification link's token is also in the agent's chat and on the owner's other device. | It drives one paused page through `/viewer`. |
| A6 | Owner attention and consent | The handoff (`show`/`resume`), the badge, Chrome's debugging bar, the sign-in limits. | An agent must not fake the owner's approval, and the owner must be able to see and stop agent work. |
| A7 | The machine | Owner's Windows or macOS account: HKCU Run key, client configs, registry, runtime dir, window state. | phantab writes config, launches processes and moves windows. A bug here reaches beyond the browser. |
| A8 | Sign-in guard state | `<runtime>/sign-in-guard.json`. | It holds the per-account send limits and stopped hosts. Tampering lifts the limits. |
| A9 | Bitwarden CLI session key (built-in source) | Windows: `<runtime>/bitwarden/session.dpapi` (DPAPI). macOS: the login Keychain. Service memory and a `bw` child's environment during a call. | With the CLI's data folder it decrypts the owner's whole vault until `bw lock`. |
| A10 | Bitwarden master password | Only during `phantab bitwarden connect`: the owner's console, phantab's zeroized buffer, one `bw unlock` child's environment. | It opens the vault everywhere, not only on this machine. |

## Trust boundaries

| # | Boundary | What crosses | What each side trusts |
|---|---|---|---|
| B1 | Agent ↔ `phantab mcp` | MCP tool calls over stdio. | The MCP server trusts nothing in arguments. The agent trusts tool results, which carry page text. |
| B2 | `phantab mcp` / CLI / host ↔ service | HTTP `/rpc` and the `/bridge` upgrade on 127.0.0.1, with the bearer token. | The service trusts a request only with the token. Clients trust the port in `endpoint.json`. |
| B3 | Any local process ↔ service port | TCP to 127.0.0.1:<port>. Loopback is shared by every user and process on the machine. | Nothing, without the token. A browser page on the same machine can also reach this port. |
| B4 | Web page ↔ CDP ↔ agent | Page text, DOM, frames, screenshots into agent context; agent actions into the page. | Page content is data. It can never supply owner authorization or handback. This is the prompt-injection boundary. |
| B5 | Extension ↔ native host ↔ service | Native messaging frames (stdio), then the bridge socket. CDP commands, results and events. A new extension sends only the events phantab reads (`phantab_cdp::EVENTS`, named in the welcome) and the service drops the rest, a performance measure only: what does cross is page-controlled (B4). | Chrome allows only `allowed_origins` to start the host. The service trusts the extension after the profile check. |
| B6 | Other extensions ↔ agent tabs | Foreign frames, content scripts, open shadow roots in pages the agent reads. | Nothing. A foreign extension's frame force-detaches the debugger. |
| B7 | Service ↔ sign-in provider | Request on stdin, sealed answer on stdout, public key in argv. | The service trusts only a sealed answer whose digest matches. The provider should trust only a parent that is the endpoint's service. |
| B8 | Installer ↔ client configs, registry, Run key | Writes to `~/.claude.json`, Codex configs, HKCU NativeMessagingHosts, HKCU Run, macOS host manifest dir. | The installer trusts its arguments after validation. Everything it did not write stays untouched. |
| B9 | Update path ↔ installed binary and extension | A new binary, a new extension folder, a protocol number. | A running service trusts its own code. A client trusts a service with its own protocol. |
| B11 | Owner's other device ↔ their private route ↔ remote listener | `GET /view` and `POST /viewer` with a link's token, through the owner's route (for example Tailscale Serve), to a loopback port. | The listener trusts the identity header as the route's own: the route must set it and drop any the device sends (Tailscale Serve does). The token decides the rest. The route is the owner's (SR-70). |
| B10 | Service ↔ Bitwarden CLI (built-in source) | argv and a minimal environment with `BW_SESSION`; vault JSON, a TOTP code or a session key on stdout. | phantab trusts the configured `bw` program as the owner's choice, and nothing it prints beyond the JSON fields it needs. `bw` trusts its environment and data folder. |

## Adversaries

| # | Adversary | Can | Wants | Boundaries |
|---|---|---|---|---|
| X1 | Malicious web page | Run script in its own origin, frame other sites, show text crafted for an agent, try `fetch` to 127.0.0.1, DNS rebinding. | Reach the service, steer the agent, harvest credentials, act on other sites. | B3, B4 |
| X2 | Prompt-injected agent | Call every tool with any argument, as its own session. | Act on another site, read another session's pages, fake owner consent, get a password. | B1, B2, B4 |
| X3 | Another local user or process | Connect to loopback, read world-readable files, race file creation, squat a freed port. As the same user: read memory and owner-only files. | Steal the token, impersonate the service, drive the browser. | B2, B3, B8, B9 |
| X4 | Malicious extension in the profile | Inject frames and content scripts, read open shadow roots, clone the phantab extension ID with the public key, use `chrome.debugger` silently if quiet debugging is on. | Break agent pages, read what the agent reads, pose as the bridge. | B5, B6 |
| X5 | Compromised provider | Answer anything on stdout, hang, spawn children, read its own environment. | Feed a wrong credential, make the service leak, keep running. | B7 |
| X6 | Supply-chain dependency | Ship malicious or vulnerable code in a crate, an npm package or a toolchain. | Run inside the service with access to every asset. | B9 |
| X7 | A second agent session | Hold the same token (every client reads `endpoint.json`), claim any client id. | Take over or read another session's pages, race its site. | B1, B2 |
| X8 | Another device or member on the owner's route, or someone who reads the chat | Reach the route's port, read a posted link. | Drive the owner's page through the link, or reach the service behind it. | B11 |
| X9 | A site's bot check, or a page that fakes one | Show a check, show many, look like a check. | Get the owner's attention again and again; push a page in front of them. | B4 |

## Threats and defences

Columns: the threat, the requirement that answers it (§ Requirements), and the lane that proves it.

### B1 and B4: agent, page and prompt injection

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T1 | Page text tells the agent to open, navigate or attach to `file:`, `chrome:`, `javascript:` or another extension's URL. | SR-30 | L1, L3 |
| T2 | An injected agent drives a page owned by another session. | SR-27 | L3 |
| T3 | Two sessions act on the same site at once and corrupt each other's flow. | SR-28 | L3 |
| T4 | An injected agent learns where other sessions have been. | SR-29 | L3 |
| T5 | An injected agent fakes owner consent to adopt an orphan or resume a shared tab. | SR-31; rest is residual R3 | L3 |
| T6 | A page's text returned to the agent claims to be a tool instruction or owner approval. | SR-32, SR-33 | L1, L3 |
| T7 | A page or injected agent reads typed field values, including a filled password. A page replaces the `value` setter or a DOM method to see what a sign-in writes, or to change what a read returns or where a click lands. | SR-34 | L2, L3 |
| T8 | A huge or deep page stalls the service or floods the agent, or a frame places an element over the embedding page or a banner over a control, so the agent clicks something it did not mean to. | SR-34 | L1, L2, L3 |
| T9 | An action interrupted by a detach is replayed, so a payment or send happens twice. | SR-35 | L3 |
| T10 | A recovery loop against a frame that keeps coming back. | SR-36 | L4 |
| T11 | Page-controlled text inside an error carries injection or very long output. | SR-32 | L3 |
| T92 | An injected agent uses a screenshot or snapshot saved to a file (`path`) to overwrite a file the owner keeps, to write where the service was started rather than where it was told, or to save a picture of a page whose screenshot is refused. | SR-88 | L1, L3 |
| T93 | An injected agent uploads a file the owner keeps (a key, a tax form, a browser profile file) to a site, accepts a dialog that says yes to a deletion or payment, or reloads or moves back or forward onto a page a form sent so the form is sent again. | SR-89; an agent that sets `ownerConfirmed` unasked, and every one of these under `parity`, is residual R3 | L1, L3 |
| T88 | With `guardrails` `light` or `full` (phantab only), a page that wants an injected agent's payment, password change or delete to go through unasked shadows the DOM names the sensitive-set check reads (a form field named `querySelector` or `querySelectorAll`), so the check throws and an unreadable page lets the act through. | SR-77; an agent that sets `ownerConfirmed` unasked is residual R3 | L3 |

### B2 and B3: clients, local processes and the service port

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T12 | A web page posts to `http://127.0.0.1:<port>/rpc` (CSRF), or rebinds a DNS name to 127.0.0.1. | SR-1, SR-2, SR-3 | L3 |
| T13 | A web page or remote host reaches the port. | SR-1 | L3 |
| T14 | A local process guesses the token or learns it by timing. | SR-4, SR-5 | L1, L3 |
| T15 | Another user reads `endpoint.json`. | SR-10, SR-11 | L1 |
| T16 | A local process squats the port after the service dies, then receives the token from a client that trusts a stale `endpoint.json`. | SR-13 | L3 |
| T17 | Two services start at once, or a reused PID blocks a start. | SR-12 | L3 |
| T18 | The first client's environment reaches the service (`NODE_OPTIONS`, `DEBUG`, `RUST_LOG`, injected loaders). | SR-14 | L3 |
| T19 | The service is started from a path an attacker controls. | SR-14, SR-48 | L1, L3 |
| T20 | Oversized request bodies exhaust memory. | SR-6 | L3 |
| T21 | Responses cached, sniffed or framed. | SR-7 | L3 |
| T22 | The viewer page is swapped on disk between requests. | SR-7 (embedded asset) | L1 |
| T23 | A viewer-token holder floods actions on the isolated page. | SR-8 | L3 |
| T24 | A second session claims another session's client id (X7). | SR-26; rest is residual R4 | L3 |
| T25 | Stopping the service mid-takeover strands the owner. | SR-37 | L3 |

### B5: extension, native host and bridge

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T26 | A web page talks to the extension. | SR-18 | L1, L4 |
| T27 | Another extension or program starts the native host. | SR-15 | L1, L4 |
| T28 | A web page opens the bridge as a WebSocket. | SR-16 | L3 |
| T29 | A peer sends a frame with a huge length prefix. | SR-17 | L1 |
| T30 | An unpacked extension carrying the public `key` gets the same ID and poses as the bridge. | SR-19 | L1, L4 |
| T31 | The service, or anyone holding the bridge, sends any CDP command, such as `Network.getAllCookies` or `Storage.getCookies`. | SR-20 | L1, L4 |
| T32 | A second profile's bridge connects and agents reach the wrong profile. | SR-21, SR-76 | L3, L4 |
| T33 | A slow or silent peer holds the bridge. | SR-17 | L3 |
| T34 | The owner cannot see or stop agent work. | SR-22 | L4 |
| T35 | A dropped service leaves attached tabs or hidden windows. | SR-22 | L4 |
| T36 | An unknown bridge op runs. | SR-20 | L4 |
| T86 | A same-user program swaps a file in the installed unpacked extension (`background.js`) and keeps its `key`, so the ID, the path and the native host's origin check all still pass. | SR-74; the rest is residual R1 | L1 |
| T87 | With other profiles allowed (phantab only; by default every profile but those left out), a copy of the bridge in one profile speaks for another: a hello that names a profile it is not in, a copy loaded where the owner allowed none or left the profile out, or a reply on one profile's link to another's call, so agents act in a profile the owner did not allow; or phantab starts a profile where the owner never loaded the bridge. | SR-76 | L1, L3, L4 |

### B6: other extensions (foreign-frame defence)

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T37 | A password manager's frame force-detaches the agent's tab. | SR-23 | L4 |
| T38 | The clear removes frames in a window the owner can see. | SR-23 | L4 |
| T39 | Page script tampers with the clear script, or markup steers or ends its scan. | SR-23 | L1, L4 |
| T40 | An agent reads another extension's frame. | SR-34 | L2, L4 |
| T41 | A foreign extension draws into an open shadow root, and the agent reads it as page content. | Residual R7 | — |
| T42 | Quiet debugging lets every debugger extension attach silently. | SR-49 | L1 |

### B7: sign-in provider and credentials

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T43 | A credential reaches a tool result, log, error, file or screenshot. | SR-38, SR-39, SR-40 | L1, L3, L4 |
| T44 | Debug logging prints CDP bodies, which carry the filled values. | SR-41, SR-42 | L3 |
| T45 | A credential stays in memory after use. | SR-38 | L1 |
| T46 | A provider's answer is replayed or rewritten. | SR-43 | L1, L6 |
| T47 | The provider inherits secrets from the service's environment, or hangs, or floods. | SR-44 | L3 |
| T48 | Any process asks the provider for a credential. | SR-11 (keep `pid`), SR-44 | L3 |
| T49 | A *saved* credential is sent over HTTP, through a GET form, or into a pay or sign-up form. | SR-45; `browser_sign_in` still refuses sign-up forms, and a sign-up's new password comes only from `browser_sign_up` (T90) | L3, L4 |
| T50 | The page moves between lookup and fill, and the value lands on another site. | SR-45 | L3 |
| T51 | Repeated sends lock the account or brute-force it. | SR-46 | L3 |
| T52 | The site echoes the value into the URL or page text. | SR-45 | L3 |
| T53 | Values cross native messaging and loopback in plain JSON. | SR-47; rest is residual R5 | L3 |
| T90 | A sign-up's new password is exposed while it waits on the page: the agent invents it, it is filled before the vault holds it, it fills another site or a reused login, the page copies it into another field, its address or its text, a show-password toggle reveals it, a screenshot shows it, or a result, log or record holds it. | SR-78 to SR-83; SR-47 and residual R5 for the way to the page | L1, L3 |
| T91 | With several providers (`docs/VAULTS.md`), a second vault overrules an owner's no in the first, a held account key goes to a vault that did not issue it, a swapped provider program is sent a sign-up's password, a sign-up password is written to two vaults, or a provider's answer carries fields the protocol does not name. | SR-84 to SR-87 | L1, L3 |

### B8: installer, client configs and registry

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T54 | A concurrent edit to a client config is lost, or unrelated config changes. | SR-50 | L1 |
| T55 | A rewritten config loses its permissions (an owner-only `~/.claude.json` becomes world-readable). | SR-50 | L1 |
| T56 | Stale extension files stay loaded after an update. | SR-51 | L1 |
| T57 | Paths or provider commands inject into a generated script or config. | SR-52 | L1 |
| T58 | The quiet edit touches Run values, shortcuts or a LaunchAgent that are not Chrome's or phantab's, or changes more than the flag. | SR-49 | L1 |
| T59 | A same-user process repoints the native host registration or the service binary. | SR-48, SR-53; rest is residual R1 | L1, L3 |

### B9: update path and supply chain

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T60 | An old service runs new tool text, or a new client talks to an old service. | SR-54 | L3 |
| T61 | Replacing a running binary corrupts it, or a half-written binary runs. | SR-54 | L1 |
| T62 | A vulnerable or malicious crate ships. | SR-55, SR-56 | L1 (`scripts/check.sh`, `scripts/release.sh`) |
| T63 | The shipped extension carries third-party runtime code. | SR-57 | L1 |
| T84 | A `cargo test` build of phantab, with the `test-seams` overrides compiled in, is installed or released as the real one. | SR-73 | L1 (`tests/install.rs`, `scripts/check.sh`, `scripts/release.sh`) |
| T85 | An npm package runs an install script on a build machine, or a compromised dev package (the TypeScript compiler, which writes the shipped JS) is never audited. | SR-56 | L1 (`scripts/check.sh`, `scripts/release.sh`) |
| T89 | An action the release workflow runs is changed under its tag (`@v4` moved to other code), and the changed code builds or uploads the release. | SR-56 | L1 (`tests/install.rs`) |

### Window control (part of A7)

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T64 | The hide hook hides or shows an unrelated window. | SR-24 | L5 |
| T65 | Show or hide acts on a window that moved. | SR-24 | L5 |
| T66 | Memory-unsafe Win32 code corrupts the service. | SR-58 | L1 (`scripts/check.sh`) |
| T67 | A page in a hidden agent window opens a dialog: Chrome draws "Leave site?" on the owner's screen with no window behind it, and the close or navigation that raised it waits for an answer. The owner may answer a dialog they cannot place. | SR-60 | L1, L4 |
| T68 | A page in a hidden agent window opens a popup (`window.open` with features, as sign-in and payment pages do) or plays sound. The popup is a new top-level window nothing hides, so it appears on the owner's screen (and with popups as tabs, Chrome shows the hidden window the tab lands in); the sound comes from no window they can see. | SR-61 | L1, L4 |

### B10: built-in Bitwarden source

`docs/BITWARDEN.md`. An external provider (B7) is the other way to sign in; this source is built in.

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T69 | The stored session key is read by another account, or copied off the machine and used there. | SR-62; same-user reads are residual R16 | L1, L3 |
| T70 | The master password is captured: echoed, in argv or shell history, in a log, or kept on disk. | SR-63; the child's environment is residual R18 | L3 |
| T71 | A planted `bw` runs: a `PATH` lookup, a batch file through `cmd.exe`, a shell. | SR-64 | L1 |
| T72 | The service's environment reaches `bw`, or `bw` floods, hangs, prompts or leaves children behind. | SR-65 | L3 |
| T73 | A login for a sensitive site is filled without the owner's go-ahead. | SR-66 | L1, L3 |
| T74 | A login fills another site's form: one saved for `http`, a pattern, a host on a shared suffix (`a.github.io` for `b.github.io`), an IP or `localhost` service, or a lookalike name; or the wrong one of several logins is picked. A subdomain of the saved site is the same site, as in Bitwarden (a deliberate choice, R6). | SR-67 | L1, L3 |
| T75 | Every candidate's password from `bw list items` stays in service memory. | SR-65; the rest is residual R17 | L1 |
| T76 | `bw`'s text (an error, a prompt, an email) reaches the agent or a log. | SR-40, SR-65 | L3 |

### B11: verification hand-off and the remote view

`docs/REMOTE.md` and README § Human checks.

| # | Threat | Requirement | Lane |
|---|---|---|---|
| T77 | Phantab gets past a check itself: clicks, focuses or scripts the challenge frame, uses a solving service, or hides the browser's identity. | SR-68 | L1, L3 |
| T78 | A site or page shows check after check to keep the owner's attention, or a fake check pushes a page in front of them. | SR-68 limits; the pop-up shows the owner's own Chrome page, never a page's content of its choosing | L1 |
| T79 | A check's end hands back a page the owner was using. | SR-69 | L3 |
| T80 | The remote listener is reached by someone else on the route, another device, a web page (DNS rebinding) or a local process; or it opens `/rpc` or `/bridge`. | SR-70 | L1, L3 |
| T81 | A link's token leaks (chat history, a proxy log, a referrer) and drives the page. | SR-71, SR-8; the chat is residual R19 | L3 |
| T82 | A link holder floods the page with input. | SR-8 | L1, L3 |
| T83 | A wake token leaks (the agent's chat, the process table) and is used to read or drive the page. | SR-72: it reads only the check's state and page id, through the endpoint token's `/rpc` | L1 |

## Rust-specific requirements

Each maps to a numbered requirement.

- **Tracing must not leak.** `RUST_LOG=trace` must not print a CDP body, a header value or a frame.
  Third-party crates (hyper, h2, tungstenite, rmcp) can log raw bytes or headers at trace. phantab
  logs CDP method, id, session, size and timing only, and caps third-party targets; sign-in is refused
  while trace logging could print a body. SR-41, SR-42.
- **zeroize.** Credentials, the ephemeral X25519 secret, the derived AES key, and bridge buffers that
  carried a credential are zeroized when dropped. SR-38, SR-43, SR-47.
- **Constant-time compare.** Endpoint and viewer tokens are compared with `subtle::ConstantTimeEq`.
  SR-4, SR-8.
- **panic=abort.** The release profile aborts (`Cargo.toml` `[profile.release]`). A panic never leaves a
  half-updated record running. Abort skips destructors, so zeroize-on-drop does not run on a panic;
  the process memory goes away with it, and core dumps are off. The panic hook prints the location,
  not the payload. SR-59.
- **cargo-deny and cargo-audit.** Advisories, licences, bans and sources are checked by
  `scripts/check.sh`, run by hand before each merge and each release; `scripts/release.sh` refuses to
  build while either fails. Nothing checks them on a schedule any more. SR-55, SR-56.
- **unsafe.** Only in `phantab-window`'s OS modules, each block with `// SAFETY:`. SR-58.
- **Runtime dir permissions.** Windows: a protected DACL for the owner SID and SYSTEM only, and a
  Medium no-read/write/execute-up label. macOS: `0700`, owned by the user. Set and checked at every
  service start. SR-10.
- **Binary replacement on update.** Write beside, verify, rename the running exe aside (Windows), rename
  the new one in, restart only at zero agent pages. SR-54.

## Requirements

Each requirement is a release blocker, and each is tested in the lanes named.

### Service port and HTTP
- **SR-1** The service binds only `127.0.0.1` on an OS-chosen port (port 0). Never `0.0.0.0`, `::`,
  `localhost` or a fixed port. *L3: assert the bound address; connect on `[::1]` fails.*
- **SR-2** Every HTTP request, `/health` included, whose `Host` header is not exactly
  `127.0.0.1:<port>` gets 403 before any other handling. A missing Host, `localhost:<port>`,
  `127.0.0.1` without the port, and a rebinding name all get 403. *L3.*
- **SR-3** A request with an `Origin` header other than exactly `http://127.0.0.1:<port>` gets 403.
  The `/bridge` upgrade is refused when any `Origin` is present. *L3.*
- **SR-4** `/rpc` and `/bridge` require `Authorization: Bearer <token>`. The compare is constant time
  over the bytes (`subtle`), and a wrong length, a prefix, a trailing space and a wrong case all give
  the same 403 body. *L1: compare function; L3: each variant.*
- **SR-5** The endpoint token is 32 bytes from the OS CSPRNG, hex-encoded, new at each service start.
  It never appears in a log, an error, an MCP result, CLI output (`doctor` says only that it is
  present), a tracing span or a panic message. *L3: token sentinel scan of every output at
  `RUST_LOG=trace`.*
- **SR-6** Request bodies are capped at 65536 bytes while reading; the 65537th byte ends the request
  with 400 and no further buffering. `method` must be in the fixed allow-list; `client` must be a
  string of 1 to 150 characters. *L3.*
- **SR-7** Every response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer`. `/view` serves the viewer page embedded in the binary
  (`include_str!`), never read from disk, with this CSP: `default-src 'none'; script-src
  'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-ancestors
  'none'`. *L1: asset embedded; L3: headers.*
- **SR-8** The viewer token is 24 CSPRNG bytes, sent only in the URL fragment, compared in constant
  time, accepted only on `/viewer`, and never returned through MCP, CLI or `status`. A key that views
  no hand-off is refused before its body is read, as `/rpc` checks its bearer first. Viewer actions
  are limited to 20 a second per page, and pointer moves apart from them to 30 a second; more get 429.
  A local hand-off's token works only on the local listener, a verification link's (SR-71) only on the
  remote one. *L3.*
  phantab status: the 429 is tested at L1 against the engine's limit message; an L3 burst needs the viewer token, which by this rule no interface returns, so it waits on an engine test seam.
- **SR-9** `/health` returns only `{service, version, protocol}`. No pid, path or token. *L3.*

### Runtime dir, endpoint file and service start
- **SR-10** The runtime dir is owner-only, set and checked by the service at every start, including
  under `PHANTAB_RUNTIME`. Windows: protected DACL (inheritance off) with full control for the current
  user SID and `S-1-5-18` only, and the mandatory label `S:(ML;OICI;NRNWNX;;;ME)`, so a process of the
  same user below Medium (a sandboxed renderer, a Low-integrity tool) cannot read, write or traverse
  it, which the user's own DACL entry would allow. The label is best effort: an owner-only dir without
  one (made before it) is labeled at the next start, and one the OS refuses leaves the dir as before.
  macOS: mode `0700`, owned by the current uid. A dir phantab creates gets this in the create call
  (R15). A dir owned by someone else, or a symlink, junction or other reparse point, makes the service
  refuse to start with a named error. *L1, on Windows and macOS (`scripts/check.sh` on each): an open
  dir is fixed; a new dir reads back with exactly these entries and nothing inherited; a foreign-owned
  dir and a junction are refused; an owner-only dir without the label gets it, reaching the files
  inside; a Low process cannot read inside a locked dir.*
- **SR-11** `endpoint.json` holds `{port, token, pid, protocol, source}` (keep `pid`: providers check
  their parent against it). It is written to a temp file created owner-only (macOS `O_CREAT|O_EXCL`,
  mode `0600`, `O_NOFOLLOW`; Windows inside the protected dir), then renamed. It is removed on a clean
  stop, before the lock is released and only when it still names this service's token and pid. *L1:
  mode or DACL of the written file, and a file naming another service is kept; L3: removed after
  `shutdown`.*
- **SR-12** One service per runtime, by an OS file lock (`LockFileEx` / `flock`) on
  `<runtime>/service.lock` held for the service's life. No PID file decides it. A second `serve` exits
  with "already running". After a kill, the next start succeeds. The lock file is opened as itself:
  a symlink (macOS `O_NOFOLLOW`), junction or other reparse point (Windows), hard link (macOS) or
  anything but a plain file at its name is refused, so taking the lock never truncates a file elsewhere. The file is never removed, not even on
  a clean stop: removed after the unlock, it could be the one a service starting that moment had just
  locked, and the next start would lock a new file beside it. *L3: two concurrent starts give one
  listener; start after `kill -9` works; the file stays after `shutdown` and the next start works. L1:
  a link at the lock file's name is refused and its target keeps its bytes.*
- **SR-13** A client proves the service before it sends the token. It sends a random nonce to an
  unauthenticated hello and checks, in constant time, the answer `HMAC-SHA256(token, "phantab-hello"
  || nonce)`. On failure it treats the endpoint as stale and starts a fresh service. The CLI, MCP
  server and native host all do this. The proof holds for the one connection that answered it: the
  token, every `/rpc` call and the host's `/bridge` join go on that connection and no other. A client
  keeps the connection for later calls, up to 60 s idle, only when the hello's answer says the service
  holds it (`keep`), and sends them on it without a new hello; a closed connection is proven again
  from the endpoint file. *L3: a fake listener on the endpoint's port never receives an
  `Authorization` header. L1 (`runtime.rs` tests) and L3 (`cli_host.rs`): one that proves the token
  and then closes never receives it, on `/rpc` or the host's `/bridge`, on any connection.*
- **SR-14** `ensure_service` starts `phantab serve` from the installed binary path (SR-48), never from
  a path in a writable config, with the environment cleared and rebuilt from an allow-list:
  `SystemRoot`, `windir`, `PATH`, `PATHEXT`, `TEMP`, `TMP`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`,
  `LOCALAPPDATA`, `APPDATA`, `ProgramData`, `ComSpec`, `HOME`, `TMPDIR`, `LANG`, `http_proxy`,
  `https_proxy`, `no_proxy`, `all_proxy` (any case; the service passes these on to `bw`, SR-65, and
  takes the proxy names out of every Chrome it starts, which on Windows and macOS takes its proxy from
  the system settings anyway), `PHANTAB_RUNTIME`, and in test builds
  `PHANTAB_TEST_*`. `RUST_LOG` is not passed. Unless the Bitwarden config sets `proxy`, which replaces
  them for every `bw`, whoever set the environment of the client that starts the service chooses the
  proxy every sign-in's `bw` uses until the service stops. That proxy sees the server's name and when
  `bw` syncs. It can stall a sync, and the sign-in is `busy`, or refuse it, and the local copy
  answers, not refreshed, until the service restarts. `bw`'s TLS checks still hold (SR-65), so over an
  `https` server it reads no vault data (phantab's `server` setting must be `https`, but a reused CLI
  login keeps the server it had). That is someone who can already run programs as the owner. It runs
  in the runtime dir, not the client's folder (a `PHANTAB_RUNTIME` given relative is passed in full),
  and the macOS process list comes from `/bin/ps` in the C locale, not a `ps` on the inherited `PATH`.
  *L3: the names in a started service's environment, read from the running process; a client started
  with `RUST_LOG=trace` and `FOO=1` leaves neither in it, while its `LANG` and `HTTPS_PROXY` (and on
  macOS and Linux `https_proxy`) reach it; a started service's working folder is the runtime dir. L1:
  every name `bw` is given passes into the service, no loader or certificate variable does, a
  configured `proxy` is the only proxy `bw` gets, and Chrome's launch removes each proxy name in any
  case, through the one function that builds every process the browser module starts.*

### Native host and bridge
- **SR-15** In native-host mode, argv[1] must equal exactly `chrome-extension://<phantab id>/` (the
  test build also accepts the test ID). Otherwise the host writes one `refused` frame and exits,
  before it reads `endpoint.json` or starts the service. *L1: argument check; L4: the real extension
  connects.*
- **SR-16** The bridge upgrade needs `Upgrade: phantab-bridge`, path `/bridge`, exact Host, no
  `Origin`, a valid bearer token (SR-4), and a service that is not stopping. Any miss gets
  `403` and a closed socket. *L3: each miss.*
- **SR-17** Every framed reader (host stdin, host socket, service socket) checks the 4-byte length
  before allocating. Inbound frames over 64 MiB close the link. Outbound frames to Chrome stay under
  1 MiB. The hello must arrive within 5 s. *L1: a header claiming 64 MiB + 1 closes without
  allocation; L3: silent peer dropped at 5 s.*
- **SR-18** The extension manifest has no `content_scripts`, no `externally_connectable`, no
  `web_accessible_resources`, and the worker registers no `onMessageExternal` or `onConnectExternal`
  listener. The only channel is `connectNative`. *L1: manifest and source check in `npm test`; L4.*
- **SR-19** The profile check accepts the bridge only when the configured profile lists the phantab
  ID, no other profile does, and that entry is an unpacked install whose `path`, canonicalised, equals
  the installed extension folder. A same-ID extension at another path is refused with a final error.
  Every check reads each Preferences file again; a parse is reused only for bytes whose SHA-256
  matches, never on modification time, size or file identity, which a writer can set back.
  *L1: fixture Preferences with a matching ID at another path; a same-size rewrite with its
  modification time restored is refused (`tests/bridge.rs`); L4.*
  phantab status: L1 done; the L4 lane is the same opt-in real-extension lane and was not run.
- **SR-76** Agents reach a Chrome profile other than the usual one only when the owner allowed it, and
  then only in that profile. Allowed means two things: the installer listed it, and the owner loaded
  its copy of the bridge there by hand (Chrome requires that for every unpacked extension, so it is the
  owner's consent step per profile). `config.json`'s `otherProfiles` lists the profile folders the
  installer allows, and it is the only list the service reads, once, at its start; the service never
  widens it. Only `phantab install` writes it. By default (`--all-profiles on`, `allProfiles` absent)
  it is every profile folder directly in `userDataDir` with a `Preferences` file and a plain profile
  folder name (`Default` or `Profile <n>`, so never a Guest or System profile), but the usual one and
  those in `excludeProfiles`, the owner's leave-out list; `--remove-profile` adds to that list and
  `--add-profile` takes off it. A profile made after an install joins at the next one. With
  `--all-profiles off` (`allProfiles: false`) the list changes only by `--add-profile` and
  `--remove-profile`. Each flag resolves Chrome's name or a folder to a real profile folder, and the
  usual profile is refused. The service ignores an entry that is not a plain profile folder name or is
  the usual profile. A closed allowed profile whose Preferences do not list the bridge is never
  started, and under `full` the owner is not sent to open it: the call fails saying how to load the
  copy. A call naming a real profile that is not allowed says whether it is left out or not yet picked
  up by an install, and which install command changes that; it gets no access either way. Each
  allowed profile gets its own copy of the bridge at `<runtime>/extension-profiles/<folder>/extension`:
  the installed files plus a `profile.json` naming the folder. Each copy is recorded and checked as the
  usual one is (SR-74), with its own `extension-files.json` beside it. A source holding a `profile.json`
  is refused as the usual bridge. The copy's hello names its folder; a hello naming a folder that is not
  allowed is refused. The profile check (SR-19) covers every allowed profile at once. The usual profile
  must list the ID from `<runtime>/extension`, each other allowed profile from its own copy, and no
  other profile may list it. A copy in the wrong profile is a final error whichever profile was asked
  for. Each profile has its own link. An op goes only over the link of the profile it names, and a
  reply or event from another link is ignored. Pages, tab lists, site leases, checks and `status` are
  per profile, and a page stays in its profile for life. A call names a profile by its folder or by
  Chrome's name for it when that name is unique; absent is the usual profile. A closed allowed profile
  is started in the owner's own Chrome with `--profile-directory=<folder> --no-startup-window`, plus
  `--user-data-dir` only when it is not Chrome's default and the quiet flag when quiet debugging is on.
  It is started with no shell and never with a debugging port, so no cookie is copied and no profile
  lock is bypassed. Under `guardrails: full` phantab never starts a profile; it waits 10 s for the owner
  to open one. Taking a profile out of `otherProfiles` (leaving it out, or switching the profile
  `--profile` binds) while its copy is still loaded refuses the bridge in every profile until the owner
  removes that copy, and install names each such profile. *L1: `tests/bridge.rs` (links, forged
  replies, unknown labels, every profile's copy and path), `tests/install.rs` (a recorded copy per
  profile, removal, every profile by default, the leave-out list, a new profile joining, `off`, the
  owner steps only where they apply), `runtime.rs` (what the service ignores); L3: engine tests (links,
  pages, tabs, leases, a hidden start, `full`, no start where the bridge was never loaded, the
  not-allowed answers); L4: the two-profile phase of `engine_real_extension`
  (opt-in, run on a macOS machine).*
- **SR-20** The extension's `send` op and the service both enforce one CDP method allow-list. It is
  one checked-in list of exact method names, the ones `phantab-cdp` sends, from the `Page`, `Runtime`,
  `DOM`, `Input`, `Emulation` and `Target` (attach, auto-attach, detach) domains. It never holds
  `Network.*`, `Storage.*`, `Fetch.*`, `Browser.*`, `Security.*`, `Target.createBrowserContext` or
  `Page.setDownloadBehavior`. An unknown op or method returns an error. `Page.createIsolatedWorld`
  is listed for phantab's own world (SR-34), `DOM.describeNode` for fill's write and the covered
  click, and `DOM.getNodeForLocation` for the covered click (SR-34): it returns only the node id and
  frame id of what is on top at a point in the tab's own document, a read-only hit test of what
  `Runtime.callFunctionOn` can already read; it reaches no other process's frame and changes nothing.
  `DOM.getBoxModel` is listed for the covered click too (SR-34, a frame's offset): it returns only the
  box quads and size of a node in the tab's own documents (the list is by method, so any node can be
  asked; phantab asks it of frame elements only), geometry `Runtime.callFunctionOn` can already read,
  and like `DOM.describeNode` it changes nothing. `DOM.setFileInputFiles`, `Page.getNavigationHistory`,
  `Page.navigateToHistoryEntry` and `Page.reload` are listed for the `upload`, `back`, `forward` and
  `reload` steps (SR-89): each acts only on the tab's own page, and `DOM.setFileInputFiles` sends only
  paths the service checked first. A `send` whose
  params carry a `grantUniveralAccess` (Chrome's spelling) that is not `false` is refused, since such
  a world reads other origins with the owner's cookies. An extension older than the service refuses a newly listed
  method, and the service's error then says to reload it. *L1: every method `phantab-cdp` sends is
  on the list, and the list has none of the banned ones; `grantUniveralAccess` refused by the
  service and the fake worker; L4: `Network.getAllCookies` and `Storage.getCookies` refused by the
  extension.*
  phantab status: L1 done in Rust and `npm test` (the fake worker refuses both); the L4 real-extension lane is opt-in (`PHANTAB_TEST_REAL_EXTENSION=1`, it shows a window) and was not run.
  Note, not part of SR-20 (perf-data-3): the event filter is a performance measure, and none of
  SR-20's guarantees rely on it. The welcome names the CDP events the service reads
  (`phantab_cdp::EVENTS`); a new extension forwards only those once it has the list, and the bridge
  drops any other event after parsing its frame (the params are scanned, not copied or broadcast). It
  reduces what crosses; it is not a boundary. Page content still reaches the service in the kept
  events (a dialog's message, frame URLs and names, `frameAttached` stacks, a context's origin and
  name), and every event crosses from an old extension, from a new one before its welcome, and under
  a service that sends no list. All event params remain page-controlled data (B4). *Tests, for the
  cost only: the Rust scan fails when the code matches an event the list lacks in the shapes it
  recognises (match arms; `Some(..)`, tuple and `let`/`if let` patterns; `==`/`!=` with the literal
  on either side, or `== Some("X")`/`!= Some("X")` with `Some` on the right; `m.eq("X")`;
  `matches!`; an inline list's `.contains`; `const`s and `static`s). It does not see
  `Some("X") == m`, `"X".eq(m)`, `eq_ignore_ascii_case`, a `let` list or set searched later, or a
  macro's literal argument; such a read filed as a command still fails, because every command name
  the code uses must be passed to a call somewhere (a read through a helper call is the gap). A
  prefix literal (`"Page."`, `format!("Page.{e}")`, `starts_with("Page.frame")`) fails a test of its
  own; a name split at its dot does not. The scan also fails when the list names an event no code
  literal names. `npm test` checks the filter, its fallbacks, the first-welcome rule and that the
  worker's own handling (dialogs, foreign frames, screencast ack) runs before it.*
- **SR-21** One link per profile: a second live extension instance in the same profile that answers
  ping is refused; the same instance replaces its own link. Profiles other than the usual one link
  only as SR-76 allows. *L3, L4.*
- **SR-22** The badge shows while any tab is attached, a session kept only for a hidden window's
  close (SR-60) included. A click takes the agents' control away at once: it posts
  `canceled_by_user` for each tab the current service attached, and from then on the service's
  commands to that tab are refused as not attached and its events are not posted. A session kept only
  for a close whose window is no longer closing is detached at the click. Each of the service's tabs
  is detached right after one `chrome.tabs.get` reads its window, unless that window's hidden close is
  already running. The sessions of such a window, attached or attached only for the close, are kept
  only for that close, so it stays quiet, and end with
  their tabs or when the close ends (about 8 s at most, and after a fallback once the window is gone,
  at most 10 s more; SR-60). The engine does not re-attach after a click. If it then closes the tab,
  the extension attaches briefly only to close the page quietly (SR-60), and a second click during
  that close keeps the session for it the same way. A dropped service detaches the other tabs that
  were attached when it dropped, at once, so the next service can attach them again, and closes
  unshown agent windows the way the agent's close does (SR-60). Their tabs are held for that close,
  no longer the service's, so a later click reports only the tabs the next service attached. A tab
  the next service attached since cleanup began keeps its session (a token per attach). The tabs of
  a window being closed are never detached before its close ends: their sessions end as the tabs
  close, so the close's fallback still has them, and the window's record stays until the window is
  gone. *L1; L4: a
  hidden page with a `beforeunload` closes when the service is killed, with no dialog and (macOS) its
  window minimized throughout.*
- **SR-23** `clearForeignFrames` runs only in a tab whose window is recorded hidden (`=== false`; an
  unknown window is refused). It runs in the isolated world, removes only `iframe`, `frame`, `embed`
  and `object` elements whose source is another extension's `chrome-extension://` URL, never their
  hosts, and stops on `markShown(true)`. phantab: it reads `children`, `tagName`, `nodeType` and
  `documentElement` through the prototypes' getters, so markup that shadows a form's or the
  document's own properties neither ends a frame's scan nor hides an added form's subtree. The guard
  it keeps per frame is read only as the global's own `phantabForeignFrames`, never by name, so
  `<div id=phantabForeignFrames>`, which the window's named properties give for that name, is not
  taken for it. *L1: `extension/test/frames.test.mjs`, the guard in a fake DOM, a clobbered form and
  document and an element named like the guard included; L4: the foreign-extension fixture; refused
  on an owner tab and a shown window.*

### Window control
- **SR-24** A window is hidden, shown or moved only when it belongs to a process whose image path is
  the configured Chrome, its rect matches at its DPI, exactly one window matches, and its title holds
  this record's `PHANTAB-<uuid>`. The handle's process is re-checked before every show or hide. A
  window hidden by the hook but never confirmed is restored with `SW_SHOWNOACTIVATE`. A window that
  moved since it was recorded is refused. *L5: an unrelated Chrome window at the same rect is restored
  and never activated.*
  phantab status: the L5 test (`crates/phantab-window/tests/window_lane.rs`) no longer runs
  automatically. There is no CI, it is Windows-only (on the Mac it passes without running), and it opens
  real Chrome windows, so it is not run on a desktop in use. It runs only by hand, with `scripts/check.sh
  --chrome` on a spare Windows machine or a Windows desktop session where pop-ups are OK. SR-25's L5
  check is in the same lane.
- **SR-25** The window module touches no window of another user session or desktop, and never calls
  `SetForegroundWindow` except in `show`. *L5.*

### Engine: ownership and agent safety
- **SR-26** The client id comes from `PHANTAB_CLIENT`, the session variables, or a random UUID, and
  is 1 to 150 characters. Every page call checks `owner == client`, with one message for an unknown
  page and another session's page. *L3.*
- **SR-27** No page method returns or changes a record owned by another client, except `adopt` of an
  orphan. *L3: every page method called with a foreign pageId.*
- **SR-28** Under `siteLock: exclusive`, `act`, `navigate` and `show` take the origin lease, refused
  while another owner or a paused record holds that origin. `navigate` locks the destination origin
  before it goes. Under `shared`, the default, no lease is taken and another owner's page refuses
  nothing; a paused record still refuses its own agent's writes. Any value but `shared` counts as
  `exclusive`. `show` with `release` ends the record (no lease, nothing to resume or close) and leaves
  the tab open as the owner's. *L1; L3.*
- **SR-29** `pages()` shows another client's orphaned record with only its pageId, mode and origin.
  No path, query, fragment or title. *L3.*
- **SR-30** Open, navigate and attach accept only `http:` and `https:`. Only the service itself makes
  the workspace `data:` URL. `allowLoopback` exists only in test builds (`cfg(test)` or a test feature
  that release builds cannot enable). *L1: URL table; L1: release build has no `allowLoopback`;
  L3.*
- **SR-31** `ownerConfirmed` is read only from the MCP argument, never from page content. The isolated
  view resumes only after the owner's Return-to-agent click through `/viewer`; `ownerConfirmed` is
  ignored there. *L3.*
- **SR-32** Errors to agents are bounded: page-derived text in an error is cut to 300 characters, and
  no error carries the token, a credential, an environment value or a file path inside the runtime
  dir. Internal errors become a fixed message plus a short code. *L3: sentinel page title of 10 kB;
  token sentinel.*
  The message for a detach caused by another extension's frame is held to the same rule. The page in
  the tab chooses the `chrome-extension://` address it frames, so that address's host is page text:
  it is looked up and named only when it has the form of an extension ID (32 letters `a` to `p`), and
  otherwise the message says "The other extension". An installed extension's name and the bridge's
  words for a frame scan that failed in the page are cut to the 300 characters too. Every session
  reads this message through `status`. *L2:
  `a_detach_message_never_names_a_page_chosen_host_and_cuts_names_and_scan_errors`.*
- **SR-33** MCP tool schemas set `additionalProperties: false`; unknown tools and extra arguments
  are errors. *L1, L3.*
- **SR-34** The page scripts read no `value` of an input
  or select, no textarea text, no frame that is not http(s), and keep the caps: 18000 text characters,
  180 elements, 500 shadow roots, 3 s per frame, reported through `framesUnread`, `framesSkipped` and
  `elementsOmitted`. While a password is filled, reads and screenshots are blocked. The sign-in's scripts of
  phantab's own are `CONTROL`, which hands the locator click the control, and `WATCH_INPUT`,
  `INPUT_SEEN` and `STOP_WATCH`. They take no argument and read no field
  value: the last three listen for a trusted pointer move in the control's document;
  `WATCH_INPUT` returns only `true`, `INPUT_SEEN` only whether one came. A page can end the wait
  early or, by blocking its main thread, delay the click by up to the wait's bound (about 3 s plus
  the moves): at worst a dropped click, which it could already cause by ignoring the click.
  phantab runs the page scripts and the sign-in scripts, these four among them, in an isolated world
  per frame and document (`Page.createIsolatedWorld`,
  kept once Chrome reported it for that frame and called by its unique context id), so page script
  cannot change what they see or see what they write. The world does not stop DOM clobbering, where
  markup alone shadows a document's or a form's own properties (`<input name=action>`, `<img
  name=body>`, `<img name=querySelectorAll>`): the click checks, readFrame, the in-page checks (the
  actionability check's `disabled` too) and every sign-in script, `findSignIn` and the aim on each
  element they judge (a `<form role=button>` control among them) and the leak sweep's `readInputs`
  and `blankInputs` included, read those through
  the prototypes' own getters and methods, and a sign-in whose form action cannot be read or resolved
  is refused, never let past the cross-site check (`page_js/mod.rs` and `signin/page.rs` list each
  such read). The
  engine's click script is left as it is: a form whose field shadows `click` makes it throw, so
  nothing is clicked. Only fill's writes and the SR-61 popup script run in the page's world: fill
  reads the field and focuses it in the isolated world, and the engine decides what to clear and type,
  so the page cannot choose the keys. The service cuts the title and each element's `tag`, `id`,
  `name` and `type` to 300, `text` to 160 and `href` to 2048 itself, the page's URL in every result to
  2048, and marks a frame element outside its frame's box offscreen. A locator click is checked and
  pressed at one point, on whole CSS pixels. A click on an element something else covers there is
  refused, not pressed, and so is one where layout has a frame element on top there, other than the
  element or one holding it, whatever its `pointer-events`, opacity or origin
  (`DOM.getNodeForLocation` with `pointer-events: none` ignored: `elementFromPoint` sees through such
  a frame, yet headless Chrome routed the press into a cross-site one). The command is asked again
  with `pointer-events` honoured. Other content both answers put on top must be the element's own
  (the element, inside it through shadow roots, or inside a label for it, but not inside a link, a
  button, a form control, a `summary`, a nested label, a `details`, a `video` or `audio` with
  `controls`, an image map, an editable region or an element with a click handler in that label,
  which takes the click itself; a handler added with `addEventListener` cannot be seen, a residual):
  this answer is the later
  one, so an overlay a page timer slid in after the page's hit test is refused. A frame's offset is
  its content box's as layout has it, from `DOM.getBoxModel` (at a device scale of 1, a `0.9px` padding
  is 57/64 px in layout,
  where `parseInt` read 0 and a point between pixels passed as whole). When the two answers differ
  (content that takes no pointer events, such as a `::after` or span decoy over a frame, lies over
  the point), when the node on top is a pseudo-element, when a frame element or one above it (up its
  document's flat tree: to the slot it is assigned to, from a shadow root to its host) may move it by
  a fraction (a `transform` that only translates, `translateZ` and 3D matrices among them, a
  `translate` or `perspective`, an identity `scale` or `rotate`, a 3D or hidden-backface layer, a `will-change` for those, `position:
  sticky`, a scroll container scrolled by a fraction or with its padding box at one, a `<details>`,
  `<select>` or `<marquee>`), or hosts a closed shadow root that may slot it through wrappers the
  world cannot read (`DOM.describeNode` asked of every candidate host, in the click check's frame
  query), when a frame on the way has a content quad not the size its style gives (to a layout unit,
  and to the six digits computed style keeps; page zoom does this) or that lies 2^18 px or more out
  (where a `float32` quad no longer holds every layout unit),
  when a command fails (an older extension refuses one), when the scroll does not read as numbers or
  it, or a frame element placing the element's process up any level, changes between the check's two
  reads of it,
  or when the point falls between pixels in a frame's document, any frame element (`<iframe>`,
  `<frame>`, `<object>`, `<embed>`, `<fencedframe>`) whose box holds the point refuses the click,
  failing closed. A test build counts each such fallback by its reason (decoy, between pixels,
  transformed, pseudo-element, failed). The whole-pixel test is exact at page zoom 100% and a device
  scale of 1: layout positions are multiples of 1/64 of a device pixel, exact in an `f64`. Under page zoom or a
  fractional device scale (125%) a whole point can read a hair off whole, and the box rule answers. A frame under opaque content or `visibility: hidden` does not count, so a
  button over an embed clicks, and so does a button under a decorative overlay with no frame at the
  point. The test runs again after the pointer moved, the frame query last, just before the press.
  A click in a frame that the page scales, rotates, skews, mirrors or zooms (on the frame element or
  above it up the flat tree: a `zoom` other than 1, an `offset-path`, a `scale` or `rotate` other
  than the identity, a `transform` whose linear part, read at full precision from the typed value, is
  not the identity, an SVG, the frame element drawn at a size other than its style's, so a closed
  shadow root's scaled wrapper cannot hide a scale that changes the size by about 1/64 px or more
  (below that the closed root sends it to the box rule), a quad that is not an upright rectangle,
  checked even when something else only moves the frame, since only the quads show a mirror or half
  turn in a closed or UA shadow root (review r9 M-1), or a box model that cannot be read, which says
  phantab could not read where the frame is drawn, not that the page turns it) is refused
  before the pointer moves, since where its press lands is not known: `Covered`, in phantab's own words, with the reason
  logged (`Transformed`).
  Known false refusals, kept by design (fail closed): a frame with `pointer-events: none` inside the
  target, same-process ones too, and, under the box rule, a button over a frame, such as an honest
  play button whose icon takes no pointer events over another site's video frame, and so a sign-in
  whose button has such a frame laid over it, which ends in a wall (`no-clear-submit`, nothing
  pressed; before SR-34's frame query it pressed the frame). A rule that passed
  it (both answers name nodes of the target, and the frame is not inside it) would rest on the press
  going where `pointer-events` honoured says, over another site's frame, which is what `#xbehind`
  and `#xclear` measure, not a guarantee, so it is not taken. The sign-in's click is that
  click on the control, once its aim has passed. Neither of the click's waits needs a rendered frame,
  so it ends in a hidden window too. Residual: a property page script sets on a custom
  element (a non-reflected `disabled`) is not seen by the actionability check; a page timer can change
  the page between the second test (or the box rule) and the press; a pinch zoom is not checked (the box model's quads are scaled by it, the
  offset takes only their differences, and the point is not mapped through it); the offset is
  layout's, not paint's: Chrome draws and routes another site's frame at a whole device pixel within
  its transform node, so with a fractional offset its document can get the press under a pixel from
  the point checked (that case goes to the box rule; `#xpad` records where the press lands, and
  `#xwhole` asserts a whole offset gets it at the point checked); a transparent cover that takes
  pointer events, inside the target, over a cross-site frame with `pointer-events: none` passes as the
  target's own, which rests on Chrome sending the press to the cover (review r6 F2: the Mac's
  headless Chrome sends it there, the card taking the press with no fallback; `#xclear` asserts only
  that phantab does not falsely refuse the cover, its control press with the cover gone reported, not
  asserted, since on the Mac's headless Chrome it did not reach the frame; no lane proves whether Chrome
  presses through a cover into a frame beneath, the S5 lanes refusing before any press, so that is a
  residual, bounded by the `Covered` refusal of a frame at the point and not closed); for a cross-site frame, Chrome routes the press by
  the hit-test data of the last frame drawn, while the test reads current layout, so a page that
  changes `display`, `visibility` or `pointer-events` right after each frame can show the test one
  state and the press another (unverified, not checked); between focusing a field and typing, the page can
  move focus into a cross-origin frame, which then gets the keys; whether `Page.createIsolatedWorld`
  works in a sandboxed frame without `allow-scripts` waits on the Chrome lane's run of its test (if
  not, the frame counts in `framesUnread`). *L1: page units for the world (made once per document, made again after a navigation, a
  lost context or a unique id gone, an answer that comes before its event, never the main world on a
  failure) and the covered click (the second test, frames inside the element, the node on top: a
  frame element or a child frame's node refused, other content passed, its document coordinates, asked
  twice at the pressed point, last; two answers that differ, one that fails, a scroll that is not
  numbers or a point between pixels sent to the box rule, each with its reason; a frame placed by its
  box model, a turned or mirrored one refused, and a scaled, far-out, moved-from-above, closed-host
  or unread one sent to the box rule, as is a page that scrolls during the check, and one 10,000 px
  wide placed by its box model; other content on
  top that is not the target's own (a timer-moved overlay) refused, a pseudo-element sent to the box
  rule; when the command fails, the box of every frame element; and in node, the rules of both, a
  decorative overlay with no frame passed, `<object>` and `<embed>` found, a `0.9px` padding kept,
  transforms and zoom found above a frame up the flat tree, through slots and shadow hosts, a
  scale hidden from the computed text found in the typed value, the target's own content through
  shadow roots and labels, and a link, button, nested label, `details`, media with controls, image
  map, editable or handled element in a label not the target's); engine units for
  the
  caps and the frame box; L2: a filled field's value never appears; page tampering, clobbering markup
  (an echo behind `<img name=body>` too), an action that is not a URL and a cross-site action refused;
  a frame in the button, in the light tree or a closed shadow root, a wall with nothing pressed
  (`tests/signin_chrome.rs`); a covered button, frames inside a target, its label and its shadow
  roots, another site's frame in a closed one, a frame with `pointer-events: none` in a card link,
  another site's such frame in a card link and laid over a button (nothing pressed), a `::after` and a
  span decoy over such a frame in a card link (refused by the box rule), a button under a decorative
  overlay with no frame (clicked by the box rule), a button far down a column of another site's frame
  (clicked; a missed scroll would refuse it), a play button over that column (refused, the known false
  refusal), frames in the first view offset by a `0.9px` padding (its button clicked by the box rule,
  between pixels, and where its document got the press recorded) and by a `1px` one (settled by the
  node on top, the press got at the point checked), a frame at `left: 99.5px` in a `translate(0.5px)`
  (clicked by the box rule, transformed), frames slotted into an open and a closed shadow root under
  a translating wrapper, a sticky one and one in a scroller at a fractional corner (clicked by the box
  rule, transformed), frames in a `scale(1.5)` in the open and through a closed shadow root (refused,
  nothing pressed), a `::before` over a card's frame (refused by the box rule, pseudo-element), a
  transparent cover over a card's frame (`#xclear`: the check passes with no fallback and the card
  takes the press; a control press with the cover gone is reported), a link in a label
  laid over its checkbox (refused), the `#xpad` and `#xclear` outcomes written to `sr34-*.txt` in the
  test target's scratch directory (`target/tmp`), each asserting
  which rule answered and why (a `test-seams` counter by reason), the card and a button over a page-sized frame again with the page scrolled both ways, in the main frame and
  in a scrolled frame of the same site and of another, and the world in a sandboxed frame (`tests/chrome.rs`); the parent-frame hit test, through a sign-in whose control is
  in a frame, a nested frame or a cross-site frame, a `<form role=button>` control, and another
  site's frame with `pointer-events: none` over the button (`overframe`, a wall, nothing posted)
  (`tests/signin_chrome.rs`).*
- **SR-35** An action interrupted by a detach is never sent again. A read runs at most once more,
  after re-attach. The client's own resend is a stricter form of the same rule: a call lost on a
  kept connection (perhaps written, then the connection ended before any answer) runs once more on
  a freshly proven connection only when it is one of `status`, `heartbeat`, `pages` and `tabs`,
  which only read or say the client is still there. *L1, L3.*
- **SR-36** At most 6 recoveries per record per minute. Recovery clears foreign frames only in hidden
  agent windows and never touches a visible tab. *L4.*
- **SR-60** A JavaScript dialog in a hidden agent window is answered by the extension before Chrome
  draws it: leave and alert accepted, confirm and prompt dismissed. Dialogs in a window the owner can
  see are never answered. An isolated-headless page answers its own. The agent learns each dialog's
  type, page text (cut to 500 characters) and answer in its next `snapshot`, `wait` or `act` result.
  A hidden page the agent closes is closed with `Target.closeTarget`, which runs no `beforeunload`;
  it is never kept as a spare window and blanked, as that navigation would run it.
  Only a tab that could not be closed so (no debugger may attach to it, or the close was refused) or
  is still open 2 s after its close was sent goes with `chrome.windows.remove`, which may raise
  "Leave site?". Its session, if any, is kept for that, and a tab attached only for its close (a
  popup) has the `Page` domain turned on first, so the dialog is answered as above. A window shown to
  the owner while it closed is theirs: no close is sent to its tabs once its record reads shown, it is
  not removed, and the bridge's `closeTab` answers an error saying it was left open (the engine
  ignores `closeTab`'s result today). A window whose record is gone is not taken as shown.
  A tab or target list that cannot be read leaves the window to the fallback. A session kept only for
  the close is detached when the close ends: at once when no fallback follows or the close fails
  (`chrome.windows.remove` fails, the window was shown, or another error), else once the window is
  gone, at most 10 s after the fallback. After a fallback the window takes no second close until it is gone (at most 10 s), so none can
  take or cut that session. A badge click detaches it at once only when its window is not closing
  (SR-22), and an attach that lands after its close ended is detached at once. A window's tabs close
  in parallel and every step is bounded (no close is sent after 4 s), so the close replies within
  about 8 s, under the service's 15 s for an op.
  *L1: extension and engine units; L4: a hidden page's close and navigation do not wait on
  "Leave site?", its close opens no dialog and (macOS) leaves its window minimized throughout, and
  confirm and alert are reported.*
- **SR-61** A page in an agent window opens its popups as tabs of that window, with `opener` and the
  window name kept, and a closed hidden agent page takes its window and those tabs with it. A tab in a
  hidden agent window is muted, and a new one there does not take the agent page's place as the active
  tab. A shown window has its sound back. The owner's own tabs get neither change. A hidden agent
  window stays hidden when Chrome shows it for a new tab: on Windows the hide is applied again at every
  show until the owner is shown the window, and a destroyed window is forgotten; the hook that does it
  sees only the windows of the Chrome process that owns a kept window, and only while one is kept and
  that process runs (held open, so its id is not reused while hooked). On macOS the extension
  minimizes it again, for 2 s after each new tab, until the window is shown (briefly visible while
  it animates). *L1: extension, page and engine units, `win32.rs` units `keeper_scope_and_lifetime` and
  `an_ended_process_takes_its_windows_and_hook`; L4: a hidden page's popup lands in its own
  window, keeps its opener, shows no window (Windows) or leaves it minimized (macOS), and goes with
  the close; L5: a kept window's show is undone, a released one stays shown, a popup, a tab and an
  alert from its page leave it hidden, and a killed browser's hook is dropped.* The popup script
  wraps `window.open` and the three-argument `document.open(url, name, features)`, which Blink sends
  to the native `open` past a replaced `window.open`. It runs in the page's own world, and a page can
  tell it is there (a Proxy's `toString` has no name); phantab does not try to hide that it drives a
  page. Chrome injects it into every new main-world context, a new iframe's initial `about:blank`
  included, so an `open` taken from a fresh same-origin iframe is wrapped too. *The real-Chrome lane
  (`phantab-cdp/tests/chrome.rs`) opens a popup each way and checks it is a tab of the page's window.*
- **SR-37** `shutdown` refuses while records remain; the service refuses to stop during a takeover.
  MCP clients with no heartbeat for 10 minutes are released (not `cli:` clients). *L3.*
- **SR-77** The sensitive-set check (`guardrails` `light` and `full`, `docs/GUARDRAILS.md`) is a script
  of phantab's own, `page_js/sensitive.js`. It runs in the isolated world like the scripts of SR-34 and,
  like them, reads the document, the control and its form only through the prototypes' own getters and
  methods (`Document.prototype.querySelector`, `elementFromPoint` and `activeElement`,
  `Element.prototype`'s `tagName`, `getAttribute`, `closest`, `matches`, `querySelector` and
  `querySelectorAll`, `HTMLElement.prototype`'s `innerText`, `Node.prototype`'s `textContent`, and an
  input's or button's own `type`, `value` and `form`), so markup that shadows those names on the
  document or on a form (DOM clobbering) cannot make it throw or answer for another element. It
  returns one of three words or `null`, never page text (SR-32). A page that cannot be read at all (a
  frame gone mid-check) still lets the act through, as `docs/GUARDRAILS.md` says: the check is a
  prompt for the owner's word, not a wall, and it does not run under the default `parity`. *The
  real-Chrome lane (`engine_chrome.rs`,
  `markup_that_shadows_dom_properties_cannot_silence_the_sensitive_check`) clicks by selector and by
  point and presses Enter on a page that shadows every one of those names, and is refused each time.*

- **SR-88** `screenshot` and `snapshot` save their result to a file only when asked with `path`.
  Writing a file adds little: the MCP client that asks already runs as the owner, with his disk, and
  the service writes as that same user, so it writes nothing the client could not. What is refused:
  a path that is not absolute (it would land in the service's own working folder), a folder that does
  not exist (named in the error), and a file that exists unless `overwrite` is true; a file that
  appears between the check and the write is still not replaced (it is made new). A saved snapshot is
  redacted as its answer is (SR-45). Every screenshot refusal (a page that showed a password or code
  back, a sign-up's new password on the page, SR-82) comes before any argument is read, so it refuses
  every form: `path`, `format`, `fullPage`, `selector`, `width` and `height`. `width` and `height`
  emulate the view for that picture alone through the already-allowed
  `Emulation.setDeviceMetricsOverride`, put back after it, also when it fails, and are refused on a
  page handed to the owner. No CDP method was added. *L1: `engine::files` tests (relative, missing
  folder, existing file, a file that appears after the check), every new form refused on a marked page
  and its saved snapshot redacted
  (`after_an_echo_every_answer_is_redacted_and_the_tab_refuses_screenshots_until_it_closes`); L3:
  `screenshots_and_snapshots_are_saved_as_files_at_the_size_asked`.*

- **SR-89** The steps that act beyond a click or a keystroke: `upload`, `dialog`, `back`, `forward` and
  `reload` (and `hover`, `drag`, which only move the mouse). An upload sends only files named by an
  absolute path that exists and is a file, checked by the service before the page is touched, into an
  element that is an enabled `<input type=file>` taking that many files (`DOM.setFileInputFiles`; no
  file chooser opens). The service runs as the owner, so any of his files can be named: with
  `guardrails` `light` or `full` every upload is asked about first (`ownerConfirmed`), whatever the
  site, and so is every `["dialog", "accept"]`, since a confirm's yes may be a deletion or a payment;
  a dismiss is not asked about. A dialog answer is used once, for that page's next dialog, and only on
  a page the owner cannot see: an isolated page, or a hidden agent window, where the extension refuses
  the answer for any other tab and drops it when the window is shown or the tab detaches. `back` and
  `forward` go only to a website (http or https) entry and take the site's lease first, as
  `navigate` does; with guardrails on, a move or reload onto an entry Chrome marks `form_submit` is
  asked about first. A drag is checked at its drop target, and a key combination by its last key, as a
  click and a press are. A page handed to the owner refuses every one of these steps. Four CDP methods
  were added to SR-20's list: `DOM.setFileInputFiles`, `Page.getNavigationHistory`,
  `Page.navigateToHistoryEntry` and `Page.reload`. *L1: `engine::steps` tests (relative, missing, a
  folder, a non-text path); the extension's answer used once and refused for other tabs
  (`events.test.mjs`); L3: `upload_sets_a_file_input_and_refuses_what_it_cannot_send`,
  `with_guardrails_on_uploads_and_dialog_accepts_are_asked_about_first`,
  `moving_onto_a_page_a_form_sent_is_asked_about_first`, `a_handed_over_page_refuses_every_new_step`.*

### Verification hand-off
- **SR-68** Phantab never solves a verification check. During a check it only reads: the CDP frame
  tree, the challenge frame's box as its parent lays it out, whether that frame's element shows (read
  on the element in the parent document), `VERIFY_STATE` in the main frame, and the page's visual
  viewport in the main frame's isolated world when Chrome refuses its layout metrics. It
  sends no input, focus or script to a challenge frame, and no input to the page at all except the
  owner's, through the viewer or their own window. No solving service, no change to the browser's
  identity. Agent writes to the page and its site are refused while the check is live. A check pops up
  at most once per page in 10 minutes and three times per site in an hour; past that nothing pops up.
  *L1: the rules and limits; L3: no `Input.*` reaches a page between its check and the check's end
  that the owner did not send.*
- **SR-69** A check's end hands back only a hand-off Phantab started. A page the owner held before
  the check stays with them until their own handback. `resume` refuses while a check Phantab started is
  live. *L1; L3.*
- **SR-70** The remote view listens on loopback only (`remoteViewer.listen` must be a loopback
  address); Phantab opens no network listener of its own. The listener serves `GET /view` and
  `POST /viewer` only: everything else, `/rpc`, `/bridge`, `/health` and `/hello` included, is 404, and no
  upgrade is served. It answers only the exact Host of `publicBaseUrl`, refuses any other Origin, and
  with `trustedIdentity` refuses a request whose header does not equal the owner's identity (constant
  time). A bad setting leaves it off. *L1: config checks; L3: each refusal.*
- **SR-71** A link's token is 24 CSPRNG bytes, made at the pop-up, in the link's fragment only, for one
  page. It works only on the remote listener and only while its check is live: a clear, Not now,
  expiry after 15 minutes, a close or a release ends it. It is never written to disk or into `status`.
  *L3: the token works only on its listener, dies with its check, and is in no runtime file.*
- **SR-72** A hand-off's wake token is 24 CSPRNG bytes, made with the link, never the link's. It reads
  only its check's state name and page id, through `check_wait` on the endpoint token's `/rpc` (no
  remote listener takes it), compared in constant time; it opens no view, sends no input and reads no
  page content. It is in the `wake` command line, so it is in the agent's chat and the process table;
  that reveals when a check ended, nothing more. It answers for 17 minutes after its pop-up, then is
  forgotten. It is never written to disk or into `status`. *L1: the token is not the link's, opens no
  viewer on either listener, and an unknown one answers `gone`.*
- **SR-75** Passkeys (README § When a site wants your passkey). Phantab never answers a passkey request: it counts them in an
  agent's page and hands the tab to the owner. The counter (`PASSKEY_WATCH`) runs in the page's main
  world, passes every call through unchanged and keeps three integers, never what was asked or
  answered; only those three leave the page, checked as non-negative integers. A page can forge or
  hide them: forging only shows its tab to the owner (as `browser_show` does), and hiding leaves the
  sign-in as it was before. The passkey hand-off is asked, as `browser_show` is, so the pop-up limits
  (SR-68) do not hold it back; it keeps the hand-off's other rules (writes on the site refused, SR-69's
  hand-back, SR-71's link). An owner's tab gets no counter. The Bitwarden source reads only whether a
  login's `fido2Credentials` list is empty, and keeps none of it. *L1: the detector's rules and
  lines; L2: `wall` / `passkey` before anything is fetched or filled; L3: the hand-off pops up with no
  grace, refuses writes and Done while the request waits, and ends at its answer with no input sent.*

### Sign-in and credentials
- **SR-38** Credential values live only in `Zeroizing`/`secrecy` types whose `Debug` prints
  `[redacted]` and which implement neither `Display` nor `Serialize`. They are zeroized on drop.
  *L1: `format!("{:?}")` of each type prints no value.*
- **SR-39** No credential byte, raw or URI-, base64- or base64url-encoded, appears in any MCP result,
  CLI output, service or host stdout or stderr, log, tracing event at any level, error, panic message,
  or file under the runtime dir (the guard file included), after any sign-in status. *L3 and L4:
  sentinel password through every status at `RUST_LOG=trace`, all outputs and files scanned; after
  each status no input in any frame holds it.*
- **SR-40** Sign-in answers carry only the whitelisted statuses and reasons. Any Rust error becomes
  `failed`/`error`. No provider text reaches the agent. *L3: fake provider prints a sentinel status
  and a stack.*
- **SR-41** CDP transport, bridge, host and service log CDP method, id, session, size and timing only.
  No code path passes a CDP params or result body, a header value, or a frame body to a `tracing`
  macro, at any level, in any build. *L1: a lint or grep test over the transport and bridge
  modules; L3: sentinel scan at `RUST_LOG=trace`.*
- **SR-42** The tracing filter caps `hyper`, `h2`, `tungstenite`, `tokio_tungstenite`, `rmcp` and any
  HTTP client crate at `info`, whatever `RUST_LOG` says. `sign_in` answers `failed`/`debug-logging`
  without starting the provider when the effective level of any phantab target is above `info`.
  *L3: service with `RUST_LOG=trace` refuses sign-in; with `RUST_LOG=hyper=trace` no header value is
  printed.*
- **SR-43** The seal is X25519 with a fresh key pair per call, HKDF-SHA256 with an empty salt and info
  `phantab-sign-in-seal-1`, a 32-byte key, AES-256-GCM with a 12-byte IV. The digest must match the request
  as sent, else `refused`. A held `accountKey` that differs gives `refused`. The secret key and AES key
  are zeroized after one unseal. *L1: known-answer vector; L6.*
- **SR-44** The provider runs with no shell, its argv from config plus the public key last (the
  program an absolute path, never looked up on `PATH` or in the current folder: a bare name is
  `provider-failed`, and `install --sign-in-provider` refuses one), an
  environment cleared to a fixed allow-list plus `PHANTAB_RUNTIME`, stderr to null, the request on stdin, stdout capped at 256 KiB, the first line
  only, and `busy` at 45 s. The service is its direct parent. On timeout or exit, the whole process
  tree is killed (Windows job object with kill-on-close; macOS process group). *L3: fake provider
  reports its env; a grandchild is gone after timeout.*
- **SR-45** Sign-in keeps these page guards: HTTPS at every level, GET-with-password blocked,
  pay, sign-up and new-password refused, `moved` re-check, owner-has-page re-check, the echo sweep,
  and stopped hosts checked before the provider is asked (the stops only under `guardrails: full`, as
  SR-46 says). phantab adds: the report's frame URL and ancestor origins must match Chrome's frame
  tree; the sweep looks for the code too; and a page left unconfirmed stays refused until every frame
  that answers the re-blank holds neither the password nor the code, in an input of any type, and the
  main frame, the sign-in frame and any frame whose value the sweep could not blank have answered (a
  frame other than the main one may instead have gone). Another frame that does not answer is passed
  over. When the sweep finds the value echoed, the sign-in goes on to its outcome with
  `echoed: true` and a fixed note, and from then on, in every `guardrails` mode and for the service's
  life, phantab redacts every form of the value (`[redacted]`) from every answer and error the agent
  gets (snapshots, text, URLs, tab titles, act, wait and status results), holding only keyed digests
  of them, never a value (SR-38). A screenshot of that tab is refused until the tab closes, a fresh
  attach to it included. With no key to redact by, the page is held as unconfirmed instead. Not
  covered: the owner's live view, a value cut by the `tabs` length limits or split across DOM nodes,
  screenshots of another tab the site opens, and a service restart.
  *L3: scripted sign-in pages, and `signin_echo` (each echo fixture through `phantab serve`); L4.*
- **SR-46** Under `guardrails: full` (`docs/GUARDRAILS.md`): at most 2 password sends per account an
  hour and 6 a day. In `parity`, the default, and in `light` the owner has the limits and the stops
  off: phantab neither reads nor writes the guard file, and nothing in phantab slows repeated
  sign-ins (security audit, 2026-11). The guard file is written
  atomically, owner-only and fsynced before the click. A damaged or wrong-version guard gives
  `stopped`. `sign-in-clear` works without the service, and only with a terminal on stdin and the
  host (or `all`) typed back at the console with echo off, as `bitwarden connect` reads the master
  password. That stops a plain non-interactive shell, an agent's included, and a clear run by
  mistake. It does not stop a determined process running as the owner: one can drive a
  pseudo-terminal (`script` on macOS) or send keys to a console on Windows and type the host back, or
  delete or rewrite the guard file, which resets every stop and limit (R20). *L3.*
- **SR-47** Values reach the page only as `Runtime.callFunctionOn` arguments, never inside function
  source. The extension neither logs nor stores them. phantab's own copies are zeroized: the opened
  seal, the values (`Secret`), and the native host's relay buffers after each chunk. The JSON the
  service serializes for that call (serde_json, the bridge frame's `Bytes`, the CDP socket's buffers)
  is not; that gap is residual R5. *L1: bridge buffer type; L4: extension source check.*

### Built-in Bitwarden source
- **SR-62** Only the CLI's session key is stored, never the master password. Windows: DPAPI, user
  scope, `CRYPTPROTECT_UI_FORBIDDEN`, a fixed entropy, in an owner-only folder, written beside and
  renamed in; a blob that does not open is an error. macOS: the login Keychain, opened by its path (the
  home folder from `getpwuid_r` for the real user ID, never `$HOME`) and used alone for the store, the
  read and the delete (never the default keychain or the search list, which a same-user program can
  point at a keychain of its own), always as a new item (every item
  under the name is deleted first, so an item another program planted with its own access list is
  never updated in place), read into a buffer that is zeroed before it is freed; test builds use their
  own service name, and on macOS a scratch keychain of their own, never the login keychain: a guard
  refuses any path that is or may be one of the owner's keychains (R21). The key is stored with its pin (SR-64). The key is checked as
  base64 of at most 512 characters before it is stored or used, is zeroized on drop, prints
  `[redacted]`, and only reaches a `bw` child in `BW_SESSION` (the environment copies are R17).
  `disconnect` removes it and runs `bw lock`; when the config no longer names the source it still
  removes it and skips only the lock. *L1: DPAPI round trip and wrong entropy, key parsing and `Debug`,
  the stored record; macOS: a store over a planted item leaves one new item, the home folder is the user
  database's. L3: `connect`, `status`
  and `disconnect` over the test store.*
- **SR-63** `connect` reads the master password only from an interactive console, with echo off, into
  a zeroized buffer, and passes it only in the environment of one `bw unlock --passwordenv` child:
  never argv, a file, stdout or a log. A wrong password stores nothing, and its error does not repeat
  it. The console's line editing and signal keys are off for the read (unix `ICANON`, `ISIG`,
  `IEXTEN`; Windows line, processed and virtual-terminal input), so Ctrl+C arrives as a key: the
  terminal's settings are restored by a guard on every return, the line ends, and `connect` exits 130
  instead of leaving echo off. A signal from outside the terminal (unix `kill`, a closed window,
  Windows Ctrl+Break) still ends the process without the guard. *L1: the prompt's keys as a pure
  function of the units typed; the Windows mode bits. L3: the fake `bw` reports where the password
  arrived; no other child had the variable; no value in its log or the error.*
- **SR-64** `bw` is the configured absolute path (or `[absolute program, args...]`), never looked up on
  `PATH`, and starts with no shell. `.cmd` and `.bat` are refused, also behind trailing dots or spaces
  (which Windows drops) and a `:` stream name; on Windows the program must name a `.exe`. The session key
  is pinned to the `bw` that `connect` made it with: the configured command and the SHA-256 of the
  program and of its script, stored with the key. Only two shapes are pinned: a native program (Windows
  `MZ`, macOS Mach-O) alone whose file is named `bw` (Windows: `bw.exe`), in any case, or `node` and one
  absolute `.js` script with nothing else; anything else is refused at `connect`, naming them (another
  program alone, which would run `bw`'s arguments as code, `node` with no script, a `#!` or other text
  program, a folder, a relative path, any Node option such as `--eval=`, a second argument). Launchers
  are refused the same on every system (npm's `bw`, `bw.cmd`, `bw.ps1` and macOS `bw` link to `bw.js`, as
  npm and Homebrew make it; Scoop's and Chocolatey's shims; Volta's `node`), naming the exact `bw` to set
  (docs/BITWARDEN.md § Installs). Before any `bw` runs, `connect` shows the resolved paths and SHA-256 it
  will pin, with everything but printable ASCII escaped (as in every refusal), and goes on only when
  `yes` is typed at the terminal; with stdin not a terminal it refuses. That stops a pipe or an agent's
  plain shell, not a same-user process driving a pseudo-terminal or sending keys (R16), which still lacks
  the master password. A run that carries the key starts only while both still match; the pinned files
  stay open until it exits, and it is started by the paths resolved from them (Windows: read back from
  the open handle, past every link and junction; macOS: the configured path canonicalized and checked to
  name the open file by device and inode). On Windows the handles share reading only: the hashed file
  cannot be opened for writing, renamed or deleted meanwhile, nor a folder on its resolved path renamed.
  The hold covers that file, not a link or junction on the configured path (repointable, but not gone
  through) nor a writable mapping made before it was opened. Otherwise nothing starts, sign-in answers
  `locked`, and `status` tells the owner to run `connect` again. `connect` checks the pin again before
  `bw` is given the master password or `login`'s prompts, and starts that `bw` from the files this check
  opened and hashed, not the path resolved before the prompt. A cached hash is trusted only while the
  file's stamp holds (unix inode and change time; Windows volume, file ID and USN). Not pinned: modules
  loaded from elsewhere (`node_modules`), system libraries, and on unix a swap or an in-place rewrite
  between the check and the moment the system opens the file (or Node reads `bw.js`); what this buys
  against same-user code is R16 (docs/BITWARDEN.md § Running bw). *L1: config parsing, the refused shapes
  (`--eval=`, a text program with no `#!`, extra options, `node`, `sh` and `powershell` alone), launchers
  refused with the `bw` to set, escaped paths, pin hashing and a same-length rewrite with its times put
  back, held files and the path read back past a junction on Windows, a repointed link not gone through,
  a key whose pin does not hold starts nothing; L3: another path, a changed program and an unpinned key
  start no `bw`, a `bw` changed during `connect`'s prompt is not given the password, `connect` runs no
  `bw` unless confirmed and refuses without a terminal, and a link repointed (and on macOS the old file
  rewritten) during the prompt sends the password only to the files checked after it.*
- **SR-65** Each `bw` run gets an environment cleared to a short allow-list plus
  `BITWARDENCLI_APPDATA_DIR`, `BW_NOINTERACTION` and, only where needed, `BW_SESSION`. The allow-list
  includes the standard proxy variables (`bw` routes its requests through `http_proxy` or
  `https_proxy`, as it does when the owner runs it; the service has them only if the client that
  started it did, SR-14, and a `proxy` in the Bitwarden config replaces them all) and never
  `NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS` or `NODE_TLS_REJECT_UNAUTHORIZED`, which would load code into
  `bw` or weaken its certificate checks; `--nointeraction` (except `connect`'s `login`); stdin null
  (a sign-up's `create` and `edit` read the encoded login from a pipe, written whole and closed,
  SR-83) and stderr null; no window; a job object or process group killed with the call; stdout capped at 4 MiB
  in a zeroized buffer; the call's deadline, then `busy`. The list output is parsed at once and its
  bytes wiped, the parsed list is wiped when the call ends, and only the chosen item's wanted fields
  become `Secret`s. No `bw` text reaches a label or an error. *L1: the allow-list holds the proxies
  and no `NODE_*` name; secrets are kept out of the copied environment. L3: the fake's logged
  environment names; huge, malformed, failed and slow output.*
- **SR-66** Ask-first: a page host on an ask-first site, or a chosen login with a URI naming one, gives
  `ask-first`; the page check runs before any `bw`. An approval opens only under the rules in
  `docs/BITWARDEN.md` § Ask first (non-empty words, at most an hour). A policy file that does not read
  gives `refused`. *L1: the clock and approvals; L3: inline sites, the file, an over-long approval, a
  broken file.*
- **SR-67** A login fits only an `https` page, by each saved URI's own setting as Bitwarden's
  clients do (`docs/BITWARDEN.md` § Matching): base domain, the default, is the same registrable domain
  under the Public Suffix List with its private section (so `a.github.io` never fits `b.github.io`);
  host is the same host and port; starts with and exact add the URL rule on the same host and port. An
  `http` entry never fits; an IP address, `localhost` or a public suffix compares host and port only;
  regular-expression and never entries never fit; `google.com` never fits `script.google.com`. Every
  URL of the request must fit one of the login's entries. More than one fit is `ambiguous` with the
  count; an agent's account name must match exactly; a held account key must be the chosen login's,
  else `refused`. A master-password-reprompt item is `refused`. *L1: matching rules, the suffix list's
  private section, IP and `localhost` hosts, `http` pages; L3: base domain against host, `http`,
  pattern and never entries, ambiguity, held keys, a form that posts elsewhere.*

### Sign-up
`browser_sign_up` (T90). The sign-in's requirements (SR-38 to SR-47) hold for it where
they apply; these are its own.
- **SR-78** The password is phantab's: 20 characters from `A-Z a-z 0-9 !@$%*-_`, one of each class,
  each an unbiased draw from the OS's random source; cut to the form's `maxlength` and never below 12,
  and narrowed by `minlength` and `passwordrules`; a form it cannot serve is refused before the vault
  is asked. It is saved in the owner's vault and read back before any character reaches the page: only
  a read-back that holds the same password and username, compared in constant time, is filled; a
  failed write or a read-back that differs fills nothing. `regenerate` replaces the saved login's
  password in place (its id unchanged), keeping the rest of the login. Ask-first applies to the
  create. The built-in Bitwarden source and a pinned v2 command provider that declared `create`
  (SR-85, SR-87) create; any other provider answers `no-provider-create` and starts nothing. *L1: the generator's alphabet, classes, lengths and rules; L3: the fake `bw`'s
  create, edit, read-back, failures and ask-first.*
- **SR-79** It fills only the page's origin: every URL above the form and every place it sends to is
  `https`, every ancestor frame is the form's origin, and every action goes to the page's host or a
  host above or below it, never a sibling, another site or a bare top-level name. A saved password is
  reused only from the login saved for this exact origin and this exact username; a login for the
  parent domain or another username is not reused, more than one is `ambiguous`, and a
  master-password-reprompt login is `refused`. *L1: the URL and site checks; L3: reuse, ambiguity and
  reprompt over the fake; L4: the fixture pages' frames and actions.*
- **SR-80** While the password is on the page, the record holds only its digests and the frames it
  was filled into. A sweep runs after the fill and before and after every snapshot, screenshot, wait
  and act on the page: a copy of the password, raw or in any leak form, in any field but a password
  field is blanked and read again. The frames that matter are the main frame, the frames it was filled
  into and every frame a sweep saw a copy in; one of them that does not answer holds the page until it
  answers clean or goes. The mark clears only when every frame that matters reads without it. *L4: a
  page that copies the password into a text field; the scripted page (`tests/signin_fake_page.rs`): a
  frame that held a copy and then stops answering, a page that puts its copy back after each blank.*
- **SR-81** A copy in a frame's address or text, where no blank reaches it, closes a tab phantab
  opened and forgets the page (`leak-stopped`); a sign-in's echo goes on instead (SR-45), but a new
  password the site has not yet taken is not left showing. A show-password toggle that makes a filled field `text` blanks it in the same
  task, before the page paints it, and the next sweep blanks what is left. Leaving the page blanks the
  fields; a form that sends by GET is refused, and a GET submit of the form is stopped. *L1: every
  leak form, found in a field, an address and a text, with digests only on the record; L4: a copy in
  the page's text, a reveal toggle, a GET form.*
- **SR-82** While the mark holds, a screenshot of the page is refused (`secret-on-page`), after the
  sweep. A snapshot still works: while the new password is on the page it reads no field's value (R8). *L4: a screenshot before and after
  the site's button.*
- **SR-83** No result, error, log, record or file holds the password: the answer is a status and a
  reason from a whitelist (and an `ambiguous` count); the generated password lives in a zeroized
  `Secret` for the call; it reaches `bw` only on a child's stdin, never its command line or
  environment, in a buffer allocated once at its final size and zeroized, and `bw`'s output of the
  item is wiped once read. *L1: the label; L3: the fake's log and argv hold no password; L4: the
  sentinel check on every result.*

### Several sign-in providers
- **SR-84** The provider list fails closed. A list that does not check (a duplicate or bad name, an
  unknown key or source, two Bitwarden sources, caps without a pin, a site that is not an `https`
  origin, a `signInSaveTo` that cannot create) makes every call `provider-failed`, and install refuses
  to write one. A sign-in asks the allowed providers in config order. Only `none`, `locked`, `busy`
  and `provider-failed` fall through; `refused`, `ask-first`, `wall` and `ambiguous` stop the chain,
  so no second vault overrules an owner's no. Matches are never merged across vaults. A sign-up saves
  to exactly one provider that declared `create`, and one that fails is the answer. The agent's
  `vault` names a provider, never a secret, and an unknown one is `provider-failed`. *L1: every status
  pair, the budget, the save target; L3: the chain over two fixture vaults (`tests/signin_chain.rs`).*
- **SR-85** A command provider that declares caps must be pinned. Its program, and any argument that
  is a file it runs, is held open and hashed before every run, then started from the held file. A
  file that is missing or changed answers `provider-failed` and starts nothing. A sign-up's password
  goes only to a pinned provider, on stdin. `phantab vaults status` shows each pin's state, never a
  path. *L1: the pin's parse; L3: a changed and a missing program over the fixture.*
- **SR-86** Account keys are namespaced per provider. A key from any provider but the bare one (the
  `default` entry, else the Bitwarden source) is returned as `<name>:<key>`, and a held key goes back
  only to the provider that issued it. A bare provider's key that reads as another provider's
  namespaced key is `provider-failed`. *L1: key routing; L3: a held key never reaches another vault.*
- **SR-87** Protocol v2 is negotiated by the config, never by the provider. A provider with no caps is
  sent v1 sign-ins only, byte for byte as before. One with caps is sent `"v":2` and only the
  operations its caps allow. A v2 answer with a key the protocol does not name is `provider-failed`,
  whether the key is outside the seal, inside it, among the values or on a plain answer. Sealed
  answers are bound to the SHA-256 of the exact request bytes. *L1: the strict reader; L3: the
  conformance kit (`tests/provider_conformance.rs`), with its canary leak test.*

### Installer
- **SR-48** The binary that the service, MCP server and native host run from sits in a folder that
  only the owner (and SYSTEM/administrators) can write, checked like SR-10 at install and at service
  start. The native host manifest `path` is that binary, absolute. *L1.*
- **SR-49** Quiet debugging adds or removes only `--silent-debugger-extension-api`, and only where
  the configured Chrome starts: HKCU Run values whose command starts with the quoted configured Chrome
  path, and on Windows this user's own `.lnk` shortcuts that target that path (on, only those on the
  configured user-data dir); on macOS only the `dev.phantab.chrome` LaunchAgent, never a plist without
  that label. phantab never changes another account's Chrome: all users' shortcuts (the `ProgramData`
  Start menu, the Public Desktop) are only reported, as are `OneDrive` Desktop shortcuts, whose change
  would sync to the owner's other PCs. Uninstall takes the flag off before any other write and forgets
  the answer only once that succeeded.
  It is on only by the owner's answer at an install terminal (the question states the trade-off: every
  debugger extension then attaches silently) or explicit `install --quiet-debugging on`; an install
  with neither changes nothing. `off`, and uninstall, take it away again. Restarting Chrome to pick the
  flag up is the owner's: `phantab chrome restart-quiet` runs only at a terminal on a typed y (no
  `--yes`, no MCP tool, no automatic restart), refuses while agent pages are open, and quits only the
  browser process on the configured user-data dir, by pid (the Restart Manager's shutdown on Windows,
  `SIGTERM` on macOS, after reading the pid's arguments again), never by image name and never forced.
  The restart keeps the switches the browser ran with. *L1: round-trips on a scratch Run key, a scratch
  shortcut folder (install's `--shortcut-dir` too) and a scratch LaunchAgents dir, other values,
  shortcuts and plists untouched; shared and synced shortcuts reported and never written; the CLI
  refusals; L5: the quit of the lane's own Chrome only.*
- **SR-50** Client configs are written atomically with the expected-bytes check, keep their original
  mode and owner (macOS) or explicit DACL (Windows), refuse when unrelated config would change, and
  uninstall keeps later edits. *L1: a `0600` config stays `0600`; concurrent edit refused.*
- **SR-51** The extension folder is replaced whole: written to a new folder, then swapped in, so no
  stale file stays. The copy takes plain files and folders only: a symlink or junction in the source
  is refused, never followed, so nothing from outside it is copied in. The first refusal is
  `extension_files::read` in `prepare` (SR-74); the copy only sees the staged files it read, and
  refuses a link as a second check. *L1: a stale file in the old
  folder is gone after install; a link in the source is refused and the installed folder kept.*
- **SR-52** Install refuses `%`, `"`, CR and LF in paths, validates profile and Chrome paths, requires
  the provider command to be a JSON array of strings, and writes no NaN. *L1.*
- **SR-53** `doctor` checks the native host registration, its manifest (`allowed_origins` exactly the
  phantab ID, `path` the installed binary), the installed binary's SHA-256 against the install
  record, the installed extension's files against their record (SR-74) and that `config.json`'s
  `installedSource` names the installed binary, and reports any drift. Install reads the running
  binary once and both hashes and copies those bytes, so the recorded SHA-256 is the installed file's
  even if the source changes meanwhile. *L1, L3; L1: the copy is the bytes read, not the source as it
  is at copy time.*
- **SR-74** Install records the SHA-256 of every file of the extension it installs in
  `<runtime>/extension-files.json`, read from the source before its first write. It writes exactly
  the bytes it hashed, through a stage folder swapped in whole, so the installed folder holds nothing
  the record does not name (each file's bytes are written by install itself, never with `fs::copy` or
  `CopyFileEx`, which carry a file's named NTFS streams along); then it checks the folder against the record, and only then sets
  `extensionFilesRecorded: true` in `config.json`, so a failed install never leaves the marker
  without a record. The record is its own file, not the install record, so the service never reads
  the client config contents that record holds. Every file is recorded, because Chrome serves any
  file in an unpacked extension's folder as a page with the extension's permissions: a typed or
  command-line `chrome-extension://<id>/x.html` is not limited by `web_accessible_resources`. Not
  recorded, because the OS rewrites them on its own: regular files named exactly `.DS_Store` or
  `Icon\r` (Finder) or `desktop.ini` or `Thumbs.db` (Explorer, any case), which are neither copied
  nor compared. That is safe only because what Chrome runs is recorded: `manifest.json` and the code
  it names are, so a skipped file loads as code only if a recorded file changes to name it; none of
  their names has an extension Chrome serves as a page (a named stream on one, `desktop.ini:x.html`,
  which a URL can name, is refused like any other, below): Chrome picks a `chrome-extension://` file's type with
  `net::GetWellKnownMimeTypeFromFile` (`AddMimeTypeHeaders` in `extension_protocols.cc`, built-in
  tables only, never the OS registry), falls back to `application/octet-stream`, and never sniffs
  that scheme (`net::ShouldSniffMimeType` sniffs only http(s), file and filesystem). Chrome's `_metadata` is not skipped: Chrome writes it into
  an unpacked folder only for a manifest's declarativeNetRequest rulesets, and this manifest has none.
  Install refuses, before writing anything, a link (a Windows junction too) or other non-regular file,
  a file over 8 MiB or 64 MiB in all, a tree over 32 folders deep or 4096 entries, a name a record
  cannot hold on both Windows and macOS (`\`, `:`, a character Windows refuses, a trailing dot or
  space, a device name such as `CON`, `CONIN$`, `COM1`, `COM¹` or `CON .js`), and two names that are
  one file where case and Unicode normalization are ignored (`a.js` and `A.js`, NFC and NFD, `Σ`, `σ`
  and `ς`, `ſ` and `s`, `ẞ`, `ß` and `ss`: each character is folded on its own, upper case then lower,
  in NFC, and again until the path stops changing, since `ẞ` lowers to `ß`, which only a second fold
  takes to `ss` as APFS folds both; that is stricter than NTFS for a few pairs and so can only refuse
  a source), so every record it writes reads back. The source's own named NTFS streams (a download's `Zone.Identifier`)
  are not read: install never copies them. Each file, and the record, is opened without following a link and checked as
  opened (`O_NOFOLLOW | O_NONBLOCK` then `fstat` on Unix, so a FIFO swapped in is never waited on;
  `FILE_FLAG_OPEN_REPARSE_POINT` then the handle's metadata on Windows; on macOS `O_NOFOLLOW_ANY`
  in place of `O_NOFOLLOW`, which macOS 15 refuses alongside it, so a link at the end or a folder on
  the path swapped for a link into a stalling mount is refused too).
  The extension folder itself must not be a link (a symlink, a junction): install refuses one and the
  check names it `.`, on every OS. On Windows the folder's path is taken from its own handle
  (`GetFinalPathNameByHandleW`, the `\\?\` form, so no path below it is cut at `MAX_PATH`; on a volume
  the Mount Manager gives no drive name, such as a RAM disk, the NT form under `\\?\GLOBALROOT`, which
  every handle there gives too, so a source on such a volume installs; a runtime there is still
  refused, by the check for its file system (below), and at bridge connect, which finds the installed
  folder with `std::fs::canonicalize`, and that fails on such a volume). Before each
  read and stream list, no folder or file below it on the way may be a link or junction
  (`symlink_metadata`; another reparse point names no other place and passes this look, and in the
  installed folder is refused for its provider, below), and after the open the path its handle is at must be the one the walk named, so a
  folder on the path swapped for a link or junction is refused there too, as `O_NOFOLLOW_ANY` refuses
  one on macOS (one swapped in between the look and the open is followed by that open first, R1).
  A recorded file with a second name (a hard link, which can be outside the folder) is refused on
  every OS as one that "has other hard links", not as changed, by the count its open handle gives
  (`st_nlink`, `nNumberOfLinks`): install writes each file new, so it has one; a source's hard links
  are not looked at, as install copies only their bytes. Nor may any file or folder in the installed
  folder, the folder itself included, be one whose bytes or entries a provider serves: on Windows a
  reparse point that is not a link, whatever its tag ("is a cloud placeholder" for a Cloud Files tag,
  "is a reparse point" for any other: ProjFS, WCI, dedup and the rest), and on macOS one with
  `SF_DATALESS` in its `st_flags` (a File Provider's placeholder, "is a cloud placeholder"). A
  same-user Cloud Files provider needs no admin (`CfRegisterSyncRoot`), and it or a ProjFS one could
  serve the check the recorded bytes and Chrome others, or hold a check for as long as it likes. So
  each is named from the walk's listing (its attributes on Windows, then the tag from a handle opened
  as the entry itself; `lstat` on macOS) before anything reads or walks it, so its provider is never
  asked, and confirmed on every handle the check opens
  (`GetFileInformationByHandleEx(FileAttributeTagInfo)` in phantab-window, SR-58); the check reads
  the handle it opened as the file itself, never one opened again through the filter, so a tag made
  after that look still asks no filter for the bytes. For the whole check its thread's placeholder
  handling is pinned and then put back (phantab-window, SR-58): on Windows
  `RtlSetThreadPlaceholderCompatibilityMode(PHCM_EXPOSE_PLACEHOLDERS)`, looked up in ntdll when first
  needed (Windows 10 1709 has it; on an older Windows this import no longer stops phantab starting,
  and the check refuses the folder saying why), so Windows, which may disguise a placeholder as a
  plain file for some programs, never does for the check. That only exposes placeholders: one is still
  fetched when opened normally, which is why the check opens each file and folder as itself and
  refuses a placeholder before it reads a byte. On macOS
  `setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD,
  IOPOL_MATERIALIZE_DATALESS_FILES_OFF)`, so no open or read the check makes asks a File Provider to
  fetch a file or folder. A check that cannot pin it refuses the folder as one it cannot check,
  naming why. Nor, on macOS and Linux, may
  anything there, the folder itself included, be on another file system than the runtime folder
  ("is another file system mounted here"): a same-user macFUSE mount (any user can make one on a
  folder the owner owns once macFUSE is installed, which takes an admin once) over the folder or a
  folder in it sees which process reads it, so it could serve the check the recorded bytes and Chrome
  others. The folder's device (`st_dev`, which the kernel gives from the
  mount, so the mounted file system cannot fake it) must be the runtime folder's, and so must that of
  every entry the walk lists (`lstat`) and every handle the check reads (`fstat`), the record's
  included. A mount over the folder itself is the swap no walk inside it can see, so the folder is
  held to its parent's device, asked of the runtime folder, never of the folder. A mount at or above
  the runtime folder gives it and everything in it one device, so on every OS the runtime folder must
  also be on a file system the check vouches for, read from a handle opened at it as itself, or the
  folder is refused as one the check cannot check before anything in it is read, the error naming the
  file system (and on Windows the device) found and saying to put the runtime on the computer's own
  disk (`PHANTAB_RUNTIME`) and install again; one whose file system cannot be read is refused the same
  way, saying so. On macOS only APFS or HFS+ not mounted through FSKit (`fstatfs`'s `f_fstypename`
  `apfs` or `hfs`, with `MNT_EXT_FSKIT` clear in its `f_flags_ext`). The name is the one the kext or
  FSKit module that mounted the file system gives: macFUSE's kext prefixes `macfuse_`, but an FSKit
  module (macOS 15.4 and later) may call itself `apfs`, so an FSKit mount is refused by the flag the
  kernel keeps on every one, whatever it calls itself: `MNTK_FSKIT`, set by `vfs_setfskit`, a private
  kernel export (xnu `config/Private.exports`), so neither a module nor a third-party kext can set or
  clear it, and reported by `vfs_getextflags` as `MNT_EXT_FSKIT` `0x2` in `f_flags_ext` (xnu
  `bsd/sys/mount.h`), which is read in the same `fstatfs` as the name. A network home (`smbfs`,
  `afpfs`, `nfs`, `webdav`), FAT, exFAT and every other one is refused by its name; the default
  runtime, `~/Library/Application Support/phantab`, is on the
  startup disk's APFS Data volume, and HFS+ is only an external disk's. On Linux anything but FUSE
  (`f_type` `FUSE_SUPER_MAGIC`, `fuseblk` included). overlayfs passes, and when the runtime folder is
  on one, a file on another device whose own file system is overlayfs too is not refused as a mount,
  as overlayfs gives a file its layer's device when the layers are on different file systems and
  `xino` is off; a FUSE mount there is still refused. On Windows NTFS or ReFS
  (`GetVolumeInformationByHandleW`) on a partition of a local disk: the handle's NT path
  (`GetFinalPathNameByHandleW(VOLUME_NAME_NT)`) must be on `\Device\HarddiskVolume<n>`. A kernel
  driver names the device, so a user-mode file system cannot: a WinFsp or Dokan volume
  (`\Device\Volume{GUID}`, which may call itself NTFS), a share (`\Device\Mup`), a RAM disk or
  VeraCrypt volume whose driver names its own device (ImDisk's `\Device\ImDisk0`,
  `\Device\VeraCryptVolume<L>`), a shadow copy and anything else is refused; an honest
  `%LOCALAPPDATA%` was NTFS on `\Device\HarddiskVolume5` (`FILE_DEVICE_DISK`) when probed. Taking a
  device or a file system asks a file system mounted there once for its attributes, so a stalling SMB,
  WebDAV or macFUSE mount can hold a check (R1), never pass one. On Windows a mount inside the folder
  is a mount point, a link, and is refused as one. A
  record that is itself a placeholder or on another file system is named as `../extension-files.json`
  with why, not as unreadable, and a recorded file found to be one only on the handle its read opened
  is named with why, not as changed. Install writes plain files in the runtime folder and the runtime folders are
  in no synced folder, so an honest install has none of these; a runtime compressed with
  `compact /exe` (WOF) is refused too. A source may be one (a OneDrive
  folder): install reads it as its filter serves it and writes plain files. A path whose case fold
  has not settled in 8 passes (two settle every character Unicode has today) is refused as a
  collision, before any write. The check stops reading once the files it read pass 64 MiB in all, like install, so it reads
  at most 64 MiB plus the one file of at most 8 MiB that crosses it, and names every recorded file
  past the cap. The profile check (SR-19: at
  bridge connect and again before every agent call that needs the browser) refuses the bridge with a
  final error, so with no retry, when a recorded file differs, is gone, has a second name or is no
  longer a regular file of at most 8 MiB, when a file or folder there is a placeholder or on another
  file system, when the folder holds anything else but those OS files (a file, a link, a FIFO, a
  name a record cannot hold, and on Windows a named NTFS stream on any file or folder there, the
  folder itself and the skipped OS files included: Chrome serves
  `chrome-extension://<id>/background.js:x.html` or `desktop.ini:x.html` from the stream, and no
  folder listing shows one; each list is read from the handle the read confirmed, with
  `GetFileInformationByHandleEx(FileStreamInfo)` in phantab-window (SR-58), and only a file system
  that has no named streams (FAT, exFAT) skips it),
  when the record is not one install writes or is over 1 MiB, or when the record is missing but `config.json` says install wrote one; the error names the paths, recorded
  files first, since a planted name is text its planter chose: each in double quotes, with a `"`
  inside it escaped and every character that shows nothing or changes the text around it escaped by
  Unicode property (general category Cc, Cf, Zl, Zp, Co or Cn, a space other than the ASCII one,
  `Default_Ignorable_Code_Point` or `Bidi_Control`: the controls, the bidi marks, the tag characters
  an LLM reads as text, U+2028, U+180E, the fillers), and so is every character a person could read
  as a quote or as the cut (every `Quotation_Mark` but the ASCII `'`, the primes drawn as `"`, `…`,
  and U+2800, a blank Braille cell) and a combining mark at the start of a name or after an escape;
  a Windows drive or UNC path is shown without its `\\?\` prefix (`\\?\C:\` as `C:\`, `\\?\UNC\` as
  `\\`) and a device path (`\\?\GLOBALROOT\...`, `\\?\Volume{...}\`) whole, each cut to 120 characters
  around a `…`, at most ten, then how many more; it says to
  run `phantab install` again from the release's extension, then reload the extension. `doctor`
  reports the same. A reinstall from the installed folder itself (no `--extension-dir`) refuses a
  changed folder or a deleted record rather than recording it. *L1: doctor names a changed file, an
  added one and a deleted record, the bridge and the engine refuse them before any retry, a
  same-folder reinstall refuses them, a record install would not write is refused, only the OS files
  are not recorded, a FIFO and a junction are refused without being followed or waited on, a named
  stream on any file or folder, a skipped OS file's included, is refused, a folder that is itself a
  link and a link on a file's path are refused (on Windows both before and after the open), a
  recorded file with a second name is refused on every OS as having other hard links, a reparse tag
  that is not a link on a recorded file, a folder, a skipped OS file or the folder itself is refused
  on Windows (an app exec link or dedup tag, or on a folder a made-up one, set with no data as any
  user can; a dataless cloud tag would make the cloud filter fail every later open of the file, so the
  Cloud Files, ProjFS and WCI kinds are checked from the tag), a tagged file's strict read and a
  tagged folder's stream list are refused from their own handles and a tagged record is named as
  such (on Windows), `SF_DATALESS` reads as a cloud placeholder on macOS, a file, a folder and the
  folder itself on another device than the runtime folder are refused as another file system mounted
  there on macOS and Linux (with a stand-in device, as a real mount needs macFUSE or a disk image),
  and named as such when only the handle shows it, the device is asked of the runtime folder, not
  the installed folder (a stand-in device for the runtime folder), a runtime folder on a file system
  the check does not vouch for is refused before anything is read with an error naming it (stand-in
  file systems: macFUSE and SMB on macOS, FUSE on Linux, a WinFsp or Dokan volume calling itself NTFS,
  a share and FAT32 on Windows), which file systems each OS vouches for, the temp folder's is one (APFS
  on macOS, NTFS or ReFS on a disk partition on Windows, not FUSE on Linux), on Linux an overlay
  layer's device is not a mount and a FUSE one is, the placeholder call is found in ntdll,
  a recorded file's refusal is named before planted ones, the check's thread has its placeholder
  mode exposed (Windows) and its dataless-file policy off (macOS) while pinned and put back after, a path whose fold does not settle within the cap is refused, a folder past
  `MAX_PATH` named by a plain path is checked, a stream list longer than its first buffer is read
  whole, the NT form is chosen when a volume gives no drive path (the choice; and on a drive that has
  one, that the form opens, reads and compares), the check stops at its cap, a planted name holding a
  newline, a tag character, U+2028 and U+180E is shown quoted and escaped in the bridge, doctor and
  install errors, `shown` escapes the rest (the other controls and invisible characters by property,
  the lookalike quotes, `…`, U+2800, a leading combining mark) and drops a drive or UNC path's `\\?\`
  prefix, the check after the copy refuses a folder that differs, a failed install leaves no marker,
  and a file install cannot record, two names that are one file included, refuses the install with
  nothing written.* phantab status: this detects a swap; it does not prevent one (R1). An install from
  before SR-74 has no record and no `extensionFilesRecorded`: the bridge accepts it and `doctor`
  reports it until install runs again, and a same-folder reinstall then trusts the folder as it is.

### Update and supply chain
- **SR-54** Update writes the new binary beside the old, verifies its size and SHA-256, renames the
  running binary aside on Windows (`phantab.exe.old`, removed at next start), renames the new one in,
  and restarts the service only at zero agent pages. A client whose protocol differs from the
  service's refuses with the drain-and-restart message. Nothing downloads code at runtime. *L1:
  replace logic on temp dirs, Windows rename-aside; L3: old service plus new client.*
  phantab status: there is no update command; `install` is the update. It verifies size and SHA-256 and renames a busy binary aside (removed at the next install, not the next start), and clients refuse another protocol, but nothing restarts the service at zero agent pages and no L3 old-service lane exists.
- **SR-55** `cargo deny check` (advisories, licences, bans, sources) runs before every merge and before
  every release, in `scripts/check.sh`. Advisories: `yanked = "deny"`,
  `unmaintained = "all"`, `unsound = "all"`; vulnerabilities always fail. Each `ignore` entry carries a
  reason and a review date. Only crates.io; no git dependencies; no wildcards. *L1
  (`scripts/check.sh`; `scripts/release.sh`, which refuses to build).*
  phantab status: `deny.toml` is set, and `cargo deny check` passes (cargo-deny 0.20.2). There is no CI, so nothing runs this on a PR by itself, and there is no longer a weekly scheduled advisory re-check: a RUSTSEC entry published after the last change is caught only when someone runs `scripts/check.sh` or `scripts/release.sh`. `release.sh` refuses to build while it fails or cargo-deny is not installed; `check.sh` reports a missing cargo-deny as INCOMPLETE (exit 2), not a pass.
- **SR-56** Releases build with `--locked` and the pinned toolchain. `cargo audit --deny warnings`
  runs before the release build as a second source. The extension's packages install with `npm ci
  --ignore-scripts`, so no package's install script runs (none has one). `npm audit
  --audit-level=high`, dev packages included, fails the release: every package is a dev one, and the
  TypeScript compiler writes the shipped JS. The release workflow names every action it runs by full
  commit, never by a tag that can be moved (`tests/install.rs`,
  `workflows_name_every_action_by_its_commit`). *L1 (`scripts/release.sh`, which refuses to build; also
  `scripts/check.sh`).*
  phantab status: `scripts/release.sh` refuses to build while either audit fails or cargo-audit is not installed, and `scripts/check.sh` runs both (a missing cargo-audit is a skip there, reported INCOMPLETE, exit 2). Both are run by hand; nothing runs them by itself. Both pass (cargo-audit 0.22.2). `release.sh` also refuses build settings from outside the repo (`RUSTFLAGS`, `CARGO_PROFILE_RELEASE_*`, a `[build]` or `[profile]` in a cargo config) and records `rustc -vV` and the linker's version in its build-info.
- **SR-57** The shipped extension holds only first-party compiled code and the manifest: no
  third-party runtime package. *L1: `dist/` file list and import check.*
- **SR-58** `unsafe` appears only in `phantab-window`'s OS modules, each block with `// SAFETY:`;
  every other crate root has `#![forbid(unsafe_code)]`. *L1 (`scripts/check.sh`): a check that fails
  on `unsafe` elsewhere.*
  On Windows the binary's first act is `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`, so a
  DLL loaded later by name (by Windows or a crate) comes from System32, never from the binary's folder
  or the working folder. It cannot reach the DLLs in the import table, loaded before `main`: of those,
  `USERENV`, `ktmw32`, `crypt32` and `bcryptprimitives` are not KnownDLLs and are found in the
  binary's folder first. Run from the installed copy, that folder is the owner-only `bin` (SR-10), so
  only the user's own processes could plant one there. Still exposed: `phantab install` run from the
  folder it was downloaded or extracted to (a `Downloads` folder holding a planted `crypt32.dll`, or a
  temporary extract folder), where a planted copy of one of those four loads first. Their own imports
  are not exposed on Windows 11: the static ones are KnownDLLs, `ntdll` and API sets, and the rest
  (`crypt32`'s `MSASN1`, `CRYPTSP` and `profapi`) are delay-loaded, so they load at first use, after
  the call, from System32. A Windows build that moved one of those into an import table would expose
  it too. The link-time fix, `/DEPENDENTLOADFLAG`, needs a load configuration directory, which the GNU
  toolchain's `ld` does not emit. *L1: the call is accepted and the process still starts programs
  after it (Windows has no call that reads the setting back).*
- **SR-59** Release builds use `panic = "abort"`. They leave overflow checks off: with the abort, an
  overflow in arithmetic a page can reach would end the service (see `Cargo.toml`); such sums saturate
  instead. No `catch_unwind` keeps the service running after a
  panic. The panic hook prints the location only, never the payload. The service turns core dumps off
  at start on macOS (`RLIMIT_CORE = 0`), and so does `phantab bitwarden` before it reads the master
  password or the session key; the `bw` children inherit the limit. *L1: hook output for a payload
  sentinel; L1: release profile; L3: the fake `bw` reports the core limit it inherited from
  `phantab bitwarden status` started under a raised one.*
- **SR-73** A binary built with the `test-seams` feature (every `cargo test` build, through the self
  dev-dependency) refuses `phantab install` and says why; uninstall still runs. `scripts/check.sh`
  fails when the release build's features (`cargo tree`, no dev-dependencies) include `test-seams`,
  and `scripts/release.sh` refuses a binary holding the refusal's words, which only that feature
  compiles in. *L1 (`tests/install.rs`: a test build refuses, holds the words, and release.sh gates on
  them; `scripts/check.sh`; `scripts/release.sh`).*

## Residual risks

These remain after every requirement holds. The README must say them in plain words.

- **R1 Same-user programs.** A program running as the owner can read service memory, the endpoint
  file, client configs and the start environment; rewrite HKCU registrations, the Run key and client
  configs; and forge a parent process. phantab detects drift (SR-53) but cannot stop it.
  The installed extension's record (SR-74) is detection only. Such a program can rewrite the record
  with the files, or the binary that checks them; can delete the record and drop
  `extensionFilesRecorded` from `config.json`, which the service reads at start, then restart the
  service; can swap a file, let Chrome load it, and put it back before the next check; and a swapped
  extension acts in the browser without the bridge at all, so the refusal stops phantab's agents from
  using it, not the code itself. It makes a careless swap visible: a swap that edits or adds to the
  extension's files (a planted page opened as `chrome-extension://<id>/x.html` included, or on Windows
  one in a named stream on any file or folder there, `chrome-extension://<id>/background.js:x.html`
  or `desktop.ini:x.html`), or also deletes the record, is refused. A skipped OS file itself
  (`desktop.ini`, `.DS_Store`, no page extension) is never a page:
  Chrome types it with `net::GetWellKnownMimeTypeFromFile` as `application/octet-stream` and
  `net::ShouldSniffMimeType` never sniffs `chrome-extension://` (Chromium's source, not a live test).
  That Chrome serves a stream page was read from its source (`ExtensionURLToRelativeFilePath` has no
  `:` check; `base::NormalizeFilePath` keeps the stream name), not tried live; the check refuses a
  stream on any file or folder there either way. On Windows a folder on a file's path swapped for a
  link between the check's look at each folder and its open is followed by that one open before the
  handle's path refuses it, so a link into a stalling share can hold one check for as long as the
  share stalls (macOS's `O_NOFOLLOW_ANY` fails the open itself); the next walk names the link. A
  placeholder (a Cloud Files, ProjFS or File Provider one, whose provider could serve the check one set
  of bytes and Chrome another, or stall the check) is refused before it is read, so it can only do
  what any swap can: be made between two checks and undone before the next (on macOS one made between
  the walk's `lstat` and the open is refused, or fails its read, without its provider being asked, as
  the check's thread never fetches a dataless file). A file system mounted over the folder or a folder
  in it on macOS or Linux is refused too, and so, on every OS, is a runtime folder on any file system
  but a local disk's (APFS or HFS+ not mounted through FSKit on macOS, NTFS or ReFS on a disk
  partition on Windows, anything but FUSE on Linux), but taking a device or file system asks it once
  for its attributes, so a stalling one can hold one check, never pass one. On macOS a disk image
  formatted APFS or HFS+, which a user attaches without an admin (`hdiutil attach`, a `ram://` RAM
  disk or a VeraCrypt volume too), passes as the whole runtime folder: probed on a Mac, one
  attached as the runtime folder read intact (`apfs, local, nodev, nosuid, noowners, nobrowse`), and
  one attached over the extension folder was refused as another file system mounted here. That is
  accepted: the kernel's own APFS or HFS+ serves the image, one view of it to every reader, so Chrome
  reads the bytes the check hashed, unlike FUSE or FSKit, whose user-space server can answer each
  reader differently; it is this residual's ordinary swap, made by attaching rather than writing. On
  Windows attaching a VHD takes an admin, so the macOS side lets through nothing more than a same-user
  write could. On Linux an overlayfs whose layer is itself on FUSE passes,
  as the overlay is what the runtime folder shows; that takes a mount namespace Chrome must run in
  too. The rule refuses some honest setups as well: a runtime on a network home or a redirected
  `%LOCALAPPDATA%` on a share, FAT or exFAT; on Windows a RAM disk or VeraCrypt volume whose driver
  names its own device (both pass on macOS when formatted APFS or HFS+); on macOS an external HFS+
  disk, should a later macOS mount HFS+ through FSKit; and on Linux one on a FUSE home (a `sshfs` or
  `gocryptfs` one); each is told to move the runtime with `PHANTAB_RUNTIME`. A source's placeholder
  can stall an install's read. A hard link to a recorded file made and removed between
  two checks is not seen.
  The link to the extension is in the same class. The service takes as the extension whichever peer
  holds the token and opens `/bridge` while no link is live, and sends it every operation, a
  sign-in's values included (R5). Only a program running as the owner can read the token, and such a
  program can already read the service's memory, so this adds no boundary; it is named here because
  the profile check (SR-19) and the file record (SR-74) say what is installed, not who is on the
  link (security audit, 2026-11).
- **R2 Prompt injection inside the agent's own pages.** A page can steer an agent that already holds
  a page on a signed-in site. phantab bounds the damage (own pages only, origin lease, no replay,
  HTTPS-only sign-in, pay refused, no password reads) but cannot tell a real instruction from page
  text. The agent's own judgement and the owner's handoff remain the defence.
- **R3 Agent-asserted consent.** `ownerConfirmed` on `adopt` and on shared-tab `resume` is set by the
  agent. An injected agent can claim it. Changing it needs a new owner gesture and a new MCP surface,
  which would break existing clients, so it is not planned for now.
- **R4 Client id is not authentication.** Every client holding the token can claim any client id.
  Session ids are hard to guess but not secret. Ownership separates honest sessions, not hostile ones.
- **R5 Credentials in plain bytes on the way to the page.** Values cross native messaging and the
  loopback socket inside the bridge, and live as JS strings in the extension and the renderer, which
  cannot be zeroized. In the service, the call's serialized JSON (serde_json, the bridge frame's
  `Bytes`, the CDP socket's buffers) is not zeroized either (SR-47). A site's own scripts can read
  their own field.
- **R6 Shared-domain logins.** A login saved for a shared domain matches pages under it, if the
  manager matches that way. The built-in Bitwarden source does, by default (SR-67,
  a deliberate choice): a login saved for `site.test` fills every subdomain of it, including a
  subdomain someone else has taken over (a dangling DNS record) and a host serving other people's
  content whose shared suffix is not on the Public Suffix List. Saving the entry as host (1) limits
  it to one host. See T74.
- **R7 Other extensions.** An extension with debugger or all-sites access can do anything phantab can
  in the profile. Quiet debugging hides its debugger use too (SR-49). An extension drawing into an
  open shadow root is read as page content.
- **R8 Third-party frames and field values are read.** Snapshots read website frames, a payment frame included, and so do selector actions, which find their element in the main document first, then in each website frame. Displayed text is read, and so is whether a box or radio is ticked and which option a select shows. With `guardrails: parity` (the default), a snapshot also shows what each text field and editable area holds (`value=`, cut at 200 characters), so whatever a page or the owner typed there reaches the agent. It never shows a password field's value, nor any field whose name, id or `autocomplete` reads as a password, card number or one-time code, nor any field of a form that holds a new password, a card field, a code field or two password fields, in any mode. No value is shown while a sign-in's echo is marked (SR-45), while a sign-up's new password is on the page (SR-82), nor while a sign-in is under way on it. With `guardrails: light` or `full`, no value is read. *L1: `page_written_fields_are_cut`; L3: `framed_forms_are_filled_by_selector_and_show_their_values_at_parity`, `with_guardrails_on_no_value_is_shown_and_framed_controls_are_checked`.*
- **R9 Viewer fragment.** The viewer token sits in the `/view` URL fragment until the page strips it. An extension with access to that tab can read it first.
- **R10 Provider parent check.** A provider that checks its parent process must expect
  `phantab serve`; one written for another parent fails closed, and sign-in answers `refused`.
- **R11 Windows crash reporting.** If an administrator turned on WER LocalDumps, a crash dump of the
  service, or of `phantab bitwarden connect`, can hold a token or a credential (the master password
  during `connect`).
- **R12 Machine load.** A busy machine stalls hidden pages and can turn calls into timeouts. Timeouts say an action may have landed; they cannot say whether it did.
- **R13 The isolated-headless Chrome's debugging port. Fixed 2026-11-05.** phantab's launch until then started that Chrome with `--remote-debugging-port=0`. That port
  has no authentication, so any local process, another user's included, that found it could drive the
  page and read what was typed into it during a live-view takeover (security review, 2026-11-04). Now
  `Browser::launch` starts it with `--remote-debugging-pipe` and speaks CDP over two anonymous pipes
  (JSON plus a NUL byte, each way). No port is opened and no `DevToolsActivePort` is written. L2
  (`a_launched_browser_opens_no_devtools_port`) checks the OS socket table for the Chrome pid. On
  Windows the pipe handles are inherited, and their values are passed with
  `--remote-debugging-io-pipes=<read>,<write>`. On macOS a `/bin/sh` `exec` puts them on fds 3 and 4.
  On Windows, any process the service starts while the two handles are inheritable inherits them too;
  one that outlived Chrome would hold its pipe open, so a crash would go unseen until it exited. Every
  spawn in the service at runtime (a launch, a sign-in provider, the owner's Chrome when a closed
  profile is opened) holds `phantab_cdp::spawn_guard`, so none lands in that moment (review of R13,
  2026-11-05; the owner's Chrome was added by the audit of 2026-11-13, with
  `the_owners_chrome_is_started_under_the_spawn_guard`). The shared Chrome was
  never affected, since it is reached through the extension. A port is still used where a caller asks
  for one: `connect`, and lanes 4 and 6, which start their own test Chrome.
- **R14 Local denial of service on the loopback service.** The HTTP service caps bodies, and a
  connection's headers must arrive within 30 s (`service::HEADER_READ_TIMEOUT`, set on both listeners;
  it is also hyper's default once a timer is set, checked against hyper 1.12, 2026-11-05). On a connection that has carried a valid `/rpc` token, a request's headers
  may take up to 120 s to arrive instead (`service::KEPT_IDLE`), so a client can keep it idle between
  calls; every other connection keeps 30 s, the remote view's always (it never carries the token).
  *L1: `only_a_valid_token_earns_the_kept_wait` runs the real server in paused time, and
  `a_kept_connection_still_checks_every_request` shows that on a kept connection a missing or wrong
  token is still refused and a stalled body is still cut at 10 s.* A body the
  service reads must arrive within 10 s, and `/viewer` reads none for a key that views no handoff on
  the listener it came in on. Both hold on the local listener and on the remote view's (L3,
  2026-11-05). The number of connections is not capped, and a viewer token's `frame`
  requests are not rate-limited. A cap would hand the same local process a way to lock real clients
  out. A local process can tie the service up; it gains no access.
- **R15 A runtime folder that was open before phantab restricted it.** Narrowed 2026-11-05 to folders
  that already existed. A runtime folder, or its `bin`, that phantab creates (install, service start, or
  the client starting the service) is owner-only from the create call on: Windows `CreateDirectoryW`
  gets the protected DACL of SR-10, so nothing is inherited; macOS `mkdir` gets mode `0700`. No other
  account ever had a way in, so nothing can be planted and no handle opened. Still open: a folder that
  already existed when `install --runtime <dir>` names it, under a folder other accounts can write to,
  is restricted afterwards. phantab then walks it and refuses any entry another account owns, any
  link, and (macOS) any file with a second name, a hard link another account may make even to this
  user's own files, so a planted file such as a `config.json` naming a sign-in provider is refused; but a handle
  another account opened while it was open keeps its access, and no restrict can take that back. The
  parent folders phantab creates on the way get what they inherit; they hold nothing of phantab's
  (security review, 2026-11-04). The default runtime, under the user's own profile, is not affected.
- **R16 Same-user reads of the Bitwarden session.** DPAPI user scope opens for any program running as
  the owner, and such a program can run `bw` with the key and phantab's data folder: the whole vault,
  until `disconnect` or `bw lock`. On macOS the Keychain asks before a program other than the one that
  stored the item reads it. The pin (SR-64) does not change this: a program that can open the store
  can write a record pinned to its own `bw`. On Windows the pin is therefore no boundary against
  same-user code at all: it stops only a swap made through `config.json` or the files alone, and
  `connect`'s confirmation shows the owner which `bw` they pin. Such a program can also answer that
  confirmation itself, by driving a pseudo-terminal (`script` on macOS, a ConPTY on Windows) or sending
  keys to a console; it still needs the master password, which only the owner types. On macOS it
  holds against a swap made before the check, and fully only once phantab is signed with the hardened
  runtime (sec-creds-2(b), open): until then `DYLD_INSERT_LIBRARIES` loads same-user code into phantab
  past any pin. The modules `bw.js` loads (`node_modules`) are never pinned. Part of R1.
- **R17 Vault data in plain memory during a call.** `bw` decrypts the vault in its own (Node) process.
  `bw list items` prints every candidate login for the base domain, passwords included; phantab wipes
  its copy of those bytes and of the parsed JSON, but serde_json's and the OS pipe's intermediate
  buffers are not wiped. phantab hands the session key from its zeroized owner straight to the
  command, with no copy of its own; `std::process::Command`'s copy and the environment block it builds
  are not wiped: in the service, every `bw` call leaves one on the heap until it is reused. Accepted
  (a deliberate choice): Bitwarden's own CLI holds `BW_SESSION` in its environment the same way.
  Phase 2 (`docs/BITWARDEN.md`) would decrypt only the chosen item.
- **R18 The master password in a child's environment.** During `connect`, a same-user process can read
  the `bw unlock` child's environment. phantab passes the password from its zeroized buffer with no
  copy of its own; `std::process::Command`'s copy and the block it builds are not wiped; `connect` is
  a short-lived process. Part of R1.
- **R19 A posted link, while its check is live.** The agent posts a verification link in its chat.
  Anyone who can read that chat and reach the owner's route within the check's life (at most 15
  minutes) can drive that one page through the viewer. The route's identity check (SR-70) closes this
  for anyone not signed in as the owner.
- **R20 Same-user resets of the sign-in guard.** The stops and send limits of SR-46 live in the guard
  file, which the owner's account can write. `sign-in-clear` asks for the host typed back at a
  console, which a plain non-interactive shell cannot do; but a process running as the owner, an
  agent's included, can answer that prompt through a pseudo-terminal or sent keys, or delete or
  rewrite the file, and with it every stop and limit (security review, 2026-11-05). Holding the guard state in the service, with the
  file as its record, is a follow-up. Part of R1.
  The built-in source's ask-first approvals (SR-66) are the same: plain entries in `sign-in-policy.json`, which
  a program running as the owner, an agent with file access included, can write for itself (security
  audit, 2026-11).
- **R21 A same-user swap under a macOS test build.** A test build's Keychain calls use a scratch
  keychain, and the guard (SR-62) is the only thing that keeps them off the owner's: while they are
  logged in their login keychain is unlocked, and securityd then accepts any password, so the scratch
  keychain's own password stops nothing. The guard checks the path, not the file opened; a same-user
  process that swaps the path for a link to the login keychain between the check and the call is not
  stopped, and nothing can pin the file (the open is lazy, and the Security framework rewrites a
  keychain by a temporary file and a rename). It reaches only the test-only service names
  (`dev.phantab.test.*`), never `dev.phantab.bitwarden`, and needs a racer during a test run. Part of
  R1.

## Out of scope

- Administrators, SYSTEM, root, the kernel and physical access.
- Bugs in Chrome itself, including sandbox escapes and `chrome.debugger` permission checks.
- The provider's own vault and its unlock flow. phantab bounds only what it accepts from it. For the
  built-in Bitwarden source: the `bw` program itself, Bitwarden's servers and the vault's encryption.
- The security of the websites the agent visits.
- Network attackers. phantab opens no network listener beyond loopback; page traffic is Chrome's.
  The route the owner puts in front of the remote view (for example Tailscale) is theirs;
  phantab checks what it forwards (SR-70).
- A same-user process killing the service or its windows (denial of service).
- The agent's model and its harness, apart from what crosses the MCP boundary.
