# phantab

phantab lets AI agents use **your own signed-in Chrome**, in windows you never see. An agent opens a
page in a hidden Chrome window of your usual profile, so your logins come with it. When a page needs
you (a check, a passkey, a decision), you take it over, then hand it back.

It is one small native program, `phantab`, plus a Chrome extension. Any MCP client can use it: Claude
Code, Codex, or anything else that speaks the Model Context Protocol over stdio. It runs on Windows and
macOS. It is free and open source under the Apache License 2.0.

## Why use it
- **Your logins just work.** The agent works in your real Chrome profile, through the extension and
  `chrome.debugger`. There is no copied profile, no exported cookies and no remote-debugging port to
  leave open.
- **It stays out of your way.** Agent pages open in hidden windows. You keep using Chrome; nothing
  steals focus. Click the toolbar badge (`PT`) and every tab is taken back from the agents at once.
- **It is light.** A single native binary (the Windows bundle is about 7 MB), no Node, Python or
  PowerShell at runtime. The service runs on two worker threads and starts on the first call.
- **It is cheap to run.** Every byte a tool returns costs your agent tokens, so phantab returns little:
  `browser_snapshot` gives the page as plain lines, not JSON, and on a repeat only what changed;
  `browser_act` runs several actions and the check after them in one call; page ids are shortened and
  unchanged fields left out. phantab never turns on Chrome's network and audit event streams, which are
  most of a heavy page's protocol traffic.
- **It knows when to stop.** Human checks and passkeys are never answered for you: phantab shows you
  the page and waits. Optional guardrails ask for your confirmation before payments, password changes
  and deletions.

## Requirements
- **Google Chrome 125 or later.** The extension is loaded unpacked (Developer mode).
- **Windows 10 version 1709 or later (x64)**, or **macOS on Apple silicon (arm64)**.
- **An MCP client.** The installer writes Claude Code's and Codex's configs; any other stdio MCP client
  can be pointed at the binary (below).
- To build from source: the Rust toolchain named in `rust-toolchain.toml` (rustup installs it on the
  first build), and Node.js 22 or later for the extension.

## Install from a release
Each release on GitHub has a ready bundle with the binary, the built extension and an install script.
No Rust or Node needed, no admin rights; everything stays in your user folder.

1. Download the bundle for your OS from the release page, and check its SHA-256 against the value the
   page lists beside the file.
2. Run the install script from the unpacked folder:
   - Windows (`phantab-windows-x64-bundle.zip`): `powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1`
   - macOS (`phantab-macos-arm64-bundle.zip`): `bash install.sh`

   It checks every file, binds the Chrome profile you used last (`-ChromeProfile` / `--profile` picks
   another), and adds phantab to `~/.claude.json` and to Codex's `~/.codex/config.toml` when that exists.
3. In that Chrome profile, open `chrome://extensions`, turn on **Developer mode**, click **Load
   unpacked** and pick the extension folder the script names (`%LOCALAPPDATA%\phantab\extension` on
   Windows, `~/Library/Application Support/phantab/extension` on macOS).
4. Restart your agent and ask it to *open example.com with phantab and read the title*.

Step-by-step guides, including what to do when a company policy blocks unsigned programs:
`docs/WORK-LAPTOP.md` (Windows) and `docs/INSTALL-MAC.md` (macOS).

## Install from source
```
cargo build --release --locked
cd extension && npm ci --ignore-scripts && npm run build && cd ..
target/release/phantab install --extension-dir extension/dist \
  --claude-config ~/.claude.json --codex-config ~/.codex/config.toml
```
Pass only the configs you have; each must already exist (an empty `{}` is fine for `.claude.json`).
The first install binds a Chrome profile: `--profile "Default"` (the folder name inside Chrome's user
data folder), with `--user-data-dir` and `--chrome` when Chrome is not in its usual place. Install
copies the binary to `<runtime>/bin` and the extension to `<runtime>/extension`; load that folder
unpacked as in step 3 above. On Windows with the GNU toolchain, run `. scripts/dev-env.sh` (Git Bash)
first (`CONTRIBUTING.md`).

Other install flags: `--add-profile` / `--remove-profile` (below), `--runtime <dir>`,
`--server-name <name>` (the MCP entry's name, default `phantab`), `--sign-in-provider <json array>`,
`--quiet-debugging on|off` (Windows), `--extension-dir <dir>` and `--uninstall`. `phantab install --help`
lists them all.

## Connect your agent
The installer adds an entry named `phantab` to the client configs you name, so the tools appear as
`mcp__phantab__browser_open`, `mcp__phantab__browser_snapshot` and so on. Restart the client after an
install.

For any other MCP client, add a stdio server whose command is the installed binary and whose only
argument is `mcp`:
- Windows: `%LOCALAPPDATA%\phantab\bin\phantab.exe mcp`
- macOS: `~/Library/Application Support/phantab/bin/phantab mcp`

Run the installer once first (with a Claude Code config, an empty `{}` file will do), so the Chrome
profile, the extension and the native messaging host are set up. `phantab doctor` says what is set up
and what is not.

The 14 tools: `browser_status`, `browser_connect`, `browser_open`, `browser_pages`, `browser_tabs`,
`browser_attach`, `browser_snapshot`, `browser_act`, `browser_wait`, `browser_show`, `browser_resume`,
`browser_screenshot`, `browser_close` and `browser_sign_in`. Each tool describes itself to the agent.

## Safety
phantab gives an AI agent your signed-in browser. Whatever the agent can be talked into, by you or by
a page it reads, it can do as you, on every site you are signed in to. Read this before you install.

- **Guardrails.** One setting, `guardrails` in `<runtime>/config.json`:
  - `parity` (the default): the agent gets the access you have; your agent's own setup owns the
    guardrails.
  - `light`: phantab asks for your explicit confirmation before a payment or checkout, a password or
    two-factor change, or deleting an account or vault items.
  - `full`: `light`, plus sign-in limits and stops, your handback before the agent resumes a page you
    hold, and your confirmation before an agent recovers another session's page.

  **On a work machine, or anywhere an agent reads untrusted pages, use `full`.** Secrets stay out of
  logs and files in every mode. See `docs/GUARDRAILS.md`, including what the confirmation cannot stop.
- **The extension's permissions.** The bridge extension asks for `debugger` (to drive tabs) and
  `<all_urls>` (to reach every site), plus `tabs`, `nativeMessaging`, `alarms`, `storage` and
  `scripting`. Those are broad on purpose: they are what lets an agent act in any tab. It has no
  content scripts and nothing a web page can message. It is loaded unpacked, so Chrome does not review
  or update it; you install each version yourself.
- **What it protects.** The service listens only on 127.0.0.1, behind a random token; saved logins are
  filled without the agent ever seeing a password; human checks and passkeys are left to you. The full
  model, its open risks included, is `docs/THREAT-MODEL.md`; a security audit and its open findings are
  in `docs/SECURITY-AUDIT-2026-11.md`. Report a vulnerability privately: `SECURITY.md`.

## When a site asks if you're human
The page pops up after a few seconds so you can do the check, and hides itself once it clears. The agent
keeps working meanwhile. With a remote view set up, the agent can also post a link so you can do it from
your phone or another computer (`docs/REMOTE.md`). phantab never does the check for you.

## When a site wants your passkey
A sign-in that meets a passkey request shows you the page at once, and the agent tells you in one line.
Confirm it in the pop-up (Bitwarden, Windows Hello or Touch ID); the page hides itself again once the site has
its answer, and the agent goes on. phantab never answers a passkey request itself.

## Another Chrome profile
Agents use your usual profile unless you allow others. To allow one, run
`phantab install --add-profile Work`, using Chrome's name for the profile or its folder (`Profile 1`).
Repeat `--add-profile` for more. Install puts a copy of the bridge for that profile in
`<runtime>/extension-profiles/<folder>/extension`. In that profile, load the copy once at
chrome://extensions (Developer mode, Load unpacked); install prints the step. The copy works in that
profile only. The usual copy also works in the usual profile only.

An agent then names the profile with `profile` on `browser_open`, `browser_tabs`, `browser_attach` or
`browser_connect`; leaving it out means your usual profile. Pages opened there are hidden, as in your
usual profile, and you can take them over the same way. If the profile has no window open, phantab
starts it in your own Chrome with no window. Under `guardrails: full` it waits for you to open the
profile instead. phantab never copies a profile's cookies and never opens a debugging port.

`phantab install --remove-profile Work` stops allowing that profile and deletes its copy. Remove the
bridge from that profile's chrome://extensions as well: until you do, phantab refuses the bridge in
every profile.

phantab reads the allowed profiles when its service starts. After adding or removing one, restart only
the phantab service, once its pages are drained; never close Chrome. Install says so when the list
changed.

## Saved logins
`browser_sign_in` fills a saved login without the agent seeing it, from the built-in Bitwarden source
(`docs/BITWARDEN.md`) or from a sign-in provider command you configure.

## Documentation
- `docs/ARCHITECTURE.md`: the pieces and how they talk.
- `docs/GUARDRAILS.md`: what each guardrails mode asks for.
- `docs/THREAT-MODEL.md`: assets, attackers, requirements and residual risks.
- `docs/SECURITY-AUDIT-2026-11.md`: a security audit and its open findings.
- `docs/BITWARDEN.md`: the built-in Bitwarden source.
- `docs/REMOTE.md`: doing a human check from another device.
- `docs/WORK-LAPTOP.md`, `docs/INSTALL-MAC.md`: installing from a release bundle.
- `docs/MAC.md`: how phantab behaves on macOS.
- `docs/TESTING.md`, `CONTRIBUTING.md`: building, testing and contributing.
- `CHANGELOG.md`: what changed in each release.

## Licence
Apache License 2.0: `LICENSE`. Parts of the CDP client are ported from Puppeteer (Apache-2.0, Google);
see `NOTICE`.

phantab is an independent project. It is not affiliated with or endorsed by Google, Bitwarden,
Anthropic or OpenAI. Chrome is a trademark of Google LLC.
