# phantab

**A fast, lightweight MCP browser server for AI agents, using your own signed-in Chrome.**

phantab lets AI agents use **your own signed-in Chrome**, in windows you never see. An agent opens a
page in a hidden Chrome window of your usual profile, so your logins come with it. When a page needs
you (a check, a passkey, a decision), you take it over, then hand it back.

It is one small native program, `phantab`, written in Rust, plus a Chrome extension. Any MCP client can
use it: Claude Code, Codex, or anything else that speaks the Model Context Protocol over stdio. Agents
use it to browse, read pages, fill forms, click through web apps and pull data from sites that need a
login. It runs on Windows and macOS. It is free and open source under the Apache License 2.0.

## The idea: user-agent parity
> **Your agent gets the browser you have, and you keep the browser your agent has.**

An agent that works for you should reach what you can reach, the way you reach it: your signed-in
Chrome profiles, the logins in your password manager, your two-step codes. And whatever it is doing,
you can see it, take it over and carry on from where it is. It is parity of access, not of knowledge:
the password manager types the password, and the agent gets back a status word, never the password.

Most browser tools start an agent in a clean browser, signed in to nothing. We measured what that
means for three tasks that start at a sign-in page. Measured on 2026-11-16 with phantab at main
`a511285`, Playwright MCP 0.0.85, Chrome DevTools MCP 1.13.0 and Claude Sonnet 5.5, on a local account
site with a stand-in password manager, five runs of each task per row:

| Tool | What the agent was told about the login | Tasks finished | Time | API cost | Password in the model's context |
|---|---|---|---|---|---|
| phantab | "My login for it is saved in my password manager." | **15 of 15** | **21.2 s** | **$0.026** | **never** |
| Playwright MCP | the same sentence | 0 of 15 | 22.6 s, to stop | $0.036 | never |
| Chrome DevTools MCP | the same sentence | 0 of 15 | 27.6 s, to stop | $0.050 | never |
| Playwright MCP | the email and password, pasted in | 15 of 15 | 31.6 s | $0.070 | in every run |
| Chrome DevTools MCP | the email and password, pasted in | 15 of 15 | 27.4 s | $0.068 | in every run |

Three more results from the same test, at the same versions:
- **A new account.** Asked to make an account and save its password, all three tools got the account
  made, 5 runs of 5. Only phantab saved the password in the password manager (5 of 5), and the model
  was never sent it. With the other two the model made the password up itself, and the only copy off
  the site was in the chat.
- **A browser that is already signed in.** Both other tools can attach to a Chrome you signed in by
  hand, so we ran them that way too. They shopped and filled a cart in every run, as phantab did. When
  the shop asked for the password again before taking an order, or the session had run out, they
  finished 0 of 20 runs; phantab finished 10 of 10.
- **A look-alike page.** Sent to a copy of the sign-in page at another address, the agents holding a
  pasted password typed it in, in 10 of 10 runs. phantab sent nothing in 5 of 5: the login is saved
  under the real site's address, so there was nothing to fill.

`docs/PARITY.md` has the whole idea, the full results and what the test does not show. `bench/parity/`
has the test and the recorded runs, so you can run it yourself.

## What makes it different
- **It is fast.** In the benchmark below, agents finished the same six browser tasks in about half
  the time they took with Chrome DevTools MCP, at well under half the cost.
- **It is light.** A single native binary (the Windows bundle is about 7 MB), no Node, Python or
  PowerShell at runtime. The service runs on two worker threads and starts on the first call.
- **Your logins just work.** The agent works in your real Chrome profile, through the extension and
  `chrome.debugger`, and in any other profile where you load the bridge once. There is no copied
  profile, no exported cookies and no remote-debugging port to leave open.
- **It stays out of your way.** Agent pages open in hidden windows. You keep using Chrome; nothing
  steals focus. Click the toolbar badge (`PT`) and every tab is taken back from the agents at once.
  Chrome's "started debugging this browser" bar can be turned off at install (below).
- **It is cheap to run.** Every byte a tool returns costs your agent tokens, so phantab returns little:
  `browser_snapshot` gives the page as plain lines, not JSON, and on a repeat only what changed;
  `browser_act` runs several actions and the check after them in one call; page ids are shortened and
  unchanged fields left out. phantab never turns on Chrome's network and audit event streams, which are
  most of a heavy page's protocol traffic.
- **It knows when to stop.** Human checks and passkeys are never answered for you: phantab shows you
  the page and waits. Optional guardrails ask for your confirmation before payments, password changes
  and deletions.
- **Passwords stay out of the conversation.** `browser_sign_in` fills a saved login from Bitwarden or
  your own provider command, and the agent never sees the password. `browser_sign_up` makes a new
  account's password, saves it in Bitwarden and types it in, unseen too.

## Benchmark
Measured on 2026-11-14 on a Windows PC: six agent tasks on local test pages (read an article, look up
orders, sign up, sign in, use a single-page app, shop through several pages), each run five times by
Claude Code (`claude -p`, Claude Sonnet 5.5), one run at a time, each in a fresh Chrome. That is 30
runs per tool, and every run succeeded with both tools. The figures add up each task's median.

| Tool | Time for the six tasks | API cost for the six tasks |
|---|---|---|
| phantab (the code released as 0.5.0) | 50.6 s | $0.24 |
| Chrome DevTools MCP | 98.5 s | $0.55 |

That is about 1.95 times faster and 2.29 times cheaper on this set. Most of the difference is fewer
agent turns and fewer tokens per turn: an agent reads a page in one call, and several actions and the
check after them in another. The harness that ran these tasks is not in this repository yet, and
results move with the model and the API's latency on the day, so take them as one measurement.

## How it compares
Several open-source tools give an AI agent a browser. They differ mainly in which browser the agent
gets and what runs on your machine. As of November 2026:

- **Chrome DevTools MCP** (Google) is a Node.js server. By default it starts its own Chrome with a
  separate profile; it can also attach to your running Chrome over remote debugging, which you turn on
  in Chrome and approve when the server connects. It has DevTools features phantab does not, such as
  performance traces and network inspection.
- **Playwright MCP** (Microsoft) is a Node.js server built on Playwright. It starts its own browser by
  default, and with its bridge extension it can use tabs in your browser. It supports Chromium, Firefox
  and WebKit.
- **Browser MCP** and similar extension-based servers drive your own browser through an extension and
  a Node.js server, in your visible tabs.

phantab's own choices: one native binary with no runtime to install, agent pages in **hidden**
windows of your profile so you keep working, no debugging port, compact tool output to keep agent
turns short, and a human takes over for checks and passkeys. If you need a clean throwaway browser,
cross-browser testing or performance profiling, one of the tools above is the better fit.

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

Other install flags: `--all-profiles on|off`, `--add-profile` / `--remove-profile` (below),
`--runtime <dir>`, `--server-name <name>` (the MCP entry's name, default `phantab`),
`--sign-in-provider <json array>`, `--quiet-debugging on|off`, `--extension-dir <dir>` and
`--uninstall`. `phantab install --help` lists them all.

### Chrome's debugging bar
Chrome shows a "started debugging this browser" bar while the bridge drives a tab. Install at a
terminal asks once, **Hide Chrome's debugging bar?** (Enter is yes), and keeps your answer;
`--quiet-debugging on|off` answers it without asking. The trade-off: with the bar hidden, every
extension that uses Chrome's debugger attaches silently, not only phantab's bridge.

Quiet debugging adds Chrome's `--silent-debugger-extension-api` switch to the places your Chrome is
started from, and nothing else:
- **Windows**: Chrome's sign-in entry in your Run key, and your own Chrome shortcuts in the Start menu,
  the taskbar's pinned items and your Desktop (each checked again at every bridge connect). Shortcuts
  shared by every account on the PC (the all-users Start menu, the Public Desktop) and those on a
  OneDrive Desktop, which syncs to your other PCs, are named but never changed: phantab never changes
  another account's Chrome or another PC's shortcuts. A Chrome started from one of those shows the bar.
  A shortcut phantab may not write is named too, and left as it was. `off` takes the switch away again
  and names each shortcut that still has it, with how to take it off.
- **macOS**: a LaunchAgent, `~/Library/LaunchAgents/dev.phantab.chrome.plist`, that opens Chrome with
  the switch at each login, so a yes also means Chrome opens at login. Turn Chrome's own "open at login"
  off, or Chrome opens without it. macOS gives no way to add a switch to the Dock or Finder: a Chrome you
  quit and start again from there has the bar until your next login, or until `phantab chrome
  restart-quiet`.

The switch only counts when Chrome starts, so a Chrome already open keeps the bar. `phantab status`
says so, and `phantab chrome restart-quiet`, run by you in a terminal, closes that Chrome the way a
system restart does (its tabs saved) and opens it again with the switches it had, the quiet switch and
your tabs. It asks first,
acts only on the Chrome phantab is set up for, and refuses while agent pages are open. phantab never
restarts Chrome on its own.

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

The 15 tools: `browser_status`, `browser_connect`, `browser_open`, `browser_pages`, `browser_tabs`,
`browser_attach`, `browser_snapshot`, `browser_act`, `browser_wait`, `browser_show`, `browser_resume`,
`browser_screenshot`, `browser_close`, `browser_sign_in` and `browser_sign_up`. Each tool describes
itself to the agent.

Results can be files. `browser_screenshot` takes a PNG or JPEG of the view, the full page or one
element, at a view size of your choosing (390 wide for a phone), and with `path` saves it there and
answers only the path and size, so an image costs the agent no tokens. `browser_snapshot` with `path`
saves the whole snapshot as JSON. The path must be absolute and its folder must exist; an existing
file is replaced only with `overwrite: true`. When the agent's work is done and you are to finish it
yourself, `browser_show` with `release: true` gives you the tab for good: it stays open as your
ordinary tab and leaves the agent's list.

## Safety
phantab gives an AI agent your signed-in browser. Whatever the agent can be talked into, by you or by
a page it reads, it can do as you, on every site you are signed in to. Read this before you install.

- **Guardrails.** One setting, `guardrails` in `<runtime>/config.json`:
  - `parity` (the default): the agent gets the access you have; your agent's own setup owns the
    guardrails. A snapshot shows what a form's text fields hold, though never a password, nor any
    field of a form that holds a new password, a card field, a code field or two password fields.
  - `light`: phantab asks for your explicit confirmation before a payment or checkout, a password or
    two-factor change, or deleting an account or vault items, and a snapshot shows no field's value.
  - `full`: `light`, plus sign-in limits and stops, your handback before the agent resumes a page you
    hold, and your confirmation before an agent recovers another session's page.

  **On a work machine, or anywhere an agent reads untrusted pages, use `full`.** Secrets stay out of
  logs and files in every mode. See `docs/GUARDRAILS.md`, including what the confirmation cannot stop.
- **Agents share a site.** By default, several agents, and you, can change one site at once
  (`siteLock: shared`). Agents signed in as one user also share what the site keeps per user: on
  ServiceNow, for example, the current update set and application scope, so one agent's switch moves
  the other's work too. Set `siteLock` to `exclusive` for one writer per site (`docs/GUARDRAILS.md`).
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

A check only counts when a person could act on it. Invisible checks (reCAPTCHA scores, hCaptcha and
Turnstile in their invisible modes) sit in zero-size, hidden or offscreen frames on ordinary sign-in
pages; they neither stop a sign-in nor pop the page up. A check you have solved keeps its box on the
page, so once its own response field is filled the sign-in goes on.

## When a site wants your passkey
A sign-in that meets a passkey request shows you the page at once, and the agent tells you in one line.
Confirm it in the pop-up (Bitwarden, Windows Hello or Touch ID); the page hides itself again once the site has
its answer, and the agent goes on. phantab never answers a passkey request itself.

## When an agent makes an account for you
Ask it to, and it fills in the form; phantab makes the password, saves it in your Bitwarden first, then
types it into the page. The agent never sees it, and it presses the site's own button itself. The new
login is named after the site and the day, so you can find it in your vault.

## Another Chrome profile
Agents may use every Chrome profile you have, each only once you load the bridge in it. Install gives
each profile besides your usual one its own copy of the bridge in
`<runtime>/extension-profiles/<folder>/extension`. In each profile you want agents in, load that copy
once at chrome://extensions (Developer mode, Load unpacked); install prints the step for each profile
that has not loaded it yet. A profile where you never load it stays out of reach: phantab does not start
it. The copy works in its own profile only, and the usual copy in the usual profile only. Guest and
System profiles are never included.

To leave a profile out, run `phantab install --remove-profile Barry`, using Chrome's name for the profile
or its folder (`Profile 5`); repeat it for more. Install deletes that profile's copy and keeps it on a
leave-out list, so a later install leaves it out too. `phantab install --add-profile Barry` brings it
back. A profile you make later joins at your next `phantab install`.

To allow only the profiles you name instead, run `phantab install --all-profiles off`: install keeps
the profiles it allows now and adds no new ones, `--add-profile Work` allows one more and
`--remove-profile Work` stops allowing it. `--all-profiles on` goes back to every profile.

An agent then names the profile with `profile` on `browser_open`, `browser_tabs`, `browser_attach` or
`browser_connect`; leaving it out means your usual profile. Pages opened there are hidden, as in your
usual profile, and you can take them over the same way. If the profile has no window open, phantab
starts it in your own Chrome with no window. Under `guardrails: full` it waits for you to open the
profile instead. phantab never copies a profile's cookies and never opens a debugging port.

When phantab stops allowing a profile where you loaded the bridge, remove the bridge from that
profile's chrome://extensions as well: until you do, phantab refuses the bridge in every profile.
Install names the profile when this applies.

phantab reads the allowed profiles when its service starts. After the list changes (a profile added,
left out or newly made), restart only the phantab service, once its pages are drained; never close
Chrome. Install says so when the list changed.

## Saved logins
`browser_sign_in` fills a saved login without the agent seeing it, from the built-in Bitwarden source
(`docs/BITWARDEN.md`) or from a sign-in provider command you configure: any password manager, and several
at once (`docs/VAULTS.md`). `browser_sign_up` makes a new login in Bitwarden, or in a provider that
declares it can, and fills a sign-up form with it (§ When an agent makes an account for you).
`phantab vaults status` shows the providers configured, never a value.

## Questions
**Does the agent get my existing logins?** Yes. It works in your own Chrome profile, so any site you
are signed in to is signed in for the agent too. That is also why the Safety section above matters.

**Does it open a remote-debugging port?** No. The extension drives your tabs with `chrome.debugger`
and talks to the native program over Chrome's native messaging; the phantab service listens only on
127.0.0.1, behind a random token. The full path is in `docs/ARCHITECTURE.md`.

**Will agent windows get in my way?** No. Agent pages open in hidden windows and never take focus. A
page shows itself when it needs you for a check or a passkey, and you can take any page over yourself.

**Which agents and clients does it work with?** Any MCP client over stdio. The installer sets up
Claude Code and Codex; for others, point the client at `phantab mcp` (§ Connect your agent).

**Can I use it for scraping or data extraction?** It reads pages as text an agent can act on, so an
agent can collect data from pages it can reach in your browser, including ones behind your login. Keep
to each site's terms. For large crawls of public pages, a headless crawler is a better tool.

**Does it work with Edge, Brave or Firefox?** It is built and tested for Google Chrome 125 or later.
Other browsers are not supported.

## Documentation
- `docs/PARITY.md`: user-agent parity, the idea phantab is built around, and the benchmark behind it.
- `docs/ARCHITECTURE.md`: the pieces and how they talk.
- `docs/GUARDRAILS.md`: what each guardrails mode asks for.
- `docs/THREAT-MODEL.md`: assets, attackers, requirements and residual risks.
- `docs/SECURITY-AUDIT-2026-11.md`: a security audit and its open findings.
- `docs/VAULTS.md`: sign-in providers, several at once, and writing one.
- `docs/BITWARDEN.md`: the built-in Bitwarden source.
- `docs/REMOTE.md`: doing a human check (a CAPTCHA, for example) from your phone or another computer.
- `docs/WORK-LAPTOP.md`, `docs/INSTALL-MAC.md`: installing from a release bundle.
- `docs/MAC.md`: how phantab behaves on macOS.
- `docs/TESTING.md`, `CONTRIBUTING.md`: building, testing and contributing.
- `CHANGELOG.md`: what changed in each release.

## Licence
Apache License 2.0: `LICENSE`. Parts of the CDP client are ported from Puppeteer (Apache-2.0, Google);
see `NOTICE`.

phantab is an independent project. It is not affiliated with or endorsed by Google, Bitwarden,
Anthropic or OpenAI. Chrome is a trademark of Google LLC.
