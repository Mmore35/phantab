# Security audit, November 2026

Audited: phantab's `main` on 2026-11-13, after v0.3.0. Written for anyone deciding whether to run
phantab, in particular where agents read untrusted pages, or for a team where one person passes the
download to others.

## Verdict

**Use v0.4.0 or later.**

The audit found no critical and no high issue. Nothing found lets a website, or another user of the
machine, read your data, take a password or run code. It found seven issues: one medium that only
matters when the download passes through other hands, and six low. Six are fixed in v0.3.1. The
seventh, finding 4, is fixed in v0.4.0, which redacts a secret a site shows back instead of stopping
(decision 2 below).

Two of the fixes matter most for a shared rollout or for agents that read untrusted pages:

- The install guide now says where to take the download's hash from. Before, it compared the
  download with a hash file that travels with it.
- The sensitive-step check can no longer be switched off by a page. That check only runs with
  `guardrails` set to `light` or `full`, and `full` is what this report recommends where an agent reads untrusted pages.

The v0.3.0 bundle was cut before the fixes and does not have them. v0.3.0 with the default
`guardrails` setting is missing only finding 2, which is low; with `light` or `full` it is also
missing finding 3. Whatever version you install, take the hash from the release page as the corrected
guide says.

Nothing in this audit changed what a website can observe. No fix touches the browser, its user agent,
headers, fingerprint, cookies or timing. No fix changes what an agent can do or how well it does it.

## How the audit was done

1. Read `docs/THREAT-MODEL.md` in full and used it as the map: ten assets, eleven trust boundaries,
   89 threats, 77 requirements (SR-1 to SR-77), 21 residual risks.
2. Checked each requirement against the code and against the test that is said to prove it.
3. Looked for holes the threat model does not name, area by area: the local service, the bridge, the
   extension, the page scripts, sign-in and the password paths, files on disk, install and update,
   the release scripts and workflow, dependencies, `unsafe` code, parsers and limits. Three
   independent reviewers each took one area with no view of the others' conclusions. Every one of
   their findings was then checked in the code before it went into this report.
4. Fixed what could be fixed without changing what an agent can do or what a website sees. Each
   code fix is a small pull request with a test that fails on the old code.
5. Built a security lane into the merge gate, so these properties are proved again on every change.

A pull request is merged only at a commit where both gates printed `RESULT: PASSED`:
`scripts/check.sh` on Windows, and `scripts/check.sh --chrome --real-extension` on macOS.
The gate includes `cargo deny`, `cargo audit` and `npm audit`.

### What the audit did not do

- No fuzzing run. Parsers were read by hand and are covered by the unit tests in the lane.
- No review of third-party dependency source. Dependencies are held by `cargo deny`, `cargo audit`,
  `npm audit`, the lock files and the pinned toolchain.
- Real-Chrome lanes ran on macOS only. The Windows gate does not run them, by the gate's own rule.
  Windows-only code is covered by unit tests and by reading it. The Windows window lane (SR-24,
  SR-25) opens real windows and runs only by hand. It was not run in this audit.
- Not tested under AppLocker, WDAC or a Chrome policy.
- Not every line was read. The macOS Keychain store, the Windows access-list code and the Bitwarden
  pin file were read in outline and through their tests, not line by line.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | Medium when the download passes through other hands, low when you download it yourself | The install guide checked the download against a hash that travels with it | Fixed in the guide, PR 50 |
| 2 | Low | A page could put its own words into a message every agent reads | Fixed, PR 51 |
| 3 | Low | A page could switch off the sensitive-step check with plain markup | Fixed, PR 47 |
| 4 | Low | After a sign-in sees the page echo a secret, your own tab keeps it and an agent can attach to it again | Fixed in 0.4.0 |
| 5 | Low | The threat model said the sign-in limits always apply; they apply only under `guardrails: full` | Docs corrected, PR 50. Decision 1 |
| 6 | Low | The release workflow ran its actions by tag, which can be moved | Fixed, PR 49 |
| 7 | Low | One process start was outside the spawn guard on Windows | Fixed, PR 48 |

### 1. The download was checked against a hash that travels with it (medium for a rollout, fixed)

**What was wrong.** The Windows and Mac guides said: check the zip against the `.sha256` file
beside it. The installer then checks every file against `SHA256SUMS.txt`, which is inside the zip.
Both lists come from the same place as the files they vouch for. They prove the copy is whole. They
do not prove it is the copy that was released.

**What an attacker could do.** Someone who can change the zip on its way to another person, on a shared
drive or a USB stick, can change the hash file beside it too. That person's check then passes on a
changed program, which would run with their signed-in browser.

**How likely.** Low when you download from GitHub yourself, over a protected connection. Higher for
someone who gets the zip from a shared place. The build was unsigned then, so this one
comparison was the only anchor there was.

**Fix.** The guides now say: compare with the `sha256:` value GitHub lists beside each file on the
release page, or with a value the releaser sends you in a message of its own. Never with a file that
came with the zip. The no-script install path now says the same, since it skips the installer's own
check. Code signing would remove the problem at its root. That was open decision 5; from 0.7.0 the
Windows programs and install script are signed, and the comparison stays, because the signature does
not cover the zip or the extension folder.

### 2. A page could put its own words into a message every agent reads (low, fixed)

**What was wrong.** When another extension's frame makes Chrome detach the agent, phantab's message
names that extension. The name was taken from the address of the frame, and a page chooses the address
it frames. A page could put a sentence of its own, at any length, where the extension's name belongs.
That message is shown to every session through `status`. A second string in the same path, the
extension's words for a failed frame scan, was also not cut. SR-32 says page text in a message to an
agent is cut to 300 characters. These two were not.

**What an attacker could do.** Place page-written text in front of other agents, dressed as part of
phantab's own message. It reads nothing and changes nothing by itself. It is a way to try prompt
injection on a session that never opened the page.

**How likely.** Low. It needs a hostile page in an agent's tab, and an agent that takes a status line
as an instruction.

**Fix.** The service names an extension only when the frame's host has the form of an extension ID.
Anything else reads "The other extension". The name and the scan error are cut to 300 characters. The
extension's files do not change. A real extension's frame reads exactly as before.

### 3. A page could switch off the sensitive-step check (low, fixed)

**Where it applies.** Only with `guardrails` set to `light` or `full`. The default, `parity`, never
runs this check.

**What was wrong.** With `light` or `full`, phantab looks at each click and key press and asks for
your yes when the step looks like a payment, a password change or a delete. The script that looks read
the page through names such as `form.querySelector` and `el.closest`. A page can shadow a form's
names with ordinary markup: a form field named `querySelector` is enough. The script then threw an
error, and a check that errors lets the step through. The real-Chrome run showed that only a form's
field names reach the check this way. An image named after one of the document's names does not.

**What an attacker could do.** A hostile page that already had the agent's attention could make a
pay, change-password or delete click go through without the confirmation prompt.

**How likely.** Low. It needs the non-default setting, a hostile page, and an agent already steered
into clicking. `docs/GUARDRAILS.md` already says the check is a prompt and not a wall.

**Fix.** The script now reads every page object through the browser's own built-in methods, which
markup cannot shadow. The other page scripts already worked this way. New requirement SR-77, new
threat T88. Two tests: a unit test that fails on any direct read in the script, and a real-Chrome
test on a page that shadows every name the check uses. The macOS gate caught a fault in the first
version of that test, in the test and not in the fix, and it was corrected before merge.

### 4. After an echo, your own tab keeps the secret (low, fixed in 0.4.0)

**What happens.** Sign-in watches for a site that echoes the password or code back into the page's
text or address. When it sees that, it stops the sign-in. If the tab is one phantab opened, it closes
the tab. If the tab is your own, one the agent attached to, phantab lets go of it and leaves it open,
because closing your tab would be worse.

**What an attacker could do.** The echoed secret is still on that page. An agent that has been
steered by a hostile page could attach to the tab again and read it.

**How likely.** Low. It needs a site that prints a password or code back into the page, which is rare
and is a fault of that site, plus a steered agent, plus a sign-in that ran in a tab of your own.

**The fix.** phantab 0.4.0 changes what an echo does, rather than refusing the attach. The sign-in no
longer stops: it goes on to its outcome and adds `echoed: true` and a short note. From then on phantab
redacts every form of the value from everything the agent receives (snapshots, page text, URLs, tab
titles, act, wait and status results, and errors), for the rest of the service's life, so a fresh
attach to that tab reads it redacted. A screenshot of that tab is refused until it closes, because an
image cannot be redacted. No account is stopped for the echo. This holds in every `guardrails` mode.
What stays open: the live view you watch is not redacted, a value cut by the tab list's length limits
or split across page elements can show in part, a screenshot of another tab the site opens is not
refused, and a service restart drops the redaction.

### 5. The sign-in limits apply only under `full` (low, docs corrected)

**What was wrong.** The threat model stated the limits without a condition: two password sends an
hour and six a day for each account, and an account stops after a rejected result. In the code, and
in `docs/GUARDRAILS.md`, these are on only when `guardrails` is `full`. In `parity`, the default, and
in `light`, phantab does not slow repeated sign-ins at all.

**What an attacker could do.** A steered agent could repeat sign-ins until the site locks the
account. It cannot learn the password by doing so.

**How likely.** Low. The site's own lockout is what stops it.

**Fix.** The threat model now says which mode the limits need. The behaviour is unchanged, because
the default is a deliberate choice. Where an agent reads untrusted pages this report recommends `full`.

### 6. The release workflow ran actions by tag (low, fixed)

**What was wrong.** `.github/workflows/release.yml` named its six actions by major tag, such as
`actions/checkout@v4`. The owner of an action can move a tag.

**What an attacker could do.** Someone who took over one of those action accounts could run their own
code inside the job that builds the files users install.

**How likely.** Low. It matters for any release the workflow builds.

**Fix.** Every action is named by its full commit, with the release in a comment. New threat T89,
SR-56 extended. A test reads every workflow file and fails on any action named by tag or branch.

### 7. One process start was outside the spawn guard (low, fixed)

**What was wrong.** On Windows, starting headless Chrome marks two pipe handles as inheritable for
the instant of the start. The threat model (R13) says every other process phantab starts takes a
guard, so none can be born in that instant and inherit the handles. One start did not take it: the one
that opens a closed profile in your own Chrome.

**What an attacker could do.** Nothing direct. No trust boundary is crossed: your Chrome is your own
process and never reads those handles. The cost was reliability: a headless crash could go unseen.

**How likely.** Needs two starts to land in the same instant.

**Fix.** That start takes the guard too. A test fails if the file ever starts a process without it.

## Smaller notes, left as they are

Each was checked in the code. None is a way in from a website or from another user. Most need a
program already running as you, which is residual risk R1. Where a change is possible it is listed
under Open decisions.

| Note | Why it is left |
|---|---|
| A program running as you, holding the token, can take the extension's place on the link when none is connected, and would then be sent sign-in values. | Same class as R1: such a program can already read the service's memory. Now written into R1. |
| `status` shows every session the last disconnect message and the page count. `tabs` lists your open tabs to any session. Any session can adopt an orphaned page without a confirmation unless `guardrails` is `full`. | By design: sessions separate honest agents, not hostile ones (R4). Decision 9. |
| No limit on how many pages or sessions exist at once. | A cap would limit agents. Decision 8. |
| An external password program is only checked to be an absolute path. On Windows a `.cmd` file would run through `cmd.exe`. | You set that path yourself. Decision 7. |
| `install` does not refuse an older version. | Rolling back is sometimes wanted. Decision 6. |
| Two flags meant for tests, `--run-key` and `--native-host-key`, exist in release builds. | They only move where your own registry entries go. Decision 7. |
| The ask-first approvals for sensitive sites are plain entries in a file you own. An agent with file access can write one. | Same class as R20. Now written there. |
| The release scripts' settings gate does not name every compiler override. | It guards the builder's own machine against its own environment. A follow-up, not a hole. |
| `doctor` reports drift but nothing checks the program's own hash at each start. | A program that can swap the binary can swap the check. R1. |
| The verification-check reader still reads a few page names directly. | A page can only hide its own check, and gains nothing: the site still blocks the agent. |
| Two small scripts run in the page's own world: popups as tabs, and the passkey counter. | A known and documented trade-off: pages expect them in their own world (SR-61, SR-75). This audit changed nothing there. |
| One debugging message may be up to 256 MiB, and a page's event queue has no cap. | A page that floods the browser can slow the service. It gains no access. Decision 8. |
| A Windows runtime folder owned by the Administrators group is accepted. | An administrator can already do anything on the machine. |
| On a domain-joined PC, the stored Bitwarden session key is protected by Windows for your account, and a domain administrator can recover such keys. | True of every program that uses Windows' store. R16. |

## Checked and found sound

Each line names what was tried. The tests are in the security lane (`scripts/security-tests.txt`),
which the merge gate runs.

### A web page reaching the local service

- The service listens on `127.0.0.1` only, on a port the OS picks. It never listens on the network.
- **DNS rebinding.** Every request must carry the exact `Host` of the service. A page that rebinds a
  name to loopback sends its own host name and is refused.
- **Cross-site requests.** Any `Origin` other than the service's own is refused, so a page's `fetch`
  to loopback is refused before the token is even looked at.
- **No token, no access.** `/rpc` and `/bridge` need the bearer token, compared in constant time. The
  token is 32 random bytes, new at each service start.
- `/health` returns the name, version and protocol only. No path, pid or token.
- Bodies are capped at 64 KiB while reading, and slow senders are cut off.

### Another program or user on the machine

- The runtime folder is owner-only, created that way and checked again at every start. On Windows the
  access list is protected, so nothing is inherited. On macOS the mode is `0700`.
- A folder that is a link, or owned by another account, is refused. So is any file inside owned by
  another account.
- The token file is written inside that folder only. Another user cannot read it.
- A client proves the service is the real one before it sends the token, with a nonce the service
  must answer. A program squatting on the port learns nothing.
- One service per runtime folder, held by an OS file lock.
- Other users can connect to the loopback port, as on any machine. Without the token they get refusals.

### The extension and the bridge

- The extension has no content scripts, no `externally_connectable`, and no host a web page can
  message. A page cannot talk to it.
- Chrome starts the native host only for phantab's extension ID. The host also checks the ID itself.
- The bridge needs the token, the right upgrade header, the exact host, and no web origin.
- Both the extension and the service hold the same allow-list of browser debugging commands. A command
  off the list is refused on both sides. Rules on addresses and tabs live in the service.
- A changed file in the installed extension is noticed, and the browser is refused at once (SR-74).
- Framed messages are length-checked before they are read.
- The shipped extension folder holds three first-party files and no third-party package.

### One session reaching another's page

- Every page belongs to the session that opened it. No call returns or changes another session's page.
- A session can take an orphaned page only through `adopt`.
- Only `http` and `https` addresses can be opened by an agent.
- Page text that reaches an agent is cut and returned as data. After PR 51 that holds for the detach
  message too.

### Sign-in and passwords

- No tool returns a password. Values travel sealed from the password source to the service and reach
  the page only as arguments to a typed call, never inside script text.
- Passwords are sent to `https` pages only, at every frame level. Pay, sign-up and new-password forms
  are refused.
- Password values are kept in memory types that wipe themselves and print nothing when logged.
- Logs carry method names, sizes and timing. No page text, no credential. Sign-in refuses to run at
  all when logging is turned above `info`.
- The Bitwarden program is run from a fixed absolute path with a cleared environment. It is never
  looked up on `PATH`, so a planted program is not picked up.
- The master password is read only from a real console, with echo off, and is never stored. Only the
  session key is stored: under Windows' per-user protection, or in the macOS login Keychain opened by
  its path.
- Passkeys are never answered by phantab. It counts the requests and hands the tab to you.

### Verification checks and the remote view

- phantab never solves an "are you human" check. During a check it only reads. No input reaches the
  page except yours. Agent writes are refused until the check ends.
- A page you already held stays with you after a check. `resume` is refused while a check is live.
- The remote view listens on loopback only and serves two paths. It has no `/rpc`, no `/bridge`.
- A link's token works for one page, on that listener only, and dies with its check.

### Install, update and supply chain

- The installer runs as you, needs no admin, and writes only to your profile and `HKCU`.
- An update writes the new program beside the old, checks its size and hash, then swaps it in.
- The extension folder is replaced whole, never patched in place.
- `doctor` checks the registration, the manifest and the extension's files and reports any drift.
- Builds use the lock file and a pinned toolchain. `cargo deny`, `cargo audit` and `npm audit` run in
  the gate.
- A test build cannot be installed as the real thing (SR-73).

### Memory safety and limits

- `unsafe` appears only in the window crate's OS modules, each block with its reason. A static check
  in the gate holds that.
- Release builds abort on a panic.
- Inputs from the network, the bridge and the extension are size-capped before they are parsed.

## Requirement check

Every requirement in `docs/THREAT-MODEL.md` was checked against the code and its named test.

| Requirements | Area | Result |
|---|---|---|
| SR-1 to SR-9 | Service port and HTTP | Met |
| SR-10 to SR-14 | Runtime folder, token file, service start | Met |
| SR-15 to SR-23, SR-76 | Native host, bridge, extension | Met |
| SR-24, SR-25 | Window control | Met in the code. Their real-window test runs only by hand and was not run |
| SR-26 to SR-31, SR-33 to SR-37, SR-60, SR-61 | Ownership and agent safety | Met |
| SR-32 | Page text in messages to agents is cut | Met after PR 51 |
| SR-77 | Sensitive-step check | Met after PR 47 |
| SR-68 to SR-72, SR-75 | Verification hand-off, remote view, passkeys | Met |
| SR-38 to SR-43, SR-47 | Credentials in memory, logs and on the way to the page | Met |
| SR-44 | The password program runs with no shell | Met, except that a `.cmd` path on Windows would run through `cmd.exe` |
| SR-45, SR-46 | Page guards, send limits and stops | Guards met. Limits and stops met under `guardrails: full`, and off by design otherwise. Wording corrected |
| SR-62 to SR-67 | Built-in Bitwarden source | Met. The macOS half was read in outline and through its tests |
| SR-48 to SR-53, SR-74 | Installer | Met |
| SR-54 | Download integrity | Partly met, as the threat model's own status line says. No signature. See finding 1 |
| SR-55 to SR-59, SR-73 | Update and supply chain | Met. SR-56 extended by PR 49 |

## Residual risks

These are open by design and are written up in `docs/THREAT-MODEL.md` § Residual risks. The ones that
matter most:

- **R1. A program running as you can do what you can.** It can read the token, rewrite your
  registrations, swap the extension, or take the extension's place on the link. phantab notices
  careless swaps and cannot stop careful ones. No user-level tool can. This is the same trust you
  already place in every program you run.
- **R2. Prompt injection.** A page can show text that talks an agent into a tool call. phantab bounds
  the damage: own pages only, no password reads, sign-in on `https` only. It cannot tell a real
  instruction from page text. The agent's own rules and your approvals are the defence. No phantab
  test can prove an agent will not be talked into something.
- **R3. Consent is the agent's word.** `ownerConfirmed` is a flag the agent sets. An agent that has
  been steered can set it without asking you.
- **R4. A session id is not a login.** Any client that holds the token can claim to be any session.
  Sessions keep honest agents apart, not hostile ones.
- **R5. Passwords are plain text inside the page.** Once typed, the site's own scripts can read them,
  as with any browser.
- **R14. Local denial of service.** A local program can tie the service up with connections. It gets
  no access.
- **R15. A runtime folder that existed before install, in a place others can write.** The default
  folder, under your own profile, is not affected. Do not point `--runtime` at a shared folder.
- **R16. The stored Bitwarden session key opens for any program running as you.** On a domain-joined
  PC a domain administrator can recover it too.
- **R20. A program running as you can reset the sign-in limits and write its own approvals.** Part
  of R1.

## Open decisions

None of these was changed. Each would alter what an agent can do, costs something, or is a trade-off
the maintainers have not settled. Item 1 is a setting each user chooses; the rest are open maintainer
decisions, and comments on them are welcome in an issue.

1. **Which `guardrails` setting where an agent reads untrusted pages.** Recommended: `full`. The default, `parity`,
   gives the agent every access you have and leaves all approvals to the agent's own setup. `light`
   adds a confirmation before payments, password changes and deletes. `full` adds the sign-in limits
   and stops, your handback before `resume`, and a confirmation before a session takes over another's
   orphaned page. The cost is more prompts. With `light` or `full`, use a build that has PR 47.
2. **After an echo, refuse a new attach to that tab** until you close it or move it to another
   page (finding 4). Settled in 0.4.0 another way: the attach is allowed, and what it reads is
   redacted, with screenshots of the tab refused.
3. **Should the sensitive-step check fail closed?** Today a page the check cannot read lets the step
   through. Refusing instead would be safer and would block some honest clicks on odd pages.
4. **Owner consent that an agent cannot assert (R3).** A real fix needs an owner gesture outside the
   agent's reach, such as a click in the extension. It adds a step for you on every confirmed action
   and changes the tool surface.
5. **Code signing.** The Windows build is unsigned. A policy that forbids unsigned programs must allow
   it by hash, again for each version, and a hash rule for `phantab.exe` says nothing about the
   extension folder beside it. A signing certificate would let such a policy allow the publisher once
   and would close finding 1 at its root. It costs money and a yearly renewal. For a team rollout this is the main practical
   hurdle. A cheaper
   half step: build the extension's hashes into the program, so one allowed hash vouches for both.
   Settled for Windows in 0.7.0: a release's `phantab.exe`, `run-check.exe` and `install.ps1` are
   signed in the release workflow with Azure Artifact Signing, each with a timestamp, and the build
   refuses to go on unless all three carry a valid signature by the expected signer. The workflow
   signs in with a short-lived GitHub identity token, so no key or password is stored, and only the
   job a `v*` tag starts may ask for one (`docs/THREAT-MODEL.md` SR-56). A policy can now allow the
   signer once. What it leaves: the signature covers those three files, not the zip or the extension
   folder, so finding 1's hash comparison stays, and the half step above is not done. The macOS build
   is still unsigned. `docs/INSTALL-WINDOWS.md` § 1 names the signer and says how to check it.
6. **Refuse an older version on install.** It would stop someone talking a user into an old build
   with a known hole. It would also block a wanted rollback unless a flag allows it.
7. **Tighten two user-set paths.** Refuse a `.cmd` or a network path as the password program, and
   leave the two test-only flags out of release builds. Both are small. Both could break a setup
   someone already uses.
8. **Caps.** A limit on pages, on sessions, and a lower limit on one browser message would bound
   memory use. Each could stop a large honest job.
9. **Tighter walls between sessions.** Show the last disconnect message only to the session it
   concerns, and ask for a confirmation before any adoption in every mode. This changes what one
   agent can see of another's work.
10. **Check what the machine's policy allows before installing.** phantab loads an unpacked extension
    that uses the browser's debugging permission, and lets an agent act in your signed-in browser. A
    device policy may forbid that regardless of how sound the tool is. This is advice to users, not a
    change to phantab.

## Notes for an install

- Take the zip's hash from the release page itself, as `docs/INSTALL-WINDOWS.md` now says. That one
  comparison is the anchor of trust for everything the installer checks afterwards.
- In a team: each person compares the hash themselves, and installs for themselves. Nothing is
  shared between users, and no admin right is used.
- Keep the default runtime folder.
- Bind phantab to a Chrome profile that holds only what you want agents to reach. An agent in that
  profile acts as you on every site signed in there.
- Set `guardrails` to `full`.

## How to re-test

```
scripts/security-check.sh            # every hostile-input test this machine can run
scripts/security-check.sh --list     # the list, and whether each test still exists
scripts/check.sh                     # the full merge gate, which runs the lane as one step
```

The lane holds 65 tests. Each feeds phantab a hostile input and needs the refusal. A listed test that
is renamed, deleted, ignored, skipped or failing fails the lane, so a protection cannot quietly lose
its proof. `docs/TESTING.md` § Security lane has the map and says how to add a line.

## Pull requests

| PR | What |
|---|---|
| 47 | Sensitive-step check reads the page through built-in methods (SR-77) |
| 48 | Opening a closed profile in your own Chrome takes the spawn guard (R13) |
| 49 | Release workflow names every action by its commit (SR-56) |
| 50 | The security lane, the corrected install guides and threat model, and this report |
| 51 | Detach messages never name a page-chosen host, and cut names and scan errors (SR-32) |
| 54 | A sign-in that sees the value echoed goes on; the value is redacted from every answer and screenshots of the tab are refused (finding 4) |

PRs 47 to 51 are in v0.3.1 (PR 53); PR 54 is in 0.4.0.
