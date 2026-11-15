# Built-in Bitwarden source

phantab can take saved logins straight from Bitwarden, with no provider program of the owner's in
between. It is optional. A config that does not name it behaves exactly as before: the external
provider command (`install --sign-in-provider`, THREAT-MODEL B7) or `no-provider`. Threat model: `docs/THREAT-MODEL.md` B10, T69 to
T76, SR-62 to SR-67, R16 to R18.

Phase 1 (this document's code) drives the official Bitwarden CLI, `bw`. Phase 2, a native API client,
is a design note only (§ Phase 2).

## Sources

Which provider a call asks, and how several work together, is in `docs/VAULTS.md`; this document is the
Bitwarden source's own part. A sign-in asks one `CredentialSource` (`crates/phantab/src/signin/source.rs`)
for the values of one login:

```rust
#[async_trait]
trait CredentialSource: Send + Sync {
    async fn ask(&self, request: &Request, budget: Duration) -> Answer;
}
```

`Request` is the same `{urls, account, accountKey, want}` the provider gets; `Answer` is the same
`Ok{values, account_key}` or `Not(Outcome)`. So everything around the source is unchanged: the page
guards, the guard file's send limits and stopped hosts, the fill, the leak sweep, and the label set
(SR-40, SR-45, SR-46). Two sources:

| `signInProvider` | Source |
|---|---|
| absent | none: `no-provider` |
| `{"command": [...]}`, or with `"source": "command"` | `CommandSource`: the provider command and its sealed protocol, unchanged |
| `{"source": "bitwarden", "bitwarden": {...}}` | `BitwardenSource` (`crates/phantab/src/signin/bitwarden/`) |
| any other `source`, `"source": "command"` without a command, `bitwarden` with a `command` too, or a `bitwarden` block that does not parse | every call `provider-failed` (fail closed); `phantab bitwarden status` says why |

A config that asks for a source never quietly gets another.

## Config

```json
"signInProvider": {
  "source": "bitwarden",
  "bitwarden": {
    "bw": "C:\\Tools\\bw.exe",
    "dataDir": "C:\\...\\phantab\\bitwarden\\cli",
    "askFirst": ["example.com"],
    "policyFile": "C:\\...\\sign-in-policy.json",
    "syncAfterSeconds": 300,
    "server": "https://vault.bitwarden.eu",
    "proxy": "http://proxy.example:3128"
  }
}
```

| Key | Required | Meaning |
|---|---|---|
| `bw` | yes | The CLI, in one of two shapes: the absolute path of the standalone program, a file named `bw` (`bw.exe` on Windows), in any case, or `["<absolute path of node>", "<absolute path of @bitwarden/cli/build/bw.js>"]`. What to set for each install is in § Installs. Never looked up on `PATH`. On Windows the program must name a `.exe`: for any other name Windows would run a `.exe` beside it. A `.cmd` or `.bat` is refused: it runs through `cmd.exe`, a shell. A launcher it knows is refused on every system, and the refusal names the exact `bw` to set: npm's `bw`, `bw.cmd` and `bw.ps1` (and on macOS the `bw` link npm and Homebrew make to `bw.js`, a `#!` script), Scoop's `shims\bw.exe`, Chocolatey's `bin\bw.exe` and Volta's `node` (on Windows `C:\Program Files\Volta\node.exe`), which start a program the pin never sees. A link is followed, so WinGet's `Links\bw.exe` pins the `bw.exe` it leads to. `connect` refuses any other shape, and says which to set: a program alone that is not named `bw` (`node`, `sh`, `powershell` and the like would run `bw`'s arguments as code), a program that is not native (a `#!` script or another text file), a folder, a relative path, a Node option (`--eval=`, `--require=`, `--env-file=`, any `-…`), a script that is not `.js`, or more than one argument (§ Running bw). |
| `dataDir` | no | `BITWARDENCLI_APPDATA_DIR` for every run. Default `<runtime>/bitwarden/cli`: phantab's own CLI state, made owner-only by `connect`, never the owner's other `bw` data. |
| `askFirst` | no | Lower-case hosts or base domains (`^[a-z0-9.-]+$`) that answer `ask-first` (§ Ask first). |
| `policyFile` | no | An absolute path to a `sign-in-policy.json`-shaped file, read on every call. |
| `syncAfterSeconds` | no | How old the local vault copy may be before a call syncs first. Default 300. |
| `server` | no | An `https://` URL `connect` points a logged-out CLI at. Sign-in calls never use it. |
| `proxy` | no | An `http://` or `https://` URL with no user name or password. Every `bw` phantab runs, sign-ins and `connect` alike, gets it as `http_proxy` and `https_proxy`, in place of every proxy variable the service or the terminal has. Set it on a network that needs a proxy, so that which client started the service does not decide it (§ Running bw). The service reads it when it starts: run `phantab shutdown` after changing it. |

Unknown keys are an error, so a typo fails closed instead of being ignored.

## One call

`BitwardenSource::decide` (`crates/phantab/src/signin/bitwarden/mod.rs`). All of it shares the call's
deadline: the provider budget (45 s) or what is left of the fill budget, whichever is less.

1. Every URL (top page, ancestors, frame, form action) must be an `https` origin, else `refused`.
2. Ask-first sites: any URL's host on one is `ask-first`, before `bw` runs. A policy file that does
   not read is `refused`.
3. The stored session (§ Session storage): none is `locked`, unreadable is `provider-failed`. It is
   read on a blocking thread within the call's deadline, so a macOS Keychain prompt cannot hold the
   call past it (`provider-failed`; the prompt stays up for the owner). A key made with another `bw`
   than the one configured now, or stored by a phantab from before pins, is `locked`, and no `bw`
   starts with it (§ Running bw).
4. `bw status --raw` with that session: anything but `unlocked` is `locked`.
5. If the copy is older than `syncAfterSeconds` (or never synced) and more than 20 s are left,
   `bw sync`. A failed sync is fine (offline: the local copy answers); one that runs out the clock is
   `busy`.
6. `bw list items --url <top page> --raw`. Parsed at once; the raw bytes are wiped, and the parsed list
   is wiped when the call ends.
7. Choose one login (§ Matching).
8. An item with master-password reprompt is `refused`: only a `reprompt` that is missing, `null` or
   the integer `0` passes, so `1`, `1.0`, `"0"`, `true` or a type a later Bitwarden adds all refuse.
   An item with any URI on an ask-first site is `ask-first`.
9. Only the wanted fields of the chosen item are moved into `Secret`s; a missing one is `none`. A
   missing password on a login with a saved passkey (`login.fido2Credentials` not empty; only its
   emptiness is read) is `wall`/`passkey` instead (README § When a site wants your passkey).
10. A code only when the page wants one: no authenticator key saved is `wall`/`code-not-saved`, else
    `bw get totp <id>`. A failure is `code-not-saved`; the code must be 4 to 10 letters or digits.
11. The account key is `sha256("phantab-sign-in:" + id)`, hex, first 32 characters, so guard-file
    limits and held pages follow the saved login, not the page.

Timeouts are `busy`; a failed, oversized or unparseable run is `provider-failed`. Nothing `bw` prints
reaches a label or an error.

## Sign-up

`browser_sign_up` (THREAT-MODEL SR-78, SR-79, SR-83) saves the new password here before
anything is filled. Besides this source, only a pinned v2 command provider that declared `create` creates
(`docs/VAULTS.md`); any other answers `no-provider-create` and
starts nothing. `BitwardenSource::make` (`crates/phantab/src/signin/bitwarden/create.rs`), within the
call's deadline as a sign-in is:

1. The page's origin must be `https`, else `refused`. Its host on an ask-first site is `ask-first`,
   before `bw` runs; a policy file that does not read is `refused`.
2. Steps 3 to 5 of § One call: the stored session, `bw status`, `bw sync` when the copy is old.
3. `bw list items --url <origin> --raw`, parsed at once and wiped when the call ends.
4. The logins saved for this exact origin (one of the item's URIs has it as its origin) and this exact
   username, of type login. A login for the parent domain, another origin or another username is not
   this one. Two or more are `ambiguous` with the count. One with master-password reprompt is
   `refused`; one with any URI on an ask-first site is `ask-first`.
5. One, and no `regenerate`: its password is the answer (`existing`), and nothing is written. One with
   no password is `refused`: the agent asks to regenerate.
6. Otherwise phantab makes the password and sets it in the login: a copy of
   the saved item (`regenerate`; every other field kept) or a new one shaped as `bw get template item`
   makes it, named by the call, with one URI, the origin, at Bitwarden's default match, and `reprompt`
   0.
7. `bw create item` (new) or `bw edit item <id>` (`regenerate`), with the login's JSON, base64, on the
   child's stdin, written whole and closed: never on its command line. Both buffers are allocated once
   at their final size and zeroized. The output must carry an id (for an edit, the same id); the
   printed item is wiped at once. A failure, a timeout or output that does not parse writes nothing
   more and answers as § One call does.
8. `bw get item <id>`: the read-back. Only a login for the same origin and username whose password is
   the one made (compared in constant time) is answered; anything else is `provider-failed`, and
   nothing is filled.
9. `bw sync`, best effort: offline or refused, the write is already on the server or in the local copy
   the next sign-in syncs.
10. The answer is the password and `new` or `replaced`.

A fill that fails after the save leaves the login saved: the next call with the same username answers
`existing` and fills it.

## Matching

`crates/phantab/src/signin/bitwarden/matching.rs`. Each saved URI is compared by its own match setting,
the way Bitwarden's clients do by default (`LoginUriView.matchesUri` in bitwarden/clients
`libs/common`). `bw list items --url` has already applied Bitwarden's own matching (with its equivalent
domains), so a login phantab keeps fits both.

| URI match setting (`login.uris[].match`) | Fits when |
|---|---|
| default (`null`), base domain (0) | the same registrable domain (eTLD+1, Public Suffix List with its private section): the parent, subdomains and siblings fit, on any port |
| host (1) | the same host and port |
| starts with (2) | the same host and port, and the page URL starts with the saved URI |
| exact (3) | the same host and port, and the page URL is the saved URI |
| regular expression (4) | never: phantab does not run a pattern from the vault against pages |
| never (5), unknown | never |

So a login saved for `site.test` (or `www.site.test`) with the default setting fills
`login.site.test`, as the Bitwarden extension does; a login set to host fills only its own host.
`a.github.io` and `b.github.io` are different sites (the list's private section), as are `bbc.co.uk`
and `evil.co.uk`.

Stricter than Bitwarden, on purpose:

- Only `https`. The page must be `https` (step 1), and an `http://` URI never fits, under any setting.
  Bitwarden ignores the scheme; phantab never hands a login to a plain-text page. A saved URI without a
  scheme (`login.site.test`) is read as `https://`.
- An IP address, `localhost` or a name under it has no registrable domain here: base domain is host
  and port equality for it (Bitwarden compares the bare host, on any port).
- A `match` value that is there but is not a number phantab knows (`"5"`, `"never"`, `5.0`, `true`,
  `99`) never fits. Only an absent or `null` one is the default, so a damaged setting never widens to
  base domain; this matters most for frames and form targets, which `bw` never filtered.
- Starts with and exact also need the same host and port, so `https://site.test` "starting"
  `https://site.test.evil.test/` is not a fit.
- Bitwarden's equivalent domains (`google.com` with `youtube.com`) are not followed.

Looser than Bitwarden, but only on the same origin: a host that is itself a public suffix
(`github.io`, `co.uk`), a name without a dot (`router`) or one ending in a dot has no registrable
domain. Bitwarden never fills it under base domain; phantab fills it when the host and port are the
saved entry's own.

Kept from Bitwarden: the one base-domain exception, a `google.com` login never fits `script.google.com`
(`Utils.DomainMatchBlacklist`). The list is compiled into phantab (the `psl` crate, MIT or Apache-2.0):
no network, no file. A newer list arrives with a phantab update.

Then: only live logins (type 1, not deleted, a UUID id) that fit the top page; an `account` from the
agent keeps exact name matches; a held account key keeps that login (none left: `refused`); none left
is `none`; every other URL (a frame, the form's target) must fit one of the login's entries under that
entry's site rule, else `wall`/`form-posts-elsewhere` (only the top page is held to an entry's "exact"
or "starts with" path, since a form posts to another path of its own site); more than one is
`ambiguous` with the count.

## Ask first

`crates/phantab/src/signin/bitwarden/policy.rs`, the owner's `sign-in-policy.json` semantics. A site is
the inline `askFirst` list plus the policy file's `askFirst`. A page host is on a site when it is the
site or ends with `.site`. A saved login asks first when any of its URIs names the site (lower-cased,
backslashes dropped, then a contains test).

An approval in the policy file, `{site, at, until, words}`, lifts one site while it is open: `words`
non-empty, `at` no later than a minute from now, `now < until`, and `until - at` at most an hour. The
file is read on every call and capped at 1 MiB. One that does not parse makes every call `refused`, never
a quiet pass.

## Session storage

`crates/phantab/src/signin/bitwarden/vault.rs`, over `phantab_window::secret_store`. Only the CLI's
session key is stored (`bw unlock --raw`'s output: base64, at most 512 characters, checked before use).
The master password is never stored, and never written anywhere.

The store holds one record, built in a buffer sized up front and zeroized:

```text
phantab-bw-session-2
{"command":["C:\\Program Files\\nodejs\\node.exe","C:\\...\\bw.js"],"files":[{"path":"...","sha256":"..."}, ...]}
<session key>
```

The second line is the key's pin (`crates/phantab/src/signin/bitwarden/pin.rs`): the `bw` command as
configured when `connect` made the key, and the SHA-256 of each file in it that runs (the program, and
each later argument that names a file, which must be an absolute path). A store without the header is the bare key an
earlier phantab wrote: it loads with no pin, so it is never used until `connect` runs again.

```rust
trait SessionVault: Send + Sync {
    fn load(&self) -> io::Result<Option<SessionKey>>;
    fn store(&self, key: &SessionKey) -> io::Result<()>;
    fn clear(&self) -> io::Result<bool>;
    fn protection(&self) -> &'static str;
}
```

| OS | Store | Notes |
|---|---|---|
| Windows | `<runtime>/bitwarden/session.dpapi`: DPAPI, user scope, `CRYPTPROTECT_UI_FORBIDDEN`, fixed entropy `dev.phantab.bitwarden-session-1` | Folder owner-only (SR-10's DACL); written beside, then renamed in. A blob that will not open is an error, not "none". |
| macOS | login Keychain, generic password, service `dev.phantab.bitwarden`, account = the bitwarden folder's path | Every call opens the login keychain by its path (`~/Library/Keychains/login.keychain-db`, the home folder taken from the user database for the real user ID with `getpwuid_r`, never from `$HOME`, which whoever starts phantab can set) and uses it alone, for the store, the read and the delete: never the default keychain or the search list, which a same-user program can point at a keychain of its own. Keychain ACL: the binary that created the item reads it without a prompt. After an update the binary's signature changes and macOS asks once for the login password ("Always Allow" ends it): normal Keychain behaviour, kept. A store deletes every item under the name, then adds a new one, so the access list is always phantab's own: an item another program planted first is never updated in place. A read copies the key out of the buffer the Keychain returns (`SecKeychainFindGenericPassword`), then zeroes and frees it. |
| tests | `MemoryVault` (`test-seams` only); macOS tests of the Keychain calls use the service `dev.phantab.test.secret-store`, and test builds of phantab use `dev.phantab.test.bitwarden` | Never the owner's `dev.phantab.bitwarden` item, and never the owner's keychain: a test build (unit tests, and `test-seams`, which a release build cannot turn on) never opens the login keychain. Each Keychain test makes a scratch keychain (`SecKeychainCreate`, in a new owner-only folder under the temporary folder, with a random password; `secret_store::test_keychain`) and deletes it when it drops, also while a panic unwinds (`SecKeychainDelete`). A test that runs the phantab binary names it in `PHANTAB_TEST_KEYCHAIN` and `PHANTAB_TEST_KEYCHAIN_PASSWORD`, read only by a `test-seams` build (the code is not in a release build). With no scratch keychain every Keychain call fails. The guard fails closed: a path with `.` or `..`, named `login.keychain`, in `~/Library/Keychains` (as given, by its folder's real path and by its own), whose folder cannot be resolved, a symbolic link, a file with more than one link, or the same file (device and inode) as any in `~/Library/Keychains` is refused before it opens. `SecKeychainCreate` puts a keychain on the search list only for a `/login.keychain` path, so a scratch keychain changes neither the search list nor the default keychain; a test reads both before, during and after one. This crate's integration tests and doctests also link `test-seams` (its own dev-dependency). A release binary holding `phantab-test-seams-build`, `PHANTAB_TEST_KEYCHAIN` or `phantab-window`'s no-test-keychain error is refused by `release.sh`'s path gate. While the owner is logged in an unlock accepts any password, so the guard is the whole defence; it checks the path, and a same-user swap between the check and the call reaches only the test service names (THREAT-MODEL R21). On Windows the DPAPI blob is a file in the runtime folder and no OS store takes part; a test build uses its own file name (`session.test.dpapi`) and entropy, so it never opens, replaces or deletes the owner's `session.dpapi` even in the owner's folder, and `check.sh` unsets `PHANTAB_RUNTIME`. |

`SessionKey` is zeroized on drop and prints `[redacted]`. It only ever reaches a `bw` child, in
`BW_SESSION`, handed straight from the key to the command: phantab makes no copy of its own, but the
standard library's command and the child's environment block do, and those are not wiped. That is the
accepted residual R17, the same exposure Bitwarden's own CLI has (its `BW_SESSION` lives in the shell's
and the CLI's environment).

## Connecting

`phantab bitwarden connect | status | disconnect` (`crates/phantab/src/bitwarden.rs`). They read
`config.json` and need no service.

- `connect` is the owner's step, in a terminal window (stdin must be a terminal).
  - CLI logged out: `bw config server <server>` if set, then `bw login --raw` interactively, with
    `bw`'s own prompts (email, master password, two-step) on the owner's terminal.
  - CLI locked: phantab asks `Bitwarden master password (typing is hidden):` with echo off (Windows
    console `ReadConsoleW`; unix `termios`). Git Bash's mintty is not a console and is refused: use
    Windows Terminal, PowerShell or cmd. The terminal's line editing and signal keys are off for the
    read and restored on every return (`phantab-window/src/console_keys.rs`): Backspace and Ctrl+U
    edit (Esc too erases the line on Windows), arrow keys are skipped, Ctrl+D or Ctrl+Z on an empty
    line ends, and Ctrl+C cancels, even inside a cut-off escape sequence: echo is
    back, the line ends, and `connect` exits 130. The password goes only into the environment of one
    `bw unlock --passwordenv PHANTAB_BW_MASTER --raw` child, never its argv. The buffer it is read
    into is zeroized and handed straight to the command; the command's and the child's copies are not
    wiped (residual R18).
  - Before any `bw` runs, `connect` pins the `bw` configured now (§ Session storage) and shows the files
    it will run, each by its resolved path (links followed) with its SHA-256, then goes on only when
    `yes` is typed at the terminal. Anything else stops it, with nothing run or stored: a `bw` the owner
    did not install (a `config.json` edit) shows here. In the paths shown, here and in every refusal,
    only printable ASCII but `{` is written as it is: every other character is written as `\u{..}` (`{`
    as `\u{7b}`) and a byte that is not UTF-8 as `\x{..}`, the same on both systems. Since a `{` is
    never shown as it is, every `{` shown opens an escape, and the text reads back to one path only: a
    folder named `u{202e}nib` after a `\` shows as `\u\u{7b}202e}nib`, not as U+202E. No list of hiding
    characters is kept,
    so none can be missed: controls (ESC, CR), bidirectional marks, zero-width and other
    default-ignorable characters (U+200B, U+2060, U+180E, U+034F), variation selectors (U+FE0F), Hangul
    fillers (U+3164) and letters that only look like ASCII ones (Cyrillic `а`) all show, so a planted
    folder name cannot move the cursor, reorder the line or hide part of itself. A folder name in another
    script reads escaped; that is the price. The confirmation is not proof that a person answered: a pipe
    or an agent's plain shell cannot answer it (stdin must be a terminal), but a same-user process
    driving a pseudo-terminal (`script` on macOS, a ConPTY on Windows) or sending keys to a console can
    type `yes`. It still has no master password: the confirmation shows the owner what they are about to
    give their password to, and the password is the boundary. A `bw` that cannot be read or pinned stops
    `connect` before it asks. The printed session key is checked with `bw status`, and stored only if it
    unlocks the vault, pinned to that `bw`. The pin is checked again just before `bw` is given the master
    password (or `login`'s prompts): a `bw` changed in between is not given it, and `connect` says to run
    it again. That `bw` is started by the files this second check opened and hashed, not by the path
    resolved before the prompt, so on macOS a link repointed and a file rewritten while the owner types
    cannot send the password to a file no check hashed. On Windows the pinned files are held for the
    whole of `connect` (no one can open them for writing, rename or delete them), and every `bw` it
    starts is started by the paths read back from those handles. Running `connect` again after changing
    `bw`, or after a Bitwarden CLI update, pins the new one, after the owner confirms it.
  - Before it reads anything, it turns core dumps off for itself and the `bw` children (`RLIMIT_CORE =
    0` on macOS, as the service does; Windows writes none unless WER LocalDumps is on, THREAT-MODEL R11).
    `status` and `disconnect` do the same.
- `status` prints `{source, protection, session: stored|stale|none|unreadable, vault:
  unlocked|locked|unauthenticated|unknown}`. No email, no server. `stale` is a key made with another
  `bw` (or by a phantab from before pins): `bw status` runs without it, and stderr says to run
  `phantab bitwarden connect` again.
- `disconnect` removes the stored key and runs `bw lock`, which also invalidates that key in the CLI's
  data (a `stale` key is not handed to the `bw` configured now: it locks without it). Prints
  `{session: removed|none, locked}`.

The default `dataDir` is phantab's own, so the first `connect` is a full `bw login`: Bitwarden sees a new
device. Pointing `dataDir` at an existing CLI folder reuses that login instead.

## Running bw

`crates/phantab/src/signin/bitwarden/cli.rs`. Every run:

- the configured program with its prefix arguments, then the command, then `--nointeraction` (not for
  `connect`'s `login`), no shell;
- an environment cleared to `SystemRoot`, `windir`, `PATH`, `PATHEXT`, `TEMP`, `TMP`, `USERPROFILE`,
  `HOMEDRIVE`, `HOMEPATH`, `HOME`, `TMPDIR`, `LANG` and the proxy variables `http_proxy`,
  `https_proxy`, `no_proxy`, `all_proxy` in lower and upper case (those that are set; on Windows,
  where case does not matter, each once), plus `BITWARDENCLI_APPDATA_DIR`, `BW_NOINTERACTION=true`,
  and `BW_SESSION` only for commands that need it. `bw` itself reads only `http_proxy`, else
  `https_proxy` (§ Checked against bitwarden/clients); the others pass because they are harmless.
  Without `proxy` in the config, a `bw` the service runs (every sign-in) takes these from the service,
  which has them only if the client that started it did (SR-14): an agent's MCP server (from its harness)
  or Chrome's native host (from Chrome's; on macOS a Chrome opened from the Dock has none of the shell's
  settings). `connect` runs in the owner's terminal, so it can sync while the service's `bw` cannot: a
  sync the network refuses leaves the local copy answering, not refreshed, and one that stalls is `busy`.
  Restarting the service does not fix that, since the extension reconnects within a second and its native
  host starts the service again with Chrome's environment. So on a network that needs a proxy, set
  `proxy` (§ Config) and run `phantab shutdown`: every `bw` then gets it, on Windows and macOS alike,
  whichever client starts the service next.
  Never `NODE_OPTIONS` (loads code into `bw`), `NODE_EXTRA_CA_CERTS` (trusts another certificate
  authority) or `NODE_TLS_REJECT_UNAUTHORIZED` (turns certificate checks off), no `APPDATA`, nothing
  of phantab's own;
- stdin and stderr null, no window; a Windows job object or a unix process group, killed with the call
  (timeout, drop); `phantab_cdp::spawn_guard` held over the spawn (R13);
- stdout capped at 4 MiB, read into a zeroized buffer;
- a command that carries the session key starts only while the key's pin holds: the configured command
  is the one pinned and each pinned file's SHA-256 is unchanged. Otherwise nothing starts and the call
  answers `locked`. This is checked in `cli::run`, which every `bw` goes through, the pinned files stay
  open from the check until that `bw` has exited, and that `bw` is started by the files' resolved paths
  (below), not the configured ones.

What runs must be what is hashed, so only two shapes are pinned, and anything else is refused, never
pinned in part:

- the standalone `bw` program, with no argument: a file named `bw` (on Windows `bw.exe`), in any case
  on both systems, since Windows names and macOS's default volume are not case-sensitive, reached
  through any links. Any other program alone would
  be given `bw`'s arguments (`status`, `unlock --passwordenv ...`), which an interpreter such as `node`,
  `sh`, `python` or `powershell` runs as code that is not hashed, so it is refused; `node` alone is
  refused by name;
- `node` and the absolute path of one `.js` script (`@bitwarden/cli/build/bw.js`), with nothing else.
  No Node option is accepted: `--eval=`, `--require=` and `--env-file=` all run or load code that is
  not hashed.

The program must be native: on Windows a `.exe` that starts `MZ`, on macOS a Mach-O. A `#!` script
would have its interpreter looked up on `PATH`, and a text file the kernel will not load is run by
`/bin/sh`. A folder (Node would run its package's main file) or a relative path (looked up from the
working folder) is refused. A link is followed, so the hash is of what runs.

A launcher it knows is refused, the same on every system, since what it starts is not what is hashed: npm's
`bw`, `bw.cmd` and `bw.ps1` beside its `node_modules` (on macOS `bin/bw`, a link to `bw.js`, as npm and
Homebrew make it), Scoop's `shims\bw.exe`, a small native program that starts the one its `bw.shim`
names, and Chocolatey's `bin\bw.exe`, one its shimgen made, which starts
`lib\bitwarden-cli\tools\bw.exe`. A Chocolatey shim is known by the help text every shimgen shim
carries (`--shimgen-help`, as UTF-16 in the file), which marks it wherever it was installed or copied,
where a path under `%ChocolateyInstall%\bin` would miss a copy; a file over 8 MiB is not read for it
(a shim is about 400 KB). Volta's `node` is one too: on Windows its installer puts `node.exe`, a copy
of `volta-shim.exe`, beside `volta.exe` in `C:\Program Files\Volta`; on macOS `~/.volta/bin/node` is a
link to `volta-shim` there. Either starts the node Volta picks, under its home's `tools/image/node`. It
is known as the file, never by its folder, the same on both systems: it is named `volta-shim` (a link
is judged as the file it leads to), or a `volta-shim` beside it holds the same bytes. So a real `bw`
that only shares a folder with Volta, such as `/usr/local/bin/bw` beside Homebrew's `volta` on an Intel
Mac, or one put in a Volta home's `bin`, is pinned as the program it is. The refusal names the exact
`bw` to set, read from the files beside the launcher: the program the `.shim` names, the one the
Chocolatey shim names (relative to its folder), the node Volta runs by default (the version its
`tools/user/platform.json` names; if that is not found, the one `volta which node` prints) with the
configured script, or `node` and the package's `bw.js` (for Homebrew by its `opt/` path, with Homebrew's
`node`; for npm with the `node` beside npm's prefix, or on Windows the installer's
`%ProgramFiles%\nodejs\node.exe`). A launcher of another kind is not known, and is pinned as the
program it is.

### Installs

What to set `bw` to, by system and install (`<you>` is the user's folder name). Each pins the same
way on both systems: the program alone, or `node` and `bw.js`.

| System | Install | `bw` |
|---|---|---|
| Windows | Bitwarden's standalone download (zip) | `"C:\\Tools\\bw.exe"`: the `bw.exe` wherever it was unzipped. |
| Windows | WinGet (`Bitwarden.CLI`) | `"C:\\Users\\<you>\\AppData\\Local\\Microsoft\\WinGet\\Links\\bw.exe"`, or the `bw.exe` under `WinGet\Packages` it leads to: the link is followed, so both pin that file. |
| Windows | Scoop (`bitwarden-cli`) | `"C:\\Users\\<you>\\scoop\\apps\\bitwarden-cli\\current\\bw.exe"`. Not `scoop\shims\bw.exe`, the launcher. |
| Windows | Chocolatey (`bitwarden-cli`) | `"C:\\ProgramData\\chocolatey\\lib\\bitwarden-cli\\tools\\bw.exe"`. Not `chocolatey\bin\bw.exe`, the launcher. |
| Windows | Volta (node, then `@bitwarden/cli`) | `["C:\\Users\\<you>\\AppData\\Local\\Volta\\tools\\image\\node\\<version>\\node.exe", "C:\\Users\\<you>\\AppData\\Local\\Volta\\tools\\image\\packages\\@bitwarden\\cli\\node_modules\\@bitwarden\\cli\\build\\bw.js"]`. Not `C:\Program Files\Volta\node.exe` or `Volta\bin\bw.cmd`, the launchers. After a new default node, set its `<version>`. Not yet confirmed on a real Volta install. |
| Windows | npm (`@bitwarden/cli`) | `["C:\\Program Files\\nodejs\\node.exe", "C:\\Users\\<you>\\AppData\\Roaming\\npm\\node_modules\\@bitwarden\\cli\\build\\bw.js"]`. Not `bw.cmd`, `bw.ps1` or `bw`, the launchers. |
| macOS | Bitwarden's standalone download (zip) | `"/usr/local/bin/bw"`: the `bw` wherever it was unzipped. |
| macOS | Homebrew (`bitwarden-cli`) | `["/opt/homebrew/bin/node", "/opt/homebrew/opt/bitwarden-cli/libexec/lib/node_modules/@bitwarden/cli/build/bw.js"]` (`/usr/local` for `/opt/homebrew` on an Intel Mac). Not `bin/bw`, a link to `bw.js`. |
| macOS | npm (`@bitwarden/cli`) | `["<prefix>/bin/node", "<prefix>/lib/node_modules/@bitwarden/cli/build/bw.js"]`, `<prefix>` from `npm prefix -g`. Not `bin/bw`, a link to `bw.js`. |
| macOS | Volta (node, then `@bitwarden/cli`) | `["/Users/<you>/.volta/tools/image/node/<version>/bin/node", "/Users/<you>/.volta/tools/image/packages/@bitwarden/cli/lib/node_modules/@bitwarden/cli/build/bw.js"]`. Not `~/.volta/bin/node` or `~/.volta/bin/bw`, links to the launcher `volta-shim`. After a new default node, set its `<version>`. Not yet confirmed on a real Volta install. |

Homebrew takes the npm shape where WinGet, Scoop and Chocolatey do not because of what each installs,
not a difference in the checks: they install Bitwarden's native standalone build, so their `bw.exe` is
the program; Homebrew's `bitwarden-cli` formula installs the npm package (it depends on
`node` and runs `npm install`) and links `bin/bw` to `bw.js`. The standalone download is the native
program on both systems. For Homebrew, `opt/bitwarden-cli` names no version, so after `brew upgrade` the
config stays and only `connect` runs again (the new files hash differently).

The standalone program is about 100 MB. It hashes in about 60 ms (SHA-256 at about 1.7 GB/s on a
desktop PC); each file's hash is then kept for the life of the process, keyed by its path and a stamp
read from the open file: size and modification time, plus on unix the inode, device and change time
(which no unprivileged writer can set back), and on Windows the creation time, the volume, the file ID
and the update sequence number (USN), which NTFS moves on at every change to the file and user code
cannot set back (`phantab_window::file_identity`). A file whose stamp changed while it was read is not
kept, and on a file system with no USN (FAT, a network share) every call hashes the file again.

Each pinned file is hashed through a handle that stays open until the `bw` it was checked for has exited
(and through the whole of `connect`), and that `bw` is started by the file's resolved path: on Windows
the path read back from the open handle (`GetFinalPathNameByHandleW`), with every link and junction
followed; on macOS the configured path, resolved, and checked to name the open file (its device and
inode). On Windows the handle shares reading only, so while it
is open no one can open the file for writing, rename or delete it, nor rename a folder on its resolved
path; the loader and Node open the file that was hashed. A link or junction on the configured path (a
Scoop `current` folder, a WinGet link) can still be repointed while the file is held, but the child does
not go through it. The hold covers the hashed file only: a writable mapping of it that a same-user
program made before phantab opened it can still change it, and same-user code has other ways in
(THREAT-MODEL R16). Unix has no such lock: there a writer that swaps or rewrites a file in place
between the check and the moment the system opens it (or Node reads `bw.js`, later still) wins.

What the pin buys:

- It keeps the key from a `bw` other than the one connected with: an edited `config.json`, another
  path, a program updated or replaced in place. The next `connect` would pin whatever `config.json`
  names then, so it shows that `bw`'s resolved paths and SHA-256 and goes on only when `yes` is typed
  at the terminal. That stops a plain non-interactive shell, an agent's included; a same-user process
  driving a pseudo-terminal or sending keys can answer it, but still needs the master password, so a
  `bw` the owner did not choose is theirs to catch there before they type it.
- Windows: nothing against code running as the owner. Such code can open the DPAPI store and write a
  record pinned to a `bw` of its own (THREAT-MODEL R16). The pin stops only a swap made through the
  config or the files alone.
- macOS: it holds against a swap made before the check, and fully only once phantab is signed with the
  hardened runtime (sec-creds-2(b), still open). Until then a same-user program can load its own code
  into phantab with `DYLD_INSERT_LIBRARIES`, past any pin.
- Not covered: the modules `bw.js` loads (its `node_modules`, for the npm and Homebrew shapes) and the
  system's own libraries.

## Testing

`crates/phantab/tests/signin_bitwarden.rs` (lane 3, no Chrome) against `phantab-fake-bw`
(`crates/phantab/tests/bin/fake_bw.rs`, `test-seams` only), a stand-in for `bw` driven by
`fake-bw.json` in the data folder. It logs each run's argv, its environment's variable names, and
whether the session and password matched; never a value. The tests never run a real `bw` and never read
a real Bitwarden folder.

Covered: one exact login and its account key; the environment a child sees (proxies in, `NODE_*` out);
each entry by its own setting (a base-domain parent fits a subdomain, a host entry for a sibling, `http`,
pattern and never entries do not; two base-domain fits are ambiguous; another site and a lookalike suffix
are none); ambiguity, the account-name pick and held keys; a form that posts elsewhere; codes only when
wanted, missing or failing; no session, a stale session, locked and logged-out vaults (no `bw` run
without a session); inline and file ask-first sites, an over-long approval and a broken file; `http`
pages, reprompt items, missing passwords; oversized, malformed and failed output, a non-list answer, and
a slow CLI that ends at the deadline; sync when old, offline, and skipped when short of time; `connect`
with a hidden password (the password only in `unlock`'s child, never in argv, logs or errors; a wrong one
stores nothing), `connect` on a logged-out CLI (the password prompt never reached), `connect` showing the
resolved program and its SHA-256 and stopping, with no `bw` run and nothing stored, unless the owner
confirms, `phantab bitwarden connect` run as a binary with stdin not a terminal refusing before any `bw`
runs, `status`, `disconnect`; `phantab bitwarden status` run as a binary under a raised core limit, with
the fake reporting the 0 it inherited; a link on the configured path (a junction on Windows, a symbolic
link on macOS) repointed to an identical copy while the owner types and the file it led to rewritten
(which fails on Windows while held), with `status` started from the file held before the prompt and
`unlock` and the new key's check from the copy the second check hashed (the fake logs the path it was
started by; it is configured as a copy named `bw`, as the pin requires); the pin: a key goes only to the
`bw` it was made with (another path with the same bytes, a program changed in place and an earlier
phantab's bare key are `locked` with no `bw` started, `status` says `stale`, `disconnect` locks without
the key, `connect` again pins the new one, a `bw` that cannot be read stops `connect` before any run, and
a `bw` changed while the owner types the password is not given it; on Windows the change itself fails
while `connect` holds the file). Unit tests cover config parsing, the policy clock and approvals,
matching rules (each setting, the Public Suffix List's private section, punycode, IP and `localhost`
hosts, the `script.google.com` exception, `http` pages), the DPAPI round trip in a temp folder and with
the wrong entropy, session-key checks, the stored record (header, pin, key; a bare key loads unpinned; a
damaged one is refused), pin hashing and its cache (a same-length rewrite with its times put back is
hashed again; on Windows a moved USN), the commands the pin refuses (any Node option, `--eval=` among
them, an argument after the script, two scripts, a folder, a relative path, a script that is not `.js`, a
script for a program that is not node, a program that is not native: a `#!` script or a text file with no
`#!` line; on Windows a program not named `.exe`; `node` with no script; `node`, `sh`, `bash`,
`powershell`, `pwsh`, `python`, `env` and other names alone, and on macOS a link named `bw` that leads to
one), `BW` (`BW.EXE`) accepted on both, a link named `bw` started by the file it leads to, the launchers
refused with the exact `bw` to set (a Scoop shim and the program its `.shim` names, a Chocolatey shim and
the program it names, npm's launcher beside `node_modules` or linked to `bw.js`, on Windows `bw.cmd` and
`bw.ps1` at the config, on macOS Homebrew's Cellar link named by its `opt/` path), a Volta launcher (a
`node` that is a copy of the `volta-shim` beside it, `volta-shim` itself, on macOS a link to
`volta-shim`) refused with the node it starts and a real `bw` beside Volta's files accepted, the paths
shown at `connect` and in refusals with everything but printable ASCII (and `{`) escaped, checked against
hand-written expected text (U+FE0F, U+034F, U+3164, U+200B, U+2060, U+180E among them, and a real folder
so named), on unix a configured path that names another file than the one held refused, a held file that
cannot be written, renamed or deleted on Windows, a link on the configured path repointed after the check
with the child started by the hashed files (a junction on Windows, a symbolic link on macOS), the path
read back from a held handle past a junction (neither its folder nor the one above can be renamed while
held; the junction can be repointed and the held path still opens the hashed file), a key whose pin does
not hold starting nothing, `reprompt` values, `Ran`'s `Debug` printing only a size, the macOS Keychain
store replacing a planted item (macOS only, in a scratch keychain, under a test-only service), a test
build never opening the login keychain (the calls failing with no scratch keychain, `~/Library/Keychains`
and `login.keychain` refused, the guard refusing links, hard links, `..`, unresolved folders and the
owner's files by device and inode, the scan skipping an entry that vanished and refusing a folder it
cannot list, the binary's `status` unreadable with none named), the scratch keychain deleted when
dropped and when a test panics, the search list and default keychain unchanged by it, a Windows test
build never opening the owner's `session.dpapi`, the login keychain's home folder
taken from the user database as `id -P` reads it, checked in a child run with `HOME` set to another
folder (macOS only), the secret variables kept apart from the copied environment, and the hidden prompt's
keys as a pure function of the bytes or UTF-16 units typed (Enter, Ctrl+C, Ctrl+D and Ctrl+Z, Backspace
over multi-byte characters and surrogate pairs, Ctrl+U, escape sequences and the keys that still act
inside a cut-off one, Esc on Windows, the length limit). No test types at a real console.

Sign-up (§ Sign-up) over the same fake: `create item` and `edit item <id>` read the encoded login on
stdin (the fake logs only its length, `stdinBytes`) and write it into `fake-bw.json`; `get item <id>`
prints it back, with another password when `readBack` is `"wrong"`. Covered: a new login saved, read back
and synced, with the vault holding what is answered and nothing but the command and its flags on the
command line; the saved login for this origin and username answering `existing` with no write, and a
parent-domain login or another username giving a new one; `regenerate` editing the saved login in place
and keeping its other fields; ambiguity, reprompt, ask-first (no `bw` at all for an ask-first host),
locked and failed lists writing nothing; a failed or malformed write and a read-back that differs
answering nothing; a failed sync after the write still answering; an `http` origin refused before any
`bw`. No test prints a password: each is compared inside the test.

## Phase 2: native API client (design only)

Drive the Bitwarden server API directly instead of the CLI: prelogin (KDF parameters), the identity
token endpoint, `/sync`, and decrypting the one chosen cipher locally (PBKDF2-SHA256 or Argon2id master
key, HKDF-stretched; AES-256-CBC with HMAC-SHA256 `EncString`s; RSA-OAEP for organisation keys). Gains:
no Node runtime, about 5 to 7 s less per call, and only the chosen item ever decrypted (fixes R17).
Costs: phantab owns vault cryptography, token refresh and the API's changes, and the stored secret
becomes a refresh token plus a protected user key.

Bitwarden's own Rust SDK (`bitwarden/sdk`, `sdk-internal`) is under the Bitwarden SDK License, which is
not an OSI licence and limits use to Bitwarden-compatible applications. phantab should not depend on it.
A phase 2 client would be written from Bitwarden's public protocol documentation and open-source
(GPL/AGPL) clients' behaviour only as reference, never their code, and would need its own threat-model
review before any code.

## Checked against bitwarden/clients cli-v2026.10.1

Read in the source at tag `cli-v2026.10.1` (2026-10-29), never by running a `bw`. Paths are under
`apps/cli/src/` unless they start with `libs/`. No behaviour phantab relies on differed; the proxy row
changed phantab's environment (§ Running bw).

| Behaviour | Source | phantab's handling |
|---|---|---|
| `status` is JSON `{serverUrl, lastSync, userEmail, userId, status}`, `status` one of `unauthenticated`, `locked`, `unlocked`; `lastSync` an ISO time or `null` | `commands/status.command.ts` | reads only `status` and `lastSync`; `locked` and `unauthenticated` answer `locked`, any other value `provider-failed`; a `null` lastSync means never synced, so the call syncs |
| An error goes to stderr and exits 1 (0 only with `BW_CLEANEXIT`) | `base-program.ts` `processResponse` | stderr is discarded; non-zero is `provider-failed`. `BW_CLEANEXIT` is never passed, so a failure cannot look like success |
| `--raw` sets `BW_RAW`, `--nointeraction` sets `BW_NOINTERACTION`; a message prints bare under `BW_RAW`; the last line has no newline on Windows or a pipe | `program.ts`, `base-program.ts`, `utils.ts` `writeLn` | both flags on every non-interactive run, plus `BW_NOINTERACTION=true`; the session key and codes are trimmed before checks |
| A locked vault with `BW_NOINTERACTION` errors "Vault is locked." and exits 1 | `base-program.ts` `exitIfLocked` | every call runs `status` first, so a locked vault answers `locked` before such a command; a non-zero exit is `provider-failed`, never a prompt |
| `unlock --passwordenv <name>` reads the password from that variable; with no password and no interaction it is a bad request | `key-management/commands/unlock.command.ts`, `utils.ts` `getPassword` | the password only in that child's `PHANTAB_BW_MASTER`, never argv |
| `unlock` tries desktop-app biometrics only with no password given and interaction allowed | `key-management/commands/unlock.command.ts` | never reached: phantab always gives `--passwordenv` and `--nointeraction` |
| `unlock --raw` prints only the new session key (base64 of a 64-byte key, 88 characters); earlier keys stop working | `key-management/commands/unlock.command.ts`, `program.ts` | the key is checked as base64 of at most 512 characters, then with `bw status`, before it is stored |
| The CLI has no PIN unlock | `key-management/commands/unlock.command.ts`, `program.ts` | none: PIN is a follow-up (§ Design decisions) |
| Every `login` prompt (email, password, two-step method, code, new-device code) writes to stderr | `auth/commands/login.command.ts` (`output: process.stderr`) | `connect`'s `bw login --raw` inherits the owner's terminal for stdin and stderr; stdout (the session key) is piped and kept |
| `login` when already logged in is an error | `auth/commands/login.command.ts` `exitIfAuthed` | `connect` runs `login` only when `status` says `unauthenticated` |
| `list items --url <url>` matches with the cipher service (default strategy, equivalent domains) and returns a JSON array of items with `login.uris[].{match, uri}` | `commands/list.command.ts`, `libs/common/src/vault/services/cipher.service.ts`, `vault/models/cipher.response.ts` | phantab narrows the answer with its own rules (§ Matching) |
| Base domain uses the Public Suffix List with private domains; `localhost` and IP addresses compare whole; `google.com` never fits `script.google.com`; starts with and exact compare strings | `libs/common/src/vault/models/view/login-uri.view.ts`, `libs/common/src/platform/misc/utils.ts` | the same, plus the tightenings in § Matching |
| `sync` prints "Syncing complete." or fails with "Syncing failed: ..." | `vault/sync.command.ts` | the exit status only; a failure answers from the local copy |
| `get totp <id>` prints the code; it can fail (no key, premium required) | `commands/get.command.ts` | a failure is `code-not-saved`; the code must be 4 to 10 letters or digits |
| `lock` destroys the session keys | `auth/commands/lock.command.ts` | `disconnect` runs it after removing the stored key |
| `BITWARDENCLI_APPDATA_DIR` sets the data folder, else `APPDATA`/`XDG_CONFIG_HOME` | `service-container/service-container.ts` | always set to phantab's `dataDir`; `APPDATA` and `XDG_CONFIG_HOME` never passed |
| Proxy: `http_proxy`, else `https_proxy` (lower case; any case on Windows), through `https-proxy-agent`; `NO_PROXY` and `ALL_PROXY` are not read | `platform/services/node-api.service.ts` | all eight proxy names pass; `NODE_*` never |

## Design decisions (2026-11-05)

The rule: on each open question, behave the way Bitwarden's own clients do, unless that loosens
phantab's security.

1. Matching: each URI by its own setting, base domain by default, as the Bitwarden browser extension;
   kept stricter on `https`, IP and `localhost` hosts, the path settings' host and regular expressions
   (§ Matching). This replaces an earlier exact-origin rule.
2. Sync: the local copy may be 300 s old before a call syncs first (skipped with 20 s or less left),
   matching Bitwarden clients, which sync on unlock and then periodically.
3. macOS Keychain: the one prompt after an update is normal macOS behaviour for a re-signed binary;
   kept, with "Always Allow" to end it.
4. Ctrl+C at the password prompt: echo is restored, the line ends, `connect` exits 130 (§ Connecting).
   The Unix path (`termios` with `ISIG` off) is checked by clippy for macOS but has not run on a Mac.
5. `bw` behaviour: checked in the source at `cli-v2026.10.1` (§ Checked against bitwarden/clients);
   `login`'s prompts all go to stderr, as believed.
6. The session key in memory: phantab's own copies are zeroized and the key is handed straight to the
   child; what the standard library and the child's environment hold is accepted residual R17, as in
   Bitwarden's CLI.
7. Proxies: the config's `proxy`, else the standard proxy variables from the service's environment,
   so from whichever client started the service (§ Running bw); `NODE_EXTRA_CA_CERTS`,
   `NODE_TLS_REJECT_UNAUTHORIZED` and `NODE_OPTIONS` never do.
8. PIN unlock: deferred. The CLI has none (`cli-v2026.10.1`), so it would need phase 2 or a desktop-app
   bridge; desktop biometrics through the CLI is the same follow-up.
