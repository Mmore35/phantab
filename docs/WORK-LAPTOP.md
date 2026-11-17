# phantab on a work laptop (Windows, no admin)

For a company-managed Windows PC where you can't build from source. Everything below runs as you:
no admin, nothing outside your user folder and HKCU. It's company equipment, so if the company has
rules about installing your own software, ask IT first. `docs/SECURITY-AUDIT-2026-11.md` says what a
security audit found, what stays open, and which settings it recommends here.

## 1. Get the zip onto the laptop
You need `phantab-windows-x64-bundle.zip` (about 7 MB) and its hash. Both are on each release's page
on GitHub (`Mmore35/phantab` → Releases): the page lists a `sha256:` value beside each file. Write
that value down from the page itself. If the laptop cannot reach GitHub, download on another
computer, then move the zip over (a Mac: `docs/INSTALL-MAC.md`):
- **Your own cloud drive** (Google Drive, personal OneDrive), opened in the laptop's browser, if the
  company allows that site. Or **a USB stick**, if removable drives are allowed.
- **Not email**: mail filters drop a zip that holds an `.exe`. Don't rename it to get past a filter;
  that filter is a company control.

Check it is the file that was released (PowerShell, in the folder you saved it to). This should print
the `sha256:` value from the release page:
`(Get-FileHash .\phantab-windows-x64-bundle.zip).Hash.ToLower()`
Take the value to compare from the release page, or from the person who released it, in a message of
its own. A `.sha256` file that travelled with the zip, and the `SHA256SUMS.txt` inside it, only show
the copy is whole: whoever could change the zip on the way could change them too. Everything the
install checks after this rests on this one comparison. If the zip came from someone else or a shared
drive, do the comparison yourself.
Then right-click → **Extract All**, anywhere in your user folder (Downloads is fine).

## 2. Test first: will Windows run an unsigned program?
Open PowerShell in the extracted `phantab-windows-x64` folder (type `powershell` in Explorer's address
bar) and run:
```
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -CheckOnly
```
It checks every file's hash, then runs `unsigned-check.exe` (a three-line program that prints one line
and touches nothing) from that folder, and again from `%LOCALAPPDATA%` the way Chrome will start
phantab: through `cmd.exe`, or directly when the Chrome policy `NativeHostsExecutablesLaunchDirectly`
is on. Then it runs `phantab.exe` itself. It installs nothing. Prefer it by hand? `.\unsigned-check.exe`
must print `unsigned-check: OK`.

| What you see | What blocked it | Ask IT for |
|---|---|---|
| `Check passed` | nothing | go to step 3 |
| `running scripts is disabled` or `is not digitally signed` | PowerShell execution policy set by group policy | nothing yet: use the no-script install below |
| `This program is blocked by group policy` | AppLocker | hash allow rules for the two programs the script lists (the message below) |
| `...App Control...` / `Device Guard` / `Application Control policy has blocked this file` | WDAC (App Control for Business), or Smart App Control when it is on (the script says which) | WDAC: the same hash rules. Smart App Control: no per-app exception exists; only a signed build gets past it |
| the `.exe` vanishes, or `Threat found` | Defender or the company's antivirus | an allow entry for the same hashes |
| `The command prompt has been disabled by your administrator` | DisableCMD policy: Chrome starts phantab through `cmd.exe` | the Chrome policy `NativeHostsExecutablesLaunchDirectly` = true (Chrome 120+), so Chrome starts it without `cmd.exe` |
| a blue `Windows protected your PC` box (double-clicking only) | SmartScreen | nothing: **More info → Run anyway**; the script avoids it |

When a program is blocked, the script prints both hashes. One message for IT: *"Can you allow, by SHA-256
hash, a user-level program, `phantab.exe`, which Chrome starts as the native messaging host of an
extension I load unpacked, and `unsigned-check.exe`, a tiny test program? They need no admin and write
only to my profile and HKCU. Hashes: (paste the two lines the script printed)."* A hash rule covers the
file in the unzipped folder and in `%LOCALAPPDATA%\phantab\bin` alike; a path rule would need both
folders. If IT allows only `phantab.exe`, install with `-SkipCheck` (it skips the test program). A hash
rule must be redone for each new version; a signed build would let IT allow the publisher once instead.

Chrome must also allow it. At `chrome://policy`, phantab is blocked by any of these:
`ExtensionInstallBlocklist` = `*` · `ExtensionSettings` with `"*": {"installation_mode": "blocked"}` ·
`ExtensionDeveloperModeSettings` = 1 · `DeveloperToolsAvailability` = 2 · `NativeMessagingBlocklist` = `*` ·
`NativeMessagingUserLevelHosts` = false.

## 3. Install: three steps
1. In the same folder: `powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Work`. It
   lists your Chrome profiles and binds the one you used last (on a re-run, the one it is already bound
   to). If that's the wrong one, add `-ChromeProfile "Profile 1"`. `-Work` writes the two settings in
   § 4; leave it out on a machine of your own.
2. In that Chrome profile: `chrome://extensions` → **Developer mode** on → **Load unpacked** → pick
   `%LOCALAPPDATA%\phantab\extension` (paste it into the folder box).
3. Quit and reopen Claude Code. Ask it to *open example.com with phantab and read the title*.

**No-script install**, when the policy refuses scripts. This path skips the script's check of every
file, so the zip's hash in step 1 is the only check: do not skip it. Run in the folder (the
`Set-Content` line only if
`%USERPROFILE%\.claude.json` doesn't exist yet). The profile is a folder name in
`%LOCALAPPDATA%\Google\Chrome\User Data`: `Default`, `Profile 1`, …
```
'{}' | Set-Content -Encoding Ascii "$env:USERPROFILE\.claude.json"
.\phantab.exe install --claude-config "$env:USERPROFILE\.claude.json" --profile "Default" --work
```
**Update:** quit Claude Code, unzip the new bundle, run step 1 again (it keeps your profile), then click
the extension's reload button. **Undo:** first remove the extension in Chrome and quit Claude Code, then
`.\install.ps1 -Uninstall -RemoveFiles`. If it stops partway, run the same line again.
Saved logins through Bitwarden are a separate, later step (`docs/BITWARDEN.md`).

## 4. The work install (`-Work`)
`install.ps1 -Work` (on a Mac `bash install.sh --work`; without the script `phantab install --work`)
writes two settings to `%LOCALAPPDATA%\phantab\config.json` and keeps every other one there:

```json
{ "profileDirectory": "Default", "work": true, "devTools": true }
```

- **`work`** turns off what a managed machine usually forbids, whatever else the file says: the
  `browser_sign_in` and `browser_sign_up` tools (not listed, and refused if called), every sign-in
  provider (a password manager is never started), the automatic pop-up when a page shows a human
  check (the agent is told; `browser_show` still hands the page to you when you or it ask), and the
  phone viewer (no port opens). You sign in yourself, in the page. `docs/GUARDRAILS.md` § A work
  laptop has the details.
- **`devTools`** turns on the developer tools: `browser_evaluate` (a script in the page),
  `browser_console`, `browser_network`, `browser_emulate` (CPU, network, location, user agent and
  more for one page) and `browser_trace` (a performance trace and its numbers).
  `docs/GUARDRAILS.md` § Developer tools says what each can reach.

A later install without `-Work`, an update for instance, keeps both. To turn one off, set it to `false`
in `config.json`. Both are read when phantab starts, so after a change quit and reopen Claude Code.

**Check it:** ask the agent to run `browser_status`. Its `work` field reads `"on": true` and lists the
four things that are off; if the config has a `remoteViewer` entry, `remoteViewer` says it is not
listening because of `work`. The agent's
tool list has no `browser_sign_in` or `browser_sign_up`, and has the five developer tools. A `note`
under `work` means the value was neither `true` nor `false`; it then counts as on. After an update,
reload the extension at `chrome://extensions`, or it does not relay the developer tools.

**Chrome DevTools MCP beside it.** Phantab leaves out some of what Chrome DevTools MCP has: insight
analysis of a trace, Lighthouse audits, a screencast and logpoints (`docs/COMING-FROM-DEVTOOLS-MCP.md`
has the whole list and what replaces the rest). For those, keep Chrome DevTools MCP as a second MCP
entry. It starts and drives its own Chrome, with its own profile and none of your sign-ins, so the two
do not share pages; ask IT before you add it, as for phantab.
