# Installing phantab on Windows (no admin)

For a Windows PC where you install from the release bundle instead of building from source.
Everything below runs as you: no admin, nothing outside your user folder and HKCU.
`docs/SECURITY-AUDIT-2026-11.md` says what a security audit found, what stays open, and which
settings it recommends.

## 1. Get the zip
You need `phantab-windows-x64-bundle.zip` (about 7 MB) and its hash. Both are on each release's page
on GitHub (`Mmore35/phantab` → Releases): the page lists a `sha256:` value beside each file. Write
that value down from the page itself. If the PC cannot reach GitHub, download on another computer
(a Mac: `docs/INSTALL-MAC.md`), then move the zip over, by a cloud drive or a USB stick. Not by
email: mail filters drop a zip that holds an `.exe`.

Check it is the file that was released (PowerShell, in the folder you saved it to). This should print
the `sha256:` value from the release page:
`(Get-FileHash .\phantab-windows-x64-bundle.zip).Hash.ToLower()`
Take the value to compare from the release page, or from the person who released it, in a message of
its own. A `.sha256` file that travelled with the zip, and the `SHA256SUMS.txt` inside it, only show
the copy is whole: whoever could change the zip on the way could change them too. Everything the
install checks after this rests on this one comparison. If the zip came from someone else or a shared
drive, do the comparison yourself.
Then right-click → **Extract All**, anywhere in your user folder (Downloads is fine).

## 2. Check first (optional)
`powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -CheckOnly`, run in the extracted
`phantab-windows-x64` folder, checks every file's hash and that Windows lets an unsigned program run
from there and from `%LOCALAPPDATA%` the way Chrome starts phantab, installs nothing, and on a refusal
says what blocked the run and prints the SHA-256 hashes of `phantab.exe` and `unsigned-check.exe`
(`-SkipCheck` on the install skips the test program).

## 3. Install: three steps
1. Open PowerShell in the extracted `phantab-windows-x64` folder (type `powershell` in Explorer's
   address bar) and run `powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1`. It lists
   your Chrome profiles and binds the one you used last (on a re-run, the one it is already bound to).
   If that's the wrong one, add `-ChromeProfile "Profile 1"`. Add `-DevTools` to turn on the developer
   tools (§ 4).
2. In that Chrome profile: `chrome://extensions` → **Developer mode** on → **Load unpacked** → pick
   `%LOCALAPPDATA%\phantab\extension` (paste it into the folder box).
3. Quit and reopen Claude Code. Ask it to *open example.com with phantab and read the title*.

**No-script install**, when PowerShell refuses scripts (`running scripts is disabled` or `is not
digitally signed`). This path skips the script's check of every file, so the zip's hash in step 1 is
the only check: do not skip it. Run in the folder (the `Set-Content` line only if
`%USERPROFILE%\.claude.json` doesn't exist yet). The profile is a folder name in
`%LOCALAPPDATA%\Google\Chrome\User Data`: `Default`, `Profile 1`, …
```
'{}' | Set-Content -Encoding Ascii "$env:USERPROFILE\.claude.json"
.\phantab.exe install --claude-config "$env:USERPROFILE\.claude.json" --profile "Default"
```
Add `--dev-tools` to that line for the developer tools.

**Update:** quit Claude Code, unzip the new bundle, run step 1 again (it keeps your profile), then click
the extension's reload button. **Undo:** first remove the extension in Chrome and quit Claude Code, then
`.\install.ps1 -Uninstall -RemoveFiles`. If it stops partway, run the same line again.
Saved logins through Bitwarden are a separate, later step (`docs/BITWARDEN.md`).

## 4. Developer tools (`-DevTools`)
`install.ps1 -DevTools` (on a Mac `bash install.sh --dev-tools`; without the script
`phantab install --dev-tools`) writes one setting to `%LOCALAPPDATA%\phantab\config.json` and keeps
every other one there:

```json
{ "profileDirectory": "Default", "devTools": true }
```

**`devTools`** turns on the developer tools: `browser_evaluate` (a script in the page),
`browser_console`, `browser_network`, `browser_emulate` (CPU, network, location, user agent and more
for one page) and `browser_trace` (a performance trace and its numbers). `docs/GUARDRAILS.md`
§ Developer tools says what each can reach.

A later install without `-DevTools`, an update for instance, keeps it. To turn it off, set it to
`false` in `config.json`. The phantab service reads it when it starts and keeps running after Claude
Code closes, so after a change restart only the phantab service, once its pages are drained (never
close Chrome), then quit and reopen Claude Code. Install says so when it turns the setting on.

**Check it:** the agent's tool list has the five developer tools after the others. After an update,
reload the extension at `chrome://extensions`, or it does not relay the developer tools.

**Chrome DevTools MCP beside it.** Phantab leaves out some of what Chrome DevTools MCP has: insight
analysis of a trace, Lighthouse audits, a screencast and logpoints (`docs/COMING-FROM-DEVTOOLS-MCP.md`
has the whole list and what replaces the rest). For those, keep Chrome DevTools MCP as a second MCP
entry. It starts and drives its own Chrome, with its own profile and none of your sign-ins, so the two
do not share pages.
