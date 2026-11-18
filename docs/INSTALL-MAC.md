# phantab on a Mac (Apple silicon, no admin)

For a Mac where you can't build from source. Everything runs as you: no admin, no sudo, nothing outside
your home folder. On a company Mac, if the company has rules about installing your own software, ask IT
first. (Windows: `docs/INSTALL-WINDOWS.md`.)

## 1. Get the zip
`phantab-macos-arm64-bundle.zip`, from the release's page on GitHub (`Mmore35/phantab` → Releases).
The page lists a `sha256:` value beside each file. Check you have the file that was released, in
Terminal in the folder you saved it to. It should print that value:
`shasum -a 256 phantab-macos-arm64-bundle.zip`
Take the value to compare from the release page, or from the person who released it, in a message of
its own. A `.sha256` file that travelled with the zip only shows the copy is whole
(`docs/INSTALL-WINDOWS.md` § 1).
Double-click the zip to unpack it (Downloads is fine).

## 2. Install
In Terminal, in the unpacked `phantab-macos-arm64` folder:
```
bash install.sh --check-only     # optional: checks the files and that macOS lets phantab run
bash install.sh
```
It checks every file's hash, clears the downloaded-file mark so macOS lets the unsigned phantab run,
lists your Chrome profiles and binds the one you used last (on a re-run, the one it is already bound to;
`--profile "Profile 1"` picks another). On a company Mac, `bash install.sh --work` also turns on the
work setting and the developer tools (`docs/INSTALL-WINDOWS.md` § 4). Then:
1. In that Chrome profile: `chrome://extensions` → **Developer mode** on → **Load unpacked** → in the
   picker press Cmd+Shift+G and paste `~/Library/Application Support/phantab/extension`.
2. Quit and reopen Claude Code. Ask it to *open example.com with phantab and read the title*.

If it says phantab does not run: a window saying the developer cannot be verified means
**System Settings → Privacy & Security → Open Anyway**, then run it again. On a company Mac, the device
policy may forbid unsigned programs; ask IT to allow phantab by its SHA-256 (in `SHA256SUMS.txt`).
Chrome must also allow it: see the `chrome://policy` list in `docs/INSTALL-WINDOWS.md` § 2, the same on a Mac.

**Update:** quit Claude Code, unpack the new bundle, run `bash install.sh` again (it keeps your profile),
then click the extension's reload button. **Undo:** remove the extension in Chrome, quit Claude Code, then
`bash install.sh --uninstall --remove-files`.
Each new agent window shows for about a second before it minimizes (`docs/MAC.md`). Saved logins
through Bitwarden are a separate, later step (`docs/BITWARDEN.md`).
