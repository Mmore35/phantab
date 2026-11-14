#!/bin/bash
# The macOS bundle's test: installs a built bundle zip from the zip alone under a throwaway HOME, checks
# every write, uninstalls, and checks it all came back. scripts/bundle-macos.sh runs it.
#
#   bash scripts/macos-bundle/test-bundle.sh <zip> [--keep]
#
# HOME points at a temp folder holding a fake Chrome user-data dir, so the runtime, the native host
# manifest and ~/.claude.json all land there; PATH is cut down to macOS's own folders (no cargo, rustc,
# node or brew). This Mac's real phantab install and Chrome are never touched: the test hashes the real
# native host manifest, runtime config and Claude Code entry before and after, and fails if any changed.
# Uses node for the JSON checks (the build machine has it; the install itself does not need it).
set -uo pipefail

zip="${1:-}"
[ -f "$zip" ] || { echo "usage: test-bundle.sh <zip> [--keep]" >&2; exit 2; }
keep=0
[ "${2:-}" != --keep ] || keep=1
zip="$(cd "$(dirname "$zip")" && pwd)/$(basename "$zip")"
node="$(command -v node)" || { echo "test-bundle.sh needs node for its JSON checks" >&2; exit 2; }

failures=0
pass() { echo "  pass: $*"; }
fail() { echo "  FAIL: $*"; failures=$((failures + 1)); }
check() { local what="$1"; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
lacks() { ! grep -qE "$1" <<<"$2"; }
hash_of() { if [ -f "$1" ]; then shasum -a 256 "$1" | cut -d' ' -f1; else echo '<absent>'; fi; }
# jget <file> <js expression over d>: prints the expression's value, '' when the file is missing.
jget() { [ -f "$1" ] && "$node" -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); const v=('"$2"'); process.stdout.write(v===undefined||v===null?"":typeof v==="string"?v:JSON.stringify(v))' "$1"; }

real_home="$HOME"
real_support="$real_home/Library/Application Support"
live_state() {
  echo "host=$(hash_of "$real_support/Google/Chrome/NativeMessagingHosts/dev.phantab.bridge.json")"
  echo "runtime-config=$(hash_of "$real_support/phantab/config.json")"
  echo "runtime-record=$(hash_of "$real_support/phantab/registration-v2.json")"
  # Only the entry: Claude Code rewrites the rest of .claude.json all the time.
  echo "claude=$(jget "$real_home/.claude.json" 'JSON.stringify(d.mcpServers||null)')"
  echo "codex=$(hash_of "$real_home/.codex/config.toml")"
}
before="$(live_state)"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/phantab-bundle-test.XXXXXX")"
tmp="$(cd "$tmp" && pwd -P)"
cleanup() { [ "$keep" = 1 ] || rm -rf "$tmp"; }
trap cleanup EXIT
home="$tmp/home"
support="$home/Library/Application Support"
runtime="$support/phantab"
bin="$runtime/bin/phantab"
user_data="$support/Google/Chrome"
echo "Bundle test: $zip"
echo "  scratch HOME $home"

# The zip alone, unpacked into an empty folder, marked as downloaded the way a browser marks it.
unzip -q "$zip" -d "$tmp/unzipped" || { echo "unzip failed"; exit 1; }
folder="$tmp/unzipped/phantab-macos-arm64"
script="$folder/install.sh"
check 'the zip holds phantab-macos-arm64/install.sh' test -f "$script"

# What ships beside the program: the licences, each listed in SHA256SUMS.txt, and a build-info that names
# no folder, user or machine (bundle-macos.sh copies release.sh's).
for f in LICENSE NOTICE THIRD-PARTY-LICENSES build-info.txt; do
  check "$f ships, listed in SHA256SUMS.txt" \
    bash -c 'test -f "$1/$2" && grep -qxE "[0-9a-f]{64}  $2" "$1/SHA256SUMS.txt"' _ "$folder" "$f"
done
info="$folder/build-info.txt"
for k in version sha target rustc cargo_lock_sha256 extension_lock_sha256 build_only; do
  check "build-info.txt records $k" [ "$(grep -cE "^$k=." "$info")" = 1 ]
done
odd="$({ grep -vE '^[A-Za-z][A-Za-z0-9_. -]*=' "$info"; grep -E '[\\/]' "$info"; } | tr '\n' ' ')"
check "build-info.txt is key=value lines with no path in them ($odd)" [ -z "$odd" ]
named=""
for who in "$(id -un)" "$(hostname -s 2>/dev/null)" "$(scutil --get LocalHostName 2>/dev/null)"; do
  [ "${#who}" -lt 3 ] || ! grep -qiwF -- "$who" "$info" || named="$named $who"
done
check 'build-info.txt names neither this user nor this machine' [ -z "$named" ]
xattr -w com.apple.quarantine '0081;00000000;Chrome;' "$folder/phantab"

# A fake Chrome user-data dir: two real profiles, the last-used one not Default; and Chrome's own Guest
# and System Profile folders, which have Preferences but are not in Local State's list.
for p in Default 'Profile 7' 'Guest Profile' 'System Profile'; do
  mkdir -p "$user_data/$p"
  echo '{}' >"$user_data/$p/Preferences"
done
local_state() { printf '{"profile":{"last_used":"%s","info_cache":{"Default":{"name":"Personal"},"Profile 7":{"name":"Work"}}}}' "$1" >"$user_data/Local State"; }
local_state 'Profile 7'
# Codex present (an empty config), Claude Code's file absent: install.sh must create it.
mkdir -p "$home/.codex"
: >"$home/.codex/config.toml"
claude="$home/.claude.json"
codex="$home/.codex/config.toml"
# A stand-in Chrome program: install records it and never starts it.
chrome="$tmp/Google Chrome"
printf '#!/bin/sh\nexit 0\n' >"$chrome"
chmod +x "$chrome"

run() { env -i HOME="$home" PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR="$tmp" /bin/bash "$@"; }
check 'no cargo, rustc, node or brew on the install PATH' \
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash -c '! command -v cargo && ! command -v rustc && ! command -v node && ! command -v brew' >/dev/null

echo '--- a changed file is refused'
cp -R "$folder" "$tmp/tampered"
echo ' ' >>"$tmp/tampered/extension/manifest.json"
said="$(run "$tmp/tampered/install.sh" --check-only 2>&1)"; rc=$?
ok=0; [ "$rc" = 1 ] && [[ "$said" == *"does not match SHA256SUMS"* ]] && ok=1
check 'install.sh refuses a bundle whose file changed' [ "$ok" = 1 ]

echo '--- install.sh --check-only'
said="$(run "$script" --check-only 2>&1)"; rc=$?
echo "$said"
check 'install.sh --check-only exits 0' [ "$rc" = 0 ]
check '--check-only installs nothing' [ ! -e "$runtime" ]
check 'the downloaded-file mark is cleared' bash -c "! xattr -p com.apple.quarantine '$folder/phantab' >/dev/null 2>&1"

echo '--- install.sh'
said="$(run "$script" --chrome "$chrome" 2>&1)"; rc=$?
echo "$said"
check 'install.sh exits 0' [ "$rc" = 0 ]
check "only Local State's profiles are offered" lacks 'Guest Profile|System Profile' "$said"
check 'the installed binary is the bundled one' [ "$(hash_of "$bin")" = "$(hash_of "$folder/phantab")" ]
check 'the extension is installed' test -f "$runtime/extension/manifest.json"
manifest="$user_data/NativeMessagingHosts/dev.phantab.bridge.json"
check 'the native host manifest is in the user-data dir' test -f "$manifest"
check 'the native host manifest names the installed binary' [ "$(jget "$manifest" d.path)" = "$bin" ]
check "bound to Chrome's last-used profile" [ "$(jget "$runtime/config.json" d.profileDirectory)" = 'Profile 7' ]
check 'bound to the Chrome user-data dir' [ "$(jget "$runtime/config.json" d.userDataDir)" = "$user_data" ]
check 'Claude Code entry phantab runs the installed binary' \
  [ "$(jget "$claude" "d.mcpServers['phantab'].command")" = "$bin" ]
check 'Claude Code entry args' [ "$(jget "$claude" "d.mcpServers['phantab'].args.join(' ')")" = 'mcp' ]
check 'Codex entry added' grep -qF '[mcp_servers."phantab"]' "$codex"
check 'the installed binary runs on the bare PATH' bash -c "env -i PATH=/usr/bin:/bin '$bin' install --help | grep -q 'Usage: phantab install'"

echo '--- install.sh again (an update over itself, another profile used last)'
local_state Default
run "$script" >/dev/null 2>&1; rc=$?
check 'a second install.sh exits 0' [ "$rc" = 0 ]
check 'an update keeps the bound profile' [ "$(jget "$runtime/config.json" d.profileDirectory)" = 'Profile 7' ]
run "$script" --profile Default >/dev/null 2>&1; rc=$?
ok=0; [ "$rc" = 0 ] && [ "$(jget "$runtime/config.json" d.profileDirectory)" = Default ] && ok=1
check '--profile rebinds' [ "$ok" = 1 ]

# Uninstall first, then --remove-files on its own run: the second run must see the finished uninstall and
# only delete the folder (a second `phantab uninstall` would refuse).
echo '--- install.sh --uninstall'
run "$script" --uninstall; rc=$?
check 'install.sh --uninstall exits 0' [ "$rc" = 0 ]
check '--uninstall alone keeps the files' test -f "$bin"
echo '--- install.sh --uninstall --remove-files (after the uninstall finished)'
run "$script" --uninstall --remove-files; rc=$?
check 'install.sh --uninstall --remove-files exits 0 after a finished uninstall' [ "$rc" = 0 ]
check 'the runtime folder is gone' [ ! -e "$runtime" ]
check 'Claude Code entry removed' [ -z "$(jget "$claude" "d.mcpServers&&d.mcpServers['phantab']")" ]
check 'Codex entry removed' bash -c "! grep -qF '[mcp_servers.\"phantab\"]' '$codex'"
check 'the native host manifest is removed' [ ! -e "$manifest" ]

after="$(live_state)"
check "this Mac's real phantab install, Claude and Codex configs are unchanged" [ "$after" = "$before" ]
[ "$after" = "$before" ] || printf 'before:\n%s\nafter:\n%s\n' "$before" "$after"

if [ "$failures" = 0 ]; then echo 'RESULT: PASSED'; exit 0; fi
echo "RESULT: FAILED ($failures)"; exit 1
