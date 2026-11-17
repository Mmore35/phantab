#!/bin/bash
# Installs phantab from this folder for the current Mac user. No admin, no sudo, no Rust, no Node.
#
# Run it from the unzipped bundle folder, in Terminal:
#   bash install.sh
#
#   1. Checks every file against SHA256SUMS.txt.
#   2. Clears the downloaded-file mark (com.apple.quarantine) on this folder, so macOS lets the unsigned
#      phantab run, and checks that it does. If it still cannot run, it stops and says why.
#   3. Runs `phantab install`, which copies itself to ~/Library/Application Support/phantab/bin, the
#      extension to ~/Library/Application Support/phantab/extension, writes Chrome's native host manifest
#      (dev.phantab.bridge) into Chrome's NativeMessagingHosts folder, and adds the MCP entry to
#      ~/.claude.json (and to Codex's ~/.codex/config.toml when that file exists).
#   Nothing outside your own home folder is written.
#
# Afterwards (your step): in Chrome, chrome://extensions, Developer mode on, Load unpacked, pick
# ~/Library/Application Support/phantab/extension. Then restart Claude Code.
#
# Options:
#   --profile <folder>     the Chrome profile folder to bind ("Default", "Profile 1"). Default: on a first
#                          install the profile Chrome used last; on a re-run (an update) the one phantab
#                          is already bound to.
#   --server-name <name>   the MCP entry's name. Default phantab.
#   --chrome <path>        the Chrome program, when it is not /Applications/Google Chrome.app.
#   --work                 for a work laptop or a managed machine: writes "work": true and "devTools": true
#                          to phantab's config.json (docs/WORK-LAPTOP.md). A later run without it keeps both.
#   --check-only           steps 1 and 2 only. Installs nothing.
#   --uninstall            undo the install: puts back the client entries and the native host it replaced.
#   --remove-files         with --uninstall: also delete ~/Library/Application Support/phantab. Remove the
#                          extension in Chrome and quit Claude Code first.
# The Windows bundle's install.ps1 does the same; keep the two in step.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
support="$HOME/Library/Application Support"
runtime="$support/phantab"
installed="$runtime/bin/phantab"
user_data="$support/Google/Chrome"
claude_config="$HOME/.claude.json"
codex_config="$HOME/.codex/config.toml"

say() { printf '%s\n' "$*"; }
stop() { printf '\nphantab install stopped: %s\n' "$*" >&2; exit 1; }

profile="" server_name=phantab chrome="" work=0 check_only=0 uninstall=0 remove_files=0
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) [ $# -ge 2 ] || stop "--profile needs a folder name"; profile="$2"; shift ;;
    --server-name) [ $# -ge 2 ] || stop "--server-name needs a name"; server_name="$2"; shift ;;
    --chrome) [ $# -ge 2 ] || stop "--chrome needs a path"; chrome="$2"; shift ;;
    --work) work=1 ;;
    --check-only) check_only=1 ;;
    --uninstall) uninstall=1 ;;
    --remove-files) remove_files=1 ;;
    -h|--help) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) stop "unknown option $1 (see bash install.sh --help)" ;;
  esac
  shift
done
[ "$remove_files" = 0 ] || [ "$uninstall" = 1 ] || stop "--remove-files goes with --uninstall"

# Reads a JSON file with macOS's own JavaScript (osascript), since a Mac has no jq. json <file> <key>...
# prints the value at that key path, or "" when it is missing; a last key of "*keys" lists the object's
# keys, one per line.
json() {
  [ -f "$1" ] || return 0
  /usr/bin/osascript -l JavaScript -e '
    ObjC.import("Foundation");
    function run(a) {
      try {
        var s = $.NSString.stringWithContentsOfFileEncodingError(a[0], $.NSUTF8StringEncoding, null);
        var v = JSON.parse(ObjC.unwrap(s));
        for (var i = 1; i < a.length; i++) {
          if (a[i] === "*keys") return Object.keys(v || {}).join("\n");
          if (v === null || typeof v !== "object") return "";
          v = v[a[i]];
        }
        return (v === undefined || v === null) ? "" : String(v);
      } catch (e) { return ""; }
    }' "$@" 2>/dev/null || true
}

# The client configs the record lists: its keys that are an existing .json or .toml file (the others are
# its own entries, the native host and the binary).
recorded_client_flags() {
  local key
  json "$runtime/registration-v2.json" '*keys' | while IFS= read -r key; do
    [ -f "$key" ] || continue
    case "$key" in
      *.toml) printf '%s\n%s\n' --codex-config "$key" ;;
      *.json) printf '%s\n%s\n' --claude-config "$key" ;;
    esac
  done
}

# ---------------------------------------------------------------------------------------------- uninstall
if [ "$uninstall" = 1 ]; then
  [ -d "$runtime" ] || stop "phantab is not installed in $runtime."
  if [ "$remove_files" = 1 ] && pgrep -f "$installed" >/dev/null 2>&1; then
    stop "phantab is still running. Remove the phantab extension at chrome://extensions (or quit Chrome) and quit Claude Code, then run this again. Nothing was changed."
  fi
  # A finished uninstall drops the record's "binary" entry; a second `phantab uninstall` would refuse,
  # so then only the folder is left to delete.
  # Read whole first: with pipefail, grep -q stopping early could fail the pipe on a SIGPIPE.
  record_keys="$(json "$runtime/registration-v2.json" '*keys')"
  if printf '%s\n' "$record_keys" | grep -qx binary; then
    [ -x "$installed" ] || stop "phantab is missing from $runtime/bin."
    flags=()
    while IFS= read -r f; do flags+=("$f"); done < <(recorded_client_flags)
    [ "${#flags[@]}" -gt 0 ] || stop "no client config is recorded in $runtime/registration-v2.json."
    say "Removing phantab from:"
    for ((i = 1; i < ${#flags[@]}; i += 2)); do say "  ${flags[$i]}"; done
    "$installed" uninstall --runtime "$runtime" "${flags[@]}" || stop "phantab uninstall failed (above)."
  else
    say "phantab is already unregistered (an earlier uninstall finished)."
    [ "$remove_files" = 1 ] || say "  Its files are still in $runtime; add --remove-files to delete them."
  fi
  if [ "$remove_files" = 1 ]; then
    rm -rf "$runtime" || stop "could not delete $runtime."
    say "Deleted $runtime."
  fi
  say ""
  say "Done. If the phantab extension is still in Chrome, remove it at chrome://extensions. Then restart Claude Code."
  exit 0
fi

# ------------------------------------------------------------------------------------------------ install
bundled="$here/phantab"
[ -f "$bundled" ] || stop "run this from the unzipped bundle folder (no phantab in $here)."
[ "$(uname -m)" = arm64 ] || stop "this bundle is for Apple silicon (arm64); this Mac is $(uname -m)."

say "[1/3] Checking the files"
sums="$here/SHA256SUMS.txt"
[ -f "$sums" ] || stop "SHA256SUMS.txt is missing; unzip the whole bundle again."
count=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  want="${line%%  *}"
  name="${line#*  }"
  [ -f "$here/$name" ] || stop "$name is missing; unzip the whole bundle again."
  [ "$(shasum -a 256 "$here/$name" | cut -d' ' -f1)" = "$want" ] ||
    stop "$name does not match SHA256SUMS.txt: the download is damaged or was changed."
  count=$((count + 1))
done <"$sums"
say "  ok: $count files match SHA256SUMS.txt"

say "[2/3] Letting the unsigned phantab run"
# A browser download marks every file it unpacks as from the internet, and macOS then refuses to run an
# unsigned program ("cannot be opened because the developer cannot be verified"). This is your own file.
xattr -dr com.apple.quarantine "$here" 2>/dev/null || true
chmod +x "$bundled"
if ! said="$("$bundled" install --help 2>&1)" || [[ "$said" != *"Usage: phantab install"* ]]; then
  [ -n "$said" ] && say "  macOS said: $said"
  stop "phantab does not run here. If a window said it cannot be verified: System Settings, Privacy & Security, Open Anyway, then run this again. On a company Mac the device policy may forbid unsigned programs: ask IT to allow phantab (its SHA-256 is in SHA256SUMS.txt)."
fi
say "  ok: phantab runs"
if [ "$check_only" = 1 ]; then
  say ""
  say "Check passed: phantab runs here. Nothing was installed."
  exit 0
fi

say "[3/3] Installing for this user"
[ -d "$user_data" ] || stop "no Chrome profile data in $user_data. Open Chrome once, then run this again."
# The real profiles: folders with a Preferences file that Local State lists ("Guest Profile" and
# "System Profile" have a Preferences file too).
listed="$(json "$user_data/Local State" profile info_cache '*keys')"
profiles=()
for d in "$user_data"/*/; do
  p="$(basename "$d")"
  [ -f "$d/Preferences" ] || continue
  if [ -n "$listed" ] && ! printf '%s\n' "$listed" | grep -qxF "$p"; then continue; fi
  profiles+=("$p")
done
# The binding phantab already has: a re-run without --profile keeps it, so an update never moves phantab
# to whichever profile happened to be used last; install then gets no --profile.
bound=""
if [ -n "$(json "$runtime/config.json" userDataDir)" ]; then bound="$(json "$runtime/config.json" profileDirectory)"; fi
keep=0
if [ -n "$bound" ] && [ -z "$profile" ]; then keep=1; profile="$bound"; fi
[ -n "$profile" ] || profile="$(json "$user_data/Local State" profile last_used)"
[ -n "$profile" ] || profile=Default
say "  Chrome profiles here:"
found=0
for p in ${profiles[@]+"${profiles[@]}"}; do
  label="$p"
  name="$(json "$user_data/Local State" profile info_cache "$p" name)"
  [ -z "$name" ] || label="$p  ($name)"
  if [ "$p" = "$profile" ]; then say "   > $label"; found=1; else say "     $label"; fi
done
[ "$found" = 1 ] || stop "Chrome profile '$profile' was not found. Pass one of the folders above: --profile 'Profile 1'."
if [ "$keep" = 1 ]; then
  say "  Keeping the profile phantab is bound to, '$profile'. To change it, add --profile 'Profile 1'."
else
  say "  Binding to '$profile'. Load the extension in that same Chrome profile."
fi

if [ ! -f "$claude_config" ]; then
  printf '{}\n' >"$claude_config"
  say "  Created $claude_config (Claude Code keeps it when it starts)."
fi
flags=(install --runtime "$runtime")
[ "$keep" = 1 ] || flags+=(--user-data-dir "$user_data" --profile "$profile")
[ -z "$chrome" ] || flags+=(--chrome "$chrome")
flags+=(--server-name "$server_name" --claude-config "$claude_config")
[ ! -f "$codex_config" ] || flags+=(--codex-config "$codex_config")
[ "$work" = 0 ] || flags+=(--work)
"$bundled" "${flags[@]}" || stop "phantab install failed (its message is above)."
said="$("$installed" install --help 2>&1)" || true
[[ "$said" == *"Usage: phantab install"* ]] || stop "phantab is installed, but the installed copy does not run: $said"

say ""
say "Installed. Two steps left, both yours:"
say "  1. In Chrome ($profile): open chrome://extensions, turn on Developer mode, click Load unpacked,"
say "     and pick $runtime/extension (in the file picker, Cmd+Shift+G and paste that path)"
say "  2. Quit and reopen Claude Code. Its MCP entry is '$server_name'."
[ "$work" = 0 ] || say "work and devTools are on in config.json; browser_status lists what work turned off."
say "To undo: bash install.sh --uninstall --remove-files"
