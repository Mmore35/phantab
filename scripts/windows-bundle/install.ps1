<#
.SYNOPSIS
  Installs phantab from this folder for the current Windows user. No admin, no Rust, no Node.

.DESCRIPTION
  Run it from the unzipped bundle folder:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1

  1. Checks every file against SHA256SUMS.txt and clears the downloaded-file mark (Unblock-File).
  2. Tests that Windows lets an unsigned program run here and from %LOCALAPPDATA% the way Chrome starts
     phantab (through cmd.exe, or directly when Chrome's NativeHostsExecutablesLaunchDirectly policy is
     on). If not, it stops and says what blocked it and what to ask IT for (docs/INSTALL-WINDOWS.md).
  3. Runs `phantab.exe install`, which copies itself to %LOCALAPPDATA%\phantab\bin, the extension to
     %LOCALAPPDATA%\phantab\extension, registers the native host dev.phantab.bridge under HKCU, and adds
     the MCP entry to %USERPROFILE%\.claude.json (and to Codex's config.toml when that file exists).
  Nothing outside the user's own profile and HKCU is written.

  Afterwards (your step): in Chrome, chrome://extensions, Developer mode on, Load unpacked,
  pick %LOCALAPPDATA%\phantab\extension. Then restart Claude Code.

.PARAMETER ChromeProfile
  The Chrome profile folder to bind ("Default", "Profile 1"). Default: on a first install the profile
  Chrome used last; on a re-run (an update) the profile phantab is already bound to.
.PARAMETER ServerName
  The MCP entry's name. Default phantab.
.PARAMETER QuietDebugging
  Hide Chrome's "started debugging this browser" bar without asking: adds the flag to Chrome's own HKCU
  Run-key entry and the shortcuts that start it. Without it, phantab install asks once at a terminal.
.PARAMETER DevTools
  Turns the developer tools on: writes "devTools": true to phantab's config.json
  (docs/INSTALL-WINDOWS.md). A later run without -DevTools keeps it.
.PARAMETER CheckOnly
  Run only steps 1 and 2: the unsigned-program test. Installs nothing.
.PARAMETER SkipCheck
  Skip step 2. For a PC where IT allowed phantab.exe itself (a hash rule) but not the test program, or
  where Chrome's launch policy comes from the cloud and so is not visible to this script.
.PARAMETER Uninstall
  Undo the install: puts back the client entries and native host registration it replaced.
.PARAMETER RemoveFiles
  With -Uninstall: also delete %LOCALAPPDATA%\phantab (settings, logs, the installed copy). Remove the
  extension in Chrome and quit Claude Code first: a running phantab keeps the folder in use.
.PARAMETER NativeHostKey
  Tests only (scripts/windows-bundle/test-bundle.ps1): register the native host under this HKCU key
  instead of Chrome's, so a test never touches a real install.
#>
[CmdletBinding()]
param(
    [string]$ChromeProfile,
    [string]$ServerName = 'phantab',
    [switch]$QuietDebugging,
    [switch]$DevTools,
    [switch]$CheckOnly,
    [switch]$SkipCheck,
    [switch]$Uninstall,
    [switch]$RemoveFiles,
    [string]$NativeHostKey
)

# Written for Windows PowerShell 5.1 and for Constrained Language Mode, which AppLocker or WDAC puts an
# unsigned script in on a managed PC: cmdlets and $env: only, no .NET types, no Add-Type. Native programs
# run through Start-Process: a 5.1 `&` call that redirects stderr turns each stderr line into an error.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$runtime = Join-Path $env:LOCALAPPDATA 'phantab'
$installed = Join-Path $runtime 'bin\phantab.exe'
$claudeConfig = Join-Path $env:USERPROFILE '.claude.json'
$codexConfig = Join-Path $env:USERPROFILE '.codex\config.toml'

function Say($text) { Write-Host $text }
function Stop-Install($text) {
    Write-Host ''
    Write-Host "phantab install stopped: $text" -ForegroundColor Red
    exit 1
}

# Runs a program, never throwing. ok = it started and exited 0. A program Windows refuses to start
# throws from Start-Process (AppLocker: "blocked by group policy"); through cmd.exe the refusal is
# cmd's own text and exit code instead. Both come back in `text`.
# The file's SHA-256, lowercase. Get-FileHash first; certutil when it can't run (in a session where
# Constrained Language Mode also covers Microsoft's own modules, Get-FileHash cannot make its hasher).
function Get-Sha256($file) {
    try { return (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
    $out = & "$env:SystemRoot\System32\certutil.exe" -hashfile $file SHA256 2>$null
    foreach ($l in $out) {
        $h = ("$l" -replace ' ', '').ToLower()
        if ($h -match '^[0-9a-f]{64}$') { return $h }
    }
    Stop-Install "cannot compute a SHA-256 here (Get-FileHash and certutil both failed) for $file."
}

function Invoke-Program($file, $arguments) {
    $tmp = Join-Path $env:TEMP ('phantab-run-' + (Get-Random))
    $result = @{ ok = $false; code = $null; text = '' }
    # Start-Process refuses an empty -ArgumentList, so it is passed only when there is one.
    $start = @{ FilePath = $file; NoNewWindow = $true; Wait = $true; PassThru = $true
        RedirectStandardOutput = "$tmp.out"; RedirectStandardError = "$tmp.err" }
    if ($arguments) { $start.ArgumentList = $arguments }
    try {
        $p = Start-Process @start
        $result.code = $p.ExitCode
        $result.ok = ($p.ExitCode -eq 0)
    } catch {
        $result.text = $_.Exception.Message
    }
    foreach ($f in "$tmp.out", "$tmp.err") {
        if (Test-Path -LiteralPath $f) {
            $result.text = ($result.text + ' ' + (Get-Content -LiteralPath $f -Raw)).Trim()
            Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
        }
    }
    return $result
}

# The programs this script runs, each with its hash from SHA256SUMS.txt: what an allow rule names. A hash
# rule covers the file wherever it sits (this folder and %LOCALAPPDATA%\phantab\bin alike); a path rule for
# the installed copy alone would not cover the bundled copy the install runs from here.
function Get-RuleAsk {
    $lines = @()
    $sums = Join-Path $here 'SHA256SUMS.txt'
    if (Test-Path -LiteralPath $sums) {
        foreach ($line in Get-Content -LiteralPath $sums) {
            $parts = $line -split '  ', 2
            if ($parts.Count -eq 2 -and $parts[1] -like '*.exe') { $lines += "      $($parts[1])  SHA-256 $($parts[0])" }
        }
    }
    return " Ask IT for allow rules by file hash for:`n$($lines -join "`n")`n" +
        '    unsigned-check.exe is only this test: if IT allows phantab.exe alone, run this again with -SkipCheck. ' +
        'A hash rule must be redone for each new version.'
}

# Smart App Control's state (0 off, 1 on, 2 evaluating), readable without admin. Its block reports the
# same "Application Control policy has blocked this file" (0x800711C7) as WDAC, so the text alone cannot
# tell them apart.
function Test-SmartAppControlOn {
    try {
        $v = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction Stop
        return ($v.VerifiedAndReputablePolicyState -eq 1)
    } catch { return $false }
}

# Chrome 120+ starts an .exe native host directly, without cmd.exe, under the policy
# NativeHostsExecutablesLaunchDirectly. Read from the machine and user policy keys; a policy set only in
# the cloud (Chrome Browser Cloud Management) shows at chrome://policy but not here.
function Test-DirectLaunchPolicy {
    foreach ($key in 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKCU:\SOFTWARE\Policies\Google\Chrome') {
        try {
            $v = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
            if ($v.NativeHostsExecutablesLaunchDirectly -eq 1) { return $true }
        } catch { }
    }
    return $false
}

# What a refusal most likely was, and what to ask IT for (docs/INSTALL-WINDOWS.md, section 2's table). Keep
# this file ASCII: Windows PowerShell 5.1 reads a script without a BOM in the ANSI code page.
function Get-Explanation($result, $exe) {
    $t = "$($result.text) exit=$($result.code)"
    if (-not (Test-Path -LiteralPath $exe)) {
        return 'The file disappeared: antivirus (Defender or the company''s EDR) quarantined it.' + (Get-RuleAsk)
    }
    if ($t -match 'disabled by your administrator') {
        return 'The Command Prompt is turned off by policy (DisableCMD), and Chrome starts native messaging ' +
            'hosts through cmd.exe. Ask IT to turn on the Chrome policy NativeHostsExecutablesLaunchDirectly ' +
            '(Chrome 120 or later): Chrome then starts phantab directly, and the cmd.exe policy can stay. Once ' +
            'chrome://policy shows it, run this again (add -SkipCheck if it is set from the cloud).'
    }
    if ($t -match 'Smart App Control' -or ($t -match 'Application Control|4551|800711C7' -and (Test-SmartAppControlOn))) {
        return 'Smart App Control blocked it. It has no per-app exception: only a signed build, or Smart App ' +
            'Control turned off (IT''s call on a company PC), gets past it.'
    }
    if ($t -match 'Application Control|Device Guard|App Control|4551|800711C7') {
        return 'Windows Defender Application Control (WDAC / App Control for Business) blocked it.' + (Get-RuleAsk)
    }
    if ($t -match 'group policy|1260|Software Restriction') {
        return 'AppLocker (or Software Restriction Policies) blocked it: programs may not run from your user ' +
            'folders.' + (Get-RuleAsk)
    }
    if ($t -match 'Access is denied|denied') {
        return 'Windows denied it (Access is denied), usually AppLocker or WDAC.' + (Get-RuleAsk)
    }
    if ($result.ok) {
        return "It exited 0 but did not print what it should, so something else answered: $($result.text)"
    }
    return "It did not run, for a reason this script does not recognise: $($result.text)"
}

# Runs $exe and checks that it exited 0 and printed $expect: a refusal can exit 0 too (cmd.exe can, after
# printing its own error). Returns $null when it ran, else what blocked it, so the caller can clean up
# before it stops. -ViaCmd is how Chrome starts a native host by default: %COMSPEC% /d /s /c "<path>" <args>.
function Test-Runs($label, $exe, $arguments, $expect, [switch]$ViaCmd) {
    if ($ViaCmd) {
        $result = Invoke-Program "$env:SystemRoot\System32\cmd.exe" "/d /s /c `"`"$exe`" $arguments`""
    } else {
        $result = Invoke-Program $exe $arguments
    }
    if ($result.ok -and $result.text -like "*$expect*") {
        Say "  ok: $label"
        return $null
    }
    Say "  FAILED: $label"
    if ($result.text) { Say "    Windows said: $($result.text)" }
    return (Get-Explanation $result $exe)
}

function Get-RecordedConfigs {
    $record = Join-Path $runtime 'registration-v2.json'
    $configs = @()
    if (Test-Path -LiteralPath $record) {
        # The record's keys: one per client config it changed (the file's path), plus its own entries
        # (the native host, the binary). Only a key that is an existing .json or .toml file is a client.
        $data = Get-Content -LiteralPath $record -Raw | ConvertFrom-Json
        foreach ($key in ($data | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name })) {
            if (($key -like '*.json' -or $key -like '*.toml') -and (Test-Path -LiteralPath $key -PathType Leaf)) {
                $configs += $key
            }
        }
    }
    return $configs
}

function Get-ClientFlags($configs) {
    $flags = @()
    foreach ($c in $configs) {
        if ($c -like '*.toml') { $flags += @('--codex-config', $c) } else { $flags += @('--claude-config', $c) }
    }
    return $flags
}

# ---------------------------------------------------------------------------------------------- uninstall
if ($Uninstall) {
    if (-not (Test-Path -LiteralPath $runtime)) { Stop-Install "phantab is not installed in $runtime." }
    if ($RemoveFiles) {
        # Chrome keeps phantab.exe running while the extension is loaded, and a running copy keeps the
        # folder in use. Checked before anything changes, so stopping here leaves the install as it was.
        $running = @(Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -and $_.Path -like "$runtime\*" })
        if ($running.Count -gt 0) {
            Stop-Install ('phantab is still running, so its folder cannot be deleted. Remove the phantab ' +
                'extension at chrome://extensions (or quit Chrome) and quit Claude Code, then run this again. ' +
                'Nothing was changed.')
        }
    }
    # A finished uninstall drops the record's "binary" entry (crates/phantab/src/install/mod.rs). The
    # client entries and native host are then already put back, and a second `phantab uninstall` refuses
    # ("registration changed since install"), so only the folder is left to delete.
    $record = Join-Path $runtime 'registration-v2.json'
    $registered = $false
    if (Test-Path -LiteralPath $record) {
        $data = Get-Content -LiteralPath $record -Raw | ConvertFrom-Json
        $registered = @($data | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name }) -contains 'binary'
    }
    if ($registered) {
        if (-not (Test-Path -LiteralPath $installed)) { Stop-Install "phantab.exe is missing from $runtime\bin." }
        $configs = @(Get-RecordedConfigs)
        if ($configs.Count -eq 0) { Stop-Install "no client config is recorded in $record." }
        Say 'Removing phantab from:'
        $configs | ForEach-Object { Say "  $_" }
        $flags = @('uninstall', '--runtime', $runtime) + @(Get-ClientFlags $configs)
        & $installed @flags
        if ($LASTEXITCODE -ne 0) { Stop-Install "phantab uninstall exited $LASTEXITCODE (above)." }
    } else {
        Say 'phantab is already unregistered (an earlier uninstall finished).'
        if (-not $RemoveFiles) { Say "  Its files are still in $runtime; add -RemoveFiles to delete them." }
    }
    if ($RemoveFiles) {
        try {
            Remove-Item -LiteralPath $runtime -Recurse -Force
            Say "Deleted $runtime."
        } catch {
            Stop-Install "could not delete $runtime (phantab is probably still running). Quit Claude Code and Chrome, then run this again with -Uninstall -RemoveFiles; it then only deletes the folder."
        }
    }
    Say ''
    Say 'Done. If the phantab extension is still in Chrome, remove it at chrome://extensions. Then restart Claude Code.'
    exit 0
}

# ------------------------------------------------------------------------------------------------ install
$bundled = Join-Path $here 'phantab.exe'
$check = Join-Path $here 'unsigned-check.exe'
if (-not (Test-Path -LiteralPath $bundled)) { Stop-Install "run this from the unzipped bundle folder (no phantab.exe in $here)." }
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -and $env:PROCESSOR_ARCHITEW6432 -ne 'AMD64') {
    Say "Note: this PC is $($env:PROCESSOR_ARCHITECTURE); the bundle is x64 and runs under emulation on ARM64."
}

Say '[1/3] Checking the files'
$sums = Join-Path $here 'SHA256SUMS.txt'
if (-not (Test-Path -LiteralPath $sums)) { Stop-Install 'SHA256SUMS.txt is missing; unzip the whole bundle again.' }
$count = 0
foreach ($line in Get-Content -LiteralPath $sums) {
    if (-not $line.Trim()) { continue }
    $parts = $line -split '  ', 2
    $file = Join-Path $here ($parts[1] -replace '/', '\')
    if (-not (Test-Path -LiteralPath $file)) { Stop-Install "$($parts[1]) is missing; unzip the whole bundle again." }
    if ((Get-Sha256 $file) -ne $parts[0]) {
        Stop-Install "$($parts[1]) does not match SHA256SUMS.txt: the download is damaged or was changed."
    }
    # A downloaded zip marks every file it unpacks as from the internet; this is the user's own file.
    Unblock-File -LiteralPath $file -ErrorAction SilentlyContinue
    $count++
}
Say "  ok: $count files match SHA256SUMS.txt"

# How Chrome will start phantab: directly under the NativeHostsExecutablesLaunchDirectly policy, else
# through cmd.exe. The tests start it the same way, and expect each program's own output.
$direct = Test-DirectLaunchPolicy
$okCheck = 'unsigned-check: OK'
$okHelp = 'Usage: phantab install'
if ($SkipCheck) {
    Say '[2/3] Skipped (-SkipCheck)'
} else {
    Say '[2/3] Testing that Windows lets an unsigned program run'
    if ($direct) { Say '  Chrome policy NativeHostsExecutablesLaunchDirectly is on: Chrome starts phantab without cmd.exe.' }
    $why = Test-Runs 'unsigned-check.exe from this folder' $check '' $okCheck
    if ($why) { Stop-Install $why }
    $probeDir = Join-Path $env:LOCALAPPDATA 'phantab-check'
    New-Item -ItemType Directory -Force -Path $probeDir | Out-Null
    $probe = Join-Path $probeDir 'unsigned-check.exe'
    Copy-Item -LiteralPath $check -Destination $probe -Force
    $why = Test-Runs 'unsigned-check.exe from %LOCALAPPDATA%, started the way Chrome starts phantab' $probe '' $okCheck -ViaCmd:(-not $direct)
    Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
    if ($why) { Stop-Install $why }
    $why = Test-Runs 'phantab.exe itself' $bundled 'install --help' $okHelp
    if ($why) { Stop-Install $why }
}
if ($CheckOnly) {
    Say ''
    Say 'Check passed: unsigned programs run here. Nothing was installed.'
    exit 0
}

Say '[3/3] Installing for this user'
$userData = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
if (-not (Test-Path -LiteralPath $userData)) { Stop-Install "no Chrome profile data in $userData. Open Chrome once, then run this again." }
$profiles = @(Get-ChildItem -LiteralPath $userData -Directory |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'Preferences') } | ForEach-Object { $_.Name })
$names = $null
$lastUsed = $null
$localState = Join-Path $userData 'Local State'
if (Test-Path -LiteralPath $localState) {
    $state = Get-Content -LiteralPath $localState -Raw | ConvertFrom-Json
    if ($state.profile) {
        $names = $state.profile.info_cache
        $lastUsed = $state.profile.last_used
    }
}
# Local State lists the real profiles; "Guest Profile" and "System Profile" have a Preferences file too.
if ($names) {
    $listed = @($names | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name })
    $profiles = @($profiles | Where-Object { $listed -contains $_ })
}
# The binding phantab already has (its config.json). A re-run without -ChromeProfile keeps it, so an
# update never moves phantab to whichever profile happened to be used last; install then gets no --profile.
$bound = $null
$runtimeConfig = Join-Path $runtime 'config.json'
if (Test-Path -LiteralPath $runtimeConfig) {
    $cfg = Get-Content -LiteralPath $runtimeConfig -Raw | ConvertFrom-Json
    if ($cfg.profileDirectory -and $cfg.userDataDir) { $bound = $cfg.profileDirectory }
}
# Not $PSBoundParameters.ContainsKey: Constrained Language Mode refuses that method call.
$keep = $bound -and -not $ChromeProfile
if ($keep) { $ChromeProfile = $bound }
if (-not $ChromeProfile -and $lastUsed) { $ChromeProfile = $lastUsed }
if (-not $ChromeProfile) { $ChromeProfile = 'Default' }
Say '  Chrome profiles here:'
foreach ($p in $profiles) {
    $label = $p
    if ($names -and $names.$p -and $names.$p.name) { $label = "$p  ($($names.$p.name))" }
    $mark = ' '
    if ($p -eq $ChromeProfile) { $mark = '>' }
    Say "   $mark $label"
}
if ($profiles -notcontains $ChromeProfile) {
    Stop-Install "Chrome profile '$ChromeProfile' was not found. Pass one of the folders above: -ChromeProfile 'Profile 1'."
}
if ($keep) {
    Say "  Keeping the profile phantab is bound to, '$ChromeProfile'. To change it, add -ChromeProfile 'Profile 1'."
} else {
    Say "  Binding to '$ChromeProfile'. Load the extension in that same Chrome profile."
}

if (-not (Test-Path -LiteralPath $claudeConfig)) {
    # Plain ASCII: Windows PowerShell's UTF8 adds a BOM, and Claude Code's JSON parse refuses one.
    Set-Content -LiteralPath $claudeConfig -Value '{}' -Encoding Ascii
    Say "  Created $claudeConfig (Claude Code keeps it when it starts)."
}
$clients = @('--claude-config', $claudeConfig)
if (Test-Path -LiteralPath $codexConfig) { $clients += @('--codex-config', $codexConfig) }

$flags = @('install', '--runtime', $runtime)
if (-not $keep) { $flags += @('--user-data-dir', $userData, '--profile', $ChromeProfile) }
$flags += @('--server-name', $ServerName) + $clients
if ($NativeHostKey) { $flags += @('--native-host-key', $NativeHostKey) }
if ($QuietDebugging) { $flags += @('--quiet-debugging', 'on') }
if ($DevTools) { $flags += @('--dev-tools') }
& $bundled @flags
if ($LASTEXITCODE -ne 0) { Stop-Install "phantab install exited $LASTEXITCODE (its message is above)." }
$why = Test-Runs 'the installed phantab.exe, started the way Chrome starts it' $installed 'install --help' $okHelp -ViaCmd:(-not $direct)
if ($why) { Stop-Install "phantab is installed, but Chrome will not be able to start it. $why" }

Say ''
Say 'Installed. Two steps left, both yours:'
Say "  1. In Chrome ($ChromeProfile): open chrome://extensions, turn on Developer mode, click Load unpacked,"
Say "     and pick $runtime\extension"
Say "  2. Quit and reopen Claude Code. Its MCP entry is '$ServerName'."
if ($DevTools) { Say 'devTools is on in config.json: Claude Code lists the developer tools once it is reopened.' }
Say 'To undo: powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall -RemoveFiles'
exit 0
