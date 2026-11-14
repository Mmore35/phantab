<#
.SYNOPSIS
  The Windows bundle's test: installs a built bundle zip from the zip alone into a throwaway user
  folder, checks every write, uninstalls, and checks it all came back. scripts/bundle-windows.sh runs it.

.DESCRIPTION
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-bundle\test-bundle.ps1 -Zip <zip>

  The install runs with USERPROFILE and LOCALAPPDATA pointed at a temp folder holding a fake Chrome
  profile set, PATH cut down to Windows' own folders (so no cargo, rustc, node or MinGW DLL can be
  found), and the native host registered under a scratch HKCU key (install.ps1 -NativeHostKey). The
  machine's real phantab install is never touched: the test hashes its native host registration, its
  runtime config and the real ~/.claude.json before and after, and fails if any changed.
#>
param(
    [Parameter(Mandatory = $true)][string]$Zip,
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
$failures = 0
function Pass($what) { Write-Host "  pass: $what" }
function Fail($what) { Write-Host "  FAIL: $what" -ForegroundColor Red; $script:failures++ }
function Check($cond, $what) { if ($cond) { Pass $what } else { Fail $what } }
function Hash-Of($path) {
    if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { '<absent>' }
}
function Entry-Of($path) {
    if (-not (Test-Path -LiteralPath $path)) { return '<absent>' }
    # Not ConvertFrom-Json: a real .claude.json on Windows holds project keys that differ only in case
    # (c:/x and C:/x), and Windows PowerShell 5.1's ConvertFrom-Json refuses those as duplicates.
    Add-Type -AssemblyName System.Web.Extensions
    $json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $json.MaxJsonLength = [int]::MaxValue
    $data = $json.DeserializeObject((Get-Content -LiteralPath $path -Raw))
    if (-not $data.ContainsKey('mcpServers')) { return '<none>' }
    return $json.Serialize($data['mcpServers'])
}
function Live-State {
    $key = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\dev.phantab.bridge'
    $value = '<absent>'
    if (Test-Path $key) { $value = (Get-Item $key).GetValue('') }
    $realLocal = [Environment]::GetFolderPath('LocalApplicationData')
    $realHome = [Environment]::GetFolderPath('UserProfile')
    return @(
        "host=$value",
        "runtime-config=$(Hash-Of (Join-Path $realLocal 'phantab\config.json'))",
        "runtime-record=$(Hash-Of (Join-Path $realLocal 'phantab\registration-v2.json'))",
        # Only the entry: Claude Code rewrites the rest of .claude.json all the time.
        "claude=$(Entry-Of (Join-Path $realHome '.claude.json'))",
        "codex=$(Hash-Of (Join-Path $realHome '.codex\config.toml'))"
    ) -join "`n"
}

$Zip = (Resolve-Path -LiteralPath $Zip).Path
$id = [guid]::NewGuid().ToString('N').Substring(0, 12)
$tmp = Join-Path ([IO.Path]::GetTempPath()) "phantab-bundle-test-$id"
$userHome = Join-Path $tmp 'home'
$local = Join-Path $userHome 'AppData\Local'
$runtime = Join-Path $local 'phantab'
$bin = Join-Path $runtime 'bin\phantab.exe'
$scratchRoot = "Software\phantab-bundle-test-$id"
$scratchKey = "HKCU\$scratchRoot\NativeMessagingHosts\dev.phantab.bridge"
$saved = @{}
foreach ($v in 'USERPROFILE', 'LOCALAPPDATA', 'PATH', 'PHANTAB_RUNTIME', 'CARGO_HOME', 'RUSTUP_HOME') {
    $saved[$v] = [Environment]::GetEnvironmentVariable($v, 'Process')
}

$before = Live-State
try {
    Write-Host "Bundle test: $Zip"
    Write-Host "  scratch user folder $userHome, scratch native host key $scratchKey"
    # The zip alone: unpacked into an empty folder, nothing from the checkout.
    $unzip = Join-Path $tmp 'unzipped'
    Expand-Archive -LiteralPath $Zip -DestinationPath $unzip
    $folder = Get-ChildItem -LiteralPath $unzip -Directory | Select-Object -First 1
    $script = Join-Path $folder.FullName 'install.ps1'
    Check (Test-Path $script) 'the zip holds one folder with install.ps1'

    # What ships beside the program: the licences, each listed in SHA256SUMS.txt, and a build-info that
    # names no folder, user or machine (bundle-windows.sh copies release.sh's).
    $sumsText = Get-Content -LiteralPath (Join-Path $folder.FullName 'SHA256SUMS.txt') -Raw
    foreach ($f in 'LICENSE', 'NOTICE', 'THIRD-PARTY-LICENSES', 'build-info.txt') {
        $listed = $sumsText -match "(?m)^[0-9a-f]{64}  $([regex]::Escape($f))\r?$"
        Check ((Test-Path -LiteralPath (Join-Path $folder.FullName $f)) -and $listed) "$f ships, listed in SHA256SUMS.txt"
    }
    $info = @(Get-Content -LiteralPath (Join-Path $folder.FullName 'build-info.txt'))
    foreach ($k in 'version', 'sha', 'target', 'rustc', 'cargo_lock_sha256', 'extension_lock_sha256', 'build_only') {
        Check (@($info | Where-Object { $_ -match "^$k=." }).Count -eq 1) "build-info.txt records $k"
    }
    $odd = @($info | Where-Object { $_ -notmatch '^[A-Za-z][A-Za-z0-9_. -]*=' -or $_ -match '[\\/]' })
    Check ($odd.Count -eq 0) "build-info.txt is key=value lines with no path in them ($($odd -join ' | '))"
    $names = @($env:USERNAME, $env:COMPUTERNAME) | Where-Object { $_ -and $_.Length -ge 3 }
    $named = @($names | Where-Object { ($info -join "`n") -match "(?i)\b$([regex]::Escape($_))\b" })
    Check ($named.Count -eq 0) "build-info.txt names neither this user nor this machine"

    # A fake Chrome user-data dir: two profiles, the last-used one not "Default", so the test sees
    # install.ps1 pick Chrome's last-used profile rather than a fixed name.
    $userData = Join-Path $local 'Google\Chrome\User Data'
    # Guest Profile and System Profile: Chrome's own folders, with Preferences but not in Local State's
    # list, which install.ps1 must not offer.
    foreach ($p in 'Default', 'Profile 7', 'Guest Profile', 'System Profile') {
        New-Item -ItemType Directory -Force -Path (Join-Path $userData $p) | Out-Null
        Set-Content -LiteralPath (Join-Path $userData "$p\Preferences") -Value '{}' -Encoding Ascii
    }
    Set-Content -LiteralPath (Join-Path $userData 'Local State') -Encoding Ascii -Value `
        '{"profile":{"last_used":"Profile 7","info_cache":{"Default":{"name":"Personal"},"Profile 7":{"name":"Work"}}}}'
    # Codex present (an empty config), Claude Code's file absent: install.ps1 must create it.
    New-Item -ItemType Directory -Force -Path (Join-Path $userHome '.codex') | Out-Null
    Set-Content -LiteralPath (Join-Path $userHome '.codex\config.toml') -Value '' -Encoding Ascii
    $claude = Join-Path $userHome '.claude.json'
    $codex = Join-Path $userHome '.codex\config.toml'

    $env:USERPROFILE = $userHome
    $env:LOCALAPPDATA = $local
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\WindowsPowerShell\v1.0"
    foreach ($v in 'PHANTAB_RUNTIME', 'CARGO_HOME', 'RUSTUP_HOME') { [Environment]::SetEnvironmentVariable($v, $null, 'Process') }
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    & $ps -NoProfile -Command 'if (Get-Command cargo, rustc, node, gcc, npm -ErrorAction SilentlyContinue) { exit 1 }'
    Check ($LASTEXITCODE -eq 0) 'no cargo, rustc, node, gcc or npm on the install PATH'

    Write-Host '--- a changed file is refused'
    $bad = Join-Path $tmp 'tampered'
    Copy-Item -LiteralPath $folder.FullName -Destination $bad -Recurse
    Add-Content -LiteralPath (Join-Path $bad 'extension\manifest.json') -Value ' '
    $said = & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $bad 'install.ps1') -CheckOnly *>&1 | Out-String
    Check ($LASTEXITCODE -eq 1 -and $said -match 'does not match SHA256SUMS') 'install.ps1 refuses a bundle whose file changed'

    # From here on, Constrained Language Mode: what AppLocker or WDAC puts an unsigned script in on a
    # managed PC. Not $env:__PSLockdownPolicy: Windows 11's PowerShell 5.1 ignores it in a process
    # environment. Instead each run lowers its own session to CLM first, and a script file it then
    # starts inherits that mode when no system policy is enforced (the probe proves it). The trap makes
    # an error that ends the script exit 1, as -File would.
    function Invoke-Clm($file, [string]$arguments) {
        & $ps -NoProfile -ExecutionPolicy Bypass -Command "trap { exit 1 }; `$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; & '$file' $arguments; exit `$LASTEXITCODE"
    }
    $probe = Join-Path $tmp 'probe.ps1'
    Set-Content -LiteralPath $probe -Encoding Ascii -Value '$ExecutionContext.SessionState.LanguageMode; exit 0'
    $mode = Invoke-Clm $probe ''
    Check ("$mode" -eq 'ConstrainedLanguage') "install.ps1 runs in Constrained Language Mode ($mode)"

    Write-Host '--- install.ps1 -CheckOnly'
    Invoke-Clm $script '-CheckOnly'
    Check ($LASTEXITCODE -eq 0) 'install.ps1 -CheckOnly exits 0'
    Check (-not (Test-Path $runtime)) '-CheckOnly installs nothing'

    Write-Host '--- install.ps1'
    $said = Invoke-Clm $script "-NativeHostKey '$scratchKey'" *>&1 | Out-String
    Write-Host $said
    Check ($LASTEXITCODE -eq 0) 'install.ps1 exits 0'
    Check ($said -notmatch 'Guest Profile|System Profile') "only Local State's profiles are offered"
    Check ((Hash-Of $bin) -eq (Hash-Of (Join-Path $folder.FullName 'phantab.exe'))) 'the installed binary is the bundled one'
    Check (Test-Path (Join-Path $runtime 'extension\manifest.json')) 'the extension is installed'
    Check (-not (Test-Path (Join-Path $local 'phantab-check'))) 'the unsigned-check copy is cleaned up'
    $hostValue = $null
    if (Test-Path "HKCU:\$scratchRoot\NativeMessagingHosts\dev.phantab.bridge") {
        $hostValue = (Get-Item "HKCU:\$scratchRoot\NativeMessagingHosts\dev.phantab.bridge").GetValue('')
    }
    Check ($hostValue -eq (Join-Path $runtime 'native-host.json')) "native host registered under the scratch key ($hostValue)"
    $manifest = Get-Content -LiteralPath (Join-Path $runtime 'native-host.json') -Raw | ConvertFrom-Json
    Check ($manifest.path -eq $bin) 'the native host manifest names the installed binary'
    $config = Get-Content -LiteralPath (Join-Path $runtime 'config.json') -Raw | ConvertFrom-Json
    Check ($config.profileDirectory -eq 'Profile 7') "bound to Chrome's last-used profile ($($config.profileDirectory))"
    Check ($config.userDataDir -eq $userData) 'bound to the Chrome user-data dir'
    $c = Get-Content -LiteralPath $claude -Raw
    Check ($c[0] -ne [char]0xFEFF) '.claude.json has no BOM'
    $entry = ($c | ConvertFrom-Json).mcpServers.'phantab'
    Check ($entry.command -eq $bin) "Claude Code entry phantab runs the installed binary"
    Check (($entry.args -join ' ') -eq 'mcp') "Claude Code entry args ($($entry.args -join ' '))"
    Check ((Get-Content -LiteralPath $codex -Raw) -match '\[mcp_servers\."phantab"\]') 'Codex entry added'
    $help = & $bin install --help
    Check ($LASTEXITCODE -eq 0 -and ($help -join "`n") -match 'Usage: phantab install') 'the installed binary runs on the bare PATH'

    # An update after the other profile was used last: it must stay bound where it was.
    Write-Host '--- install.ps1 again (an update over itself, another profile used last)'
    Set-Content -LiteralPath (Join-Path $userData 'Local State') -Encoding Ascii -Value `
        '{"profile":{"last_used":"Default","info_cache":{"Default":{"name":"Personal"},"Profile 7":{"name":"Work"}}}}'
    Invoke-Clm $script "-NativeHostKey '$scratchKey'"
    Check ($LASTEXITCODE -eq 0) 'a second install.ps1 exits 0'
    $config = Get-Content -LiteralPath (Join-Path $runtime 'config.json') -Raw | ConvertFrom-Json
    Check ($config.profileDirectory -eq 'Profile 7') "an update keeps the bound profile ($($config.profileDirectory))"
    Invoke-Clm $script "-NativeHostKey '$scratchKey' -ChromeProfile Default"
    $config = Get-Content -LiteralPath (Join-Path $runtime 'config.json') -Raw | ConvertFrom-Json
    Check ($LASTEXITCODE -eq 0 -and $config.profileDirectory -eq 'Default') "-ChromeProfile rebinds ($($config.profileDirectory))"

    # Uninstall first, then -RemoveFiles on its own run: the second run must see the finished uninstall
    # and only delete the folder (a second `phantab uninstall` would refuse).
    Write-Host '--- install.ps1 -Uninstall'
    Invoke-Clm $script '-Uninstall'
    Check ($LASTEXITCODE -eq 0) 'install.ps1 -Uninstall exits 0'
    Check (Test-Path $bin) '-Uninstall alone keeps the files'
    Write-Host '--- install.ps1 -Uninstall -RemoveFiles (after the uninstall finished)'
    Invoke-Clm $script '-Uninstall -RemoveFiles'
    Check ($LASTEXITCODE -eq 0) 'install.ps1 -Uninstall -RemoveFiles exits 0 after a finished uninstall'
    Check (-not (Test-Path $runtime)) 'the runtime folder is gone'
    $after = Get-Content -LiteralPath $claude -Raw | ConvertFrom-Json
    Check (-not ($after.mcpServers -and $after.mcpServers.'phantab')) 'Claude Code entry removed'
    Check (-not ((Get-Content -LiteralPath $codex -Raw) -match '\[mcp_servers\."phantab"\]')) 'Codex entry removed'
    $hostAfter = $null
    if (Test-Path "HKCU:\$scratchRoot\NativeMessagingHosts\dev.phantab.bridge") {
        $hostAfter = (Get-Item "HKCU:\$scratchRoot\NativeMessagingHosts\dev.phantab.bridge").GetValue('')
    }
    Check (-not $hostAfter) 'scratch native host registration removed'
} catch {
    Fail "the test itself failed: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)"
} finally {
    foreach ($v in $saved.Keys) { [Environment]::SetEnvironmentVariable($v, $saved[$v], 'Process') }
    if (Test-Path "HKCU:\$scratchRoot") { Remove-Item -LiteralPath "HKCU:\$scratchRoot" -Recurse -Force }
    if (-not $Keep -and (Test-Path $tmp)) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
$afterLive = Live-State
Check ($afterLive -eq $before) "this machine's real phantab install, Claude and Codex configs are unchanged"
if ($afterLive -ne $before) { Write-Host "before:`n$before`nafter:`n$afterLive" }

if ($failures -eq 0) { Write-Host 'RESULT: PASSED'; exit 0 }
Write-Host "RESULT: FAILED ($failures)"; exit 1
