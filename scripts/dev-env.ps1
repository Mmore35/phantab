# Dot-source before cargo on Windows with the GNU toolchain:  . .\scripts\dev-env.ps1   (why: scripts/dev-env.sh)
$cargo = Join-Path $HOME '.cargo\bin'
if (Test-Path $cargo) { $env:PATH = "$cargo;$env:PATH" }
$bin = Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages') -Filter 'BrechtSanders.WinLibs.*' -Directory -ErrorAction SilentlyContinue |
  ForEach-Object { Join-Path $_.FullName 'mingw64\bin' } | Where-Object { Test-Path (Join-Path $_ 'dlltool.exe') } | Select-Object -First 1
if ($bin) { $env:PATH = "$bin;$env:PATH" }
