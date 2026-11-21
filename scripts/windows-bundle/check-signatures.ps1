<#
.SYNOPSIS
  Checks that files carry a valid Authenticode signature by one expected signer, with a timestamp.
  scripts/sign-windows.sh (seal) and scripts/bundle-windows.sh run it, through
  scripts/windows-bundle/common.sh.

.DESCRIPTION
  $env:PHANTAB_SIGNER = '<the certificate subject>'
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-bundle\check-signatures.ps1 -Folder <folder> <file name>...

  Each file passes only when all of these hold:
    - Get-AuthenticodeSignature says Valid: the bytes are what was signed, and this Windows trusts the
      certificate's chain.
    - The signature is in the file itself (not a catalog on this machine), so it travels with the file.
    - The signer certificate's subject is exactly $env:PHANTAB_SIGNER, compared as text, case and all.
    - There is a timestamp. The signing certificates last days; without a timestamp the signature ends
      when the certificate does.
  Exits 0 when every file passes, 1 otherwise. Each failure prints the subject it found, so a wrong
  PHANTAB_SIGNER can be corrected from the output.
#>
param(
    [Parameter(Mandatory = $true)][string]$Folder,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Files
)
$ErrorActionPreference = 'Stop'
$signer = $env:PHANTAB_SIGNER
if (-not $signer) { Write-Host 'check-signatures.ps1: PHANTAB_SIGNER is not set (the signing certificate subject).'; exit 1 }
if (-not $Files -or $Files.Count -eq 0) { Write-Host 'check-signatures.ps1: no file named.'; exit 1 }

$bad = 0
foreach ($name in $Files) {
    $file = Join-Path $Folder $name
    $why = $null
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        $why = 'it is missing'
    } else {
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        $subject = ''
        if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
        if ("$($sig.Status)" -eq 'NotSigned') {
            $why = 'it is not signed'
        } elseif ("$($sig.Status)" -ne 'Valid') {
            $why = "its signature is $($sig.Status), by '$subject': $($sig.StatusMessage)"
        } elseif ("$($sig.SignatureType)" -ne 'Authenticode') {
            $why = "its signature is not in the file ($($sig.SignatureType)), so it would not travel with it"
        } elseif ($subject -cne $signer) {
            $why = "it is signed by '$subject', not by '$signer'"
        } elseif (-not $sig.TimeStamperCertificate) {
            $why = 'its signature has no timestamp, so it ends when the certificate does'
        }
    }
    if ($why) {
        Write-Host "  FAIL: ${name}: $why"
        $bad++
    } else {
        Write-Host "  ok: ${name}: signed by '$subject', timestamped"
    }
}
if ($bad -gt 0) { exit 1 }
exit 0
