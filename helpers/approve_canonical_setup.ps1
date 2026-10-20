# APPROVE THE CANONICAL VIRULE SETUPS (helpers\canonical_setup.ps1).
#
# The ONE way a Setup binary becomes canonical. Normal releases never run
# this: they publish the pinned binaries unchanged. Both Setups are
# PERMANENT (owner ruling 2026-10-19). A re-cut happens only when the owner
# explicitly authorizes a change to Setup itself, and then BOTH downloaders
# are re-cut TOGETHER from ONE source commit, signed and verified together:
#
#   1. helpers\build.ps1 -Stage setup -Environment Production
#      helpers\build.ps1 -Stage setup -Environment Staging
#   2. sign both exact files with the VIRULE identity (sign_client_setup)
#   3. this script with -Production, -Staging, -SourceCommit and -Replace,
#      which verifies each signature, timestamp and environment, copies both
#      into release\setup\<environment>\ and pins their SHA-256 and size;
#      then commit release\setup\ and publish.
#
# It refuses to replace one environment alone. The ONLY single-environment
# approval it allows is pinning an environment that has no pin yet (the
# first staging Setup, 2026-10-19).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File helpers\approve_canonical_setup.ps1 `
#       -Production <signed exe> -Staging <signed exe> -SourceCommit <sha> -Replace
#   powershell -ExecutionPolicy Bypass -File helpers\approve_canonical_setup.ps1 `
#       -Staging <signed exe> -SourceCommit <sha>        # only while unpinned

param(
    [string]$Production,
    [string]$Staging,
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [switch]$Replace
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'canonical_setup.ps1')

$pin = Read-CanonicalSetupPin
$given = [ordered]@{}
if ($Production) { $given['production'] = $Production }
if ($Staging) { $given['staging'] = $Staging }
if ($given.Count -eq 0) { Stop-CanonicalSetup 'name at least one signed Setup (-Production / -Staging)' }

$replacing = @($given.Keys | Where-Object { $null -ne $pin.$_ })
if ($replacing.Count -gt 0) {
    if (-not $Replace) {
        Stop-CanonicalSetup ("already pinned: {0}. Setup is permanent; pass -Replace only for an owner-authorized change to Setup itself." -f ($replacing -join ', '))
    }
    if ($given.Count -ne 2) {
        Stop-CanonicalSetup 'a Setup change re-cuts BOTH downloaders together: pass -Production and -Staging, built from the same commit'
    }
}

# Verify every candidate before anything is copied or pinned.
foreach ($k in $given.Keys) {
    $envName = if ($k -eq 'production') { 'Production' } else { 'Staging' }
    Assert-SetupFile $given[$k] $envName "the candidate $envName Setup"
}

$out = [ordered]@{}
foreach ($k in 'production', 'staging') {
    if (-not $given.Contains($k)) { $out[$k] = $pin.$k; continue }
    $rel = "$k/Virule-Setup.exe"
    $dest = Join-Path $script:CanonicalSetupRoot $rel
    New-Item -ItemType Directory -Force (Split-Path -Parent $dest) | Out-Null
    if ((Resolve-Path -LiteralPath $given[$k]).Path -ne $dest) { Copy-Item -LiteralPath $given[$k] -Destination $dest -Force }
    $sig = Get-AuthenticodeSignature -LiteralPath $dest
    $out[$k] = [ordered]@{
        file             = $rel
        sha256           = (Get-SetupSha256 $dest)
        size             = (Get-Item -LiteralPath $dest).Length
        setupVersion     = [string](Get-Item -LiteralPath $dest).VersionInfo.FileVersion
        sourceCommit     = $SourceCommit
        signer           = $script:CanonicalSigner
        signerThumbprint = $sig.SignerCertificate.Thumbprint
        approved         = (Get-Date).ToString('yyyy-MM-dd')
    }
}
($out | ConvertTo-Json -Depth 4) | Out-File -Encoding ascii -LiteralPath $script:CanonicalSetupPin

foreach ($k in $given.Keys) {
    $envName = if ($k -eq 'production') { 'Production' } else { 'Staging' }
    $c = Get-CanonicalSetup $envName
    Write-Host "OK:   canonical $envName Setup approved: sha256=$($c.Sha256) size=$($c.Size) version=$($c.Version)" -ForegroundColor Green
}
Write-Host '      Commit release\setup\ and publish; normal releases reuse it unchanged.'
