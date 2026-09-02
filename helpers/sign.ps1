# Sign one VIRULE Client artifact through the EXISTING VIRULE Microsoft
# Artifact Signing workflow (VIRULE_SECURITY\artifact-signing): the same
# signtool.exe, the same Azure.CodeSigning dlib, the same metadata.json
# (endpoint / account / certificate profile), the same timestamp service.
# No new Azure credentials or configuration are introduced here; the dlib
# authenticates via DefaultAzureCredential exactly as the owner's signing
# control panel does.
#
# Usage:  powershell -ExecutionPolicy Bypass -File helpers\sign.ps1 -File <exe>

param(
    [Parameter(Mandatory = $true)][string]$File
)

$ErrorActionPreference = 'Stop'

$signingRoot = 'D:\Dropbox\Dropbox\development\VIRULE_SECURITY\artifact-signing'
$manifestPath = Join-Path $signingRoot 'manifest.json'
$metadataPath = Join-Path $signingRoot 'metadata.json'
if (-not (Test-Path $manifestPath)) { throw "signing manifest not found: $manifestPath" }
if (-not (Test-Path $metadataPath)) { throw "signing metadata not found: $metadataPath" }
if (-not (Test-Path $File)) { throw "file to sign not found: $File" }

$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$signtool = [string]$manifest.tools.signtool
$dlib = [string]$manifest.tools.dlib
$timestampUrl = [string]$manifest.tools.timestampUrl
if (-not (Test-Path $signtool)) { throw "signtool not found: $signtool" }
if (-not (Test-Path $dlib)) { throw "signing dlib not found: $dlib" }

Write-Host "signing: $File"
& $signtool sign /v /fd SHA256 /tr $timestampUrl /td SHA256 /dlib $dlib /dmdf $metadataPath $File
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed (exit $LASTEXITCODE)" }

& $signtool verify /pa $File
if ($LASTEXITCODE -ne 0) { throw "signtool verify /pa failed (exit $LASTEXITCODE)" }

$sig = Get-AuthenticodeSignature $File
Write-Host ("signed: {0} ({1})" -f $File, $sig.SignerCertificate.Subject)
if ($sig.Status -ne 'Valid') { throw "Authenticode status not Valid: $($sig.Status)" }
