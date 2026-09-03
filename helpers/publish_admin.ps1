# VIRULE Admin release publisher (Phase 2). Deterministic, minimal, and
# verification-first: it packages the canonical published Admin folder,
# publishes it as a GitHub Release asset on getvirule/virule-overlay-releases,
# and emits the EXACT admin-manifest JSON the virule.app Worker must serve.
#
# This is NOT the full release automation (Phase 3). It does, in order:
#   1. verifies Authenticode + the VIRULE signer identity on every
#      VIRULE-owned binary in the publish folder (CEF runtime files are
#      third-party and deliberately not required to carry our signature);
#   2. creates Virule-v<version>.zip with the publish folder's CONTENTS at
#      the zip root (virule.exe at root, .resources\ beside it), the exact
#      directory structure VIRULE requires;
#   3. computes the package SHA-256 and size;
#   4. creates the prerelease tag when missing and uploads the zip - but
#      REFUSES to replace an already-published package whose bytes differ;
#   5. re-downloads the public direct asset URL and verifies the hash;
#   6. prints the admin manifest JSON (version/url/sha256/size/
#      minimumClientVersion) to paste into VIRULE_BACKEND's client_service.
#
# It never signs anything (signing is centralized in
# VIRULE_SECURITY\artifact-signing) and never rebuilds anything.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File helpers\publish_admin.ps1 -Version 0.1.1-alpha.8
#   ... -Validate   packages and verifies signatures only; uploads nothing.

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+$')]
    [string]$Version,
    [string]$MinimumClientVersion = '0.2.0',
    [switch]$Validate
)

$ErrorActionPreference = 'Stop'

$publishDir = 'D:\Dropbox\Dropbox\development\VIRULE\v2_mvp\virule\publish\Virule'
$ghRepo     = 'getvirule/virule-overlay-releases'
$publicBase = "https://github.com/$ghRepo/releases/download"
$expectedSubject = 'CN=Heath Michaels'
$stageDir   = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\publish'

$tag       = "v$Version"
$zipName   = "Virule-v$Version.zip"
$zipPath   = Join-Path $stageDir $zipName
$publicUrl = "$publicBase/$tag/$zipName"

function Fail([string]$msg) { throw "ADMIN PUBLISH FAILED: $msg" }

function Invoke-Gh([string[]]$GhArgs, [switch]$AllowFail) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = (& gh @GhArgs 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
    if ($code -ne 0 -and -not $AllowFail) {
        Fail ("gh {0} failed (exit {1}):`n{2}" -f ($GhArgs -join ' '), $code, $out)
    }
    return @{ Code = $code; Out = $out }
}

function Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() }

# ---- 1. the publish folder and its signatures ----
if (-not (Test-Path (Join-Path $publishDir 'virule.exe'))) {
    Fail "publish folder has no virule.exe: $publishDir"
}

# Every VIRULE-owned binary in the package must be validly signed by the
# VIRULE identity. The stock CEF/Chromium runtime files (libcef, bootstrap,
# locales, ...) are third-party material and are excluded by this list.
$requiredSigned = @(
    'virule.exe',
    '.resources\admin\ViruleAdminHost.exe',
    '.resources\bin\Win32\SidecarK32.dll',
    '.resources\bin\Win32\SidecarKHost.exe',
    '.resources\bin\x64\SidecarK64.dll',
    '.resources\bin\x64\SidecarKHost.exe'
)
foreach ($rel in $requiredSigned) {
    $p = Join-Path $publishDir $rel
    if (-not (Test-Path $p)) { Fail "required signed file missing: $p" }
    $sig = Get-AuthenticodeSignature $p
    if ($sig.Status -ne 'Valid') { Fail "$rel is not validly signed (status: $($sig.Status))" }
    if ($sig.SignerCertificate.Subject -notlike "*$expectedSubject*") {
        Fail "$rel signer is not the VIRULE identity: $($sig.SignerCertificate.Subject)"
    }
    Write-Host "OK:   signed  $rel"
}

# ---- 2. the package: folder CONTENTS at the zip root ----
New-Item -ItemType Directory -Force $stageDir | Out-Null
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Write-Host "--    packaging $publishDir -> $zipPath"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $publishDir, $zipPath,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false)   # contents at root: virule.exe + .resources\ + ReadMe.md

# Sanity: the zip must carry virule.exe at its root.
$zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $rootExe = $zip.Entries | Where-Object { $_.FullName -eq 'virule.exe' }
    $entryCount = $zip.Entries.Count
} finally { $zip.Dispose() }
if (-not $rootExe) { Fail 'packaged zip does not carry virule.exe at its root' }

$zipSha  = Sha256 $zipPath
$zipSize = (Get-Item $zipPath).Length
Write-Host "OK:   package $zipName entries=$entryCount size=$zipSize sha256=$zipSha"

$manifestJson = '{{"version":"{0}","channel":"alpha","url":"{1}","sha256":"{2}","size":{3},"minimumClientVersion":"{4}"}}' -f `
    $Version, $publicUrl, $zipSha, $zipSize, $MinimumClientVersion

if ($Validate) {
    Write-Host ''
    Write-Host 'OK:   VALIDATION PASSED. Nothing was uploaded.' -ForegroundColor Green
    Write-Host "manifest: $manifestJson"
    return
}

# ---- 3. the release ----
$view = Invoke-Gh @('release', 'view', $tag, '-R', $ghRepo) -AllowFail
if ($view.Code -ne 0) {
    Write-Host "--    creating prerelease $tag"
    $notes = @"
Virule Admin Alpha v$Version

This is the public alpha release of Virule Admin for Windows. This software comes as-is with no warranties.

Install
The recommended path is https://virule.app - it installs and verifies VIRULE for you.

Manual run
Download the zip.
Extract it into a folder.
Run virule.exe.

Supports:
EFPSE
Unity
"@
    $null = Invoke-Gh @('release', 'create', $tag, '-R', $ghRepo,
        '--title', "Virule Admin [ALPHA] v$Version", '--prerelease',
        '--notes', $notes)
} else {
    Write-Host "OK:   release $tag already exists"
}

# ---- 4. the package asset (immutable once published) ----
$assets = Invoke-Gh @('release', 'view', $tag, '-R', $ghRepo, '--json', 'assets', '-q', '.assets[].name') -AllowFail
if ($assets.Code -eq 0 -and ($assets.Out -split "`n") -contains $zipName) {
    $tmpDir = Join-Path $stageDir ("remote_" + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force $tmpDir | Out-Null
    $null = Invoke-Gh @('release', 'download', $tag, '-R', $ghRepo, '--pattern', $zipName, '--dir', $tmpDir)
    $remoteSha = Sha256 (Join-Path $tmpDir $zipName)
    Remove-Item $tmpDir -Recurse -Force
    if ($remoteSha -eq $zipSha) {
        Write-Host 'OK:   package already published with identical bytes; leaving it.'
    } else {
        Fail ("IMMUTABILITY VIOLATION: $tag already carries $zipName with DIFFERENT bytes " +
              "(remote=$remoteSha local=$zipSha). Publish the next alpha instead.")
    }
} else {
    Write-Host "--    uploading $zipName ($([math]::Round($zipSize / 1MB)) MB)"
    $null = Invoke-Gh @('release', 'upload', $tag, '-R', $ghRepo, $zipPath)
    Write-Host 'OK:   uploaded'
}

# ---- 5. verify what the world will actually download ----
$tmp = Join-Path $stageDir ("verify_" + [IO.Path]::GetRandomFileName())
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $publicUrl -OutFile $tmp | Out-Null
} catch {
    Fail "package not downloadable from $publicUrl ($($_.Exception.Message))"
}
$publicSha = Sha256 $tmp
Remove-Item $tmp -Force
if ($publicSha -ne $zipSha) { Fail "$publicUrl served wrong bytes (got=$publicSha)" }
Write-Host "OK:   verified public asset at $publicUrl"

Write-Host ''
Write-Host 'SUCCESS: Admin release published and verified.' -ForegroundColor Green
Write-Host "  package  $publicUrl"
Write-Host ''
Write-Host 'Admin manifest for the virule.app Worker (client_service.ts):'
Write-Host "  $manifestJson"
