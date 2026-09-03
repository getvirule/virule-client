# VIRULE distribution publisher: pushes the SIGNED Virule-Setup.exe, the
# SIGNED virule-client.exe and its manifest.json to the versioned GitHub
# Release on getvirule/virule-client. GitHub Releases are the MVP binary
# distribution source; the LATEST release's manifest is the mutable pointer
# Virule-Setup.exe follows at install time.
#
# This is the minimum deterministic Phase-1 distribution publisher, NOT the
# full release automation. What it does, in order:
#   1. requires a VALID VIRULE Authenticode signature on every artifact it
#      is about to publish (it never signs anything itself);
#   2. computes the client's SHA-256 and size;
#   3. generates manifest.json (version / direct asset url / sha256 / size);
#   4. creates the release tag v<version> when it does not exist yet;
#   5. uploads virule-client.exe, Virule-Setup.exe and manifest.json - but
#      REFUSES to replace an already-published virule-client.exe whose
#      bytes differ (a published client version is never rewritten; bump
#      VIRULE_CLIENT_VERSION instead);
#   6. re-downloads every asset from its public direct URL and verifies the
#      hash against the local signed artifact;
#   7. fails clearly on any mismatch.
#
# Authentication is the machine's existing `gh` login (org member with repo
# scope); nothing is stored here. GitHub is a HOST, not a trust anchor:
# Setup independently enforces manifest SHA-256 + Authenticode + the VIRULE
# signer identity on what it downloads.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File helpers\publish.ps1            # publish
#   powershell -ExecutionPolicy Bypass -File helpers\publish.ps1 -Validate  # checks only

param(
    [switch]$Validate
)

$ErrorActionPreference = 'Stop'

$repo       = Split-Path -Parent $PSScriptRoot
$ghRepo     = 'getvirule/virule-client'
$publicBase = "https://github.com/$ghRepo/releases/download"
$expectedSubject = 'CN=Heath Michaels'

$clientExe = Join-Path $repo 'build\Release\x64\virule-client.exe'
$setupExe  = Join-Path $repo 'build\Release\x64\Virule-Setup.exe'
$versionH  = Join-Path $repo 'src\shared\version.h'
$stageDir  = Join-Path $repo 'build\publish'

function Fail([string]$msg) { throw "PUBLISH FAILED: $msg" }

function Require-Signed([string]$path, [string]$label) {
    if (-not (Test-Path $path)) { Fail "$label missing: $path" }
    $sig = Get-AuthenticodeSignature $path
    if ($sig.Status -ne 'Valid') { Fail "$label is not validly signed (status: $($sig.Status)). Sign it first; this tool never publishes unsigned binaries." }
    if ($sig.SignerCertificate.Subject -notlike "*$expectedSubject*") {
        Fail "$label signer is not the VIRULE identity: $($sig.SignerCertificate.Subject)"
    }
    Write-Host "OK:   $label signed ($($sig.SignerCertificate.Subject))"
}

function Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() }

function Invoke-Gh([string[]]$GhArgs, [switch]$AllowFail) {
    $out = & gh @GhArgs 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowFail) {
        Fail ("gh {0} failed (exit {1}):`n{2}" -f ($GhArgs -join ' '), $code, ($out | Out-String))
    }
    return @{ Code = $code; Out = ($out | Out-String) }
}

# Downloads one published release asset to a temp file; $null when the
# asset does not exist on the release.
function Get-RemoteAssetHash([string]$tag, [string]$asset) {
    $tmpDir = Join-Path $stageDir ("remote_" + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force $tmpDir | Out-Null
    $r = Invoke-Gh @('release', 'download', $tag, '-R', $ghRepo, '--pattern', $asset, '--dir', $tmpDir) -AllowFail
    $file = Join-Path $tmpDir $asset
    if ($r.Code -ne 0 -or -not (Test-Path $file)) {
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        if ($r.Code -ne 0 -and $r.Out -notmatch 'no assets|not found|release not found') {
            Fail "could not probe remote asset ${asset}:`n$($r.Out)"
        }
        return $null
    }
    $h = Sha256 $file
    Remove-Item $tmpDir -Recurse -Force
    return $h
}

# Verifies what the world actually downloads: the PUBLIC direct asset URL.
function Verify-PublicAsset([string]$url, [string]$expectedSha, [string]$label) {
    $tmp = Join-Path $stageDir ("verify_" + [IO.Path]::GetRandomFileName())
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp | Out-Null
    } catch {
        Fail "$label not downloadable from $url ($($_.Exception.Message))"
    }
    $h = Sha256 $tmp
    Remove-Item $tmp -Force
    if ($h -ne $expectedSha) { Fail "$url served wrong bytes (got=$h expected=$expectedSha)" }
    Write-Host "OK:   verified $label at $url"
}

# ---- version (from the client's one version source) ----
$vline = (Get-Content $versionH) -match 'VIRULE_CLIENT_VERSION_STRING\s+"([^"]+)"'
if (-not ($vline -and $vline[0] -match '"([^"]+)"')) { Fail "could not read VIRULE_CLIENT_VERSION_STRING from $versionH" }
$version = $Matches[1]
$tag = "v$version"
Write-Host "OK:   client version $version (release tag $tag)"

# ---- gate: only signed artifacts are ever published ----
Require-Signed $clientExe 'virule-client.exe'
Require-Signed $setupExe  'Virule-Setup.exe'

$clientSha  = Sha256 $clientExe
$clientSize = (Get-Item $clientExe).Length
$setupSha   = Sha256 $setupExe
$clientUrl  = "$publicBase/$tag/virule-client.exe"
Write-Host "OK:   client sha256=$clientSha size=$clientSize"
Write-Host "OK:   setup  sha256=$setupSha"

New-Item -ItemType Directory -Force $stageDir | Out-Null

# ---- the manifest: the one mutable pointer ----
# COMPACT JSON on purpose: Setup's parser is the product's exact marker
# scanner ("name":"value" with no whitespace); keep the wire form it reads.
$manifestPath = Join-Path $stageDir 'manifest.json'
$manifestJson = '{{"version":"{0}","url":"{1}","sha256":"{2}","size":{3}}}' -f `
    $version, $clientUrl, $clientSha, $clientSize
$manifestJson | Out-File -Encoding ascii -NoNewline $manifestPath
$manifestSha = Sha256 $manifestPath
Write-Host "OK:   manifest staged: $manifestJson"

if ($Validate) {
    Write-Host ''
    Write-Host 'OK:   VALIDATION PASSED. Nothing was uploaded.' -ForegroundColor Green
    return
}

# ---- the release (created once; publishing to it moves 'latest') ----
$view = Invoke-Gh @('release', 'view', $tag, '-R', $ghRepo) -AllowFail
if ($view.Code -ne 0) {
    Write-Host "--    creating release $tag"
    $null = Invoke-Gh @('release', 'create', $tag, '-R', $ghRepo,
        '--title', "VIRULE Client $version", '--latest',
        '--notes', "VIRULE Client $version. Virule-Setup.exe installs the client release this release's manifest.json describes, after verifying its SHA-256, Authenticode signature, and signer identity.")
} else {
    Write-Host "OK:   release $tag already exists"
}

# ---- 1. the IMMUTABLE versioned client ----
$remoteClient = Get-RemoteAssetHash $tag 'virule-client.exe'
if ($null -eq $remoteClient) {
    $null = Invoke-Gh @('release', 'upload', $tag, '-R', $ghRepo, $clientExe)
    Write-Host 'OK:   uploaded virule-client.exe'
} elseif ($remoteClient -eq $clientSha) {
    Write-Host 'OK:   virule-client.exe already published with identical bytes; leaving it.'
} else {
    Fail ("IMMUTABILITY VIOLATION: $tag already carries a virule-client.exe with DIFFERENT bytes " +
          "(remote=$remoteClient local=$clientSha). Bump VIRULE_CLIENT_VERSION and rebuild; " +
          'a published client version is never rewritten.')
}

# ---- 2. the manifest (mutable pointer; safe to replace) ----
$null = Invoke-Gh @('release', 'upload', $tag, '-R', $ghRepo, $manifestPath, '--clobber')
Write-Host 'OK:   uploaded manifest.json'

# ---- 3. Virule-Setup.exe (replaced when its bytes changed) ----
$remoteSetup = Get-RemoteAssetHash $tag 'Virule-Setup.exe'
if ($remoteSetup -eq $setupSha) {
    Write-Host 'OK:   Virule-Setup.exe unchanged remotely; not re-uploaded.'
} else {
    $null = Invoke-Gh @('release', 'upload', $tag, '-R', $ghRepo, $setupExe, '--clobber')
    Write-Host 'OK:   uploaded Virule-Setup.exe'
}

# ---- 4. verify what the world will actually download ----
Verify-PublicAsset "$publicBase/$tag/virule-client.exe" $clientSha 'virule-client.exe'
Verify-PublicAsset "$publicBase/$tag/manifest.json" $manifestSha 'manifest.json'
Verify-PublicAsset "$publicBase/$tag/Virule-Setup.exe" $setupSha 'Virule-Setup.exe'
# The pointer Setup actually follows: the LATEST release's manifest.
Verify-PublicAsset "https://github.com/$ghRepo/releases/latest/download/manifest.json" $manifestSha 'latest manifest pointer'

Write-Host ''
Write-Host 'SUCCESS: GitHub release published and verified.' -ForegroundColor Green
Write-Host "  setup    $publicBase/$tag/Virule-Setup.exe"
Write-Host "  client   $clientUrl"
Write-Host "  manifest $publicBase/$tag/manifest.json"
Write-Host "  pointer  https://github.com/$ghRepo/releases/latest/download/manifest.json"
