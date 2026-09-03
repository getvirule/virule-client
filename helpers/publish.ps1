# VIRULE distribution publisher: pushes the SIGNED Virule-Setup.exe and the
# SIGNED versioned virule-client.exe plus its manifest to the Cloudflare R2
# bucket behind https://downloads.virule.app.
#
# This is the minimum deterministic Phase-1 distribution publisher, NOT the
# full release automation. What it does, in order:
#   1. requires a VALID VIRULE Authenticode signature on every artifact it
#      is about to publish (it never signs anything itself);
#   2. computes the client's SHA-256 and size;
#   3. uploads the client to its IMMUTABLE versioned path
#      client/<version>/virule-client.exe (an existing remote object with
#      different bytes is a hard failure, never an overwrite);
#   4. generates and uploads client/manifest.json, the one mutable pointer
#      to the approved client release;
#   5. uploads Virule-Setup.exe only when its bytes actually changed;
#   6. re-downloads every touched object and verifies its hash;
#   7. fails clearly on any mismatch.
#
# Credentials follow the established VIRULE Cloudflare convention: the API
# token lives in the Windows User env var CLOUDFLARE_VIRULE_API_TOKEN and is
# exported to the wrangler child processes only for the life of this run.
# wrangler itself comes from the VIRULE_BACKEND repo's node_modules.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File helpers\publish.ps1            # publish
#   powershell -ExecutionPolicy Bypass -File helpers\publish.ps1 -Validate  # checks only

param(
    [switch]$Validate
)

$ErrorActionPreference = 'Stop'

$repo        = Split-Path -Parent $PSScriptRoot
$backendRepo = 'D:\Dropbox\Dropbox\development\VIRULE_BACKEND'
$bucket      = 'virule-downloads'
$publicBase  = 'https://downloads.virule.app'
$accountId   = 'ced7bb3fa764673bcea6f952378e9790'
$zoneId      = 'ea0b2025cd494d70fac6013b34301ea1'   # virule.app
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

# wrangler, run from the backend repo (its node_modules carries the pinned
# wrangler), with the VIRULE account context. Returns stdout lines; throws
# on nonzero exit unless -AllowFail.
function Invoke-Wrangler([string[]]$WranglerArgs, [switch]$AllowFail) {
    Push-Location $backendRepo
    try {
        $out = & npx --no-install wrangler @WranglerArgs 2>&1
        $code = $LASTEXITCODE
    } finally { Pop-Location }
    if ($code -ne 0 -and -not $AllowFail) {
        Fail ("wrangler {0} failed (exit {1}):`n{2}" -f ($WranglerArgs -join ' '), $code, ($out | Out-String))
    }
    return @{ Code = $code; Out = ($out | Out-String) }
}

# Downloads a remote object to a temp file via wrangler; $null when the key
# does not exist.
function Get-RemoteObjectHash([string]$key) {
    $tmp = Join-Path $stageDir ("remote_" + [IO.Path]::GetRandomFileName())
    $r = Invoke-Wrangler @('r2', 'object', 'get', "$bucket/$key", '--file', $tmp, '--remote') -AllowFail
    if ($r.Code -ne 0 -or -not (Test-Path $tmp)) {
        if ($r.Out -match 'does not exist|not found|404') { return $null }
        if ($r.Code -ne 0) { Fail "could not read remote object ${key}:`n$($r.Out)" }
        return $null
    }
    $h = Sha256 $tmp
    Remove-Item $tmp -Force
    return $h
}

function Put-RemoteObject([string]$key, [string]$file, [string]$contentType,
                          [string]$cacheControl, [string]$contentDisposition) {
    $putArgs = @('r2', 'object', 'put', "$bucket/$key", '--file', $file,
              '--content-type', $contentType, '--cache-control', $cacheControl,
              '--remote')
    if ($contentDisposition) { $putArgs += @('--content-disposition', $contentDisposition) }
    $null = Invoke-Wrangler $putArgs
    Write-Host "OK:   uploaded $key"
}

function Verify-PublicObject([string]$key, [string]$expectedSha) {
    $tmp = Join-Path $stageDir ("verify_" + [IO.Path]::GetRandomFileName())
    $url = "$publicBase/$key"
    try {
        # Cache-busting query so the edge cannot answer with a stale copy of
        # the mutable objects; R2 serves the object regardless.
        Invoke-WebRequest -UseBasicParsing -Uri ($url + "?v=" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -OutFile $tmp | Out-Null
    } catch {
        # The custom domain may not be attached/propagated yet; fall back to
        # reading back through R2 itself so the publish is still verified.
        Write-Host "WARN: $url not reachable ($($_.Exception.Message)); verifying through R2 directly." -ForegroundColor Yellow
        $remote = Get-RemoteObjectHash $key
        if ($remote -ne $expectedSha) { Fail "remote object $key hash mismatch (remote=$remote expected=$expectedSha)" }
        Write-Host "OK:   verified $key via R2 (sha256=$expectedSha)"
        return
    }
    $h = Sha256 $tmp
    Remove-Item $tmp -Force
    if ($h -ne $expectedSha) { Fail "$url served wrong bytes (got=$h expected=$expectedSha)" }
    Write-Host "OK:   verified $url (sha256=$expectedSha)"
}

# ---- credentials (established convention; never printed, never stored) ----
$token = [Environment]::GetEnvironmentVariable('CLOUDFLARE_VIRULE_API_TOKEN', 'User')
if ([string]::IsNullOrWhiteSpace($token)) { Fail 'CLOUDFLARE_VIRULE_API_TOKEN (User env var) is not set.' }
$env:CLOUDFLARE_API_TOKEN = $token
$env:CLOUDFLARE_ACCOUNT_ID = $accountId

try {
    # ---- version (from the client's one version source) ----
    $vline = (Get-Content $versionH) -match 'VIRULE_CLIENT_VERSION_STRING\s+"([^"]+)"'
    if (-not ($vline -and $vline[0] -match '"([^"]+)"')) { Fail "could not read VIRULE_CLIENT_VERSION_STRING from $versionH" }
    $version = $Matches[1]
    Write-Host "OK:   client version $version"

    # ---- gate: only signed artifacts are ever published ----
    Require-Signed $clientExe 'virule-client.exe'
    Require-Signed $setupExe  'Virule-Setup.exe'

    $clientSha  = Sha256 $clientExe
    $clientSize = (Get-Item $clientExe).Length
    $setupSha   = Sha256 $setupExe
    $clientKey  = "client/$version/virule-client.exe"
    $clientUrl  = "$publicBase/$clientKey"
    Write-Host "OK:   client sha256=$clientSha size=$clientSize"
    Write-Host "OK:   setup  sha256=$setupSha"

    New-Item -ItemType Directory -Force $stageDir | Out-Null

    # ---- the manifest: the one mutable pointer ----
    # COMPACT JSON on purpose: Setup's parser is the product's exact marker
    # scanner ("name":"value" with no whitespace); keep the wire form it
    # reads. PS 5.1's ConvertTo-Json inserts spaces, so emit by hand.
    $manifestPath = Join-Path $stageDir 'manifest.json'
    $manifestJson = '{{"version":"{0}","url":"{1}","sha256":"{2}","size":{3}}}' -f `
        $version, $clientUrl, $clientSha, $clientSize
    $manifestJson | Out-File -Encoding ascii -NoNewline $manifestPath
    $manifestSha = Sha256 $manifestPath
    Write-Host "OK:   manifest staged: $(Get-Content $manifestPath -Raw)"

    if ($Validate) {
        Write-Host ''
        Write-Host 'OK:   VALIDATION PASSED. Nothing was uploaded.' -ForegroundColor Green
        return
    }

    # ---- bucket + custom domain (idempotent provisioning) ----
    $buckets = Invoke-Wrangler @('r2', 'bucket', 'list')
    if ($buckets.Out -notmatch [regex]::Escape($bucket)) {
        Write-Host "--    creating R2 bucket $bucket"
        $null = Invoke-Wrangler @('r2', 'bucket', 'create', $bucket)
    }
    $domains = Invoke-Wrangler @('r2', 'bucket', 'domain', 'list', $bucket) -AllowFail
    if ($domains.Out -notmatch 'downloads\.virule\.app') {
        Write-Host '--    attaching custom domain downloads.virule.app'
        $null = Invoke-Wrangler @('r2', 'bucket', 'domain', 'add', $bucket,
            '--domain', 'downloads.virule.app', '--zone-id', $zoneId, '--min-tls', '1.2')
    }
    Write-Host "OK:   bucket $bucket + downloads.virule.app ready"

    # ---- 1. the IMMUTABLE versioned client ----
    $remoteClient = Get-RemoteObjectHash $clientKey
    if ($null -eq $remoteClient) {
        Put-RemoteObject $clientKey $clientExe 'application/octet-stream' `
            'public, max-age=31536000, immutable' 'attachment; filename="virule-client.exe"'
    } elseif ($remoteClient -eq $clientSha) {
        Write-Host "OK:   $clientKey already published with identical bytes; leaving it."
    } else {
        Fail ("IMMUTABILITY VIOLATION: $clientKey already exists remotely with DIFFERENT bytes " +
              "(remote=$remoteClient local=$clientSha). Bump VIRULE_CLIENT_VERSION and rebuild; " +
              'a published client version is never rewritten.')
    }

    # ---- 2. the manifest (mutable, short cache) ----
    Put-RemoteObject 'client/manifest.json' $manifestPath 'application/json' `
        'no-cache' ''

    # ---- 3. Virule-Setup.exe (stable binary, normal caching) ----
    $remoteSetup = Get-RemoteObjectHash 'Virule-Setup.exe'
    if ($remoteSetup -eq $setupSha) {
        Write-Host 'OK:   Virule-Setup.exe unchanged remotely; not re-uploaded.'
    } else {
        Put-RemoteObject 'Virule-Setup.exe' $setupExe 'application/octet-stream' `
            'public, max-age=300' 'attachment; filename="Virule-Setup.exe"'
    }

    # ---- 4. verify what the world will actually download ----
    Verify-PublicObject $clientKey $clientSha
    Verify-PublicObject 'client/manifest.json' $manifestSha
    Verify-PublicObject 'Virule-Setup.exe' $setupSha

    Write-Host ''
    Write-Host 'SUCCESS: distribution published and verified.' -ForegroundColor Green
    Write-Host "  setup    $publicBase/Virule-Setup.exe"
    Write-Host "  client   $clientUrl"
    Write-Host "  manifest $publicBase/client/manifest.json"
}
finally {
    $env:CLOUDFLARE_API_TOKEN = $null
    $env:CLOUDFLARE_ACCOUNT_ID = $null
}
