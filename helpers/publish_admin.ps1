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
# -Environment Staging publishes the UNSIGNED STAGING Admin package instead:
# same packaging, same hash and size discipline, same public re-download
# proof, but sourced from virule\publish\Virule-staging, uploaded to the
# staging release repository under a FIXED tag, and gated on the package
# being a STAGING build rather than on Authenticode (staging artifacts are
# deliberately never signed). Production is the default and unchanged.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File helpers\publish_admin.ps1 -Version 0.1.1-alpha.8
#   ... -Validate   packages and verifies signatures only; uploads nothing.
#   ... -ExpectedSha256 <hash>   publish exactly this package and no other.
#   ... -Environment Staging     publish the unsigned staging package.

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+$')]
    [string]$Version,
    [string]$MinimumClientVersion = '0.2.0',
    # The SHA-256 of an already approved package. When given, an existing zip
    # whose bytes match is published AS IS instead of being re-packaged, and a
    # package that does not match aborts before anything is created or
    # uploaded. This is how a release promotion ships the exact candidate that
    # was tested rather than a freshly rebuilt equivalent of it. Omitted, the
    # script behaves exactly as before.
    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSha256 = '',
    # STAGING publishes the UNSIGNED staging Admin package to the staging
    # release repository. Same packaging, same hash and size discipline, same
    # public re-download proof; what changes is the source folder, the
    # repository, the tag, and WHICH gate the package must pass. Production is
    # the default and is unchanged in every respect.
    [ValidateSet('Production', 'Staging')]
    [string]$Environment = 'Production',
    [switch]$Validate
)

$ErrorActionPreference = 'Stop'

$staging    = ($Environment -eq 'Staging')
$v2Root     = 'D:\Dropbox\Dropbox\development\VIRULE\v2_mvp'
$expectedSubject = 'CN=Heath Michaels'

# The compiled-in staging Worker host. A staging build carries it and a
# production build cannot; reading it out of virule.exe is what makes the
# environment gate below structural rather than a naming convention.
$stagingHostMarker = 'virule-api-staging.heath-michaels9441.workers.dev'
$prodHostMarker    = 'api.virule.app'

if ($staging) {
    $publishDir = Join-Path $v2Root 'virule\publish\Virule-staging'
    $ghRepo     = 'getvirule/virule-staging-releases'
    $stageDir   = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\publish-staging'
    # A FIXED tag, and an asset name that cannot collide with a production
    # release at v<version>. Staging packages are replaced in place; nothing
    # in the world pins their bytes. Reached only from release_staging.ps1,
    # the one staging build/publish path.
    $tag        = 'admin-staging'
    $zipName    = "Virule-v$Version-staging.zip"
} else {
    $publishDir = Join-Path $v2Root 'virule\publish\Virule'
    $ghRepo     = 'getvirule/virule-overlay-releases'
    $stageDir   = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\publish'
    $tag        = "v$Version"
    $zipName    = "Virule-v$Version.zip"
}

$publicBase = "https://github.com/$ghRepo/releases/download"
$zipPath    = Join-Path $stageDir $zipName
$publicUrl  = "$publicBase/$tag/$zipName"

if ($staging -and $ExpectedSha256 -ne '') {
    throw 'ADMIN PUBLISH FAILED: -ExpectedSha256 belongs to the production promotion path; a staging package is re-cut freely and nothing pins its bytes.'
}

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

# What GitHub reports about one asset on a release: present, and its size.
function Get-ReleaseAssetInfo([string]$Tag, [string]$Repo, [string]$Name) {
    $r = @{ Present = $false; Size = [long]0 }
    $v = Invoke-Gh @('release', 'view', $Tag, '-R', $Repo, '--json', 'assets') -AllowFail
    if ($v.Code -ne 0) { return $r }
    try { $rel = $v.Out | ConvertFrom-Json } catch { return $r }
    $pa = $rel.PSObject.Properties['assets']
    if ($null -eq $pa -or $null -eq $pa.Value) { return $r }
    foreach ($a in @($pa.Value)) {
        if ([string]$a.name -eq $Name) { $r.Present = $true; $r.Size = [long]$a.size; break }
    }
    return $r
}

# Upload a release asset with BOUNDED RETRY. A large GitHub asset upload fails
# transiently (2026-09-17: a 308 MB upload failed repeatedly with HTTP 500 while
# a manual upload of the same file succeeded). A failed upload is an UPLOAD
# problem: the fix is to retry the upload, never to rebuild, re-sign or
# re-package. This:
#   - checks first whether the asset is already there with the expected size
#     (a previous attempt or a resume) and, if so, uploads nothing;
#   - removes a partial/mismatched leftover from an interrupted attempt before
#     retrying (for a versioned production tag; staging clobbers in place);
#   - retries with backoff on any failure;
#   - verifies GitHub reports the expected size after a reported success.
# Byte verification against the public URL is done by the caller (step 5), on
# every path. Returns when the asset is present at the expected size; Fails
# after the last attempt WITHOUT touching any earlier stage.
function Publish-AssetWithRetry([string]$Tag, [string]$Repo, [string]$ZipPath, [string]$Name,
                                [long]$ExpectedSize, [switch]$Clobber) {
    $maxAttempts = 5
    $delays = @(5, 15, 45, 90, 120)
    $mb = [math]::Round($ExpectedSize / 1MB)
    for ($i = 1; $i -le $maxAttempts; $i++) {
        $info = Get-ReleaseAssetInfo $Tag $Repo $Name
        if ($info.Present -and $info.Size -eq $ExpectedSize) {
            Write-Host ("OK:   asset already present at the expected size ({0} bytes); not re-uploading" -f $info.Size)
            return
        }
        if ($info.Present -and $info.Size -ne $ExpectedSize -and -not $Clobber) {
            Write-Host ("--    removing a partial/mismatched asset from an interrupted attempt (size {0}, expected {1})" -f $info.Size, $ExpectedSize)
            $null = Invoke-Gh @('release', 'delete-asset', $Tag, $Name, '-R', $Repo, '--yes') -AllowFail
        }
        $ghArgs = @('release', 'upload', $Tag, '-R', $Repo, $ZipPath)
        if ($Clobber) { $ghArgs += '--clobber' }
        Write-Host ("--    uploading {0} (attempt {1} of {2}, {3} MB)" -f $Name, $i, $maxAttempts, $mb)
        $up = Invoke-Gh $ghArgs -AllowFail
        if ($up.Code -eq 0) {
            $post = Get-ReleaseAssetInfo $Tag $Repo $Name
            if ($post.Present -and $post.Size -eq $ExpectedSize) { Write-Host 'OK:   uploaded and size-verified against GitHub'; return }
            Write-Host ("--    upload reported success but GitHub shows size {0}, expected {1}; retrying" -f $post.Size, $ExpectedSize)
        } else {
            Write-Host ("--    upload attempt {0} failed (gh exit {1}); GitHub asset-upload errors are transient" -f $i, $up.Code)
        }
        if ($i -lt $maxAttempts) {
            $d = $delays[[Math]::Min($i - 1, $delays.Count - 1)]
            Write-Host ("--    backing off {0}s before the next attempt" -f $d)
            Start-Sleep -Seconds $d
        }
    }
    Fail ("the package upload did not succeed after $maxAttempts attempts. This is an UPLOAD failure only: " +
          "the release object and every earlier stage (build, sign, package) are intact. Re-run to resume the " +
          "upload; nothing is rebuilt, re-signed or re-packaged.")
}

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

# Reads raw bytes and answers whether an ASCII or UTF-16LE occurrence of the
# needle is present. Used only by the staging gate below.
function Test-ContainsLiteral([string]$path, [string]$needle) {
    $bytes = [IO.File]::ReadAllBytes($path)
    foreach ($enc in @([Text.Encoding]::ASCII, [Text.Encoding]::Unicode)) {
        $pat = $enc.GetBytes($needle)
        $limit = $bytes.Length - $pat.Length
        for ($i = 0; $i -le $limit; $i++) {
            if ($bytes[$i] -ne $pat[0]) { continue }
            $ok = $true
            for ($j = 1; $j -lt $pat.Length; $j++) {
                if ($bytes[$i + $j] -ne $pat[$j]) { $ok = $false; break }
            }
            if ($ok) { return $true }
        }
    }
    return $false
}

if ($staging) {
    # STAGING IS NOT SIGNED, ON PURPOSE, so the signature gate is replaced by
    # an equally absolute one in the other direction: this must be a STAGING
    # build. virule.exe carries the staging Worker host compiled in (the
    # environment seam in launch_policy.hpp) and a production build cannot,
    # so a production package can never be published to the staging channel
    # even by pointing this script at the wrong folder.
    #
    # The SidecarK and producer binaries in the package are the SIGNED
    # production ones, copied unchanged: they speak to no service and are
    # manually signed hard stop artifacts. Staging spends no signing capacity.
    foreach ($rel in $requiredSigned) {
        $p = Join-Path $publishDir $rel
        if (-not (Test-Path $p)) { Fail "required file missing: $p" }
    }
    $exe = Join-Path $publishDir 'virule.exe'
    if (-not (Test-ContainsLiteral $exe $stagingHostMarker)) {
        Fail ('virule.exe is NOT a staging build: the staging host is not compiled into it. ' +
              'Build it with helpers\release_staging.ps1 (VIRULE_ENV=Staging).')
    }
    if (Test-ContainsLiteral $exe $prodHostMarker) {
        Fail 'virule.exe carries the PRODUCTION API host. Refusing to publish it as staging.'
    }
    Write-Host 'OK:   staging build confirmed (staging host compiled in, production host absent)'
    Write-Host 'OK:   signature gate not applied: staging artifacts are never signed'
} else {
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
}

# ---- 1b. the Outreach provider configuration ----
# Connect Google / Connect Microsoft work in an installed Admin only because
# the package carries the owner's registered application configuration at
# its root (mail_provider.cpp reads <root>\outreach_providers.json). A user
# signs in; nothing is ever configured by hand. publish_release.bat stages
# the file from the owner's security folder; this gate refuses to package,
# validate or publish a tree where it is missing or incomplete for EITHER
# provider, for production and staging alike. The check is the pure, tested
# function in v2_mvp\helpers\outreach_providers_check.ps1.
$providersCheck = Join-Path $v2Root 'helpers\outreach_providers_check.ps1'
if (-not (Test-Path $providersCheck)) { Fail "missing $providersCheck" }
. $providersCheck
$providersProblems = @(Get-OutreachProviderConfigProblems (Join-Path $publishDir 'outreach_providers.json'))
if ($providersProblems.Count -gt 0) {
    Fail ("the package would ship without a working Outreach provider configuration (Connect Google / Connect Microsoft would fail as an application error):`n  " +
          ($providersProblems -join "`n  ") +
          "`n  Regenerate it with v2_mvp\helpers\make_outreach_providers.ps1 and stage the publish tree again.")
}
Write-Host 'OK:   outreach_providers.json complete (google + microsoft)'

# ---- 2. the package: folder CONTENTS at the zip root ----
$expected = $ExpectedSha256.ToLowerInvariant()
New-Item -ItemType Directory -Force $stageDir | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem

# -ExpectedSha256 names a package that has already been approved, so this
# publishes THAT FILE. It is never rebuilt: re-packaging identical inputs is
# very nearly deterministic, but 'very nearly' is not what an approval means,
# and the bytes that were tested are the bytes that ship. A drift is refused
# BEFORE the file is touched, so a package that is still needed is never
# destroyed in the act of discovering it does not match.
if ($expected -ne '') {
    if (-not (Test-Path $zipPath)) {
        Fail "the approved package is not there to publish: $zipPath (nothing was created or uploaded)"
    }
    $have = Sha256 $zipPath
    if ($have -ne $expected) {
        Fail ("package sha256 does not match the approved package (got=$have expected=$expected). " +
              "Nothing was published and $zipName was left as it was.")
    }
    Write-Host "OK:   reusing the approved package (sha256 matches); not re-packaging"
} else {
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Write-Host "--    packaging $publishDir -> $zipPath"
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $publishDir, $zipPath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false)   # contents at root: virule.exe + .resources\ + ReadMe.md
}

# Sanity: the zip must carry virule.exe at its root. Checked on the reused
# package too, so a reuse is never a way past this gate.
$zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $rootExe = $zip.Entries | Where-Object { $_.FullName -eq 'virule.exe' }
    $rootCfg = $zip.Entries | Where-Object { $_.FullName -eq 'outreach_providers.json' }
    $entryCount = $zip.Entries.Count
} finally { $zip.Dispose() }
if (-not $rootExe) { Fail 'packaged zip does not carry virule.exe at its root' }
if (-not $rootCfg) { Fail 'packaged zip does not carry outreach_providers.json at its root' }

$zipSha  = Sha256 $zipPath
$zipSize = (Get-Item $zipPath).Length
Write-Host "OK:   package $zipName entries=$entryCount size=$zipSize sha256=$zipSha"

# Belt and braces, on the hash actually computed from the file that is about
# to be uploaded. Still BEFORE the tag, the upload and the manifest, so a
# drifted package is refused rather than published into an immutable tag.
if ($expected -ne '' -and $zipSha -ne $expected) {
    Fail ("package sha256 does not match the approved package (got=$zipSha expected=$expected). " +
          "Nothing was published.")
}

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
if ($staging) {
    if ($view.Code -ne 0) {
        Write-Host "--    creating staging release $tag"
        $stagingNotes = 'UNSIGNED staging build of VIRULE Admin. It talks ONLY to the VIRULE ' +
                        'staging services and is installed ONLY by the staging VIRULE Client. ' +
                        'This tag is replaced in place on every staging build; it is not a ' +
                        'versioned release and nothing pins its bytes.'
        $null = Invoke-Gh @('release', 'create', $tag, '-R', $ghRepo,
            '--title', 'VIRULE Admin STAGING', '--prerelease', '--notes', $stagingNotes)
    } else {
        Write-Host "OK:   staging release $tag already exists"
    }
    Publish-AssetWithRetry $tag $ghRepo $zipPath $zipName $zipSize -Clobber
} elseif ($view.Code -ne 0) {
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
# Staging already uploaded above, with --clobber: a staging package is re-cut
# freely and nothing pins its bytes, so immutability would be wrong there.
$assets = if ($staging) { @{ Code = 1; Out = '' } }
          else { Invoke-Gh @('release', 'view', $tag, '-R', $ghRepo, '--json', 'assets', '-q', '.assets[].name') -AllowFail }
if ($staging) {
    # already uploaded
} elseif ($assets.Code -eq 0 -and ($assets.Out -split "`n") -contains $zipName) {
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
    # A versioned production asset is immutable once published; the retry helper
    # only ever removes a PARTIAL leftover from an interrupted attempt (wrong
    # size), never a correctly published one, and the immutability check above
    # already refused a mismatching complete asset.
    Publish-AssetWithRetry $tag $ghRepo $zipPath $zipName $zipSize
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
if ($staging) {
    Write-Host 'SUCCESS: STAGING Admin package published and verified.' -ForegroundColor Green
    Write-Host "  package  $publicUrl"
    Write-Host ''
    Write-Host 'Admin manifest for the staging Worker (ADMIN_MANIFEST_JSON secret):'
} else {
    Write-Host 'SUCCESS: Admin release published and verified.' -ForegroundColor Green
    Write-Host "  package  $publicUrl"
    Write-Host ''
    Write-Host 'Admin manifest for the virule.app Worker (client_service.ts):'
}
Write-Host "  $manifestJson"
