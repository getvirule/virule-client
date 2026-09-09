# VIRULE STAGING client publisher: pushes the UNSIGNED staging
# Virule-Setup.exe, the UNSIGNED staging virule-client.exe and their
# manifest.json to the FIXED `client-staging` tag on the staging release
# repository.
#
# WHY THIS IS A SEPARATE SCRIPT FROM publish.ps1. Not because the logic
# differs, but because the two REFUSALS differ and both must stay absolute:
#
#   publish.ps1 (production) refuses to publish anything unsigned, and
#   refuses to rewrite a published client version.
#
#   this script refuses to publish a PRODUCTION-configured binary, and
#   refuses to touch a production repository or tag. It never signs, never
#   asks for a signature, and always clobbers, because a staging build is
#   re-cut freely and nothing in the world pins its bytes.
#
# The structural guard that makes the first refusal real: a staging build
# has the staging Worker hostname compiled into it (the environment seam in
# src\shared\environment.hpp). This script reads the bytes of each artifact
# and refuses if that marker is absent or if the production host is present,
# so a production binary cannot be published here even by pointing the
# script at the wrong directory.
#
# WHY A FIXED TAG. The staging release repository also carries the Admin
# packages, so its "latest" release means whichever release was cut last,
# which is not a client pointer. Staging therefore reads a fixed tag, and
# the staging build has that exact URL compiled in.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File helpers\publish_staging_client.ps1
#   powershell -ExecutionPolicy Bypass -File helpers\publish_staging_client.ps1 -Validate

param(
    [switch]$Validate
)

$ErrorActionPreference = 'Stop'

$repo       = Split-Path -Parent $PSScriptRoot
$ghRepo     = 'getvirule/virule-staging-releases'
$prodGhRepo = 'getvirule/virule-client'
$tag        = 'client-staging'
$publicBase = "https://github.com/$ghRepo/releases/download"

$stagingHost = 'virule-api-staging.heath-michaels9441.workers.dev'
$prodHost    = 'api.virule.app'

$clientExe = Join-Path $repo 'build\Release\x64\staging\virule-client.exe'
$setupExe  = Join-Path $repo 'build\Release\x64\staging\Virule-Setup.exe'
$versionH  = Join-Path $repo 'src\shared\version.h'
$stageDir  = Join-Path $repo 'build\publish-staging'

function Fail([string]$msg) { throw "STAGING PUBLISH FAILED: $msg" }

if ($ghRepo -eq $prodGhRepo) { Fail 'the staging release repository is the production one' }

function Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() }

# Reads the raw bytes and answers whether an ASCII or UTF-16LE occurrence of
# the needle is present. The compiled-in hostnames are the only reliable
# proof of which environment a binary was built for.
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

function Require-StagingBuild([string]$path, [string]$label) {
    if (-not (Test-Path $path)) {
        Fail "$label missing: $path. Build it with helpers\build.ps1 -Environment Staging."
    }
    if (-not (Test-ContainsLiteral $path $stagingHost)) {
        Fail ("$label is NOT a staging build: the staging host is not compiled into it. " +
              'Rebuild with helpers\build.ps1 -Environment Staging.')
    }
    if (Test-ContainsLiteral $path $prodHost) {
        Fail "$label carries the PRODUCTION API host. Refusing to publish it as staging."
    }
    Write-Host "OK:   $label is a staging build"
}

function Invoke-Gh([string[]]$GhArgs, [switch]$AllowFail) {
    # PS 5.1: redirecting a native exe's stderr wraps each line in an
    # ErrorRecord and, under $ErrorActionPreference='Stop', turns expected
    # nonzero exits into terminating errors. Neutralize locally.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = (& gh @GhArgs 2>&1 | ForEach-Object { "$_" }) -join [Environment]::NewLine
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
    if ($code -ne 0 -and -not $AllowFail) {
        Fail ("gh {0} failed (exit {1}): {2}" -f ($GhArgs -join ' '), $code, $out)
    }
    return @{ Code = $code; Out = $out }
}

function Remove-TempPath([string]$p) {
    # The repo lives under Dropbox: its sync client briefly holds freshly
    # written files, so a one-shot Remove-Item loses the race.
    for ($i = 0; $i -lt 10; $i++) {
        try { Remove-Item $p -Recurse -Force -ErrorAction Stop; return } catch {}
        Start-Sleep -Milliseconds 500
    }
}

function Test-PublicAsset([string]$url, [string]$expectedSha, [string]$label) {
    $tmp = Join-Path $stageDir ("verify_" + [IO.Path]::GetRandomFileName())
    for ($i = 1; $i -le 5; $i++) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp | Out-Null
            break
        } catch {
            if ($i -eq 5) { Fail "$label not downloadable from $url ($($_.Exception.Message))" }
            Start-Sleep -Seconds 5
        }
    }
    $h = Sha256 $tmp
    Remove-TempPath $tmp
    if ($h -ne $expectedSha) { Fail "$url served wrong bytes (got=$h expected=$expectedSha)" }
    Write-Host "OK:   verified $label at $url"
}

# ---- version (from the client's one version source) ----
$vline = (Get-Content $versionH) -match 'VIRULE_CLIENT_VERSION_STRING\s+"([^"]+)"'
if (-not ($vline -and $vline[0] -match '"([^"]+)"')) { Fail "could not read VIRULE_CLIENT_VERSION_STRING from $versionH" }
$version = $Matches[1]
Write-Host "OK:   client version $version (staging tag $tag)"

# ---- the gate: only STAGING builds are ever published here ----
Require-StagingBuild $clientExe 'virule-client.exe'
Require-StagingBuild $setupExe  'Virule-Setup.exe'

$clientSha  = Sha256 $clientExe
$clientSize = (Get-Item $clientExe).Length
$setupSha   = Sha256 $setupExe
$clientUrl  = "$publicBase/$tag/virule-client.exe"
Write-Host "OK:   client sha256=$clientSha size=$clientSize"
Write-Host "OK:   setup  sha256=$setupSha"

New-Item -ItemType Directory -Force $stageDir | Out-Null

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

# ---- the fixed staging release ----
$view = Invoke-Gh @('release', 'view', $tag, '-R', $ghRepo) -AllowFail
if ($view.Code -ne 0) {
    Write-Host "--    creating staging release $tag"
    $null = Invoke-Gh @('release', 'create', $tag, '-R', $ghRepo,
        '--title', 'VIRULE Client STAGING', '--prerelease',
        '--notes', ('UNSIGNED staging build of the VIRULE Client and Virule-Setup. ' +
                    'It talks ONLY to the VIRULE staging services and installs ONLY ' +
                    'staging Admin packages. This tag is replaced in place on every ' +
                    'staging build; it is not a versioned release and nothing pins its bytes.'))
} else {
    Write-Host "OK:   staging release $tag already exists"
}

# Staging assets are always replaced: nothing in the world pins them.
$null = Invoke-Gh @('release', 'upload', $tag, '-R', $ghRepo, $clientExe, '--clobber')
Write-Host 'OK:   uploaded virule-client.exe'
$null = Invoke-Gh @('release', 'upload', $tag, '-R', $ghRepo, $manifestPath, '--clobber')
Write-Host 'OK:   uploaded manifest.json'
$null = Invoke-Gh @('release', 'upload', $tag, '-R', $ghRepo, $setupExe, '--clobber')
Write-Host 'OK:   uploaded Virule-Setup.exe'

Test-PublicAsset "$publicBase/$tag/virule-client.exe" $clientSha 'virule-client.exe'
Test-PublicAsset "$publicBase/$tag/manifest.json" $manifestSha 'manifest.json'
Test-PublicAsset "$publicBase/$tag/Virule-Setup.exe" $setupSha 'Virule-Setup.exe'

Write-Host ''
Write-Host 'SUCCESS: staging client published and verified.' -ForegroundColor Green
Write-Host "  setup    $publicBase/$tag/Virule-Setup.exe"
Write-Host "  client   $clientUrl"
Write-Host "  manifest $publicBase/$tag/manifest.json"
