# THE CANONICAL VIRULE SETUP (owner ruling 2026-10-19). Dot-source this file.
#
# Virule-Setup.exe is a bootstrapper, not the application: it downloads the
# approved client release of ITS environment and verifies it. It is therefore
# a STABLE, SIGNED artifact reused unchanged across releases. Normal releases
# (staging and production) never build, sign or substitute Setup; they
# publish the approved binary from release\setup\<environment>\ and nothing
# else.
#
# Setup is environment-specific at compile time (the client manifest URL, the
# download prefix and the signature rule in launch_policy.hpp), so there are
# exactly two canonical binaries, one per environment, both signed with the
# VIRULE identity. Their SHA-256 and size are pinned in
# release\setup\canonical_setup.json, committed with the binaries.
#
# Every check here FAILS CLOSED: a missing pin, a missing file, any byte
# difference, an invalid or foreign signature, or the other environment's
# markers refuses the release. Nothing ever falls back to a freshly built
# Setup.
#
# Replacing a canonical Setup (only when Setup's own code must change) is a
# deliberate owner-approved act: helpers\approve_canonical_setup.ps1.

$script:CanonicalSetupRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'release\setup'
$script:CanonicalSetupPin  = Join-Path $script:CanonicalSetupRoot 'canonical_setup.json'
$script:CanonicalSigner    = 'CN=Heath Michaels'

# The compiled-in release repository is the reliable proof of which
# environment a Setup belongs to (it is the manifest URL Setup follows).
$script:SetupEnvMarker = @{
    Production = 'https://github.com/getvirule/virule-client/releases/'
    Staging    = 'https://github.com/getvirule/virule-staging-releases/'
}

function Test-SetupContainsLiteral([string]$Path, [string]$Needle) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    foreach ($enc in @([Text.Encoding]::ASCII, [Text.Encoding]::Unicode)) {
        $pat = $enc.GetBytes($Needle)
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

function Get-SetupSha256([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

function Stop-CanonicalSetup([string]$Message) { throw "CANONICAL SETUP REFUSED: $Message" }

# Signature + identity + environment, for any Setup file (the canonical one,
# a downloaded copy, or a candidate being approved).
function Assert-SetupFile([string]$Path, [ValidateSet('Production', 'Staging')][string]$Environment, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) { Stop-CanonicalSetup "$Label is missing: $Path" }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid') { Stop-CanonicalSetup "$Label is not validly signed (status: $($sig.Status))" }
    if ($null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notlike "*$script:CanonicalSigner*") {
        Stop-CanonicalSetup "$Label is not signed by the VIRULE identity"
    }
    if ($null -eq $sig.TimeStamperCertificate) { Stop-CanonicalSetup "$Label carries no timestamp (its signature would expire with the certificate)" }
    $other = if ($Environment -eq 'Production') { 'Staging' } else { 'Production' }
    if (-not (Test-SetupContainsLiteral $Path $script:SetupEnvMarker[$Environment])) {
        Stop-CanonicalSetup "$Label is not a $Environment Setup (its release repository is not compiled in)"
    }
    if (Test-SetupContainsLiteral $Path $script:SetupEnvMarker[$other]) {
        Stop-CanonicalSetup "$Label carries the $other release repository"
    }
}

function Read-CanonicalSetupPin {
    if (-not (Test-Path -LiteralPath $script:CanonicalSetupPin)) { Stop-CanonicalSetup "the pin file is missing: $script:CanonicalSetupPin" }
    return (Get-Content -Raw -LiteralPath $script:CanonicalSetupPin | ConvertFrom-Json)
}

# The approved Setup for one environment, fully verified. Returns
# @{ Path; Sha256; Size; Version }.
function Get-CanonicalSetup([ValidateSet('Production', 'Staging')][string]$Environment) {
    $pin = (Read-CanonicalSetupPin).($Environment.ToLowerInvariant())
    if ($null -eq $pin) { Stop-CanonicalSetup "no approved $Environment Setup is pinned in $script:CanonicalSetupPin" }
    $path = Join-Path $script:CanonicalSetupRoot ([string]$pin.file)
    Assert-SetupFile $path $Environment "the canonical $Environment Setup"
    $size = (Get-Item -LiteralPath $path).Length
    if ($size -ne [long]$pin.size) { Stop-CanonicalSetup "the canonical $Environment Setup is $size bytes, the pin says $($pin.size)" }
    $sha = Get-SetupSha256 $path
    if ($sha -ne ([string]$pin.sha256).ToLowerInvariant()) { Stop-CanonicalSetup "the canonical $Environment Setup's SHA-256 $sha is not the pinned $($pin.sha256)" }
    return @{ Path = $path; Sha256 = $sha; Size = $size; Version = [string]$pin.setupVersion }
}

# What the world downloads: the published Setup must be the canonical one,
# byte for byte, and validly signed. Returns the verified SHA-256.
function Assert-PublishedSetup([string]$Url, [ValidateSet('Production', 'Staging')][string]$Environment) {
    $canon = Get-CanonicalSetup $Environment
    $tmp = Join-Path $env:TEMP ('virule_setup_check_' + [guid]::NewGuid().ToString('N') + '.exe')
    try {
        for ($i = 1; $i -le 5; $i++) {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -UseBasicParsing -Uri ($Url + '?fresh=' + [guid]::NewGuid().ToString('N')) -OutFile $tmp | Out-Null
                break
            } catch {
                if ($i -eq 5) { Stop-CanonicalSetup "the published Setup could not be downloaded from $Url ($($_.Exception.Message))" }
                Start-Sleep -Seconds 5
            }
        }
        $sha = Get-SetupSha256 $tmp
        if ($sha -ne $canon.Sha256) { Stop-CanonicalSetup "$Url serves $sha, not the canonical $Environment Setup $($canon.Sha256)" }
        Assert-SetupFile $tmp $Environment "the published Setup at $Url"
        return $sha
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}
