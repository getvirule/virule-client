# VIRULE Client build stages. THIS SCRIPT NEVER SIGNS - signing is
# centralized in D:\Dropbox\Dropbox\development\VIRULE_SECURITY\artifact-signing
# (sign_client.bat / sign_client_setup.bat).
#
# virule-client.exe and Virule-Setup.exe are INDEPENDENT signed artifacts.
# Setup embeds nothing: it downloads the approved client release from the
# getvirule/virule-client GitHub Release at install time and verifies it
# (manifest SHA-256 + Authenticode + the VIRULE signing identity). There is
# no build coupling and no required order between the two; sign whichever
# artifact was rebuilt.
#
# Release flow per artifact:
#   client: helpers\build.ps1 -Stage client  ->  sign_client.bat
#   setup : helpers\build.ps1 -Stage setup   ->  sign_client_setup.bat
# Publishing to the GitHub Release is helpers\publish.ps1.
#
# -Environment Staging builds the SAME sources with VIRULE_ENV_STAGING
# defined (Directory.Build.targets), which selects the staging half of
# src\shared\environment.hpp and of virule\core\launch_policy.hpp, and
# writes to build\Release\x64\staging\ so a staging binary can never be
# mistaken for a production one. STAGING ARTIFACTS ARE NEVER SIGNED; they
# are published by helpers\publish_staging_client.ps1 to the staging
# release repository. Production output is unchanged by its presence.
#
# Usage:  powershell -ExecutionPolicy Bypass -File helpers\build.ps1 [-Stage all|client|setup] [-Environment Production|Staging]

param(
    [ValidateSet('all', 'client', 'setup')]
    [string]$Stage = 'all',
    [ValidateSet('Production', 'Staging')]
    [string]$Environment = 'Production'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$staging = ($Environment -eq 'Staging')
$outLeaf = if ($staging) { 'staging\' } else { '' }
# NOTE: an `if` expression unrolls a one-element array, so the extra
# arguments are built with an explicit assignment. Splatting a bare
# string at a native command would pass it one character at a time.
$envArgs = @()
if ($staging) { $envArgs = [string[]]@('/p:VIRULE_ENV=Staging') }

function Find-MSBuild {
    $candidates = @(
        'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    throw 'MSBuild.exe not found'
}

$msbuild = Find-MSBuild
$clientExe = Join-Path $repo ('build\Release\x64\' + $outLeaf + 'virule-client.exe')
$setupExe  = Join-Path $repo ('build\Release\x64\' + $outLeaf + 'Virule-Setup.exe')

# This repository lives under Dropbox, whose sync client briefly memory-maps
# and holds freshly written files. MSBuild then dies writing a .tlog or a .pdb
# with MSB6003 "user-mapped section open" / "being used by another process", or
# with C1041. It is transient and clears within seconds, and it is not a build
# error: retrying is the correct response, not reporting a failure. Anything
# that is NOT one of those signatures fails on the first attempt as before.
function Invoke-MsBuildWithRetry([string[]]$msbuildArgs, [string]$label) {
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $out = & $msbuild @msbuildArgs 2>&1 | ForEach-Object { Write-Host "$_"; "$_" }
        if ($LASTEXITCODE -eq 0) { return }
        $text = $out -join [Environment]::NewLine
        $transient = ($text -match 'user-mapped section open') -or
                     ($text -match 'C1041') -or
                     ($text -match 'being used by another process')
        if (-not $transient -or $attempt -eq 3) { throw "$label failed" }
        Write-Host "--    $label hit a transient file lock (Dropbox sync); retrying ($attempt of 2)"
        Start-Sleep -Seconds 10
    }
}

function Build-Client {
    Write-Host "=== build virule-client.exe ($Environment) ==="
    Invoke-MsBuildWithRetry (@((Join-Path $repo 'client\virule_client.vcxproj'),
        '/p:Configuration=Release', '/p:Platform=x64', "/p:SolutionDir=$repo\") +
        $envArgs + @('/nologo', '/v:minimal')) 'client build'
    if (-not (Test-Path $clientExe)) { throw "client build produced no exe: $clientExe" }
}

function Build-Setup {
    Write-Host "=== build Virule-Setup.exe ($Environment) ==="
    Invoke-MsBuildWithRetry (@((Join-Path $repo 'setup\virule_setup.vcxproj'),
        '/p:Configuration=Release', '/p:Platform=x64', "/p:SolutionDir=$repo\") +
        $envArgs + @('/nologo', '/v:minimal')) 'setup build'
    if (-not (Test-Path $setupExe)) { throw "setup build produced no exe: $setupExe" }
}

switch ($Stage) {
    'client' {
        Build-Client
        Write-Host ''
        Write-Host "DONE (stage: client, environment: $Environment)"
        Write-Host "  client: $clientExe"
        if (-not $staging) {
            Write-Host 'Next: sign it via VIRULE_SECURITY\artifact-signing\sign_client.bat,'
            Write-Host 'then publish via helpers\publish.ps1.'
        } else {
            Write-Host 'Staging builds are not signed. Publish via helpers\publish_staging_client.ps1.'
        }
    }
    'setup' {
        Build-Setup
        Write-Host ''
        Write-Host "DONE (stage: setup, environment: $Environment)"
        Write-Host "  setup : $setupExe"
        if (-not $staging) {
            Write-Host 'Next: sign it via VIRULE_SECURITY\artifact-signing\sign_client_setup.bat,'
            Write-Host 'then publish via helpers\publish.ps1.'
        } else {
            Write-Host 'Staging builds are not signed. Publish via helpers\publish_staging_client.ps1.'
        }
    }
    'all' {
        Build-Client
        Build-Setup
        Write-Host ''
        Write-Host "DONE (unsigned build, environment: $Environment)"
        Write-Host "  client: $clientExe"
        Write-Host "  setup : $setupExe"
    }
}
