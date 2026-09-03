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
# Usage:  powershell -ExecutionPolicy Bypass -File helpers\build.ps1 [-Stage all|client|setup]

param(
    [ValidateSet('all', 'client', 'setup')]
    [string]$Stage = 'all'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

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
$clientExe = Join-Path $repo 'build\Release\x64\virule-client.exe'
$setupExe  = Join-Path $repo 'build\Release\x64\Virule-Setup.exe'

function Build-Client {
    Write-Host '=== build virule-client.exe ==='
    & $msbuild (Join-Path $repo 'client\virule_client.vcxproj') /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$repo\" /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { throw 'client build failed' }
    if (-not (Test-Path $clientExe)) { throw "client build produced no exe: $clientExe" }
}

function Build-Setup {
    Write-Host '=== build Virule-Setup.exe ==='
    & $msbuild (Join-Path $repo 'setup\virule_setup.vcxproj') /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$repo\" /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { throw 'setup build failed' }
    if (-not (Test-Path $setupExe)) { throw "setup build produced no exe: $setupExe" }
}

switch ($Stage) {
    'client' {
        Build-Client
        Write-Host ''
        Write-Host 'DONE (stage: client)'
        Write-Host "  client: $clientExe"
        Write-Host 'Next: sign it via VIRULE_SECURITY\artifact-signing\sign_client.bat,'
        Write-Host 'then publish via helpers\publish.ps1.'
    }
    'setup' {
        Build-Setup
        Write-Host ''
        Write-Host 'DONE (stage: setup)'
        Write-Host "  setup : $setupExe"
        Write-Host 'Next: sign it via VIRULE_SECURITY\artifact-signing\sign_client_setup.bat,'
        Write-Host 'then publish via helpers\publish.ps1.'
    }
    'all' {
        Build-Client
        Build-Setup
        Write-Host ''
        Write-Host 'DONE (unsigned development build)'
        Write-Host "  client: $clientExe"
        Write-Host "  setup : $setupExe"
    }
}
