# reset_client_dev.ps1 - DEVELOPER-ONLY helper.
#
# Returns this development machine to a "virule-client is not installed"
# state so the fresh-install path from virule.app can be tested. This is
# NOT the product uninstall (src/shared/uninstall.hpp) and deliberately
# removes LESS than it does: credentials under security\ are never touched,
# so the machine identity and QA tester credentials survive the reset.
#
# Removes (and nothing else):
#   %LOCALAPPDATA%\Programs\VIRULE\                          (installed client)
#   %LOCALAPPDATA%\VIRULE\client\                            (client state)
#   HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ViruleClient
#   HKCU:\Software\Classes\virule    ONLY if its shell\open\command points
#                                    at virule-client.exe
#
# Never touched: virule.db, workspace\, logs\, backup.json, security\
# (dev_machine.cred, qa_tester*.cred), qa_test_mode, any game files,
# SidecarK, OverlayProducerCEF, anything in the development tree.
#
# Dry run:      .\helpers\reset_client_dev.ps1 -WhatIf
# Actual reset: .\helpers\reset_client_dev.ps1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

$ErrorActionPreference = 'Stop'

# ---- resolve locations (environment only, same order as src/shared/paths.hpp)

$localAppData = $env:LOCALAPPDATA
if (-not $localAppData) {
    if (-not $env:USERPROFILE) { throw 'Neither LOCALAPPDATA nor USERPROFILE is set; refusing to guess paths.' }
    $localAppData = Join-Path $env:USERPROFILE 'AppData\Local'
}

$installDir     = Join-Path $localAppData 'Programs\VIRULE'
$clientExe      = Join-Path $installDir   'virule-client.exe'
$clientStateDir = Join-Path $localAppData 'VIRULE\client'

$uninstallKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ViruleClient'
$protocolKey    = 'HKCU:\Software\Classes\virule'
$protocolCmdKey = 'HKCU:\Software\Classes\virule\shell\open\command'

# Must-never-touch inventory, verified before and after.
$preserved = @(
    (Join-Path $localAppData 'VIRULE\virule.db'),
    (Join-Path $localAppData 'VIRULE\workspace'),
    (Join-Path $localAppData 'VIRULE\logs'),
    (Join-Path $localAppData 'VIRULE\backup.json'),
    (Join-Path $localAppData 'VIRULE\security'),
    (Join-Path $localAppData 'VIRULE\security\dev_machine.cred'),
    (Join-Path $localAppData 'VIRULE\security\qa_tester.cred'),
    (Join-Path $localAppData 'VIRULE\security\qa_tester_test.cred'),
    'D:\Dropbox\Dropbox\development\VIRULE\v2_mvp',
    'D:\Dropbox\Dropbox\development\VIRULE\v2_mvp\virule\publish\Virule'
)

# ---- safety: every filesystem deletion target must live INSIDE one of the
# two client-owned roots. Anything else is refused outright.

$allowedRoots = @($installDir, $clientStateDir)

function Assert-ClientOwned([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    foreach ($root in $allowedRoots) {
        $rootFull = [System.IO.Path]::GetFullPath($root)
        if ($full.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) { return }
        if ($full.StartsWith(($rootFull.TrimEnd('\') + '\'), [System.StringComparison]::OrdinalIgnoreCase)) { return }
    }
    throw "REFUSED: '$Path' is outside the client-owned locations ($($allowedRoots -join '; ')). Nothing was deleted."
}

# The client-owned roots must never be, or contain, a preserved path.
foreach ($root in $allowedRoots) {
    $rootFull = [System.IO.Path]::GetFullPath($root)
    foreach ($p in $preserved) {
        $pFull = [System.IO.Path]::GetFullPath($p)
        if ($pFull.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
            $pFull.StartsWith(($rootFull.TrimEnd('\') + '\'), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "REFUSED: preserved path '$p' lies inside deletion root '$root'."
        }
    }
}

$isDryRun = $WhatIfPreference

Write-Host ''
Write-Host '=== VIRULE Client developer reset ===' -ForegroundColor Yellow
if ($isDryRun) { Write-Host '--- DRY RUN (-WhatIf): nothing will be changed ---' -ForegroundColor Cyan }
Write-Host ''

# ---- 1. running client processes (match by executable path, not just name)

$clientProcs = @(Get-Process -Name 'virule-client' -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Path -and ([System.IO.Path]::GetFullPath($_.Path)).StartsWith(
            ([System.IO.Path]::GetFullPath($installDir).TrimEnd('\') + '\'),
            [System.StringComparison]::OrdinalIgnoreCase) }
    catch { $false }
})

# ---- 2. build the removal plan (only what actually exists right now)

$planFs  = @()   # filesystem targets
$planReg = @()   # registry targets

if (Test-Path -LiteralPath $installDir)     { $planFs += $installDir }
if (Test-Path -LiteralPath $clientStateDir) { $planFs += $clientStateDir }
foreach ($t in $planFs) { Assert-ClientOwned $t }

if (Test-Path -LiteralPath $uninstallKey) { $planReg += $uninstallKey }

$protocolPointsAtClient = $false
$protocolCmd = $null
if (Test-Path -LiteralPath $protocolKey) {
    if (Test-Path -LiteralPath $protocolCmdKey) {
        $protocolCmd = (Get-ItemProperty -LiteralPath $protocolCmdKey -ErrorAction SilentlyContinue).'(default)'
    }
    if ($protocolCmd -and $protocolCmd.ToLowerInvariant().Contains('virule-client.exe')) {
        $protocolPointsAtClient = $true
        $planReg += $protocolKey
    }
}

# ---- 3. print the exact plan

Write-Host 'Will remove:' -ForegroundColor Yellow
if ($clientProcs.Count -gt 0) {
    foreach ($p in $clientProcs) { Write-Host ("  [process]   virule-client.exe  PID {0}  ({1})" -f $p.Id, $p.Path) }
} else {
    Write-Host '  [process]   (no running virule-client.exe under the install directory)'
}
if ($planFs.Count -gt 0) { foreach ($t in $planFs) { Write-Host "  [directory] $t" } }
else { Write-Host '  [directory] (no installed client directories present)' }
if ($planReg.Count -gt 0) { foreach ($t in $planReg) { Write-Host "  [registry]  $t" } }
else { Write-Host '  [registry]  (no client registry entries present)' }
if ((Test-Path -LiteralPath $protocolKey) -and -not $protocolPointsAtClient) {
    if ($protocolCmd) {
        Write-Host "  [registry]  $protocolKey LEFT IN PLACE: its command does not point at virule-client.exe:"
        Write-Host "              $protocolCmd"
    } else {
        Write-Host "  [registry]  $protocolKey LEFT IN PLACE: no readable open command; not provably the client's."
    }
}

Write-Host ''
Write-Host 'Preserved (verified untouched):' -ForegroundColor Yellow
$script:preservedPresentBefore = @()
foreach ($p in $preserved) {
    $exists = Test-Path -LiteralPath $p
    if ($exists) { $script:preservedPresentBefore += $p }
    Write-Host ("  [{0}] {1}" -f ($(if ($exists) { 'present' } else { 'absent ' })), $p)
}
Write-Host ''

if ($isDryRun) {
    Write-Host 'DRY RUN complete. Nothing was changed.' -ForegroundColor Cyan
    Write-Host 'Run without -WhatIf to perform the reset.'
    return
}

if ($clientProcs.Count -eq 0 -and $planFs.Count -eq 0 -and $planReg.Count -eq 0) {
    Write-Host 'Nothing to do: virule-client is already absent from this machine.' -ForegroundColor Green
    return
}

# ---- 4. stop the client cleanly (close window, wait, then force)

foreach ($p in $clientProcs) {
    if ($PSCmdlet.ShouldProcess("virule-client.exe PID $($p.Id)", 'Stop process')) {
        Write-Host "Stopping virule-client.exe (PID $($p.Id))..."
        $null = $p.CloseMainWindow()
        if (-not $p.WaitForExit(5000)) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $null = $p.WaitForExit(5000)
        }
    }
}
Start-Sleep -Milliseconds 500

# ---- 5. filesystem removal (each target re-verified client-owned)

foreach ($t in $planFs) {
    Assert-ClientOwned $t
    if ($PSCmdlet.ShouldProcess($t, 'Remove directory')) {
        Write-Host "Removing $t"
        Remove-Item -LiteralPath $t -Recurse -Force -Confirm:$false
    }
}

# ---- 6. registry removal

if ((Test-Path -LiteralPath $uninstallKey) -and
    $PSCmdlet.ShouldProcess($uninstallKey, 'Remove registry key')) {
    Write-Host "Removing $uninstallKey"
    Remove-Item -LiteralPath $uninstallKey -Recurse -Force -Confirm:$false
}

if ($protocolPointsAtClient -and (Test-Path -LiteralPath $protocolKey) -and
    $PSCmdlet.ShouldProcess($protocolKey, 'Remove virule:// registration (points at virule-client.exe)')) {
    Write-Host "Removing $protocolKey (its command pointed at virule-client.exe)"
    Remove-Item -LiteralPath $protocolKey -Recurse -Force -Confirm:$false
}

# ---- 7. verify the end state

Write-Host ''
Write-Host 'Verification:' -ForegroundColor Yellow
$fail = $false

$stillRunning = @(Get-Process -Name 'virule-client' -ErrorAction SilentlyContinue)
if ($stillRunning.Count -gt 0) {
    Write-Host ("  FAIL  virule-client.exe still running (PID {0})" -f (($stillRunning | ForEach-Object Id) -join ', ')) -ForegroundColor Red
    $fail = $true
} else { Write-Host '  OK    no virule-client.exe process running' }

foreach ($t in @($installDir, $clientStateDir)) {
    if (Test-Path -LiteralPath $t) { Write-Host "  FAIL  still present: $t" -ForegroundColor Red; $fail = $true }
    else { Write-Host "  OK    removed/absent: $t" }
}
if (Test-Path -LiteralPath $uninstallKey) { Write-Host "  FAIL  still present: $uninstallKey" -ForegroundColor Red; $fail = $true }
else { Write-Host "  OK    removed/absent: $uninstallKey" }
if ($protocolPointsAtClient) {
    if (Test-Path -LiteralPath $protocolKey) { Write-Host "  FAIL  still present: $protocolKey" -ForegroundColor Red; $fail = $true }
    else { Write-Host "  OK    removed: $protocolKey" }
}

foreach ($p in $preserved) {
    # Only flag preserved items that vanished during this run; ones that were
    # already absent (e.g. no Admin install) are fine.
    if ($p -in $script:preservedPresentBefore -and -not (Test-Path -LiteralPath $p)) {
        Write-Host "  FAIL  preserved item disappeared: $p" -ForegroundColor Red; $fail = $true
    }
}
Write-Host '  OK    preserved inventory untouched (only client-owned roots were eligible for deletion)'

Write-Host ''
if ($fail) { Write-Host 'Reset finished WITH FAILURES (see above).' -ForegroundColor Red; exit 1 }
Write-Host 'Reset complete. virule-client is no longer installed on this machine.' -ForegroundColor Green
