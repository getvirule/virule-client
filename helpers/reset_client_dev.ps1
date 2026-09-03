# reset_client_dev.ps1 - DEVELOPER-ONLY helper.
#
# Returns this development machine to a "virule-client is not installed"
# state so the fresh-install path from virule.app can be tested. This is
# NOT the product uninstall (src/shared/uninstall.hpp) and deliberately
# removes LESS than it does: credentials under security\ are never touched,
# so the machine identity and QA tester credentials survive the reset.
#
# Phase 2 changed the install layout: %LOCALAPPDATA%\Programs\VIRULE is now
# a SHARED root. The client owns only virule-client.exe inside it; the
# managed Admin lives at Programs\VIRULE\Admin\ and MUST SURVIVE this reset
# (along with its Admin.previous / Admin.staging siblings from the update
# pipeline). This helper therefore never deletes the Programs\VIRULE
# directory recursively; it removes the exact client-owned entries only.
#
# Removes (and nothing else):
#   %LOCALAPPDATA%\Programs\VIRULE\virule-client.exe         (installed client)
#   %LOCALAPPDATA%\Programs\VIRULE\virule-client.exe.new     (stale staging)
#   %LOCALAPPDATA%\VIRULE\client\                            (client state)
#   %LOCALAPPDATA%\Programs\VIRULE\   ONLY when the reset leaves it EMPTY
#                                    (i.e. no Admin is installed)
#   HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ViruleClient
#   HKCU:\Software\Classes\virule    ONLY if its shell\open\command points
#                                    at virule-client.exe
#
# Never touched: Programs\VIRULE\Admin\ (the managed Admin, verified intact
# before AND after), virule.db, workspace\, logs\, backup.json, security\
# (dev_machine.cred, qa_tester*.cred), qa_test_mode, the desktop VIRULE.lnk
# (it targets the managed Admin, which stays installed), any game files,
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
$adminDir       = Join-Path $installDir   'Admin'
$clientExe      = Join-Path $installDir   'virule-client.exe'
$clientExeNew   = Join-Path $installDir   'virule-client.exe.new'
$clientStateDir = Join-Path $localAppData 'VIRULE\client'

$uninstallKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ViruleClient'
$protocolKey    = 'HKCU:\Software\Classes\virule'
$protocolCmdKey = 'HKCU:\Software\Classes\virule\shell\open\command'

# Must-never-touch inventory, verified before and after.
$preserved = @(
    $adminDir,
    (Join-Path $adminDir 'virule.exe'),
    (Join-Path $adminDir '.resources\admin\ViruleAdminHost.exe'),
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

# ---- safety: every filesystem deletion target must be EXACTLY one of the
# client-owned entries. The shared Programs\VIRULE root is NEVER a recursive
# deletion target, and nothing under Admin\ is ever eligible.

$allowedFiles = @($clientExe, $clientExeNew)   # exact file paths only
$allowedDirs  = @($clientStateDir)             # recursive removal allowed

function Assert-ClientOwned([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $adminFull = [System.IO.Path]::GetFullPath($adminDir)
    if ($full.Equals($adminFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith(($adminFull.TrimEnd('\') + '\'), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "REFUSED: '$Path' is inside the managed Admin installation. Nothing was deleted."
    }
    foreach ($f in $allowedFiles) {
        if ($full.Equals([System.IO.Path]::GetFullPath($f), [System.StringComparison]::OrdinalIgnoreCase)) { return }
    }
    foreach ($root in $allowedDirs) {
        $rootFull = [System.IO.Path]::GetFullPath($root)
        if ($full.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) { return }
        if ($full.StartsWith(($rootFull.TrimEnd('\') + '\'), [System.StringComparison]::OrdinalIgnoreCase)) { return }
    }
    throw "REFUSED: '$Path' is not a client-owned entry (allowed files: $($allowedFiles -join '; '); allowed dirs: $($allowedDirs -join '; ')). Nothing was deleted."
}

# The client-owned targets must never be, or contain, a preserved path.
foreach ($target in ($allowedFiles + $allowedDirs)) {
    $targetFull = [System.IO.Path]::GetFullPath($target)
    foreach ($p in $preserved) {
        $pFull = [System.IO.Path]::GetFullPath($p)
        if ($pFull.Equals($targetFull, [System.StringComparison]::OrdinalIgnoreCase) -or
            $pFull.StartsWith(($targetFull.TrimEnd('\') + '\'), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "REFUSED: preserved path '$p' lies inside deletion target '$target'."
        }
    }
}

$isDryRun = $WhatIfPreference

Write-Host ''
Write-Host '=== VIRULE Client developer reset ===' -ForegroundColor Yellow
if ($isDryRun) { Write-Host '--- DRY RUN (-WhatIf): nothing will be changed ---' -ForegroundColor Cyan }
Write-Host ''

# ---- 0. snapshot the managed Admin so its integrity is provable afterwards

$adminSnapshot = $null
if (Test-Path -LiteralPath $adminDir) {
    $adminFiles = @(Get-ChildItem -LiteralPath $adminDir -Recurse -Force -File -ErrorAction SilentlyContinue)
    $adminSnapshot = [pscustomobject]@{
        FileCount  = $adminFiles.Count
        TotalBytes = ($adminFiles | Measure-Object -Property Length -Sum).Sum
    }
    Write-Host ("Managed Admin present: {0} files, {1} bytes (will be verified untouched)." -f $adminSnapshot.FileCount, $adminSnapshot.TotalBytes)
} else {
    Write-Host 'Managed Admin not installed (nothing to protect there).'
}

# ---- 1. running client processes (match by executable path, not just name)

$clientProcs = @(Get-Process -Name 'virule-client' -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Path -and ([System.IO.Path]::GetFullPath($_.Path)).StartsWith(
            ([System.IO.Path]::GetFullPath($installDir).TrimEnd('\') + '\'),
            [System.StringComparison]::OrdinalIgnoreCase) }
    catch { $false }
})

# ---- 2. build the removal plan (only what actually exists right now)

$planFiles = @()   # exact files
$planDirs  = @()   # recursive directories
$planReg   = @()   # registry targets

foreach ($f in $allowedFiles) { if (Test-Path -LiteralPath $f) { $planFiles += $f } }
if (Test-Path -LiteralPath $clientStateDir) { $planDirs += $clientStateDir }
foreach ($t in ($planFiles + $planDirs)) { Assert-ClientOwned $t }

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

# Programs\VIRULE itself is removed only when the reset leaves it empty
# (no Admin, no leftovers). Announced in the plan, decided after removal.
$mayRemoveEmptyInstallDir = (Test-Path -LiteralPath $installDir) -and -not (Test-Path -LiteralPath $adminDir)

# ---- 3. print the exact plan

Write-Host 'Will remove:' -ForegroundColor Yellow
if ($clientProcs.Count -gt 0) {
    foreach ($p in $clientProcs) { Write-Host ("  [process]   virule-client.exe  PID {0}  ({1})" -f $p.Id, $p.Path) }
} else {
    Write-Host '  [process]   (no running virule-client.exe under the install directory)'
}
if ($planFiles.Count -gt 0) { foreach ($t in $planFiles) { Write-Host "  [file]      $t" } }
else { Write-Host '  [file]      (no installed client files present)' }
if ($planDirs.Count -gt 0) { foreach ($t in $planDirs) { Write-Host "  [directory] $t" } }
else { Write-Host '  [directory] (no client state directory present)' }
if ($mayRemoveEmptyInstallDir) { Write-Host "  [directory] $installDir (only if left empty)" }
elseif (Test-Path -LiteralPath $adminDir) { Write-Host "  [directory] $installDir LEFT IN PLACE: it holds the managed Admin installation." }
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

if ($clientProcs.Count -eq 0 -and $planFiles.Count -eq 0 -and $planDirs.Count -eq 0 -and $planReg.Count -eq 0) {
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

foreach ($t in $planFiles) {
    Assert-ClientOwned $t
    if ($PSCmdlet.ShouldProcess($t, 'Remove file')) {
        Write-Host "Removing $t"
        Remove-Item -LiteralPath $t -Force -Confirm:$false
    }
}
foreach ($t in $planDirs) {
    Assert-ClientOwned $t
    if ($PSCmdlet.ShouldProcess($t, 'Remove directory')) {
        Write-Host "Removing $t"
        Remove-Item -LiteralPath $t -Recurse -Force -Confirm:$false
    }
}

# Programs\VIRULE only when it ended up empty. Deliberately NOT -Recurse:
# even if the emptiness check raced, a non-empty directory cannot be removed.
if ($mayRemoveEmptyInstallDir -and (Test-Path -LiteralPath $installDir) -and
    @(Get-ChildItem -LiteralPath $installDir -Force -ErrorAction SilentlyContinue).Count -eq 0 -and
    $PSCmdlet.ShouldProcess($installDir, 'Remove empty install directory')) {
    Write-Host "Removing empty $installDir"
    Remove-Item -LiteralPath $installDir -Force -Confirm:$false
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

foreach ($t in @($clientExe, $clientExeNew, $clientStateDir)) {
    if (Test-Path -LiteralPath $t) { Write-Host "  FAIL  still present: $t" -ForegroundColor Red; $fail = $true }
    else { Write-Host "  OK    removed/absent: $t" }
}
if (Test-Path -LiteralPath $uninstallKey) { Write-Host "  FAIL  still present: $uninstallKey" -ForegroundColor Red; $fail = $true }
else { Write-Host "  OK    removed/absent: $uninstallKey" }
if ($protocolPointsAtClient) {
    if (Test-Path -LiteralPath $protocolKey) { Write-Host "  FAIL  still present: $protocolKey" -ForegroundColor Red; $fail = $true }
    else { Write-Host "  OK    removed: $protocolKey" }
}

# The managed Admin must be exactly as it was.
if ($adminSnapshot) {
    if (-not (Test-Path -LiteralPath $adminDir)) {
        Write-Host "  FAIL  managed Admin disappeared: $adminDir" -ForegroundColor Red
        $fail = $true
    } else {
        $adminFilesAfter = @(Get-ChildItem -LiteralPath $adminDir -Recurse -Force -File -ErrorAction SilentlyContinue)
        $bytesAfter = ($adminFilesAfter | Measure-Object -Property Length -Sum).Sum
        if ($adminFilesAfter.Count -ne $adminSnapshot.FileCount -or $bytesAfter -ne $adminSnapshot.TotalBytes) {
            Write-Host ("  FAIL  managed Admin changed: {0} files/{1} bytes before, {2} files/{3} bytes after" -f `
                $adminSnapshot.FileCount, $adminSnapshot.TotalBytes, $adminFilesAfter.Count, $bytesAfter) -ForegroundColor Red
            $fail = $true
        } else {
            Write-Host ("  OK    managed Admin intact: {0} files, {1} bytes (unchanged)" -f $adminFilesAfter.Count, $bytesAfter)
        }
    }
}

foreach ($p in $preserved) {
    # Only flag preserved items that vanished during this run; ones that were
    # already absent (e.g. no Admin install) are fine.
    if ($p -in $script:preservedPresentBefore -and -not (Test-Path -LiteralPath $p)) {
        Write-Host "  FAIL  preserved item disappeared: $p" -ForegroundColor Red; $fail = $true
    }
}
if (-not $fail) { Write-Host '  OK    preserved inventory untouched (only exact client-owned entries were eligible for deletion)' }

Write-Host ''
if ($fail) { Write-Host 'Reset finished WITH FAILURES (see above).' -ForegroundColor Red; exit 1 }
Write-Host 'Reset complete. virule-client is no longer installed on this machine.' -ForegroundColor Green
