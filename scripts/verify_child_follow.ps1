# L4 child-process following: invariants.
#
# Builds nothing. Expects scripts\build_runtime_windows.ps1 to have run, so
# dist\ holds launcher.exe, lpvirt.dll and spawn_chain.exe.
#
# What it proves, in order:
#   1. a program run by the launcher reads the virtual file   (level 1)
#   2. it starts another program, which is redirected back into the launcher
#   3. that child sees the same virtual tree                    (level 2, 3)
#   4. the counters show exactly one redirect per spawning launcher
#   5. the product binary imports no remote-injection API at all
#   6. a program started outside the launcher does NOT see the virtual tree,
#      which is the boundary the L4 work is about
#   7. the mechanism did not add anything to the AV quarantine

param(
  [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
  [string]$Dist = ''
)
$ErrorActionPreference = 'Stop'
if ($Dist -eq '') { $Dist = Join-Path $Root 'dist' }

$launcher = Join-Path $Dist 'launcher.exe'
$virt = Join-Path $Dist 'lpvirt.dll'
$chain = Join-Path $Dist 'spawn_chain.exe'
foreach ($p in @($launcher, $virt, $chain)) {
  if (-not (Test-Path -LiteralPath $p)) {
    throw "missing $p - run scripts\build_runtime_windows.ps1 first"
  }
}

$script:failed = 0
function Check([bool]$ok, [string]$what) {
  if ($ok) {
    Write-Host "  PASS  $what"
  } else {
    Write-Host "  FAIL  $what" -ForegroundColor Red
    $script:failed++
  }
}

$q = 'C:\ProgramData\Huorong\Sysdiag\Quarantine'
function QuarantineCount {
  if (Test-Path -LiteralPath $q) {
    return @(Get-ChildItem -LiteralPath $q -File -Force -ErrorAction SilentlyContinue).Count
  }
  return -1
}
$before = QuarantineCount
$hips = @(Get-Process HipsTray, wsctrlsvc -ErrorAction SilentlyContinue).Count
Write-Host "Huorong processes active: $hips ; quarantine before: $before"

# ------------------------------------------------------------------ the chain
Write-Host '==> three-level chain (launcher -> launcher -> launcher)'
$env:LUNAPACK_TEST_CHILD = $chain
$env:LUNAPACK_TEST_LEVEL = '1'
$outFile = Join-Path $env:TEMP ("lunapack-chain-" + [guid]::NewGuid().ToString('N') + ".txt")
# The three processes share this console, so the output is captured to a file
# rather than read back through a pipeline.
& $launcher $Dist $chain > $outFile 2>&1
$code = $LASTEXITCODE
$out = Get-Content -LiteralPath $outFile -Raw
Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
Remove-Item Env:\LUNAPACK_TEST_CHILD -ErrorAction SilentlyContinue
Remove-Item Env:\LUNAPACK_TEST_LEVEL -ErrorAction SilentlyContinue

Write-Host '--- chain output ---'
$out -split "`r?`n" | Where-Object { $_ -match 'SPAWN|child follow|inherited|child mode' } |
  ForEach-Object { Write-Host "  $_" }

Check ($code -eq 0) "launcher exit code 0 (got $code)"
Check ($out -match 'SPAWN level=1 virtual read=OK data="VIRTUAL-FS-OK"') 'level 1 read the virtual file'
Check ($out -match 'SPAWN level=1 starting level 2') 'level 1 started another program'
Check ($out -match 'SPAWN level=2 virtual read=OK data="VIRTUAL-FS-OK"') 'level 2 read the same virtual file'
Check ($out -match 'SPAWN level=2 starting level 3') 'level 2 started a third program'
Check ($out -match 'SPAWN level=3 virtual read=OK data="VIRTUAL-FS-OK"') 'level 3 read the same virtual file'
Check ($out -match 'SPAWN chain end') 'chain reached its end'
Check (@([regex]::Matches($out, 'inherited virtual tree from parent: YES')).Count -eq 2) 'both children inherited the tree'

# One redirect each in the two launchers that spawned something, none in the
# innermost one.
$redirects = @([regex]::Matches($out, 'child follow: redirects=(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
Check ($redirects.Count -eq 3) "three launchers reported counters (got $($redirects.Count))"
Check (($redirects | Where-Object { $_ -eq 1 }).Count -eq 2) 'exactly two launchers redirected one spawn each'
Check (($redirects | Where-Object { $_ -eq 0 }).Count -eq 1) 'the innermost launcher redirected nothing'
Check ($out -notmatch 'child follow: redirects=\d+ failures=[1-9]') 'no redirect failed'

# ------------------------------------------------------- no injection imports
Write-Host '==> product binary imports'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswhere) {
  $vsPath = (& $vswhere -latest -products * -property installationPath).Trim()
  $dumpbin = Get-ChildItem (Join-Path $vsPath 'VC\Tools\MSVC') -Directory |
    Sort-Object Name -Descending | Select-Object -First 1 |
    ForEach-Object { Join-Path $_.FullName 'bin\HostX64\x64\dumpbin.exe' }
  $imports = (& $dumpbin /imports $virt 2>&1) -join "`n"
  foreach ($api in @('CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                     'VirtualProtectEx', 'OpenProcess', 'SetThreadContext',
                     'QueueUserAPC', 'NtCreateThreadEx')) {
    Check ($imports -notmatch "\b$api\b") "lpvirt.dll does not import $api"
  }
  Check ($imports -match '\bCreateProcessW\b') 'lpvirt.dll imports CreateProcessW (the redirect)'
} else {
  Write-Host '  SKIP  dumpbin not available, import table not checked'
}

# --------------------------------------------------------- the boundary itself
Write-Host '==> a program started outside the launcher'
$env:LUNAPACK_TEST_LEVEL = '1'
$bare = & $chain 2>&1 | Out-String
$bareCode = $LASTEXITCODE
Remove-Item Env:\LUNAPACK_TEST_LEVEL -ErrorAction SilentlyContinue
Write-Host "  (exit $bareCode)"
$bare -split "`r?`n" | Where-Object { $_ -match 'SPAWN' } | ForEach-Object { Write-Host "  $_" }
Check ($bare -match 'SPAWN level=1 virtual read=FAILED') 'without the launcher the virtual file is not there'

# ------------------------------------------------------------------- AV gate
Write-Host '==> AV retest (separate mechanism)'
$after = QuarantineCount
Check ($before -eq $after) "Huorong quarantine unchanged ($before -> $after)"

Write-Host '==> verdict'
if ($script:failed -eq 0) {
  Write-Host 'ALL CHILD-FOLLOW INVARIANTS PASSED'
  exit 0
}
Write-Host "$($script:failed) CHILD-FOLLOW INVARIANT(S) FAILED" -ForegroundColor Red
exit 1
