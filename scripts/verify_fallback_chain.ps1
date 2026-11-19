# L2.5 fallback-chain integrity: independent assertions + AV retest.
#
#   powershell -File scripts\verify_fallback_chain.ps1 [-DistDir <dir>]
#
# Proves two things, item by item:
#   A) STRUCTURAL - lpvirt.dll's own IAT never points at one of our thunks
#      (self_thunk_hits=0) and every real fallback target resolves. This is the
#      "no trampoline / no recursion" guarantee.
#   B) BEHAVIOURAL - a virtual miss in EACH thunk category returns real OS data
#      through the fallback_target.exe probe (W file/attrs/enum, A file,
#      registry, ntdll symbol, temp path), plus the existing host real-file and
#      real-registry checks and the L2.3 native win.ini fallback.
#
# This mechanism adds no new OS-level behaviour beyond what L2.0-L2.3 already
# ran, but per the Loop protocol it gets its own Huorong retest (AV_RETEST M2c).

param([string]$DistDir = "")

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $DistDir) { $DistDir = Join-Path $root 'dist' }
$dist = (Resolve-Path $DistDir).Path
$launcher = Join-Path $dist 'launcher.exe'
$hostExe = Join-Path $dist 'host.exe'
$target = Join-Path $dist 'fallback_target.exe'
$ntdll = Join-Path $dist 'ntdll_target.exe'
foreach ($p in @($launcher, $hostExe, $target, $ntdll)) {
  if (-not (Test-Path -LiteralPath $p)) { throw "missing $p - run build_runtime_windows.ps1 first" }
}

$failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$label) {
  if ($ok) { Write-Host "  PASS  $label" }
  else { Write-Host "  FAIL  $label"; $failures.Add($label) }
}
function QuarantineCount() {
  $q = "C:\ProgramData\Huorong\Sysdiag\Quarantine"
  if (-not (Test-Path -LiteralPath $q)) { return -1 }
  return @(Get-ChildItem -LiteralPath $q -File -Force -ErrorAction SilentlyContinue).Count
}

Write-Host "==> L2.5 fallback-chain integrity, dist=$dist"
$avBefore = QuarantineCount
$hips = @(Get-Process HipsTray, wsctrlsvc -ErrorAction SilentlyContinue).Count
Write-Host "Huorong processes active: $hips ; quarantine before: $avBefore"

# ---- A) structural audit (through the real host demo) --------------------
Write-Host "==> structural audit (lpvirt.dll self IAT)"
$hostOut = Join-Path $env:TEMP 'lp_fb_host_stdout.txt'
if (-not (Test-Path -LiteralPath $hostOut)) { Set-Content -LiteralPath $hostOut -Value '' -Encoding ascii }
& $hostExe $dist '--consume' > $hostOut 2>&1
$hostExit = $LASTEXITCODE
$h = (Get-Content -LiteralPath $hostOut -Raw) -join "`n"
Check ($hostExit -eq 0) "host.exe exit 0 (got $hostExit)"
Check ($h -match 'fallback audit: self_thunk_hits=0 probes=9 unresolved=0 status=0') `
  'lpvirt.dll own IAT unpatched; all 9 fallback targets resolve'
Check ($h -match 'hook lifecycle:.*violations=0') 'L2.4 detach guard still clean'
Check ($h -match 'real file\s+:.*REAL-FS-OK') 'host real-file fall-through (CreateFileW/ReadFile)'
Check ($h -match 'real registry: open=0 \(fall-through\)') 'host real-registry fall-through (RegOpenKeyExW)'

# ---- B) behavioural per-category probe ----------------------------------
Write-Host "==> behavioural per-category fallback probe"
$fbOut = Join-Path $env:TEMP 'lp_fb_target_stdout.txt'
if (-not (Test-Path -LiteralPath $fbOut)) { Set-Content -LiteralPath $fbOut -Value '' -Encoding ascii }
& $launcher $dist $target > $fbOut 2>&1
$fbExit = $LASTEXITCODE
$f = (Get-Content -LiteralPath $fbOut -Raw) -join "`n"
Write-Host $f
Check ($fbExit -eq 0) "fallback_target exit 0 (got $fbExit)"
foreach ($cat in @('W file','W attrs','A file','W enum','registry','ntdll resolve','temp path')) {
  Check ($f -match [regex]::Escape("$cat") + '\s*: OK') "$cat category falls through to real OS API"
}
Check ($f -match 'FALLBACK TARGET DONE') 'probe reached the end without faulting'
Check ($f -match 'hook lifecycle:.*violations=0') 'no detach-order violation in probe'

# ---- B2) ntdll native fallback (L2.3 regression under this mechanism) ----
Write-Host "==> native-API fallback regression"
$ntOut = Join-Path $env:TEMP 'lp_fb_ntdll_stdout.txt'
if (-not (Test-Path -LiteralPath $ntOut)) { Set-Content -LiteralPath $ntOut -Value '' -Encoding ascii }
& $launcher $dist $ntdll > $ntOut 2>&1
$n = (Get-Content -LiteralPath $ntOut -Raw) -join "`n"
Check ($n -match 'NTDLL virtual=OK') 'ntdll virtual path (regression)'
Check ($n -match 'NTDLL fallback=OK') 'ntdll real win.ini fall-through'

# ---- AV retest -----------------------------------------------------------
Write-Host "==> AV retest (separate mechanism)"
$avAfter = QuarantineCount
Check ($avAfter -eq $avBefore) "Huorong quarantine unchanged ($avBefore -> $avAfter)"

Write-Host "==> verdict"
if ($failures.Count -gt 0) {
  Write-Host "FAILED: $($failures.Count) invariant(s)"
  $failures | ForEach-Object { Write-Host "  - $_" }
  exit 1
}
Write-Host "ALL FALLBACK-CHAIN INVARIANTS PASSED"
exit 0
