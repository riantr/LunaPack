# L3 PE-loader completeness: independent assertions + AV retest.
#
#   powershell -File scripts\verify_pe_features.ps1 [-DistDir <dir>]
#
# Covers the four x64 PE-loader completeness items (L3.1-L3.4):
#   L3.1 ordinal imports   - ordinal consumer maps + calls a NONAME import
#   L3.2 forwarded exports - mapped provider's forwarder resolves to kernel32
#   L3.3 delay imports     - white-box descriptor parsing (moon test)
#   L3.4 TLS + SEH         - white-box directory readers + C ABI exports exist
# L3.5-3.7 (x86) is a documented toolchain NO-GO (x86_64-only MoonBit backend).
#
# New mechanisms (ordinal export-table walk, forwarder resolution) get their own
# Huorong retest (AV_RETEST M3).

param([string]$DistDir = "")

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $DistDir) { $DistDir = Join-Path $root 'dist' }
$dist = (Resolve-Path $DistDir).Path
$launcher = Join-Path $dist 'launcher.exe'
$ordExe = Join-Path $dist 'pe_ordinal_consumer.exe'
$xpExe = Join-Path $dist 'pe_export_probe.exe'
$provider = Join-Path $dist 'pe_provider.dll'
foreach ($p in @($launcher, $ordExe, $xpExe, $provider)) {
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

Write-Host "==> L3 PE features, dist=$dist"
$avBefore = QuarantineCount
$hips = @(Get-Process HipsTray, wsctrlsvc -ErrorAction SilentlyContinue).Count
Write-Host "Huorong processes active: $hips ; quarantine before: $avBefore"

# ---- L3.1 ordinal imports ------------------------------------------------
Write-Host "==> L3.1 ordinal import resolution"
$oOut = Join-Path $env:TEMP 'lp_l3_ordinal.txt'
if (-not (Test-Path -LiteralPath $oOut)) { Set-Content -LiteralPath $oOut -Value '' -Encoding ascii }
& $launcher $dist $ordExe > $oOut 2>&1
$oExit = $LASTEXITCODE
$o = (Get-Content -LiteralPath $oOut -Raw) -join "`n"
Check ($oExit -eq 0) "ordinal consumer exit 0 (got $oExit)"
Check ($o -match 'ORDINAL IMPORT OK') 'NONAME ordinal import resolved from provider export table'
Check (-not ($o -match 'MANUAL MAP FAILED')) 'no map failure (ordinal no longer rejected)'
Check ($o -match 'hook lifecycle:.*violations=0') 'no detach-order violation'

# ---- L3.2 forwarded exports ----------------------------------------------
Write-Host "==> L3.2 forwarded export resolution"
$xOut = Join-Path $env:TEMP 'lp_l3_forward.txt'
if (-not (Test-Path -LiteralPath $xOut)) { Set-Content -LiteralPath $xOut -Value '' -Encoding ascii }
& $xpExe $dist $provider > $xOut 2>&1
$xExit = $LASTEXITCODE
$x = (Get-Content -LiteralPath $xOut -Raw) -join "`n"
Write-Host $x
Check ($xExit -eq 0) "export probe exit 0 (got $xExit)"
Check ($x -match 'pe_add\s+= 0x[0-9a-f]+ \(in mapped image: YES\)') 'normal export resolved inside mapped image'
Check ($x -match 'forwarded matches kernel32: YES') 'forwarded export resolved to real kernel32.GetCurrentProcessId'
Check ($x -match 'PE EXPORT PROBE OK') 'export probe self-check passed'

# ---- L3.3 / L3.4 white-box gates (via build stage moon test) -------------
Write-Host "==> L3.3 / L3.4 white-box (delay/TLS/EH directory readers)"
$mtFile = Join-Path $env:TEMP 'lp_l3_moon_test.txt'
if (-not (Test-Path -LiteralPath $mtFile)) { Set-Content -LiteralPath $mtFile -Value '' -Encoding ascii }
Push-Location (Join-Path $root 'runtime')
& moon test --target native > $mtFile 2>&1
$mtExit = $LASTEXITCODE
Pop-Location
$mt = (Get-Content -LiteralPath $mtFile -Raw) -join "`n"
Check ($mtExit -eq 0) "runtime moon test exit 0 (got $mtExit)"
Check ($mt -match 'Total tests: \d+, passed: \d+, failed: 0') 'runtime white-box tests all pass (delay/TLS/EH readers)'

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
Write-Host "ALL PE-FEATURE INVARIANTS PASSED"
exit 0
