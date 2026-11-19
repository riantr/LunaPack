# L2.3 ntdll-boundary interception spike: independent assertions + AV retest.
#
#   powershell -File scripts\verify_ntdll_spike.ps1 [-DistDir <dir>]
#
# This script runs ONLY the new mechanism (NtCreateFile/NtOpenFile/NtReadFile/
# NtClose routed through lpvirt.dll's hook table). It deliberately does not
# run the L1 host, the mini/CRT targets or the LoadLibrary harness, so a
# Huorong event can be attributed to this mechanism alone (AV_RETEST M2b).
#
# The target bypasses the Win32 IAT layer: it resolves the native APIs through
# GetProcAddress and calls them directly. Success on the virtual path proves
# the ntdll-boundary thunk served the bytes; success on C:\Windows\win.ini
# proves the real OS path still works.

param([string]$DistDir = "")

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $DistDir) { $DistDir = Join-Path $root 'dist' }
$dist = (Resolve-Path $DistDir).Path
$launcher = Join-Path $dist 'launcher.exe'
$target = Join-Path $dist 'ntdll_target.exe'

if (-not (Test-Path -LiteralPath $launcher)) { throw "missing $launcher - run build_runtime_windows.ps1 first" }
if (-not (Test-Path -LiteralPath $target)) { throw "missing $target - run build_runtime_windows.ps1 first" }

$failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$label) {
  if ($ok) { Write-Host "  PASS  $label" }
  else { Write-Host "  FAIL  $label"; $failures.Add($label) }
}
function Snapshot([string]$dir, [string]$pattern) {
  $result = @{}
  if (-not (Test-Path -LiteralPath $dir)) { return $result }
  Get-ChildItem -LiteralPath $dir -File -Force -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    Where-Object { -not $pattern -or $_.Name -match $pattern } |
    ForEach-Object { $result[$_.FullName] = "$($_.Length):$($_.LastWriteTimeUtc.Ticks)" }
  return $result
}
function QuarantineCount() {
  $q = "C:\ProgramData\Huorong\Sysdiag\Quarantine"
  if (-not (Test-Path -LiteralPath $q)) { return -1 }
  return @(Get-ChildItem -LiteralPath $q -File -Force -ErrorAction SilentlyContinue).Count
}

Write-Host "==> L2.3 ntdll spike, dist=$dist"
$avBefore = QuarantineCount
$hips = @(Get-Process HipsTray, wsctrlsvc -ErrorAction SilentlyContinue).Count
Write-Host "Huorong processes active: $hips ; quarantine before: $avBefore"
$beforeDist = Snapshot $dist $null
$tempDir = $env:TEMP
if (-not $tempDir) { $tempDir = [System.IO.Path]::GetTempPath() }
$tempPattern = 'lunapack|lpvirt|payload|launcher|ntdll_target'
$selfCapture = Join-Path $env:TEMP 'lp_ntdll_stdout.txt'
if (-not (Test-Path -LiteralPath $selfCapture)) { Set-Content -LiteralPath $selfCapture -Value '' -Encoding ascii }
$beforeTemp = Snapshot $tempDir $tempPattern

Write-Host "==> run launcher.exe --consume on the native-API target"
$outFile = Join-Path $env:TEMP 'lp_ntdll_stdout.txt'
& $launcher $dist $target '--consume' > $outFile 2>&1
$exit = $LASTEXITCODE
$out = (Get-Content -LiteralPath $outFile -Raw) -join "`n"
Write-Host $out

Check ($exit -eq 0) "ntdll target launcher exit code 0 (got $exit)"
Check ($out -match 'target file deleted before mapping: YES') 'native target deleted before mapping'
Check ($out -match 'OS loader knows target\s+: NO') 'native target not registered with the OS loader'
Check ($out -match 'patched IAT slots\s+: [1-9]') 'GetProcAddress slot patched for the native target'
Check ($out -match 'NTDLL virtual=OK') 'NtCreateFile/NtReadFile served a virtual file'
Check ($out -match 'NTDLL fallback=OK') 'NtOpenFile/NtReadFile fell through to a real file'
Check ($out -match 'NTDLL TARGET OK') 'native target self-check passed'
Check ($out -match 'counters:.*ntdll=[1-9]') 'ntdll-boundary virtual hit counter incremented'
Check ($out -match 'THIN LAUNCHER OK') 'launcher completed cleanly'

Write-Host "==> filesystem invariants"
$afterDist = Snapshot $dist $null
$newDist = @($afterDist.Keys | Where-Object { -not $beforeDist.ContainsKey($_) })
$unexpected = @($newDist | Where-Object {
  $n = [System.IO.Path]::GetFileName($_)
  $n -ne 'real.txt' -and $n -ne 'crt_result.txt'
})
Check ($unexpected.Count -eq 0) "no unexpected new file in dist (found: $($unexpected -join ', '))"
Check (-not (Test-Path -LiteralPath $target)) 'ntdll_target.exe absent after --consume'
$afterTemp = Snapshot $tempDir $tempPattern
$newTemp = @($afterTemp.Keys | Where-Object { -not $beforeTemp.ContainsKey($_) })
Check ($newTemp.Count -eq 0) "no new runtime-named file in TEMP (found: $($newTemp -join ', '))"

Write-Host "==> AV retest (M2b, mechanism on its own)"
Start-Sleep -Seconds 2
$avAfter = QuarantineCount
Check ($avAfter -eq $avBefore) "Huorong quarantine unchanged ($avBefore -> $avAfter)"

Write-Host "==> verdict"
if ($failures.Count -gt 0) {
  Write-Host "FAILED: $($failures.Count) invariant(s)"
  $failures | ForEach-Object { Write-Host "  - $_" }
  exit 1
}
Write-Host "ALL NTDLL SPIKE INVARIANTS PASSED"
exit 0
