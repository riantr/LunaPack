# Automated zero-disk + AV assertion for the L2.0 thin launcher spike.
#
#   powershell -File scripts\verify_thin_launcher.ps1 [-DistDir <dir>]
#
# The thin launcher maps a real PE32+ EXE image (not a DLL) into its own
# process, patches that image's IAT, and calls its AddressOfEntryPoint. This
# is a NEW mechanism compared with the L1 DLL harness, so per the Loop protocol
# it gets its own Huorong retest instead of riding on the earlier result.
#
# Invariants:
#   1. target EXE is deleted before mapping and stays absent
#   2. OS loader never knows the target image
#   3. >= 1 IAT slot patched on the mapped EXE
#   4. mapped EXE reads the virtual file through the hooked IAT (result=OK)
#   5. mapped EXE exits 0 and launcher exits 0
#   6. no new file in dist other than the harness's own real.txt
#   7. no new lunapack/lpvirt/payload/launcher/mini_target file in %TEMP%
#   8. Huorong quarantine count unchanged (AV retest for this mechanism)

param([string]$DistDir = "")

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $DistDir) { $DistDir = Join-Path $root 'dist' }
$dist = (Resolve-Path $DistDir).Path
$launcher = Join-Path $dist 'launcher.exe'
$target = Join-Path $dist 'mini_target.exe'

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

Write-Host "==> thin launcher assertion, dist=$dist"
$avBefore = QuarantineCount
$beforeDist = Snapshot $dist $null
$tempDir = $env:TEMP
if (-not $tempDir) { $tempDir = [System.IO.Path]::GetTempPath() }
$tempPattern = 'lunapack|lpvirt|payload|launcher|mini_target'
# The assertion's own capture file lives in %TEMP% and matches the pattern;
# snapshot it as "already present" so it is not reported as a new file.
$selfCapture = Join-Path $env:TEMP 'lp_thin_launcher_stdout.txt'
if (-not (Test-Path -LiteralPath $selfCapture)) { Set-Content -LiteralPath $selfCapture -Value '' -Encoding ascii }
$beforeTemp = Snapshot $tempDir $tempPattern

Write-Host "==> run launcher.exe --consume (output captured)"
$outFile = Join-Path $env:TEMP 'lp_thin_launcher_stdout.txt'
& $launcher $dist $target '--consume' > $outFile 2>&1
$exit = $LASTEXITCODE
$out = (Get-Content -LiteralPath $outFile -Raw) -join "`n"
Write-Host $out

Write-Host "==> output invariants"
Check ($exit -eq 0) "launcher.exe exit code 0 (got $exit)"
Check ($out -match 'target file deleted before mapping: YES') 'target deleted before mapping'
Check ($out -match 'OS loader knows target\s+: NO') 'OS loader does not know target image'
Check ($out -match 'target file still on disk\s+: NO') 'target absent from disk after run'
Check ($out -match 'patched IAT slots\s+: [1-9]') '>= 1 IAT slot patched on mapped EXE'
Check ($out -match 'THIN-EXE file="VIRTUAL-FS-OK"') 'mapped EXE read virtual file through hooked IAT'
Check ($out -match 'THIN-EXE .* result=OK') 'mapped EXE self-check passed'
Check ($out -match 'THIN-EXE ansi attrs=0x80') 'L2.1 GetFileAttributesA through mapped IAT'
Check ($out -match 'THIN-EXE ansi create=OK') 'L2.1 CreateFileA + WriteFile through mapped IAT'
Check ($out -match 'THIN-EXE temp=OK') 'L2.1 GetTempPathW returns virtual temp path'
Check ($out -match 'THIN-EXE dyn gpa attrs=0x80') 'L2.2 GetProcAddress returns a virtualized thunk'
Check ($out -match 'THIN-EXE dyn ordinal=no-fault') 'L2.2 ordinal GetProcAddress does not fault'
Check ($out -match 'THIN-EXE dyn lib probe=OK') 'L2.2 LoadLibraryA patches a runtime-loaded module IAT'
Check ($out -match 'counters:.*dyn=[1-9]') 'L2.2 dynamic hook counter incremented'
Check ($out -match 'hook lifecycle: mapped=[1-9] loaded=[1-9]') 'L2.4 mapped + LoadLibrary paths used the one installer'
Check ($out -match 'hook lifecycle:.*violations=0') 'L2.4 no detach-order violation'
Check ($out -match 'mapped EXE exit code\s+: 0') 'mapped EXE exit code 0'
Check ($out -match 'THIN LAUNCHER OK') 'thin launcher completed'

Write-Host "==> L2.1 ExitProcess strategy (CRT target on worker thread)"
$crtExe = Join-Path $dist 'crt_target.exe'
$crtResult = Join-Path $dist 'crt_result.txt'
if (Test-Path -LiteralPath $crtResult) { Remove-Item -LiteralPath $crtResult -Force }
$env:RESULT_FILE = $crtResult
$crtOutFile = Join-Path $env:TEMP 'lp_thin_crt_stdout.txt'
if (-not (Test-Path -LiteralPath $crtOutFile)) { Set-Content -LiteralPath $crtOutFile -Value '' -Encoding ascii }
& $launcher $dist $crtExe '--thread' > $crtOutFile 2>&1
$crtExit = $LASTEXITCODE
$crtOut = (Get-Content -LiteralPath $crtOutFile -Raw) -join "`n"
Write-Host $crtOut
Check ($crtExit -eq 0) "CRT launcher exit code 0 (got $crtExit)"
Check ($crtOut -match 'worker thread\s+: YES') 'CRT entry ran on worker thread'
Check ($crtOut -match 'ExitProcess intercepted\s+: YES') 'CRT ExitProcess was redirected'
Check ($crtOut -match 'THIN LAUNCHER OK') 'launcher regained control after ExitProcess'
$crtFileOk = $false
if (Test-Path -LiteralPath $crtResult) {
  $crtFileOk = ((Get-Content -LiteralPath $crtResult -Raw) -match 'ok=1')
  Remove-Item -LiteralPath $crtResult -Force
}
Check $crtFileOk 'CRT main() read virtual file via hooked IAT'

Write-Host "==> filesystem invariants"
$afterDist = Snapshot $dist $null
$newDist = @($afterDist.Keys | Where-Object { -not $beforeDist.ContainsKey($_) })
$allowedNew = @('real.txt')
$unexpected = @($newDist | Where-Object { $n = [System.IO.Path]::GetFileName($_); $allowedNew -notcontains $n })
Check ($unexpected.Count -eq 0) "no unexpected new file in dist (found: $($unexpected -join ', '))"
Check (-not (Test-Path -LiteralPath $target)) 'mini_target.exe absent after run'

$afterTemp = Snapshot $tempDir $tempPattern
$newTemp = @($afterTemp.Keys | Where-Object { -not $beforeTemp.ContainsKey($_) })
Check ($newTemp.Count -eq 0) "no new runtime-named file in TEMP (found: $($newTemp -join ', '))"

Write-Host "==> AV retest (separate mechanism)"
$avAfter = QuarantineCount
Check ($avAfter -eq $avBefore) "Huorong quarantine unchanged ($avBefore -> $avAfter)"

Write-Host "==> verdict"
if ($failures.Count -gt 0) {
  Write-Host "FAILED: $($failures.Count) invariant(s)"
  $failures | ForEach-Object { Write-Host "  - $_" }
  exit 1
}
Write-Host "ALL THIN LAUNCHER INVARIANTS PASSED"
exit 0
