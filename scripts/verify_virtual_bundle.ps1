# Automated end-to-end assertion for the L6 virtual bundle path.
#
#   powershell -File scripts\verify_virtual_bundle.ps1 [-DistDir <dir>]
#
# This verifies the shipping path, not the C test host: the CLI makes a v7
# bundle, lpvhost.exe maps the embedded runtime and main image in memory, and
# the mapped program reads its virtual files through the hooked IAT. The source
# fixture is deleted after packing, so a successful run is proof that nothing
# was unpacked to disk first.
#
# Invariants:
#   1. the CLI reports a v7 bundle with a virtual layer and the runtime entry
#   2. --no-virtual still produces a plain, unpacking bundle
#   3. lpvhost.exe refuses a bundle that has no virtual layer
#   4. lpvhost.exe runs the CLI bundle and every mapped-program check passes
#   5. a checksum-damaged copy of the bundle is refused
#   6. no payload file is extracted into the working directory or %TEMP%
#   7. Huorong quarantine count is unchanged (separate AV retest for L6)

param([string]$DistDir = "", [switch]$KeepScratch)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $DistDir) { $DistDir = Join-Path $root 'dist' }
$dist = (Resolve-Path $DistDir).Path

$cli = Join-Path $root '_build\native\release\build\LunaPack.exe'
$launcher = Join-Path $dist 'lpvhost.exe'
$runtime = Join-Path $dist 'lpvirt.dll'
$target = Join-Path $dist 'mini_target.exe'
$dynlib = Join-Path $dist 'dynlib.dll'

foreach ($needed in @($cli, $launcher, $runtime, $target, $dynlib)) {
  if (-not (Test-Path -LiteralPath $needed)) {
    throw "missing $needed - build the root CLI and scripts/build_runtime_windows.ps1 first"
  }
}

$failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$label) {
  if ($ok) { Write-Host "  PASS  $label" }
  else { Write-Host "  FAIL  $label"; $failures.Add($label) }
}
function Quote([string]$text) {
  return '"' + $text.Replace('"', '\"') + '"'
}
function RunCapture([string]$exe, [string[]]$arguments, [string]$outFile) {
  # Windows PowerShell 5.1 turns native stderr into an error record even when
  # 2>&1 is present. cmd.exe performs the redirection before PowerShell sees
  # the output, so the verifier gets the text and the real exit code.
  $parts = @((Quote $exe))
  foreach ($argument in $arguments) { $parts += Quote $argument }
  $command = ($parts -join ' ') + ' > ' + (Quote $outFile) + ' 2>&1'
  & cmd.exe /c $command | Out-Null
  return $LASTEXITCODE
}
function ReadOut([string]$path) {
  return ((Get-Content -LiteralPath $path -Raw) -join "`n")
}
function Snapshot([string]$dir, [string]$pattern) {
  $set = New-Object 'System.Collections.Generic.HashSet[string]'
  if (-not (Test-Path -LiteralPath $dir)) { return $set }
  Get-ChildItem -LiteralPath $dir -File -Force -Recurse -ErrorAction SilentlyContinue |
    Where-Object { -not $pattern -or $_.Name -match $pattern } |
    ForEach-Object { [void]$set.Add($_.FullName) }
  return $set
}
function QuarantineCount() {
  $q = "C:\ProgramData\Huorong\Sysdiag\Quarantine"
  if (-not (Test-Path -LiteralPath $q)) { return -1 }
  return @(Get-ChildItem -LiteralPath $q -File -Force -ErrorAction SilentlyContinue).Count
}
function WriteAscii([string]$path, [string]$text) {
  [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.ASCIIEncoding))
}

$scratch = Join-Path $root 'build\verify_virtual_bundle'
if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
try {
  $fixture = Join-Path $scratch 'fixture'
  $registry = Join-Path $scratch 'registry.json'
  $bundle = Join-Path $scratch 'vdemo.exe'
  $plain = Join-Path $scratch 'plain.exe'
  $corrupt = Join-Path $scratch 'damaged.exe'
  $bundleOut = Join-Path $scratch 'bundle.txt'
  $infoOut = Join-Path $scratch 'info.txt'
  $plainBundleOut = Join-Path $scratch 'plain_bundle.txt'
  $plainInfoOut = Join-Path $scratch 'info_plain.txt'
  $runOut = Join-Path $scratch 'run.txt'
  $plainOut = Join-Path $scratch 'plain.txt'
  $damagedOut = Join-Path $scratch 'damaged.txt'

  New-Item -ItemType Directory -Path (Join-Path $fixture 'virt') -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $fixture 'cfg') -Force | Out-Null
  WriteAscii (Join-Path $fixture 'virt\hello.txt') 'VIRTUAL-FS-OK'
  WriteAscii (Join-Path $fixture 'virt\ansi.txt') 'ANSI'
  WriteAscii (Join-Path $fixture 'cfg\seed.txt') 'SEED'
  Copy-Item -LiteralPath $dynlib -Destination (Join-Path $fixture 'dynlib.dll') -Force
  WriteAscii $registry '{"values":[{"root":"hklm","key":"Software\\LunaPackVerify","name":"Port","kind":"REG_DWORD","number":8080}]}'
  foreach ($log in @($bundleOut, $infoOut, $plainBundleOut, $plainInfoOut, $runOut, $plainOut, $damagedOut)) {
    WriteAscii $log ''
  }

  Write-Host "==> build the virtual bundle with the shipping CLI"
  $bundleExit = RunCapture $cli @(
    'bundle', '-i', $target, '-o', $bundle,
    '--Files', $fixture,
    '--virtual', '--virtual-root=C:/', '--virtual-temp=C:/virt/tmp/',
    '--registry', $registry, '--compression-method=none',
    '--launcher', $launcher
  ) $bundleOut
  $bundleLog = ReadOut $bundleOut
  Write-Host $bundleLog
  Check ($bundleExit -eq 0) "CLI bundle exit code 0 (got $bundleExit)"
  Check (Test-Path -LiteralPath $bundle) 'virtual bundle was produced'

  $infoExit = RunCapture $cli @('info', $bundle) $infoOut
  $bundleInfo = ReadOut $infoOut
  Check ($infoExit -eq 0) "CLI info exit code 0 (got $infoExit)"
  Check ($bundleInfo -match 'format:\s+v7') 'bundle uses format v7'
  Check ($bundleInfo -match 'virtual:\s+C:\\\s+\(5 files, 1 registry values\)') 'manifest carries the virtual layer and typed registry seed'
  Check ($bundleInfo -match 'runtime:\s+@runtime/lpvirt\.dll') 'runtime DLL is a checksummed archive entry'

  Write-Host "==> build and refuse a plain bundle"
  $plainExit = RunCapture $cli @(
    'bundle', '-i', $target, '-o', $plain,
    '--Files', $fixture, '--no-virtual',
    '--compression-method=none', '--launcher', $launcher
  ) $plainBundleOut
  Check ($plainExit -eq 0) "--no-virtual bundle exit code 0 (got $plainExit)"
  $plainInfoExit = RunCapture $cli @('info', $plain) $plainInfoOut
  $plainInfo = ReadOut $plainInfoOut
  Check ($plainInfoExit -eq 0) "CLI info on plain bundle exit code 0 (got $plainInfoExit)"
  Check ($plainInfo -match 'virtual:\s+none') '--no-virtual manifest has no virtual layer'
  $refuseExit = RunCapture $plain @() $plainOut
  $refuseLog = ReadOut $plainOut
  Write-Host $refuseLog
  Check ($refuseExit -ne 0) "lpvhost refuses the plain bundle (got $refuseExit)"
  Check ($refuseLog -match 'carries no LunaPack virtual bundle') 'refusal names the missing virtual layer'

  Write-Host "==> damage one virtual file inside a copy of the bundle"
  $bytes = [System.IO.File]::ReadAllBytes($bundle)
  $needle = [System.Text.Encoding]::ASCII.GetBytes('VIRTUAL-FS-OK')
  $found = -1
  for ($i = 0; $i -le $bytes.Length - $needle.Length; $i++) {
    $same = $true
    for ($j = 0; $j -lt $needle.Length; $j++) {
      if ($bytes[$i + $j] -ne $needle[$j]) { $same = $false; break }
    }
    if ($same) { $found = $i }
  }
  Check ($found -ge 0) 'virtual payload bytes are present in the bundle'
  if ($found -ge 0) {
    $bytes[$found + $needle.Length - 1] = [byte][char]'X'
    [System.IO.File]::WriteAllBytes($corrupt, $bytes)
    $damagedExit = RunCapture $corrupt @() $damagedOut
    $damagedLog = ReadOut $damagedOut
    Write-Host $damagedLog
    Check ($damagedExit -ne 0) "corrupted bundle is refused (got $damagedExit)"
    Check ($damagedLog -match 'checksum|damaged|does not decompress|manifest is not JSON') 'refusal names integrity damage'
  }

  Write-Host "==> remove the source fixture and run the bundle"
  Remove-Item -LiteralPath $fixture -Recurse -Force
  $avBefore = QuarantineCount
  $tempDir = $env:TEMP
  if (-not $tempDir) { $tempDir = [System.IO.Path]::GetTempPath() }
  $tempPattern = 'lunapack|lpvirt|lpvhost|mini_target|dynlib|hello\.txt|ansi\.txt|seed\.txt|fromansi\.txt'
  $beforeScratch = Snapshot $scratch $null
  $beforeTemp = Snapshot $tempDir $tempPattern

  $runExit = RunCapture $bundle @() $runOut
  $runLog = ReadOut $runOut
  Write-Host $runLog
  Check ($runExit -eq 0) "virtual bundle exit code 0 (got $runExit)"
  # mini_target.exe's putn() emits a NUL before the digits of a two-digit
  # number; the console hides it, a byte-accurate assertion must not.
  Check ($runLog -match 'THIN-EXE file="VIRTUAL-FS-OK" size=\x00?13\s+attrs=0x80 result=OK') 'mapped program read the virtual file through the hooked IAT'
  Check ($runLog -match 'THIN-EXE ansi attrs=0x80') 'ANSI file attributes came from the virtual FS'
  Check ($runLog -match 'THIN-EXE ansi create=OK') 'a new file was created in memory under the seeded virtual directory'
  Check ($runLog -match 'THIN-EXE temp=OK') 'GetTempPathW returned the seeded virtual temp directory'
  Check ($runLog -match 'THIN-EXE dyn gpa attrs=0x80') 'dynamic API resolution reached a virtualized thunk'
  Check ($runLog -match 'THIN-EXE dyn lib probe=OK') 'runtime-loaded DLL saw the virtual file'

  Write-Host "==> no-payload-on-disk and AV invariants"
  $afterScratch = Snapshot $scratch $null
  $newScratch = @($afterScratch | Where-Object { -not $beforeScratch.Contains($_) })
  Check ($newScratch.Count -eq 0) "no new file in the working directory (found: $($newScratch -join ', '))"
  foreach ($name in @('hello.txt', 'ansi.txt', 'seed.txt', 'fromansi.txt', 'dynlib.dll')) {
    $foundFiles = @(Get-ChildItem -LiteralPath $scratch -File -Force -Recurse -Filter $name -ErrorAction SilentlyContinue)
    Check ($foundFiles.Count -eq 0) "no extracted $name in the working directory"
  }
  $afterTemp = Snapshot $tempDir $tempPattern
  $newTemp = @($afterTemp | Where-Object { -not $beforeTemp.Contains($_) })
  Check ($newTemp.Count -eq 0) "no new payload file in TEMP (found: $($newTemp -join ', '))"
  $avAfter = QuarantineCount
  Check ($avAfter -eq $avBefore) "Huorong quarantine unchanged ($avBefore -> $avAfter)"

  Write-Host "==> verdict"
  if ($failures.Count -gt 0) {
    Write-Host "FAILED: $($failures.Count) invariant(s)"
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
  }
  Write-Host "ALL VIRTUAL BUNDLE INVARIANTS PASSED"
  exit 0
}
finally {
  if (-not $KeepScratch -and (Test-Path -LiteralPath $scratch)) {
    Remove-Item -LiteralPath $scratch -Recurse -Force
  }
}
