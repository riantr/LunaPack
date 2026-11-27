# Automated zero-disk assertion for the in-process runtime (L0.3).
#
#   powershell -File scripts\verify_zero_disk.ps1 [-DistDir <dir>]
#
# This is not a demonstration: it fails (non-zero exit) if any of the
# invariants below is broken. It wraps the existing host.exe --consume demo,
# snapshots the working directory and %TEMP% around the run, and checks both
# the harness output and the filesystem.
#
# Invariants:
#   1. payload.dll is deleted before mapping, and is still absent afterward
#   2. OS loader never knows payload.dll
#   3. every hooked API this payload imports gets its IAT slot rewritten (22)
#   4. real HKLM key was never created
#   5. no new file in the dist directory other than the harness's own real.txt
#   6. no new lunapack/lpvirt/payload-named file in %TEMP%
#   7. host.exe exits 0
#   8. L1 semantics: write / by-handle info / attributes / overlapped /
#      rename / delete / completion all succeed from the memory tree

param([string]$DistDir = "")

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $DistDir) { $DistDir = Join-Path $root 'dist' }
$dist = (Resolve-Path $DistDir).Path
$hostExe = Join-Path $dist 'host.exe'
$payload = Join-Path $dist 'payload.dll'

if (-not (Test-Path -LiteralPath $hostExe)) { throw "missing $hostExe - run build_runtime_windows.ps1 first" }
if (-not (Test-Path -LiteralPath $payload)) { throw "missing $payload - run build_runtime_windows.ps1 first" }

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

Write-Host "==> zero-disk assertion, dist=$dist"
$beforeDist = Snapshot $dist $null
$tempDir = $env:TEMP
if (-not $tempDir) { $tempDir = [System.IO.Path]::GetTempPath() }
$tempPattern = 'lunapack|lpvirt|payload|lunapack_runtime'
$beforeTemp = Snapshot $tempDir $tempPattern

Write-Host "==> run host.exe --consume (output captured)"
$outFile = Join-Path $env:TEMP 'lp_zero_disk_stdout.txt'
& $hostExe $dist '--consume' > $outFile 2>&1
$exit = $LASTEXITCODE
$out = (Get-Content -LiteralPath $outFile -Raw) -join "`n"
Write-Host $out

# ---- output invariants -------------------------------------------------
Write-Host "==> output invariants"
Check ($exit -eq 0) "host.exe exit code 0 (got $exit)"
Check ($out -match 'payload file deleted before mapping: YES') 'payload deleted before mapping'
Check ($out -match 'OS loader knows payload.dll: NO') 'OS loader does not know payload.dll'
Check ($out -match 'payload file still on disk : NO') 'payload absent from disk after run'
# One patched slot per imported hooked API. The number rose from 21 to 22
# when L5 hooks landed, and to 24 after the L2.6/L2.7/L2.8 resolution hooks,
# so pin a floor rather than an exact count: growth is expected, a fall is not.
$iatSlots = 0
$iatMatch = [regex]::Match($out, 'patched IAT slots\s+: (\d+)')
if ($iatMatch.Success) { $iatSlots = [int]$iatMatch.Groups[1].Value }
Check ($iatSlots -ge 22) "IAT slots patched >= 22 (got $iatSlots; one per hooked API the payload imports)"
Check ($out -match 'DllMain\(DLL_PROCESS_ATTACH\): TRUE') 'DllMain attach succeeded'
Check ($out -match 'real registry key open = 2') 'real HKLM key never created'
Check ($out -match 'virtual file :.*VIRTUAL-FS-OK') 'virtual file read from memory'
Check ($out -match 'dynamic hook : data="DYNAMIC-HOOK-OK"') 'dynamic GetProcAddress hook hit'

# ---- L1 semantics ----------------------------------------------------
Write-Host "==> L1 semantics invariants"
Check ($out -match 'L1 write : ok=1 wrote=8 data="APPENDED"') 'L1 WriteFile extends virtual file'
Check ($out -match 'L1 byhandle: ok=1 size=8 fid=\d+') 'L1 GetFileInformationByHandle size + file ID'
Check ($out -match 'L1 attrsex: ok=1 attrs=0x80 size=8') 'L1 GetFileAttributesExW metadata'
Check ($out -match 'L1 overlap: ok=1 got=4 data="PPEN"') 'L1 overlapped positioned read'
Check ($out -match 'L1 ren/del: move=1 renamedAttrs=0x80 del=1') 'L1 rename + delete virtual file'
Check ($out -match 'L1 completion: ok=1 key=4242 bytes=7') 'L1 completion queue drain'

# ---- filesystem invariants ---------------------------------------------
Write-Host "==> filesystem invariants"
$afterDist = Snapshot $dist $null
$newDist = @($afterDist.Keys | Where-Object { -not $beforeDist.ContainsKey($_) })
$allowedNew = @('real.txt')   # the harness deliberately creates this real file
$unexpected = @($newDist | Where-Object { $n = [System.IO.Path]::GetFileName($_); $allowedNew -notcontains $n })
Check ($unexpected.Count -eq 0) "no unexpected new file in dist (found: $($unexpected -join ', '))"
Check (-not (Test-Path -LiteralPath $payload)) 'payload.dll absent after run'

$afterTemp = Snapshot $tempDir $tempPattern
$newTemp = @($afterTemp.Keys | Where-Object { -not $beforeTemp.ContainsKey($_) })
Check ($newTemp.Count -eq 0) "no new lunapack/lpvirt/payload file in TEMP (found: $($newTemp -join ', '))"

# ---- verdict ------------------------------------------------------------
Write-Host "==> verdict"
if ($failures.Count -gt 0) {
  Write-Host "FAILED: $($failures.Count) invariant(s)"
  $failures | ForEach-Object { Write-Host "  - $_" }
  exit 1
}
Write-Host "ALL ZERO-DISK INVARIANTS PASSED"
exit 0
