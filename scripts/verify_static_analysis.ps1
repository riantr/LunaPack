# Static-analysis gate: the numbers may only go down.
#
#   powershell -File scripts\verify_static_analysis.ps1
#   powershell -File scripts\verify_static_analysis.ps1 -UpdateBaseline
#
# Two analyzers run over the tree. Their outputs are compared with
# `scripts\static_analysis_baseline.json`, and a count that rose past the
# baseline stops the release.
#
# Why it is a script and not a paragraph: the earlier baseline in the tracker
# said "LunaFlow dead=1 taint=9", measured with the default `--max-functions
# 150`. Re-run without that cap the same code reports taint=53, so the number
# in the tracker was really "what the first 150 functions happened to contain".
# A number nobody can reproduce cannot be a gate.
#
# Both coordinates are pinned, not `@latest`: the counts move with the analyzer,
# so a green run against a different build says nothing about this one.

param(
  [string]$BaselineFile = "",
  [switch]$UpdateBaseline
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $BaselineFile) { $BaselineFile = Join-Path $PSScriptRoot 'static_analysis_baseline.json' }

$msaCoordinate = 'riantr/moonbit_static_analysis@0.5.0'
$flowCoordinate = 'riantr/LunaFlow@0.1.28'
# The default cap interprets the first 150 functions in file order, which makes
# every count a function of file names rather than of the code. Lift it.
$flowMaxFunctions = 5000

$moonx = (Get-Command moonx -ErrorAction SilentlyContinue).Source
if (-not $moonx) { throw 'moonx is not on PATH - it ships with the MoonBit toolchain under ~/.moon/bin' }

$failures = New-Object System.Collections.Generic.List[string]
$script:checks = 0
function Check([bool]$ok, [string]$label) {
  $script:checks = $script:checks + 1
  if ($ok) { Write-Host "  PASS  $label" }
  else { Write-Host "  FAIL  $label"; $failures.Add($label) }
}

function Invoke-Tool([string]$coordinate, [string[]]$arguments) {
  $output = & $moonx $coordinate @arguments 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) {
    throw "$coordinate exited $LASTEXITCODE`n$($output.Substring(0, [Math]::Min(2000, $output.Length)))"
  }
  return $output
}

# `SUMMARY files=83 parsed=83 actionable=0 notices=787 ...`
function Parse-Msa([string]$text) {
  $line = ($text -split "`n" | Where-Object { $_ -match '^SUMMARY\s' } | Select-Object -First 1)
  if (-not $line) { throw 'the MSA run printed no SUMMARY line' }
  $row = @{}
  foreach ($pair in ($line -split "\s+")) {
    if ($pair -match '^([a-z]+)=(-?\d+)$') { $row[$Matches[1]] = [int]$Matches[2] }
  }
  return $row
}

# Per-file notice counts, so a rise can be attributed instead of argued about.
function Parse-MsaFiles([string]$text) {
  $row = @{}
  foreach ($line in ($text -split "`n")) {
    $line = $line.TrimEnd("`r")
    if ($line -match '^FOUND\s+\S+\s+defects=(\d+)\s+notices=(\d+)\s+unchecked=(\d+)\s+(\./\S+)$') {
      $row[$Matches[4]] = @{ defects = [int]$Matches[1]; notices = [int]$Matches[2] }
    }
    elseif ($line -match '^CLEAN\s+\S+\s+unchecked=\d+\s+(\./\S+)$') {
      $row[$Matches[1]] = @{ defects = 0; notices = 0 }
    }
  }
  return $row
}

# `dead_code<TAB>1`
function Parse-Flow([string]$text) {
  $row = @{}
  foreach ($line in ($text -split "`n")) {
    if ($line -match '^([a-z_]+)\t(-?\d+)\s*$') { $row[$Matches[1]] = [int]$Matches[2] }
  }
  return $row
}

# Both tools walk a directory, and a tree that has been built holds a copy of
# every source under `_build`, plus every vendored package under `.mooncakes`.
# Analysing those measures somebody else's code twice, and it makes the counts a
# function of whether anybody has run a build: on 2026-11-23 this tree measured
# 83 files with `studio/.mooncakes` moved aside and 270 with it in place, and
# every one of the 21 actionable findings came from the vendored copy. So the
# analysis runs on a staging directory that holds only this repository's
# sources, and a number from it means the same thing on every machine.
$stage = Join-Path $env:TEMP 'lunapack-static-src'
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$staged = 0
$candidates = @(Get-ChildItem -LiteralPath $root -Filter *.mbt -File -Recurse -ErrorAction SilentlyContinue |
  Where-Object {
    # `-Filter *.mbt` also matches `*.mbti` on NTFS, and a generated interface
    # file is not source. The extension is compared instead of trusted.
    $_.Extension -eq '.mbt' -and
    $_.FullName -notmatch '\\_build\\' -and $_.FullName -notmatch '\\\.mooncakes\\' -and
    $_.FullName -notmatch '\\\.git\\'
  })
foreach ($file in $candidates) {
  $rel = $file.FullName.Substring($root.Length).TrimStart('\')
  $target = Join-Path $stage $rel
  $parent = [System.IO.Path]::GetDirectoryName($target)
  if (-not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  Copy-Item -LiteralPath $file.FullName -Destination $target -Force
  $staged = $staged + 1
}
Write-Host "==> source staging: $staged files, no build output and no vendored packages"
# The set is pinned to what git tracks: if a run stages more than that, something
# outside the repository's sources got in, and every count below is suspect.
$trackedCount = @(& git -C $root ls-files '*.mbt').Count
Check ($staged -eq $trackedCount) "the staging holds exactly the tracked sources ($staged staged, $trackedCount tracked)"

$baseline = $null
if (Test-Path -LiteralPath $BaselineFile) {
  $baseline = Get-Content -LiteralPath $BaselineFile -Raw | ConvertFrom-Json
}

Push-Location $stage
try {
  Write-Host "==> moonbit_static_analysis ($msaCoordinate)"
  $msaText = Invoke-Tool $msaCoordinate @('.')
  $msa = Parse-Msa $msaText
  $msaFiles = Parse-MsaFiles $msaText
  Write-Host ("    files={0} parsed={1} actionable={2} notices={3} unchecked={4}" -f `
      $msa['files'], $msa['parsed'], $msa['actionable'], $msa['notices'], $msa['unchecked'])
  # The staging is the thing that keeps these numbers honest, so it is asserted
  # rather than assumed: a run that somehow saw a built tree again would report
  # a number this one never produced.
  Check ($msa['files'] -eq $staged) "the analyzer saw the staged sources and nothing else ($($msa['files']) of $staged)"

  Write-Host "==> LunaFlow ($flowCoordinate, --funnel, --max-functions $flowMaxFunctions)"
  # The `--flag=value` form is accepted without complaint and then ignored: the
  # run silently falls back to the 150-function cap and reports 9 taint sinks
  # instead of 83. That is how the tracker ended up with a number nobody could
  # reproduce, so the arguments are space-separated here and the cap is checked
  # below.
  $flowText = Invoke-Tool $flowCoordinate @('.', '--funnel', '--max-functions', "$flowMaxFunctions", '--out', (Join-Path $env:TEMP 'lunapack-static-analysis'))
  $flow = Parse-Flow $flowText
} finally {
  Pop-Location
}
Write-Host ("    files={0} functions={1} dead_code={2} taint_sinks={3} abstract_findings={4} vcs={5}/{6}/{7}" -f `
    $flow['files'], $flow['functions'], $flow['dead_code'], $flow['taint_sinks'],
    $flow['abstract_findings'], $flow['vcs_proved'], $flow['vcs_failed'], $flow['vcs_unknown'])
# A count taken under the default cap describes the first 150 functions in file
# order, not the module. This module has far more than 150, so a run that
# reports 150 or fewer did not honour the flag and its numbers are not a
# measurement of anything.
Check ($flow['functions'] -gt 150) "the function cap was lifted ($($flow['functions']) functions interpreted, not the default 150)"

$measured = [ordered]@{
  commit   = (& git -C $root rev-parse --short HEAD)
  date     = (Get-Date -Format 'yyyy-MM-dd')
  msa      = [ordered]@{
    coordinate = $msaCoordinate
    files      = $msa['files']
    parsed     = $msa['parsed']
    actionable = $msa['actionable']
    notices    = $msa['notices']
    unchecked  = $msa['unchecked']
  }
  lunaflow = [ordered]@{
    coordinate      = $flowCoordinate
    maxFunctions    = $flowMaxFunctions
    level           = $flow['level']
    files           = $flow['files']
    functions       = $flow['functions']
    dead_code       = $flow['dead_code']
    taint_sinks     = $flow['taint_sinks']
    abstract_findings = $flow['abstract_findings']
    vcs_proved      = $flow['vcs_proved']
    vcs_failed      = $flow['vcs_failed']
    vcs_unknown     = $flow['vcs_unknown']
  }
}

if ($UpdateBaseline) {
  $perFile = [ordered]@{}
  foreach ($file in ($msaFiles.Keys | Sort-Object)) { $perFile[$file] = $msaFiles[$file].notices }
  $record = [ordered]@{
    note = 'Counts may only go down. Re-run with -UpdateBaseline only after the rise is explained in the commit message.'
    commit = $measured.commit
    date = $measured.date
    msa = [ordered]@{
      coordinate = $measured.msa.coordinate
      files      = $measured.msa.files
      parsed     = $measured.msa.parsed
      actionable = $measured.msa.actionable
      notices    = $measured.msa.notices
      unchecked  = $measured.msa.unchecked
      perFileNotices = $perFile
    }
    lunaflow = $measured.lunaflow
  }
  $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $BaselineFile -Encoding utf8
  Write-Host "baseline written to $BaselineFile"
  # Read it back rather than trusting the in-memory copy: this also proves the
  # file a later run will parse is the file this run just wrote.
  $baseline = Get-Content -LiteralPath $BaselineFile -Raw | ConvertFrom-Json
}

Write-Host "==> the numbers against the baseline"
# A missing baseline is not a pass: without a number to compare against, this
# script would print a green verdict that gates nothing, which is exactly the
# failure mode it exists to prevent. -UpdateBaseline is the way to create one.
Check ($null -ne $baseline) "a baseline exists at $BaselineFile (run with -UpdateBaseline to record one)"
if ($null -ne $baseline) {
  # Actionable findings are not a budget: any of them fails, whatever the
  # baseline says, because they are the reason the tool exists.
  Check ($msa['actionable'] -eq 0) "MSA actionable findings == 0 (got $($msa['actionable']))"

  $pairs = @(
    @{ name = 'MSA notices'; now = $msa['notices']; was = $baseline.msa.notices },
    @{ name = 'MSA unchecked'; now = $msa['unchecked']; was = $baseline.msa.unchecked },
    @{ name = 'LunaFlow dead code'; now = $flow['dead_code']; was = $baseline.lunaflow.dead_code },
    @{ name = 'LunaFlow taint sinks'; now = $flow['taint_sinks']; was = $baseline.lunaflow.taint_sinks },
    @{ name = 'LunaFlow abstract findings'; now = $flow['abstract_findings']; was = $baseline.lunaflow.abstract_findings },
    @{ name = 'LunaFlow failed VCs'; now = $flow['vcs_failed']; was = $baseline.lunaflow.vcs_failed },
    @{ name = 'LunaFlow unknown VCs'; now = $flow['vcs_unknown']; was = $baseline.lunaflow.vcs_unknown }
  )
  foreach ($pair in $pairs) {
    Check ($pair.now -le $pair.was) ("{0} did not rise ({1} -> {2})" -f $pair.name, $pair.was, $pair.now)
  }

  # A rise is only useful when it names the file that caused it, so the reader
  # can decide between "new code, expected" and "new finding, fix it".
  if ($msa['notices'] -gt $baseline.msa.notices) {
    Write-Host "  attribution (notices per file):"
    $known = $baseline.msa.perFileNotices
    foreach ($file in ($msaFiles.Keys | Sort-Object)) {
      $entry = $null
      if ($null -ne $known) { $entry = $known.PSObject.Properties[$file] }
      if ($null -eq $entry) {
        Write-Host ("    {0}  new file, notices={1}" -f $file, $msaFiles[$file].notices)
      } elseif ([int]$entry.Value -ne $msaFiles[$file].notices) {
        Write-Host ("    {0}  {1} -> {2}" -f $file, [int]$entry.Value, $msaFiles[$file].notices)
      }
    }
  }
}

Write-Host "==> verdict"
if ($failures.Count -gt 0) {
  Write-Host "FAILED: $($failures.Count) static-analysis gate(s)"
  $failures | ForEach-Object { Write-Host "  - $_" }
  exit 1
}
Write-Host "ALL $($script:checks) STATIC-ANALYSIS CHECKS PASSED"
exit 0
