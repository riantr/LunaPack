# Refresh the exact identities of the Tier B samples.
#
#   powershell -File snapshot.ps1 [-Out manifest.tsv]
#
# The manifest records path, size, SHA-256 and PE machine so a later run can
# tell whether it is measuring the same binary. This script only reads files.

param([string]$Out = "")

$ErrorActionPreference = 'SilentlyContinue'
$samples = @(
  'C:\Program Files\CMake\bin\cmake-gui.exe',
  'C:\Program Files\Calibre2\calibre.exe',
  'C:\Program Files\Calibre2\calibredb.exe',
  'C:\Program Files\Audacity\Audacity.exe',
  'C:\Program Files (x86)\Enigma Virtual Box\enigmavb.exe',
  'C:\Program Files (x86)\Inno Setup 6\Compil32.exe',
  'C:\Program Files (x86)\HTML Help Workshop\hhc.exe',
  'C:\Windows\System32\cmd.exe'
)

function Get-PeMachine([string]$path) {
  $fs = [System.IO.File]::OpenRead($path)
  try {
    $br = New-Object System.IO.BinaryReader($fs)
    $fs.Position = 0x3c
    $off = $br.ReadUInt32()
    $fs.Position = $off
    $sig = $br.ReadUInt32()
    if ($sig -ne 0x00004550) { return 'not-pe' }
    $m = $br.ReadUInt16()
    switch ($m) {
      0x014c { return 'x86' }
      0x8664 { return 'x64' }
      0xaa64 { return 'arm64' }
      default { return ('0x{0:x4}' -f $m) }
    }
  } finally { $fs.Dispose() }
}

$rows = New-Object System.Collections.Generic.List[string]
$rows.Add("path`tbytes`tsha256`tmachine")
foreach ($p in $samples) {
  if (-not (Test-Path -LiteralPath $p)) {
    $rows.Add("$p`tMISSING`t`t")
    continue
  }
  $item = Get-Item -LiteralPath $p
  $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
  $machine = Get-PeMachine $p
  $rows.Add("$p`t$($item.Length)`t$hash`t$machine")
}

if ($Out) {
  if ([System.IO.Path]::IsPathRooted($Out)) {
    $target = $Out
  } else {
    $target = Join-Path $PSScriptRoot $Out
  }
  [System.IO.File]::WriteAllLines($target, $rows, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host "wrote $target"
} else {
  $rows | ForEach-Object { Write-Host $_ }
}
