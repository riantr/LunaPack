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
#   8. 360 Total Security records no new detection, and the bundle is unchanged
#   9. a bundle with an Authenticode signature appended still runs: the archive
#      ends where its footer says, not where the file ends (L7.2a)
#  10. a bundle that was cut short is refused, and a footer-looking tail after
#      the real one is skipped rather than believed

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
$chainExe = Join-Path $dist 'spawn_chain.exe'
$crtProbe = Join-Path $dist 'crt_open.exe'
$searchProbe = Join-Path $dist 'searchpath_probe.exe'
$cmdSearchProbe = Join-Path $dist 'cmd_search_probe.exe'
$cHost = Join-Path $dist 'launcher.exe'

foreach ($needed in @($cli, $launcher, $runtime, $target, $dynlib, $chainExe, $crtProbe, $searchProbe, $cmdSearchProbe, $cHost)) {
  if (-not (Test-Path -LiteralPath $needed)) {
    throw "missing $needed - build the root CLI and scripts/build_runtime_windows.ps1 first"
  }
}

$failures = New-Object System.Collections.Generic.List[string]
$script:checks = 0
function Check([bool]$ok, [string]$label) {
  $script:checks = $script:checks + 1
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
  #
  # The text lands in a file nothing else knows about first. A log that was
  # created up front can be held open by whatever is scanning the folder, and
  # cmd.exe then fails to redirect and reports that failure as the exit code of
  # the program - which would be read here as the program refusing something.
  $parts = @((Quote $exe))
  foreach ($argument in $arguments) { $parts += Quote $argument }
  # A program that was written a moment ago is still being scanned, and the
  # engine holds it without sharing: starting it then fails with "the process
  # cannot access the file", which would be read here as the program refusing
  # to run. Wait until the file can be opened with sharing instead.
  for ($attempt = 0; $attempt -lt 100; $attempt++) {
    try {
      $handle = Open-Shared $exe ([System.IO.FileMode]::Open) ([System.IO.FileAccess]::Read)
      $handle.Close()
      break
    } catch {
      Start-Sleep -Milliseconds 200
    }
  }
  $tmp = [System.IO.Path]::GetTempFileName()
  try {
    $command = ($parts -join ' ') + ' > ' + (Quote $tmp) + ' 2>&1'
    & cmd.exe /c $command | Out-Null
    $code = $LASTEXITCODE
    WriteAllBytes $outFile (ReadAllBytes $tmp)
    return $code
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}
function RunChecked([string]$exe, [string[]]$arguments, [string]$outFile) {
  # Two messages here are the machine talking, not the program: the engine that
  # scans a file written moments ago holds it without sharing, so cmd.exe cannot
  # redirect into the log, or the CLI cannot rename its temporary output onto
  # the target. Both were observed on this machine and both would otherwise be
  # recorded as the program refusing something. The run is repeated instead.
  $code = 1
  for ($attempt = 0; $attempt -lt 5; $attempt++) {
    $code = RunCapture $exe $arguments $outFile
    $text = ReadOut $outFile
    if ($text -notmatch 'Access is denied|拒绝访问|正在使用此文件|cannot access the file') { break }
    Start-Sleep -Milliseconds 1500
  }
  return $code
}
function ReadOut([string]$path) {
  return ((Get-Content -LiteralPath $path -Raw) -join "`n")
}
function Test-PathQuiet([string]$path) {
  # An engine holding the file without sharing makes Test-Path throw instead of
  # answering, which would end the script before the assertions that follow.
  for ($attempt = 0; $attempt -lt 10; $attempt++) {
    try { return (Test-Path -LiteralPath $path) } catch { Start-Sleep -Milliseconds 200 }
  }
  return $false
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

# 360 Total Security has no quarantine directory to count while it has never
# quarantined anything, so the countable signal is its real-time record: the
# engine appends one entry per action to
#   Log\RealtimeProtectLog\<date>.log
# as UTF-16LE, and each entry names the file it acted on. That is the closest
# thing to Huorong's quarantine listing and it moves for the same reason.
function Av360LogDir() { return 'C:\Program Files\360\360sd\Log\RealtimeProtectLog' }

function Av360Live() {
  $service = Get-Service -Name '360rp' -ErrorAction SilentlyContinue
  if ($null -eq $service -or $service.Status -ne 'Running') { return $false }
  $process = Get-Process -Name '360sd', '360tray' -ErrorAction SilentlyContinue
  return ($null -ne $process)
}

function Av360Records() {
  $dir = Av360LogDir
  if (-not (Test-Path -LiteralPath $dir)) { return @() }
  $records = New-Object System.Collections.Generic.List[string]
  $files = @(Get-ChildItem -LiteralPath $dir -Filter *.log -File -Force -ErrorAction SilentlyContinue)
  foreach ($file in $files) {
    try {
      # The engine keeps the current day's file open for writing; read with a
      # share mode instead of failing on the lock.
      $stream = [System.IO.File]::Open($file.FullName, 'Open', 'Read', 'ReadWrite')
      $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::Unicode)
      $text = $reader.ReadToEnd()
      $reader.Close()
      $stream.Close()
    } catch { continue }
    foreach ($match in [regex]::Matches($text, '(?i)[a-z]:\\[^\r\n"]{4,220}\.(?:exe|dll|com|bin|txt)')) {
      $records.Add($match.Value)
    }
  }
  return @($records)
}
function WriteAscii([string]$path, [string]$text) {
  [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.ASCIIEncoding))
}

# A file that was just written can be held by whichever engine is scanning it,
# and the default FileShare.Read open fails while that happens. Open with
# ReadWrite+Delete sharing and retry: this is the same trick the launcher probe
# already uses. The last attempt is unwrapped, so a file that is really
# unreadable still fails the run with the reason Windows gives.
function Open-Shared([string]$path, [System.IO.FileMode]$mode, [System.IO.FileAccess]$access) {
  return [System.IO.File]::Open(
    $path, $mode, $access,
    ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
  )
}
function ReadAllBytes([string]$path) {
  for ($attempt = 0; $attempt -lt 50; $attempt++) {
    $stream = $null
    $memory = $null
    try {
      $stream = Open-Shared $path ([System.IO.FileMode]::Open) ([System.IO.FileAccess]::Read)
      $memory = New-Object System.IO.MemoryStream
      $stream.CopyTo($memory)
      return $memory.ToArray()
    } catch {
      Start-Sleep -Milliseconds 200
    } finally {
      if ($stream) { $stream.Dispose() }
      if ($memory) { $memory.Dispose() }
    }
  }
  return [System.IO.File]::ReadAllBytes($path)
}

function WriteAllBytes([string]$path, [byte[]]$bytes) {
  for ($attempt = 0; $attempt -lt 50; $attempt++) {
    $stream = $null
    try {
      $stream = Open-Shared $path ([System.IO.FileMode]::Create) ([System.IO.FileAccess]::Write)
      $stream.Write($bytes, 0, $bytes.Length)
      return
    } catch {
      Start-Sleep -Milliseconds 200
    } finally {
      if ($stream) { $stream.Dispose() }
    }
  }
  [System.IO.File]::WriteAllBytes($path, $bytes)
}

# Signing a file is how a user gets past the "unknown publisher" prompt, and it
# is also the reason the reader cannot assume the footer is the last 24 bytes:
# Authenticode appends the signature after the last byte of the file. A
# self-signed certificate is enough to test that: the chain is not trusted, and
# nothing here checks it - what is checked is that a signature was appended and
# that the bundle still runs.
function Find-SignTool() {
  $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($null -ne $command) { return $command.Source }
  $kits = 'C:\Program Files (x86)\Windows Kits\10\bin'
  if (-not (Test-Path -LiteralPath $kits)) { return '' }
  $candidates = @(Get-ChildItem -LiteralPath $kits -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
    Where-Object { Test-Path -LiteralPath $_ })
  if ($candidates.Count -eq 0) { return '' }
  return $candidates[0]
}

# A certificate is only worth something here if a signature can be read back out
# of the file, so that is what is asserted rather than the size of the tail.
function HasSignature([string]$path) {
  try {
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($path)
    return ($null -ne $cert)
  } catch {
    return $false
  }
}

# Best-effort cleanup. An anti-virus engine can hold a freshly written file
# open for a while, and on this machine a removal can be refused outright.
# Retry a few times, then leave a note and carry on: the assertions that need
# the fixture gone check the path itself, so a stale fixture shows up as a
# failed check instead of aborting the whole run before the other invariants
# are measured.
function Remove-Path([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return }
  for ($attempt = 0; $attempt -lt 10; $attempt++) {
    try { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop } catch { }
    if (-not (Test-Path -LiteralPath $path)) { return }
    Start-Sleep -Milliseconds 200
  }
  Write-Host "  note  could not remove $path - continuing; stale-fixture checks will report it"
}

$scratch = Join-Path $root 'build\verify_virtual_bundle'
Remove-Path $scratch
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
# Set when this run creates a signing certificate of its own, so that the store
# is left the way it was found.
$createdCert = ''
try {
  $fixture = Join-Path $scratch 'fixture'
  $registry = Join-Path $scratch 'registry.json'
  $bundle = Join-Path $scratch 'vdemo.exe'
  $plain = Join-Path $scratch 'plain.exe'
  $corrupt = Join-Path $scratch 'damaged.exe'
  $signed = Join-Path $scratch 'signed.exe'
  $bogus = Join-Path $scratch 'bogus_tail.exe'
  $cut = Join-Path $scratch 'cut_short.exe'
  $signedOut = Join-Path $scratch 'signed.txt'
  $bogusOut = Join-Path $scratch 'bogus.txt'
  $cutOut = Join-Path $scratch 'cut.txt'
  $signtoolOut = Join-Path $scratch 'signtool.txt'
  $bundleOut = Join-Path $scratch 'bundle.txt'
  $infoOut = Join-Path $scratch 'info.txt'
  $plainBundleOut = Join-Path $scratch 'plain_bundle.txt'
  $plainInfoOut = Join-Path $scratch 'info_plain.txt'
  $runOut = Join-Path $scratch 'run.txt'
  $plainOut = Join-Path $scratch 'plain.txt'
  $damagedOut = Join-Path $scratch 'damaged.txt'
  # L4 in the shipping path: a program inside the bundle starts another one,
  # and the child has to see the same virtual tree.
  $chainFixture = Join-Path $scratch 'chain_fixture'
  $chain = Join-Path $scratch 'chain.exe'
  $chainOut = Join-Path $scratch 'chain.txt'
  $chainDiskOut = Join-Path $scratch 'chain_disk.txt'
  $chainBundleOut = Join-Path $scratch 'chain_bundle.txt'
  $chainInfoOut = Join-Path $scratch 'info_chain.txt'
  $crtOut = Join-Path $scratch 'crt.txt'
  # L2.6: resolution of a virtual path, first in the mapped program and then
  # in a real cmd.exe child that resolves before it opens.
  $searchBundle = Join-Path $scratch 'search.exe'
  $searchOut = Join-Path $scratch 'search.txt'
  $searchBundleOut = Join-Path $scratch 'search_bundle.txt'
  $searchInfoOut = Join-Path $scratch 'info_search.txt'
  $cmdSearchBundle = Join-Path $scratch 'cmdsearch.exe'
  $cmdSearchOut = Join-Path $scratch 'cmdsearch.txt'
  $cmdSearchBundleOut = Join-Path $scratch 'cmdsearch_bundle.txt'
  $cmdSearchInfoOut = Join-Path $scratch 'info_cmdsearch.txt'

  New-Item -ItemType Directory -Path (Join-Path $fixture 'virt') -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $fixture 'cfg') -Force | Out-Null
  WriteAscii (Join-Path $fixture 'virt\hello.txt') 'VIRTUAL-FS-OK'
  WriteAscii (Join-Path $fixture 'virt\ansi.txt') 'ANSI'
  WriteAscii (Join-Path $fixture 'cfg\seed.txt') 'SEED'
  Copy-Item -LiteralPath $dynlib -Destination (Join-Path $fixture 'dynlib.dll') -Force
  WriteAscii $registry '{"values":[{"root":"hklm","key":"Software\\LunaPackVerify","name":"Port","kind":"REG_DWORD","number":8080}]}'
  # Every log exists, empty, before the no-payload snapshot is taken: otherwise
  # the verifier's own output looks like a file the run left behind.
  foreach ($log in @($bundleOut, $infoOut, $plainBundleOut, $plainInfoOut, $runOut, $plainOut, $damagedOut, $chainOut, $chainDiskOut, $chainBundleOut, $chainInfoOut, $crtOut, $searchOut, $searchBundleOut, $searchInfoOut, $cmdSearchOut, $cmdSearchBundleOut, $cmdSearchInfoOut, $signedOut, $bogusOut, $cutOut, $signtoolOut)) {
    WriteAscii $log ''
  }

  Write-Host "==> build the virtual bundle with the shipping CLI"
  $bundleExit = RunChecked $cli @(
    'bundle', '-i', $target, '-o', $bundle,
    '--Files', $fixture,
    '--virtual', '--virtual-root=C:/', '--virtual-temp=C:/virt/tmp/',
    '--registry', $registry, '--compression-method=none',
    '--launcher', $launcher
  ) $bundleOut
  $bundleLog = ReadOut $bundleOut
  Write-Host $bundleLog
  Check ($bundleExit -eq 0) "CLI bundle exit code 0 (got $bundleExit)"
  Check (Test-PathQuiet $bundle) 'virtual bundle was produced'

  $infoExit = RunChecked $cli @('info', $bundle) $infoOut
  $bundleInfo = ReadOut $infoOut
  Check ($infoExit -eq 0) "CLI info exit code 0 (got $infoExit)"
  Check ($bundleInfo -match 'format:\s+v7') 'bundle uses format v7'
  Check ($bundleInfo -match 'virtual:\s+C:\\\s+\(5 files, 1 registry values\)') 'manifest carries the virtual layer and typed registry seed'
  Check ($bundleInfo -match 'runtime:\s+@runtime/lpvirt\.dll') 'runtime DLL is a checksummed archive entry'

  Write-Host "==> build the child chain bundle (L4 in the shipping path)"
  New-Item -ItemType Directory -Path $chainFixture -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $dist 'spawn_chain.exe') -Destination (Join-Path $chainFixture 'spawn_chain.exe') -Force
  WriteAscii (Join-Path $chainFixture 'hello.txt') 'VIRTUAL-FS-OK'
  $chainExit = RunChecked $cli @(
    'bundle', '-i', (Join-Path $dist 'spawn_chain.exe'), '-o', $chain,
    '--Files', $chainFixture,
    '--virtual', '--virtual-root=C:/virt', '--compression-method=none',
    '--launcher', $launcher
  ) $chainBundleOut
  Check ($chainExit -eq 0) "child chain bundle exit code 0 (got $chainExit)"
  $chainInfoExit = RunChecked $cli @('info', $chain) $chainInfoOut
  $chainInfo = ReadOut $chainInfoOut
  Check ($chainInfoExit -eq 0) "CLI info on the chain bundle exit code 0 (got $chainInfoExit)"
  Check ($chainInfo -match 'format:\s+v7') 'chain bundle uses format v7'
  # The source of the child program goes away before it runs: the only copy
  # left is the one inside the package, so a second process reading it proves
  # both the redirect and the state handover.
  Remove-Path $chainFixture

  Write-Host "==> build the L2.6 resolution bundles (negative test first)"
  $searchBuildExit = RunChecked $cli @(
    'bundle', '-i', $searchProbe, '-o', $searchBundle,
    '--Files', $fixture,
    '--virtual', '--virtual-root=C:/', '--virtual-temp=C:/virt/tmp/',
    '--compression-method=none', '--launcher', $launcher
  ) $searchBundleOut
  Check ($searchBuildExit -eq 0) "L2.6 search bundle exit code 0 (got $searchBuildExit)"
  $searchInfoExit = RunChecked $cli @('info', $searchBundle) $searchInfoOut
  Check ($searchInfoExit -eq 0) "CLI info on the search bundle exit code 0 (got $searchInfoExit)"
  Check ((ReadOut $searchInfoOut) -match 'format:\s+v7') 'search bundle uses format v7'

  $cmdSearchBuildExit = RunChecked $cli @(
    'bundle', '-i', $cmdSearchProbe, '-o', $cmdSearchBundle,
    '--Files', $fixture,
    '--virtual', '--virtual-root=C:/', '--virtual-temp=C:/virt/tmp/',
    '--compression-method=none', '--launcher', $launcher
  ) $cmdSearchBundleOut
  Check ($cmdSearchBuildExit -eq 0) "L2.6 cmd bundle exit code 0 (got $cmdSearchBuildExit)"
  $cmdSearchInfoExit = RunChecked $cli @('info', $cmdSearchBundle) $cmdSearchInfoOut
  Check ($cmdSearchInfoExit -eq 0) "CLI info on the cmd bundle exit code 0 (got $cmdSearchInfoExit)"
  Check ((ReadOut $cmdSearchInfoOut) -match 'format:\s+v7') 'cmd bundle uses format v7'

  Write-Host "==> build and refuse a plain bundle"
  $plainExit = RunChecked $cli @(
    'bundle', '-i', $target, '-o', $plain,
    '--Files', $fixture, '--no-virtual',
    '--compression-method=none', '--launcher', $launcher
  ) $plainBundleOut
  Check ($plainExit -eq 0) "--no-virtual bundle exit code 0 (got $plainExit)"
  $plainInfoExit = RunChecked $cli @('info', $plain) $plainInfoOut
  $plainInfo = ReadOut $plainInfoOut
  Check ($plainInfoExit -eq 0) "CLI info on plain bundle exit code 0 (got $plainInfoExit)"
  Check ($plainInfo -match 'virtual:\s+none') '--no-virtual manifest has no virtual layer'
  $refuseExit = RunChecked $plain @() $plainOut
  $refuseLog = ReadOut $plainOut
  Write-Host $refuseLog
  Check ($refuseExit -ne 0) "lpvhost refuses the plain bundle (got $refuseExit)"
  Check ($refuseLog -match 'carries no LunaPack virtual bundle') 'refusal names the missing virtual layer'

  Write-Host "==> damage one virtual file inside a copy of the bundle"
  $bytes = ReadAllBytes $bundle
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
    WriteAllBytes $corrupt $bytes
    $damagedExit = RunChecked $corrupt @() $damagedOut
    $damagedLog = ReadOut $damagedOut
    Write-Host $damagedLog
    Check ($damagedExit -ne 0) "corrupted bundle is refused (got $damagedExit)"
    Check ($damagedLog -match 'checksum|damaged|does not decompress|manifest is not JSON') 'refusal names integrity damage'
  }

  Write-Host "==> sign a copy, and make the copies a reader has to refuse"
  # Authenticode puts the signature after the last byte of the file, so a
  # signed bundle is the launcher, the archive, and then the signature. The
  # archive therefore no longer ends where the file ends, and the reader has to
  # find the footer instead of assuming it is the last 24 bytes. That is the
  # whole of L7.2a, and this is where it is measured.
  # A certificate this run creates: the store of a real machine holds
  # certificates whose keys signtool will not touch, and a verifier that picks
  # whichever one it finds first reports a signing failure that is really a
  # choice of certificate. One made here is one that works, and it is removed
  # again at the end.
  $signtool = Find-SignTool
  $thumb = ''
  if ($signtool) {
    try {
      $made = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject 'CN=LunaPack Verify Signer' `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(2) -ErrorAction Stop
      $thumb = $made.Thumbprint
      $createdCert = $thumb
    } catch { $thumb = '' }
  }
  $signReady = ($thumb -ne '')
  $plainBytes = ReadAllBytes $bundle
  $ascii = New-Object System.Text.ASCIIEncoding
  $magic = $ascii.GetBytes('APPKGD02')
  # A footer after the real one that cannot close an archive: the numbers point
  # far outside the file. A reader that believes the last marker it sees breaks
  # here; one that checks the numbers skips it and finds the real footer.
  $bogusBytes = New-Object byte[] ($plainBytes.Length + 24)
  [Array]::Copy($plainBytes, $bogusBytes, $plainBytes.Length)
  [Array]::Copy($magic, 0, $bogusBytes, $plainBytes.Length, 8)
  [Array]::Copy([BitConverter]::GetBytes([int64]0x7fffff0), 0, $bogusBytes, $plainBytes.Length + 8, 8)
  [Array]::Copy([BitConverter]::GetBytes([int64]4096), 0, $bogusBytes, $plainBytes.Length + 16, 8)
  WriteAllBytes $bogus $bogusBytes
  # And a bundle that was cut short: no footer anywhere, so it is not a bundle.
  $cutBytes = New-Object byte[] ($plainBytes.Length - 100)
  [Array]::Copy($plainBytes, $cutBytes, $cutBytes.Length)
  WriteAllBytes $cut $cutBytes
  if ($signReady) {
    # The copy was written a moment ago and the engine that scans it still holds
    # it, so the signer can be refused a handle. The copy is written again from
    # the same bytes before every attempt, so a half-signed file is never the
    # file that is checked.
    $signExit = 1
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
      WriteAllBytes $signed $plainBytes
      $signExit = RunChecked $signtool @('sign', '/sha1', $thumb, '/fd', 'sha256', $signed) $signtoolOut
      if ($signExit -eq 0) { break }
      Start-Sleep -Milliseconds 500
    }
    if ($signExit -ne 0) { Write-Host (ReadOut $signtoolOut) }
    $signedBytes = ReadAllBytes $signed
    Check ($signExit -eq 0) "signtool signed the copy (got $signExit)"
    if ($signExit -eq 0) {
      Check ($signedBytes.Length -gt $plainBytes.Length) "the signature was appended after the file ($($plainBytes.Length) -> $($signedBytes.Length) bytes)"
      Check (HasSignature $signed) 'an Authenticode signature can be read back out of the copy'
      # Signing writes the hash into the certificate table of the PE headers and
      # updates the checksum there, so the first bytes do change. Everything
      # from the headers to the end of the archive has to be untouched: that is
      # the part the signature covers and the part the reader reads.
      $lastDiff = -1
      for ($i = 0; $i -lt $plainBytes.Length; $i++) {
        if ($signedBytes[$i] -ne $plainBytes[$i]) { $lastDiff = $i }
      }
      Check ($lastDiff -lt 4096) "signing changed the PE headers only, not the archive (last changed byte at $lastDiff)"
    }
  } else {
    Write-Host "  SKIP  no Authenticode signer here (signtool plus a code-signing certificate are needed)"
  }

  Write-Host "==> remove the source fixture and run the bundle"
  Remove-Path $fixture
  $avBefore = QuarantineCount
  $av360Live = Av360Live
  $av360Before = if ($av360Live) { @(Av360Records) } else { @() }
  $bundleHash = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash
  $tempDir = $env:TEMP
  if (-not $tempDir) { $tempDir = [System.IO.Path]::GetTempPath() }
  $tempPattern = 'lunapack|lpvirt|lpvhost|mini_target|dynlib|hello\.txt|ansi\.txt|seed\.txt|fromansi\.txt'
  $beforeScratch = Snapshot $scratch $null
  $beforeTemp = Snapshot $tempDir $tempPattern

  $runExit = RunChecked $bundle @() $runOut
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

  Write-Host "==> a signed bundle, a bad tail, a cut bundle"
  if ($signReady) {
    $signedExit = RunChecked $signed @() $signedOut
    $signedLog = ReadOut $signedOut
    Write-Host $signedLog
    Check ($signedExit -eq 0) "signed bundle exit code 0 (got $signedExit)"
    Check ($signedLog -match 'THIN-EXE file="VIRTUAL-FS-OK" size=\x00?13\s+attrs=0x80 result=OK') 'the signed bundle found its archive in front of the signature'
  }
  $bogusExit = RunChecked $bogus @() $bogusOut
  $bogusLog = ReadOut $bogusOut
  Write-Host $bogusLog
  Check ($bogusExit -eq 0) "a footer that closes nothing is skipped (got $bogusExit)"
  Check ($bogusLog -match 'THIN-EXE file="VIRTUAL-FS-OK" size=\x00?13\s+attrs=0x80 result=OK') 'the real footer was still found behind the bogus one'
  $cutExit = RunChecked $cut @() $cutOut
  $cutLog = ReadOut $cutOut
  Write-Host $cutLog
  Check ($cutExit -ne 0) "a bundle cut short is refused (got $cutExit)"
  Check ($cutLog -match 'carries no LunaPack virtual bundle') 'the refusal names the archive that is not there'

  Write-Host "==> a child process follows the virtual layer"
  # spawn_chain.exe reads C:\virt\hello.txt, starts another copy of itself and
  # reports the level it is on. Both the program and the file it reads exist
  # only inside the package, so three generations reading it is the whole
  # claim: the redirect, the state handover and the recursion.
  $env:LUNAPACK_TEST_CHILD = 'C:\virt\spawn_chain.exe'
  $env:LUNAPACK_TEST_LEVEL = '1'
  $chainRunExit = RunChecked $chain @() $chainOut
  $env:LUNAPACK_TEST_CHILD = $null
  $env:LUNAPACK_TEST_LEVEL = $null
  $chainLog = ReadOut $chainOut
  Write-Host $chainLog
  Check ($chainRunExit -eq 0) "child chain exit code 0 (got $chainRunExit)"
  Check (([regex]::Matches($chainLog, 'virtual read=OK data="VIRTUAL-FS-OK"')).Count -eq 3) 'three generations read the same virtual file'
  Check ($chainLog -match 'level=2 child exit=0') 'the middle generation exited cleanly'
  Check ($chainLog -match 'SPAWN chain end') 'the chain stopped at the third generation'

  Write-Host "==> a child that lives on disk is followed too"
  # The same bundle, but this time the parent asks for a program that was never
  # packed. It still has to run, and it still has to see the virtual tree: the
  # import is what makes the child's filesystem the parent's, whichever copy of
  # the program it mapped.
  $env:LUNAPACK_TEST_CHILD = $chainExe
  $env:LUNAPACK_TEST_LEVEL = '1'
  $chainDiskExit = RunChecked $chain @() $chainDiskOut
  $env:LUNAPACK_TEST_CHILD = $null
  $env:LUNAPACK_TEST_LEVEL = $null
  $chainDiskLog = ReadOut $chainDiskOut
  Write-Host $chainDiskLog
  Check ($chainDiskExit -eq 0) "disk-child chain exit code 0 (got $chainDiskExit)"
  Check (([regex]::Matches($chainDiskLog, 'virtual read=OK data="VIRTUAL-FS-OK"')).Count -eq 3) 'a program from disk saw the virtual tree at every level'

  Write-Host "==> the CRT boundary (L2.7 restricted whitelist)"
  # fopen lives in ucrtbase/msvcrt. L2.7 patches only the file-I/O slots of
  # those two modules (loader/process/registry slots stay on the real APIs), so
  # a program that reads the ordinary way reaches the virtual tree while the
  # OS loader is never re-entered. Both reads must now agree.
  $crtExit = RunChecked (Join-Path $dist 'launcher.exe') @(
    $dist, (Join-Path $dist 'crt_open.exe'), '--thread'
  ) $crtOut
  $crtLog = ReadOut $crtOut
  Write-Host $crtLog
  Check ($crtExit -eq 0) "CRT probe exit code 0 (got $crtExit)"
  Check ($crtLog -match 'win32\s+result=OK data="VIRTUAL-FS-OK"') 'CreateFileW on the virtual path reaches the layer'
  Check ($crtLog -match 'C-open\s+result=OK n=\d+ data="VIRTUAL-FS-OK"') 'CRT stdio reaches the virtual tree (L2.7)'
  Check ($crtLog -match 'crtmods=2') 'both CRT modules matched the whitelist'
  Check ($crtLog -match 'crtslots=([1-9]\d*)') 'at least one CRT file slot was patched'

  Write-Host "==> L2.6 path resolution (child cmd.exe read still gated by L2.8)"
  # SearchPathW is how cmd.exe resolves a name before opening it. The Win32
  # open side and CRT stdio are virtualized, but cmd /c type still resolves
  # through an unhooked API (GetFullPathNameW-class), so this last assertion
  # stays red until L2.8 closes that gap.
  $searchExit = RunChecked $searchBundle @() $searchOut
  $searchLog = ReadOut $searchOut
  Write-Host $searchLog
  Check ($searchExit -eq 0) "L2.6 search probe exit code 0 (got $searchExit)"
  Check ($searchLog -match 'SEARCH-W hit=OK') 'SearchPathW resolved a virtual absolute path'
  Check ($searchLog -match 'SEARCH-W part=OK') 'SearchPathW filled lpFilePart inside the buffer'
  Check ($searchLog -match 'SEARCH-W small=OK') 'SearchPathW reported the required size for a short buffer'
  Check ($searchLog -match 'SEARCH-A hit=OK') 'SearchPathA resolved a virtual absolute path'
  Check ($searchLog -match 'SEARCH-A part=OK') 'SearchPathA filled lpFilePart inside the buffer'
  Check ($searchLog -match 'SEARCH-W real=OK') 'SearchPathW still resolves a real system DLL'
  Check ($searchLog -match 'SEARCH-W read=OK') 'the path from SearchPathW opens through CreateFileW'

  $cmdSearchExit = RunChecked $cmdSearchBundle @() $cmdSearchOut
  $cmdSearchLog = ReadOut $cmdSearchOut
  Write-Host $cmdSearchLog
  Check ($cmdSearchExit -eq 0) "child cmd.exe probe exit code 0 (got $cmdSearchExit)"
  Check ($cmdSearchLog -match 'CMD-PROBE control=OK') 'child cmd.exe started and ran an echo control'
  Check ($cmdSearchLog -match 'CMD-PROBE exist=OK') 'child cmd.exe sees the virtual file through GetFileAttributesW'
  Check ($cmdSearchLog -match 'VIRTUAL-FS-OK') 'child cmd.exe read the virtual file (L2.7 CRT stdio)'
  Check ($cmdSearchLog -match 'CMD-PROBE child=OK code=0') 'child cmd.exe exited successfully'

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
  # A CI runner has no Huorong installation, so there is nothing to compare:
  # the AV retest is a manual step on a machine that runs the engine. Saying so
  # is better than letting -1 compare equal to -1 and printing a pass that
  # proves nothing.
  if ($avBefore -lt 0) {
    Write-Host "  SKIP  no Huorong installation here (the AV retest is manual, see runtime/tests/corpus/AV_RETEST.md)"
  } else {
    Check ($avAfter -eq $avBefore) "Huorong quarantine unchanged ($avBefore -> $avAfter)"
  }

  # The second engine, same rule: report it on its own, and only count what can
  # be attributed to this run. A detection of somebody else's file during the
  # run is noise; a detection of anything under this repository is not.
  if (-not $av360Live) {
    Write-Host "  SKIP  no 360 engine running here (second gate is manual, see runtime/tests/corpus/AV_RETEST.md)"
  } else {
    Check (Test-Path -LiteralPath (Av360LogDir)) 'the 360 real-time log is readable'
    $av360After = @(Av360Records)
    $oursBefore = @($av360Before | Where-Object { $_ -match [regex]::Escape($root) })
    $oursAfter = @($av360After | Where-Object { $_ -match [regex]::Escape($root) })
    $newOurs = @($oursAfter | Where-Object { $oursBefore -notcontains $_ })
    Check ($newOurs.Count -eq 0) "360 recorded no new detection under the repository ($($oursBefore.Count) -> $($oursAfter.Count))"
    if ($newOurs.Count -gt 0) { $newOurs | ForEach-Object { Write-Host "        detected: $_" } }
    Write-Host "        (360 recorded $($av360Before.Count) -> $($av360After.Count) detections in total, others included)"
    Check (Test-PathQuiet $bundle) 'the bundle is still on disk after the run'
    if (Test-PathQuiet $bundle) {
      $hashAfter = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash
      Check ($hashAfter -eq $bundleHash) 'the bundle is byte-identical after the run'
    }
  }

  Write-Host "==> verdict"
  if ($failures.Count -gt 0) {
    Write-Host "FAILED: $($failures.Count) invariant(s)"
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
  }
  Write-Host "ALL $($script:checks) VIRTUAL BUNDLE INVARIANTS PASSED"
  exit 0
}
finally {
  if (-not $KeepScratch) {
    try { Remove-Path $scratch } catch { Write-Host "  note  $($_.Exception.Message)" }
  }
  # A certificate this run created is not left behind: a verifier that changes
  # the machine it verifies on is a verifier nobody can run twice.
  if ($createdCert) {
    try { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$createdCert" -Force -ErrorAction Stop } catch { }
  }
}
