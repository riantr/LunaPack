# L5 COM / ActiveX activation without administrator rights: invariants.
#
# Builds nothing. Expects scripts\build_runtime_windows.ps1 to have run, so
# dist\ holds lpvirt.dll, com_server.dll, com_server_crt.dll, com_consumer.exe
# and com_host.exe.
#
# Two components are driven, and both go through the same exchange:
#   com_server.dll      a server with no CRT at all (/NOENTRY, hand-written
#                       DllMain) - the minimal shape the runtime must support
#   com_server_crt.dll  the same source built the ordinary way: CRT start-up,
#                       real DllMain, and it registers itself through
#                       GetModuleFileNameW instead of a hard-coded path
#
# For each, what is proved, in order:
#   1. a component can register itself            (writes land in the hive)
#   1b. it registers the type library embedded in its own image (L5.6): the
#       library is parsed out of the archive, its keys go into the hive, and a
#       client can load it back by LIBID although no .tlb file exists
#   2. the class database then reads that hive    (combase/ole32 patched)
#   3. real COM activates the class               (CoCreateInstance returns S_OK)
#   4. the server came out of the archive         (LoadLibrary served by the VFS)
#   5. the server's DllMain ran                   (it refuses to serve otherwise)
#   6. none of it touched the real registry, and no administrator was involved
#   7. unregistering removes the class and the library again
# plus one run with --consume, where the file is deleted from disk before it is
# ever mapped, and a final AV check.
#
# For the ordinary build, step 4 is also the proof that GetModuleFileNameW was
# answered by the runtime: its fallback path is deliberately absent from the
# archive, so a loader answer would have registered a class that cannot load.

param(
  [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
  [string]$Dist = ''
)
$ErrorActionPreference = 'Stop'
if ($Dist -eq '') { $Dist = Join-Path $Root 'dist' }

$virt = Join-Path $Dist 'lpvirt.dll'
$hostExe = Join-Path $Dist 'com_host.exe'
$consumer = Join-Path $Dist 'com_consumer.exe'
$servers = @('com_server.dll', 'com_server_crt.dll')
foreach ($p in @($virt, $hostExe, $consumer) + ($servers | ForEach-Object { Join-Path $Dist $_ })) {
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

$clsidKey = 'Registry::HKEY_CLASSES_ROOT\CLSID\{9B1F0A4C-2D3E-4A55-8F01-112233445566}'
$progIdKey = 'Registry::HKEY_CLASSES_ROOT\LunaPack.Answer'
$machineKey = 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{9B1F0A4C-2D3E-4A55-8F01-112233445566}'
$realBefore = (Test-Path -LiteralPath $clsidKey) -or (Test-Path -LiteralPath $progIdKey) -or
              (Test-Path -LiteralPath $machineKey)
Check (-not $realBefore) 'the class is not present in the real registry before the run'

function Run-Host([string]$serverName, [bool]$consume, [string]$label) {
  $dir = Join-Path $env:TEMP ("lunapack-com-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Copy-Item -LiteralPath $virt, $hostExe, $consumer, (Join-Path $Dist $serverName) -Destination $dir
  $argList = @('.', $serverName, 'com_consumer.exe')
  if ($consume) { $argList += '--consume' }
  # com_host prints the whole exchange; it is captured to a file because the
  # process is what is being observed, not the pipeline.
  Push-Location $dir
  try {
    & (Join-Path $dir 'com_host.exe') @argList > (Join-Path $dir 'run.txt') 2>&1
    $code = $LASTEXITCODE
  } finally {
    Pop-Location
  }
  $text = Get-Content -LiteralPath (Join-Path $dir 'run.txt') -Raw
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "--- $label ---"
  $text -split "`r?`n" | Where-Object {
    $_ -match 'COM |DllRegister|DllUnregister|DllMain|load-map|hive after|slots patched|thunks used|' +
              'typelib|hive TypeLib|hive Interface|hive CLSID|REG '
  } | ForEach-Object { Write-Host "  $_" }
  return @{ Code = $code; Text = $text }
}

function Assert-Run([hashtable]$run, [string]$serverName, [bool]$consume, [bool]$ordinaryBuild) {
  Check ($run.Code -eq 0) "host exit code 0 (got $($run.Code))"
  Check ($run.Text -match 'DllMain\(DLL_PROCESS_ATTACH\): TRUE') 'the entry point ran'
  Check ($run.Text -match 'DllRegisterServer returned 0x00000000') 'the component registered itself'
  Check ($run.Text -match 'register thunks: RegCreateKeyExW=4 RegSetValueExW=5') 'registration went through the registry thunks'
  # 5 writes are the component's own keys, 13 are the type library's: the
  # library, its version, its language and platform, one interface with its
  # proxy and method count, and one coclass. An exact number is the check that
  # the library is registered once and not twice.
  Check ($run.Text -match 'hive after register: open=0 create=4 enum=0 delete=0 query=0 write=18 ') 'the class and the type library landed in the hive'
  Check ($run.Text -match 'combase\.dll: ([1-9]\d*) slots patched') 'combase.dll is patched, so the class database reads the hive'
  Check ($run.Text -match 'ole32\.dll: ([1-9]\d*) slots patched') 'ole32.dll is patched as well'
  Check ($run.Text -match 'COM init=0x00000000') 'CoInitializeEx succeeded'
  Check ($run.Text -match 'COM create=0x00000000') 'CoCreateInstance returned S_OK'
  Check ($run.Text -match 'COM call=0x00000000') 'the method call succeeded'
  Check ($run.Text -match 'COM answer=4242') 'the object created by COM answered 4242'
  Check ($run.Text -match 'consumer exit=0') 'the client exited cleanly'
  # L5.6: the component's registration goes through a type library that exists
  # only inside the archive. Without it `LoadTypeLibEx` on a path with no file
  # fails, `DllRegisterServer` aborts, and nothing above would have run.
  Check ($run.Text -match 'typelib thunks: LoadTypeLibEx=1 RegisterTypeLib=1') 'the component loaded and registered its type library through the runtime'
  Check ($run.Text -match 'typelib after register: loaded=1 registered=1 unregistered=0 objects=1') 'one library parsed, registered, with one live ITypeLib object'
  Check ($run.Text -match 'hive TypeLib key: present') 'the library landed under TypeLib\{LIBID}'
  Check ($run.Text -match 'hive TypeLib name: LunaPack answer typelib') 'the library name came from the parsed typelib'
  Check ($run.Text -match 'hive TypeLib 1.0 key: present') 'the library was registered under its version'
  $virtLibPath = 'hive TypeLib path: C:\\virt\\' + [regex]::Escape($serverName)
  Check ($run.Text -match $virtLibPath) 'the platform entry names the virtual path, not a file on disk'
  Check ($run.Text -match 'hive Interface name: ILpAnswer') 'the interface came from the typelib, with its name'
  Check ($run.Text -match 'hive Interface TypeLib: \{A1B2C3D4-0001-4000-9000-000000000001\}') 'Interface\{IID}\TypeLib names the library, whole GUID and all'
  Check ($run.Text -match 'hive Interface NumMethods: 4 \(type=4\)') 'NumMethods came from the typelib vtable size'
  Check ($run.Text -match 'hive CLSID TypeLib: \{A1B2C3D4-0001-4000-9000-000000000001\}') 'the coclass points back at the library'
  # And the round trip: a client asks the registry for the library it
  # registered and gets the same object back, though no .tlb file exists.
  Check ($run.Text -match 'REG load=0x00000000') 'LoadRegTypeLib found the registered library in the hive'
  Check ($run.Text -match 'REG count=2 hr=0x00000000') 'the library it got back reports its two types'
  # The activation path itself: combase resolved the class through a cached root
  # handle, the runtime translated it back to hkcr, and LoadLibrary was answered
  # from the archive under the path the component registered.
  Check ($run.Text -match 'base \\REGISTRY\\USER\\S-1-5-[\d-]+_Classes -> hkcr') 'a real cached hive root was translated back to hkcr'
  $loadLine = 'load-map C:\\virt\\' + [regex]::Escape($serverName)
  Check ($run.Text -match $loadLine) 'the server was mapped out of the virtual filesystem'
  Check ($run.Text -match ($loadLine + ' base=\d+ dllmain=1')) 'the mapped server ran its DllMain'
  Check ($run.Text -match 'DllUnregisterServer returned 0x00000000') 'the component unregistered itself'
  # The other half of L5.6: taking the library out again. The version halves
  # arrive as WORD arguments, so this also proves they are read as words.
  Check ($run.Text -match 'typelib thunks total: .*UnRegisterTypeLib=1') 'unregistration called the runtime, not the real registry'
  Check ($run.Text -match ('typelib-unregister TypeLib\\\{A1B2C3D4-0001-4000-9000-000000000001\}\\1\.0')) 'the library key was removed by its own name and version'
  Check ($run.Text -match 'hive TypeLib after unregister: gone') 'nothing of the library is left in the hive'
  Check ($run.Text -match 'typelib after unregister: .*unregistered=1') 'the runtime counted the removal'
  Check ($run.Text -match 'hive after unregister: .* delete=3 ') 'unregistering removed the class keys and the library from the hive'
  if ($ordinaryBuild) {
    # A CRT build registers the path GetModuleFileNameW reported. The loader
    # cannot name a hand-mapped image, so a nonzero count here means the runtime
    # answered -- and the load above proves the answer was usable.
    Check ($run.Text -match 'GetModuleFileNameW=[1-9]\d*') 'the ordinary build asked the runtime where it lives'
  }
  if ($consume) {
    Check ($run.Text -match 'server file deleted before mapping: YES') 'the server was deleted from disk before it was ever mapped'
  }
}

foreach ($serverName in $servers) {
  $ordinary = $serverName -like '*_crt*'
  Write-Host "==> $serverName : register, activate, unregister"
  $run = Run-Host $serverName $false $serverName
  Assert-Run $run $serverName $false $ordinary
}

Write-Host '==> com_server.dll with the file deleted before it is mapped'
$runConsume = Run-Host 'com_server.dll' $true 'consume'
Assert-Run $runConsume 'com_server.dll' $true $false

# ------------------------------------------------------ the registry stayed real
Write-Host '==> the real registry'
Check (-not (Test-Path -LiteralPath $clsidKey)) 'HKCR\CLSID\{9B1F...} was never created'
Check (-not (Test-Path -LiteralPath $progIdKey)) 'HKCR\LunaPack.Answer was never created'
Check (-not (Test-Path -LiteralPath $machineKey)) 'HKLM\Software\Classes was never written'

# ------------------------------------------------------------- no administrator
Write-Host '==> rights'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "  process elevated: $elevated (not required either way)"
# The point is not that the process is unelevated but that the write path never
# needed HKLM: the hive answered it, and the machine half of the registry is
# untouched.
Check ($runConsume.Text -match 'hive after activate: open=[1-9]\d* .* query=\d+ write=18') 'the hive answered the activation reads, not HKLM'

# ------------------------------------------------------------------- AV gate
Write-Host '==> AV retest (separate mechanism)'
$after = QuarantineCount
Check ($before -eq $after) "Huorong quarantine unchanged ($before -> $after)"

Write-Host '==> verdict'
if ($script:failed -eq 0) {
  Write-Host 'ALL COM ACTIVATION INVARIANTS PASSED'
  exit 0
}
Write-Host "$($script:failed) COM ACTIVATION INVARIANT(S) FAILED" -ForegroundColor Red
exit 1
