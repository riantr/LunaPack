# Build the Windows in-process runtime from the LunaPack repository.
#
#   powershell -File scripts\build_runtime_windows.ps1 [-SkipDemo] [-Consume]
#
# The root module stays cross-platform; everything here lives in runtime/,
# which is its own MoonBit module. Steps:
#   1. check / test / build the runtime static archive with MoonBit
#   2. link that archive into lpvirt.dll with the MSVC linker
#   3. compile the C test doubles and run the end-to-end demo
#   4. compile the L2.0 thin launcher + no-CRT target EXE and run it
#
# -Consume makes each harness delete its target image from disk after reading
# its bytes, before mapping them. That is the zero-disk proof. No security
# software is disabled or bypassed by this script.

param(
  [switch]$SkipDemo,
  [switch]$Consume
)

# Native tools (moon, cl, link) write their progress to stderr. Under
# 'Stop' PowerShell 5.1 turns that into a terminating NativeCommandError, so
# failures are detected through $LASTEXITCODE instead of ErrorActionPreference.
$ErrorActionPreference = 'Continue'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runtimeDir = Join-Path $root 'runtime'
$distDir = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

function Assert-Ok($label) {
  if ($LASTEXITCODE -ne 0) { throw "$label failed (exit $LASTEXITCODE)" }
}

# ---------------------------------------------------------------- 1. MoonBit
Write-Host '==> runtime: moon fmt --check / info / check / test / build'
Push-Location $runtimeDir
try {
  & moon fmt --check; Assert-Ok 'moon fmt --check'
  & moon info; Assert-Ok 'moon info'
  & moon check --target native; Assert-Ok 'moon check'
  & moon test --target native; Assert-Ok 'moon test'
  & moon build --release --target native; Assert-Ok 'moon build'
} finally {
  Pop-Location
}
$archive = Join-Path $runtimeDir '_build\native\release\build\lunapack_runtime.lib'
if (-not (Test-Path $archive)) { throw "missing archive: $archive" }

# ------------------------------------------------------------- 2. MSVC tools
$linkExe = (Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
$clExe = (Get-Command cl.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
$msvcRoot = $null
if (-not $linkExe -or -not $clExe) {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path $vswhere)) { throw "MSVC toolchain not found ($vswhere missing)" }
  $vsPath = (& $vswhere -latest -products * -property installationPath).Trim()
  $msvcRoot = (Get-ChildItem (Join-Path $vsPath 'VC\Tools\MSVC') -Directory |
               Sort-Object Name -Descending | Select-Object -First 1).FullName
  $binDir = Join-Path $msvcRoot 'bin\HostX64\x64'
  $linkExe = Join-Path $binDir 'link.exe'
  $clExe = Join-Path $binDir 'cl.exe'
} else {
  $binDir = Split-Path $linkExe -Parent
  $msvcRoot = (Resolve-Path (Join-Path $binDir '..\..\..')).Path
}

$sdkLibRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Lib'
$sdkVersion = (Get-ChildItem $sdkLibRoot -Directory |
               Where-Object { $_.Name -match '^10\.' } |
               Sort-Object Name -Descending | Select-Object -First 1).Name
$umLib = Join-Path $sdkLibRoot "$sdkVersion\um\x64"
$ucrtLib = Join-Path $sdkLibRoot "$sdkVersion\ucrt\x64"
$sdkInc = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Include\$sdkVersion"
if ($msvcRoot) {
  $env:INCLUDE = "$msvcRoot\include;$sdkInc\um;$sdkInc\ucrt;$sdkInc\shared"
  $env:LIB = "$msvcRoot\lib\x64;$umLib;$ucrtLib"
}
$env:PATH = "$binDir;$env:PATH"

Write-Host "==> link.exe: $linkExe"
Write-Host "==> cl.exe  : $clExe"

# --------------------------------------------------------------- 3. lpvirt.dll
$rsp = Join-Path $distDir 'lpvirt.rsp'
$def = (Join-Path $runtimeDir 'lpvirt.def').Replace('\', '/')
$outDll = (Join-Path $distDir 'lpvirt.dll').Replace('\', '/')
$implib = (Join-Path $distDir 'lpvirt_implib.lib').Replace('\', '/')
$archiveArg = $archive.Replace('\', '/')
$umArg = $umLib.Replace('\', '/')
$ucrtArg = $ucrtLib.Replace('\', '/')
@(
  '/DLL', '/NOLOGO', '/MACHINE:X64',
  "/DEF:`"$def`"",
  "/OUT:`"$outDll`"",
  "/IMPLIB:`"$implib`"",
  "/LIBPATH:`"$umArg`"",
  "/LIBPATH:`"$ucrtArg`"",
  "`"$archiveArg`"",
  'kernel32.lib', 'user32.lib', 'advapi32.lib', 'bcrypt.lib',
  'shell32.lib', 'dbghelp.lib', 'ws2_32.lib'
) | Set-Content -Path $rsp -Encoding ascii
Write-Host '==> link lpvirt.dll'
& $linkExe "@$rsp"
Assert-Ok 'link lpvirt.dll'
if (-not (Test-Path (Join-Path $distDir 'lpvirt.dll'))) { throw 'lpvirt.dll was not produced' }

if ($SkipDemo) { Write-Host '==> demo skipped'; return }

# --------------------------------------------------------------- 4. C doubles
$payloadSrc = Join-Path $runtimeDir 'tests\payload.c'
$hostSrc = Join-Path $runtimeDir 'tests\host.c'
$payloadDll = Join-Path $distDir 'payload.dll'
$hostExe = Join-Path $distDir 'host.exe'
$objDir = "$distDir\"
Write-Host '==> compile payload.dll'
& $clExe /nologo /LD "/Fo:$objDir" "/Fe:$payloadDll" "$payloadSrc" /link advapi32.lib kernel32.lib
Assert-Ok 'cl payload.dll'
Write-Host '==> compile host.exe'
& $clExe /nologo "/Fo:$objDir" "/Fe:$hostExe" "$hostSrc" /link advapi32.lib kernel32.lib
Assert-Ok 'cl host.exe'

# ------------------------------------------------ 4b. L2.0 thin launcher pair
$miniSrc = Join-Path $runtimeDir 'tests\mini_exe.c'
$launcherSrc = Join-Path $runtimeDir 'tests\launcher.c'
$targetExe = Join-Path $distDir 'mini_target.exe'
$crtSrc = Join-Path $runtimeDir 'tests\crt_target.c'
$crtExe = Join-Path $distDir 'crt_target.exe'
$launcherExe = Join-Path $distDir 'launcher.exe'
$miniObj = Join-Path $distDir 'mini_exe.obj'
$dynSrc = Join-Path $runtimeDir 'tests\dynlib.c'
$dynDll = Join-Path $distDir 'dynlib.dll'
$ntdllSrc = Join-Path $runtimeDir 'tests\ntdll_target.c'
$ntdllObj = Join-Path $distDir 'ntdll_target.obj'
$ntdllExe = Join-Path $distDir 'ntdll_target.exe'
$fbSrc = Join-Path $runtimeDir 'tests\fallback_target.c'
$fbObj = Join-Path $distDir 'fallback_target.obj'
$fbExe = Join-Path $distDir 'fallback_target.exe'
$provSrc = Join-Path $runtimeDir 'tests\pe_provider.c'
$provDef = Join-Path $runtimeDir 'tests\pe_provider.def'
$provDll = Join-Path $distDir 'pe_provider.dll'
$ordSrc = Join-Path $runtimeDir 'tests\pe_ordinal_consumer.c'
$ordImpDef = Join-Path $runtimeDir 'tests\pe_ordinal_import.def'
$ordImpLib = Join-Path $distDir 'pe_ordinal_import.lib'
$ordObj = Join-Path $distDir 'pe_ordinal_consumer.obj'
$ordExe = Join-Path $distDir 'pe_ordinal_consumer.exe'
$xpSrc = Join-Path $runtimeDir 'tests\pe_export_probe.c'
$xpExe = Join-Path $distDir 'pe_export_probe.exe'
Write-Host '==> compile mini_target.exe (no CRT, /ENTRY:mini_main)'
& $clExe /nologo /c /GS- "/Fo:$miniObj" "$miniSrc"
Assert-Ok 'cl mini_exe.c'
& $linkExe /nologo /MACHINE:X64 /SUBSYSTEM:CONSOLE /ENTRY:mini_main /NODEFAULTLIB `
  "/OUT:$targetExe" "$miniObj" kernel32.lib
Assert-Ok 'link mini_target.exe'
Write-Host '==> compile dynlib.dll (L2.2 runtime-loaded module with virtualized imports)'
& $clExe /nologo /LD "/Fo:$objDir" "/Fe:$dynDll" "$dynSrc" /link kernel32.lib
Assert-Ok 'cl dynlib.dll'
Write-Host '==> compile ntdll_target.exe (L2.3 native API spike, /ENTRY:ntdll_main)'
& $clExe /nologo /c /GS- "/Fo:$ntdllObj" "$ntdllSrc"
Assert-Ok 'cl ntdll_target.c'
& $linkExe /nologo /MACHINE:X64 /SUBSYSTEM:CONSOLE /ENTRY:ntdll_main /NODEFAULTLIB `
  "/OUT:$ntdllExe" "$ntdllObj" kernel32.lib
Assert-Ok 'link ntdll_target.exe'
Write-Host '==> compile fallback_target.exe (L2.5 per-category fallback probe, /ENTRY:fb_main)'
& $clExe /nologo /c /GS- "/Fo:$fbObj" "$fbSrc"
Assert-Ok 'cl fallback_target.c'
& $linkExe /nologo /MACHINE:X64 /SUBSYSTEM:CONSOLE /ENTRY:fb_main /NODEFAULTLIB `
  "/OUT:$fbExe" "$fbObj" kernel32.lib advapi32.lib
Assert-Ok 'link fallback_target.exe'
Write-Host '==> compile pe_provider.dll (L3 ordinal + forwarded-export fixture)'
& $clExe /nologo /LD "/Fo:$objDir" "/Fe:$provDll" "$provSrc" /link /DEF:"$provDef" kernel32.lib
Assert-Ok 'cl pe_provider.dll'
Write-Host '==> build ordinal import library (NONAME -> ordinal 1)'
& (Join-Path $binDir 'lib.exe') /nologo /MACHINE:X64 /DEF:"$ordImpDef" "/OUT:$ordImpLib"
Assert-Ok 'lib pe_ordinal_import'
Write-Host '==> compile pe_ordinal_consumer.exe (no CRT, imports by ordinal)'
& $clExe /nologo /c /GS- "/Fo:$ordObj" "$ordSrc"
Assert-Ok 'cl pe_ordinal_consumer.c'
& $linkExe /nologo /MACHINE:X64 /SUBSYSTEM:CONSOLE /ENTRY:pe_ordinal_main /NODEFAULTLIB `
  "/OUT:$ordExe" "$ordObj" "$ordImpLib" kernel32.lib
Assert-Ok 'link pe_ordinal_consumer.exe'
Write-Host '==> compile pe_export_probe.exe (L3 forwarded-export probe)'
& $clExe /nologo "/Fo:$objDir" "/Fe:$xpExe" "$xpSrc" /link kernel32.lib
Assert-Ok 'cl pe_export_probe.exe'
Write-Host '==> compile crt_target.exe (CRT diagnostic, /SUBSYSTEM:CONSOLE)'
& $clExe /nologo "/Fo:$objDir" "/Fe:$crtExe" "$crtSrc" /link kernel32.lib
Assert-Ok 'cl crt_target.exe'
Write-Host '==> compile launcher.exe'
& $clExe /nologo "/Fo:$objDir" "/Fe:$launcherExe" "$launcherSrc" /link kernel32.lib
Assert-Ok 'cl launcher.exe'

# --------------------------------------------------------------- 5. run demos
$args = @($distDir)
if ($Consume) { $args += '--consume' }
Write-Host '==> run the end-to-end demo'
& $hostExe @args
Assert-Ok 'host.exe'

$laArgs = @($distDir, $targetExe)
if ($Consume) { $laArgs += '--consume' }
Write-Host '==> run the L2.0 thin launcher (no-CRT target, direct entry)'
& $launcherExe @laArgs
Assert-Ok 'launcher.exe'
$crtArgs = @($distDir, $crtExe, '--thread')
if ($Consume) { $crtArgs += '--consume' }
Write-Host '==> run the L2.1 CRT target (worker thread + ExitProcess redirect)'
& $launcherExe @crtArgs
Assert-Ok 'launcher.exe crt --thread'
Write-Host '==> done'
