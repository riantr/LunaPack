# Build the Windows in-process runtime from the LunaPack repository.
#
#   powershell -File scripts\build_runtime_windows.ps1 [-SkipDemo] [-Consume]
#
# The root module stays cross-platform; everything here lives in runtime/,
# which is its own MoonBit module. Steps:
#   1. check / test / build the runtime static archive with MoonBit
#   2. link that archive into lpvirt.dll with the MSVC linker
#   3. compile the two C test doubles and run the end-to-end demo
#
# -Consume makes the harness delete payload.dll from disk after reading its
# bytes, before mapping them. That is the zero-disk proof. No security software
# is disabled or bypassed by this script.

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

# --------------------------------------------------------------- 5. run demo
$args = @($distDir)
if ($Consume) { $args += '--consume' }
Write-Host '==> run the end-to-end demo'
& $hostExe @args
Assert-Ok 'host.exe'
Write-Host '==> done'
