# Compatibility corpus (L0.2)

This is the fixed set of programs the in-process runtime is measured against.
Every later loop reruns the same list; adding a program here is a deliberate
change that must be recorded in the loop notes, not a quiet substitution after
a failure. The point is to stop "that program is special" from becoming a way
to declare success.

The corpus is built for **measurement**, not distribution. Nothing here is
copied into the repository; the manifest records the exact installed file,
its size and its SHA-256 so a machine can report which sample it actually ran.
`snapshot.ps1` refreshes that record when a sample is replaced.

## Tier A — controlled doubles (always runnable, in-repo build)

| Sample | Source | What it proves |
| --- | --- | --- |
| `host.exe` + `lpvirt.dll` + `payload.dll` | `runtime/tests/host.c`, `payload.c`, built by `scripts/build_runtime_windows.ps1` | virtual file read/enum, HKLM virtual read+write, real-FS and real-registry fall-through, dynamic `GetProcAddress` hook, 20/20 IAT slots, DllMain attach/detach order, zero-disk mapping; plus L1: write/append, `GetFileInformationByHandle` (file ID), `GetFileAttributesExW`, overlapped positioned read, rename/delete, completion queue |
| `-Consume` variant | same, `-Consume` flag | payload deleted before mapping; OS loader never knows the image |
| `launcher.exe` + `mini_target.exe` (L2.0 thin launcher) | `runtime/tests/launcher.c`, `mini_exe.c`, built by `scripts/build_runtime_windows.ps1` | a real **EXE image** (not a DLL) mapped in-process, 10 IAT slots patched on the EXE, its entry point called directly, virtual file read through the hooked IAT; L2.1 ANSI (`CreateFileA`/`GetFileAttributesA`) + virtual `GetTempPathW`; L2.2 dynamic `GetProcAddress`→thunk, ordinal no-fault, and `LoadLibraryA` of `dynlib.dll` (whose static imports are then patched); `--consume` proves zero disk. `crt_target.exe` runs on a worker thread and its `ExitProcess` is redirected to `ExitThread`, so a CRT `main()` reads the virtual file and the launcher regains control. |
| `dynlib.dll` (L2.2 runtime-loaded module) | `runtime/tests/dynlib.c`, built by `scripts/build_runtime_windows.ps1` | loaded at runtime by the mapped EXE through the hooked `LoadLibraryA`; its static `CreateFileW`/`ReadFile` IAT is patched so `dyn_probe()` reads the virtual file - proof that dynamically loaded application modules get the same hooks (system DLLs are skipped). |

Tier A is the only tier that runs on CI today. It is the minimum gate before a
Tier B run is meaningful.

## Tier B — real programs (at least five, one per required capability)

Captured on this machine 2026-11-18. All paths are absolute so a run is
reproducible; replace with an equivalent local install on another machine and
record the change.

| # | Capability under test | Sample | Arch | Notes / expected stress |
| --- | --- | --- | --- | --- |
| B1 | GUI program with many DLL dependencies | `C:\Program Files\CMake\bin\cmake-gui.exe` | x64 | Qt-based GUI; exercises IAT of a large GUI binary and its Qt plugins. Start with `--help` to avoid a window. |
| B2 | Python-packaged application | `C:\Program Files\Calibre2\calibre.exe` (bundles `python311.dll`, many `.pyd`) | x64 | PyInstaller-style launcher; the exact class EVB v11.30 fixed. Run `calibredb.exe --version` for a non-interactive probe. |
| B3 | Program with plugin DLLs | `C:\Program Files\Audacity\Audacity.exe` (ships `lib-*.dll` plugin set) | x64 | Loads plugins by name at runtime; stresses `LoadLibrary`/`GetProcAddress` coverage. |
| B4 | 32-bit program | `C:\Program Files (x86)\Enigma Virtual Box\enigmavb.exe` | x86 | **unsupported (toolchain)** — machine type measured `0x014C` (i386). MoonBit native emits no 32-bit Windows target and the runtime is `int64_t`/PE32+ only; formal NO-GO in `X86_DECISION.md`. A Tier B run skips B4 with this reason, not "program unsupported". `Compil32.exe` and `hhc.exe` are alternate x86 samples, same verdict. |
| B5 | ntdll / direct-syscall program | `runtime/tests/ntdll_target.c` (`dist/ntdll_target.exe`, L2.3) | x64 | Built in L2.3. Resolves `NtCreateFile`/`NtOpenFile`/`NtReadFile`/`NtClose` through `GetProcAddress` and calls them directly. Virtual read + real `C:\Windows\win.ini` fall-through both pass. Direct **syscalls** (bypassing ntdll exports) remain outside scope: no inline patch was attempted. |
| B6 | Simple console fall-through | `C:\Windows\System32\cmd.exe` with `/c echo OK` | x64 | Control case: almost all requests should fall through to the real FS; verifies hooking does not break ordinary programs. |

## Tier C — explicit non-goals (do not count as failures)

Programs that bring their own anti-tamper, kernel drivers or injection are out
of scope for this project, matching the P0 decision not to ship an injector.
Games with anti-cheat, AV products themselves, and anything requiring a kernel
driver are excluded. A program is moved from Tier B to Tier C only with a
written reason in the relevant loop notes.

## How to run

There is no automatic harness yet. In L1–L3 each run records, for every sample:

- command line and exit code;
- whether a virtual file was actually read (the sample must expose a probe);
- whether any file appeared in the sample's directory or `%TEMP%` (see the
  zero-disk harness from L0.3);
- Huorong quarantine count before and after.

A sample that cannot expose a virtual-file probe is not a pass; it is an
incomplete test and must be upgraded or replaced.

`scripts/verify_zero_disk.ps1` (L0.3) is the reusable assertion wrapper for
Tier A. It requires `payload.dll` to be present, so run the plain build first
(the `--consume` demo deletes the payload and cannot be reused):

```powershell
powershell -File scripts\build_runtime_windows.ps1        # rebuilds payload.dll + mini_target.exe
powershell -File scripts\verify_zero_disk.ps1             # 18 invariants, exit 1 on failure
powershell -File scripts\verify_thin_launcher.ps1         # 25 invariants + AV retest (L2.0/L2.1/L2.2)
```

Both verification scripts consume their target image, so run the plain build
first each time. The thin launcher's script also records a separate Huorong
quarantine count before/after (M2a in `AV_RETEST.md`).

The harness checks the demo's output plus a before/after snapshot of the dist
directory and `%TEMP%`; the only new file it tolerates is `real.txt`, which the
harness deliberately creates as the real-FS fall-through probe. The 18
invariants are the original 12 (zero-disk + fall-through + hook) plus 6 for the
L1 writable/handle semantics (write, by-handle info, attributes, overlapped
read, rename/delete, completion).
