# LunaPack in-process runtime (experimental, Windows x64 only)

This directory is a **separate MoonBit module** (`riantr/lunapack_runtime`), not
a package of the root `riantr/LunaPack` module. That separation is deliberate:

- it is Windows-only and calls Win32 directly through `extern "C"`;
- it is a `foreign_library`, so its native test executables need
  `advapi32.lib` on the linker line;
- the root module must keep building for **native + wasm** on Linux, macOS and
  Windows. A Windows-only link flag inside the root module would break its
  Linux and macOS CI jobs.

The root CLI is unchanged. Nothing here is bundled into `LunaPack.exe`, and the
wasm front end never sees this code.

## What it does

`lpvirt.dll` is a C ABI DLL built from MoonBit. A host loads it **into its own
process**, seeds an in-memory filesystem and registry hive, and points a
consumer module's import address table at the thunks the DLL exports.

Two ways to get a consumer into the process are supported:

1. `LoadLibrary` a DLL and call `lp_install_iat_hooks(hmodule)`.
2. **Manual PE mapping** — read the DLL bytes into memory and call
   `lp_map_image(data, len)`. The consumer never has to exist as a file while
   it runs. This is the zero-disk path.

The mapper copies headers and sections into private pages of the current
process, applies base relocations, resolves imports with
`LoadLibraryA`/`GetProcAddress`, gives each section the protection its PE
characteristics ask for, and flushes the instruction cache. It does **not** use
`CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory` or `OpenProcess`;
`VirtualAlloc` here reserves pages of the *current* process.

Thirty-two Win32 entry points are hooked. The original twelve (unchanged):

```
CreateFileW  ReadFile  CloseHandle  GetFileAttributesW  GetFileSizeEx
FindFirstFileW  FindNextFileW
RegOpenKeyExW  RegQueryValueExW  RegSetValueExW  RegCloseKey
GetProcAddress
```

Seven added in L1 for writable files and full handle semantics:

```
WriteFile  GetFileAttributesExW  GetFileInformationByHandle
SetFilePointerEx  DeleteFileW  MoveFileExW  GetQueuedCompletionStatus
```

One added in L2.1 so a mapped CRT image can finish without ending the host:

```
ExitProcess   (redirected to ExitThread; code via lp_virt_exit_query)
```

Eight added in L2.1 for ANSI paths and virtual temp directories:

```
CreateFileA  GetFileAttributesA  GetFileAttributesExA  FindFirstFileA
FindNextFileA  DeleteFileA  MoveFileExA  GetTempPathW
```

Four added in L2.2 so dynamically loaded modules are hooked too:

```
LoadLibraryA  LoadLibraryW  LoadLibraryExA  LoadLibraryExW
```

The real loader brings the module in, then its IAT is rewritten with the same
hook table. Windows system DLLs (`\windows\system32\`, `syswow64`, `winsxs`,
`systemapps`) are skipped: patching their own `LoadLibrary` slots makes the OS
loader's internal API-set resolution re-enter our thunk and recurse. `GetProcAddress`
now also handles ordinal lookups safely (returns 0, not virtualized) and only
substitutes a thunk when the target module actually exports the symbol.

`GetProcAddress` is hooked so an application that resolves APIs dynamically is
covered too. A request that is not in the virtual tree falls through to the
real Win32 API through `lpvirt.dll`'s own unpatched import — no trampoline is
needed. HKLM writes land in the memory hive, so no administrator rights are
required and the real registry is untouched.

## Build and demo

From the repository root, on Windows with MoonBit and an MSVC toolchain:

```powershell
powershell -File scripts\build_runtime_windows.ps1 -Consume
```

The script runs `moon fmt`, `moon info`, `moon check`, `moon test` and
`moon build --release` inside this directory, links `dist/lpvirt.dll`, compiles
the C test doubles in `tests/`, and runs two demos:

1. the L1 DLL harness (`host.exe` + `payload.dll`), and
2. the L2.0 thin launcher (`launcher.exe` + `mini_target.exe`), which maps a
   real **EXE image** (not a DLL), patches its IAT and calls its entry point
   directly.

`-Consume` deletes each target image from disk **after reading its bytes but
before mapping them**, which is the zero-disk proof. `-SkipDemo` stops after
the link. The thin launcher's own assertions, including a separate AV retest,
run with:

```powershell
powershell -File scripts\verify_thin_launcher.ps1
```

The C files in `tests/` are throwaway harnesses, not product code. They exist
because a consumer that believes it is an ordinary Windows program cannot be
written in MoonBit. Everything that ships is `*.mbt`.

### Thin-launcher entry-point boundary (L2.0)

The thin launcher demonstrates the mapping-and-hooking path for a **no-CRT**
EXE (`mini_target.exe`): its entry point returns control to the launcher, which
then prints counters and exits 0. A normal **CRT** EXE (`crt_target.c`,
diagnostic only) also runs correctly: L2.1 redirects its `ExitProcess` to
`ExitThread` and runs the mapped entry on a worker thread, so the launcher
regains control, reads the target exit code and finishes its epilogue. This is
still a diagnostic target, not a Tier B pass — the product launcher/CLI arrives
in L6.

`moonbit_init` must be called before any other export: the MoonBit runtime
inside a DLL is not initialized by the OS loader.

## Exports

| Export | Purpose |
| --- | --- |
| `moonbit_init` | Initialize the MoonBit runtime. Call first. |
| `lp_virt_reset` | Clear the VFS, hive and counters. |
| `lp_virt_add_file` | Register a virtual file (UTF-16 path + bytes). |
| `lp_virt_set_reg` | Seed a virtual registry value (root + subkey + name). |
| `lp_virt_stats` | Up to thirteen counters. First six (original ABI): creates, reads, fall-throughs, reg queries, patched slots, dynamic hits. Next six (L1): writes, seeks, deletes, renames, info queries, pending completions. Slot 12 (L2.3) counts ntdll-boundary virtual hits. Pass `cap >= 48` for L1, `cap >= 52` for all thirteen. |
| `lp_virt_set_meta` | Set a file's attributes and three FILETIMEs. |
| `lp_virt_set_cwd` | Set the directory used to resolve relative virtual paths. |
| `lp_virt_add_alias` | Register a short-name alias (e.g. `progra~1` -> `program files`). |
| `lp_virt_post_completion` | Post an overlapped completion record to the in-memory queue. |
| `lp_install_iat_hooks` | Patch the 52 hooked IAT slots of an image base (45 Win32 + 7 ntdll). Works for loaded and manually mapped images. |
| `lp_virt_exit_query` | Did a mapped image call ExitProcess, and with what code? Returns 1/0; writes the code to the given address. |
| `lp_virt_set_temp_path` | Seed the virtual temp directory returned by GetTempPathW (UTF-16LE). Empty disables the override. |
| `lp_map_image` | Manually map a PE32+ DLL from a byte array. Returns the image base, or 0. |
| `lp_map_error` | Why the last map failed (one of the `MAP_*` constants). |
| `lp_get_export` | Address of a named export of a mapped image. |
| `lp_get_entry` | Address of DllMain of a mapped image. |
| `lp_unmap_image` | Release the private pages of a mapped image. Records a detach-order violation if ATTACH was noted without DETACH. |
| `lp_mapped_attach`, `lp_mapped_detach` | L2.4: record the host's manual DllMain ATTACH / DETACH for a mapped image. DETACH must precede unmap. |
| `lp_virt_lifecycle_stats` | L2.4: `[mapped_hooks, loaded_hooks, attaches, detaches, violations]` — proves both install paths share one hook table and teardown order held. |
| `lp_virt_fallback_audit` | L2.5: `[self_thunk_hits, probes, unresolved, status]`. `self_thunk_hits=0` proves lpvirt.dll's own IAT is unpatched (no trampoline/recursion). |
| `lp_get_tls_callbacks` | L3.4: allocate a TLS index and return the callback array VA of a mapped image (host invokes each callback). |
| `lp_register_eh`, `lp_unregister_eh` | L3.4: register/unregister the mapped image's `.pdata` with RtlAdd/DeleteFunctionTable for SEH unwinding. |
| `lp_*_w` / `lp_*` | The Win32 thunks, one per name in the hook table. |
| `lp_nt_create_file`, `lp_nt_open_file`, `lp_nt_read_file`, `lp_nt_close` | L2.3 native file API thunks, reached through static ntdll IAT slots or the hooked `GetProcAddress`. |
| `lp_virt_ntdll_stats` | Current ntdll-boundary hit count. |
| `lp_create_process_w`, `lp_create_process_a` | L4.1: start a program under the virtual layer by redirecting the request into the launcher. Inert unless a bootstrap path is set. |
| `lp_set_bootstrap_path` | L4.1: record the launcher's own path (and put it in `LUNAPACK_BOOTSTRAP`). Called by the launcher on itself. |
| `lp_import_inherited_state` | L4.2: open the section named in `LUNAPACK_VFS_SECTION` and replace the virtual tree with its contents. Returns 0 imported, 1 nothing to import, 2-5 specific failures. |
| `lp_proc_stats` | L4: `[redirects, failures, sections_kept_open, last_error]`. |
| `lp_vfs_export` / `lp_vfs_import` | L4.2 serialization of the whole tree (files + metadata + dirs + aliases + cwd + temp path + registry) as a self-describing blob. |
| `lp_reg_get_value_w`, `lp_reg_create_key_ex_w/a`, `lp_reg_open_key_ex_a`, `lp_reg_delete_key_w/a`, `lp_reg_delete_value_w`, `lp_reg_enum_key_ex_w`, `lp_reg_enum_value_w`, `lp_reg_query_info_key_w` | L5 registry thunks: the surface a component registers itself with and the class database activates through. |
| `lp_nt_open_key`, `lp_nt_query_value_key`, `lp_nt_query_key` | L5 native registry entry points. combase reaches the class database through these as well as through Win32, so both layers answer from the hive. `NtQueryKey(KeyNameInformation)` is also how a real key handle is translated back into a hive path. |
| `lp_reg_stats` | L5: `[open, create, enum, delete, query, write]` request counters. |
| `lp_reg_log_count` / `lp_reg_log_get` | L5: the last registry requests the thunks saw (`kind detail`), so a failed activation can be read back instead of guessed at. |
| `lp_api_hits` / `lp_api_hits_reset` | L5: how often each thunk was reached, by API name. Tells a registration path apart from an activation path. |
| `lp_get_module_file_name_w` | L5.5: answer `GetModuleFileNameW` for a mapped image with its virtual path. A component that registers itself writes that path into `InprocServer32`, so this is what makes the class point back into the archive. |
| `lp_set_module_path` | L5.5: tell the runtime where a host's own manually mapped image lives, before calling into it. |

## Limits — read these before treating this as production code

- **x64 PE32+ only.** x86 images, PE32 images and ARM64 are refused with
  `MAP_NOT_X64`. A matching 32-bit runtime is a hard toolchain NO-GO: MoonBit
  native emits only `x86_64`/`aarch64-pc-windows-msvc` and the runtime is built
  on `int64_t` pointer math. Full reasoning and restart conditions in
  `tests/corpus/X86_DECISION.md`.
- **Ordinal imports (L3.1) and forwarded exports (L3.2) are supported** by
  parsing the provider's in-memory export directory. `GetProcAddress` by ordinal
  from application code is still not virtualized (it returns 0 — an L2.2
  limitation), but the mapper resolves ordinal *imports* and forwarder strings
  (`DLL.Export` / `DLL.#ord`) at load time.
- **Delay imports (L3.3)** are resolved eagerly at map time into the IAT, with
  our thunk installed when the API is one we virtualize (no `__delayLoadHelper2`
  needed). **TLS callbacks (L3.4)** are enumerated via `lp_get_tls_callbacks`
  (host must invoke them) and the `.pdata` exception table can be registered for
  SEH via `lp_register_eh`. These C ABI exports are validated by white-box tests
  and their end-to-end real-program exercise remains in L6.
- **The OS loader is not involved.** `GetModuleHandle("payload.dll")` returns
  NULL, the image is absent from the module list, and neither DllMain nor TLS
  callbacks run automatically. The host must call DllMain itself using
  `lp_get_entry`, and must call it with `DLL_PROCESS_DETACH` before
  `lp_unmap_image` — otherwise the statically linked CRT leaves onexit
  handlers pointing into freed memory and the process crashes at exit.
- **VFS is writable with full handle semantics (L1).** Create dispositions,
  `WriteFile`, positioned/overlapped reads and writes, `SetFilePointerEx`,
  `GetFileInformationByHandle` (with stable file IDs), delete/rename,
  attributes and timestamps are served from memory. New files are created in
  memory only under a seeded virtual directory; everything else falls through
  to the real FS. Not covered: reparse points, symlinks, file locking/share
  enforcement, by-handle directory handles beyond enumeration.
- **Overlapped completion: queued, not callback-driven.** ReadFile/WriteFile
  with an `OVERLAPPED` complete synchronously in memory and post a record that
  `GetQueuedCompletionStatus` drains. `ReadFileEx`/`WriteFileEx` **completion
  routines (APCs)** are not invoked — that needs an alertable-wait mechanism
  and is tracked as a later item. Completion ports for real handles still
  fall through to kernel32.
- **IAT hooking only — no inline patches.** L2.1 added the ANSI (`...A`) file
  APIs and L2.3 added `NtCreateFile`/`NtOpenFile`/`NtReadFile`/`NtClose` to the
  same IAT/`GetProcAddress` table, so direct native callers are covered. We do
  **not** rewrite ntdll code, kernel32/KernelBase internals, or issue direct
  syscalls; programs that obtain the Win32 API outside our IAT/GPA hooks still
  bypass the runtime. Inline hooking remains a separate AV-gated decision.
- **Child processes follow, but only through this hook (L4).** A program that
  calls `CreateProcessW`/`CreateProcessA` is redirected into the launcher, the
  virtual tree is carried in a named shared section, and a grandchild follows
  the same way — verified as a three-level chain. **Not** covered:
  `CreateProcessAsUserW`, `CreateProcessWithTokenW`, `CreateProcessWithLogonW`
  and `ShellExecute*`, so a launch that passes its own token leaves the virtual
  layer. Each spawn keeps one section handle open for the life of the process.
  A mapped image's `GetCommandLineW` and CRT `argv` still describe the launcher,
  not the image, because the PEB belongs to the process — PEB fidelity is L6
  work.
- **COM components register and activate without administrator rights (L5).**
  The whole `HKCR` namespace (and both `Software\Classes` subtrees, which are
  folded onto `hkcr`) is owned by the hive, so `DllRegisterServer` writes land in
  memory and the class database reads them back; reads of keys the hive does not
  hold still fall through to the real registry, so already-installed components
  keep working. `CoCreateInstance` then finds `InprocServer32`, `LoadLibrary*` is
  answered out of the virtual filesystem, `GetProcAddress` is answered from the
  image's own export directory, and the entry point is run by the runtime (a
  hand-mapped image gets no `DllMain` from the loader). `GetModuleFileNameW` is
  answered with the virtual path, which is what a self-registering component
  writes into `InprocServer32`. **Not** covered: type-library registration.
  `scrrun.dll` fails with `TYPE_E_CANTLOADLIBRARY` because `RegisterTypeLib`
  loads the typelib from a path that does not exist on disk, and `wshom.ocx`
  fails with `0x80040201` *natively as well*, so that one is the component's
  limit, not ours. Shipped OCX that self-register through an embedded typelib
  need typelib virtualization, tracked as L5.6. Only the wide
  `GetModuleFileNameW` is virtualized, so VB6-era ANSI servers remain out of
  reach — they need the VB runtime, which manual mapping does not provide.
- **A mapped image runs its entry point only when the runtime maps it.** For an
  image the runtime loads out of the VFS it calls `DllMain(base,
  DLL_PROCESS_ATTACH, NULL)` itself, through a small stub the runtime writes
  into its own page and hands to `InitOnceExecuteOnce` (MoonBit cannot call a
  computed address, and the runtime stays free of C). A host that maps an image
  itself — the way `regsvr32` runs `DllRegisterServer` — still has to make that
  call, and should call `lp_set_module_path` first so the image can answer
  `GetModuleFileNameW`.
- **AV behaviour is measured, not assumed.** On the development machine
  (Huorong), the P0 remote-injection experiment was quarantined 11 times as
  `HVM:Trojan/Injector.gen!A`; this in-process runtime, including the manual
  mapper, produced no new quarantine entries. Other engines, unsigned
  binaries and signed binaries may behave differently. Re-test every new
  mechanism on a machine with security software enabled.
- **Not wired into the CLI yet.** No command in `LunaPack.exe` uses this DLL;
  there is no archive format for virtual files yet, and the release workflow
  ships `lpvirt.dll` as an experimental asset only.

## Baselines (L0 measured 2026-11-18, L1 re-measured 2026-11-18)

These are the numbers every later loop must compare against. A regression is
any fall below them; a number that only moves because the analyzer version
changed must be recorded with that version, not silently accepted. The L0
column is the frozen baseline; the L1 column is the current post-L1 value.

| Gate | Command | L0 baseline | L1 current |
| --- | --- | --- | --- |
| Root tests | `moon test --target native` (repo root) | 209 / 209 | **209 / 209 passed, 0 failed** |
| Runtime tests | `moon test --target native` (this directory) | 10 / 10 | **21 / 21 passed, 0 failed** |
| End-to-end demo | `scripts/build_runtime_windows.ps1 -Consume` | exit 0; 12 IAT slots | exit 0; 20 IAT slots; payload deleted before mapping, OS loader uninvolved, real HKLM untouched |
| Zero-disk assertions | `scripts/verify_zero_disk.ps1` | 12 invariants | **18 invariants** (12 base + 6 L1) all passing; 21 IAT slots on the DLL harness |
| Thin launcher (L2.0/L2.1/L2.2) | `scripts/verify_thin_launcher.ps1` | — | **25 invariants** all passing; real EXE mapped, 10 IAT slots, ANSI + temp path + ExitProcess redirect + GetProcAddress/LoadLibrary dynamic resolution + runtime module IAT patch, 16 → 16 AV |
| Static analysis (MSA) | `moonx riantr/moonbit_static_analysis@0.4.45 <repo>` | `actionable=0 notices=577` | `files=68 parsed=68 actionable=0 defects=0 notices=616 unreliable=0 withheld=0` |
| Static analysis (LunaFlow L1) | `moonx riantr/LunaFlow@0.1.19 analyze --dir <repo> --out <dir>` | `dead_code=4 taint_sinks=17` | `files=60 dead_code=4 unreachable=0 infinite_loop=0 taint_sinks=15` |
| Static analysis (LunaFlow --funnel) | same + `--funnel` | L2 abstract=57, L3 vcs=0 | `level=3 abstract_findings=23 vcs=0` |
| AV (Huorong) | quarantine directory count | 16 → 16 | **16 → 16** before and after the in-process + L1 demo (no new entries) |

The MSA notice count rose from 577 to 616 in L1 because MSA reports every new
`test`, `const` and `struct` declaration as "outside the analyzed subset" — a
notice, not a finding (`actionable=0 defects=0` is unchanged). LunaFlow
`taint_sinks` fell from 17 to 15; numbers here only ever move down.

### L2.3 re-measure (2026-11-19)

Root tests 209/209; runtime tests **23/23** (two pure white-box tests for NT
prefix stripping and disposition mapping). Zero-disk 18 invariants and thin
launcher 25 invariants still pass with the enlarged hook table; the new
`scripts/verify_ntdll_spike.ps1` adds 13 invariants for the native-API target
(virtual read, real-file fall-through, target deleted before mapping, ntdll hit
counter, zero disk, AV). MSA 0.4.45: `actionable=0 defects=0 notices=639`
(notices are structural only); LunaFlow 0.1.19: `dead_code=4 taint_sinks=15
unreachable=0 infinite_loop=0`, funnel L2 `abstract_findings=23`, L3 `vcs=0`.
Huorong quarantine **16 → 16** in the M2b run (Huorong only; second engine
still pending). No inline ntdll code patch was attempted — see the L2.3 note
in `LunaPack_EVB_parity_TODO.md`.

Toolchain actually measured on: `moon 0.1.20261102 (ea07287 2026-11-02)`,
`moonc 0.10.19+bee578715`. The root `README.mbt.md` quotes `0.1.20261104` as
the version every number in *that* file was measured on; this runtime baseline
was taken on `0.1.20261102` and says so rather than inheriting the other date.

### L2.4 / L2.5 / L3 re-measure (2026-11-19)

Root tests 209/209; runtime tests **30/30** (six new white-box tests: L2.4
lifecycle, L3.1 ordinal decode, L3.2 forwarder split/decimal/RVA, L3.3 delay
descriptor count, L3.4 TLS/exception dir readers). All four independent verify
scripts pass: `verify_thin_launcher.ps1` (27 invariants, L2.4 unified installer
+ no violation), `verify_ntdll_spike.ps1` (13), `verify_fallback_chain.ps1`
(L2.5 structural `self_thunk_hits=0` + 7 per-category fall-through + ntdll
regression, own AV retest), `verify_pe_features.ps1` (L3.1 ordinal consumer
`ORDINAL IMPORT OK`, L3.2 forwarder resolves to real kernel32 address, white-box
gate, own AV retest). Zero-disk 18 invariants still pass.

MSA 0.4.45: `actionable=0 defects=0 notices=667` (structural notices only).
LunaFlow 0.1.19: `dead_code=1` (down from the 4 baseline — the ordinal-reject
path was removed), `taint_sinks=15 unreachable=0 infinite_loop=0`, funnel L2
`abstract_findings=23`, L3 `vcs=0`. Huorong quarantine **16 → 16** for each new
mechanism's independent retest (M2c fallback, M3 PE features; Huorong only,
second engine pending). `moon fmt --check` clean in root and `runtime`;
`moon info` stable; `pkg.generated.mbti` grew by 137 additive public signatures.

L3.5-3.7 (32-bit) is a documented NO-GO — see `tests/corpus/X86_DECISION.md`.

Analyzer version notes, kept so the numbers are reproducible:

- `moonx ... @latest` (MSA 0.4.52, LunaFlow 0.1.27) currently **fails to start**
  on this toolchain: `LinkError: Import "moonbitlang/async" "thread_pool/make_openat_job"
  requires a callable`. The pinned versions above are the ones that actually ran.
- MSA 0.4.46 agrees with 0.4.45 (`actionable=0`). MSA 0.4.50 reports
  `actionable=1`: a `DeadStore` on `let mut h : UInt32 = 0` at `lz4.mbt:69`,
  inside `xxhash32`. The initial zero is the accumulator seed and is read on
  the loop path; the detector does not follow it. Not a real defect. Recorded
  here so the jump is not mistaken for a regression when a newer pin is used.

AV quarantine path on this machine: `C:\ProgramData\Huorong\Sysdiag\Quarantine`.
The 16 files include 11 from the P0 remote-injection experiment (2026-11-13)
and 5 older entries; none are from this runtime.

## Source map

| File | Contents |
| --- | --- |
| `mem.mbt` | Raw in-process memory reads/writes, PE integer helpers, ASCII/UTF-16 conversion, FILETIME/OVERLAPPED helpers. |
| `vfs.mbt` | In-memory filesystem: writable files, dispositions, handles/offsets, metadata, enumeration, path normalization and aliases, completion queue. |
| `registry.mbt` | In-memory registry hive, HKLM/HKCU/HKCR redirection, handle translation for real keys. |
| `registry_api.mbt` | L5: the Win32 registry thunks (`RegCreateKeyEx*`, `RegOpenKeyExA`, `RegDelete*`, `RegEnum*`, `RegQueryInfoKeyW`, `RegGetValueW`), the request log and the hive counters. |
| `registry_nt.mbt` | L5: the native registry entry points (`NtOpenKey`, `NtQueryValueKey`, `NtQueryKey`) that combase uses alongside Win32. |
| `state.mbt` | Lazy process-wide state and the 52-entry hook table. |
| `entry.mbt` | L5.3: emits a `DllMain(base, DLL_PROCESS_ATTACH, NULL)` stub and has the system call it, for images the runtime maps itself. |
| `iat.mbt` | In-process import address table patcher; also patches runtime-loaded modules, skipping Windows system DLLs. |
| `thunks.mbt` | The Win32-compatible C ABI thunks and management exports. |
| `mapper.mbt` | Manual PE mapping, relocations, imports, protections, export lookup. |
| `runtime_wbtest.mbt` | Unit tests for the data model, L1/L2.1 VFS semantics, the PE layout reader, the hive and the entry stub (36 tests). |
| `tests/dynlib.c` | L2.2 runtime-loaded DLL whose static virtualized imports prove LoadLibrary IAT patching. |
