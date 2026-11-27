# LunaPack in-process runtime and virtual launcher (Windows x64)

This directory is a **separate MoonBit module** (`riantr/lunapack_runtime`), not
a package of the root `riantr/LunaPack` module. That separation is deliberate:

- it is Windows-only and calls Win32 directly through `extern "C"`;
- it is a `foreign_library`, so its native test executables need
  `advapi32.lib` on the linker line;
- the root module must keep building for **native + wasm** on Linux, macOS and
  Windows. A Windows-only link flag inside the root module would break its
  Linux and macOS CI jobs.

The root CLI stays cross-platform: nothing here is compiled into
`LunaPack.exe`, and the wasm build never sees this code. But `lunapack bundle
--virtual` now writes a virtual layer into the v7 archive, and `lpvhost.exe` —
built in `host/` next to this module — maps the runtime and the program out of
that archive. `lpvirt.dll` is a shipping image, not just a test asset.

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
`moon build --release` inside this directory and `host/`, links
`dist/lpvirt.dll`, copies the launcher to `dist/lpvhost.exe`, compiles the C
test doubles in `tests/`, and runs two demos:

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

### CLI virtual bundles (L6)

`lpvhost.exe` is the product launcher. A virtual bundle is a launcher image
with a v7 archive appended; the manifest's `virtual` section names the virtual
root, temp directory, main program, file map and typed registry seeds. The
runtime DLL is packed as a reserved `@runtime/lpvirt.dll` entry, so its bytes
are covered by the same SHA-256 check as the program and the data files.

```powershell
lunapack bundle -i app.exe -o app-virtual.exe --Files assets `
  --virtual --virtual-root=C:\ --virtual-temp=C:\virt\tmp\ `
  --registry values.json --launcher dist\lpvhost.exe
.\app-virtual.exe
```

Bare `--virtual` uses `C:\`; `--no-virtual` produces a plain archive that
unpacks. Encryption, LZ4 and an automatic launcher are refused for a virtual
bundle. The ordinary launcher refuses a virtual bundle instead of unpacking it.

The launcher cannot hold the thunks itself. MoonBit only allows `#export_name`
in a `foreign_library`, and a `foreign_library` may not contain `main`, so a
pure-MoonBit executable has no C symbols to put in its export table. Instead
`lpvhost.exe` maps the embedded `lpvirt.dll` in memory, records its base in the
runtime state, and calls `lp_run_bundle`. The DLL parses and verifies the
archive, seeds the VFS and hive, maps the main image, patches its IAT and runs
it. Only `Int64`/`Int32` values cross the launcher boundary: two independently
linked MoonBit runtimes must not exchange `Bytes`, `String` or closures.

`bundle.mbt` holds the archive reader and runner; `host_api.mbt` exposes the
address-based bridge; `host/main.mbt` is the launcher's tiny front end. The
shipping assertion is:

```powershell
powershell -File scripts\verify_virtual_bundle.ps1
```

It uses the CLI and the shipping launcher, deletes the fixture after packing,
and checks the mapped program, checksum refusal, `--no-virtual`, zero disk and
a separate Huorong count.

### Thin-launcher entry-point boundary (L2.0)

The thin launcher demonstrates the mapping-and-hooking path for a **no-CRT**
EXE (`mini_target.exe`): its entry point returns control to the launcher, which
then prints counters and exits 0. A normal **CRT** EXE (`crt_target.c`,
diagnostic only) also runs correctly: L2.1 redirects its `ExitProcess` to
`ExitThread` and runs the mapped entry on a worker thread, so the launcher
regains control, reads the target exit code and finishes its epilogue. It is
still a controlled double; the product launcher now follows the same
worker-thread boundary through `lp_run_bundle`.

For a **hand-mapped DLL** the loader never runs DllMain, so its statically
linked CRT heap is still zeroed. The launcher must call the image entry with
`DLL_PROCESS_ATTACH` first, then `moonbit_init` on the main thread, and keep
`lp_run_bundle` on the worker so `ExitProcess`→`ExitThread` cannot end the
launcher. Skipping the attach makes `HeapAlloc` fault inside the runtime.

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
| `lp_install_iat_hooks` | Patch the 65 hooked IAT slots of an image base (58 Win32 + 7 ntdll), plus any oleaut32 slot imported by ordinal. Works for loaded and manually mapped images; also installs the L2.7 restricted CRT whitelist. |
| `lp_patch_crt_iat` | L2.7: patch only the file-I/O slots of `ucrtbase.dll` and `msvcrt.dll` (loader/process/registry slots stay real). Returns the number of slots patched; runs once per process, and `lp_install_iat_hooks` calls it too. |
| `lp_virt_exit_query` | Did a mapped image call ExitProcess, and with what code? Returns 1/0; writes the code to the given address. |
| `lp_virt_set_temp_path` | Seed the virtual temp directory returned by GetTempPathW (UTF-16LE). Empty disables the override. |
| `lp_map_image` | Manually map a PE32+ DLL from a byte array. Returns the image base, or 0. |
| `lp_map_error` | Why the last map failed (one of the `MAP_*` constants). |
| `lp_get_export` | Address of a named export of a mapped image. |
| `lp_get_entry` | Address of DllMain of a mapped image. |
| `lp_unmap_image` | Release the private pages of a mapped image. Records a detach-order violation if ATTACH was noted without DETACH. |
| `lp_mapped_attach`, `lp_mapped_detach` | L2.4: record the host's manual DllMain ATTACH / DETACH for a mapped image. DETACH must precede unmap. |
| `lp_virt_lifecycle_stats` | L2.4: `[mapped_hooks, loaded_hooks, attaches, detaches, violations]`, plus `[crt_modules, crt_slots]` when the caller passes at least 28 bytes (L2.7). Proves both install paths share one hook table, teardown order held, and the CRT whitelist matched. |
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
| `lp_reg_log_count` / `lp_reg_log_get` / `lp_reg_log_reset` | L5: the last registry requests the thunks saw (`kind detail`), so a failed activation can be read back instead of guessed at. The log is bounded at 128 entries; `reset` starts a new phase, which is what a host wants after an activation has filled it. |
| `lp_api_hits` / `lp_api_hits_reset` | L5: how often each thunk was reached, by API name. Tells a registration path apart from an activation path. |
| `lp_get_module_file_name_w` | L5.5: answer `GetModuleFileNameW` for a mapped image with its virtual path. A component that registers itself writes that path into `InprocServer32`, so this is what makes the class point back into the archive. |
| `lp_set_module_path` | L5.5: tell the runtime where a host's own manually mapped image lives, before calling into it. |
| `lp_load_typelib_ex`, `lp_load_typelib`, `lp_load_reg_typelib`, `lp_register_typelib`, `lp_register_typelib_for_user`, `lp_unregister_typelib`, `lp_unregister_typelib_for_user` | L5.6: the seven oleaut32 entry points a self-registering component uses. Each answers from the parsed library for a virtual path and falls through to the real API otherwise. Reached by name *and* by ordinal — see `ordinal_table()` in `state.mbt`. |
| `lp_typelib_stats` | L5.6: `[loaded, registered, unregistered, live_objects]`. |
| `lp_tl_query_interface` … `lp_tl_release_tl_attr` | L5.6: the thirteen `ITypeLib` vtable entries handed to a caller. `GetTypeInfo*`, `FindName`, `GetTypeComp` and `GetDocumentation` answer `E_NOTIMPL`; the rest are real. |
| `lp_virt_get_reg`, `lp_virt_has_reg` | L5.6: read a value, or a key's existence, back out of the hive. The hive is not the real registry, so a check has no other way to see what a registration wrote. |

## Limits

*Read these before treating this as production code.*

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
- **Child processes follow, and the shipping launcher does it too (L4).** A
  program that calls `CreateProcessW`/`CreateProcessA` is redirected into the
  launcher, the virtual tree is carried in a named shared section, and a
  grandchild follows the same way — verified as a three-level chain. Since L4
  was wired into `lp_run_bundle`, this holds for a v7 bundle as well: every
  generation of the bundle is its own bootstrap, so a child that the parent
  packed **and** a child that only exists on the parent's disk both run inside
  the layer, with the imported tree taking precedence over the archive.
  **Not** covered: `CreateProcessAsUserW`, `CreateProcessWithTokenW`,
  `CreateProcessWithLogonW` and `ShellExecute*`, so a launch that passes its own
  token leaves the virtual layer. Each spawn keeps one section handle open for
  the life of the process. A mapped image's `GetCommandLineW` and CRT `argv`
  still describe the launcher, not the image, because the PEB belongs to the
  process — PEB fidelity is L6 work. Arguments *are* forwarded: the child's
  command line is the bootstrap followed by the parent's tail, so `argv[1..]`
  is what the parent passed.
- **A child is only redirected when the target exists.** A path that is in
  neither the virtual tree nor on disk is handed to the real `CreateProcess`,
  so caller code that handles "file not found" still works. This also means
  the runtime never invents a process for a path it cannot map.
- **CRT-mediated file I/O is virtualized (L2.7), by a restricted whitelist.**
  System DLLs used to be excluded from IAT patching: rewriting a CRT's own
  `LoadLibrary` slot re-enters the OS loader and overflows the stack. L2.7 adds
  a narrow exception — `ucrtbase.dll` and `msvcrt.dll` get only their file slots
  (`CreateFile*`, `ReadFile`, `WriteFile`, `GetFileType`, `SearchPath*`, …)
  rewritten; loader, process and registry slots stay on the real APIs.
  `runtime/tests/crt_open.c` now reports `C-open result=OK` next to
  `win32 result=OK`, including through the shipping virtual-bundle path.
  A virtual miss still falls through to the real API. Which modules matched and
  how many slots changed are counted in `lp_virt_lifecycle_stats` (`crtmods`,
  `crtslots`).
- **`SearchPathW`/`SearchPathA` are hooked (L2.6).** Resolution happens before
  open: `cmd.exe` asks `SearchPathW` where a file lives, and a virtual answer
  includes the `lpFilePart` offset and the required length for a short buffer.
  A miss falls back to the real resolver.
- **Canonicalization and wildcard expansion are hooked (L2.8).** `cmd.exe` also
  calls `GetFullPathNameW` to normalize a `TYPE` argument and `FindFirstFileExW`
  to expand it. The real `FindFirstFileExW` reports `ERROR_PATH_NOT_FOUND` (3)
  when the parent exists only in the archive, which was the last reason a child
  `cmd.exe /c type <virtual file>` failed after L2.6/L2.7. Both now answer from
  the same virtual tree as `CreateFileW`, with a real-API fallback on a miss.
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
  writes into `InprocServer32`. `wshom.ocx` still fails its own
  `DllRegisterServer` with `0x80040201` *natively as well*, so that one is the
  component's limit, not ours. Only the wide `GetModuleFileNameW` is
  virtualized, so VB6-era ANSI servers remain out of reach — they need the VB
  runtime, which manual mapping does not provide.
- **A component's type library is virtualized too (L5.6).** An ordinary server
  registers itself by calling `LoadTypeLibEx` on its own path and handing the
  result to `RegisterTypeLib`; original oleaut32 can only do that from a file,
  so under any file-less scheme that call has to be answered from the archive.
  (`scrrun.dll` is *not* an example of that gap: it stores its library under the
  resource type name `'TYPELIB'` instead of the number 7, so `FindResource(h, 7,
  1)` misses it natively too and `LoadTypeLibEx` fails with
  `TYPE_E_CANTLOADLIBRARY` with or without a runtime in the way.) The runtime
  therefore reads the library itself: it walks the
  `TYPELIB` resource (`RT_TYPELIB`, id 1) out of the module bytes and parses the
  `MSFT` layout MIDL writes — library identity, version, LCID and platform, and
  for each interface and coclass its GUID, name, documentation and vtable size.
  `LoadTypeLibEx`/`LoadTypeLib` answer with a real `ITypeLib` object of ours,
  `RegisterTypeLib` writes the library into the hive the same way it writes
  classes (`TypeLib\{LIBID}\<ver>\<lcid>\win64|win32`, `Interface\{IID}` with
  `TypeLib`/`ProxyStubClsid32`/`NumMethods`, `CLSID\{CLSID}\TypeLib`),
  `LoadRegTypeLib` gives a client back the library it registered, and
  `UnRegisterTypeLib` removes it. Both `oleaut32.dll` import shapes are hooked:
  by name and by ordinal, because a component built the ordinary way imports
  these entry points by number (163, 183, 186, 442, 443) and a name-only hook
  would never fire. **Not** covered: no `ITypeInfo` per type, so
  `GetTypeInfo`, `GetTypeInfoOfGuid`, `GetTypeInfoType`'s follow-ups,
  `FindName`, `GetTypeComp` and `GetDocumentation` answer `E_NOTIMPL` (a BSTR
  would have to come from the real allocator); libraries in other formats
  (`SLTG`, the VB6-era layout) are refused rather than half-read, and the caller
  then falls through to the real API; `LoadTypeLibEx(REGKIND_REGISTER)` also
  registers, as it does natively, while `REGKIND_DEFAULT` and `REGKIND_NONE`
  differ from each other only in whether oleaut32 would consult the registry
  for a path, which a virtual file never has.
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
- **Wired into the CLI and Studio, but Windows x64 only.** `lunapack bundle
  --virtual` writes v7 virtual layers and `lpvhost.exe` runs them in memory;
  Studio's Virtual tab edits the root, temp path, runtime image and typed
  registry seeds. There is no x86 runtime (see `X86_DECISION.md`). The ordinary
  launcher intentionally refuses a virtual bundle.

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

- `moonx ... @latest` (MSA 0.4.52, LunaFlow 0.1.27) used to **fail to start** on
  this toolchain: `LinkError: Import "moonbitlang/async"
  "thread_pool/make_openat_job" requires a callable`. After the `async`/`fs`/
  `http` migration it runs again, and it is what the L5.6 numbers below were
  taken with; the pinned runs above and `@latest` now agree
  (`actionable=0`; LunaFlow `dead_code=1 taint_sinks=15`).
- MSA 0.4.46 agrees with 0.4.45 (`actionable=0`). MSA 0.4.50 reports
  `actionable=1`: a `DeadStore` on `let mut h : UInt32 = 0` at `lz4.mbt:69`,
  inside `xxhash32`. This note originally called it a false positive — it is
  not. Both branches of the `if` assign `h` before anything reads it, so the
  initial `0` was dead, and under `@latest` it was the only remaining
  actionable finding. `xxhash32` now computes the seed accumulator in the `if`
  expression itself, and `actionable` is back to 0 with the same checksums
  (`lz4_test.mbt` and the 209 root tests pin them).

AV quarantine path on this machine: `C:\ProgramData\Huorong\Sysdiag\Quarantine`.
The 16 files include 11 from the P0 remote-injection experiment (2026-11-13)
and 5 older entries; none are from this runtime.

### L5.6 re-measure (2026-11-19)

Root tests 209/209; runtime tests **41/41** (four new white-box tests: the
`MSFT` reader against a library assembled field by field in the test, refusal of
buffers that are not type libraries, the GUID binary/text round trip with the
field order pinned, and the oleaut32 ordinal table including the
same-number-different-library case; plus `read_file` returning a whole 9 KB file
rather than a prefix, which was the bug that started this loop).

`verify_com_activation.ps1` now runs **33 assertions per run** over the same
three runs (no-CRT server, ordinary CRT server, `--consume`): the previous set,
the type-library keys read back out of the hive (`TypeLib\{LIBID}` name and
version, the `win64` path pointing at `C:\virt\…`, `Interface\{IID}\TypeLib`
with the whole GUID, `NumMethods=4` from the vtable size, `CLSID\{CLSID}\TypeLib`),
the `LoadRegTypeLib` round trip (`REG count=2`), and the removal
(`UnRegisterTypeLib=1`, key gone, `delete=3`). The other five scripts are
unchanged and still pass: `verify_zero_disk` 18 (22 IAT slots),
`verify_thin_launcher` 27, `verify_ntdll_spike` 13, `verify_fallback_chain` 18,
`verify_pe_features` 11, `verify_child_follow` 23.

MSA @latest (0.4.52): `files=79 parsed=79 actionable=0 defects=0 notices=742`
(notices are structural only; +28 from the two new files and the new tests).
LunaFlow @latest (0.1.27): `dead_code=1 taint_sinks=15 unreachable=0
infinite_loop=0`, funnel L2 `abstract_findings=23`, L3 `vcs=0` — unchanged from
the L2.4/L2.5/L3 re-measure. `moon fmt --check` clean in root and `runtime`;
`pkg.generated.mbti` grew by 82 additive public signatures. Huorong quarantine
**16 → 16** for the M6 retest (Huorong only, second engine pending).

Two things are worth recording because they cost the most time:

- **oleaut32 is imported by ordinal.** `LoadTypeLibEx`/`RegisterTypeLib`/
  `UnRegisterTypeLib` arrive as `Ordinal 183/163/186`, so a hook table keyed on
  names patches nothing and every symptom looks like "the type library did not
  parse". `patch_imports` now reads the importing DLL's name and resolves
  ordinals through `ordinal_table()`; `verify_com_activation.ps1` asserts the
  thunk counters so this cannot silently regress.
- **`rc.exe` has no `TYPELIB` keyword.** `1 TYPELIB "x.tlb"` produces a
  *named* resource type (`'TYPELIB'`), which `FindResource(h, 7, 1)` — and
  therefore `LoadTypeLibEx` — cannot find; the resource type has to be written
  as `1 7 "x.tlb"`. The same defect exists in shipped Microsoft binaries:
  `scrrun.dll` stores its type library under the string type `'TYPELIB'`, which
  is why it fails with `TYPE_E_CANTLOADLIBRARY` natively and under any file-less
  scheme alike. That is a component bug, not a gap in this runtime.

### L6 re-measure (2026-11-23)

Root tests **213/213**; runtime tests **50/50** (L2.6/L2.7 added three, L2.8 one more). All nine assertion scripts are
green: `verify_virtual_bundle`, `verify_child_follow`, `verify_com_activation`,
`verify_fallback_chain`, `verify_ntdll_spike`, `verify_pe_features`,
`verify_thin_launcher`, `verify_zero_disk` (run last, because the consume demos
remove their own targets) and `verify_static_analysis`. The virtual script
checks **55 invariants**: a CLI-produced v7 layer, the embedded runtime entry,
mapped-program output, checksum refusal of a byte-flipped payload,
`--no-virtual`, a signed copy whose appended certificate table must not hide the
archive, a forged footer that must be skipped rather than believed, a bundle cut
short that must still be refused, no extracted file in the working directory or
`%TEMP%`, a three-level child chain where the child is **in the layer** and a
second one where the child is **only on disk**, and the CRT boundary
(`C-open FAILED` beside `win32 OK`). The AV comparisons are one per engine, so
they are counted on a machine that runs the engines and reported as skipped on a
CI runner, which has none (**17 → 17** for Huorong, whose baseline carries the
one entry the EICAR calibration wrote; no new record naming this repository for
360).

MSA 0.5.0 over the 74 git-tracked `.mbt` files: `files=74 parsed=74
actionable=0 notices=793 unchecked=2133`. LunaFlow 0.1.28 with
`--max-functions 5000`: `dead_code=1 taint_sinks=84 abstract_findings=75
vcs=0/0/0` over 1216 functions. The `taint_sinks=9` quoted by an earlier
revision of this section was the analyzer's default 150-function cap — writing
`--max-functions=5000` as a single `--flag=value` argument is accepted and then
silently ignored — so it measured a prefix of the code, not the code. Both
analyzers are now driven by `scripts/verify_static_analysis.ps1` over a staged
copy of the tracked files, because a built tree adds `_build` source copies and
`studio/.mooncakes`, and the same code then reports 21 actionable findings
instead of none. The one new finding that release did introduce — a
user-supplied path interpolated into a `fail` message in
`virtual_runtime_image` — was removed by printing the path and failing with a
constant. `moon fmt --check` is clean in the root, `runtime/` and `runtime/host/`,
and `moon info` leaves every `.mbti` byte-identical.

**CI runs it with the shipping CLI.** `.github/workflows/ci.yml` has a
`virtual-bundle` job that builds the root release CLI, builds this runtime and
its C fixtures **without** `-Consume` (that switch deletes the very target
images the verifier packs), and then runs `scripts/verify_virtual_bundle.ps1`
under Windows PowerShell 5.1 — the shell it was validated in, because
PowerShell 7.3+ re-quotes the arguments of a native command and the verifier
hands each command line to `cmd.exe`.

Two constraints shaped the launcher and are worth recording before anyone
tries to simplify it:

- A MoonBit **executable cannot export its own thunks**. `#export_name` is
  legal only in a `foreign_library`, and a `foreign_library` may not contain
  `main`. A `.def` on the executable produces `LNK2001` because the MoonBit
  amalgamation gives those functions mangled, static names. The runtime must
  therefore be mapped from the bundle as a DLL.
- A hand-mapped DLL has no CRT heap until its entry point sees
  `DLL_PROCESS_ATTACH`. The first `HeapAlloc` faults with `0xC0000005` if the
  launcher calls `moonbit_init` first. The correct order is attach,
  `moonbit_init` on the main thread, then `lp_run_bundle` on a worker.

## Source map

| File | Contents |
| --- | --- |
| `mem.mbt` | Raw in-process memory reads/writes, PE integer helpers, ASCII/UTF-16 conversion, FILETIME/OVERLAPPED helpers. |
| `vfs.mbt` | In-memory filesystem: writable files, dispositions, handles/offsets, metadata, enumeration, path normalization and aliases, completion queue. |
| `registry.mbt` | In-memory registry hive, HKLM/HKCU/HKCR redirection, handle translation for real keys. |
| `registry_api.mbt` | L5: the Win32 registry thunks (`RegCreateKeyEx*`, `RegOpenKeyExA`, `RegDelete*`, `RegEnum*`, `RegQueryInfoKeyW`, `RegGetValueW`), the request log and the hive counters. |
| `registry_nt.mbt` | L5: the native registry entry points (`NtOpenKey`, `NtQueryValueKey`, `NtQueryKey`) that combase uses alongside Win32. |
| `typelib.mbt` | L5.6: reads a type library out of module bytes — the `TYPELIB` resource walk and the `MSFT` layout (segment directory, type-info records, GUID/name/string tables) — reduced to what a registration writes. |
| `oleaut.mbt` | L5.6: the seven oleaut32 thunks, the `ITypeLib` object and its vtable, and the hive writes a registration produces. |
| `state.mbt` | Lazy process-wide state, the 65-entry hook table, the L2.7 CRT module/API whitelists, and the ordinal table for libraries that export by number. |
| `entry.mbt` | L5.3: emits a `DllMain(base, DLL_PROCESS_ATTACH, NULL)` stub and has the system call it, for images the runtime maps itself. |
| `iat.mbt` | In-process import address table patcher; also patches runtime-loaded modules, skipping Windows system DLLs except the L2.7 restricted CRT whitelist. |
| `thunks.mbt` | The Win32-compatible C ABI thunks and management exports. |
| `mapper.mbt` | Manual PE mapping, relocations, imports, protections, export lookup. |
| `bundle.mbt` | L6: v7 virtual-layer manifest reader, the backwards footer search that lets a signed bundle keep running, checksummed archive entry decoder, registry seeding and `lp_run_bundle` — the whole run lives inside the DLL. |
| `host_api.mbt` | L6: address-based bridge for the launcher: map an image, find an export, call a computed address, run an entry on a worker, read the exit code. |
| `host/main.mbt` | L6: `lpvhost.exe`, the shipping virtual launcher — maps the embedded runtime, attaches its CRT, calls `moonbit_init` and transfers to `lp_run_bundle`. |
| `runtime_wbtest.mbt` | Unit tests for the data model, L1/L2.1 VFS semantics, the PE layout reader, the hive, the entry stub, the type-library reader and the footer search (43 tests). |
| `tests/dynlib.c` | L2.2 runtime-loaded DLL whose static virtualized imports prove LoadLibrary IAT patching. |
