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

Twelve Win32 entry points are hooked:

```
CreateFileW  ReadFile  CloseHandle  GetFileAttributesW  GetFileSizeEx
FindFirstFileW  FindNextFileW
RegOpenKeyExW  RegQueryValueExW  RegSetValueExW  RegCloseKey
GetProcAddress
```

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
the two C test doubles in `tests/`, and runs the end-to-end demo. `-Consume`
deletes `payload.dll` from disk **after reading its bytes but before mapping
them**, which is the zero-disk proof. `-SkipDemo` stops after the link.

The C files in `tests/` are throwaway harnesses, not product code. They exist
because a consumer that believes it is an ordinary Windows program cannot be
written in MoonBit. Everything that ships is `*.mbt`.

`moonbit_init` must be called before any other export: the MoonBit runtime
inside a DLL is not initialized by the OS loader.

## Exports

| Export | Purpose |
| --- | --- |
| `moonbit_init` | Initialize the MoonBit runtime. Call first. |
| `lp_virt_reset` | Clear the VFS, hive and counters. |
| `lp_virt_add_file` | Register a virtual file (UTF-16 path + bytes). |
| `lp_virt_set_reg` | Seed a virtual registry value (root + subkey + name). |
| `lp_virt_stats` | Six counters: creates, reads, fall-throughs, reg queries, patched slots, dynamic hits. |
| `lp_install_iat_hooks` | Patch the 12 IAT slots of an image base. Works for loaded and manually mapped images. |
| `lp_map_image` | Manually map a PE32+ DLL from a byte array. Returns the image base, or 0. |
| `lp_map_error` | Why the last map failed (one of the `MAP_*` constants). |
| `lp_get_export` | Address of a named export of a mapped image. |
| `lp_get_entry` | Address of DllMain of a mapped image. |
| `lp_unmap_image` | Release the private pages of a mapped image. |
| `lp_*_w` / `lp_*` | The 12 Win32 thunks. |

## Limits — read these before treating this as production code

- **x64 PE32+ only.** x86 images, PE32 images and ARM64 are refused with
  `MAP_NOT_X64`. Building a matching 32-bit runtime is still open work.
- **No ordinal imports.** `GetProcAddress` is declared once with a borrowed
  byte buffer, so an import by ordinal returns `MAP_ORDINAL_IMPORT`. Ordinary
  MSVC-produced DLLs import by name.
- **No forwarded exports**, no delay imports, no TLS callbacks, no exception
  directory registration, no SEH unwinding for code in the mapped image.
- **The OS loader is not involved.** `GetModuleHandle("payload.dll")` returns
  NULL, the image is absent from the module list, and neither DllMain nor TLS
  callbacks run automatically. The host must call DllMain itself using
  `lp_get_entry`, and must call it with `DLL_PROCESS_DETACH` before
  `lp_unmap_image` — otherwise the statically linked CRT leaves onexit
  handlers pointing into freed memory and the process crashes at exit.
- **VFS is a read-only snapshot.** No writes, no directory handle semantics
  beyond enumeration, no overlapping or asynchronous I/O, no reparse points.
- **IAT hooking only.** Inline hooks, ntdll-level interception and direct
  syscalls are not covered.
- **AV behaviour is measured, not assumed.** On the development machine
  (Huorong), the P0 remote-injection experiment was quarantined 11 times as
  `HVM:Trojan/Injector.gen!A`; this in-process runtime, including the manual
  mapper, produced no new quarantine entries. Other engines, unsigned
  binaries and signed binaries may behave differently. Re-test every new
  mechanism on a machine with security software enabled.
- **Not wired into the CLI yet.** No command in `LunaPack.exe` uses this DLL;
  there is no archive format for virtual files yet, and the release workflow
  ships `lpvirt.dll` as an experimental asset only.

## Source map

| File | Contents |
| --- | --- |
| `mem.mbt` | Raw in-process memory reads/writes, PE integer helpers, ASCII/UTF-16 conversion. |
| `vfs.mbt` | In-memory filesystem, handles, enumeration, path normalization. |
| `registry.mbt` | In-memory registry hive, HKLM/HKCU redirection. |
| `state.mbt` | Lazy process-wide state and the hook table. |
| `iat.mbt` | In-process import address table patcher. |
| `thunks.mbt` | The 12 Win32-compatible C ABI thunks and management exports. |
| `mapper.mbt` | Manual PE mapping, relocations, imports, protections, export lookup. |
| `runtime_wbtest.mbt` | Unit tests for the data model and the PE layout reader. |
