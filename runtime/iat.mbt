// In-process IAT hooking.
//
// We walk the import descriptors of a module that is already loaded INTO THIS
// PROCESS and replace selected import address table slots with the addresses
// of our own exported thunks. This is the low-profile alternative to a remote
// injection: no OpenProcess, no VirtualAllocEx, no WriteProcessMemory, no
// CreateRemoteThread. The only memory we write is the target module's own
// IAT, made writable with VirtualProtect and restored immediately after.

///|
const PAGE_READWRITE : Int32 = 0x04

///|
fn patch_slot(addr : Int64, value : Int64, ptr_size : Int32) -> Bool {
  let old = Bytes::make(4, b'\x00')
  if virtual_protect(addr, ptr_size.to_int64(), PAGE_READWRITE, old) == 0 {
    return false
  }
  let saved = le_u32(old, 0)
  if ptr_size == 8 {
    poke64(addr, value)
  } else {
    poke_bytes(addr, u32le(value), 4)
  }
  let scratch = Bytes::make(4, b'\x00')
  ignore(virtual_protect(addr, ptr_size.to_int64(), saved.to_int(), scratch))
  true
}

///|
/// Rewrite the IAT of `module_base`. Returns the number of slots patched.
fn patch_imports(module_base : Int64) -> Int32 {
  if module_base == 0L || peek16(module_base) != 0x5a4d {
    return 0
  }
  let pe_off = peek32(module_base + 0x3CL)
  let nt = module_base + pe_off
  if peek32(nt) != 0x4550L {
    return 0
  }
  let opt = nt + 24L
  let magic = peek16(opt)
  let ptr_size = if magic == 0x20b { 8 } else { 4 }
  // Data directory entry 1 is the import table; each entry is 8 bytes.
  let dd = if magic == 0x20b { opt + 112L } else { opt + 96L }
  let import_rva = peek32(dd + 8L)
  let import_size = peek32(dd + 12L)
  if import_rva == 0L || import_size == 0L {
    return 0
  }
  let desc = module_base + import_rva
  let desc_end = desc + import_size
  let mut cur = desc
  let mut patched = 0
  while cur < desc_end {
    let orig = peek32(cur)
    let first = peek32(cur + 16L)
    if orig == 0L && first == 0L {
      break
    }
    let lookup_base = module_base + (if orig != 0L { orig } else { first })
    let iat_base = module_base + first
    let mut i = 0
    while i < 4096 {
      let step = (i * ptr_size).to_int64()
      let entry = if ptr_size == 8 {
        peek64(lookup_base + step)
      } else {
        peek32(lookup_base + step)
      }
      if entry == 0L {
        break
      }
      // A set high bit means an ordinal import, which has no name to match.
      let by_name = if ptr_size == 8 {
        entry >= 0L
      } else {
        (entry & 0x80000000L) == 0L
      }
      if by_name {
        let name_rva = entry & 0xFFFFFFFFL
        let api = ascii_at(module_base + name_rva + 2L, 128)
        match lookup_thunk(api) {
          Some(thunk_name) => {
            let target = thunk_address(thunk_name)
            if target != 0L && patch_slot(iat_base + step, target, ptr_size) {
              patched = patched + 1
            }
          }
          None => ()
        }
      }
      i = i + 1
    }
    cur = cur + 20L
  }
  patched
}

///|
/// L2.4: the single installer used for every image, whether it was manually
/// mapped into private pages or brought in by the OS loader. Both paths funnel
/// through `patch_imports` and the one `hook_table()`; the only difference is
/// whether the module is eligible for patching. A manually mapped image is an
/// application image by construction and has no file path, so it skips the
/// guard. A loader-loaded module is checked against lpvirt.dll itself and the
/// Windows system directories before its IAT is touched.
fn eligible_for_patch(module_base : Int64, guard_system : Bool) -> Bool {
  if module_base == 0L || peek16(module_base) != 0x5a4d {
    return false
  }
  if !guard_system {
    return true
  }
  let self_mod = get_module_handle_a(cstring("lpvirt.dll"))
  if module_base == self_mod {
    return false
  }
  // Windows system DLLs must never be patched. The OS loader resolves API-set
  // dependencies through LoadLibraryExW during startup; rewriting such a DLL's
  // own LoadLibrary slot makes its internal calls re-enter our thunk and recurse
  // until the stack overflows (observed on the CRT target). Only application
  // modules get their IATs rewritten.
  let path_buf = Bytes::make(520, b'\x00')
  let got = get_module_file_name_a(module_base, path_buf, 520)
  if got > 0 {
    let path = bytes_to_ascii(path_buf).to_lower()
    if path.contains("\\windows\\system32\\") ||
      path.contains("\\windows\\syswow64\\") ||
      path.contains("\\windows\\winsxs\\") ||
      path.contains("\\windows\\systemapps\\") {
      return false
    }
  }
  true
}

///|
/// The one hook installer. `guard_system` distinguishes the two call sites;
/// `accumulate` selects replace (first mapped image) vs add (runtime loads).
/// Both L2.4 callers share this body so the mapped-image and LoadLibrary paths
/// can never drift onto different hook tables.
fn install_hooks(
  module_base : Int64,
  guard_system : Bool,
  accumulate : Bool,
) -> Int32 {
  if !eligible_for_patch(module_base, guard_system) {
    return 0
  }
  let n = patch_imports(module_base)
  if n > 0 {
    if accumulate {
      g_runtime.patched_count = g_runtime.patched_count + n
    } else {
      g_runtime.patched_count = n
    }
  }
  n
}

///|
/// Install the hooks into an already-loaded module. `module_base` is an
/// HMODULE in this process, obtained by the host with GetModuleHandleA/W, or a
/// base returned by lp_map_image. This is the single public installer for both
/// manually mapped and loader-loaded images (L2.4).
#export_name("lp_install_iat_hooks")
pub fn install_iat_hooks(module_base : Int64) -> Int32 {
  let n = install_hooks(module_base, false, false)
  if n > 0 {
    g_runtime.mapped_hook_count = g_runtime.mapped_hook_count + 1
  }
  n
}

///|
/// Patch a module the target loaded at runtime (L2.2). Same installer as the
/// mapped-image path; the system/lpvirt guard is the only difference. Its
/// imports are the unwrapped real Win32 references used for fall-through, so
/// patching them would send every fallback back into our own thunks.
fn patch_loaded_module(hmod : Int64) -> Int32 {
  let n = install_hooks(hmod, true, true)
  if n > 0 {
    g_runtime.loaded_hook_count = g_runtime.loaded_hook_count + 1
  }
  n
}
