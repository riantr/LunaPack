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
/// Install the hooks into an already-loaded module. `module_base` is an
/// HMODULE in this process, obtained by the host with GetModuleHandleA/W.
#export_name("lp_install_iat_hooks")
pub fn install_iat_hooks(module_base : Int64) -> Int32 {
  let n = patch_imports(module_base)
  g_runtime.patched_count = n
  n
}
