// L2.5 fallback-chain integrity.
//
// Every virtual-first thunk forwards a virtual miss to the real Win32 API
// through lpvirt.dll's OWN import table. That chain is only sound if lpvirt.dll
// itself is never patched: if one of its IAT slots were rewritten to one of
// our thunks, every fallback would recurse back into us (and without a
// trampoline there is no way out). L2.4's installer already skips lpvirt.dll
// and the Windows system directories; this module AUDITS that property rather
// than trusting it, by walking lpvirt.dll's live import table in this process
// and checking that no slot points at any of our exported thunks.
//
// This is a structural check, not a behavioural one: the behavioural proof
// (a virtual miss returns real OS data) is covered item by item in
// scripts/verify_fallback_chain.ps1.

///|
/// A real OS API every packaged app relies on. Used to confirm fallback target
/// addresses actually resolve in this process (a broken OS binding would
/// otherwise silently pass the IAT-walk check).
struct FallbackProbe {
  module_name : String
  api_name : String
}

///|
fn fallback_probes() -> Array[FallbackProbe] {
  [
    { module_name: "kernel32.dll", api_name: "CreateFileW", },
    { module_name: "kernel32.dll", api_name: "ReadFile", },
    { module_name: "kernel32.dll", api_name: "WriteFile", },
    { module_name: "kernel32.dll", api_name: "CloseHandle", },
    { module_name: "kernel32.dll", api_name: "CreateFileA", },
    { module_name: "advapi32.dll", api_name: "RegOpenKeyExW", },
    { module_name: "ntdll.dll", api_name: "NtCreateFile", },
    { module_name: "ntdll.dll", api_name: "NtReadFile", },
    { module_name: "kernel32.dll", api_name: "LoadLibraryA", },
  ]
}

///|
/// Is `addr` one of OUR exported thunks? Compares against every thunk in the
/// one hook table, including the ntdll and LoadLibrary entries.
fn is_one_of_our_thunks(addr : Int64) -> Bool {
  let table = hook_table()
  let mut i = 0
  while i < table.length() {
    let (_, export_name) = table[i]
    if addr != 0L && addr == thunk_address(export_name) {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// Walk the import address table of `module_base` and count how many slots
/// currently point at one of our thunks. Returns (-1) on an unreadable image.
fn count_thunk_slots(module_base : Int64) -> Int32 {
  if module_base == 0L || peek16(module_base) != 0x5a4d {
    return -1
  }
  let pe_off = peek32(module_base + 0x3cL)
  let nt = module_base + pe_off
  if peek32(nt) != 0x4550L {
    return -1
  }
  let opt = nt + 24L
  let magic = peek16(opt)
  let ptr_size = if magic == 0x20b { 8 } else { 4 }
  let dd = if magic == 0x20b { opt + 112L } else { opt + 96L }
  let import_rva = peek32(dd + 8L)
  let import_size = peek32(dd + 12L)
  if import_rva == 0L || import_size == 0L {
    return -1
  }
  let desc = module_base + import_rva
  let desc_end = desc + import_size
  let mut cur = desc
  let mut hits = 0
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
      i = i + 1
      // IAT and lookup table entries are identical after the loader resolves
      // them (both hold the function address), so reading the lookup slot is
      // equivalent to reading the live IAT slot for our purposes.
      let slot = if ptr_size == 8 {
        peek64(iat_base + step)
      } else {
        peek32(iat_base + step)
      }
      if is_one_of_our_thunks(slot) {
        hits = hits + 1
      }
    }
    cur = cur + 20L
  }
  hits
}

///|
/// Audit the fallback chain. Output layout:
///   [0] self_iat_thunk_hits  - MUST be 0 (lpvirt.dll IAT points at real APIs)
///   [1] probe_count          - number of real APIs resolved
///   [2] probe_unresolved     - MUST be 0 (every fallback target resolves)
///   [3] self_iat_status      - 0 = walked, negative = unreadable image
/// Returns 0 on success, -1 for a bad output buffer.
#export_name("lp_virt_fallback_audit")
pub fn lp_virt_fallback_audit(out : Int64, cap : Int32) -> Int32 {
  if out == 0L || cap < 16 {
    return -1
  }
  let self_mod = get_module_handle_a(cstring("lpvirt.dll"))
  let hits = count_thunk_slots(self_mod)
  let probes = fallback_probes()
  let mut unresolved = 0
  let mut resolved = 0
  let mut i = 0
  while i < probes.length() {
    let p = probes[i]
    let mod = get_module_handle_a(cstring(p.module_name))
    let addr = if mod != 0L {
      real_get_proc_address(mod, cstring(p.api_name))
    } else {
      0L
    }
    if addr == 0L {
      unresolved = unresolved + 1
    } else {
      resolved = resolved + 1
    }
    i = i + 1
  }
  poke_bytes(out, u32le(if hits < 0 { 0L } else { hits.to_int64() }), 4)
  poke_bytes(out + 4L, u32le(resolved.to_int64()), 4)
  poke_bytes(out + 8L, u32le(unresolved.to_int64()), 4)
  poke_bytes(out + 12L, u32le(hits.to_int64()), 4)
  0
}
