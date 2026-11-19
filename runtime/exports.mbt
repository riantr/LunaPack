// L3.1 / L3.2: ordinal imports and forwarded exports for the manual mapper.
//
// `resolve_imports` used to reject an ordinal thunk outright (MAP_ORDINAL_IMPORT)
// and `lp_get_export` returned 0 for a forwarder. Both are common in real PE
// files: the Windows API-set DLLs forward heavily, and ordinal imports appear
// in older/third-party modules. This module resolves both by reading the
// EXPORT DIRECTORY of the already-loaded provider module in this process.
//
// Everything here reads memory in OUR process with the same peek* primitives
// as the mapper. No GetProcAddress-by-ordinal binding is needed (MoonBit allows
// only one extern per C symbol), so we parse the provider's export table
// directly: ordinal -> AddressOfFunctions[ordinal - Base].

///|
const IMAGE_DIRECTORY_ENTRY_EXPORT : Int32 = 0

// --- pure decoding helpers (white-box tested) ---

///|
/// The ordinal of a PE32+ ordinal thunk is its low 16 bits; the high bit marks
/// it as an ordinal. `entry` is the raw 64-bit import lookup entry.
fn ordinal_from_thunk(entry : Int64) -> Int32 {
  (entry & 0xffffL).to_int()
}

///|
/// A forwarder string has the form "DLLNAME.ExportName" or "DLLNAME.#ordinal".
/// Split at the LAST dot so DLL names containing dots (api-ms-win-core-*) are
/// handled. Returns (dll_name, export_part); export_part keeps a leading '#'
/// for ordinal forwarders.
fn forwarder_parts(s : String) -> (String, String)? {
  let mut dot = -1
  let mut i = 0
  while i < s.length() {
    if s[i] == '.' {
      dot = i
    }
    i = i + 1
  }
  if dot <= 0 || dot == s.length() - 1 {
    return None
  }
  Some((str_slice(s, 0, dot), str_slice(s, dot + 1, s.length())))
}

///|
/// Is a function RVA a forwarder? A forwarder RVA points INSIDE the export
/// directory range, where the bytes are an ASCII "DLL.Export" string.
fn is_forwarder_rva(
  rva : Int64,
  export_rva : Int64,
  export_size : Int64,
) -> Bool {
  export_size > 0L && rva >= export_rva && rva < export_rva + export_size
}

// --- in-memory export directory reader ---

///|
/// Locate a loaded module's export directory. Returns (base, export_rva,
/// export_size, num_functions, address_of_functions, ordinal_base) or None.
fn loaded_export_dir(
  handle : Int64,
) -> (Int64, Int64, Int64, Int64, Int64, Int64)? {
  if handle == 0L || peek16(handle) != 0x5a4d {
    return None
  }
  let pe_off = peek32(handle + 0x3cL)
  let nt = handle + pe_off
  if peek32(nt) != 0x4550L {
    return None
  }
  let opt = nt + 24L
  let magic = peek16(opt)
  // PE32+ directories start at opt+112; PE32 at opt+96.
  let dd = if magic == 0x20b { opt + 112L } else { opt + 96L }
  let export_rva = peek32(dd)
  let export_size = peek32(dd + 4L)
  if export_rva == 0L || export_size == 0L {
    return None
  }
  let ed = handle + export_rva
  let ordinal_base = peek32(ed + 16L)
  let num_functions = peek32(ed + 20L)
  let address_of_functions = peek32(ed + 28L)
  Some(
    (
      handle, export_rva, export_size, num_functions, address_of_functions, ordinal_base,
    ),
  )
}

///|
/// Resolve an export by ordinal from a loaded module. Returns the absolute
/// address, or 0 when the ordinal is out of range. Recurses through forwarders
/// with a depth bound to avoid cycles.
fn export_by_ordinal_depth(
  handle : Int64,
  ordinal : Int32,
  depth : Int32,
) -> Int64 {
  if depth > 8 {
    return 0L
  }
  let dir = match loaded_export_dir(handle) {
    Some(d) => d
    None => return 0L
  }
  let (base, export_rva, export_size, num_funcs, funcs, ord_base) = dir
  let idx = ordinal.to_int64() - ord_base
  if idx < 0L || idx >= num_funcs {
    return 0L
  }
  let function_rva = peek32(base + funcs + idx * 4L)
  if function_rva == 0L {
    return 0L
  }
  if is_forwarder_rva(function_rva, export_rva, export_size) {
    let fwd = ascii_at(base + function_rva, 256)
    return resolve_forwarder(fwd, depth + 1)
  }
  base + function_rva
}

///|
/// Resolve an export by name from a loaded module (used for forwarders).
fn export_by_name_depth(handle : Int64, name : String, depth : Int32) -> Int64 {
  if depth > 8 || handle == 0L {
    return 0L
  }
  let dir = match loaded_export_dir(handle) {
    Some(d) => d
    None => return 0L
  }
  let (base, export_rva, export_size, _, _, _) = dir
  // Re-read the name pointer table / ordinal table (ed offsets 32 and 36).
  let pe_off = peek32(base + 0x3cL)
  let ed = base + export_rva
  ignore(pe_off)
  let num_names = peek32(ed + 24L)
  let functions = peek32(ed + 28L)
  let names = peek32(ed + 32L)
  let ordinals = peek32(ed + 36L)
  let mut i = 0L
  while i < num_names {
    let name_rva = peek32(base + names + i * 4L)
    if ascii_at(base + name_rva, 256) == name {
      let ord = peek16(base + ordinals + i * 2L).to_int64()
      let frva = peek32(base + functions + ord * 4L)
      if is_forwarder_rva(frva, export_rva, export_size) {
        return resolve_forwarder(ascii_at(base + frva, 256), depth + 1)
      }
      return base + frva
    }
    i = i + 1L
  }
  0L
}

///|
/// Parse an ASCII decimal ordinal (digits only). Returns -1 on any non-digit.
fn parse_decimal(s : String) -> Int32 {
  if s.length() == 0 {
    return -1
  }
  let mut v = 0
  let mut i = 0
  while i < s.length() {
    let c = s[i]
    if c < '0' || c > '9' {
      return -1
    }
    v = v * 10 + (c.to_int() - '0'.to_int())
    i = i + 1
  }
  v
}

///|
/// Resolve a forwarder string such as "NTDLL.RtlAllocateHeap" or
/// "api-ms-win-core-x-l1-1-0.#42".
fn resolve_forwarder(fwd : String, depth : Int32) -> Int64 {
  let parts = match forwarder_parts(fwd) {
    Some(p) => p
    None => return 0L
  }
  let (dll_name, export_part) = parts
  let mut dll_with_ext = dll_name
  if !dll_with_ext.has_suffix(".dll") && !dll_with_ext.has_suffix(".DLL") {
    dll_with_ext = dll_with_ext + ".dll"
  }
  let handle = load_library_a(cstring(dll_with_ext))
  if handle == 0L {
    return 0L
  }
  if export_part.has_prefix("#") {
    let ord = parse_decimal(str_slice(export_part, 1, export_part.length()))
    if ord < 0 {
      0L
    } else {
      export_by_ordinal_depth(handle, ord, depth)
    }
  } else {
    export_by_name_depth(handle, export_part, depth)
  }
}

///|
/// Public entry used by the mapper: resolve an import by ordinal from the
/// provider module, including forwarded exports.
fn resolve_import_ordinal(handle : Int64, ordinal : Int32) -> Int64 {
  export_by_ordinal_depth(handle, ordinal, 0)
}
