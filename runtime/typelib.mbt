// Type libraries that live in the archive (L5.6).
//
// A COM component that registers itself does not write registry keys itself.
// It calls `LoadTypeLibEx` on its own module, then `RegisterTypeLib`, and
// oleaut32 does the writing. The type library it registers is an `ITypeLib`
// object built from the bytes of the `TYPELIB` resource inside the DLL — and
// that is exactly what a file-less image does not have: oleaut32 can only load
// a type library from a path on disk.
//
// So the runtime reads the type library itself. This file parses the `MSFT`
// layout that MIDL emits (`MSFT` magic, then a header, a table of type-info
// records, and the GUID, name and string tables). It reads only what a
// registration needs: the library identity and version, and for each type its
// kind, GUID, name, documentation and vtable size. Method and parameter
// descriptors are deliberately not parsed — nothing in a registration reads
// them, and parsing them would be a large amount of code with no consumer.
//
// The layout is not guessed. Every offset below was checked against a typelib
// built by MIDL 8.01 and against the field layout in Wine's in-memory MSFT
// reader, and `runtime_wbtest.mbt` checks the parser against a typelib that is
// embedded in the test itself, so a wrong offset fails a test rather than
// silently registering nonsense.

///|
/// `TKIND_*` values that matter to a registration. Anything else (modules,
/// records, enums, aliases) carries no registry identity.
const TKIND_INTERFACE : Int32 = 3

///|
const TKIND_DISPATCH : Int32 = 4

///|
const TKIND_COCLASS : Int32 = 5

///|
/// One type inside a library, reduced to what a registration writes.
pub struct TypeEntry {
  kind : Int32
  guid : String
  name : String
  doc : String
  major : Int32
  minor : Int32
  c_funcs : Int32
  // Virtual-table size in bytes, including inherited slots. A registration
  // stores the slot count, which is this divided by the pointer size.
  c_vft : Int32
  c_impl : Int32
  flags : Int32
}

///|
/// A type library, reduced to what a registration writes.
pub struct TypeLibInfo {
  libid : String
  name : String
  doc : String
  major : Int32
  minor : Int32
  lcid : Int32
  syskind : Int32
  varflags : Int32
  // The library's own `flags` field, which is what a registration reports as
  // the library flags; `varflags` is a different field that mostly carries the
  // target platform.
  flags : Int32
  types : Array[TypeEntry]
}

// ------------------------------------------------------------ primitives ---

///|
fn tl_u16(d : Bytes, off : Int32) -> Int32 {
  if off < 0 || off + 2 > d.length() {
    return 0
  }
  d[off].to_int() + (d[off + 1].to_int() << 8)
}

///|
fn tl_u32(d : Bytes, off : Int32) -> Int32 {
  tl_u16(d, off) + (tl_u16(d, off + 2) << 16)
}

///|
/// A 32-bit field, read as two's complement. `Int` is 32-bit on this target, so
/// an absent offset (`0xFFFFFFFF`) arrives here as -1 and a caller can test for
/// it with a comparison instead of a mask.
fn tl_i32(d : Bytes, off : Int32) -> Int32 {
  tl_u32(d, off)
}

///|
fn tl_hex(v : Int32, digits : Int32) -> String {
  let table : Array[Char] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
  ]
  let mut out = ""
  let mut i = digits - 1
  while i >= 0 {
    out = out + String::make(1, table[(v >> (i * 4)) & 0xF])
    i = i - 1
  }
  out
}

///|
/// A GUID in registry spelling, `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`. The
/// binary form is the usual COM one: three little-endian fields then eight
/// bytes in order, so the text never matches the byte order except by accident.
fn tl_guid(d : Bytes, off : Int32) -> String {
  if off < 0 || off + 16 > d.length() {
    return ""
  }
  let mut tail = ""
  for i = 8; i < 16; i = i + 1 {
    tail = tail + tl_hex(d[off + i].to_int(), 2)
  }
  "{" +
  tl_hex(tl_u32(d, off), 8) +
  "-" +
  tl_hex(tl_u16(d, off + 4), 4) +
  "-" +
  tl_hex(tl_u16(d, off + 6), 4) +
  "-" +
  str_slice(tail, 0, 4) +
  "-" +
  str_slice(tail, 4, 16) +
  "}"
}

///|
/// A name from the name table. Each record is a one-byte length, a two-byte
/// reference, the characters, and then eight bytes the writer uses as a link.
/// Offsets are relative to the table start with one such record of slack before
/// the first one, which is measured behaviour rather than documentation: the
/// first name of every typelib sits eight bytes into the segment.
fn tl_name_at(d : Bytes, table : Int32, rel : Int32) -> String {
  if table < 0 || rel < 0 {
    return ""
  }
  let at = table + 8 + rel
  if at + 4 > d.length() {
    return ""
  }
  let n = d[at].to_int()
  if n <= 0 || n > 127 || at + 4 + n > d.length() {
    return ""
  }
  let mut out = ""
  for i = 0; i < n; i = i + 1 {
    let c = d[at + 4 + i]
    if c.to_int() >= 0x20 && c.to_int() <= 0x7E {
      out = out + String::make(1, c.to_char())
    }
  }
  out
}

///|
/// A GUID that a caller handed us as a pointer, in registry spelling.
pub fn guid_text_at(addr : Int64) -> String {
  if addr == 0L {
    return ""
  }
  let mut tail = ""
  for i = 8; i < 16; i = i + 1 {
    tail = tail + tl_hex(peek_bytes(addr + i.to_int64(), 1)[0].to_int(), 2)
  }
  "{" +
  tl_hex(peek32(addr).to_int(), 8) +
  "-" +
  tl_hex(peek16(addr + 4L), 4) +
  "-" +
  tl_hex(peek16(addr + 6L), 4) +
  "-" +
  str_slice(tail, 0, 4) +
  "-" +
  str_slice(tail, 4, 16) +
  "}"
}

///|
/// The binary form of a GUID we printed ourselves. The text is canonical
/// (`{8-4-4-4-12}`), so this is a fixed-shape parse and returns an empty buffer
/// for anything else rather than guessing.
pub fn guid_bytes(text : String) -> Bytes {
  let empty = Bytes::make(0, b'\x00')
  if text.length() != 38 ||
    text[0].to_int() != '{'.to_int() ||
    text[37].to_int() != '}'.to_int() {
    return empty
  }
  // Digits only: the four dashes are at fixed positions.
  let digits : Array[Int32] = []
  let mut i = 1
  while i < 37 {
    let c = text[i]
    if c.to_int() != '-'.to_int() {
      digits.push(tl_digit(c))
    }
    i = i + 1
  }
  if digits.length() != 32 {
    return empty
  }
  let out = FixedArray::make(16, b'\x00')
  // Three little-endian fields, then eight bytes in order.
  out[0] = (digits[6] * 16 + digits[7]).to_byte()
  out[1] = (digits[4] * 16 + digits[5]).to_byte()
  out[2] = (digits[2] * 16 + digits[3]).to_byte()
  out[3] = (digits[0] * 16 + digits[1]).to_byte()
  out[4] = (digits[10] * 16 + digits[11]).to_byte()
  out[5] = (digits[8] * 16 + digits[9]).to_byte()
  out[6] = (digits[14] * 16 + digits[15]).to_byte()
  out[7] = (digits[12] * 16 + digits[13]).to_byte()
  for k = 8; k < 16; k = k + 1 {
    out[k] = (digits[16 + (k - 8) * 2] * 16 + digits[17 + (k - 8) * 2]).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
fn tl_digit(c : UInt16) -> Int32 {
  let v = c.to_int()
  if v >= '0'.to_int() && v <= '9'.to_int() {
    v - '0'.to_int()
  } else if v >= 'A'.to_int() && v <= 'F'.to_int() {
    v - 'A'.to_int() + 10
  } else if v >= 'a'.to_int() && v <= 'f'.to_int() {
    v - 'a'.to_int() + 10
  } else {
    0
  }
}

///|
/// A documentation string. Records are a two-byte character count followed by
/// the characters, packed to a four-byte boundary; unlike a name there is no
/// slack before the first one.
fn tl_string_at(d : Bytes, table : Int32, rel : Int32) -> String {
  if table < 0 || rel < 0 {
    return ""
  }
  let at = table + rel
  if at + 2 > d.length() {
    return ""
  }
  let n = tl_u16(d, at)
  if n == 0 || n > 1024 || at + 2 + n > d.length() {
    return ""
  }
  let mut out = ""
  for i = 0; i < n; i = i + 1 {
    let c = d[at + 2 + i]
    if c.to_int() >= 0x20 && c.to_int() <= 0x7E {
      out = out + String::make(1, c.to_char())
    }
  }
  out
}

// ---------------------------------------------------------------- parsing ---

///|
/// Parse a type library in the `MSFT` layout. Returns None for anything that is
/// not one: a caller then falls through to the real API rather than answering
/// with a library it does not understand.
pub fn parse_msft(d : Bytes) -> TypeLibInfo? {
  let n = d.length()
  if n < 0x54 {
    return None
  }
  if d[0] != b'M' || d[1] != b'S' || d[2] != b'F' || d[3] != b'T' {
    return None
  }
  let count = tl_u32(d, 0x20)
  if count < 0 || count > 512 {
    return None
  }
  let varflags = tl_u32(d, 0x14)
  // The segment directory follows the header and one four-byte entry per type,
  // plus a help-DLL offset when the library has one.
  let segdir = 0x54 + count * 4 + (if (varflags & 0x100) != 0 { 4 } else { 0 })
  if segdir + 15 * 16 > n {
    return None
  }
  // Segments, in file order: type infos, imports, import files, references,
  // GUID hash, GUID table, name hash, name table, string table, …
  let ti_off = tl_i32(d, segdir)
  let guid_off = tl_i32(d, segdir + 5 * 16)
  let name_off = tl_i32(d, segdir + 7 * 16)
  let str_off = tl_i32(d, segdir + 8 * 16)
  if ti_off < 0 || guid_off < 0 {
    return None
  }
  let libid = tl_guid(d, guid_off + tl_i32(d, 0x08))
  if libid == "" {
    return None
  }
  let version = tl_u32(d, 0x18)
  let types : Array[TypeEntry] = []
  let mut i = 0
  while i < count {
    let o = ti_off + i * 100
    if o + 100 > n {
      break
    }
    let kind = tl_u32(d, o) & 0xF
    let posguid = tl_i32(d, o + 0x2C)
    let guid = if posguid < 0 { "" } else { tl_guid(d, guid_off + posguid) }
    let wanted = kind == TKIND_INTERFACE ||
      kind == TKIND_DISPATCH ||
      kind == TKIND_COCLASS
    if wanted && guid != "" {
      let elem = tl_u32(d, o + 0x18)
      let ver = tl_u32(d, o + 0x38)
      types.push({
        kind,
        guid,
        name: tl_name_at(d, name_off, tl_i32(d, o + 0x34)),
        doc: tl_string_at(d, str_off, tl_i32(d, o + 0x3C)),
        major: ver & 0xFFFF,
        minor: (ver >> 16) & 0xFFFF,
        c_funcs: elem & 0xFFFF,
        c_vft: tl_u16(d, o + 0x4E),
        c_impl: tl_u16(d, o + 0x4C),
        flags: tl_u32(d, o + 0x30),
      })
    }
    i = i + 1
  }
  Some({
    libid,
    name: tl_name_at(d, name_off, tl_i32(d, 0x38)),
    doc: tl_string_at(d, str_off, tl_i32(d, 0x24)),
    major: version & 0xFFFF,
    minor: (version >> 16) & 0xFFFF,
    lcid: tl_u32(d, 0x0C),
    syskind: varflags & 0xF,
    varflags,
    flags: tl_u32(d, 0x1C),
    types,
  })
}

// ------------------------------------------------- resource extraction ---

///|
/// Walk one resource-directory level and return the child offset of a numeric
/// id, with the subdirectory bit cleared. Named entries sort first and are
/// skipped: the type-library resource is always the numeric `RT_TYPELIB`.
fn tl_res_child(d : Bytes, base : Int32, dir_rel : Int32, id : Int32) -> Int32? {
  let dir = base + dir_rel
  if dir + 16 > d.length() {
    return None
  }
  let total = tl_u16(d, dir + 12) + tl_u16(d, dir + 14)
  let mut i = 0
  while i < total {
    let e = dir + 16 + i * 8
    let name = tl_u32(d, e)
    if (name & 0x8000_0000) == 0 && name == id {
      return Some(tl_u32(d, e + 4) & 0x7FFF_FFFF)
    }
    i = i + 1
  }
  None
}

///|
/// The first child of a directory, whatever it is named. A type library has
/// exactly one id under `RT_TYPELIB` and at least one language under that, and
/// which one is used only affects which language wins.
fn tl_res_first(d : Bytes, base : Int32, dir_rel : Int32) -> Int32? {
  let dir = base + dir_rel
  if dir + 16 > d.length() {
    return None
  }
  let total = tl_u16(d, dir + 12) + tl_u16(d, dir + 14)
  if total <= 0 {
    return None
  }
  Some(tl_u32(d, dir + 20) & 0x7FFF_FFFF)
}

///|
/// The `TYPELIB` resource of an image, in its file bytes.
fn tl_res_typelib(d : Bytes) -> Bytes? {
  let (layout, err) = parse_layout(d)
  if err != 0 {
    return None
  }
  let (rsrc_rva, rsrc_size) = dir_entry(layout, 2)
  if rsrc_rva == 0L || rsrc_size == 0L {
    return None
  }
  let base = match rva_to_file(layout, rsrc_rva) {
    Some(o) => o.to_int()
    None => return None
  }
  let type_rel = match tl_res_child(d, base, 0, 7) {
    Some(v) => v
    None => return None
  }
  let id_rel = match tl_res_first(d, base, type_rel) {
    Some(v) => v
    None => return None
  }
  let lang_rel = match tl_res_first(d, base, id_rel) {
    Some(v) => v
    None => return None
  }
  // A leaf is an IMAGE_RESOURCE_DATA_ENTRY: RVA, size, code page, reserved.
  let entry = base + lang_rel
  let rva = img_u32(d, entry.to_int64())
  let size = img_u32(d, entry.to_int64() + 4L)
  if rva == 0L || size == 0L {
    return None
  }
  let off = match rva_to_file(layout, rva) {
    Some(o) => o
    None => return None
  }
  Some(img_slice(d, off, size))
}

///|
/// A type library out of an image in the archive. A standalone `.tlb` file is
/// the type library itself; anything else is a module, and its type library is
/// the `TYPELIB` resource inside it.
pub fn typelib_from_image(d : Bytes) -> TypeLibInfo? {
  if d.length() >= 4 &&
    d[0] == b'M' &&
    d[1] == b'S' &&
    d[2] == b'F' &&
    d[3] == b'T' {
    return parse_msft(d)
  }
  match tl_res_typelib(d) {
    Some(res) => parse_msft(res)
    None => None
  }
}
