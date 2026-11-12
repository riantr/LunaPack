// A minimal PE (Portable Executable) reader.
//
// Only what is needed to pull resources out of a Windows executable: the
// section table, the resource directory and the resource payloads.

///|
/// A parsed PE image.
pub struct PeFile {
  /// The whole file.
  data : Bytes
  /// Sections as (virtual_address, virtual_size, raw_pointer, raw_size).
  sections : Array[(Int64, Int64, Int64, Int64)]
  /// RVA and size of the resource directory, (0, 0) when there is none.
  resource_rva : Int64
  resource_size : Int64
}

///|
fn u16_at(data : Bytes, off : Int64) -> Int32 {
  let i = off.to_int()
  data.at(i).to_int() | (data.at(i + 1).to_int() << 8)
}

///|
fn u32_at(data : Bytes, off : Int64) -> Int64 {
  let i = off.to_int()
  data.at(i).to_int64() |
  (data.at(i + 1).to_int64() << 8) |
  (data.at(i + 2).to_int64() << 16) |
  (data.at(i + 3).to_int64() << 24)
}

///|
/// Does `data` hold the `PE\0\0` signature at `pe_off`?
///
/// An MZ header alone is not a PE image. The DOS stub of a program that is
/// not a PE file is arbitrary bytes, and reading a subsystem out of them
/// would let a file that is not an executable decide whether the bundle
/// opens a console window.
fn has_pe_signature(data : Bytes, pe_off : Int64) -> Bool {
  if pe_off + 4 > data.length().to_int64() {
    return false
  }
  let i = pe_off.to_int()
  data.at(i).to_int() == 'P'.to_int() &&
  data.at(i + 1).to_int() == 'E'.to_int() &&
  data.at(i + 2).to_int() == 0 &&
  data.at(i + 3).to_int() == 0
}

///|
/// Parse the headers of a PE image.
pub fn parse_pe(data : Bytes) -> PeFile raise {
  if data.length() < 0x40 {
    fail("not a PE file (too small)")
  }
  if data.at(0).to_int() != 'M'.to_int() || data.at(1).to_int() != 'Z'.to_int() {
    fail("not a PE file (no MZ header)")
  }
  let pe_off = u32_at(data, 0x3c)
  if pe_off + 24 > data.length().to_int64() {
    fail("not a PE file (bad header offset)")
  }
  if !has_pe_signature(data, pe_off) {
    fail("not a PE file (no PE signature)")
  }
  let coff = pe_off + 4
  let num_sections = u16_at(data, coff + 2)
  let opt_size = u16_at(data, coff + 16).to_int64()
  let opt = coff + 20
  let magic = u16_at(data, opt).to_int64()
  // The data directory starts after the fixed part of the optional header.
  let dir_base = if magic == 0x20b { opt + 112 } else { opt + 96 }
  if dir_base + 24 > data.length().to_int64() {
    fail("not a PE file (truncated optional header)")
  }
  let resource_rva = u32_at(data, dir_base + 16)
  let resource_size = u32_at(data, dir_base + 20)
  let section_table = opt + opt_size
  let sections = []
  let mut i = 0
  while i < num_sections {
    let off = section_table + (i * 40).to_int64()
    if off + 40 > data.length().to_int64() {
      fail("not a PE file (truncated section table)")
    }
    sections.push(
      (
        u32_at(data, off + 12),
        u32_at(data, off + 8),
        u32_at(data, off + 20),
        u32_at(data, off + 16),
      ),
    )
    i = i + 1
  }
  { data, sections, resource_rva, resource_size, }
}

///|
/// Translate a relative virtual address into a file offset.
fn rva_to_offset(pe : PeFile, rva : Int64) -> Int64 raise {
  for s in pe.sections {
    let (vaddr, vsize, raw_ptr, raw_size) = s
    let span = if vsize > raw_size { vsize } else { raw_size }
    if rva >= vaddr && rva < vaddr + span {
      return raw_ptr + (rva - vaddr)
    }
  }
  fail("RVA is not inside any section")
}

///|
/// The entries of one resource directory level.
///
/// Every entry is (id, offset), where the offset points either at a nested
/// directory or at a data entry, depending on the level.
fn dir_entries(
  pe : PeFile,
  base : Int64,
  dir_off : Int64,
) -> Array[(Int64, Int64)] {
  let out = []
  let count = u16_at(pe.data, base + dir_off + 12) +
    u16_at(pe.data, base + dir_off + 14)
  let mut i = 0
  while i < count {
    let off = base + dir_off + 16 + (i * 8).to_int64()
    let name = u32_at(pe.data, off) & 0x7fffffff
    let target = u32_at(pe.data, off + 4) & 0x7fffffff
    out.push((name, target))
    i = i + 1
  }
  out
}

///|
/// Look up one entry of a resource directory level by id.
fn find_dir_entry(
  pe : PeFile,
  base : Int64,
  dir_off : Int64,
  want : Int64,
) -> Int64? {
  for e in dir_entries(pe, base, dir_off) {
    if e.0 == want {
      return Some(e.1)
    }
  }
  None
}

///|
/// The first entry of a resource directory level, as (id, offset).
fn first_dir_entry(
  pe : PeFile,
  base : Int64,
  dir_off : Int64,
) -> (Int64, Int64)? {
  let entries = dir_entries(pe, base, dir_off)
  if entries.length() == 0 {
    return None
  }
  Some(entries[0])
}

///|
/// The payload of a resource, as (offset in the file, size in bytes).
///
/// `rtype` and `name` are the numeric resource type and name, `lang` the
/// language id; use 0 for the first match and a negative `name` to accept the
/// first entry of that type.
pub fn find_resource(
  pe : PeFile,
  rtype : Int64,
  name : Int64,
  lang : Int64,
) -> (Int64, Int64)? raise {
  if pe.resource_rva == 0 {
    return None
  }
  let base = rva_to_offset(pe, pe.resource_rva)
  let type_dir = match find_dir_entry(pe, base, 0, rtype) {
    Some(t) => t
    None => return None
  }
  let name_dir = if name < 0 {
    match first_dir_entry(pe, base, type_dir) {
      Some((_, off)) => off
      None => return None
    }
  } else {
    match find_dir_entry(pe, base, type_dir, name) {
      Some(n) => n
      None => return None
    }
  }
  // The language level: take the requested one, or the first entry.
  let lang_entry = if lang == 0 {
    let entries = dir_entries(pe, base, name_dir)
    if entries.length() == 0 {
      return None
    }
    entries[0].1
  } else {
    match find_dir_entry(pe, base, name_dir, lang) {
      Some(l) => l
      None => return None
    }
  }
  // The language level points at the data entry.
  let data_entry = base + lang_entry
  let rva = u32_at(pe.data, data_entry)
  let size = u32_at(pe.data, data_entry + 4)
  let off = rva_to_offset(pe, rva)
  Some((off, size))
}

///|
/// Read `size` bytes at `off` from the image.
pub fn read_at(pe : PeFile, off : Int64, size : Int64) -> Bytes {
  let start = off.to_int()
  let len = size.to_int()
  let arr = []
  let mut i = 0
  while i < len {
    arr.push(pe.data.at((start + i : Int32)))
    i = i + 1
  }
  Bytes::from_array(arr)
}

///|
/// Resource type ids used by the icon resources.
pub const RT_ICON : Int64 = 3

///|
pub const RT_GROUP_ICON : Int64 = 14

///|
/// The icon of a PE image.
///
/// Returns the id of the group icon, the group icon itself and every icon it
/// references, or None when the image carries no icon.
pub fn extract_icon(
  pe : PeFile,
) -> (Int64, Bytes, Array[(Int64, Bytes)])? raise {
  // The group icon is not necessarily stored under id 1; .NET applications
  // often use a high id such as 32512.
  let group = match find_resource(pe, RT_GROUP_ICON, -1, 0) {
    Some(g) => g
    None => return None
  }
  let group_data = read_at(pe, group.0, group.1)
  // GRPICONDIR: reserved(2), type(2), count(2), then count entries of 14 bytes.
  if group_data.length() < 6 {
    return None
  }
  let count = u16_at(group_data, 4)
  let icons = []
  let mut i = 0
  while i < count {
    let off = (6 + i * 14).to_int64()
    if off + 14 > group_data.length().to_int64() {
      break
    }
    // The last two bytes of the entry hold the icon id.
    let id = u16_at(group_data, off + 12).to_int64()
    match find_resource(pe, RT_ICON, id, 0) {
      Some(r) => icons.push((id, read_at(pe, r.0, r.1)))
      None => ()
    }
    i = i + 1
  }
  if icons.length() == 0 {
    return None
  }
  // Recover the id the group icon is stored under.
  let base = rva_to_offset(pe, pe.resource_rva)
  let group_id = match find_dir_entry(pe, base, 0, RT_GROUP_ICON) {
    Some(t) =>
      match first_dir_entry(pe, base, t) {
        Some((id, _)) => id
        None => 1
      }
    None => 1
  }
  Some((group_id, group_data, icons))
}

///|
/// The subsystem of a windowed application.
pub const PE_SUBSYSTEM_GUI : Int32 = 2

///|
/// The subsystem of a console application.
pub const PE_SUBSYSTEM_CUI : Int32 = 3

///|
/// The offset of the subsystem field in the optional header of a PE image.
///
/// The value is at offset 68 of the optional header, in PE32 as well as in
/// PE32+. 2 means a windowed application, 3 a console one.
pub const PE_SUBSYSTEM_OFFSET : Int64 = 68

///|
/// The subsystem of a PE image, or 0 when it is not one.
///
/// The value decides whether Windows opens a console window for the
/// process, so a bundle has to carry the subsystem of the program it
/// carries: a windowed program that is bundled must not flash a console
/// window when it is started.
pub fn pe_subsystem(data : Bytes) -> Int32 {
  if data.length() < 0x40 {
    return 0
  }
  if data.at(0).to_int() != 'M'.to_int() || data.at(1).to_int() != 'Z'.to_int() {
    return 0
  }
  let pe_off = u32_at(data, 0x3c)
  // The optional header starts 24 bytes after the PE signature, and the
  // subsystem sits 68 bytes into it.
  let opt = pe_off + 24
  if opt + PE_SUBSYSTEM_OFFSET + 2 > data.length().to_int64() {
    return 0
  }
  if !has_pe_signature(data, pe_off) {
    return 0
  }
  u16_at(data, opt + PE_SUBSYSTEM_OFFSET)
}

///|
/// The subsystem of the PE image at `path`, or 0 when it is not one.
pub async fn pe_subsystem_of(path : String) -> Int32 {
  let data = @fs.read_binary(path) catch { _ => return 0 }
  pe_subsystem(data)
}

// ---------------------------------------------------------------- imports ---

///|
/// The offset of the data directory in the optional header of a PE image.
///
/// The directory is a list of (RVA, size) pairs, one per kind of table the
/// image carries: the exports, the imports, the resources, the delay-loaded
/// imports and so on. Where it starts depends on the kind of image, so it
/// is worked out from the magic number of the optional header.
fn data_dir_base(data : Bytes) -> Int64 {
  if data.length() < 0x40 {
    return 0
  }
  let pe_off = u32_at(data, 0x3c)
  // The optional header starts 24 bytes after the PE signature.
  let opt = pe_off + 24
  if opt + 96 > data.length().to_int64() {
    return 0
  }
  let magic = u16_at(data, opt).to_int64()
  if magic == 0x20b {
    opt + 112
  } else {
    opt + 96
  }
}

///|
/// How many entries the data directory of a PE image has.
fn data_dir_count(data : Bytes) -> Int32 {
  let base = data_dir_base(data)
  if base < 4 {
    return 0
  }
  u32_at(data, base - 4).to_int()
}

///|
/// The RVA and the size of the data directory entry at `index`.
///
/// The entry is (0, 0) when the image does not carry that kind of table.
fn data_dir(data : Bytes, index : Int32) -> (Int64, Int64) {
  if index >= data_dir_count(data) {
    return (0, 0)
  }
  let base = data_dir_base(data)
  let off = base + (index * 8).to_int64()
  if off + 8 > data.length().to_int64() {
    return (0, 0)
  }
  (u32_at(data, off), u32_at(data, off + 4))
}

///|
/// The name that starts at `off` and ends at the byte that closes it.
fn cstr_at(pe : PeFile, off : Int64) -> String {
  let limit = pe.data.length().to_int64()
  let mut end = off
  while end < limit && pe.data.at(end.to_int()) != 0 {
    end = end + 1
  }
  utf8_bytes_to_string(read_at(pe, off, end - off))
}

///|
/// The name of the library that the import descriptor at `name_rva` names,
/// or None when the image does not carry that name.
fn import_name_at(pe : PeFile, name_rva : Int64) -> String? {
  let off = rva_to_offset(pe, name_rva) catch { _ => return None }
  Some(cstr_at(pe, off))
}

///|
/// The names of the DLLs that a PE image imports.
///
/// The import directory is a list of descriptors, one per library, and every
/// descriptor names the library it is about. The list ends with a descriptor
/// that is all zeroes, and an image that imports nothing has no directory at
/// all.
///
/// A file that is not a PE image imports nothing, and so does a file whose
/// import directory does not make sense: the names that cannot be read are
/// left out rather than guessed at.
pub fn pe_import_dlls(data : Bytes) -> Array[String] {
  let pe = parse_pe(data) catch { _ => return [] }
  let (rva, _size) = data_dir(data, 1)
  if rva == 0 {
    return []
  }
  let mut off = rva_to_offset(pe, rva) catch { _ => return [] }
  let limit = data.length().to_int64()
  let out = []
  while off + 20 <= limit {
    // The name of the library is the fourth field of the descriptor.
    let name_rva = u32_at(data, off + 12)
    if name_rva == 0 {
      break
    }
    match import_name_at(pe, name_rva) {
      Some(n) => out.push(n)
      None => break
    }
    off = off + 20
  }
  out
}

///|
/// The names of the DLLs that a PE image loads with delay loading.
///
/// A program that loads a library later, when it needs it, writes the name
/// into the delay-load directory instead of the import directory. Such a
/// program cannot start without the library either, so its names are read as
/// well.
pub fn pe_delay_import_dlls(data : Bytes) -> Array[String] {
  let pe = parse_pe(data) catch { _ => return [] }
  let (rva, _size) = data_dir(data, 13)
  if rva == 0 {
    return []
  }
  let mut off = rva_to_offset(pe, rva) catch { _ => return [] }
  let limit = data.length().to_int64()
  let out = []
  while off + 32 <= limit {
    // The name of the library is the second field of the descriptor.
    let name_rva = u32_at(data, off + 4)
    if name_rva == 0 {
      break
    }
    match import_name_at(pe, name_rva) {
      Some(n) => out.push(n)
      None => break
    }
    off = off + 32
  }
  out
}

///|
/// Set the subsystem of the PE image at `path`.
///
/// The value decides whether Windows opens a console window for the
/// process. A bundle has to carry the subsystem of the program it carries,
/// because the bundle is what Windows starts: a windowed program that is
/// bundled into a console bundle flashes a console window on every start.
///
/// The change is written in place, at the offset of the field, and the
/// file keeps its size.
pub async fn set_pe_subsystem(path : String, subsystem : Int32) -> Bool {
  if subsystem != PE_SUBSYSTEM_GUI && subsystem != PE_SUBSYSTEM_CUI {
    return false
  }
  let data = @fs.read_binary(path) catch { _ => return false }
  if pe_subsystem(data) == 0 {
    return false
  }
  let pe_off = u32_at(data, 0x3c)
  let opt = pe_off + 24
  let at = opt + PE_SUBSYSTEM_OFFSET
  if at + 2 > data.length().to_int64() {
    return false
  }
  // The field is written directly: the file keeps its size and its
  // layout, and only two bytes change.
  let out = @fs.open(path, mode=@fs.Mode::ReadWrite)
  defer out.close()
  let bytes = FixedArray::make(2, b'\x00')
  bytes[0] = (subsystem & 0xff).to_byte()
  bytes[1] = ((subsystem >> 8) & 0xff).to_byte()
  out.write_at(Bytes::from_array(bytes[:]), position=at)
  true
}
