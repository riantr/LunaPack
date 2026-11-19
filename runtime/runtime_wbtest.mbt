// Whitebox tests for the pure data model and the PE layout reader. No Win32
// calls are made from a test: the mapper's memory work is exercised by the
// end-to-end harness in runtime/tests/.

///|
test "paths normalize separators, case, trailing slash and duplicates" {
  assert_true(norm_path("C:\\Virt\\Hello.TXT") == "c:/virt/hello.txt")
  assert_true(norm_path("c:/virt/") == "c:/virt")
  assert_true(norm_path("C:/VIRT//x") == "c:/virt/x")
  // L1.4: extended-length and UNC prefixes are stripped to a canonical form.
  assert_true(norm_path("\\\\?\\C:\\Virt\\Hello.TXT") == "c:/virt/hello.txt")
  assert_true(norm_path("\\\\?\\UNC\\server\\share\\f") == "//server/share/f")
  assert_true(norm_path("c:/virt/a/../b/./c") == "c:/virt/b/c")
}

///|
test "a virtual file opens, reads, reports size and closes" {
  let v = Vfs::new()
  v.add_file("C:\\virt\\hello.txt", ascii_bytes("virtual-hello"))
  let h = v.open("c:/VIRT/hello.txt").unwrap()
  assert_true(v.size(h).unwrap() == 13L)
  let first = v.read(h, 7).unwrap()
  assert_true(first.length() == 7)
  assert_true(bytes_to_ascii(first) == "virtual")
  let rest = v.read(h, 100).unwrap()
  assert_true(rest.length() == 6)
  assert_true(v.read(h, 100).unwrap().length() == 0)
  assert_true(v.close(h))
  assert_true(!v.close(h))
}

///|
test "unknown paths have no attributes and no handle" {
  let v = Vfs::new()
  v.add_file("c:/virt/a.txt", Bytes::make(3, b'a'))
  assert_true(v.open("c:/virt/missing.txt") is None)
  assert_true(v.attributes("c:/virt/a.txt") == FILE_ATTRIBUTE_NORMAL)
  assert_true(v.attributes("c:/virt") == FILE_ATTRIBUTE_DIRECTORY)
  assert_true(v.attributes("c:/virt/nope") == -1)
}

///|
test "directory enumeration is memory-only and honours a wildcard" {
  let v = Vfs::new()
  v.add_file("c:/virt/a.txt", Bytes::make(1, b'a'))
  v.add_file("c:/virt/b.txt", Bytes::make(1, b'b'))
  v.add_file("c:/virt/c.dat", Bytes::make(1, b'c'))
  v.add_file("c:/other/d.txt", Bytes::make(1, b'd'))
  match v.find_first("c:/virt/*.txt") {
    None => assert_true(false)
    Some((h, first)) => {
      assert_true(first == "a.txt" || first == "b.txt")
      let mut count = 1
      let mut more = v.find_next(h)
      while (match more {
              Some(_) => true
              None => false
            }) {
        count = count + 1
        more = v.find_next(h)
      }
      assert_true(count == 2)
      assert_true(v.find_next(h) is None)
      assert_true(v.close_find(h))
    }
  }
  assert_true(v.find_first("c:/virt/*.exe") is None)
}

///|
test "HKLM writes land in the virtual hive and need no real registry" {
  let r = VirtualRegistry::new()
  let product = utf16le_no_nul("LunaPack")
  assert_true(
    r.set_value(-2147483646L, "SOFTWARE\\LunaPack", "Product", REG_SZ, product),
  )
  let h = r.open_key(0x80000002L, "software/lunapack").unwrap()
  let got = r.query_value(h, "PRODUCT").unwrap()
  assert_true(got.typ == REG_SZ)
  let decoded = @utf16.decode(got.data) catch { _ => "" }
  assert_true(decoded == "LunaPack")
  assert_true(r.close_key(h))
  assert_true(r.query_value(h, "Product") is None)
}

///|
test "a DWORD value and a missing key behave like the Win32 contract" {
  let r = VirtualRegistry::new()
  ignore(
    r.set_value(0x80000001L, "Software\\Demo", "Version", REG_DWORD, u32le(42L)),
  )
  let h = r.open_key(0x80000001L, "Software\\Demo").unwrap()
  let v = r.query_value(h, "version").unwrap()
  assert_true(v.typ == REG_DWORD)
  assert_true(le_u32(v.data, 0) == 42L)
  assert_true(r.query_value(h, "absent") is None)
  assert_true(r.open_key(0x80000002L, "Software\\NotVirtual") is None)
}

// ----------------------------------------------------------------- L1 VFS ---

///|
test "L1.1 CREATE_ALWAYS truncates, CREATE_NEW refuses, OPEN_ALWAYS creates" {
  let v = Vfs::new()
  v.add_file("c:/cfg/app.ini", ascii_bytes("old"))
  // OPEN_EXISTING on a real virtual file.
  match v.create_file("c:/cfg/app.ini", 0x80000000, OPEN_EXISTING) {
    Opened(h) => {
      assert_true(v.read(h, 100).unwrap() == b"old")
      ignore(v.close(h))
    }
    _ => assert_true(false)
  }
  // CREATE_ALWAYS truncates the existing file to zero.
  match v.create_file("c:/cfg/app.ini", 0x40000000, CREATE_ALWAYS) {
    Opened(h) => {
      assert_true(v.size(h).unwrap() == 0L)
      ignore(v.close(h))
    }
    _ => assert_true(false)
  }
  // CREATE_NEW on an existing virtual file fails with ERROR_FILE_EXISTS.
  match v.create_file("c:/cfg/app.ini", 0x40000000, CREATE_NEW) {
    Failed(code) => assert_true(code == 80)
    _ => assert_true(false)
  }
  // OPEN_ALWAYS creates a new file under a seeded virtual directory.
  match v.create_file("c:/cfg/new.ini", 0x40000000, OPEN_ALWAYS) {
    Opened(h) => {
      assert_true(v.size(h).unwrap() == 0L)
      ignore(v.close(h))
    }
    _ => assert_true(false)
  }
  // A path outside any virtual root falls through (no in-memory create).
  match v.create_file("d:/real/file.txt", 0x40000000, CREATE_ALWAYS) {
    NotVirtual => ()
    _ => assert_true(false)
  }
}

///|
test "L1.1 writes extend the file and respect access and attributes" {
  let v = Vfs::new()
  v.add_file("c:/data/log.txt", ascii_bytes("abc"))
  match v.create_file("c:/data/log.txt", 0x40000000, OPEN_EXISTING) {
    Opened(h) => {
      // Seek to the end so the write extends "abc" into "abcDEF".
      assert_true(v.seek(h, 0L, FILE_END).unwrap() == 3L)
      assert_true(v.write_at(h, ascii_bytes("DEF"), None).unwrap() == 3)
      assert_true(v.size(h).unwrap() == 6L)
      assert_true(v.seek(h, 0L, FILE_BEGIN).unwrap() == 0L)
      assert_true(bytes_to_ascii(v.read(h, 100).unwrap()) == "abcDEF")
      ignore(v.close(h))
    }
    _ => assert_true(false)
  }
  // A read-only handle cannot write.
  match v.create_file("c:/data/log.txt", 0x80000000, OPEN_EXISTING) {
    Opened(h) => {
      assert_true(v.write_at(h, ascii_bytes("x"), None) is None)
      ignore(v.close(h))
    }
    _ => assert_true(false)
  }
  // A file with the READONLY attribute refuses a write-capable open.
  assert_true(v.set_meta("c:/data/log.txt", 0x1, 1L, 2L, 3L))
  match v.create_file("c:/data/log.txt", 0x40000000, OPEN_EXISTING) {
    Failed(code) => assert_true(code == 5)
    _ => assert_true(false)
  }
}

///|
test "L1.2 positioned write and read via OVERLAPPED offsets" {
  let v = Vfs::new()
  v.add_file("c:/data/random.bin", Bytes::make(8, b'x'))
  let h = match v.create_file("c:/data/random.bin", 0x40000000, OPEN_EXISTING) {
    Opened(x) => x
    _ => return assert_true(false)
  }
  assert_true(v.write_at(h, ascii_bytes("AB"), Some(4L)).unwrap() == 2)
  assert_true(v.seek(h, 0L, FILE_BEGIN).unwrap() == 0L)
  assert_true(bytes_to_ascii(v.read(h, 100).unwrap()) == "xxxxABxx")
  // A positioned read does not advance the handle pointer: after the full
  // read above the pointer is at 8, and stays there after read_at.
  assert_true(bytes_to_ascii(v.read_at(h, 2, 2L).unwrap()) == "xx")
  assert_true(v.read(h, 2).unwrap().length() == 0)
  assert_true(v.seek(h, 4L, FILE_BEGIN).unwrap() == 4L)
  assert_true(bytes_to_ascii(v.read(h, 2).unwrap()) == "AB")
  ignore(v.close(h))
}

///|
test "L1.2 SetFilePointerEx honours BEGIN, CURRENT, END and rejects negatives" {
  let v = Vfs::new()
  v.add_file("c:/data/seek.bin", ascii_bytes("0123456789"))
  let h = match v.create_file("c:/data/seek.bin", 0x80000000, OPEN_EXISTING) {
    Opened(x) => x
    _ => return assert_true(false)
  }
  assert_true(v.seek(h, 3L, FILE_BEGIN).unwrap() == 3L)
  assert_true(v.seek(h, 2L, FILE_CURRENT).unwrap() == 5L)
  assert_true(v.seek(h, -1L, FILE_END).unwrap() == 9L)
  assert_true(bytes_to_ascii(v.read(h, 1).unwrap()) == "9")
  assert_true(v.seek(h, -20L, FILE_BEGIN) is None)
  assert_true(v.seek(h, 0L, 99) is None)
  ignore(v.close(h))
}

///|
test "L1.2 delete and rename move bytes and follow open handles" {
  let v = Vfs::new()
  v.add_file("c:/data/a.txt", ascii_bytes("payload"))
  let h = match v.create_file("c:/data/a.txt", 0x80000000, OPEN_EXISTING) {
    Opened(x) => x
    _ => return assert_true(false)
  }
  assert_true(v.rename_file("c:/data/a.txt", "c:/data/b.txt"))
  // The open handle now reads through the new path.
  ignore(v.seek(h, 0L, FILE_BEGIN))
  assert_true(bytes_to_ascii(v.read(h, 100).unwrap()) == "payload")
  assert_true(v.attributes("c:/data/a.txt") == -1)
  assert_true(v.attributes("c:/data/b.txt") == FILE_ATTRIBUTE_NORMAL)
  assert_true(v.delete_file("c:/data/b.txt"))
  assert_true(v.attributes("c:/data/b.txt") == -1)
  assert_true(!v.delete_file("c:/data/b.txt"))
  assert_true(!v.delete_file("d:/real/nope.txt"))
  ignore(v.close(h))
}

///|
test "L1.5 metadata: stable file ID, attributes and FILETIMEs in FileInfo" {
  let v = Vfs::new()
  v.add_file("c:/meta/f.txt", ascii_bytes("1234"))
  assert_true(v.set_meta("c:/meta/f.txt", 0x20, 100L, 200L, 300L))
  let h = match v.create_file("c:/meta/f.txt", 0x80000000, OPEN_EXISTING) {
    Opened(x) => x
    _ => return assert_true(false)
  }
  let fi = v.file_info(h).unwrap()
  assert_true(fi.size == 4L)
  assert_true(fi.attrs == 0x20)
  assert_true(fi.created == 100L)
  assert_true(fi.accessed == 200L)
  assert_true(fi.written == 300L)
  assert_true(fi.links == 1)
  assert_true(fi.file_id > 0L)
  let pi = v.path_info("c:/meta/f.txt").unwrap()
  assert_true(pi.file_id == fi.file_id)
  assert_true(v.path_info("c:/meta/missing.txt") is None)
  let pi_dir = v.path_info("c:/meta").unwrap()
  assert_true(pi_dir.attrs == FILE_ATTRIBUTE_DIRECTORY)
  ignore(v.close(h))
}

///|
test "L1.4 relative paths, CWD and short-name aliases resolve to canonical" {
  let v = Vfs::new()
  v.add_file("c:/proj/config/settings.ini", ascii_bytes("k=v"))
  v.set_cwd("c:/proj")
  assert_true(v.attributes(".\\config\\settings.ini") == FILE_ATTRIBUTE_NORMAL)
  assert_true(v.attributes("config/settings.ini") == FILE_ATTRIBUTE_NORMAL)
  v.add_alias("c:/progra~1", "c:/program files")
  v.add_file("c:/program files/app/data.bin", ascii_bytes("d"))
  assert_true(v.attributes("C:/PROGRA~1/app/data.bin") == FILE_ATTRIBUTE_NORMAL)
  // Auto-generated 8.3 alias for a long name.
  v.add_file("c:/longname/longfilename.txt", ascii_bytes("z"))
  assert_true(v.attributes("c:/longname/longfi~1.txt") == FILE_ATTRIBUTE_NORMAL)
}

///|
test "L1.3 completion queue drains FIFO and reports remaining count" {
  let v = Vfs::new()
  v.post_completion(11L, 4L, 0x1000L)
  v.post_completion(22L, 8L, 0x2000L)
  let c1 = v.take_completion().unwrap()
  assert_true(c1.key == 11L && c1.bytes == 4L && c1.overlapped == 0x1000L)
  let c2 = v.take_completion().unwrap()
  assert_true(c2.key == 22L && c2.bytes == 8L)
  assert_true(v.take_completion() is None)
}

// ------------------------------------------------------------------- L2.1 ---

///|
test "L2.1 narrow ASCII paths normalize like their wide counterparts" {
  // The ANSI thunks feed ansi_to_string() into the same VFS entry points as
  // the wide thunks. Only the string source differs, so canonicalization must
  // be identical for narrow ASCII input.
  let v = Vfs::new()
  v.add_file("C:\\Virt\\ansi.txt", ascii_bytes("ANSI"))
  assert_true(v.attributes("c:\\virt\\ansi.txt") == 0x80)
  assert_true(v.attributes("C:/VIRT/ANSI.TXT") == 0x80)
  assert_true(v.find_first("c:\\virt\\*").unwrap().1 == "ansi.txt")
}

///|
test "L2.1 ANSI create, rename and delete use the virtual tree" {
  let v = Vfs::new()
  v.add_file("c:\\cfg\\seed.txt", ascii_bytes("S"))
  match v.create_file("C:\\cfg\\new.txt", 0x40000000, 2) {
    Opened(h) => {
      assert_true(v.write_at(h, ascii_bytes("N"), None).unwrap() == 1)
      ignore(v.close(h))
    }
    Failed(_) => assert_true(false)
    NotVirtual => assert_true(false)
  }
  assert_true(v.attributes("c:\\cfg\\new.txt") == 0x80)
  assert_true(v.rename_file("c:\\cfg\\new.txt", "c:\\cfg\\renamed.txt"))
  assert_true(v.delete_file("c:\\cfg\\renamed.txt"))
  assert_true(v.attributes("c:\\cfg\\renamed.txt") == -1)
}

///|
test "L2.1 virtual temp path defaults empty and can be seeded" {
  let v = Vfs::new()
  assert_true(v.temp_path == "")
  v.temp_path = "c:\\virt\\tmp"
  assert_true(v.temp_path == "c:\\virt\\tmp")
  // reset produces a fresh VFS with no temp override.
  let fresh = Vfs::new()
  assert_true(fresh.temp_path == "")
}

// ------------------------------------------------------------- PE layout ---

///|
fn u16le(v : Int64) -> Bytes {
  let a = FixedArray::make(2, b'\x00')
  a[0] = (v & 255L).to_byte()
  a[1] = ((v >> 8) & 255L).to_byte()
  Bytes::from_array(a[:])
}

///|
fn put(d : FixedArray[Byte], off : Int32, b : Bytes) -> Unit {
  for i = 0; i < b.length(); i = i + 1 {
    d[off + i] = b[i]
  }
}

///|
/// A well-formed but empty PE32+ image with one executable section.
fn synthetic_pe() -> Bytes {
  let d = FixedArray::make(1024, b'\x00')
  d[0] = b'M'
  d[1] = b'Z'
  put(d, 0x3c, u32le(0x80L))
  d[0x80] = b'P'
  d[0x81] = b'E'
  put(d, 0x84, u16le(MACHINE_AMD64))
  put(d, 0x86, u16le(1L))
  put(d, 0x94, u16le(0xf0L))
  let opt = 0x98
  put(d, opt, u16le(PE32PLUS_MAGIC))
  put(d, opt + 16, u32le(0x1000L))
  put(d, opt + 24, u64le(0x180000000L))
  put(d, opt + 56, u32le(0x4000L))
  put(d, opt + 60, u32le(0x200L))
  put(d, opt + 108, u32le(16L))
  put(d, opt + 112 + 8, u32le(0x2000L))
  put(d, opt + 112 + 12, u32le(0x100L))
  let sec = opt + 0xf0
  put(d, sec + 8, u32le(0x100L))
  put(d, sec + 12, u32le(0x2000L))
  put(d, sec + 16, u32le(0x200L))
  put(d, sec + 20, u32le(0x200L))
  put(d, sec + 36, u32le(0x60000020L))
  Bytes::from_array(d[:])
}

///|
test "the PE layout reader accepts a PE32+ image and reads its directory" {
  let (layout, status) = parse_layout(synthetic_pe())
  assert_true(status == MAP_OK)
  assert_true(layout.image_base == 0x180000000L)
  assert_true(layout.size_of_image == 0x4000L)
  assert_true(layout.size_of_headers == 0x200L)
  assert_true(layout.num_sections == 1L)
  assert_true(layout.entry_rva == 0x1000L)
  let (rva, size) = dir_entry(layout, IMAGE_DIRECTORY_ENTRY_IMPORT)
  assert_true(rva == 0x2000L)
  assert_true(size == 0x100L)
}

///|
test "RVA translation covers headers, sections and nothing else" {
  let (layout, _) = parse_layout(synthetic_pe())
  assert_true(rva_to_file(layout, 0x100L) is Some(0x100L))
  assert_true(rva_to_file(layout, 0x2000L) is Some(0x200L))
  assert_true(rva_to_file(layout, 0x2050L) is Some(0x250L))
  assert_true(rva_to_file(layout, 0x9000L) is None)
}

///|
test "a truncated or non-x64 image is refused with a specific reason" {
  assert_true(parse_layout(Bytes::make(64, b'\x00')).1 == MAP_BAD_MZ)
  let no_sig = synthetic_pe()
  let a = FixedArray::make(no_sig.length(), b'\x00')
  for i = 0; i < no_sig.length(); i = i + 1 {
    a[i] = no_sig[i]
  }
  a[0x80] = b'X'
  assert_true(parse_layout(Bytes::from_array(a[:])).1 == MAP_BAD_PE)
  let b = FixedArray::make(no_sig.length(), b'\x00')
  for i = 0; i < no_sig.length(); i = i + 1 {
    b[i] = no_sig[i]
  }
  put(b, 0x84, u16le(0x14cL))
  assert_true(parse_layout(Bytes::from_array(b[:])).1 == MAP_NOT_X64)
}

///|
test "file-image reads are bounds checked and NUL terminated" {
  let d = synthetic_pe()
  assert_true(img_u16(d, 0x84L) == MACHINE_AMD64)
  assert_true(img_u32(d, 0x3cL) == 0x80L)
  assert_true(img_u16(d, 4000L) == 0L)
  assert_true(img_u32(d, 4000L) == 0L)
  assert_true(img_slice(d, 0L, 2L) == b"MZ")
  assert_true(img_slice(d, 0L, 2000L).length() == 0)
  assert_true(img_cstr(d, 0x200L, 8L).length() <= 8)
}

// --- L2.3: ntdll-boundary path/disposition helpers (pure; no Win32 calls) ---

///|
test "NT object-name prefixes are stripped before VFS resolution" {
  assert_true(
    nt_strip_prefix("\\??\\C:\\virt\\hello.txt") == "C:\\virt\\hello.txt",
  )
  assert_true(
    nt_strip_prefix("\\DosDevices\\C:\\virt\\hello.txt") ==
    "C:\\virt\\hello.txt",
  )
  assert_true(nt_strip_prefix("\\\\?\\C:\\virt\\a.txt") == "C:\\virt\\a.txt")
  assert_true(nt_strip_prefix("\\\\.\\C:\\virt\\a.txt") == "C:\\virt\\a.txt")
  assert_true(nt_strip_prefix("C:\\virt\\plain.txt") == "C:\\virt\\plain.txt")
}

///|
test "NT create dispositions map to Win32 dispositions" {
  assert_true(nt_disposition(FILE_SUPERSEDE) == CREATE_ALWAYS)
  assert_true(nt_disposition(FILE_OPEN) == OPEN_EXISTING)
  assert_true(nt_disposition(FILE_CREATE) == CREATE_NEW)
  assert_true(nt_disposition(FILE_OPEN_IF) == OPEN_ALWAYS)
  assert_true(nt_disposition(FILE_OVERWRITE) == TRUNCATE_EXISTING)
  assert_true(nt_disposition(FILE_OVERWRITE_IF) == CREATE_ALWAYS)
  assert_true(nt_disposition(99) == OPEN_EXISTING)
}

// --- L2.4: attach/detach lifecycle guard (pure over g_runtime state) ---

///|
test "detach-before-unmap guard tracks attach then detach" {
  g_runtime.attach_bases = []
  g_runtime.detach_bases = []
  note_attach(0x180001000L)
  assert_true(detach_missing(0x180001000L))
  note_detach(0x180001000L)
  assert_true(!detach_missing(0x180001000L))
  // duplicate notes are idempotent
  note_attach(0x180001000L)
  note_detach(0x180001000L)
  assert_true(g_runtime.attach_bases.length() == 1)
  assert_true(g_runtime.detach_bases.length() == 1)
  // an unattached image is never "missing detach"
  assert_true(!detach_missing(0xdeadbeefL))
  g_runtime.attach_bases = []
  g_runtime.detach_bases = []
}

// --- L3.1 / L3.2: ordinal + forwarder decoding (pure helpers) ---

///|
test "ordinal imports decode the low 16 bits of a PE32+ thunk" {
  assert_true(ordinal_from_thunk(0x8000000000000005L) == 5)
  assert_true(ordinal_from_thunk(0x80000000000000f0L) == 240)
  assert_true(ordinal_from_thunk(0x0000000080000001L) == 1)
}

///|
test "forwarder strings split at the last dot (API-set names included)" {
  assert_true(
    forwarder_parts("NTDLL.RtlAllocateHeap") ==
    Some(("NTDLL", "RtlAllocateHeap")),
  )
  assert_true(
    forwarder_parts("api-ms-win-core-x-l1-1-0.#42") ==
    Some(("api-ms-win-core-x-l1-1-0", "#42")),
  )
  assert_true(
    forwarder_parts("KERNEL32.HeapFree") == Some(("KERNEL32", "HeapFree")),
  )
  assert_true(forwarder_parts("nodll") == None)
  assert_true(forwarder_parts(".empty") == None)
  assert_true(forwarder_parts("trailing.") == None)
}

///|
test "decimal ordinal parsing accepts digits only" {
  assert_true(parse_decimal("42") == 42)
  assert_true(parse_decimal("0") == 0)
  assert_true(parse_decimal("1234") == 1234)
  assert_true(parse_decimal("12x") == -1)
  assert_true(parse_decimal("") == -1)
}

///|
test "a forwarder RVA lies inside the export directory range" {
  assert_true(is_forwarder_rva(0x2100L, 0x2000L, 0x200L))
  assert_true(!is_forwarder_rva(0x3000L, 0x2000L, 0x200L))
  assert_true(!is_forwarder_rva(0x2100L, 0x2000L, 0L))
}

// --- L3.3 / L3.4: delay-import / TLS / exception directory readers ---

///|
/// Build a synthetic PE32+ with a 0x600-byte file and one section whose RVA
/// 0x2000 maps to file 0x200. The three directories point into that section:
///   exception @ 0x2100 (3 RUNTIME_FUNCTION = 36 bytes)
///   TLS       @ 0x2140 (40 bytes)
///   delay imp @ 0x2200 (one 32-byte descriptor + 32-byte terminator)
fn synthetic_pe_features() -> Bytes {
  let d = FixedArray::make(0x600, b'\x00')
  d[0] = b'M'
  d[1] = b'Z'
  put(d, 0x3c, u32le(0x80L))
  d[0x80] = b'P'
  d[0x81] = b'E'
  put(d, 0x84, u16le(MACHINE_AMD64))
  put(d, 0x86, u16le(1L))
  put(d, 0x94, u16le(0xf0L))
  let opt = 0x98
  put(d, opt, u16le(PE32PLUS_MAGIC))
  put(d, opt + 16, u32le(0x1000L))
  put(d, opt + 24, u64le(0x180000000L))
  put(d, opt + 56, u32le(0x4000L))
  put(d, opt + 60, u32le(0x200L))
  put(d, opt + 108, u32le(16L))
  let dir_base = opt + 112
  put(d, dir_base + 3 * 8, u32le(0x2100L))
  put(d, dir_base + 3 * 8 + 4, u32le(36L))
  put(d, dir_base + 9 * 8, u32le(0x2140L))
  put(d, dir_base + 9 * 8 + 4, u32le(40L))
  put(d, dir_base + 13 * 8, u32le(0x2200L))
  put(d, dir_base + 13 * 8 + 4, u32le(64L))
  let sec = opt + 0xf0
  put(d, sec + 8, u32le(0x400L))
  put(d, sec + 12, u32le(0x2000L))
  put(d, sec + 16, u32le(0x400L))
  put(d, sec + 20, u32le(0x200L))
  put(d, sec + 36, u32le(0x60000020L))
  // one delay descriptor: rvaDLLName -> "x.dll" at rva 0x2300 (file 0x500)
  // and rvaIAT = 0x2400. The second 32-byte slot stays zero (terminator).
  put(d, 0x400, u32le(1L)) // grAttrs = dlattrRva
  put(d, 0x404, u32le(0x2300L)) // rvaDLLName
  put(d, 0x40c, u32le(0x2400L)) // rvaIAT
  put(d, 0x410, u32le(0x2410L)) // rvaINT
  put(d, 0x500, b"x.dll\x00")
  Bytes::from_array(d[:])
}

///|
test "L3.3 delay-import descriptors are counted (terminator aware)" {
  let (feat, st1) = parse_layout(synthetic_pe_features())
  assert_true(st1 == MAP_OK)
  assert_true(delay_import_count(feat) == 1)
  let (plain, _) = parse_layout(synthetic_pe())
  assert_true(delay_import_count(plain) == 0)
}

///|
test "L3.4 TLS and exception directory readers detect declared dirs" {
  let (feat, _) = parse_layout(synthetic_pe_features())
  assert_true(has_tls_directory(feat))
  assert_true(eh_function_count(feat) == 3)
  let (plain, _) = parse_layout(synthetic_pe())
  assert_true(!has_tls_directory(plain))
  assert_true(eh_function_count(plain) == 0)
}

// --- L4.2: virtual tree serialization round-trip ---

///|
test "a blob round-trips files, metadata, directories and the registry" {
  let a = Vfs::new()
  let ra = VirtualRegistry::new()
  a.add_file("C:/virt/hello.txt", ascii_bytes("CHILD-VIRTUAL-FS-OK"))
  a.add_file("C:/virt/sub/note.txt", ascii_bytes("note"))
  a.set_cwd("C:/virt")
  a.temp_path = "C:/virt/tmp"
  a.add_alias("C:/virt/HELLO~1.TXT", "C:/virt/hello.txt")
  ignore(
    ra.set_value(
      0x80000002L,
      "Software/LunaPack",
      "Name",
      1,
      ascii_bytes("LunaPack"),
    ),
  )
  ignore(ra.set_value(0x80000002L, "Software/LunaPack", "Count", 4, u32le(7L)))

  let blob = a.export_blob(ra)
  assert_true(blob.length() > 16)

  let b = Vfs::new()
  let rb = VirtualRegistry::new()
  assert_true(b.import_blob(rb, blob))
  // whatever normalization produced, the round trip preserves it exactly
  assert_true(b.cwd == a.cwd)
  assert_true(b.temp_path == a.temp_path)
  match b.open("C:/virt/hello.txt") {
    Some(h) =>
      match b.read(h, 64) {
        Some(d) => assert_true(bytes_to_ascii(d) == "CHILD-VIRTUAL-FS-OK")
        None => assert_true(false)
      }
    None => assert_true(false)
  }
  assert_true(b.path_info("C:/virt/sub/note.txt") is Some(_))
  // metadata survives: same number of entries, and they are still writable
  let bm = b.meta.to_array()
  assert_true(bm.length() == a.meta.to_array().length())
  assert_true(bm[0].1.writable)
  // every alias survives, key and target
  let aa = a.aliases.to_array()
  assert_true(aa.length() > 0)
  for i = 0; i < aa.length(); i = i + 1 {
    let (short, long) = aa[i]
    assert_true(b.aliases.get(short) == Some(long))
  }
  // registry values survive with their type
  match rb.open_key(0x80000002L, "Software/LunaPack") {
    Some(k) =>
      match rb.query_value(k, "Name") {
        Some(v) => {
          assert_true(v.typ == 1)
          assert_true(bytes_to_ascii(v.data) == "LunaPack")
        }
        None => assert_true(false)
      }
    None => assert_true(false)
  }
}

///|
test "a damaged blob is refused and leaves the tree alone" {
  let a = Vfs::new()
  a.add_file("C:/virt/keep.txt", ascii_bytes("keep"))
  let blob = a.export_blob(VirtualRegistry::new())
  let short = bytes_slice(blob, 0, blob.length() - 5)
  let b = Vfs::new()
  b.add_file("C:/other/mine.txt", ascii_bytes("mine"))
  assert_true(!b.import_blob(VirtualRegistry::new(), short))
  // the destination was not touched
  assert_true(b.path_info("C:/other/mine.txt") is Some(_))
  assert_true(b.path_info("C:/virt/keep.txt") is None)
  // a blob with the wrong magic is refused too
  assert_true(
    !b.import_blob(
      VirtualRegistry::new(),
      ascii_bytes("not a lunapack blob at all"),
    ),
  )
}

///|
test "a component registration lands in the hive, and HKCR answers" {
  let r = VirtualRegistry::new()
  let clsid = "CLSID\\{9B1F0A4C-2D3E-4A55-8F01-112233445566}"
  let dll = utf16le("C:/virt/com_server.dll")
  assert_true(
    r.set_value(HKEY_CLASSES_ROOT, clsid + "\\InprocServer32", "", REG_SZ, dll),
  )
  // Opening the class key through HKCR finds it.
  let h = r.open_key(HKEY_CLASSES_ROOT, clsid)
  assert_true(h is Some(_))
  // The same key reached through the machine classes subtree is the same key.
  let via_machine = r.open_key(
    HKEY_LOCAL_MACHINE,
    "Software\\Classes\\" + clsid,
  )
  assert_true(via_machine is Some(_))
  match r.read_value(HKEY_CLASSES_ROOT, clsid + "\\InprocServer32", "") {
    Some(v) => {
      // REG_SZ is stored as UTF-16LE, so the payload is the same bytes the
      // component wrote.
      assert_true(v.typ == REG_SZ)
      assert_true(v.data.length() == dll.length())
      assert_true(v.data[0] == b'C')
      assert_true(v.data[1] == b'\x00')
    }
    None => assert_true(false)
  }
  // Enumeration reports the class as one subkey of CLSID.
  let clsid_key = r.open_key(HKEY_CLASSES_ROOT, "CLSID")
  match clsid_key {
    Some(k) => {
      assert_true(
        r.enum_key(k, 0) == Some("{9b1f0a4c-2d3e-4a55-8f01-112233445566}"),
      )
      assert_true(r.enum_key(k, 1) is None)
      match r.info(k) {
        Some((n_sub, _m_key, _n_val, _m_name, _m_data)) =>
          assert_true(n_sub == 1)
        None => assert_true(false)
      }
    }
    None => assert_true(false)
  }
  // Unregister removes the class and everything under it.
  assert_true(r.delete_key(HKEY_CLASSES_ROOT, clsid))
  assert_true(r.open_key(HKEY_CLASSES_ROOT, clsid) is None)
  assert_true(
    r.read_value(HKEY_CLASSES_ROOT, clsid + "\\InprocServer32", "") is None,
  )
}

///|
test "creating a class key through HKCR is claimed and counted" {
  let r = VirtualRegistry::new()
  let clsid = "CLSID\\{9B1F0A4C-2D3E-4A55-8F01-112233445566}"
  assert_true(r.claims(HKEY_CLASSES_ROOT, clsid))
  match r.create_key(HKEY_CLASSES_ROOT, clsid) {
    Some((h, existed)) => {
      assert_true(!existed)
      assert_true(r.calls_create == 1)
      assert_true(r.handles.contains(h))
      // A second create reports the key as already there.
      match r.create_key(HKEY_CLASSES_ROOT, clsid) {
        Some((_, again)) => assert_true(again)
        None => assert_true(false)
      }
    }
    None => assert_true(false)
  }
}

///|
test "a mapped image reports its virtual path through GetModuleFileNameW" {
  let base = 0x1234_5678L
  let path = "C:\\virt\\com_server_crt.dll"
  assert_true(mapped_path_of(base) is None)
  note_mapped_image(base, path)
  assert_true(mapped_path_of(base) == Some(path))
  // The image is now one the GetProcAddress and GetModuleFileName thunks answer
  // for, which is what makes a self-registering component work.
  assert_true(is_mapped_image(base))

  let cap = 260
  let buf = virtual_alloc(
    0L,
    (cap * 2).to_int64(),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE,
  )
  assert_true(buf != 0L)
  let n = thunk_get_module_file_name_w(base, buf, cap)
  // The reported count is characters, without the terminator.
  assert_true(n == path.length())
  assert_true(wide_to_string(buf) == path)

  // A buffer that cannot hold the path returns the buffer size, writes no
  // terminator past the end, and reports why.
  let tiny = virtual_alloc(0L, 16L, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
  assert_true(tiny != 0L)
  assert_true(write_module_path(path, tiny, 8) == 8)

  // A base the loader owns is not in the map, so the thunk does not answer for
  // it: the caller is sent back to the real API instead of getting a guess.
  assert_true(mapped_path_of(0x7ff0_0000_0000L) is None)
  ignore(virtual_free(buf, 0L, MEM_RELEASE))
  ignore(virtual_free(tiny, 0L, MEM_RELEASE))
}

///|
test "the entry stub encodes the DllMain call it documents" {
  let code = entry_stub_code()
  assert_true(code.length() == 39)
  // sub rsp, 28h
  assert_true(code[0] == b'\x48' && code[1] == b'\x83' && code[3] == b'\x28')
  // mov rcx, imm64 -- the base goes in at offset 6
  assert_true(code[4] == b'\x48' && code[5] == b'\xb9')
  // mov edx, 1 (DLL_PROCESS_ATTACH)
  assert_true(code[14] == b'\xba' && code[15] == b'\x01')
  // xor r8d, r8d -- lpReserved = NULL
  assert_true(code[19] == b'\x45' && code[21] == b'\xc0')
  // mov rax, imm64 -- the entry point goes in at offset 24
  assert_true(code[22] == b'\x48' && code[23] == b'\xb8')
  // call rax / add rsp, 28h / ret
  assert_true(code[32] == b'\xff' && code[33] == b'\xd0')
  assert_true(code[38] == b'\xc3')
  // An image with no entry point is skipped rather than called.
  assert_true(run_entry_point(0x1000L, 0L) == 0)
}
