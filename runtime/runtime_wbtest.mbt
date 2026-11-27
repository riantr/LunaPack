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
test "L2.6 SearchPath resolves an absolute virtual file to an openable path" {
  let v = Vfs::new()
  v.add_file("C:\\virt\\hello.txt", ascii_bytes("VIRTUAL-FS-OK"))
  match v.search_virtual("", "C:\\virt\\hello.txt", "") {
    Some(p) => {
      assert_true(p == "C:\\virt\\hello.txt")
      // The string SearchPath returns must work on the way back into CreateFileW.
      assert_true(v.attributes(p) == FILE_ATTRIBUTE_NORMAL)
    }
    None => assert_true(false)
  }
  assert_true(v.search_virtual("", "C:\\virt\\missing.txt", "") is None)
}

///|
test "L2.6 SearchPath honours the path list, extension and virtual CWD" {
  let v = Vfs::new()
  v.add_file("c:/bin/tool.exe", Bytes::make(2, b'x'))
  v.add_file("c:/work/tool.exe", Bytes::make(2, b'y'))
  v.add_file("c:/work/data.txt", Bytes::make(2, b'z'))
  v.set_cwd("C:\\work")
  // The explicit lpPath list wins over the CWD copy.
  assert_true(
    v.search_virtual("c:/nowhere;c:/bin", "tool", ".exe").unwrap() ==
    "C:\\bin\\tool.exe",
  )
  assert_true(
    v.search_virtual("", "data.txt", "").unwrap() == "C:\\work\\data.txt",
  )
  assert_true(v.search_virtual("c:/nowhere", "tool.exe", "") is None)
}

///|
test "L2.6 hook table registers both SearchPath forms" {
  let mut count = 0
  let mut wide = false
  let mut ansi = false
  for pair in hook_table() {
    let (name, _) = pair
    count = count + 1
    if name == "SearchPathW" {
      wide = true
    }
    if name == "SearchPathA" {
      ansi = true
    }
  }
  assert_true(count == 65)
  assert_true(wide)
  assert_true(ansi)
  assert_true(
    lookup_thunk("GetFullPathNameW").unwrap() == "lp_get_full_path_name_w",
  )
  assert_true(
    lookup_thunk("GetFullPathNameA").unwrap() == "lp_get_full_path_name_a",
  )
  assert_true(
    lookup_thunk("FindFirstFileExW").unwrap() == "lp_find_first_file_ex_w",
  )
}

///|
test "L2.8 GetFullPathName canonicalizes virtual paths only" {
  let v = Vfs::new()
  v.add_file("C:\\virt\\hello.txt", ascii_bytes("VIRTUAL-FS-OK"))
  v.set_cwd("C:\\work")
  assert_true(v.full_path("c:/virt/./hello.txt") == Some("C:\\virt\\hello.txt"))
  // An owned directory is canonicalized too, even before a file is added under it.
  assert_true(v.full_path("C:\\virt") == Some("C:\\virt"))
  // A host path must reach the real API so relative paths keep the real CWD.
  assert_true(v.full_path("C:\\Windows\\System32\\cmd.exe") is None)
  assert_true(v.full_path("") is None)
}

///|
test "L2.7 CRT whitelist names the two CRT modules only" {
  let mods = crt_module_whitelist()
  assert_true(mods.length() == 2)
  assert_true(mods[0] == "ucrtbase.dll")
  assert_true(mods[1] == "msvcrt.dll")
  // The leaf is matched, not the directory: GetModuleFileNameA answers with a
  // full path even when the module was loaded by short name.
  assert_true(is_crt_module("c:\\windows\\system32\\ucrtbase.dll"))
  assert_true(is_crt_module("C:/Windows/System32/MSVCRT.DLL"))
  assert_true(!is_crt_module("c:\\windows\\system32\\kernel32.dll"))
  assert_true(!is_crt_module("c:\\windows\\system32\\ucrtbase2.dll"))
  // Matching is by leaf name, not directory: an app that ships its own CRT is
  // still a CRT, and GetModuleHandleA resolves by leaf name too.
}

///|
test "L2.7 CRT API whitelist is file I/O only" {
  let apis = crt_api_whitelist()
  for
    name in [
      "CreateFileW", "CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "GetFileSizeEx",
      "GetFileType", "SetFilePointerEx", "GetFileAttributesW", "GetFileAttributesExW",
      "FindFirstFileW", "FindFirstFileExW", "FindNextFileW", "SearchPathW", "SearchPathA",
      "GetFullPathNameW", "GetFullPathNameA",
    ] {
    assert_true(string_in(apis, name))
  }
  // Touching any of these inside a CRT DLL risks loader re-entry, so they must
  // stay outside the restricted set even though they are in hook_table().
  for
    name in [
      "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW", "GetProcAddress", "ExitProcess",
      "CreateProcessW", "RegOpenKeyExW", "NtCreateFile", "GetModuleFileNameW", "LoadTypeLibEx",
      "SearchPathMissing",
    ] {
    assert_true(!string_in(apis, name))
  }
}

///|
test "L2.7 restricted lookup filters the full hook table" {
  match lookup_thunk_restricted("CreateFileW", true) {
    Some(thunk) => assert_true(thunk == "lp_create_file_w")
    None => assert_true(false)
  }
  match lookup_thunk_restricted("LoadLibraryW", true) {
    Some(_) => assert_true(false)
    None => ()
  }
  // Unrestricted modules still get every slot in hook_table().
  match lookup_thunk_restricted("LoadLibraryW", false) {
    Some(thunk) => assert_true(thunk == "lp_load_library_w")
    None => assert_true(false)
  }
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

///|
test "read_file returns the whole file, not a prefix" {
  let v = Vfs::new()
  let data = Bytes::make(9216, b'A')
  v.add_file("c:/virt/big.dll", data)
  let back = v.read_file("c:/virt/big.dll")
  match back {
    Some(b) => assert_true(b.length() == 9216)
    None => fail("virtual file was not readable")
  }
  // The same through a handle, which is the path an application takes.
  let h = v.open("c:/virt/big.dll").unwrap()
  assert_true(v.size(h) == Some(9216L))
  let chunk = v.read(h, 9216).unwrap()
  assert_true(chunk.length() == 9216)
}

// --- L5.6: the MSFT type-library reader ---
//
// The reader is checked against a library assembled field by field in the test.
// A real one comes out of MIDL as two kilobytes of opaque bytes; a synthetic
// one states where every field is, so a wrong offset fails here rather than
// registering a class under a GUID that does not exist.

///|
fn tlw_8(a : FixedArray[Byte], off : Int32, v : Int32) -> Unit {
  a[off] = (v & 0xFF).to_byte()
}

///|
fn tlw_16(a : FixedArray[Byte], off : Int32, v : Int32) -> Unit {
  tlw_8(a, off, v & 0xFF)
  tlw_8(a, off + 1, v >> 8)
}

///|
fn tlw_32(a : FixedArray[Byte], off : Int32, v : Int32) -> Unit {
  tlw_16(a, off, v & 0xFFFF)
  tlw_16(a, off + 2, v >> 16)
}

///|
fn tlw_ascii(a : FixedArray[Byte], off : Int32, s : String) -> Unit {
  let mut i = 0
  while i < s.length() {
    tlw_8(a, off + i, s[i].to_int())
    i = i + 1
  }
}

///|
/// Store a GUID in the packed COM form: three little-endian fields, then eight
/// bytes in order. Written out by hand because that is exactly the property the
/// text form has to undo.
fn tlw_guid(
  a : FixedArray[Byte],
  off : Int32,
  d1 : Int32,
  d2 : Int32,
  d3 : Int32,
  tail : Int64,
) -> Unit {
  tlw_32(a, off, d1)
  tlw_16(a, off + 4, d2)
  tlw_16(a, off + 6, d3)
  let mut i = 0
  while i < 8 {
    tlw_8(a, off + 8 + i, ((tail >> ((7 - i) * 8)) & 0xFFL).to_int())
    i = i + 1
  }
}

///|
/// A library with one interface (three methods, four vtable slots) and one
/// coclass, laid out where MIDL puts everything.
fn tlw_library() -> Bytes {
  let segdir = 0x54 + 2 * 4
  let ti = segdir + 15 * 16
  let guid = ti + 2 * 100
  let name = guid + 3 * 16
  let str = name + 8 + 3 * 20
  let size = str + 28
  let a = FixedArray::make(size, b'\x00')
  // Header: magic, LIBID position, LCID, varflags, version, type count, name
  // and doc-string offsets.
  tlw_ascii(a, 0, "MSFT")
  tlw_32(a, 0x08, 0)
  tlw_32(a, 0x0C, 1033)
  tlw_32(a, 0x14, 3)
  tlw_32(a, 0x18, 2 + (1 << 16))
  tlw_32(a, 0x1C, 0x02)
  tlw_32(a, 0x20, 2)
  tlw_32(a, 0x24, 0)
  tlw_32(a, 0x38, 40)
  // Segment directory: type infos, GUID table, name table, string table.
  tlw_32(a, segdir, ti)
  tlw_32(a, segdir + 5 * 16, guid)
  tlw_32(a, segdir + 7 * 16, name)
  tlw_32(a, segdir + 8 * 16, str)
  tlw_guid(a, guid, 0x11112222, 0x3333, 0x4444, 0x5555666677778888L)
  tlw_guid(a, guid + 16, 0x9B1F0A4D, 0x2D3E, 0x4A55, 0x8F01112233445566L)
  tlw_guid(a, guid + 32, 0x9B1F0A4C, 0x2D3E, 0x4A55, 0x8F01112233445566L)
  // The interface: kind, method count, IID, name, version, doc, vtable size.
  tlw_32(a, ti, 3)
  tlw_32(a, ti + 0x18, 3)
  tlw_32(a, ti + 0x2C, 16)
  tlw_32(a, ti + 0x30, 1)
  tlw_32(a, ti + 0x34, 0)
  tlw_32(a, ti + 0x38, 1)
  tlw_32(a, ti + 0x3C, 16)
  tlw_16(a, ti + 0x4C, 1)
  tlw_16(a, ti + 0x4E, 32)
  tlw_32(a, ti + 0x50, 32)
  // The coclass: no methods, no vtable, no doc string.
  let co = ti + 100
  tlw_32(a, co, 5)
  tlw_32(a, co + 0x2C, 32)
  tlw_32(a, co + 0x30, 2)
  tlw_32(a, co + 0x34, 20)
  tlw_32(a, co + 0x38, 1)
  tlw_32(a, co + 0x3C, -1)
  // Name records: one byte of length, three reserved, the characters, padding.
  tlw_8(a, name + 8, 7)
  tlw_ascii(a, name + 12, "ILpFace")
  tlw_8(a, name + 28, 6)
  tlw_ascii(a, name + 32, "TestCo")
  tlw_8(a, name + 48, 7)
  tlw_ascii(a, name + 52, "TestLib")
  // Doc strings: a two-byte character count then the characters.
  tlw_16(a, str, 12)
  tlw_ascii(a, str + 2, "Test library")
  tlw_16(a, str + 16, 9)
  tlw_ascii(a, str + 18, "IFace doc")
  Bytes::from_array(a[:])
}

///|
test "the MSFT reader walks the segment directory the header declares" {
  let info = parse_msft(tlw_library()).unwrap()
  assert_true(info.libid == "{11112222-3333-4444-5555-666677778888}")
  assert_true(info.name == "TestLib")
  assert_true(info.doc == "Test library")
  assert_true(info.major == 2 && info.minor == 1)
  assert_true(info.lcid == 1033)
  // varflags carries the platform; three is SYS_WIN64, which decides whether a
  // registration writes its path under `win64` or `win32`.
  assert_true(info.syskind == 3)
  assert_true(info.flags == 0x02)
  assert_true(info.types.length() == 2)
  let face = info.types[0]
  assert_true(face.kind == 3)
  assert_true(face.name == "ILpFace")
  assert_true(face.guid == "{9B1F0A4D-2D3E-4A55-8F01-112233445566}")
  assert_true(face.doc == "IFace doc")
  assert_true(face.c_funcs == 3)
  // 32 bytes of vtable is four pointers, which is the NumMethods a
  // registration stores.
  assert_true(face.c_vft == 32)
  assert_true(face.c_impl == 1)
  assert_true(face.major == 1 && face.minor == 0)
  let co = info.types[1]
  assert_true(co.kind == 5)
  assert_true(co.name == "TestCo")
  assert_true(co.guid == "{9B1F0A4C-2D3E-4A55-8F01-112233445566}")
  // A field the reader must not invent: this coclass has no doc string.
  assert_true(co.doc == "")
}

///|
test "a blob that is not a type library is refused, not half-read" {
  match parse_msft(Bytes::make(0, b'\x00')) {
    None => ()
    Some(_) => fail("an empty buffer was accepted as a type library")
  }
  match parse_msft(Bytes::make(0x100, b'\x00')) {
    None => ()
    Some(_) => fail("a zeroed buffer was accepted as a type library")
  }
  match parse_msft(Bytes::make(0x100, b'M')) {
    None => ()
    Some(_) => fail("a buffer that is not an MSFT image was accepted")
  }
  // Truncated mid-directory: the segments are past the end of the bytes.
  let full = tlw_library()
  match parse_msft(img_slice(full, 0L, 0x60L)) {
    None => ()
    Some(_) =>
      fail("a type library cut off before its segment directory was accepted")
  }
}

///|
test "a GUID survives the trip to binary and back" {
  let text = "{9B1F0A4D-2D3E-4A55-8F01-112233445566}"
  let bin = guid_bytes(text)
  assert_true(bin.length() == 16)
  // The three fields are little-endian; the last eight bytes are in order.
  assert_true(
    bin[0] == b'\x4d' &&
    bin[1] == b'\x0a' &&
    bin[2] == b'\x1f' &&
    bin[3] == b'\x9b',
  )
  assert_true(bin[4] == b'\x3e' && bin[5] == b'\x2d')
  assert_true(bin[6] == b'\x55' && bin[7] == b'\x4a')
  assert_true(bin[8] == b'\x8f' && bin[9] == b'\x01' && bin[15] == b'\x66')
  // Only the canonical shape is parsed; anything else is refused rather than
  // guessed at, because a wrong GUID registers a key nobody will look up.
  assert_true(guid_bytes("").length() == 0)
  assert_true(guid_bytes("{short}").length() == 0)
  assert_true(
    guid_bytes("x9B1F0A4D-2D3E-4A55-8F01-112233445566}").length() == 0,
  )
  assert_true(guid_bytes("{9B1F0A4D-2D3E-4A55-8F01-11223344556}").length() == 0)
}

///|
test "the ordinal table resolves oleaut32's automation entry points" {
  // A component built the ordinary way imports these by number, so the number
  // is the only thing an IAT hook has to go on.
  assert_true(ordinal_thunk("oleaut32.dll", 161) == Some("lp_load_typelib"))
  assert_true(ordinal_thunk("oleaut32.dll", 163) == Some("lp_register_typelib"))
  assert_true(ordinal_thunk("oleaut32.dll", 183) == Some("lp_load_typelib_ex"))
  assert_true(
    ordinal_thunk("oleaut32.dll", 186) == Some("lp_unregister_typelib"),
  )
  assert_true(
    ordinal_thunk("oleaut32.dll", 443) == Some("lp_unregister_typelib_for_user"),
  )
  // The library name is part of the key: the same number elsewhere is a
  // different function, and guessing would patch an unrelated import.
  assert_true(ordinal_thunk("kernel32.dll", 183) == None)
  assert_true(ordinal_thunk("oleaut32.dll", 999) == None)
}

///|
/// A little-endian 8-byte number, for the archives these tests build by hand.
fn le8_for_test(v : Int64) -> Bytes {
  let out = FixedArray::make(8, b'\x00')
  let mut x = v
  let mut i = 0
  while i < 8 {
    out[i] = (x & 0xFFL).to_byte()
    x = x >> 8
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
fn put_for_test(out : FixedArray[Byte], at : Int32, src : Bytes) -> Int32 {
  let mut i = 0
  while i < src.length() {
    out[at + i] = src[i]
    i = i + 1
  }
  at + src.length()
}

///|
/// A whole archive: [magic][manifest][magic][offset][length], followed by
/// `tail` bytes that are not part of it.
fn archive_for_test(manifest : String, tail : Int32) -> Bytes {
  let magic = b"APPKGD02"
  let m = @utf8.encode(manifest)
  let out = FixedArray::make(8 + m.length() + 24 + tail, b'\x00')
  let mut at = put_for_test(out, 0, magic)
  at = put_for_test(out, at, m)
  at = put_for_test(out, at, magic)
  at = put_for_test(out, at, le8_for_test(8L))
  ignore(put_for_test(out, at, le8_for_test(m.length().to_int64())))
  Bytes::from_array(out[:])
}

///|
test "the banner of an archive is found in front of what was appended to it" {
  // A bundle is signed by appending the signature after the last byte of the
  // file, so the archive no longer ends where the file ends. The reader has to
  // find the archive anyway: the footer says where the archive ends, and the
  // bytes after it are somebody else's.
  let manifest = "{\"name\":\"demo\"}"
  match manifest_text(archive_for_test(manifest, 0)) {
    Some((base, text)) => {
      assert_true(base == 0)
      assert_true(text == manifest)
    }
    None => fail("an archive with nothing appended was not found")
  }
  match manifest_text(archive_for_test(manifest, 4096)) {
    Some((base, text)) => {
      assert_true(base == 0)
      assert_true(text == manifest)
    }
    None => fail("an archive with a signature appended was not found")
  }
  // A signature that is longer than the window the file is read in must not
  // change that either: the search walks the whole file, not a fixed tail.
  match manifest_text(archive_for_test(manifest, 200000)) {
    Some((_, text)) => assert_true(text == manifest)
    None => fail("an archive under a long signature was not found")
  }
}

///|
test "a footer that does not close an archive is not taken for one" {
  let manifest = "{}"
  // The marker in the middle is not a footer when the two numbers do not add
  // up to an archive that is there.
  let m = @utf8.encode(manifest)
  let out = FixedArray::make(8 + m.length() + 24, b'\x00')
  let mut at = put_for_test(out, 0, b"APPKGD02")
  at = put_for_test(out, at, m)
  at = put_for_test(out, at, b"APPKGD02")
  at = put_for_test(out, at, le8_for_test(9999L))
  at = put_for_test(out, at, le8_for_test(m.length().to_int64()))
  let wrong = Bytes::from_array(out[:])
  assert_true(manifest_text(wrong) is None)
  // And a file that carries no footer at all carries no archive.
  let head = FixedArray::make(8 + m.length(), b'\x00')
  let at2 = put_for_test(head, 0, b"APPKGD02")
  ignore(put_for_test(head, at2, m))
  assert_true(manifest_text(Bytes::from_array(head[:])) is None)
}
