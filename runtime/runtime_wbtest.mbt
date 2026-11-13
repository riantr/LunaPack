// Whitebox tests for the pure data model and the PE layout reader. No Win32
// calls are made from a test: the mapper's memory work is exercised by the
// end-to-end harness in runtime/tests/.

///|
test "paths normalize separators, case and trailing slash" {
  assert_true(norm_path("C:\\Virt\\Hello.TXT") == "c:/virt/hello.txt")
  assert_true(norm_path("c:/virt/") == "c:/virt")
  assert_true(norm_path("C:/VIRT//x") == "c:/virt//x")
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
