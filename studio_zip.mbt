// Extraction of the LunaPack Studio release archive.
//
// Studio is shipped as a plain zip attached to the *same* GitHub release as
// this CLI. It is unpacked here rather than by an external `unzip` or `tar`:
// a command line tool that downloads a window should not also depend on
// whichever archiver happens to be installed on the machine.
//
// Only the two methods a release zip actually uses are supported: stored
// (directory entries) and raw deflate (everything else). Sizes come from the
// central directory, so entries with a data descriptor work too.

///|
/// One file in the central directory.
struct ZipEntry {
  name : String
  codec : Int32
  compressed : Int32
  size : Int32
  local_off : Int32
}

///|
fn zip_u16(data : Bytes, off : Int32) -> Int32 {
  data.at(off).to_int() | (data.at(off + 1).to_int() << 8)
}

///|
fn zip_u32(data : Bytes, off : Int32) -> Int64 {
  zip_u16(data, off).to_int64() | (zip_u16(data, off + 2).to_int64() << 16)
}

///|
/// Offset of the end-of-central-directory record. The comment at the end of
/// a zip can be up to 65535 bytes, so the record is looked for backwards.
fn find_eocd(data : Bytes) -> Int32 raise {
  let n = data.length()
  if n < 22 {
    fail("the downloaded Studio archive is too small to be a zip file")
  }
  let lower = if n > 65557 { n - 65557 } else { 0 }
  let mut i = n - 22
  while i >= lower {
    if zip_u32(data, i) == 0x06054b50L {
      return i
    }
    i = i - 1
  }
  fail("the downloaded Studio archive is not a zip file")
}

///|
fn zip_entries(data : Bytes) -> Array[ZipEntry] raise {
  let eocd = find_eocd(data)
  let count = zip_u16(data, eocd + 10)
  let mut p = zip_u32(data, eocd + 16).to_int()
  let out : Array[ZipEntry] = []
  for _i = 0; _i < count; _i = _i + 1 {
    if p < 0 || p + 46 > data.length() || zip_u32(data, p) != 0x02014b50L {
      fail("the downloaded Studio archive has a damaged central directory")
    }
    let codec = zip_u16(data, p + 10)
    let compressed = zip_u32(data, p + 20).to_int()
    let size = zip_u32(data, p + 24).to_int()
    let name_len = zip_u16(data, p + 28)
    let extra_len = zip_u16(data, p + 30)
    let comment_len = zip_u16(data, p + 32)
    let local_off = zip_u32(data, p + 42).to_int()
    if p + 46 + name_len > data.length() {
      fail("the downloaded Studio archive has a truncated file name")
    }
    let name = @utf8.decode_lossy(data[p + 46:p + 46 + name_len])
    out.push({ name, codec, compressed, size, local_off, })
    p = p + 46 + name_len + extra_len + comment_len
  }
  out
}

///|
/// Windows packers often write `\` as the separator inside a zip. The zip
/// format specifies `/`, but a name taken verbatim would produce a path with
/// mixed separators: `dest/foo\bar\baz`. On Windows `@fs.mkdir` then reports
/// "The system cannot find the path specified", and a directory entry ending
/// in `\` is mistaken for a file. Normalise once, before any path is built.
pub fn normalized_zip_name(name : String) -> String {
  name.replace_all(old="\\", new="/")
}

///|
/// A zip is data from the network, so an entry name is not allowed to escape
/// the directory it is being unpacked into.
fn safe_zip_name(name : String) -> Bool {
  let n = normalized_zip_name(name)
  if n.has_prefix("/") {
    return false
  }
  if n.length() > 1 && n[1] == ':' {
    return false
  }
  if n == ".." ||
    n.has_prefix("../") ||
    n.has_suffix("/..") ||
    n.find("/../") is Some(_) {
    return false
  }
  true
}

///|
/// Unpack every entry of `data` below `dest`, creating parent directories.
pub async fn extract_zip(data : Bytes, dest : String) -> Unit {
  let entries = zip_entries(data)
  if entries.length() == 0 {
    fail("the downloaded Studio archive contains no files")
  }
  @fs.mkdir(dest, recursive=true, allow_exist=true)
  for e in entries {
    let name = normalized_zip_name(e.name)
    if !safe_zip_name(name) {
      fail("the downloaded Studio archive has an unsafe path: " + e.name)
    }
    if name == "" {
      continue
    }
    if name.has_suffix("/") {
      // A trailing slash makes some runtimes report NotFound for the last
      // component. The directory itself is the same path without it.
      let trimmed = name[:name.length() - 1].to_owned()
      @fs.mkdir(dest + "/" + trimmed, recursive=true, allow_exist=true)
      continue
    }
    let lh = e.local_off
    if lh < 0 || lh + 30 > data.length() || zip_u32(data, lh) != 0x04034b50L {
      fail("the downloaded Studio archive has a damaged local header")
    }
    let start = lh + 30 + zip_u16(data, lh + 26) + zip_u16(data, lh + 28)
    if start < 0 || e.compressed < 0 || start + e.compressed > data.length() {
      fail("the downloaded Studio archive has a truncated entry")
    }
    let payload = data[start:start + e.compressed]
    let path = dest + "/" + name
    ensure_parent_dir(path)
    if e.codec == 0 {
      @fs.write_binary(path, payload)
    } else if e.codec == 8 {
      let bytes = @flate.inflate_exact(
        payload,
        max_output=e.size,
        two_pass=true,
      ) catch {
        _ => fail("cannot unpack " + e.name)
      }
      @fs.write_binary(path, bytes)
    } else {
      fail("unsupported zip compression method " + e.codec.to_string())
    }
    // A downloaded executable must be runnable on Unix. The call is skipped
    // on Windows, where chmod is a no-op the runtime does not implement.
    if host_platform() != "windows" {
      @fs.chmod(path, 493) catch {
        _ => ()
      }
    }
  }
}
