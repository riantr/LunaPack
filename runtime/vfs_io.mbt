// Serialization of the virtual tree, so a child process can see the same
// files and registry values as its parent (L4.2).
//
// The blob is handed across the process boundary through an inheritable
// anonymous shared section - no file is written anywhere, and nothing is
// injected into the child. The format is deliberately dumb: a magic, a
// version, then length-prefixed records. A reader that runs out of bytes
// fails and leaves the destination empty rather than half-filled.

///|
const BLOB_MAGIC : Int32 = 0x5356504C // 'LPVS' little-endian

///|
const BLOB_VERSION : Int32 = 1

///|
fn blob_push_u32(out : Array[Byte], v : Int32) -> Unit {
  out.push((v & 0xFF).to_byte())
  out.push(((v >> 8) & 0xFF).to_byte())
  out.push(((v >> 16) & 0xFF).to_byte())
  out.push(((v >> 24) & 0xFF).to_byte())
}

///|
/// ASCII bytes of `s` without a terminator. Virtual paths are ASCII.
fn blob_str(s : String) -> Bytes {
  let a = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = s[i].to_byte()
  }
  Bytes::from_array(a[:])
}

///|
fn blob_push_str(out : Array[Byte], s : String) -> Unit {
  blob_push_u32(out, s.length())
  let b = blob_str(s)
  for i = 0; i < b.length(); i = i + 1 {
    out.push(b[i])
  }
}

///|
fn blob_push_bytes(out : Array[Byte], b : Bytes) -> Unit {
  blob_push_u32(out, b.length())
  for i = 0; i < b.length(); i = i + 1 {
    out.push(b[i])
  }
}

///|
/// The growable buffer is an array; `Bytes` wants a fixed one.
fn blob_to_bytes(a : Array[Byte]) -> Bytes {
  let f = FixedArray::make(a.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    f[i] = a[i]
  }
  Bytes::from_array(f[:])
}

///|
/// A cursor over a blob. Every read returns `None` when the blob is short, so
/// a damaged blob stops the import instead of reading past the end.
priv struct BlobReader {
  data : Bytes
  mut pos : Int32
}

///|
fn BlobReader::u32(self : BlobReader) -> Int32? {
  if self.pos + 4 > self.data.length() {
    return None
  }
  let v = self.data[self.pos].to_int() |
    (self.data[self.pos + 1].to_int() << 8) |
    (self.data[self.pos + 2].to_int() << 16) |
    (self.data[self.pos + 3].to_int() << 24)
  self.pos = self.pos + 4
  Some(v)
}

///|
fn BlobReader::bytes(self : BlobReader, n : Int32) -> Bytes? {
  if n < 0 || self.pos + n > self.data.length() {
    return None
  }
  let out = bytes_slice(self.data, self.pos, self.pos + n)
  self.pos = self.pos + n
  Some(out)
}

///|
fn BlobReader::str(self : BlobReader) -> String? {
  match self.u32() {
    None => None
    Some(n) =>
      match self.bytes(n) {
        None => None
        Some(b) => Some(bytes_to_ascii(b))
      }
  }
}

///|
fn BlobReader::field(self : BlobReader) -> Bytes? {
  match self.u32() {
    None => None
    Some(n) => self.bytes(n)
  }
}

///|
/// Serialize the whole virtual tree: files (with metadata), directories,
/// roots, short-name aliases, the current directory, the virtual temp path,
/// and the registry hive.
pub fn Vfs::export_blob(self : Vfs, reg : VirtualRegistry) -> Bytes {
  let out : Array[Byte] = []
  blob_push_u32(out, BLOB_MAGIC)
  blob_push_u32(out, BLOB_VERSION)
  blob_push_str(out, self.cwd)
  blob_push_str(out, self.temp_path)

  let files = self.files.to_array()
  blob_push_u32(out, files.length())
  for i = 0; i < files.length(); i = i + 1 {
    let (path, data) = files[i]
    blob_push_str(out, path)
    blob_push_bytes(out, data)
    let writable = match self.meta.get(path) {
      Some(m) => m.writable
      None => true
    }
    let (attrs, file_id, created, accessed, written) = match
      self.meta.get(path) {
      Some(m) => (m.attrs, m.file_id, m.created, m.accessed, m.written)
      None =>
        (
          FILE_ATTRIBUTE_NORMAL,
          0L,
          DEFAULT_FILETIME,
          DEFAULT_FILETIME,
          DEFAULT_FILETIME,
        )
    }
    blob_push_u32(out, if writable { 1 } else { 0 })
    blob_push_u32(out, attrs)
    blob_push_u32(out, (file_id & 0xFFFFFFFFL).to_int())
    blob_push_u32(out, ((file_id >> 32) & 0xFFFFFFFFL).to_int())
    blob_push_u32(out, (created & 0xFFFFFFFFL).to_int())
    blob_push_u32(out, ((created >> 32) & 0xFFFFFFFFL).to_int())
    blob_push_u32(out, (accessed & 0xFFFFFFFFL).to_int())
    blob_push_u32(out, ((accessed >> 32) & 0xFFFFFFFFL).to_int())
    blob_push_u32(out, (written & 0xFFFFFFFFL).to_int())
    blob_push_u32(out, ((written >> 32) & 0xFFFFFFFFL).to_int())
  }

  let dirs = self.dirs.to_array()
  blob_push_u32(out, dirs.length())
  for i = 0; i < dirs.length(); i = i + 1 {
    let (path, _) = dirs[i]
    blob_push_str(out, path)
  }

  let roots = self.roots.to_array()
  blob_push_u32(out, roots.length())
  for i = 0; i < roots.length(); i = i + 1 {
    let (path, _) = roots[i]
    blob_push_str(out, path)
  }

  let aliases = self.aliases.to_array()
  blob_push_u32(out, aliases.length())
  for i = 0; i < aliases.length(); i = i + 1 {
    let (short, long) = aliases[i]
    blob_push_str(out, short)
    blob_push_str(out, long)
  }

  let values = reg.values.to_array()
  blob_push_u32(out, values.length())
  for i = 0; i < values.length(); i = i + 1 {
    let (key, v) = values[i]
    blob_push_str(out, key)
    blob_push_u32(out, v.typ)
    blob_push_bytes(out, v.data)
  }

  let keys = reg.keys.to_array()
  blob_push_u32(out, keys.length())
  for i = 0; i < keys.length(); i = i + 1 {
    let (key, _) = keys[i]
    blob_push_str(out, key)
  }

  blob_to_bytes(out)
}

///|
/// Replace the contents of the virtual tree with a blob produced by
/// `export_blob`. Returns false, leaving the tree untouched, when the blob is
/// not one of ours or is truncated.
pub fn Vfs::import_blob(
  self : Vfs,
  reg : VirtualRegistry,
  blob : Bytes,
) -> Bool {
  let r = BlobReader::{ data: blob, pos: 0, }
  match r.u32() {
    Some(m) if m == BLOB_MAGIC => ()
    _ => return false
  }
  match r.u32() {
    Some(v) if v == BLOB_VERSION => ()
    _ => return false
  }
  let cwd = match r.str() {
    Some(s) => s
    None => return false
  }
  let temp = match r.str() {
    Some(s) => s
    None => return false
  }

  let file_count = match r.u32() {
    Some(n) => n
    None => return false
  }
  // Read everything into a local list first: a damaged blob must not leave a
  // half-imported tree behind.
  let files : Array[(String, Bytes, Bool, Int32, Int64, Int64, Int64, Int64)] = []
  for i = 0; i < file_count; i = i + 1 {
    let path = match r.str() {
      Some(s) => s
      None => return false
    }
    let data = match r.field() {
      Some(b) => b
      None => return false
    }
    let writable = match r.u32() {
      Some(v) => v != 0
      None => return false
    }
    let attrs = match r.u32() {
      Some(v) => v
      None => return false
    }
    let id_lo = match r.u32() {
      Some(v) => v
      None => return false
    }
    let id_hi = match r.u32() {
      Some(v) => v
      None => return false
    }
    let c_lo = match r.u32() {
      Some(v) => v
      None => return false
    }
    let c_hi = match r.u32() {
      Some(v) => v
      None => return false
    }
    let a_lo = match r.u32() {
      Some(v) => v
      None => return false
    }
    let a_hi = match r.u32() {
      Some(v) => v
      None => return false
    }
    let w_lo = match r.u32() {
      Some(v) => v
      None => return false
    }
    let w_hi = match r.u32() {
      Some(v) => v
      None => return false
    }
    files.push(
      (
        path,
        data,
        writable,
        attrs,
        (id_hi.to_int64() << 32) | (id_lo.to_int64() & 0xFFFFFFFFL),
        (c_hi.to_int64() << 32) | (c_lo.to_int64() & 0xFFFFFFFFL),
        (a_hi.to_int64() << 32) | (a_lo.to_int64() & 0xFFFFFFFFL),
        (w_hi.to_int64() << 32) | (w_lo.to_int64() & 0xFFFFFFFFL),
      ),
    )
  }

  let dir_count = match r.u32() {
    Some(n) => n
    None => return false
  }
  let dirs : Array[String] = []
  for i = 0; i < dir_count; i = i + 1 {
    match r.str() {
      Some(s) => dirs.push(s)
      None => return false
    }
  }

  let root_count = match r.u32() {
    Some(n) => n
    None => return false
  }
  let roots : Array[String] = []
  for i = 0; i < root_count; i = i + 1 {
    match r.str() {
      Some(s) => roots.push(s)
      None => return false
    }
  }

  let alias_count = match r.u32() {
    Some(n) => n
    None => return false
  }
  let aliases : Array[(String, String)] = []
  for i = 0; i < alias_count; i = i + 1 {
    let short = match r.str() {
      Some(s) => s
      None => return false
    }
    let long = match r.str() {
      Some(s) => s
      None => return false
    }
    aliases.push((short, long))
  }

  let value_count = match r.u32() {
    Some(n) => n
    None => return false
  }
  let values : Array[(String, Int32, Bytes)] = []
  for i = 0; i < value_count; i = i + 1 {
    let key = match r.str() {
      Some(s) => s
      None => return false
    }
    let typ = match r.u32() {
      Some(v) => v
      None => return false
    }
    let data = match r.field() {
      Some(b) => b
      None => return false
    }
    values.push((key, typ, data))
  }

  let key_count = match r.u32() {
    Some(n) => n
    None => return false
  }
  let keys : Array[String] = []
  for i = 0; i < key_count; i = i + 1 {
    match r.str() {
      Some(s) => keys.push(s)
      None => return false
    }
  }

  // Everything parsed: apply. The tree is replaced, not merged, because the
  // child's job is to see what the parent saw.
  self.files.clear()
  self.meta.clear()
  self.dirs.clear()
  self.roots.clear()
  self.aliases.clear()
  self.handles.clear()
  self.access.clear()
  self.offsets.clear()
  self.find_names.clear()
  self.find_index.clear()
  self.completions.clear()
  self.completion_head = 0
  self.cwd = cwd
  self.temp_path = temp

  for i = 0; i < files.length(); i = i + 1 {
    let (path, data, writable, attrs, file_id, created, accessed, written) = files[i]
    self.files.set(path, data)
    self.meta.set(path, {
      attrs,
      file_id,
      created,
      accessed,
      written,
      writable,
    })
    if file_id >= self.next_file_id {
      self.next_file_id = file_id + 1L
    }
  }
  for i = 0; i < dirs.length(); i = i + 1 {
    self.dirs.set(dirs[i], ())
  }
  for i = 0; i < roots.length(); i = i + 1 {
    self.roots.set(roots[i], ())
  }
  for i = 0; i < aliases.length(); i = i + 1 {
    let (short, long) = aliases[i]
    self.aliases.set(short, long)
  }

  reg.values.clear()
  reg.keys.clear()
  reg.handles.clear()
  for i = 0; i < values.length(); i = i + 1 {
    let (key, typ, data) = values[i]
    reg.values.set(key, { typ, data, })
  }
  for i = 0; i < keys.length(); i = i + 1 {
    reg.keys.set(keys[i], ())
  }
  true
}

///|
/// Size in bytes of the blob the current tree would serialize to. A host calls
/// this first so it can size its buffer.
#export_name("lp_vfs_export_size")
pub fn lp_vfs_export_size() -> Int32 {
  state_vfs().export_blob(state_reg()).length()
}

///|
/// Write the blob of the current tree into a caller-owned buffer. Returns the
/// number of bytes written, or -1 when the buffer is too small or missing.
#export_name("lp_vfs_export")
pub fn lp_vfs_export(out : Int64, cap : Int32) -> Int32 {
  if out == 0L || cap <= 0 {
    return -1
  }
  let blob = state_vfs().export_blob(state_reg())
  if blob.length() > cap {
    return -1
  }
  poke_bytes(out, blob, blob.length())
  blob.length()
}

///|
/// Replace the tree with a blob in a caller-owned buffer. Returns 0 on
/// success, 1 when the blob was refused, 2 when the arguments are invalid.
#export_name("lp_vfs_import")
pub fn lp_vfs_import(data : Int64, len : Int32) -> Int32 {
  if data == 0L || len <= 0 {
    return 2
  }
  if state_vfs().import_blob(state_reg(), peek_bytes(data, len)) {
    0
  } else {
    1
  }
}
