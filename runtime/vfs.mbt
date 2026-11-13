// In-memory filesystem.
//
// The whole tree lives in MoonBit Maps. No file is created on disk: `add_file`
// registers a path and its bytes, and the Win32 thunks serve those bytes to
// callers that believe they are opening a real file.

///|
const INVALID_HANDLE_VALUE : Int64 = -1L

///|
const FILE_ATTRIBUTE_DIRECTORY : Int32 = 0x10

///|
const FILE_ATTRIBUTE_NORMAL : Int32 = 0x80

///|
const ERROR_FILE_NOT_FOUND : Int32 = 2

///|
const ERROR_INVALID_HANDLE : Int32 = 6

///|
const ERROR_NO_MORE_FILES : Int32 = 18

///|
const ERROR_SUCCESS : Int32 = 0

///|
/// A slice of a String as a new String. `s[i]` is a UTF-16 code unit.
fn str_slice(s : String, start : Int32, end : Int32) -> String {
  let a : Array[Char] = []
  for i = start; i < end; i = i + 1 {
    match s[i].to_char() {
      Some(x) => a.push(x)
      None => a.push('?')
    }
  }
  String::from_array(a[:])
}

///|
fn str_take(s : String, n : Int32) -> String {
  str_slice(s, 0, n)
}

///|
fn bytes_slice(data : Bytes, start : Int32, end : Int32) -> Bytes {
  let n = end - start
  let a = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    a[i] = data[start + i]
  }
  Bytes::from_array(a[:])
}

///|
/// Windows paths are case-insensitive and use either separator. A trailing
/// separator is dropped so a directory and a file never collide by accident.
pub fn norm_path(p : String) -> String {
  let s = p.replace_all(old="\\", new="/").to_lower()
  let mut end = s.length()
  while end > 0 && s[end - 1] == '/' {
    end = end - 1
  }
  str_take(s, end)
}

///|
fn parent_dir(p : String) -> String {
  let mut i = p.length() - 1
  while i >= 0 {
    if p[i] == '/' {
      return str_take(p, i)
    }
    i = i - 1
  }
  ""
}

///|
fn basename(p : String) -> String {
  let mut i = p.length() - 1
  while i >= 0 {
    if p[i] == '/' {
      return str_slice(p, i + 1, p.length())
    }
    i = i - 1
  }
  p
}

///|
fn wildcard_match(name : String, pat : String) -> Bool {
  if pat == "*" || pat == "" {
    return true
  }
  if pat.has_prefix("*.") {
    return name.has_suffix(str_slice(pat, 1, pat.length()))
  }
  name == pat
}

///|
pub struct Vfs {
  files : Map[String, Bytes]
  dirs : Map[String, Unit]
  handles : Map[Int64, String]
  offsets : Map[Int64, Int64]
  find_names : Map[Int64, Array[String]]
  find_index : Map[Int64, Int32]
  mut next_handle : Int64
  mut calls_create : Int32
  mut calls_read : Int32
  mut calls_fallback : Int32
}

///|
pub fn Vfs::new() -> Vfs {
  {
    files: {},
    dirs: {},
    handles: {},
    offsets: {},
    find_names: {},
    find_index: {},
    next_handle: 0x4C500000L,
    calls_create: 0,
    calls_read: 0,
    calls_fallback: 0,
  }
}

///|
pub fn Vfs::note_create(self : Vfs) -> Unit {
  self.calls_create = self.calls_create + 1
}

///|
pub fn Vfs::note_fallback(self : Vfs) -> Unit {
  self.calls_fallback = self.calls_fallback + 1
}

///|
fn alloc_handle(v : Vfs) -> Int64 {
  let h = v.next_handle
  v.next_handle = v.next_handle + 1L
  h
}

///|
pub fn Vfs::add_file(self : Vfs, path : String, data : Bytes) -> Unit {
  let p = norm_path(path)
  self.files.set(p, data)
  let mut d = parent_dir(p)
  while d.length() > 0 {
    self.dirs.set(d, ())
    d = parent_dir(d)
  }
  self.dirs.set("", ())
}

///|
pub fn Vfs::open(self : Vfs, path : String) -> Int64? {
  let p = norm_path(path)
  if !self.files.contains(p) {
    return None
  }
  let h = alloc_handle(self)
  self.handles.set(h, p)
  self.offsets.set(h, 0L)
  Some(h)
}

///|
pub fn Vfs::read(self : Vfs, handle : Int64, max_len : Int32) -> Bytes? {
  match self.handles.get(handle) {
    None => None
    Some(p) =>
      match self.files.get(p) {
        None => None
        Some(data) => {
          let start = match self.offsets.get(handle) {
            Some(o) => o.to_int()
            None => 0
          }
          let total = data.length()
          let avail = if start >= total { 0 } else { total - start }
          let n = if avail < max_len { avail } else { max_len }
          self.offsets.set(handle, (start + n).to_int64())
          self.calls_read = self.calls_read + 1
          Some(bytes_slice(data, start, start + n))
        }
      }
  }
}

///|
pub fn Vfs::size(self : Vfs, handle : Int64) -> Int64? {
  match self.handles.get(handle) {
    None => None
    Some(p) =>
      match self.files.get(p) {
        None => None
        Some(data) => Some(data.length().to_int64())
      }
  }
}

///|
pub fn Vfs::close(self : Vfs, handle : Int64) -> Bool {
  if !self.handles.contains(handle) {
    return false
  }
  self.handles.remove(handle)
  self.offsets.remove(handle)
  true
}

///|
pub fn Vfs::close_find(self : Vfs, handle : Int64) -> Bool {
  if !self.find_names.contains(handle) {
    return false
  }
  self.find_names.remove(handle)
  self.find_index.remove(handle)
  true
}

///|
pub fn Vfs::attributes(self : Vfs, path : String) -> Int32 {
  let p = norm_path(path)
  if self.files.contains(p) {
    return FILE_ATTRIBUTE_NORMAL
  }
  if self.dirs.contains(p) {
    return FILE_ATTRIBUTE_DIRECTORY
  }
  -1
}

///|
/// Enumerate virtual files directly under the pattern's directory.
pub fn Vfs::find_first(self : Vfs, pattern : String) -> (Int64, String)? {
  let p = norm_path(pattern)
  let dir = parent_dir(p)
  let wild = basename(p)
  let names : Array[String] = []
  let entries = self.files.to_array()
  for i = 0; i < entries.length(); i = i + 1 {
    let (key, _) = entries[i]
    if parent_dir(key) == dir && wildcard_match(basename(key), wild) {
      names.push(basename(key))
    }
  }
  if names.length() == 0 {
    return None
  }
  let h = alloc_handle(self)
  self.find_names.set(h, names)
  self.find_index.set(h, 1)
  Some((h, names[0]))
}

///|
pub fn Vfs::is_find_handle(self : Vfs, handle : Int64) -> Bool {
  self.find_names.contains(handle)
}

///|
pub fn Vfs::find_next(self : Vfs, handle : Int64) -> String? {
  match self.find_names.get(handle) {
    None => None
    Some(names) => {
      let idx = match self.find_index.get(handle) {
        Some(i) => i
        None => 0
      }
      if idx >= names.length() {
        return None
      }
      self.find_index.set(handle, idx + 1)
      Some(names[idx])
    }
  }
}
