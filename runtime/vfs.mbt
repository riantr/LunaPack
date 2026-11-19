// In-memory filesystem.
//
// The whole tree lives in MoonBit Maps. No file is created on disk: `add_file`
// registers a path and its bytes, and the Win32 thunks serve those bytes to
// callers that believe they are opening a real file.
//
// L1 extends the original read-only snapshot with the semantics a real program
// expects from a filesystem: creation dispositions, writes, truncation,
// delete/rename, positioned and overlapped I/O, per-handle access, stable file
// IDs, timestamps/attributes, canonical path handling and a completion queue.
// Nothing in that extension touches the disk: everything still lives in Maps.

///|
const INVALID_HANDLE_VALUE : Int64 = -1L

///|
const FILE_ATTRIBUTE_READONLY : Int32 = 0x1

///|
const FILE_ATTRIBUTE_DIRECTORY : Int32 = 0x10

///|
const FILE_ATTRIBUTE_ARCHIVE : Int32 = 0x20

///|
const FILE_ATTRIBUTE_NORMAL : Int32 = 0x80

///|
const ERROR_SUCCESS : Int32 = 0

///|
const ERROR_FILE_NOT_FOUND : Int32 = 2

///|
const ERROR_ACCESS_DENIED : Int32 = 5

///|
const ERROR_INVALID_HANDLE : Int32 = 6

///|
const ERROR_NO_MORE_FILES : Int32 = 18

///|
const ERROR_FILE_EXISTS : Int32 = 80

///|
const ERROR_ALREADY_EXISTS : Int32 = 183

// CreateFileW dwCreationDisposition values.

///|
const CREATE_NEW : Int32 = 1

///|
const CREATE_ALWAYS : Int32 = 2

///|
const OPEN_EXISTING : Int32 = 3

///|
const OPEN_ALWAYS : Int32 = 4

///|
const TRUNCATE_EXISTING : Int32 = 5

// SetFilePointerEx dwMoveMethod values.

///|
const FILE_BEGIN : Int32 = 0

///|
const FILE_CURRENT : Int32 = 1

///|
const FILE_END : Int32 = 2

///|
/// GENERIC_READ as a 32-bit pattern (0x80000000, negative when signed).
const GENERIC_READ_ACCESS : Int32 = -2147483648

// A fixed, deterministic FILETIME used for files seeded from tests/hosts.

///|
const DEFAULT_FILETIME : Int64 = 132000000000000000L

///|
/// The result of a CreateFileW request against the virtual tree. `NotVirtual`
/// tells the thunk to fall through to the real CreateFileW; `Failed` carries a
/// Win32 error code that must be reported to the caller instead.
pub enum CreateResult {
  Opened(Int64)
  NotVirtual
  Failed(Int32)
}

///|
/// Metadata kept alongside the bytes of a virtual file. FILETIME values are
/// 100ns ticks since 1601-01-01, the same unit Win32 uses.
pub struct VFileMeta {
  attrs : Int32
  file_id : Int64
  created : Int64
  accessed : Int64
  written : Int64
  writable : Bool
}

///|
/// BY_HANDLE_FILE_INFORMATION-compatible view produced by `file_info`.
pub struct FileInfo {
  attrs : Int32
  size : Int64
  file_id : Int64
  created : Int64
  accessed : Int64
  written : Int64
  links : Int32
}

///|
/// One queued overlapped-I/O completion. `key` is the completion key for an
/// IOCP-style post, or the completion-routine address for a ReadFileEx call.
pub struct Completion {
  key : Int64
  bytes : Int64
  overlapped : Int64
}

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
/// Convert one UTF-16 code unit of `s` to a one-character String.
fn char_str(s : String, i : Int32) -> String {
  match s[i].to_char() {
    Some(x) => String::make(1, x)
    None => "?"
  }
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
/// Return `data` with `chunk` written at `off`, extending the file with zero
/// bytes when the write goes past the current end.
fn bytes_write(data : Bytes, off : Int32, chunk : Bytes) -> Bytes {
  if off < 0 {
    return data
  }
  let end = off + chunk.length()
  let n = if end > data.length() { end } else { data.length() }
  let a = FixedArray::make(n, b'\x00')
  for i = 0; i < data.length(); i = i + 1 {
    a[i] = data[i]
  }
  for i = 0; i < chunk.length(); i = i + 1 {
    a[off + i] = chunk[i]
  }
  Bytes::from_array(a[:])
}

///|
/// Split a normalized path into non-empty segments, keeping a leading UNC
/// marker. `.` segments disappear and `..` pops the previous segment.
fn split_segments(s : String) -> Array[String] {
  let parts : Array[String] = []
  let n = s.length()
  let mut cur = ""
  let mut i = 0
  while i < n {
    let c = s[i]
    if c == '/' {
      if cur.length() > 0 {
        if cur == ".." {
          if parts.length() > 0 {
            ignore(parts.pop())
          }
        } else if cur != "." {
          parts.push(cur)
        }
      }
      cur = ""
    } else {
      cur = cur + char_str(s, i)
    }
    i = i + 1
  }
  if cur.length() > 0 {
    if cur == ".." {
      if parts.length() > 0 {
        ignore(parts.pop())
      }
    } else if cur != "." {
      parts.push(cur)
    }
  }
  parts
}

///|
/// Determine whether a normalized path is absolute (drive-qualified or UNC).
fn is_absolute(s : String) -> Bool {
  if s.has_prefix("//") {
    return true
  }
  s.length() >= 3 && s[1] == ':' && s[2] == '/'
}

///|
/// Windows paths are case-insensitive and use either separator. Duplicate
/// separators are collapsed, `.`/`..` resolved, and the `\\?\` (extended-length)
/// and `\\?\UNC\` prefixes are stripped so a virtual path can never be
/// confused with a differently-spelled real path.
pub fn norm_path(p : String) -> String {
  let raw = p.replace_all(old="\\", new="/").to_lower()
  let mut s = raw
  let mut unc = false
  if s.has_prefix("//?/unc/") {
    s = "//" + str_slice(s, 8, s.length())
    unc = true
  } else if s.has_prefix("//?/") {
    s = str_slice(s, 4, s.length())
  } else if s.has_prefix("//") {
    unc = true
  }
  let parts = split_segments(s)
  let mut out = if unc { "//" } else { "" }
  for i = 0; i < parts.length(); i = i + 1 {
    if i > 0 {
      out = out + "/"
    }
    out = out + parts[i]
  }
  out
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
/// A deterministic 8.3 alias for a long name: first six alphanumeric
/// characters + "~1" + the first three extension characters. Returns `None`
/// for names that are already 8.3-compatible.
fn short_name(name : String) -> String? {
  let mut dot = name.length()
  for i = 0; i < name.length(); i = i + 1 {
    if name[i] == '.' {
      dot = i
      break
    }
  }
  let stem = str_take(name, dot)
  let ext = if dot < name.length() {
    str_slice(name, dot + 1, name.length())
  } else {
    ""
  }
  if stem.length() <= 8 && ext.length() <= 3 {
    return None
  }
  let mut head = ""
  for i = 0; i < stem.length() && head.length() < 6; i = i + 1 {
    let c = stem[i]
    if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
      head = head + char_str(stem, i)
    }
  }
  if head.length() == 0 {
    head = "file"
  }
  let mut short = head + "~1"
  if ext.length() > 0 {
    short = short + "." + str_take(ext, 3)
  }
  Some(short)
}

///|
pub struct Vfs {
  files : Map[String, Bytes]
  meta : Map[String, VFileMeta]
  dirs : Map[String, Unit]
  roots : Map[String, Unit]
  handles : Map[Int64, String]
  access : Map[Int64, Int32]
  offsets : Map[Int64, Int64]
  find_names : Map[Int64, Array[String]]
  find_index : Map[Int64, Int32]
  aliases : Map[String, String]
  completions : Array[Completion]
  mut cwd : String
  // L2.1: virtual temp directory returned by GetTempPathW. Empty = no override.
  mut temp_path : String
  mut completion_head : Int32
  mut next_handle : Int64
  mut next_file_id : Int64
  mut calls_create : Int32
  mut calls_read : Int32
  mut calls_write : Int32
  mut calls_seek : Int32
  mut calls_delete : Int32
  mut calls_rename : Int32
  mut calls_info : Int32
  mut calls_fallback : Int32
}

///|
pub fn Vfs::new() -> Vfs {
  {
    files: {},
    meta: {},
    dirs: {},
    roots: {},
    handles: {},
    access: {},
    offsets: {},
    find_names: {},
    find_index: {},
    aliases: {},
    completions: [],
    cwd: "",
    temp_path: "",
    completion_head: 0,
    next_handle: 0x4C500000L,
    next_file_id: 0x10000L,
    calls_create: 0,
    calls_read: 0,
    calls_write: 0,
    calls_seek: 0,
    calls_delete: 0,
    calls_rename: 0,
    calls_info: 0,
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
/// Resolve a caller-supplied path to a canonical virtual path: normalize,
/// anchor relative paths at the virtual CWD, then apply short-name aliases.
pub fn Vfs::resolve(self : Vfs, path : String) -> String {
  let n = norm_path(path)
  let with_cwd = if !is_absolute(n) && self.cwd.length() > 0 {
    norm_path(self.cwd + "/" + n)
  } else {
    n
  }
  // Exact alias first.
  match self.aliases.get(with_cwd) {
    Some(long) => long
    None => {
      // Then a prefix alias: `c:/progra~1/app/x` with alias
      // `c:/progra~1` -> `c:/program files` becomes `c:/program files/app/x`.
      let pairs = self.aliases.to_array()
      let mut result = with_cwd
      let mut i = 0
      while i < pairs.length() {
        let (short, target) = pairs[i]
        if with_cwd.has_prefix(short + "/") {
          result = target +
            str_slice(with_cwd, short.length(), with_cwd.length())
          i = pairs.length()
        }
        i = i + 1
      }
      result
    }
  }
}

///|
/// Set the directory relative paths are resolved against.
pub fn Vfs::set_cwd(self : Vfs, path : String) -> Unit {
  self.cwd = norm_path(path)
}

///|
/// Register an explicit short-name alias (e.g. `progra~1` -> `program files`).
pub fn Vfs::add_alias(self : Vfs, short : String, long : String) -> Unit {
  self.aliases.set(norm_path(short), norm_path(long))
}

///|
fn seed_meta(v : Vfs, p : String, writable : Bool) -> Unit {
  let id = v.next_file_id
  v.next_file_id = v.next_file_id + 1L
  v.meta.set(p, {
    attrs: FILE_ATTRIBUTE_NORMAL,
    file_id: id,
    created: DEFAULT_FILETIME,
    accessed: DEFAULT_FILETIME,
    written: DEFAULT_FILETIME,
    writable,
  })
}

///|
fn register_dirs(v : Vfs, p : String) -> Unit {
  let mut d = parent_dir(p)
  while d.length() > 0 {
    v.dirs.set(d, ())
    d = parent_dir(d)
  }
  let root = parent_dir(p)
  if root.length() > 0 {
    v.roots.set(root, ())
  }
}

///|
pub fn Vfs::add_file(self : Vfs, path : String, data : Bytes) -> Unit {
  let p = norm_path(path)
  self.files.set(p, data)
  seed_meta(self, p, true)
  register_dirs(self, p)
  match short_name(basename(p)) {
    Some(s) => {
      let parent = parent_dir(p)
      let short_path = if parent.length() > 0 { parent + "/" + s } else { s }
      self.aliases.set(short_path, p)
    }
    None => ()
  }
}

///|
/// Override metadata for a seeded file (attributes and three FILETIMEs).
pub fn Vfs::set_meta(
  self : Vfs,
  path : String,
  attrs : Int32,
  created : Int64,
  accessed : Int64,
  written : Int64,
) -> Bool {
  let p = self.resolve(path)
  match self.meta.get(p) {
    None => false
    Some(m) => {
      self.meta.set(p, {
        attrs,
        file_id: m.file_id,
        created,
        accessed,
        written,
        writable: m.writable,
      })
      true
    }
  }
}

///|
/// Whether a path is owned by the virtual tree (an existing file or a path
/// beneath a seeded virtual directory). Owned paths are served from memory;
/// everything else falls through to the real FS.
fn owned(v : Vfs, p : String) -> Bool {
  if v.files.contains(p) {
    return true
  }
  let roots = v.roots.to_array()
  for i = 0; i < roots.length(); i = i + 1 {
    let (r, _) = roots[i]
    if p == r || p.has_prefix(r + "/") {
      return true
    }
  }
  false
}

///|
fn wants_write(access : Int32) -> Bool {
  (access & 0x40000000) != 0 || // GENERIC_WRITE
  (access & 0x10000000) != 0 || // GENERIC_ALL
  (access & 0x00000002) != 0 || // FILE_WRITE_DATA
  (access & 0x00000004) != 0 // FILE_APPEND_DATA
}

///|
/// CreateFileW with full disposition handling. A brand-new path is only
/// created in memory when it lies under a seeded virtual directory, which
/// keeps the "unmatched means real call" fallback contract intact.
pub fn Vfs::create_file(
  self : Vfs,
  path : String,
  access : Int32,
  disp : Int32,
) -> CreateResult {
  let p = self.resolve(path)
  if !owned(self, p) {
    return NotVirtual
  }
  let exists = self.files.contains(p)
  let write = wants_write(access)
  let is_readonly = match self.meta.get(p) {
    Some(m) => (m.attrs & FILE_ATTRIBUTE_READONLY) != 0
    None => false
  }
  if exists && is_readonly && write {
    return Failed(ERROR_ACCESS_DENIED)
  }
  let should_create = match disp {
    CREATE_NEW => {
      if exists {
        return Failed(ERROR_FILE_EXISTS)
      }
      true
    }
    CREATE_ALWAYS => true
    OPEN_EXISTING =>
      if exists {
        false
      } else {
        return Failed(ERROR_FILE_NOT_FOUND)
      }
    OPEN_ALWAYS => !exists
    TRUNCATE_EXISTING =>
      if exists {
        false
      } else {
        return Failed(ERROR_FILE_NOT_FOUND)
      }
    _ => if exists { false } else { return Failed(ERROR_FILE_NOT_FOUND) }
  }
  if should_create {
    self.files.set(p, Bytes::make(0, b'\x00'))
    seed_meta(self, p, true)
    register_dirs(self, p)
  } else if disp == TRUNCATE_EXISTING || disp == CREATE_ALWAYS {
    self.files.set(p, Bytes::make(0, b'\x00'))
    touch(self, p)
  }
  let h = alloc_handle(self)
  self.handles.set(h, p)
  self.access.set(h, access)
  self.offsets.set(h, 0L)
  Opened(h)
}

///|
fn touch(v : Vfs, p : String) -> Unit {
  match v.meta.get(p) {
    Some(m) =>
      v.meta.set(p, {
        attrs: m.attrs,
        file_id: m.file_id,
        created: m.created,
        accessed: m.accessed,
        written: DEFAULT_FILETIME + 1L,
        writable: m.writable,
      })
    None => ()
  }
}

///|
/// Legacy read-only open, kept for existing callers and tests.
pub fn Vfs::open(self : Vfs, path : String) -> Int64? {
  match self.create_file(path, GENERIC_READ_ACCESS, OPEN_EXISTING) {
    Opened(h) => Some(h)
    _ => None
  }
}

///|
/// Write bytes at a handle's current offset. `at` carries an OVERLAPPED
/// offset for positioned writes; `None` uses (and advances) the handle offset.
pub fn Vfs::write_at(
  self : Vfs,
  handle : Int64,
  data : Bytes,
  at : Int64?,
) -> Int32? {
  let p = match self.handles.get(handle) {
    Some(x) => x
    None => return None
  }
  let access = match self.access.get(handle) {
    Some(a) => a
    None => return None
  }
  if !wants_write(access) {
    return None
  }
  match self.meta.get(p) {
    Some(m) if !m.writable || (m.attrs & FILE_ATTRIBUTE_READONLY) != 0 =>
      return None
    _ => ()
  }
  let offset = match at {
    Some(o) => o
    None =>
      match self.offsets.get(handle) {
        Some(o) => o
        None => 0L
      }
  }
  if offset < 0L {
    return None
  }
  let old = match self.files.get(p) {
    Some(b) => b
    None => return None
  }
  let n = data.length()
  self.files.set(p, bytes_write(old, offset.to_int(), data))
  match at {
    None => self.offsets.set(handle, offset + n.to_int64())
    Some(_) => ()
  }
  touch(self, p)
  self.calls_write = self.calls_write + 1
  Some(n)
}

///|
fn read_from(v : Vfs, handle : Int64, max_len : Int32, at : Int64?) -> Bytes? {
  let p = match v.handles.get(handle) {
    Some(x) => x
    None => return None
  }
  match v.files.get(p) {
    None => None
    Some(data) => {
      let base = match at {
        Some(o) => o
        None =>
          match v.offsets.get(handle) {
            Some(o) => o
            None => 0L
          }
      }
      if base < 0L {
        return None
      }
      let total = data.length()
      let start = base.to_int()
      let avail = if start >= total { 0 } else { total - start }
      let n = if avail < max_len { avail } else { max_len }
      match at {
        None => v.offsets.set(handle, (start + n).to_int64())
        Some(_) => ()
      }
      v.calls_read = v.calls_read + 1
      Some(bytes_slice(data, start, start + n))
    }
  }
}

///|
/// Whole contents of a virtual file, for the paths that map an image or hash an
/// entry rather than stream it.
pub fn Vfs::read_file(self : Vfs, path : String) -> Bytes? {
  let h = match self.open(path) {
    Some(x) => x
    None => return None
  }
  let n = match self.size(h) {
    Some(s) => s.to_int()
    None => 0
  }
  let data = self.read(h, n)
  ignore(self.close(h))
  data
}

///|
pub fn Vfs::read(self : Vfs, handle : Int64, max_len : Int32) -> Bytes? {
  read_from(self, handle, max_len, None)
}

///|
/// Positioned read used when ReadFile is called with a non-null OVERLAPPED.
pub fn Vfs::read_at(
  self : Vfs,
  handle : Int64,
  max_len : Int32,
  at : Int64,
) -> Bytes? {
  read_from(self, handle, max_len, Some(at))
}

///|
/// SetFilePointerEx semantics. Returns the new absolute offset.
pub fn Vfs::seek(
  self : Vfs,
  handle : Int64,
  distance : Int64,
  method : Int32,
) -> Int64? {
  let p = match self.handles.get(handle) {
    Some(x) => x
    None => return None
  }
  let cur = match self.offsets.get(handle) {
    Some(o) => o
    None => 0L
  }
  let size = match self.files.get(p) {
    Some(b) => b.length().to_int64()
    None => 0L
  }
  let base = if method == FILE_BEGIN {
    0L
  } else if method == FILE_CURRENT {
    cur
  } else if method == FILE_END {
    size
  } else {
    return None
  }
  let next = base + distance
  if next < 0L {
    return None
  }
  self.offsets.set(handle, next)
  self.calls_seek = self.calls_seek + 1
  Some(next)
}

///|
pub fn Vfs::size(self : Vfs, handle : Int64) -> Int64? {
  let p = match self.handles.get(handle) {
    Some(x) => x
    None => return None
  }
  match self.files.get(p) {
    None => None
    Some(data) => Some(data.length().to_int64())
  }
}

///|
/// BY_HANDLE_FILE_INFORMATION for a virtual handle.
pub fn Vfs::file_info(self : Vfs, handle : Int64) -> FileInfo? {
  let p = match self.handles.get(handle) {
    Some(x) => x
    None => return None
  }
  match self.files.get(p) {
    None => None
    Some(data) => {
      let m = match self.meta.get(p) {
        Some(x) => x
        None => return None
      }
      self.calls_info = self.calls_info + 1
      Some(FileInfo::{
        attrs: m.attrs,
        size: data.length().to_int64(),
        file_id: m.file_id,
        created: m.created,
        accessed: m.accessed,
        written: m.written,
        links: 1,
      })
    }
  }
}

///|
/// WIN32_FILE_ATTRIBUTE_DATA for a virtual path (files and directories).
pub fn Vfs::path_info(self : Vfs, path : String) -> FileInfo? {
  let p = self.resolve(path)
  if self.files.contains(p) || self.dirs.contains(p) {
    let is_dir = self.dirs.contains(p) && !self.files.contains(p)
    let size = match self.files.get(p) {
      Some(b) => b.length().to_int64()
      None => 0L
    }
    let m = match self.meta.get(p) {
      Some(x) => x
      None =>
        VFileMeta::{
          attrs: if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
          } else {
            FILE_ATTRIBUTE_NORMAL
          },
          file_id: 0L,
          created: DEFAULT_FILETIME,
          accessed: DEFAULT_FILETIME,
          written: DEFAULT_FILETIME,
          writable: false,
        }
    }
    let attrs = if is_dir { FILE_ATTRIBUTE_DIRECTORY } else { m.attrs }
    self.calls_info = self.calls_info + 1
    Some(FileInfo::{
      attrs,
      size,
      file_id: m.file_id,
      created: m.created,
      accessed: m.accessed,
      written: m.written,
      links: 1,
    })
  } else {
    None
  }
}

///|
/// Delete a virtual file. Returns false when the path is not owned, so the
/// thunk can fall through to the real DeleteFileW.
pub fn Vfs::delete_file(self : Vfs, path : String) -> Bool {
  let p = self.resolve(path)
  if !self.files.contains(p) {
    return false
  }
  self.files.remove(p)
  self.meta.remove(p)
  self.calls_delete = self.calls_delete + 1
  true
}

///|
/// Rename/move a virtual file, updating any open handles that pointed at it.
pub fn Vfs::rename_file(self : Vfs, old : String, new : String) -> Bool {
  let src = self.resolve(old)
  let dst = self.resolve(new)
  let data = match self.files.get(src) {
    Some(b) => b
    None => return false
  }
  let m = self.meta.get(src)
  self.files.remove(src)
  self.meta.remove(src)
  self.files.set(dst, data)
  match m {
    Some(x) => self.meta.set(dst, x)
    None => ()
  }
  register_dirs(self, dst)
  let handles = self.handles.to_array()
  for i = 0; i < handles.length(); i = i + 1 {
    let (h, hp) = handles[i]
    if hp == src {
      self.handles.set(h, dst)
    }
  }
  self.calls_rename = self.calls_rename + 1
  true
}

///|
/// Queue an overlapped completion (IOCP key or completion-routine address).
pub fn Vfs::post_completion(
  self : Vfs,
  key : Int64,
  bytes : Int64,
  overlapped : Int64,
) -> Unit {
  self.completions.push(Completion::{ key, bytes, overlapped, })
}

///|
/// Drain the oldest completion, if any.
pub fn Vfs::take_completion(self : Vfs) -> Completion? {
  if self.completion_head >= self.completions.length() {
    return None
  }
  let c = self.completions[self.completion_head]
  self.completion_head = self.completion_head + 1
  Some(c)
}

///|
pub fn Vfs::close(self : Vfs, handle : Int64) -> Bool {
  if !self.handles.contains(handle) {
    return false
  }
  self.handles.remove(handle)
  self.access.remove(handle)
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
  let p = self.resolve(path)
  if self.files.contains(p) {
    match self.meta.get(p) {
      Some(m) => m.attrs
      None => FILE_ATTRIBUTE_NORMAL
    }
  } else if self.dirs.contains(p) {
    FILE_ATTRIBUTE_DIRECTORY
  } else {
    -1
  }
}

///|
/// Enumerate virtual files directly under the pattern's directory.
pub fn Vfs::find_first(self : Vfs, pattern : String) -> (Int64, String)? {
  let p = self.resolve(pattern)
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
