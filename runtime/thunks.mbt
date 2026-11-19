// Win32-compatible C ABI thunks.
//
// Each thunk is "virtual-first": if the request refers to something we put in
// the in-memory filesystem or hive, it is served from memory; otherwise it is
// forwarded to the real Win32 API through lpvirt.dll's own (unpatched)
// import. A packaged application therefore keeps working with real files and
// real registry keys that we do not own.

///|
extern "C" fn real_create_file_w(
  path : Int64,
  access : Int32,
  share : Int32,
  sec : Int64,
  disp : Int32,
  flags : Int32,
  tmpl : Int64,
) -> Int64 = "CreateFileW"

///|
extern "C" fn real_read_file(
  handle : Int64,
  buf : Int64,
  len : Int32,
  written : Int64,
  overlapped : Int64,
) -> Int32 = "ReadFile"

///|
extern "C" fn real_close_handle(handle : Int64) -> Int32 = "CloseHandle"

///|
extern "C" fn real_get_file_attributes_w(path : Int64) -> Int32 = "GetFileAttributesW"

///|
extern "C" fn real_get_file_size_ex(handle : Int64, size : Int64) -> Int32 = "GetFileSizeEx"

///|
extern "C" fn real_find_first_file_w(path : Int64, data : Int64) -> Int64 = "FindFirstFileW"

///|
extern "C" fn real_find_next_file_w(handle : Int64, data : Int64) -> Int32 = "FindNextFileW"

///|
extern "C" fn real_reg_open_key_ex_w(
  hkey : Int64,
  subkey : Int64,
  options : Int32,
  sam : Int32,
  result : Int64,
) -> Int32 = "RegOpenKeyExW"

///|
extern "C" fn real_reg_query_value_ex_w(
  hkey : Int64,
  name : Int64,
  reserved : Int64,
  typ : Int64,
  data : Int64,
  size : Int64,
) -> Int32 = "RegQueryValueExW"

///|
extern "C" fn real_reg_set_value_ex_w(
  hkey : Int64,
  name : Int64,
  reserved : Int64,
  typ : Int32,
  data : Int64,
  len : Int32,
) -> Int32 = "RegSetValueExW"

///|
extern "C" fn real_reg_close_key(hkey : Int64) -> Int32 = "RegCloseKey"

// --- L1 additions: writable files, handle semantics, metadata, overlapped IO.

///|
extern "C" fn real_write_file(
  handle : Int64,
  buf : Int64,
  len : Int32,
  written : Int64,
  overlapped : Int64,
) -> Int32 = "WriteFile"

///|
extern "C" fn real_delete_file_w(path : Int64) -> Int32 = "DeleteFileW"

///|
extern "C" fn real_move_file_ex_w(
  old_path : Int64,
  new_path : Int64,
  flags : Int32,
) -> Int32 = "MoveFileExW"

///|
extern "C" fn real_set_file_pointer_ex(
  handle : Int64,
  distance : Int64,
  new_pos : Int64,
  method : Int32,
) -> Int32 = "SetFilePointerEx"

///|
extern "C" fn real_get_file_information_by_handle(
  handle : Int64,
  info : Int64,
) -> Int32 = "GetFileInformationByHandle"

///|
extern "C" fn real_get_file_attributes_ex_w(
  path : Int64,
  level : Int32,
  info : Int64,
) -> Int32 = "GetFileAttributesExW"

///|
extern "C" fn real_get_queued_completion_status(
  port : Int64,
  bytes : Int64,
  key : Int64,
  overlapped : Int64,
  timeout : Int32,
) -> Int32 = "GetQueuedCompletionStatus"

///|
/// WIN32_FIND_DATAW is 592 bytes; cFileName starts at offset 44.
fn fill_find_data(addr : Int64, name : String) -> Unit {
  if addr == 0L {
    return
  }
  let a = FixedArray::make(592, b'\x00')
  a[0] = (128).to_byte()
  let wide = utf16le(name)
  let n = if wide.length() < 520 { wide.length() } else { 520 }
  for i = 0; i < n; i = i + 1 {
    a[44 + i] = wide[i]
  }
  poke_bytes(addr, Bytes::from_array(a[:]), 592)
}

///|
#export_name("lp_create_file_w")
pub fn thunk_create_file_w(
  path : Int64,
  access : Int32,
  share : Int32,
  sec : Int64,
  disp : Int32,
  flags : Int32,
  tmpl : Int64,
) -> Int64 {
  let v = state_vfs()
  match v.create_file(wide_to_string(path), access, disp) {
    Opened(h) => {
      v.note_create()
      set_last_error(ERROR_SUCCESS)
      h
    }
    Failed(code) => {
      set_last_error(code)
      INVALID_HANDLE_VALUE
    }
    NotVirtual => {
      v.note_fallback()
      real_create_file_w(path, access, share, sec, disp, flags, tmpl)
    }
  }
}

///|
#export_name("lp_read_file")
pub fn thunk_read_file(
  handle : Int64,
  buf : Int64,
  len : Int32,
  written : Int64,
  overlapped : Int64,
) -> Int32 {
  let v = state_vfs()
  // An OVERLAPPED request reads at the structure's explicit offset and does
  // not advance the handle pointer; a NULL OVERLAPPED uses the normal path.
  let data = if overlapped == 0L {
    v.read(handle, len)
  } else {
    v.read_at(handle, len, ov_offset(overlapped))
  }
  match data {
    Some(bytes) => {
      if buf != 0L {
        poke_bytes(buf, bytes, bytes.length())
      }
      if written != 0L {
        poke_bytes(written, u32le(bytes.length().to_int64()), 4)
      }
      if overlapped != 0L {
        ov_complete(overlapped, 0L, bytes.length().to_int64())
        let ev = ov_event(overlapped)
        if ev != 0L {
          ignore(set_event(ev))
        }
      }
      set_last_error(ERROR_SUCCESS)
      1
    }
    None => real_read_file(handle, buf, len, written, overlapped)
  }
}

///|
#export_name("lp_close_handle")
pub fn thunk_close_handle(handle : Int64) -> Int32 {
  let v = state_vfs()
  if v.close(handle) || v.close_find(handle) {
    set_last_error(ERROR_SUCCESS)
    1
  } else {
    real_close_handle(handle)
  }
}

///|
#export_name("lp_get_file_attributes_w")
pub fn thunk_get_file_attributes_w(path : Int64) -> Int32 {
  let v = state_vfs()
  let attrs = v.attributes(wide_to_string(path))
  if attrs == -1 {
    real_get_file_attributes_w(path)
  } else {
    attrs
  }
}

///|
#export_name("lp_get_file_size_ex")
pub fn thunk_get_file_size_ex(handle : Int64, size : Int64) -> Int32 {
  let v = state_vfs()
  match v.size(handle) {
    Some(n) => {
      if size != 0L {
        poke_bytes(size, u64le(n), 8)
      }
      1
    }
    None => real_get_file_size_ex(handle, size)
  }
}

///|
#export_name("lp_find_first_file_w")
pub fn thunk_find_first_file_w(path : Int64, data : Int64) -> Int64 {
  let v = state_vfs()
  match v.find_first(wide_to_string(path)) {
    Some((h, name)) => {
      fill_find_data(data, name)
      set_last_error(ERROR_SUCCESS)
      h
    }
    None => real_find_first_file_w(path, data)
  }
}

///|
#export_name("lp_find_next_file_w")
pub fn thunk_find_next_file_w(handle : Int64, data : Int64) -> Int32 {
  let v = state_vfs()
  match v.find_next(handle) {
    Some(name) => {
      fill_find_data(data, name)
      1
    }
    None =>
      if v.is_find_handle(handle) {
        set_last_error(ERROR_NO_MORE_FILES)
        0
      } else {
        real_find_next_file_w(handle, data)
      }
  }
}

///|
#export_name("lp_reg_open_key_ex_w")
pub fn thunk_reg_open_key_ex_w(
  hkey : Int64,
  subkey : Int64,
  options : Int32,
  sam : Int32,
  result : Int64,
) -> Int32 {
  let r = state_reg()
  match r.open_key(hkey, wide_to_string(subkey)) {
    Some(h) => {
      if result != 0L {
        poke_bytes(result, u64le(h), 8)
      }
      ERROR_SUCCESS
    }
    None => real_reg_open_key_ex_w(hkey, subkey, options, sam, result)
  }
}

///|
#export_name("lp_reg_query_value_ex_w")
pub fn thunk_reg_query_value_ex_w(
  hkey : Int64,
  name : Int64,
  reserved : Int64,
  typ : Int64,
  data : Int64,
  size : Int64,
) -> Int32 {
  let r = state_reg()
  match r.query_value(hkey, wide_to_string(name)) {
    Some(val) => {
      let need = val.data.length().to_int64()
      let requested = if size != 0L { peek32(size) } else { 0L }
      if typ != 0L {
        poke_bytes(typ, u32le(val.typ.to_int64()), 4)
      }
      if size != 0L {
        poke_bytes(size, u32le(need), 4)
      }
      if data != 0L && requested >= need {
        poke_bytes(data, val.data, val.data.length())
        ERROR_SUCCESS
      } else {
        ERROR_MORE_DATA
      }
    }
    None => real_reg_query_value_ex_w(hkey, name, reserved, typ, data, size)
  }
}

///|
#export_name("lp_reg_set_value_ex_w")
pub fn thunk_reg_set_value_ex_w(
  hkey : Int64,
  name : Int64,
  reserved : Int64,
  typ : Int32,
  data : Int64,
  len : Int32,
) -> Int32 {
  let r = state_reg()
  if !r.is_virtual_key(hkey) {
    return real_reg_set_value_ex_w(hkey, name, reserved, typ, data, len)
  }
  let bytes = peek_bytes(data, len)
  if r.set_value(hkey, "", wide_to_string(name), typ, bytes) {
    ERROR_SUCCESS
  } else {
    real_reg_set_value_ex_w(hkey, name, reserved, typ, data, len)
  }
}

///|
#export_name("lp_reg_close_key")
pub fn thunk_reg_close_key(hkey : Int64) -> Int32 {
  let r = state_reg()
  if r.close_key(hkey) {
    ERROR_SUCCESS
  } else {
    real_reg_close_key(hkey)
  }
}

// --------------------------------------------------------- L1 thunks ---

///|
#export_name("lp_write_file")
pub fn thunk_write_file(
  handle : Int64,
  buf : Int64,
  len : Int32,
  written : Int64,
  overlapped : Int64,
) -> Int32 {
  let v = state_vfs()
  let data = if len > 0 {
    peek_bytes(buf, len)
  } else {
    Bytes::make(0, b'\x00')
  }
  let at = if overlapped == 0L { None } else { Some(ov_offset(overlapped)) }
  match v.write_at(handle, data, at) {
    Some(n) => {
      if written != 0L {
        poke_bytes(written, u32le(n.to_int64()), 4)
      }
      if overlapped != 0L {
        ov_complete(overlapped, 0L, n.to_int64())
        let ev = ov_event(overlapped)
        if ev != 0L {
          ignore(set_event(ev))
        }
      }
      set_last_error(ERROR_SUCCESS)
      1
    }
    None => real_write_file(handle, buf, len, written, overlapped)
  }
}

///|
#export_name("lp_delete_file_w")
pub fn thunk_delete_file_w(path : Int64) -> Int32 {
  let v = state_vfs()
  if v.delete_file(wide_to_string(path)) {
    set_last_error(ERROR_SUCCESS)
    1
  } else {
    real_delete_file_w(path)
  }
}

///|
#export_name("lp_move_file_ex_w")
pub fn thunk_move_file_ex_w(
  old_path : Int64,
  new_path : Int64,
  flags : Int32,
) -> Int32 {
  let v = state_vfs()
  if v.rename_file(wide_to_string(old_path), wide_to_string(new_path)) {
    set_last_error(ERROR_SUCCESS)
    1
  } else {
    real_move_file_ex_w(old_path, new_path, flags)
  }
}

///|
#export_name("lp_set_file_pointer_ex")
pub fn thunk_set_file_pointer_ex(
  handle : Int64,
  distance : Int64,
  new_pos : Int64,
  method : Int32,
) -> Int32 {
  let v = state_vfs()
  match v.seek(handle, distance, method) {
    Some(pos) => {
      if new_pos != 0L {
        poke_bytes(new_pos, u64le(pos), 8)
      }
      set_last_error(ERROR_SUCCESS)
      1
    }
    None => real_set_file_pointer_ex(handle, distance, new_pos, method)
  }
}

///|
/// Fill a 52-byte BY_HANDLE_FILE_INFORMATION from a FileInfo value.
fn fill_by_handle_info(addr : Int64, info : FileInfo) -> Unit {
  if addr == 0L {
    return
  }
  let a = FixedArray::make(52, b'\x00')
  poke_bytes(addr, Bytes::from_array(a[:]), 52)
  poke_bytes(addr, u32le(info.attrs.to_int64()), 4)
  poke_filetime(addr + 4L, info.created)
  poke_filetime(addr + 12L, info.accessed)
  poke_filetime(addr + 20L, info.written)
  poke_bytes(addr + 28L, u32le(0L), 4) // volume serial number
  poke_bytes(addr + 32L, u32le((info.size >> 32) & 0xFFFFFFFFL), 4) // high
  poke_bytes(addr + 36L, u32le(info.size & 0xFFFFFFFFL), 4) // low
  poke_bytes(addr + 40L, u32le(info.links.to_int64()), 4)
  poke_bytes(addr + 44L, u32le((info.file_id >> 32) & 0xFFFFFFFFL), 4)
  poke_bytes(addr + 48L, u32le(info.file_id & 0xFFFFFFFFL), 4)
}

///|
#export_name("lp_get_file_information_by_handle")
pub fn thunk_get_file_information_by_handle(
  handle : Int64,
  info : Int64,
) -> Int32 {
  let v = state_vfs()
  match v.file_info(handle) {
    Some(fi) => {
      fill_by_handle_info(info, fi)
      set_last_error(ERROR_SUCCESS)
      1
    }
    None => real_get_file_information_by_handle(handle, info)
  }
}

// --- L2.1 additions: ANSI variants + virtual temp path.

///|
extern "C" fn real_create_file_a(
  path : Int64,
  access : Int32,
  share : Int32,
  sec : Int64,
  disp : Int32,
  flags : Int32,
  tmpl : Int64,
) -> Int64 = "CreateFileA"

///|
extern "C" fn real_get_file_attributes_a(path : Int64) -> Int32 = "GetFileAttributesA"

///|
extern "C" fn real_get_file_attributes_ex_a(
  path : Int64,
  level : Int32,
  info : Int64,
) -> Int32 = "GetFileAttributesExA"

///|
extern "C" fn real_find_first_file_a(path : Int64, data : Int64) -> Int64 = "FindFirstFileA"

///|
extern "C" fn real_find_next_file_a(handle : Int64, data : Int64) -> Int32 = "FindNextFileA"

///|
extern "C" fn real_delete_file_a(path : Int64) -> Int32 = "DeleteFileA"

///|
extern "C" fn real_move_file_ex_a(
  old_path : Int64,
  new_path : Int64,
  flags : Int32,
) -> Int32 = "MoveFileExA"

///|
extern "C" fn real_get_temp_path_w(len : Int32, buf : Int64) -> Int32 = "GetTempPathW"

///|
/// Fill a WIN32_FIND_DATAA (320 bytes; cFileName at offset 44, 260 ANSI bytes).
fn fill_find_data_a(addr : Int64, name : String) -> Unit {
  if addr == 0L {
    return
  }
  let a = FixedArray::make(320, b'\x00')
  a[0] = (128).to_byte()
  let ansi = ascii_bytes(name)
  let n = if ansi.length() < 259 { ansi.length() } else { 259 }
  for i = 0; i < n; i = i + 1 {
    a[44 + i] = ansi[i]
  }
  poke_bytes(addr, Bytes::from_array(a[:]), 320)
}

///|
/// Fill a 36-byte WIN32_FILE_ATTRIBUTE_DATA from a FileInfo value.
fn fill_attribute_data(addr : Int64, info : FileInfo) -> Unit {
  if addr == 0L {
    return
  }
  poke_bytes(addr, u32le(info.attrs.to_int64()), 4)
  poke_filetime(addr + 4L, info.created)
  poke_filetime(addr + 12L, info.accessed)
  poke_filetime(addr + 20L, info.written)
  poke_bytes(addr + 28L, u32le((info.size >> 32) & 0xFFFFFFFFL), 4)
  poke_bytes(addr + 32L, u32le(info.size & 0xFFFFFFFFL), 4)
}

///|
#export_name("lp_get_file_attributes_ex_w")
pub fn thunk_get_file_attributes_ex_w(
  path : Int64,
  level : Int32,
  info : Int64,
) -> Int32 {
  let v = state_vfs()
  match v.path_info(wide_to_string(path)) {
    Some(fi) => {
      fill_attribute_data(info, fi)
      set_last_error(ERROR_SUCCESS)
      1
    }
    None => real_get_file_attributes_ex_w(path, level, info)
  }
}

///|
/// Completion-port drain: serve our in-memory completion queue first, then
/// fall through to the real kernel32 call when the queue is empty.
#export_name("lp_get_queued_completion_status")
pub fn thunk_get_queued_completion_status(
  port : Int64,
  bytes : Int64,
  key : Int64,
  overlapped : Int64,
  timeout : Int32,
) -> Int32 {
  let v = state_vfs()
  match v.take_completion() {
    Some(c) => {
      if bytes != 0L {
        poke_bytes(bytes, u32le(c.bytes & 0xFFFFFFFFL), 4)
      }
      if key != 0L {
        poke_bytes(key, u64le(c.key), 8)
      }
      if overlapped != 0L {
        poke_bytes(overlapped, u64le(c.overlapped), 8)
      }
      set_last_error(ERROR_SUCCESS)
      1
    }
    None =>
      real_get_queued_completion_status(port, bytes, key, overlapped, timeout)
  }
}

///|
/// ANSI CreateFileA: convert the narrow path to a MoonBit string, then use the
/// same virtual-first disposition logic as CreateFileW. On a virtual miss the
/// original narrow pointer is forwarded to the real CreateFileA.
#export_name("lp_create_file_a")
pub fn thunk_create_file_a(
  path : Int64,
  access : Int32,
  share : Int32,
  sec : Int64,
  disp : Int32,
  flags : Int32,
  tmpl : Int64,
) -> Int64 {
  let v = state_vfs()
  match v.create_file(ansi_to_string(path), access, disp) {
    Opened(h) => {
      v.note_create()
      set_last_error(ERROR_SUCCESS)
      h
    }
    Failed(code) => {
      set_last_error(code)
      INVALID_HANDLE_VALUE
    }
    NotVirtual => {
      v.note_fallback()
      real_create_file_a(path, access, share, sec, disp, flags, tmpl)
    }
  }
}

///|
#export_name("lp_get_file_attributes_a")
pub fn thunk_get_file_attributes_a(path : Int64) -> Int32 {
  let v = state_vfs()
  let attrs = v.attributes(ansi_to_string(path))
  if attrs == -1 {
    real_get_file_attributes_a(path)
  } else {
    attrs
  }
}

///|
#export_name("lp_get_file_attributes_ex_a")
pub fn thunk_get_file_attributes_ex_a(
  path : Int64,
  level : Int32,
  info : Int64,
) -> Int32 {
  let v = state_vfs()
  match v.path_info(ansi_to_string(path)) {
    Some(fi) => {
      fill_attribute_data(info, fi)
      set_last_error(ERROR_SUCCESS)
      1
    }
    None => real_get_file_attributes_ex_a(path, level, info)
  }
}

///|
#export_name("lp_find_first_file_a")
pub fn thunk_find_first_file_a(path : Int64, data : Int64) -> Int64 {
  let v = state_vfs()
  match v.find_first(ansi_to_string(path)) {
    Some((h, name)) => {
      fill_find_data_a(data, name)
      set_last_error(ERROR_SUCCESS)
      h
    }
    None => real_find_first_file_a(path, data)
  }
}

///|
#export_name("lp_find_next_file_a")
pub fn thunk_find_next_file_a(handle : Int64, data : Int64) -> Int32 {
  let v = state_vfs()
  match v.find_next(handle) {
    Some(name) => {
      fill_find_data_a(data, name)
      1
    }
    None =>
      if v.is_find_handle(handle) {
        set_last_error(ERROR_NO_MORE_FILES)
        0
      } else {
        real_find_next_file_a(handle, data)
      }
  }
}

///|
#export_name("lp_delete_file_a")
pub fn thunk_delete_file_a(path : Int64) -> Int32 {
  let v = state_vfs()
  if v.delete_file(ansi_to_string(path)) {
    set_last_error(ERROR_SUCCESS)
    1
  } else {
    real_delete_file_a(path)
  }
}

///|
#export_name("lp_move_file_ex_a")
pub fn thunk_move_file_ex_a(
  old_path : Int64,
  new_path : Int64,
  flags : Int32,
) -> Int32 {
  let v = state_vfs()
  if v.rename_file(ansi_to_string(old_path), ansi_to_string(new_path)) {
    set_last_error(ERROR_SUCCESS)
    1
  } else {
    real_move_file_ex_a(old_path, new_path, flags)
  }
}

///|
/// Virtual temp path. GetTempPathW(buf, len) writes the seeded virtual temp
/// directory as UTF-16LE and returns the character count (matching Win32), so
/// programs that build temp paths under it stay inside the virtual tree. If no
/// temp path is seeded, fall through to the real GetTempPathW.
#export_name("lp_get_temp_path_w")
pub fn thunk_get_temp_path_w(len : Int32, buf : Int64) -> Int32 {
  let v = state_vfs()
  if v.temp_path.length() == 0 {
    return real_get_temp_path_w(len, buf)
  }
  let path = if v.temp_path.has_suffix("\\") {
    v.temp_path
  } else {
    v.temp_path + "\\"
  }
  let chars = path.length()
  if buf != 0L && len > chars {
    let b = utf16le(path)
    let n = (chars + 1) * 2
    poke_bytes(buf, b, n)
  }
  // Win32 returns the required buffer size (including NUL) when too small.
  if len <= chars {
    chars + 1
  } else {
    chars
  }
}

///|
/// Seed the virtual temp directory. Empty string disables the override.
#export_name("lp_virt_set_temp_path")
pub fn lp_virt_set_temp_path(path : Int64) -> Int32 {
  let v = state_vfs()
  v.temp_path = wide_to_string(path)
  0
}

///|
/// Cover the dynamic-resolution path: an application that calls
/// GetProcAddress("CreateFileW") gets our thunk instead of the real function.
#export_name("lp_get_proc_address")
pub fn thunk_get_proc_address(hmod : Int64, name : Int64) -> Int64 {
  if name == 0L {
    return 0L
  }
  // Ordinal lookups pass a small integer in the "name" pointer (HIWORD == 0).
  // Reading it as a C string would fault. Ordinals have no name to match our
  // table and cannot be expressed through the Bytes-based FFI binding, so
  // return 0 (not found). This is a documented L2.2 limitation, not a crash.
  if name < 0x10000L {
    return 0L
  }
  let api = ascii_at(name, 128)
  let real = real_get_proc_address(hmod, cstring(api))
  match lookup_thunk(api) {
    Some(thunk_name) => {
      let our = thunk_address(thunk_name)
      if our != 0L && real != 0L {
        g_runtime.dynamic_hits = g_runtime.dynamic_hits + 1
        return our
      }
    }
    None => ()
  }
  real
}

///|
/// L2.2: LoadLibrary variants. The real loader brings the module in, then we
/// rewrite that module's IAT with the same hook table used for mapped images.
/// lpvirt.dll itself is skipped inside patch_loaded_module so the real-API
/// fall-through references are never replaced (which would recurse).
#export_name("lp_load_library_a")
pub fn thunk_load_library_a(name : Int64) -> Int64 {
  // mapper.mbt already binds the LoadLibraryA C symbol; a second extern for
  // the same symbol is rejected by link-core. Reuse that binding by turning
  // the incoming raw ANSI pointer into a MoonBit string first.
  let h = load_library_a(cstring(ansi_to_string(name)))
  ignore(patch_loaded_module(h))
  h
}

///|
#export_name("lp_load_library_w")
pub fn thunk_load_library_w(name : Int64) -> Int64 {
  let h = real_load_library_w(name)
  ignore(patch_loaded_module(h))
  h
}

///|
#export_name("lp_load_library_ex_a")
pub fn thunk_load_library_ex_a(
  name : Int64,
  file : Int64,
  flags : Int32,
) -> Int64 {
  let h = real_load_library_ex_a(name, file, flags)
  ignore(patch_loaded_module(h))
  h
}

///|
#export_name("lp_load_library_ex_w")
pub fn thunk_load_library_ex_w(
  name : Int64,
  file : Int64,
  flags : Int32,
) -> Int64 {
  let h = real_load_library_ex_w(name, file, flags)
  ignore(patch_loaded_module(h))
  h
}

///|
/// A mapped CRT image calls ExitProcess from its entry point. Redirecting that
/// to ExitThread ends only the thread the image is running on, so the launcher
/// keeps control and can read the requested exit code via `lp_virt_exit_code`.
/// The code is recorded first because ExitThread never returns.
#export_name("lp_exit_process")
pub fn thunk_exit_process(code : Int32) -> Unit {
  g_runtime.exit_called = true
  g_runtime.target_exit_code = code
  exit_thread(code)
}

///|
/// Did a mapped image call ExitProcess, and with what code? The launcher reads
/// this after its worker thread finishes. Returns 1 when it was called.
#export_name("lp_virt_exit_query")
pub fn lp_virt_exit_query(out_code : Int64) -> Int32 {
  if out_code != 0L {
    poke_bytes(out_code, u32le(g_runtime.target_exit_code.to_int64()), 4)
  }
  if g_runtime.exit_called {
    1
  } else {
    0
  }
}

///|
/// Reset all virtual state. The host calls this right after `moonbit_init`.
#export_name("lp_virt_reset")
pub fn lp_virt_reset() -> Unit {
  g_runtime.vfs = Some(Vfs::new())
  g_runtime.registry = Some(VirtualRegistry::new())
  g_runtime.patched_count = 0
  g_runtime.dynamic_hits = 0
  g_runtime.map_error = 0
  g_runtime.exit_called = false
  g_runtime.target_exit_code = 0
  g_runtime.ntdll_hits = 0
  g_runtime.mapped_hook_count = 0
  g_runtime.loaded_hook_count = 0
  g_runtime.attach_bases = []
  g_runtime.detach_bases = []
  g_runtime.detach_order_violations = 0
  g_runtime.eh_table = 0L
}

///|
/// Register a virtual file. `path` is UTF-16LE, `data` is raw bytes.
#export_name("lp_virt_add_file")
pub fn lp_virt_add_file(path : Int64, data : Int64, len : Int32) -> Int32 {
  let v = state_vfs()
  v.add_file(wide_to_string(path), peek_bytes(data, len))
  0
}

///|
/// Seed a virtual registry value. `root` is a Win32 HKEY pseudo-handle.
#export_name("lp_virt_set_reg")
pub fn lp_virt_set_reg(
  root : Int64,
  subkey : Int64,
  name : Int64,
  typ : Int32,
  data : Int64,
  len : Int32,
) -> Int32 {
  let r = state_reg()
  let ok = r.set_value(
    root,
    wide_to_string(subkey),
    wide_to_string(name),
    typ,
    peek_bytes(data, len),
  )
  if ok {
    0
  } else {
    5
  }
}

///|
/// Thirteen counters. The first six are the original ABI and unchanged:
/// creates, reads, fall-throughs, reg queries, patched slots, dynamic hits.
/// The L1 additions are: writes, seeks, deletes, renames, info queries,
/// completions drained. Slot 12 (L2.3) counts ntdll-boundary virtual hits.
/// Callers pass the output capacity in bytes; a buffer of at least 24 bytes
/// keeps the original six available, 48 bytes exposes all L1 counters, and
/// 52 bytes adds the ntdll count.
#export_name("lp_virt_stats")
pub fn lp_virt_stats(out : Int64, cap : Int32) -> Int32 {
  if out == 0L || cap < 24 {
    return -1
  }
  let v = state_vfs()
  let r = state_reg()
  let vals : Array[Int64] = [
    v.calls_create.to_int64(),
    v.calls_read.to_int64(),
    v.calls_fallback.to_int64(),
    r.calls_query.to_int64(),
    g_runtime.patched_count.to_int64(),
    g_runtime.dynamic_hits.to_int64(),
    v.calls_write.to_int64(),
    v.calls_seek.to_int64(),
    v.calls_delete.to_int64(),
    v.calls_rename.to_int64(),
    v.calls_info.to_int64(),
    (v.completions.length() - v.completion_head).to_int64(),
    g_runtime.ntdll_hits.to_int64(),
  ]
  let n = if cap < 48 { 6 } else if cap < 52 { 12 } else { vals.length() }
  for i = 0; i < n; i = i + 1 {
    poke_bytes(out + (i * 4).to_int64(), u32le(vals[i]), 4)
  }
  0
}

///|
/// Set attributes and the three FILETIMEs of a previously seeded file.
#export_name("lp_virt_set_meta")
pub fn lp_virt_set_meta(
  path : Int64,
  attrs : Int32,
  created : Int64,
  accessed : Int64,
  written : Int64,
) -> Int32 {
  if state_vfs().set_meta(
      wide_to_string(path),
      attrs,
      created,
      accessed,
      written,
    ) {
    0
  } else {
    5
  }
}

///|
/// Set the directory used to resolve relative virtual paths.
#export_name("lp_virt_set_cwd")
pub fn lp_virt_set_cwd(path : Int64) -> Int32 {
  state_vfs().set_cwd(wide_to_string(path))
  0
}

///|
/// Register a short-name alias (e.g. `progra~1` -> `program files`).
#export_name("lp_virt_add_alias")
pub fn lp_virt_add_alias(short_path : Int64, long_path : Int64) -> Int32 {
  state_vfs().add_alias(wide_to_string(short_path), wide_to_string(long_path))
  0
}

///|
/// Post an overlapped completion record into the in-memory queue, so IOCP
/// callers can drain it through GetQueuedCompletionStatus.
#export_name("lp_virt_post_completion")
pub fn lp_virt_post_completion(
  key : Int64,
  bytes : Int64,
  overlapped : Int64,
) -> Int32 {
  state_vfs().post_completion(key, bytes, overlapped)
  0
}
