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
  match v.open(wide_to_string(path)) {
    Some(h) => {
      v.note_create()
      set_last_error(ERROR_SUCCESS)
      h
    }
    None => {
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
  match v.read(handle, len) {
    Some(data) => {
      if buf != 0L {
        poke_bytes(buf, data, data.length())
      }
      if written != 0L {
        poke_bytes(written, u32le(data.length().to_int64()), 4)
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

///|
/// Cover the dynamic-resolution path: an application that calls
/// GetProcAddress("CreateFileW") gets our thunk instead of the real function.
#export_name("lp_get_proc_address")
pub fn thunk_get_proc_address(hmod : Int64, name : Int64) -> Int64 {
  if name == 0L {
    return 0L
  }
  let api = ascii_at(name, 128)
  let real = real_get_proc_address(hmod, cstring(api))
  match lookup_thunk(api) {
    Some(thunk_name) => {
      let our = thunk_address(thunk_name)
      if our != 0L {
        g_runtime.dynamic_hits = g_runtime.dynamic_hits + 1
        return our
      }
    }
    None => ()
  }
  real
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
/// Six counters: virtual creates, virtual reads, file fall-throughs,
/// virtual registry queries, patched IAT slots, dynamic-hook hits.
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
  ]
  for i = 0; i < vals.length(); i = i + 1 {
    poke_bytes(out + (i * 4).to_int64(), u32le(vals[i]), 4)
  }
  0
}
