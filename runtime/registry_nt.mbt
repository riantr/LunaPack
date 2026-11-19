// L5: the registry at the ntdll boundary.
//
// combase keeps its class cache in terms of native handles: it opens the CLSID
// key with `NtOpenKey` and reads values with `NtQueryValueKey`. Patched Win32
// IAT slots do not see those calls, so a hive handle returned by
// `RegOpenKeyExW` is later handed back to the kernel, which knows nothing about
// it and answers STATUS_INVALID_HANDLE.
//
// The fix is the same one L2.3 used for files: put the two native entry points
// in the hook table, resolve them against the hive, and fall through to the
// real ntdll export for everything the hive does not own. No inline patch of
// ntdll.dll, no code in another process.

///|
const STATUS_BUFFER_TOO_SMALL : Int32 = -1073741789 // 0xC0000023

///|
const KEY_VALUE_BASIC_INFORMATION : Int32 = 1

///|
const KEY_VALUE_PARTIAL_INFORMATION : Int32 = 2

///|
extern "C" fn real_nt_open_key(
  key_handle : Int64,
  access : Int32,
  object_attributes : Int64,
) -> Int32 = "NtOpenKey"

///|
extern "C" fn real_nt_query_value_key(
  key : Int64,
  value_name : Int64,
  info_class : Int32,
  info : Int64,
  length : Int32,
  result_length : Int64,
) -> Int32 = "NtQueryValueKey"

///|
/// The `ObjectName` of an OBJECT_ATTRIBUTES, as text. On x64 the layout is
/// Length@0 (4), padding@4, RootDirectory@8, ObjectName@16, and a
/// UNICODE_STRING is Length@0 (2), MaximumLength@2 (2), Buffer@8.
fn nt_reg_name(obj : Int64) -> String {
  if obj == 0L {
    return ""
  }
  let name = peek64(obj + 16L)
  if name == 0L {
    return ""
  }
  let len = peek16(name)
  let buf = peek64(name + 8L)
  if buf == 0L || len <= 0 {
    return ""
  }
  wide_exact(buf, len)
}

///|
/// The hive path a native open asks for, or None when the request is outside
/// the hive and must go to the real kernel.
fn nt_reg_path(r : VirtualRegistry, root : Int64, name : String) -> String? {
  if root == 0L {
    // An absolute native path always starts at the registry root.
    return translate_native(name)
  }
  let base = match base_key_path(r, root) {
    Some(b) => b
    None => return None
  }
  let sub = norm_path(name)
  if sub.length() == 0 {
    Some(base)
  } else {
    Some(canonical(base + "/" + sub))
  }
}

///|
#export_name("lp_nt_open_key")
pub fn lp_nt_open_key(key_handle : Int64, access : Int32, obj : Int64) -> Int32 {
  hit("NtOpenKey")
  let r = state_reg()
  let root = if obj != 0L { peek64(obj + 8L) } else { 0L }
  let name = nt_reg_name(obj)
  let path = nt_reg_path(r, root, name)
  match path {
    Some(k) =>
      if r.contains_path(k) {
        let handle = r.handle_for(k)
        if key_handle != 0L {
          poke_bytes(key_handle, u64le(handle), 8)
        }
        g_runtime.ntdll_hits = g_runtime.ntdll_hits + 1
        STATUS_SUCCESS
      } else if r.handles.contains(root) {
        // A key the hive owns does not have this child, and asking the kernel
        // about our own handle would only produce an invalid-handle error.
        STATUS_OBJECT_NAME_NOT_FOUND
      } else {
        real_nt_open_key(key_handle, access, obj)
      }
    None => real_nt_open_key(key_handle, access, obj)
  }
}

///|
/// Answer `KeyValuePartialInformation` (type, data) and
/// `KeyValueBasicInformation` (type, name) for a hive key.
fn nt_emit_value(
  name : String,
  v : RegValue,
  info_class : Int32,
  info : Int64,
  length : Int32,
  result_length : Int64,
) -> Int32 {
  if info_class == KEY_VALUE_PARTIAL_INFORMATION {
    let need = 12 + v.data.length()
    if result_length != 0L {
      put32(result_length, need)
    }
    if info == 0L || length < need {
      return STATUS_BUFFER_TOO_SMALL
    }
    put32(info, 0)
    put32(info + 4L, v.typ)
    put32(info + 8L, v.data.length())
    poke_bytes(info + 12L, v.data, v.data.length())
    STATUS_SUCCESS
  } else if info_class == KEY_VALUE_BASIC_INFORMATION {
    let name_bytes = name.length() * 2
    let need = 12 + name_bytes
    if result_length != 0L {
      put32(result_length, need)
    }
    if info == 0L || length < need {
      return STATUS_BUFFER_TOO_SMALL
    }
    put32(info, 0)
    put32(info + 4L, v.typ)
    put32(info + 8L, name_bytes)
    if name_bytes > 0 {
      let b = utf16le(name)
      poke_bytes(info + 12L, b, name_bytes)
    }
    STATUS_SUCCESS
  } else {
    // Other information classes describe the key, not the value.
    STATUS_BUFFER_TOO_SMALL
  }
}

///|
#export_name("lp_nt_query_value_key")
pub fn lp_nt_query_value_key(
  key : Int64,
  value_name : Int64,
  info_class : Int32,
  info : Int64,
  length : Int32,
  result_length : Int64,
) -> Int32 {
  hit("NtQueryValueKey")
  let r = state_reg()
  let path = match r.handles.get(key) {
    Some(k) => k
    None =>
      return real_nt_query_value_key(
        key, value_name, info_class, info, length, result_length,
      )
  }
  let name = nt_reg_name_from(value_name)
  match r.value_in_path(path, name) {
    Some(v) => {
      g_runtime.ntdll_hits = g_runtime.ntdll_hits + 1
      nt_emit_value(name, v, info_class, info, length, result_length)
    }
    None => STATUS_OBJECT_NAME_NOT_FOUND
  }
}

///|
/// A value name arrives as a bare UNICODE_STRING pointer, not wrapped in
/// OBJECT_ATTRIBUTES, and may be NULL for the default value.
fn nt_reg_name_from(us : Int64) -> String {
  if us == 0L {
    return ""
  }
  let len = peek16(us)
  let buf = peek64(us + 8L)
  if buf == 0L || len <= 0 {
    return ""
  }
  wide_exact(buf, len)
}

///|
const KEY_NAME_INFORMATION_CLASS : Int32 = 3

///|
extern "C" fn nt_query_key(
  key : Int64,
  info_class : Int32,
  info : Int64,
  length : Int32,
  result_length : Int64,
) -> Int32 = "NtQueryKey"

///|
/// The native name of a hive key, which is what `NtQueryKey` reports: the
/// classes tree is reached through the machine hive in native terms.
fn native_name_of(k : String) -> String {
  let prefix = "\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES"
  if k == "hkcr" {
    prefix
  } else if k.has_prefix("hkcr/") {
    let rest = str_slice(k, 5, k.length()).replace_all(old="/", new="\\")
    prefix + "\\" + rest.to_upper()
  } else if k == "hklm" {
    "\\REGISTRY\\MACHINE"
  } else if k.has_prefix("hklm/") {
    "\\REGISTRY\\MACHINE\\" +
    str_slice(k, 5, k.length()).replace_all(old="/", new="\\")
  } else if k == "hkcu" {
    "\\REGISTRY\\USER"
  } else if k.has_prefix("hkcu/") {
    "\\REGISTRY\\USER\\" +
    str_slice(k, 5, k.length()).replace_all(old="/", new="\\")
  } else {
    "\\REGISTRY\\MACHINE"
  }
}

///|
#export_name("lp_nt_query_key")
pub fn lp_nt_query_key(
  key : Int64,
  info_class : Int32,
  info : Int64,
  length : Int32,
  result_length : Int64,
) -> Int32 {
  hit("NtQueryKey")
  let r = state_reg()
  let path = match r.handles.get(key) {
    Some(k) => k
    None => return nt_query_key(key, info_class, info, length, result_length)
  }
  if info_class != KEY_NAME_INFORMATION_CLASS {
    // The other classes describe the security and the value counts; a caller
    // that asks for those is better served by the real key it does not have.
    return nt_query_key(key, info_class, info, length, result_length)
  }
  let name = native_name_of(path)
  let b = utf16le(name)
  let need = 4 + b.length()
  if result_length != 0L {
    put32(result_length, need)
  }
  if info == 0L || length < need {
    return STATUS_BUFFER_TOO_SMALL
  }
  put32(info, b.length())
  poke_bytes(info + 4L, b, b.length())
  STATUS_SUCCESS
}
