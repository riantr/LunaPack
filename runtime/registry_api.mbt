// Registry entry points that a self-registering COM component needs (L5.1).
//
// The first pass covered four calls: open, query, set, close. A component that
// registers itself also creates keys, walks the tree it just made, reports its
// size back to the caller, and deletes itself on uninstall. Activation adds one
// more: `RegGetValueW`, which is how the class database in combase reads
// `InprocServer32` instead of open-then-query.
//
// Every thunk keeps the same shape: serve the call from the hive when the hive
// owns the key, otherwise hand the original arguments to the real API. A key the
// hive does not own keeps behaving like the real registry.

///|
const ERROR_NO_MORE_ITEMS : Int32 = 259

///|
const ERROR_INVALID_PARAMETER : Int32 = 87

///|
const REG_OPTION_OPEN_LINK : Int32 = 0x8

///|
const REG_CREATED_NEW_KEY : Int32 = 1

///|
const REG_OPENED_EXISTING_KEY : Int32 = 2

///|
extern "C" fn real_reg_get_value_w(
  hkey : Int64,
  subkey : Int64,
  value : Int64,
  flags : Int32,
  typ : Int64,
  data : Int64,
  size : Int64,
) -> Int32 = "RegGetValueW"

///|
extern "C" fn real_reg_create_key_ex_w(
  hkey : Int64,
  subkey : Int64,
  reserved : Int32,
  class : Int64,
  options : Int32,
  sam : Int32,
  sa : Int64,
  result : Int64,
  disposition : Int64,
) -> Int32 = "RegCreateKeyExW"

///|
extern "C" fn real_reg_delete_key_w(hkey : Int64, subkey : Int64) -> Int32 = "RegDeleteKeyW"

///|
extern "C" fn real_reg_delete_value_w(hkey : Int64, name : Int64) -> Int32 = "RegDeleteValueW"

///|
extern "C" fn real_reg_enum_key_ex_w(
  hkey : Int64,
  index : Int32,
  name : Int64,
  cch : Int64,
  reserved : Int64,
  class : Int64,
  cch_class : Int64,
  last_write : Int64,
) -> Int32 = "RegEnumKeyExW"

///|
extern "C" fn real_reg_enum_value_w(
  hkey : Int64,
  index : Int32,
  name : Int64,
  cch : Int64,
  reserved : Int64,
  typ : Int64,
  data : Int64,
  cb : Int64,
) -> Int32 = "RegEnumValueW"

///|
extern "C" fn real_reg_query_info_key_w(
  hkey : Int64,
  class : Int64,
  cch_class : Int64,
  reserved : Int64,
  subkeys : Int64,
  max_subkey : Int64,
  max_class : Int64,
  values : Int64,
  max_value_name : Int64,
  max_value_data : Int64,
  sec_desc : Int64,
  last_write : Int64,
) -> Int32 = "RegQueryInfoKeyW"

///|
extern "C" fn real_reg_open_key_ex_a(
  hkey : Int64,
  subkey : Int64,
  options : Int32,
  sam : Int32,
  result : Int64,
) -> Int32 = "RegOpenKeyExA"

///|
extern "C" fn real_reg_create_key_ex_a(
  hkey : Int64,
  subkey : Int64,
  reserved : Int32,
  class : Int64,
  options : Int32,
  sam : Int32,
  sa : Int64,
  result : Int64,
  disposition : Int64,
) -> Int32 = "RegCreateKeyExA"

///|
extern "C" fn real_reg_delete_key_a(hkey : Int64, subkey : Int64) -> Int32 = "RegDeleteKeyA"

///|
/// Store a 32-bit out-parameter when the caller asked for one.
fn put32(addr : Int64, v : Int32) -> Unit {
  if addr != 0L {
    poke_bytes(addr, u32le(v.to_int64()), 4)
  }
}

///|
/// Answer a value read: report the type, write what fits, and follow the Win32
/// size protocol. Used by `RegQueryValueExW` and `RegGetValueW` so the two can
/// never answer differently.
fn emit_value(val : RegValue, typ : Int64, data : Int64, size : Int64) -> Int32 {
  let need = val.data.length().to_int64()
  let requested = if size != 0L { peek32(size) } else { 0L }
  put32(typ, val.typ)
  put32(size, need.to_int())
  if data != 0L && requested >= need {
    poke_bytes(data, val.data, val.data.length())
    ERROR_SUCCESS
  } else if data == 0L {
    // A NULL buffer asks only for the size.
    ERROR_SUCCESS
  } else {
    ERROR_MORE_DATA
  }
}

///|
/// Copy a string into a caller buffer using the `RegEnum*` protocol: the
/// capacity comes in as a character count, the written length goes out without
/// the terminator, and a short buffer reports the size it needs instead.
fn emit_wide_string(s : String, name : Int64, cch : Int64) -> Int32 {
  let need = s.length()
  if name == 0L || cch == 0L {
    return ERROR_INVALID_PARAMETER
  }
  let cap = peek32(cch).to_int()
  if cap < need + 1 {
    put32(cch, need + 1)
    return ERROR_MORE_DATA
  }
  let b = utf16le(s)
  poke_bytes(name, b, b.length())
  put32(cch, need)
  ERROR_SUCCESS
}

///|
#export_name("lp_reg_get_value_w")
pub fn thunk_reg_get_value_w(
  hkey : Int64,
  subkey : Int64,
  value : Int64,
  flags : Int32,
  typ : Int64,
  data : Int64,
  size : Int64,
) -> Int32 {
  hit("RegGetValueW")
  let r = state_reg()
  log_reg(
    "get " + hkey.to_string(),
    wide_to_string(subkey) + " | " + wide_to_string(value),
  )
  // The type filter (RRF_RT_*) is not applied: the hive only ever holds the
  // types a component wrote itself.
  let key = wide_to_string(subkey)
  let name = wide_to_string(value)
  match r.read_value(hkey, key, name) {
    Some(v) => emit_value(v, typ, data, size)
    None =>
      // A key the hive owns answers for itself. Passing our own handle to the
      // real API would fail with ERROR_INVALID_HANDLE, which is a different
      // answer than "this key has no such value".
      if r.is_virtual_key(hkey) || r.has_key(hkey, key) {
        ERROR_FILE_NOT_FOUND
      } else {
        real_reg_get_value_w(hkey, subkey, value, flags, typ, data, size)
      }
  }
}

///|
#export_name("lp_reg_create_key_ex_w")
pub fn thunk_reg_create_key_ex_w(
  hkey : Int64,
  subkey : Int64,
  reserved : Int32,
  class : Int64,
  options : Int32,
  sam : Int32,
  sa : Int64,
  result : Int64,
  disposition : Int64,
) -> Int32 {
  hit("RegCreateKeyExW")
  let r = state_reg()
  let name = wide_to_string(subkey)
  log_reg(
    "create",
    hkey.to_string() +
    " " +
    name +
    " claim=" +
    (if r.claims(hkey, name) { "1" } else { "0" }),
  )
  // A link is a different object in the real registry; leave those alone.
  if (options & REG_OPTION_OPEN_LINK) != 0 || !r.claims(hkey, name) {
    return real_reg_create_key_ex_w(
      hkey, subkey, reserved, class, options, sam, sa, result, disposition,
    )
  }
  match r.create_key(hkey, name) {
    Some((h, existed)) => {
      if result != 0L {
        poke_bytes(result, u64le(h), 8)
      }
      put32(
        disposition,
        if existed {
          REG_OPENED_EXISTING_KEY
        } else {
          REG_CREATED_NEW_KEY
        },
      )
      ERROR_SUCCESS
    }
    None =>
      real_reg_create_key_ex_w(
        hkey, subkey, reserved, class, options, sam, sa, result, disposition,
      )
  }
}

///|
#export_name("lp_reg_create_key_ex_a")
pub fn thunk_reg_create_key_ex_a(
  hkey : Int64,
  subkey : Int64,
  reserved : Int32,
  class : Int64,
  options : Int32,
  sam : Int32,
  sa : Int64,
  result : Int64,
  disposition : Int64,
) -> Int32 {
  hit("RegCreateKeyExA")
  let r = state_reg()
  let name = ansi_to_string(subkey)
  if (options & REG_OPTION_OPEN_LINK) != 0 || !r.claims(hkey, name) {
    return real_reg_create_key_ex_a(
      hkey, subkey, reserved, class, options, sam, sa, result, disposition,
    )
  }
  match r.create_key(hkey, name) {
    Some((h, existed)) => {
      if result != 0L {
        poke_bytes(result, u64le(h), 8)
      }
      put32(
        disposition,
        if existed {
          REG_OPENED_EXISTING_KEY
        } else {
          REG_CREATED_NEW_KEY
        },
      )
      ERROR_SUCCESS
    }
    None =>
      real_reg_create_key_ex_a(
        hkey, subkey, reserved, class, options, sam, sa, result, disposition,
      )
  }
}

///|
#export_name("lp_reg_open_key_ex_a")
pub fn thunk_reg_open_key_ex_a(
  hkey : Int64,
  subkey : Int64,
  options : Int32,
  sam : Int32,
  result : Int64,
) -> Int32 {
  hit("RegOpenKeyExA")
  let r = state_reg()
  match r.open_key(hkey, ansi_to_string(subkey)) {
    Some(h) => {
      if result != 0L {
        poke_bytes(result, u64le(h), 8)
      }
      ERROR_SUCCESS
    }
    None => real_reg_open_key_ex_a(hkey, subkey, options, sam, result)
  }
}

///|
#export_name("lp_reg_delete_key_w")
pub fn thunk_reg_delete_key_w(hkey : Int64, subkey : Int64) -> Int32 {
  hit("RegDeleteKeyW")
  let r = state_reg()
  let name = wide_to_string(subkey)
  if r.claims(hkey, name) {
    if r.delete_key(hkey, name) {
      return ERROR_SUCCESS
    }
    // Claimed but absent: the real registry cannot do better.
    return ERROR_FILE_NOT_FOUND
  }
  real_reg_delete_key_w(hkey, subkey)
}

///|
#export_name("lp_reg_delete_key_a")
pub fn thunk_reg_delete_key_a(hkey : Int64, subkey : Int64) -> Int32 {
  hit("RegDeleteKeyA")
  let r = state_reg()
  let name = ansi_to_string(subkey)
  if r.claims(hkey, name) {
    if r.delete_key(hkey, name) {
      return ERROR_SUCCESS
    }
    return ERROR_FILE_NOT_FOUND
  }
  real_reg_delete_key_a(hkey, subkey)
}

///|
#export_name("lp_reg_delete_value_w")
pub fn thunk_reg_delete_value_w(hkey : Int64, name : Int64) -> Int32 {
  hit("RegDeleteValueW")
  let r = state_reg()
  if r.is_virtual_key(hkey) {
    if r.delete_value(hkey, wide_to_string(name)) {
      return ERROR_SUCCESS
    }
    return ERROR_FILE_NOT_FOUND
  }
  real_reg_delete_value_w(hkey, name)
}

///|
#export_name("lp_reg_enum_key_ex_w")
pub fn thunk_reg_enum_key_ex_w(
  hkey : Int64,
  index : Int32,
  name : Int64,
  cch : Int64,
  reserved : Int64,
  class : Int64,
  cch_class : Int64,
  last_write : Int64,
) -> Int32 {
  hit("RegEnumKeyExW")
  let r = state_reg()
  match r.enum_key(hkey, index) {
    Some(k) => {
      put32(cch_class, 0)
      emit_wide_string(k, name, cch)
    }
    None =>
      if r.is_virtual_key(hkey) {
        ERROR_NO_MORE_ITEMS
      } else {
        real_reg_enum_key_ex_w(
          hkey, index, name, cch, reserved, class, cch_class, last_write,
        )
      }
  }
}

///|
#export_name("lp_reg_enum_value_w")
pub fn thunk_reg_enum_value_w(
  hkey : Int64,
  index : Int32,
  name : Int64,
  cch : Int64,
  reserved : Int64,
  typ : Int64,
  data : Int64,
  cb : Int64,
) -> Int32 {
  hit("RegEnumValueW")
  let r = state_reg()
  match r.enum_value_at(hkey, index) {
    Some((n, v)) => {
      let st = emit_wide_string(n, name, cch)
      if st != ERROR_SUCCESS {
        return st
      }
      emit_value(v, typ, data, cb)
    }
    None =>
      if r.is_virtual_key(hkey) {
        ERROR_NO_MORE_ITEMS
      } else {
        real_reg_enum_value_w(hkey, index, name, cch, reserved, typ, data, cb)
      }
  }
}

///|
#export_name("lp_reg_query_info_key_w")
pub fn thunk_reg_query_info_key_w(
  hkey : Int64,
  class : Int64,
  cch_class : Int64,
  reserved : Int64,
  subkeys : Int64,
  max_subkey : Int64,
  max_class : Int64,
  values : Int64,
  max_value_name : Int64,
  max_value_data : Int64,
  sec_desc : Int64,
  last_write : Int64,
) -> Int32 {
  hit("RegQueryInfoKeyW")
  let r = state_reg()
  match r.info(hkey) {
    Some((n_sub, m_key, n_val, m_name, m_data)) => {
      put32(cch_class, 0)
      put32(subkeys, n_sub)
      put32(max_subkey, m_key)
      put32(max_class, 0)
      put32(values, n_val)
      put32(max_value_name, m_name)
      put32(max_value_data, m_data)
      put32(sec_desc, 0)
      if last_write != 0L {
        poke_filetime(last_write, 0L)
      }
      ERROR_SUCCESS
    }
    None =>
      real_reg_query_info_key_w(
        hkey, class, cch_class, reserved, subkeys, max_subkey, max_class, values,
        max_value_name, max_value_data, sec_desc, last_write,
      )
  }
}

///|
/// Six L5.1 counters: opens, creates, enumerations, deletes, queries and
/// writes served from the hive. The checks read them to prove that a
/// registration ran through the hive and not the real registry.
#export_name("lp_reg_stats")
pub fn lp_reg_stats(out : Int64, cap : Int32) -> Int32 {
  if out == 0L || cap < 24 {
    return -1
  }
  let r = state_reg()
  let vals : Array[Int64] = [
    r.calls_open.to_int64(),
    r.calls_create.to_int64(),
    r.calls_enum.to_int64(),
    r.calls_delete.to_int64(),
    r.calls_query.to_int64(),
    r.calls_write.to_int64(),
  ]
  // The rest of the stats ABI is 32-bit words, so these are too.
  let n = if cap / 4 < vals.length() { cap / 4 } else { vals.length() }
  for i = 0; i < n; i = i + 1 {
    poke_bytes(out + (i * 4).to_int64(), u32le(vals[i]), 4)
  }
  n
}

///|
/// Record one registry path request. Bounded, because a running application can
/// ask about thousands of keys and only the recent ones matter when a lookup
/// fails.
fn log_reg(kind : String, detail : String) -> Unit {
  if g_runtime.reg_log.length() >= 128 {
    return
  }
  g_runtime.reg_log.push(kind + " " + detail)
}

///|
/// Start a new phase of the log. A long run fills the bound quickly -- COM
/// activation alone asks about dozens of keys -- and what a caller wants after
/// that is what happened *in the phase it just entered*, not the tail of the
/// one before it.
#export_name("lp_reg_log_reset")
pub fn lp_reg_log_reset() -> Unit {
  g_runtime.reg_log.clear()
}

///|
#export_name("lp_reg_log_count")
pub fn lp_reg_log_count() -> Int32 {
  g_runtime.reg_log.length()
}

///|
#export_name("lp_reg_log_get")
pub fn lp_reg_log_get(i : Int32, out : Int64, cap : Int32) -> Int32 {
  if i < 0 || i >= g_runtime.reg_log.length() || out == 0L || cap <= 0 {
    return -1
  }
  let s = g_runtime.reg_log[i]
  let n = if s.length() < cap - 1 { s.length() } else { cap - 1 }
  poke_bytes(out, ascii_bytes(str_slice(s, 0, n)), n)
  poke_bytes(out + n.to_int64(), Bytes::make(1, b'\x00'), 1)
  n
}
