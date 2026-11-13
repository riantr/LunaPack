// In-memory registry hive.
//
// The point of virtualizing the registry is that a packaged application may
// write to HKLM without administrator rights: the write lands in this hive,
// never in the real registry. Keys that are not virtual fall through to the
// real Win32 API.

///|
const HKEY_CLASSES_ROOT : Int64 = 0x80000000L

///|
const HKEY_CURRENT_USER : Int64 = 0x80000001L

///|
const HKEY_LOCAL_MACHINE : Int64 = 0x80000002L

///|
const HKEY_USERS : Int64 = 0x80000003L

///|
const REG_SZ : Int32 = 1

///|
const REG_BINARY : Int32 = 3

///|
const REG_DWORD : Int32 = 4

///|
const ERROR_MORE_DATA : Int32 = 234

///|
pub struct RegValue {
  typ : Int32
  data : Bytes
}

///|
pub struct VirtualRegistry {
  values : Map[String, RegValue]
  keys : Map[String, Unit]
  handles : Map[Int64, String]
  mut next_handle : Int64
  mut calls_query : Int32
  mut calls_write : Int32
}

///|
pub fn VirtualRegistry::new() -> VirtualRegistry {
  {
    values: {},
    keys: {},
    handles: {},
    next_handle: 0x4C600000L,
    calls_query: 0,
    calls_write: 0,
  }
}

///|
fn root_name(root : Int64) -> String? {
  let low = root & 0xFFFFFFFFL
  if low == HKEY_LOCAL_MACHINE {
    Some("hklm")
  } else if low == HKEY_CURRENT_USER {
    Some("hkcu")
  } else if low == HKEY_CLASSES_ROOT {
    Some("hkcr")
  } else if low == HKEY_USERS {
    Some("hku")
  } else {
    None
  }
}

///|
fn value_key(key : String, name : String) -> String {
  key + "::" + name.to_lower()
}

///|
fn add_key_ancestors(r : VirtualRegistry, key : String) -> Unit {
  let mut k = key
  while k.length() > 0 {
    r.keys.set(k, ())
    k = parent_dir(k)
  }
}

///|
/// Resolve an HKEY (either a Win32 pseudo-handle or one of our own handles)
/// plus a subkey to a normalized hive path.
fn full_key(r : VirtualRegistry, hkey : Int64, subkey : String) -> String? {
  let base = match r.handles.get(hkey) {
    Some(k) => k
    None =>
      match root_name(hkey) {
        Some(n) => n
        None => return None
      }
  }
  let s = norm_path(subkey)
  if s.length() == 0 {
    Some(base)
  } else {
    Some(base + "/" + s)
  }
}

///|
pub fn VirtualRegistry::open_key(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
) -> Int64? {
  let k = match full_key(self, hkey, subkey) {
    Some(x) => x
    None => return None
  }
  if !self.keys.contains(k) {
    return None
  }
  let h = self.next_handle
  self.next_handle = self.next_handle + 1L
  self.handles.set(h, k)
  Some(h)
}

///|
pub fn VirtualRegistry::query_value(
  self : VirtualRegistry,
  hkey : Int64,
  name : String,
) -> RegValue? {
  match self.handles.get(hkey) {
    None => None
    Some(k) => {
      self.calls_query = self.calls_query + 1
      self.values.get(value_key(k, name))
    }
  }
}

///|
/// Record a value. `hkey` may be a root pseudo-handle, so callers can seed
/// the hive before any key is opened.
pub fn VirtualRegistry::set_value(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
  name : String,
  typ : Int32,
  data : Bytes,
) -> Bool {
  let k = match full_key(self, hkey, subkey) {
    Some(x) => x
    None => return false
  }
  self.calls_write = self.calls_write + 1
  add_key_ancestors(self, k)
  self.values.set(value_key(k, name), { typ, data, })
  true
}

///|
pub fn VirtualRegistry::is_virtual_key(
  self : VirtualRegistry,
  hkey : Int64,
) -> Bool {
  self.handles.contains(hkey)
}

///|
pub fn VirtualRegistry::close_key(self : VirtualRegistry, hkey : Int64) -> Bool {
  if !self.handles.contains(hkey) {
    return false
  }
  self.handles.remove(hkey)
  true
}
