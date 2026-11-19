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
  // L5.1: a component that registers itself walks the key tree, so the hive
  // has to answer "how many subkeys", "give me the fourth one" and "delete
  // this key". These counters make that traffic visible to the checks.
  mut calls_open : Int32
  mut calls_create : Int32
  mut calls_enum : Int32
  mut calls_delete : Int32
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
    calls_open: 0,
    calls_create: 0,
    calls_enum: 0,
    calls_delete: 0,
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
/// Both `HKLM\Software\Classes` and `HKCU\Software\Classes` are the same
/// namespace as `HKCR`, so the hive keeps one copy under `hkcr`. A component
/// may register into either spelling and be activated through the third; this
/// makes all three land on the same key.
fn canonical(k : String) -> String {
  let machine = "hklm/software/classes"
  let user = "hkcu/software/classes"
  if k == machine || k == user {
    "hkcr"
  } else if k.has_prefix(machine + "/") {
    "hkcr/" + str_slice(k, machine.length() + 1, k.length())
  } else if k.has_prefix(user + "/") {
    "hkcr/" + str_slice(k, user.length() + 1, k.length())
  } else {
    k
  }
}

///|
/// Resolve an HKEY (either a Win32 pseudo-handle or one of our own handles)
/// plus a subkey to a normalized hive path.
fn full_key(r : VirtualRegistry, hkey : Int64, subkey : String) -> String? {
  let base = match base_key_path(r, hkey) {
    Some(k) => k
    None => return None
  }
  let s = norm_path(subkey)
  if s.length() == 0 {
    Some(canonical(base))
  } else {
    Some(canonical(base + "/" + s))
  }
}

///|
/// Reserved for the one native call the runtime makes on its own behalf.
const NT_SCRATCH_SIZE : Int32 = 4096

///|
/// Ask Windows what a real key handle points at. A runtime that has already
/// opened `HKCR\CLSID` before our hooks went in passes that handle back to us
/// for a relative open; without translation the lookup cannot be answered, and
/// the class database would fall through to the real registry.
fn nt_key_name(hkey : Int64) -> String? {
  let scratch = nt_scratch()
  if scratch == 0L {
    return None
  }
  // scratch+0 holds the returned length, scratch+8 the KEY_NAME_INFORMATION
  // header (a name length) followed by the name itself.
  let st = nt_query_key(
    hkey,
    KEY_NAME_INFORMATION_CLASS,
    scratch + 8L,
    NT_SCRATCH_SIZE - 8,
    scratch,
  )
  if st < 0 {
    return None
  }
  let mut len = peek32(scratch + 8L).to_int()
  if len < 2 || len > NT_SCRATCH_SIZE - 14 {
    return None
  }
  // The reported length counts the terminator, and callers compare paths, so
  // trim it here rather than in every comparison.
  while len >= 2 && peek16(scratch + 12L + (len - 2).to_int64()) == 0 {
    len = len - 2
  }
  Some(wide_exact(scratch + 12L, len))
}

///|
/// Turn a native registry path into a hive path:
/// `\REGISTRY\MACHINE\SOFTWARE\CLASSES\CLSID` -> `hkcr/clsid`.
fn translate_native(native : String) -> String? {
  let p = native.replace_all(old="\\", new="/").to_lower()
  let machine_classes = "/registry/machine/software/classes"
  let machine = "/registry/machine"
  if p == machine_classes {
    return Some("hkcr")
  }
  if p.has_prefix(machine_classes + "/") {
    return Some(
      "hkcr/" + str_slice(p, machine_classes.length() + 1, p.length()),
    )
  }
  if p == machine {
    return Some("hklm")
  }
  if p.has_prefix(machine + "/") {
    return Some("hklm/" + str_slice(p, machine.length() + 1, p.length()))
  }
  let user = "/registry/user/"
  if p.has_prefix(user) {
    // `...\<sid>_Classes` is the per-user classes root; anything else under a
    // user hive is treated as HKCU, which is close enough for a fall-through
    // path we only use when the hive has no answer of its own.
    let rest = str_slice(p, user.length(), p.length())
    let mut i = rest.length() - 1
    while i >= 0 {
      if rest[i] == '/' {
        let leaf = str_slice(rest, 0, i)
        let classes = str_slice(rest, i + 1, rest.length())
        if leaf.has_suffix("_classes") {
          if classes.length() == 0 {
            return Some("hkcr")
          }
          return Some("hkcr/" + classes)
        }
        break
      }
      i = i - 1
    }
    if rest.has_suffix("_classes") {
      return Some("hkcr")
    }
    return Some("hkcu/" + rest)
  }
  None
}

///|
/// The hive path a handle stands for: one of ours, a root constant, or a real
/// handle translated through the kernel.
fn base_key_path(r : VirtualRegistry, hkey : Int64) -> String? {
  match r.handles.get(hkey) {
    Some(k) => Some(k)
    None =>
      match root_name(hkey) {
        Some(n) => Some(n)
        None => {
          // A real key handle is a small integer on modern Windows, so there
          // is nothing to sanity-check here; an invalid handle simply fails
          // the query and the call falls through to the real API.
          if hkey == 0L {
            return None
          }
          match nt_key_name(hkey) {
            Some(native) => {
              let mapped = translate_native(native)
              log_reg(
                "base",
                native + " -> " + (if mapped is Some(p) { p } else { "?" }),
              )
              mapped
            }
            None => {
              log_reg("ntfail", hkey.to_string())
              None
            }
          }
        }
      }
  }
}

///|
/// The hive path for `hkey` + `subkey`, but only when the hive actually holds
/// it. Used by every read path so an HKCR lookup finds machine or user classes.
pub fn VirtualRegistry::resolve_existing(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
) -> String? {
  let k = match full_key(self, hkey, subkey) {
    Some(x) => x
    None => return None
  }
  if self.keys.contains(k) {
    Some(k)
  } else {
    None
  }
}

///|
fn VirtualRegistry::make_handle(self : VirtualRegistry, k : String) -> Int64 {
  let h = self.next_handle
  self.next_handle = self.next_handle + 1L
  self.handles.set(h, k)
  h
}

///|
pub fn VirtualRegistry::open_key(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
) -> Int64? {
  match self.resolve_existing(hkey, subkey) {
    Some(k) => {
      self.calls_open = self.calls_open + 1
      Some(self.make_handle(k))
    }
    None => None
  }
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

// ------------------------------------------------------- L5.1: COM keys ---
//
// A COM component registers itself by creating a key tree and writing values
// into it, then gets activated by a read of that same tree. Both directions
// have to land in this hive, or registration needs administrator rights and
// CoCreateInstance looks at the real registry instead.

///|
/// Keys the hive owns on sight, before anything was written. Registration
/// targets HKCR (the merged classes view) or one of the two Classes subtrees;
/// claiming those is what makes a per-machine registration work without
/// administrator rights. Everything else still falls through to the real
/// registry, so an application that reads machine state keeps seeing it.
fn claimed_path(k : String) -> Bool {
  k == "hkcr" ||
  k.has_prefix("hkcr/") ||
  k == "hklm/software/classes" ||
  k.has_prefix("hklm/software/classes/") ||
  k == "hkcu/software/classes" ||
  k.has_prefix("hkcu/software/classes/")
}

///|
/// Should a write to this key be served by the hive? True when the hive already
/// holds the key or it is inside a claimed subtree.
pub fn VirtualRegistry::claims(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
) -> Bool {
  match full_key(self, hkey, subkey) {
    None => false
    Some(k) => self.keys.contains(k) || claimed_path(k)
  }
}

///|
/// Create a key in the hive and return an open handle. Anchors are added so a
/// later open of a parent still succeeds.
pub fn VirtualRegistry::create_key(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
) -> (Int64, Bool)? {
  let k = match full_key(self, hkey, subkey) {
    Some(x) => x
    None => return None
  }
  let existed = self.keys.contains(k)
  self.calls_create = self.calls_create + 1
  add_key_ancestors(self, k)
  Some((self.make_handle(k), existed))
}

///|
/// Does the hive hold this key?
pub fn VirtualRegistry::has_key(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
) -> Bool {
  self.resolve_existing(hkey, subkey) is Some(_)
}

///|
/// Immediate children of a hive key, sorted so repeated enumeration agrees
/// with itself. `RegEnumKeyExW` walks these by index.
fn VirtualRegistry::child_keys(
  self : VirtualRegistry,
  k : String,
) -> Array[String] {
  let out : Array[String] = []
  self.keys.each(fn(one, _v) {
    if one != k && parent_dir(one) == k {
      out.push(basename(one))
    }
  })
  out.sort()
  out
}

///|
/// Value names held under a hive key, sorted. The unnamed default value has the
/// name "" and sorts first, which is how Windows enumerates it too.
fn VirtualRegistry::value_names(
  self : VirtualRegistry,
  k : String,
) -> Array[String] {
  let prefix = k + "::"
  let out : Array[String] = []
  self.values.each(fn(one, _v) {
    if one.has_prefix(prefix) {
      out.push(str_slice(one, prefix.length(), one.length()))
    }
  })
  out.sort()
  out
}

///|
/// Read a value by path, so a caller holding only a root handle (COM activation
/// through HKCR) reaches the hive without opening the key first.
pub fn VirtualRegistry::read_value(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
  name : String,
) -> RegValue? {
  let k = match self.resolve_existing(hkey, subkey) {
    Some(x) => x
    None => return None
  }
  match self.values.get(value_key(k, name)) {
    Some(v) => {
      self.calls_query = self.calls_query + 1
      Some(v)
    }
    None => {
      log_reg("vmiss", k + " [" + name + "]")
      None
    }
  }
}

///|
pub fn VirtualRegistry::enum_key(
  self : VirtualRegistry,
  hkey : Int64,
  i : Int32,
) -> String? {
  match self.handles.get(hkey) {
    None => None
    Some(k) => {
      let kids = self.child_keys(k)
      if i < 0 || i >= kids.length() {
        return None
      }
      self.calls_enum = self.calls_enum + 1
      Some(kids[i])
    }
  }
}

///|
pub fn VirtualRegistry::enum_value_at(
  self : VirtualRegistry,
  hkey : Int64,
  i : Int32,
) -> (String, RegValue)? {
  match self.handles.get(hkey) {
    None => None
    Some(k) => {
      let names = self.value_names(k)
      if i < 0 || i >= names.length() {
        return None
      }
      match self.values.get(value_key(k, names[i])) {
        None => None
        Some(v) => {
          self.calls_enum = self.calls_enum + 1
          Some((names[i], v))
        }
      }
    }
  }
}

///|
/// `RegQueryInfoKey` answers four numbers we can compute: subkeys, the longest
/// subkey name, values, and the longest value name. Class, security descriptor
/// and last-write time are reported as empty, which is what a component that
/// only enumerates its own registration reads.
pub fn VirtualRegistry::info(
  self : VirtualRegistry,
  hkey : Int64,
) -> (Int32, Int32, Int32, Int32, Int32)? {
  match self.handles.get(hkey) {
    None => None
    Some(k) => {
      let kids = self.child_keys(k)
      let names = self.value_names(k)
      let mut max_key = 0
      for i = 0; i < kids.length(); i = i + 1 {
        if kids[i].length() > max_key {
          max_key = kids[i].length()
        }
      }
      let mut max_name = 0
      for i = 0; i < names.length(); i = i + 1 {
        if names[i].length() > max_name {
          max_name = names[i].length()
        }
      }
      let mut max_data = 0
      for i = 0; i < names.length(); i = i + 1 {
        match self.values.get(value_key(k, names[i])) {
          Some(v) =>
            if v.data.length() > max_data {
              max_data = v.data.length()
            }
          None => ()
        }
      }
      Some((kids.length(), max_key, names.length(), max_name, max_data))
    }
  }
}

///|
/// Remove a key and everything below it, including its values and any open
/// handle that pointed at it.
pub fn VirtualRegistry::delete_key(
  self : VirtualRegistry,
  hkey : Int64,
  subkey : String,
) -> Bool {
  let k = match full_key(self, hkey, subkey) {
    Some(x) => x
    None => return false
  }
  if !self.keys.contains(k) {
    return false
  }
  self.calls_delete = self.calls_delete + 1
  let under = k + "/"
  let val_under = k + "::"
  self.keys.retain(fn(one, _v) { one != k && !one.has_prefix(under) })
  self.values.retain(fn(one, _v) {
    !one.has_prefix(val_under) && !one.has_prefix(under)
  })
  let dead : Array[Int64] = []
  self.handles.each(fn(h, one) {
    if one == k || one.has_prefix(under) {
      dead.push(h)
    }
  })
  for i = 0; i < dead.length(); i = i + 1 {
    self.handles.remove(dead[i])
  }
  true
}

///|
pub fn VirtualRegistry::delete_value(
  self : VirtualRegistry,
  hkey : Int64,
  name : String,
) -> Bool {
  let k = match self.handles.get(hkey) {
    Some(x) => x
    None => return false
  }
  let vk = value_key(k, name)
  if !self.values.contains(vk) {
    return false
  }
  self.calls_delete = self.calls_delete + 1
  self.values.remove(vk)
  true
}

// ---------------------------------------------- L5: paths for the ntdll layer ---
//
// The Win32 registry API hands a caller an opaque handle and takes it straight
// back. The native API does the same, but it is also how a component that
// resolves NtOpenKey itself walks the class tree, so the hive has to answer in
// the same terms. These three helpers work on an already-resolved hive path.

///|
pub fn VirtualRegistry::contains_path(
  self : VirtualRegistry,
  k : String,
) -> Bool {
  self.keys.contains(k)
}

///|
pub fn VirtualRegistry::handle_for(self : VirtualRegistry, k : String) -> Int64 {
  self.calls_open = self.calls_open + 1
  self.make_handle(k)
}

///|
pub fn VirtualRegistry::value_in_path(
  self : VirtualRegistry,
  k : String,
  name : String,
) -> RegValue? {
  self.calls_query = self.calls_query + 1
  self.values.get(value_key(k, name))
}
