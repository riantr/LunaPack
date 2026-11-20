// Type-library entry points for a component in the archive (L5.6).
//
// `RegisterTypeLib` is where a self-registering COM server stops working under
// manual mapping. The server calls `LoadTypeLibEx` on its own path, oleaut32
// tries to open that file, and there is no file: the module only ever existed
// inside the archive. Without a type library the registration aborts, and an
// aborted registration means no `InprocServer32`, which means no activation.
//
// The runtime answers the three questions involved:
//
//   * `LoadTypeLibEx` / `LoadTypeLib` on a virtual path return an `ITypeLib`
//     object of ours, backed by the TYPELIB resource parsed out of the image.
//   * `RegisterTypeLib` on one of our objects writes the library's keys into
//     the in-memory hive. Nothing is written to the real registry, so no
//     administrator rights are involved.
//   * `LoadRegTypeLib` on a library registered this way returns the same
//     object, so a program can load back what it registered even though the
//     bytes are still only in memory.
//
// The object is a real COM object with a real vtable: a component may QueryInterface,
// AddRef, call GetTypeInfoCount / GetTypeInfoType / GetLibAttr on it and
// Release it. Methods that would need an `ITypeInfo` per type are not
// implemented and answer E_NOTIMPL; that is written down in runtime/README.md
// rather than papered over, because a caller that needs them is asking for
// something this runtime does not provide.

///|
const S_OK : Int32 = 0

///|
const E_NOTIMPL : Int32 = 0x80004001

///|
const E_NOINTERFACE : Int32 = 0x80004002

///|
const E_POINTER : Int32 = 0x80004003

///|
const E_FAIL : Int32 = 0x80004005

///|
const E_OUTOFMEMORY : Int32 = 0x8007000E

///|
/// A type index past the end of the library.
const DISP_E_BADINDEX : Int32 = -2147352565

///|
/// `REGKIND_REGISTER`, the one `LoadTypeLibEx` mode that also registers. The
/// enum is `REGKIND_DEFAULT = 0`, `REGKIND_REGISTER = 1`, `REGKIND_NONE = 2`:
/// the "none" mode is the *highest* value, not zero, and a check written
/// against a guessed `0 / 1` ordering registers on every plain load.
const REGKIND_REGISTER : Int32 = 1

///|
/// The universal proxy for an oleautomation interface, which is what a
/// registration stores for `ProxyStubClsid32`.
const PSOA_INTERFACE : String = "{00020420-0000-0000-C000-000000000046}"

// ------------------------------------------------------------- real APIs ---

///|
extern "C" fn real_load_typelib_ex(
  path : Int64,
  regkind : Int32,
  out : Int64,
) -> Int32 = "LoadTypeLibEx"

///|
extern "C" fn real_load_typelib(path : Int64, out : Int64) -> Int32 = "LoadTypeLib"

///|
extern "C" fn real_register_typelib(
  tlb : Int64,
  path : Int64,
  help_dir : Int64,
) -> Int32 = "RegisterTypeLib"

///|
extern "C" fn real_register_typelib_for_user(
  tlb : Int64,
  path : Int64,
  help_dir : Int64,
) -> Int32 = "RegisterTypeLibForUser"

///|
extern "C" fn real_unregister_typelib(
  libid : Int64,
  major : Int32,
  minor : Int32,
  lcid : Int32,
  syskind : Int32,
) -> Int32 = "UnRegisterTypeLib"

///|
extern "C" fn real_unregister_typelib_for_user(
  libid : Int64,
  major : Int32,
  minor : Int32,
  lcid : Int32,
  syskind : Int32,
) -> Int32 = "UnRegisterTypeLibForUser"

///|
extern "C" fn real_load_reg_typelib(
  libid : Int64,
  major : Int32,
  minor : Int32,
  lcid : Int32,
  out : Int64,
) -> Int32 = "LoadRegTypeLib"

// ------------------------------------------------------- the ITypeLib stub ---

///|
/// The vtable of the object we hand to a caller. The entries are our own
/// exported functions, addressed through lpvirt.dll's export directory — the
/// same mechanism the IAT patcher uses to find a thunk.
fn typelib_vtable() -> Int64 {
  if g_runtime.typelib_vtable == 0L {
    let names : Array[String] = [
      "lp_tl_query_interface", "lp_tl_add_ref", "lp_tl_release", "lp_tl_type_info_count",
      "lp_tl_type_info", "lp_tl_type_info_type", "lp_tl_type_info_of_guid", "lp_tl_get_lib_attr",
      "lp_tl_get_documentation", "lp_tl_find_name", "lp_tl_is_name", "lp_tl_type_comp",
      "lp_tl_release_tl_attr",
    ]
    let vt = virtual_alloc(
      0L,
      (names.length() * 8).to_int64(),
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE,
    )
    if vt == 0L {
      return 0L
    }
    let mut i = 0
    while i < names.length() {
      poke64(vt + (i * 8).to_int64(), thunk_address(names[i]))
      i = i + 1
    }
    g_runtime.typelib_vtable = vt
  }
  g_runtime.typelib_vtable
}

///|
/// A library object: vtable, reference count, index into the parsed libraries,
/// and a lazily created TLIBATTR buffer. The index is what `RegisterTypeLib`
/// uses to find the parsed library again, so a foreign ITypeLib — one the real
/// oleaut32 made — is recognised by the vtable pointer and falls through.
fn new_typelib_object(info : TypeLibInfo) -> Int64 {
  g_runtime.typelibs.push(info)
  let index = g_runtime.typelibs.length() - 1
  let obj = virtual_alloc(0L, 32L, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
  if obj == 0L {
    return 0L
  }
  poke64(obj, typelib_vtable())
  poke_bytes(obj + 8L, u32le(1L), 4)
  poke_bytes(obj + 12L, u32le(index.to_int64()), 4)
  poke64(obj + 16L, 0L)
  obj
}

///|
/// The library behind one of our objects, or None if the pointer is not ours.
fn typelib_of(obj : Int64) -> TypeLibInfo? {
  if obj == 0L || typelib_vtable() == 0L {
    return None
  }
  if peek64(obj) != typelib_vtable() {
    return None
  }
  let index = peek32(obj + 12L).to_int()
  if index < 0 || index >= g_runtime.typelibs.length() {
    return None
  }
  Some(g_runtime.typelibs[index])
}

///|
fn iid_is(riid : Int64, lo : Int64, hi : Int64) -> Bool {
  riid != 0L && peek64(riid) == lo && peek64(riid + 8L) == hi
}

///|
#export_name("lp_tl_query_interface")
pub fn tl_query_interface(this : Int64, riid : Int64, out : Int64) -> Int32 {
  if out == 0L {
    return E_POINTER
  }
  poke64(out, 0L)
  if typelib_of(this) is None {
    return E_NOINTERFACE
  }
  // IUnknown and ITypeLib share the tail; ITypeLib2 is refused rather than
  // answered with a vtable that has no entries for its extra methods.
  let tail = 0x46000000000000C0L
  if iid_is(riid, 0x0000000000000000L, tail) {
    poke64(out, this)
    ignore(tl_add_ref(this))
    return S_OK
  }
  if iid_is(riid, 0x0000000000020402L, tail) {
    poke64(out, this)
    ignore(tl_add_ref(this))
    return S_OK
  }
  E_NOINTERFACE
}

///|
#export_name("lp_tl_add_ref")
pub fn tl_add_ref(this : Int64) -> Int32 {
  if this == 0L {
    return 0
  }
  let n = peek32(this + 8L) + 1L
  poke_bytes(this + 8L, u32le(n), 4)
  n.to_int()
}

///|
#export_name("lp_tl_release")
pub fn tl_release(this : Int64) -> Int32 {
  if this == 0L {
    return 0
  }
  let n = peek32(this + 8L) - 1L
  poke_bytes(this + 8L, u32le(n), 4)
  if n <= 0L {
    let attr = peek64(this + 16L)
    if attr != 0L {
      ignore(virtual_free(attr, 0L, MEM_RELEASE))
    }
    ignore(virtual_free(this, 0L, MEM_RELEASE))
  }
  n.to_int()
}

///|
#export_name("lp_tl_type_info_count")
pub fn tl_get_type_info_count(this : Int64, out : Int64) -> Int32 {
  if out == 0L {
    return E_POINTER
  }
  match typelib_of(this) {
    Some(info) => {
      poke_bytes(out, u32le(info.types.length().to_int64()), 4)
      S_OK
    }
    None => E_FAIL
  }
}

///|
#export_name("lp_tl_type_info_type")
pub fn tl_get_type_info_type(this : Int64, index : Int32, out : Int64) -> Int32 {
  if out == 0L {
    return E_POINTER
  }
  match typelib_of(this) {
    Some(info) => {
      let i = index.to_int()
      if i < 0 || i >= info.types.length() {
        return DISP_E_BADINDEX
      }
      poke_bytes(out, u32le(info.types[i].kind.to_int64()), 4)
      S_OK
    }
    None => E_FAIL
  }
}

///|
#export_name("lp_tl_get_lib_attr")
pub fn tl_get_lib_attr(this : Int64, out : Int64) -> Int32 {
  if out == 0L {
    return E_POINTER
  }
  match typelib_of(this) {
    Some(info) => {
      let mut attr = peek64(this + 16L)
      if attr == 0L {
        attr = virtual_alloc(0L, 32L, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if attr == 0L {
          return E_OUTOFMEMORY
        }
        poke64(this + 16L, attr)
        let g = guid_bytes(info.libid)
        if g.length() == 16 {
          poke_bytes(attr, g, 16)
        }
        poke_bytes(attr + 16L, u32le(info.lcid.to_int64()), 4)
        poke_bytes(attr + 20L, u32le(info.syskind.to_int64()), 4)
        poke_bytes(attr + 24L, u32le(info.major.to_int64()), 2)
        poke_bytes(attr + 26L, u32le(info.minor.to_int64()), 2)
        poke_bytes(attr + 28L, u32le(info.flags.to_int64()), 2)
        poke_bytes(attr + 30L, u32le(0L), 2)
      }
      poke64(out, attr)
      S_OK
    }
    None => E_FAIL
  }
}

// ------------------------------------------------------------- loads ---

///|
/// Parse a type library out of a virtual file and adopt it. None means "not
/// ours": the path is not in the archive, or the bytes are not a type library,
/// and the caller falls through to the real API.
fn adopt_typelib(path : String) -> Int64? {
  if path == "" {
    return None
  }
  let data = match state_vfs().read_file(path) {
    Some(d) => d
    None =>
      // Not in the archive: the real API gets its turn, exactly as before.
      return None
  }
  match typelib_from_image(data) {
    None => {
      // The path was virtual, so the real API would only fail on a file that
      // cannot exist. Say why the bytes were not usable, then fall through.
      log_reg(
        "tlb-noparse",
        path +
        " size=" +
        data.length().to_string() +
        " head=" +
        (if data.length() >= 2 {
          data[0].to_int().to_string() + "," + data[1].to_int().to_string()
        } else {
          "?"
        }),
      )
      None
    }
    Some(i) => {
      let obj = new_typelib_object(i)
      if obj == 0L {
        return None
      }
      g_runtime.typelibs_loaded = g_runtime.typelibs_loaded + 1
      log_reg(
        "typelib-load",
        path + " id=" + i.libid + " types=" + i.types.length().to_string(),
      )
      Some(obj)
    }
  }
}

///|
/// The methods below need a full `ITypeInfo` per type, which this runtime does
/// not provide: it parses what a registration writes and nothing more. They say
/// so instead of returning a plausible-looking empty answer. Parameters that go
/// unread are named because the vtable shape requires them, not because
/// anything is forgotten, so each one is explicitly ignored.
#export_name("lp_tl_type_info")
pub fn tl_get_type_info(this : Int64, index : Int32, out : Int64) -> Int32 {
  ignore(this)
  ignore(index)
  if out == 0L {
    return E_POINTER
  }
  poke64(out, 0L)
  E_NOTIMPL
}

///|
#export_name("lp_tl_type_info_of_guid")
pub fn tl_get_type_info_of_guid(
  this : Int64,
  guid : Int64,
  out : Int64,
) -> Int32 {
  ignore(this)
  ignore(guid)
  if out == 0L {
    return E_POINTER
  }
  poke64(out, 0L)
  E_NOTIMPL
}

///|
#export_name("lp_tl_get_documentation")
pub fn tl_get_documentation(
  this : Int64,
  index : Int32,
  name : Int64,
  doc : Int64,
  help_context : Int64,
  help_file : Int64,
) -> Int32 {
  // A BSTR has to come from the real allocator, because the caller frees it with
  // SysFreeString. Rather than link the runtime against oleaut32's string
  // allocator for one method nothing here calls, the answer is "not supported".
  ignore(this)
  ignore(index)
  ignore(name)
  ignore(doc)
  ignore(help_context)
  ignore(help_file)
  E_NOTIMPL
}

///|
#export_name("lp_tl_find_name")
pub fn tl_find_name(
  this : Int64,
  name : Int64,
  hash : Int32,
  info : Int64,
  member : Int64,
  found : Int64,
) -> Int32 {
  ignore(this)
  ignore(name)
  ignore(hash)
  ignore(info)
  ignore(member)
  if found != 0L {
    poke_bytes(found, u32le(0L), 2)
  }
  E_NOTIMPL
}

///|
#export_name("lp_tl_is_name")
pub fn tl_is_name(
  this : Int64,
  name : Int64,
  hash : Int32,
  out : Int64,
) -> Int32 {
  ignore(this)
  ignore(name)
  ignore(hash)
  if out == 0L {
    return E_POINTER
  }
  poke_bytes(out, u32le(0L), 4)
  S_OK
}

///|
#export_name("lp_tl_type_comp")
pub fn tl_type_comp(this : Int64, out : Int64) -> Int32 {
  ignore(this)
  if out == 0L {
    return E_POINTER
  }
  poke64(out, 0L)
  E_NOTIMPL
}

///|
#export_name("lp_tl_release_tl_attr")
pub fn tl_release_tl_attr(this : Int64, attr : Int64) -> Int32 {
  // The buffer belongs to the object and is freed with it, so the caller's
  // release is acknowledged rather than acted on.
  ignore(this)
  ignore(attr)
  S_OK
}

///|
#export_name("lp_load_typelib_ex")
pub fn thunk_load_typelib_ex(
  path : Int64,
  regkind : Int32,
  out : Int64,
) -> Int32 {
  hit("LoadTypeLibEx")
  if out == 0L {
    return E_POINTER
  }
  let p = wide_to_string(path)
  match adopt_typelib(p) {
    Some(obj) => {
      poke64(out, obj)
      // REGKIND_REGISTER asks for the registration as part of the load, and a
      // caller that asks for it gets the same hive writes as an explicit
      // RegisterTypeLib call.
      if regkind == REGKIND_REGISTER {
        match typelib_of(obj) {
          Some(info) => register_type_lib_in_hive(info, p, "")
          None => ()
        }
      }
      S_OK
    }
    None => real_load_typelib_ex(path, regkind, out)
  }
}

///|
#export_name("lp_load_typelib")
pub fn thunk_load_typelib(path : Int64, out : Int64) -> Int32 {
  hit("LoadTypeLib")
  if out == 0L {
    return E_POINTER
  }
  match adopt_typelib(wide_to_string(path)) {
    Some(obj) => {
      poke64(out, obj)
      S_OK
    }
    None => real_load_typelib(path, out)
  }
}

///|
#export_name("lp_register_typelib")
pub fn thunk_register_typelib(
  tlb : Int64,
  path : Int64,
  help_dir : Int64,
) -> Int32 {
  hit("RegisterTypeLib")
  match typelib_of(tlb) {
    Some(info) => {
      let p = wide_to_string(path)
      register_type_lib_in_hive(info, p, wide_to_string(help_dir))
      g_runtime.typelibs_registered = g_runtime.typelibs_registered + 1
      log_reg("typelib-register", info.libid + " " + p)
      S_OK
    }
    None => real_register_typelib(tlb, path, help_dir)
  }
}

///|
#export_name("lp_register_typelib_for_user")
pub fn thunk_register_typelib_for_user(
  tlb : Int64,
  path : Int64,
  help_dir : Int64,
) -> Int32 {
  hit("RegisterTypeLibForUser")
  match typelib_of(tlb) {
    Some(info) => {
      let p = wide_to_string(path)
      register_type_lib_in_hive(info, p, wide_to_string(help_dir))
      g_runtime.typelibs_registered = g_runtime.typelibs_registered + 1
      log_reg("typelib-register-user", info.libid + " " + p)
      S_OK
    }
    None => real_register_typelib_for_user(tlb, path, help_dir)
  }
}

///|
/// Undo a virtual registration. The hive answers for the key, so there is
/// nothing to ask the real registry about; a library that was never registered
/// here falls through so the real API can report accurately.
fn unregister_here(libid : Int64, major : Int32, minor : Int32) -> Bool {
  let text = guid_text_at(libid)
  if text == "" {
    return false
  }
  // The version halves are `WORD` parameters. The x64 convention says only the
  // low 16 bits of such an argument are defined, and the caller does not have
  // to clear the rest: one observed call delivered `1` in DX and garbage above
  // it, so a key built from the full register names a version that cannot
  // exist. Mask before formatting.
  let key = "TypeLib\\" +
    text +
    "\\" +
    (major & 0xFFFF).to_string() +
    "." +
    (minor & 0xFFFF).to_string()
  let r = state_reg()
  if !r.delete_key(HKEY_CLASSES_ROOT, key) {
    return false
  }
  g_runtime.typelibs_unregistered = g_runtime.typelibs_unregistered + 1
  log_reg("typelib-unregister", key)
  true
}

///|
#export_name("lp_unregister_typelib")
pub fn thunk_unregister_typelib(
  libid : Int64,
  major : Int32,
  minor : Int32,
  lcid : Int32,
  syskind : Int32,
) -> Int32 {
  hit("UnRegisterTypeLib")
  if unregister_here(libid, major, minor) {
    S_OK
  } else {
    real_unregister_typelib(libid, major, minor, lcid, syskind)
  }
}

///|
#export_name("lp_unregister_typelib_for_user")
pub fn thunk_unregister_typelib_for_user(
  libid : Int64,
  major : Int32,
  minor : Int32,
  lcid : Int32,
  syskind : Int32,
) -> Int32 {
  hit("UnRegisterTypeLibForUser")
  if unregister_here(libid, major, minor) {
    S_OK
  } else {
    real_unregister_typelib_for_user(libid, major, minor, lcid, syskind)
  }
}

///|
/// Loading back a library that was registered from the archive. The registry
/// entry it would normally read points at a path that has no file, so the
/// parsed library the runtime already holds is the honest answer.
#export_name("lp_load_reg_typelib")
pub fn thunk_load_reg_typelib(
  libid : Int64,
  major : Int32,
  minor : Int32,
  lcid : Int32,
  out : Int64,
) -> Int32 {
  hit("LoadRegTypeLib")
  if out == 0L {
    return E_POINTER
  }
  let text = guid_text_at(libid)
  // Word parameters: see `unregister_here` -- only the low half is defined.
  let want_major = major & 0xFFFF
  let want_minor = minor & 0xFFFF
  let mut i = 0
  while i < g_runtime.typelibs.length() {
    let info = g_runtime.typelibs[i]
    if info.libid == text &&
      info.major == want_major &&
      info.minor == want_minor {
      let obj = new_typelib_object(info)
      if obj == 0L {
        return E_OUTOFMEMORY
      }
      poke64(out, obj)
      log_reg("typelib-loadreg", text)
      return S_OK
    }
    i = i + 1
  }
  real_load_reg_typelib(libid, major, minor, lcid, out)
}

// ------------------------------------------------ registration into the hive ---

///|
fn hive_sz(
  r : VirtualRegistry,
  key : String,
  name : String,
  value : String,
) -> Unit {
  ignore(r.set_value(HKEY_CLASSES_ROOT, key, name, REG_SZ, utf16le(value)))
}

///|
fn hive_dword(
  r : VirtualRegistry,
  key : String,
  name : String,
  value : Int32,
) -> Unit {
  ignore(
    r.set_value(
      HKEY_CLASSES_ROOT,
      key,
      name,
      REG_DWORD,
      u32le(value.to_int64()),
    ),
  )
}

///|
/// Write what `RegisterTypeLib` would have written, into the hive.
///
/// The shape is the documented one: the library under `TypeLib\{LIBID}\ver`
/// with the platform path, one `Interface\{IID}` per interface with its
/// library and proxy, and one `CLSID\{CLSID}\TypeLib` per coclass. The path
/// stored is the virtual one, so a registration reads back consistently with
/// what the component wrote into its own `InprocServer32`.
fn register_type_lib_in_hive(
  info : TypeLibInfo,
  path : String,
  help_dir : String,
) -> Unit {
  let r = state_reg()
  let ver = info.major.to_string() + "." + info.minor.to_string()
  let title = if info.doc != "" { info.doc } else { info.name }
  let lib = "TypeLib\\" + info.libid
  hive_sz(r, lib, "", title)
  let versioned = lib + "\\" + ver
  hive_sz(r, versioned, "", title)
  hive_dword(r, versioned, "FLAGS", info.flags & 0xFFFF)
  if help_dir != "" {
    hive_sz(r, versioned, "HELPDIR", help_dir)
  }
  // The registration points at the language and platform the library was built
  // for. A library with no platform declared is stored under `win32`, which is
  // what oleaut32 assumes for an unknown syskind.
  let platform = if info.syskind == 3 { "win64" } else { "win32" }
  if path != "" {
    hive_sz(r, versioned + "\\" + info.lcid.to_string(), platform, path)
  }
  for t in info.types {
    if t.kind == TKIND_INTERFACE || t.kind == TKIND_DISPATCH {
      let ik = "Interface\\" + t.guid
      hive_sz(r, ik, "", t.name)
      hive_sz(r, ik, "TypeLib", info.libid)
      hive_sz(r, ik, "ProxyStubClsid32", PSOA_INTERFACE)
      let iv = ik + "\\" + t.major.to_string() + "." + t.minor.to_string()
      hive_sz(r, iv, "", t.name)
      hive_sz(r, iv, "TypeLib", info.libid)
      hive_sz(r, iv, "ProxyStubClsid32", PSOA_INTERFACE)
      // The slot count is the vtable size in pointers; a vtable that does not
      // divide evenly is not something to guess at.
      let slots = t.c_vft / 8
      if slots > 0 && slots * 8 == t.c_vft {
        hive_dword(r, iv, "NumMethods", slots)
      }
    } else if t.kind == TKIND_COCLASS {
      let ck = "CLSID\\" + t.guid
      hive_sz(r, ck + "\\TypeLib", "", info.libid)
      hive_sz(
        r,
        ck + "\\Version",
        "",
        t.major.to_string() + "." + t.minor.to_string(),
      )
    }
  }
}

// ------------------------------------------------------------------ stats ---

///|
/// Counters the checks read: libraries parsed, registered and unregistered, and
/// how many entries the last parsed library produced. Same 32-bit ABI as the
/// other stats exports.
#export_name("lp_typelib_stats")
pub fn lp_typelib_stats(out : Int64, cap : Int32) -> Int32 {
  if out == 0L || cap < 16 {
    return -1
  }
  let vals : Array[Int64] = [
    g_runtime.typelibs_loaded.to_int64(),
    g_runtime.typelibs_registered.to_int64(),
    g_runtime.typelibs_unregistered.to_int64(),
    g_runtime.typelibs.length().to_int64(),
  ]
  let n = if cap / 4 < vals.length() { cap / 4 } else { vals.length() }
  for i = 0; i < n; i = i + 1 {
    poke_bytes(out + (i * 4).to_int64(), u32le(vals[i]), 4)
  }
  n
}
