// Lazy process-wide state.
//
// The MoonBit runtime in a DLL is initialized by `moonbit_init`, which the
// host calls before anything else. All heap state is therefore created on
// first use rather than as a top-level initializer.

///|
struct RuntimeState {
  mut vfs : Vfs?
  mut registry : VirtualRegistry?
  mut patched_count : Int32
  mut dynamic_hits : Int32
  mut map_error : Int32
}

///|
let g_runtime : RuntimeState = {
  vfs: None,
  registry: None,
  patched_count: 0,
  dynamic_hits: 0,
  map_error: 0,
}

///|
fn state_vfs() -> Vfs {
  match g_runtime.vfs {
    Some(v) => v
    None => {
      let v = Vfs::new()
      g_runtime.vfs = Some(v)
      v
    }
  }
}

///|
fn state_reg() -> VirtualRegistry {
  match g_runtime.registry {
    Some(r) => r
    None => {
      let r = VirtualRegistry::new()
      g_runtime.registry = Some(r)
      r
    }
  }
}

///|
/// The Win32 entry points we virtualize, and the exported MoonBit thunk that
/// stands in for each one. Only these IAT slots are rewritten.
fn hook_table() -> Array[(String, String)] {
  [
    ("CreateFileW", "lp_create_file_w"),
    ("ReadFile", "lp_read_file"),
    ("CloseHandle", "lp_close_handle"),
    ("GetFileAttributesW", "lp_get_file_attributes_w"),
    ("GetFileSizeEx", "lp_get_file_size_ex"),
    ("FindFirstFileW", "lp_find_first_file_w"),
    ("FindNextFileW", "lp_find_next_file_w"),
    ("RegOpenKeyExW", "lp_reg_open_key_ex_w"),
    ("RegQueryValueExW", "lp_reg_query_value_ex_w"),
    ("RegSetValueExW", "lp_reg_set_value_ex_w"),
    ("RegCloseKey", "lp_reg_close_key"),
    ("GetProcAddress", "lp_get_proc_address"),
  ]
}

///|
fn lookup_thunk(api : String) -> String? {
  let table = hook_table()
  let mut i = 0
  while i < table.length() {
    let (name, thunk) = table[i]
    if api == name {
      return Some(thunk)
    }
    i = i + 1
  }
  None
}

///|
/// Address of one of our own exported thunks.
fn thunk_address(export_name : String) -> Int64 {
  let self_mod = get_module_handle_a(cstring("lpvirt.dll"))
  real_get_proc_address(self_mod, cstring(export_name))
}
