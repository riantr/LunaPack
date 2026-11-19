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
  // L2.1: a mapped CRT image's ExitProcess is redirected to ExitThread, which
  // ends only the worker thread. These fields record the requested code so the
  // launcher still sees it after the thread is gone.
  mut exit_called : Bool
  mut target_exit_code : Int32
  // L2.3: calls served by the ntdll-boundary thunks (NtCreateFile/NtOpenFile/
  // NtReadFile/NtClose), reached through static IAT slots or GetProcAddress.
  mut ntdll_hits : Int32
  // L2.4: one installer serves both manually mapped and loader-loaded images.
  // These counters prove both paths ran; the base lists track DllMain lifecycle
  // so lp_unmap_image can detect a missing DLL_PROCESS_DETACH instead of
  // crashing at process teardown.
  mut mapped_hook_count : Int32
  mut loaded_hook_count : Int32
  mut attach_bases : Array[Int64]
  mut detach_bases : Array[Int64]
  mut detach_order_violations : Int32
  // L3.4: exception table registered with the kernel for the mapped image.
  mut eh_table : Int64
  // L4.1: the launcher's own path. When set, a program that starts another
  // program is redirected to it instead of escaping the virtual tree. Empty
  // means the redirect is off, which is the case for a plain host.
  mut bootstrap_path : String
  mut child_redirects : Int32
  mut child_failures : Int32
  mut child_last_error : Int32
  // L4.2: one handle per published state section, kept open because the child
  // opens the section by name.
  sections : Array[Int64]
}

///|
let g_runtime : RuntimeState = {
  vfs: None,
  registry: None,
  patched_count: 0,
  dynamic_hits: 0,
  map_error: 0,
  exit_called: false,
  target_exit_code: 0,
  ntdll_hits: 0,
  mapped_hook_count: 0,
  loaded_hook_count: 0,
  attach_bases: [],
  detach_bases: [],
  detach_order_violations: 0,
  eh_table: 0L,
  bootstrap_path: "",
  child_redirects: 0,
  child_failures: 0,
  child_last_error: 0,
  sections: [],
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
fn arr_has(a : Array[Int64], v : Int64) -> Bool {
  let mut i = 0
  while i < a.length() {
    if a[i] == v {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// L2.4: a manually mapped image has no OS loader to run DllMain, so the host
/// calls these to record that it invoked DLL_PROCESS_ATTACH / DETACH by hand.
/// The runtime keeps the bases so lp_unmap_image can check detach-before-unmap.
fn note_attach(base : Int64) -> Unit {
  if base != 0L && !arr_has(g_runtime.attach_bases, base) {
    g_runtime.attach_bases.push(base)
  }
}

///|
fn note_detach(base : Int64) -> Unit {
  if base != 0L && !arr_has(g_runtime.detach_bases, base) {
    g_runtime.detach_bases.push(base)
  }
}

///|
/// True when `base` was attached but DETACH was never recorded. Used by the
/// unmap guard and by the white-box tests; kept pure over g_runtime state.
fn detach_missing(base : Int64) -> Bool {
  base != 0L &&
  arr_has(g_runtime.attach_bases, base) &&
  !arr_has(g_runtime.detach_bases, base)
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
    ("WriteFile", "lp_write_file"),
    ("CloseHandle", "lp_close_handle"),
    ("GetFileAttributesW", "lp_get_file_attributes_w"),
    ("GetFileAttributesExW", "lp_get_file_attributes_ex_w"),
    ("GetFileSizeEx", "lp_get_file_size_ex"),
    ("GetFileInformationByHandle", "lp_get_file_information_by_handle"),
    ("SetFilePointerEx", "lp_set_file_pointer_ex"),
    ("DeleteFileW", "lp_delete_file_w"),
    ("MoveFileExW", "lp_move_file_ex_w"),
    ("FindFirstFileW", "lp_find_first_file_w"),
    ("FindNextFileW", "lp_find_next_file_w"),
    ("RegOpenKeyExW", "lp_reg_open_key_ex_w"),
    ("RegQueryValueExW", "lp_reg_query_value_ex_w"),
    ("RegSetValueExW", "lp_reg_set_value_ex_w"),
    ("RegCloseKey", "lp_reg_close_key"),
    ("GetQueuedCompletionStatus", "lp_get_queued_completion_status"),
    ("GetProcAddress", "lp_get_proc_address"),
    ("ExitProcess", "lp_exit_process"),
    ("CreateFileA", "lp_create_file_a"),
    ("GetFileAttributesA", "lp_get_file_attributes_a"),
    ("GetFileAttributesExA", "lp_get_file_attributes_ex_a"),
    ("FindFirstFileA", "lp_find_first_file_a"),
    ("FindNextFileA", "lp_find_next_file_a"),
    ("DeleteFileA", "lp_delete_file_a"),
    ("MoveFileExA", "lp_move_file_ex_a"),
    ("GetTempPathW", "lp_get_temp_path_w"),
    ("LoadLibraryA", "lp_load_library_a"),
    ("LoadLibraryW", "lp_load_library_w"),
    ("LoadLibraryExA", "lp_load_library_ex_a"),
    ("LoadLibraryExW", "lp_load_library_ex_w"),
    // L2.3: native file APIs. Reached from a mapped image's static ntdll
    // imports or through our GetProcAddress thunk; no inline ntdll patch.
    ("NtCreateFile", "lp_nt_create_file"),
    ("NtOpenFile", "lp_nt_open_file"),
    ("NtReadFile", "lp_nt_read_file"),
    ("NtClose", "lp_nt_close"),
    // L4.1: a program that starts another program is redirected to the
    // launcher, so the child is virtualized too. Inert unless the launcher has
    // recorded its own path in LUNAPACK_BOOTSTRAP.
    ("CreateProcessW", "lp_create_process_w"),
    ("CreateProcessA", "lp_create_process_a"),
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
