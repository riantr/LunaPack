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
  // L2.7: the restricted CRT patch is process-wide and runs once. These count
  // what it actually changed, so a probe can tell "whitelist matched nothing"
  // apart from "stdio still bypasses the layer".
  mut crt_patched : Bool
  mut crt_modules_patched : Int32
  mut crt_patched_slots : Int32
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
  // L5: which of our thunks was actually reached, per API name. A component
  // that registers itself and a runtime that activates it take different
  // routes through the registry, and this is how the checks tell which one a
  // given binary uses.
  api_hits : Map[String, Int32]
  // L5: images brought in from the virtual filesystem rather than by the OS
  // loader. They are not in the loader's module list, so GetProcAddress has to
  // be answered from their own export directory, and GetModuleFileName has to
  // be answered from `mapped_paths`: a component that registers itself writes
  // its own location into InprocServer32, and for an image that only ever
  // existed inside the archive the honest answer is the virtual path.
  mapped_images : Array[Int64]
  mapped_paths : Map[Int64, String]
  // One page the runtime keeps for calls that need a native buffer of its own
  // (NtQueryKey). Allocated on first use, never freed.
  mut nt_scratch : Int64
  // L6: where this DLL's own image sits when it was not loaded by the loader.
  //
  // A virtual bundle carries the runtime inside its archive: the launcher maps
  // that DLL out of the bundle's bytes, so the image is not in the loader's
  // module list, `GetModuleHandleA("lpvirt.dll")` answers NULL, and every IAT
  // hook that has to name a thunk address names nothing. The base is recorded
  // once by `lp_run_bundle`, which is the entry point the launcher calls, and
  // `thunk_address` reads this image's own export directory instead.
  mut self_base : Int64
  // L5: the last registry paths the thunks were asked about. A component that
  // "cannot register" and a runtime that "cannot find the class" are the same
  // question asked from two sides; this is how the checks see which key was
  // actually requested when the hive does not answer.
  reg_log : Array[String]
  // L5.6: type libraries parsed out of the archive. A component registers its
  // own type library before it registers its classes, and oleaut32 can only
  // read one from a file, so the runtime parses the TYPELIB resource itself and
  // hands back an object of its own. The array is the store; an object carries
  // its index. `typelib_vtable` is the one shared vtable.
  typelibs : Array[TypeLibInfo]
  mut typelib_vtable : Int64
  mut typelibs_loaded : Int32
  mut typelibs_registered : Int32
  mut typelibs_unregistered : Int32
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
  crt_patched: false,
  crt_modules_patched: 0,
  crt_patched_slots: 0,
  attach_bases: [],
  detach_bases: [],
  detach_order_violations: 0,
  eh_table: 0L,
  bootstrap_path: "",
  child_redirects: 0,
  child_failures: 0,
  child_last_error: 0,
  sections: [],
  api_hits: {},
  mapped_images: [],
  mapped_paths: {},
  nt_scratch: 0L,
  self_base: 0L,
  reg_log: [],
  typelibs: [],
  typelib_vtable: 0L,
  typelibs_loaded: 0,
  typelibs_registered: 0,
  typelibs_unregistered: 0,
}

///|
/// Record that an API thunk ran. Cheap enough for the registry surface, which
/// is called tens of times per activation rather than thousands.
fn hit(api : String) -> Unit {
  let n = match g_runtime.api_hits.get(api) {
    Some(x) => x
    None => 0
  }
  g_runtime.api_hits.set(api, n + 1)
}

///|
#export_name("lp_api_hits")
pub fn lp_api_hits(name : Int64) -> Int32 {
  match g_runtime.api_hits.get(ascii_at(name, 64)) {
    Some(n) => n
    None => 0
  }
}

///|
#export_name("lp_api_hits_reset")
pub fn lp_api_hits_reset() -> Unit {
  g_runtime.api_hits.clear()
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
/// Remember an image that was mapped from the virtual filesystem, and the path
/// it was mounted at.
fn note_mapped_image(base : Int64, path : String) -> Unit {
  if base != 0L && !arr_has(g_runtime.mapped_images, base) {
    g_runtime.mapped_images.push(base)
    g_runtime.mapped_paths.set(base, path)
  }
}

///|
/// The virtual path a mapped image was loaded from, or None for a module the OS
/// loader owns.
fn mapped_path_of(base : Int64) -> String? {
  if base == 0L {
    return None
  }
  g_runtime.mapped_paths.get(base)
}

///|
/// A page of process memory for structures the runtime must build for a native
/// call. The heap belongs to MoonBit, so this is a plain allocation.
fn nt_scratch() -> Int64 {
  if g_runtime.nt_scratch == 0L {
    let p = virtual_alloc(
      0L,
      NT_SCRATCH_SIZE.to_int64(),
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE,
    )
    g_runtime.nt_scratch = p
  }
  g_runtime.nt_scratch
}

///|
fn is_mapped_image(base : Int64) -> Bool {
  arr_has(g_runtime.mapped_images, base)
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
    // L2.7: the CRT asks for the handle type right after CreateFileW; an
    // unhooked GetFileType answers FILE_TYPE_UNKNOWN for a virtual handle and
    // fopen fails with errno 9 (EBADF) even though the open succeeded.
    ("GetFileType", "lp_get_file_type"),
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
    // L5.1: registration and activation. A component that registers itself
    // creates the CLSID tree and walks it; combase reads `InprocServer32`
    // through RegGetValueW rather than open-then-query.
    ("RegGetValueW", "lp_reg_get_value_w"),
    ("RegCreateKeyExW", "lp_reg_create_key_ex_w"),
    ("RegCreateKeyExA", "lp_reg_create_key_ex_a"),
    ("RegOpenKeyExA", "lp_reg_open_key_ex_a"),
    ("RegDeleteKeyW", "lp_reg_delete_key_w"),
    ("RegDeleteKeyA", "lp_reg_delete_key_a"),
    ("RegDeleteValueW", "lp_reg_delete_value_w"),
    ("RegEnumKeyExW", "lp_reg_enum_key_ex_w"),
    ("RegEnumValueW", "lp_reg_enum_value_w"),
    ("RegQueryInfoKeyW", "lp_reg_query_info_key_w"),
    ("GetQueuedCompletionStatus", "lp_get_queued_completion_status"),
    ("GetProcAddress", "lp_get_proc_address"),
    ("ExitProcess", "lp_exit_process"),
    ("CreateFileA", "lp_create_file_a"),
    ("GetFileAttributesA", "lp_get_file_attributes_a"),
    ("GetFileAttributesExA", "lp_get_file_attributes_ex_a"),
    // L2.6: resolution before open. cmd.exe asks SearchPathW where a file is
    // before CreateFileW sees it; without these slots a virtual name is
    // reported as missing even though the open side is virtualized.
    ("SearchPathW", "lp_search_path_w"),
    ("SearchPathA", "lp_search_path_a"),
    // L2.8: normalization and enumeration before open. cmd.exe expands a TYPE
    // argument with FindFirstFileExW and canonicalizes it with GetFullPathNameW;
    // without these slots a virtual-only path reports ERROR_PATH_NOT_FOUND (3)
    // although GetFileAttributesW and CreateFileW already answer for it.
    ("GetFullPathNameW", "lp_get_full_path_name_w"),
    ("GetFullPathNameA", "lp_get_full_path_name_a"),
    ("FindFirstFileExW", "lp_find_first_file_ex_w"),
    ("FindFirstFileA", "lp_find_first_file_a"),
    ("FindNextFileA", "lp_find_next_file_a"),
    ("DeleteFileA", "lp_delete_file_a"),
    ("MoveFileExA", "lp_move_file_ex_a"),
    ("GetTempPathW", "lp_get_temp_path_w"),
    ("LoadLibraryA", "lp_load_library_a"),
    ("LoadLibraryW", "lp_load_library_w"),
    ("LoadLibraryExA", "lp_load_library_ex_a"),
    ("LoadLibraryExW", "lp_load_library_ex_w"),
    // L5.5: a component that registers itself asks where it lives and writes the
    // answer into InprocServer32. For an image that was mapped out of the
    // archive the only correct answer is its virtual path, so the question is
    // answered here instead of by the loader, which has never heard of it.
    // Only the wide form is hooked: the ANSI variant is used by VB6-era servers,
    // which cannot run under manual mapping in the first place (runtime/README).
    ("GetModuleFileNameW", "lp_get_module_file_name_w"),
    // L2.3: native file APIs. Reached from a mapped image's static ntdll
    // imports or through our GetProcAddress thunk; no inline ntdll patch.
    ("NtCreateFile", "lp_nt_create_file"),
    // L5: the native registry entry points combase itself uses. Same boundary
    // as the file thunks above: resolved from the IAT, no inline patch.
    ("NtOpenKey", "lp_nt_open_key"),
    ("NtQueryValueKey", "lp_nt_query_value_key"),
    ("NtQueryKey", "lp_nt_query_key"),
    ("NtOpenFile", "lp_nt_open_file"),
    ("NtReadFile", "lp_nt_read_file"),
    ("NtClose", "lp_nt_close"),
    // L4.1: a program that starts another program is redirected to the
    // launcher, so the child is virtualized too. Inert unless the launcher has
    // recorded its own path in LUNAPACK_BOOTSTRAP.
    ("CreateProcessW", "lp_create_process_w"),
    ("CreateProcessA", "lp_create_process_a"),
    // L5.6: type libraries. A self-registering component calls LoadTypeLibEx on
    // its own path and hands the result to RegisterTypeLib, which is where a
    // file-less image used to stop: oleaut32 can only read a type library from
    // a file. These answer from the TYPELIB resource instead, and keep the
    // registration in the hive.
    ("LoadTypeLibEx", "lp_load_typelib_ex"),
    ("LoadTypeLib", "lp_load_typelib"),
    ("RegisterTypeLib", "lp_register_typelib"),
    ("RegisterTypeLibForUser", "lp_register_typelib_for_user"),
    ("UnRegisterTypeLib", "lp_unregister_typelib"),
    ("UnRegisterTypeLibForUser", "lp_unregister_typelib_for_user"),
    ("LoadRegTypeLib", "lp_load_reg_typelib"),
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
/// L2.7: the only system DLLs whose IATs may be rewritten. `hook_table()` is
/// deliberately blind to the importing module: an ordinary application image
/// gets every slot, but a Windows DLL is left alone because the OS loader
/// resolves its own API-set dependencies through LoadLibraryExW at startup and
/// a patched LoadLibrary slot re-enters us until the stack overflows. These two
/// CRT modules are the one narrow exception: a program built the ordinary way
/// reaches stdio through them, so their file slots have to answer from the
/// virtual tree. Only `crt_api_whitelist()` below is touched in them.
fn crt_module_whitelist() -> Array[String] {
  ["ucrtbase.dll", "msvcrt.dll"]
}

///|
/// L2.7: the only imports rewritten inside a whitelisted CRT module. Restricted
/// to file I/O on purpose: no LoadLibrary*, GetProcAddress, ExitProcess,
/// CreateProcess*, registry, ntdll, module-name or type-library slot is safe to
/// touch inside a DLL the loader depends on. A virtual miss still falls back to
/// the real API, so an unmatched real path keeps working.
fn crt_api_whitelist() -> Array[String] {
  [
    "CreateFileW", "CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "GetFileSizeEx",
    "GetFileType", "SetFilePointerEx", "GetFileAttributesW", "GetFileAttributesA",
    "GetFileAttributesExW", "GetFileAttributesExA", "FindFirstFileW", "FindFirstFileA",
    "FindNextFileW", "FindNextFileA", "DeleteFileW", "DeleteFileA", "MoveFileExW",
    "MoveFileExA", "SearchPathW", "SearchPathA", "GetTempPathW",
    // L2.8: the same resolution steps the CRT takes before CreateFileW. Every
    // one of these falls through to the real API on a virtual miss.
     "GetFullPathNameW", "GetFullPathNameA", "FindFirstFileExW",
  ]
}

///|
/// Linear membership test. Both whitelists are tiny (2 modules, 22 APIs) and
/// read on every patch decision, so a Map would cost more to build than it
/// saves.
fn string_in(list : Array[String], item : String) -> Bool {
  let mut i = 0
  while i < list.length() {
    if list[i] == item {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// The leaf of a lower-cased module path. GetModuleFileNameA answers with a
/// full path (`C:\\Windows\\System32\\ucrtbase.dll`) even when the module was
/// loaded by short name, so matching has to ignore the directories.
fn crt_module_name(path : String) -> String {
  let normalized = path.to_lower().replace_all(old="\\", new="/")
  basename(normalized)
}

///|
/// Is this lower-cased module path one of the two CRT modules we may patch?
fn is_crt_module(path : String) -> Bool {
  string_in(crt_module_whitelist(), crt_module_name(path))
}

///|
/// Resolve an import name to a thunk under the L2.7 restriction. An ordinary
/// mapped image passes `restricted=false` and uses the full hook table; a CRT
/// module passes `true` and only its file slots can change.
fn lookup_thunk_restricted(api : String, restricted : Bool) -> String? {
  if restricted && !string_in(crt_api_whitelist(), api) {
    return None
  }
  lookup_thunk(api)
}

///|
/// Address of one of our own exported thunks.
///
/// Two ways to be loaded, two ways to answer. As `lpvirt.dll` next to a
/// launcher the image is in the loader's module list and `GetProcAddress` on
/// it is the whole answer. As the runtime a virtual bundle carries, the image
/// was mapped out of the archive by the launcher: the loader has never heard
/// of it, so the module name it would be looked up by does not resolve, and
/// the same export table is read out of the base the launcher recorded.
fn thunk_address(export_name : String) -> Int64 {
  let own = g_runtime.self_base
  if own != 0L {
    let thunk = export_address(own, export_name)
    if thunk != 0L {
      return thunk
    }
  }
  let self_mod = get_module_handle_a(cstring("lpvirt.dll"))
  real_get_proc_address(self_mod, cstring(export_name))
}

///|
/// Imports that are not by name.
///
/// oleaut32's import library exports most of the automation API by ordinal, so
/// a component built with it imports `LoadTypeLibEx` as "ordinal 183". That is
/// not a corner case: it is what every ATL/MFC server, and every VB6 server,
/// looks like. An IAT hook that only matches names silently never runs for
/// them, and the failure looks like "the component cannot load its own type
/// library" rather than "the hook was not installed".
///
/// The ordinals are the ones in the system oleaut32's export table; a name
/// import still works through the hook table above, so both spellings of the
/// same function are covered.
fn ordinal_table() -> Array[(String, Int32, String)] {
  [
    ("oleaut32.dll", 161, "lp_load_typelib"),
    ("oleaut32.dll", 162, "lp_load_reg_typelib"),
    ("oleaut32.dll", 163, "lp_register_typelib"),
    ("oleaut32.dll", 183, "lp_load_typelib_ex"),
    ("oleaut32.dll", 186, "lp_unregister_typelib"),
    ("oleaut32.dll", 442, "lp_register_typelib_for_user"),
    ("oleaut32.dll", 443, "lp_unregister_typelib_for_user"),
  ]
}

///|
fn ordinal_thunk(dll : String, ordinal : Int32) -> String? {
  let table = ordinal_table()
  let mut i = 0
  while i < table.length() {
    let (name, ord, thunk) = table[i]
    if ord == ordinal && name == dll {
      return Some(thunk)
    }
    i = i + 1
  }
  None
}
