// The runtime's host-facing surface.
//
// The exported `lp_*` functions take addresses, because a C host can only hand
// over addresses. A MoonBit host has the same data as `Bytes` and `String`
// values and cannot take addresses of them, so it needs a second door: the
// same operations, taking what MoonBit already has. Both doors end in the same
// process state — a host that comes through this one and a host that comes
// through the DLL see the same virtual filesystem and the same hive — so the
// two cannot drift into behaving differently.

///|
/// `REG_EXPAND_SZ`; the registry's string-with-variables type.
const REG_EXPAND_SZ : Int32 = 2

///|
/// `INFINITE` for `WaitForSingleObject`.
const WAIT_INFINITE : Int32 = -1

// ------------------------------------------------------------ process ---

///|
/// `CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
/// dwCreationFlags, lpThreadId)`. The start address is a pointer the runtime
/// computed — the entry point of a mapped image — and Windows is the one that
/// calls it, which is the same arrangement `entry.mbt` uses for `DllMain` and
/// for the same reason: MoonBit cannot call an address it computed.
extern "C" fn create_thread(
  attr : Int64,
  stack : Int32,
  start : Int64,
  param : Int64,
  flags : Int32,
  id : Int64,
) -> Int64 = "CreateThread"

///|
extern "C" fn wait_for_single_object(handle : Int64, millis : Int32) -> Int32 = "WaitForSingleObject"

///|
extern "C" fn get_exit_code_thread(handle : Int64, out : Int64) -> Int32 = "GetExitCodeThread"

///|
extern "C" fn close_handle(handle : Int64) -> Int32 = "CloseHandle"

// ---------------------------------------------------------------- state ---

///|
/// Start from an empty virtual filesystem and an empty hive.
///
/// A host calls this once, before it seeds anything: the runtime state is
/// process-wide and a second host in the same process would otherwise inherit
/// the first one's tree.
pub fn host_reset() -> Unit {
  lp_virt_reset()
}

///|
/// Put `data` into the virtual filesystem at `path`.
pub fn host_add_file(path : String, data : Bytes) -> Unit {
  state_vfs().add_file(path, data)
}

///|
/// The directory a relative open resolves against.
pub fn host_set_cwd(path : String) -> Unit {
  state_vfs().set_cwd(path)
}

///|
/// The directory `GetTempPath` answers with.
pub fn host_set_temp(path : String) -> Unit {
  state_vfs().temp_path = path
}

///|
/// How many virtual files, and how many registry values, the tree holds. A
/// host prints this so the run says what it actually seeded.
pub fn host_stats() -> (Int32, Int32) {
  (state_vfs().files.size().to_int(), state_reg().values.size().to_int())
}

// ------------------------------------------------------------- registry ---

///|
/// The registry type and payload for one seeded value.
///
/// A string is stored the way the registry stores one: UTF-16 with a
/// terminating zero, so a program that asks for its size gets the size it
/// expects. A `REG_DWORD` is four little-endian bytes, never a string.
fn seed_payload(
  kind : String,
  text : String,
  number : Int32,
  data : Bytes,
) -> (Int32, Bytes) {
  match kind {
    "REG_DWORD" => (REG_DWORD, u32le(number.to_int64()))
    "REG_BINARY" => (REG_BINARY, data)
    "REG_EXPAND_SZ" => (REG_EXPAND_SZ, utf16le(text))
    _ => (REG_SZ, utf16le(text))
  }
}

///|
/// Seed one registry value into the hive.
///
/// The hive owns the whole of `hkcr` (with `hklm/hkcu\Software\Classes`
/// folded in), so a seeded value is visible to `RegQueryValueExW` and to the
/// native `NtQueryValueKey` that combase uses, exactly like a value the
/// program wrote itself.
pub fn host_seed_reg(
  root : String,
  key : String,
  name : String,
  kind : String,
  text : String,
  number : Int32,
  data : Bytes,
) -> Bool {
  let hkey = match root.to_lower() {
    "hkcu" => HKEY_CURRENT_USER
    "hklm" => HKEY_LOCAL_MACHINE
    "hkcr" => HKEY_CLASSES_ROOT
    // Nothing else can be represented: the hive is the classes tree plus the
    // two software keys, and a value anywhere else would only look seeded.
    _ => return false
  }
  let (typ, payload) = seed_payload(kind, text, number, data)
  state_reg().set_value(hkey, key, name, typ, payload)
}

// -------------------------------------------------------------- imaging ---

///|
/// Map a PE image out of a byte array: headers, sections, relocations,
/// imports, section protections. Returns the base address, or 0 on failure.
pub fn host_map(data : Bytes) -> Int64 {
  map_image_bytes(data)
}

///|
/// Tell the runtime where a mapped image came from, so that
/// `GetModuleFileNameW` inside it answers the virtual path and a component
/// that registers itself writes a path back into the archive.
pub fn host_set_module_path(base : Int64, path : String) -> Unit {
  note_mapped_image(base, path)
}

///|
/// Patch the image's IAT and record the attach, the same pair a host has to
/// do for an image it mapped itself.
pub fn host_install(base : Int64) -> Int32 {
  let n = install_iat_hooks(base)
  note_attach(base)
  n
}

///|
/// Run a mapped EXE image's entry point on a thread of its own and hand back
/// the code it exited with.
///
/// The entry point is called by Windows through `CreateThread`, so no thunk or
/// trampoline is needed: the address is simply the thread's start routine,
/// which is the one calling convention Windows will both make and accept.
///
/// A thread rather than the calling thread, because an application ends by
/// calling `ExitProcess`, which the runtime turns into `ExitThread`: on the
/// calling thread that would end the host before it could report anything,
/// and on a worker it ends only the worker. The code is read back afterwards,
/// with the intercepted `ExitProcess` taking precedence over the thread's
/// return value, because a program that exits explicitly means that number.
pub fn host_run(base : Int64) -> Int32 {
  let entry = lp_get_entry(base)
  if entry == 0L {
    return -1
  }
  let page = virtual_alloc(0L, 4096L, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
  if page == 0L {
    return -1
  }
  defer ignore(virtual_free(page, 4096L, MEM_RELEASE))
  let thread = create_thread(0L, 0, entry, 0L, 0, 0L)
  if thread == 0L {
    return -1
  }
  ignore(wait_for_single_object(thread, WAIT_INFINITE))
  ignore(get_exit_code_thread(thread, page))
  ignore(close_handle(thread))
  let returned = peek32(page).to_int()
  if g_runtime.exit_called {
    g_runtime.target_exit_code
  } else {
    returned
  }
}

///|
/// Why the last map failed, as a `MAP_*` code, for a host that prints it.
pub fn host_map_error() -> Int32 {
  g_runtime.map_error
}

// ------------------------------------------------------------- mapping ---

///|
/// The address of `name` among `base`'s exports, or 0.
///
/// A launcher that mapped an image itself has no way to ask the loader for one
/// of its exports - the image was never registered - so it reads the export
/// directory the image carries. That is the same answer `GetProcAddress` gives
/// for a loaded module, taken from the same place.
pub fn host_image_export(base : Int64, name : String) -> Int64 {
  export_address(base, name)
}

///|
/// Call `address(arg)` and hand back what it returned.
///
/// MoonBit cannot call an address it computed, and the images this runtime
/// deals with are exactly that case: a DLL mapped out of a bundle, whose entry
/// point is a number found in its own export table. Windows is asked to make
/// the call instead - the address is the start routine of a thread, which is
/// the one calling convention Windows will both make and accept - and the
/// result comes back as that thread's exit code.
///
/// The worker matters for the same reason it does in `host_run`: a launcher is
/// about to end the process with the code the program ended with, so the call
/// that produces that code must not be cancelled by the program's own
/// `ExitProcess` reaching the only thread there is.

///|
/// Give a hand-mapped image the `DLL_PROCESS_ATTACH` the loader would have
/// delivered. Without it the image's CRT heap is still zeroed, and the first
/// allocation inside `moonbit_init` calls `HeapAlloc` with a null heap handle.
/// `run_entry_point` builds the calling stub and `lp_get_entry` reads the
/// address out of the mapped headers.
pub fn host_attach_image(base : Int64) -> Int32 {
  run_entry_point(base, lp_get_entry(base))
}

///|
/// Call a computed address synchronously, on this thread.
///
/// `call_address` uses a worker because a program may end with `ExitProcess`,
/// which the runtime redirects to `ExitThread`; the worker keeps that from
/// ending the launcher. MoonBit runtime initialisation is the opposite case:
/// it has to happen on the thread that will own the process, the way a C host
/// calls `moonbit_init()` directly. Windows is still the caller - a small stub
/// is handed to `InitOnceExecuteOnce`, whose callback argument is a function
/// pointer, and the stub writes the result into a page we own.
pub fn host_call_sync(address : Int64, arg : Int64) -> Int32 {
  if address == 0L {
    return -1
  }
  let page = virtual_alloc(
    0L,
    4096L,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
  )
  if page == 0L {
    return -1
  }
  defer ignore(virtual_free(page, 4096L, MEM_RELEASE))
  let out = virtual_alloc(0L, 4096L, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
  if out == 0L {
    return -1
  }
  defer ignore(virtual_free(out, 4096L, MEM_RELEASE))
  // x64: sub rsp,28h; mov rcx,arg; mov rax,address; call rax;
  //      mov rdx,out; mov [rdx],eax; add rsp,28h; ret
  let code = [
    b'\x48', b'\x83', b'\xec', b'\x28', b'\x48', b'\xb9', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x48', b'\xb8', b'\x00', b'\x00',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\xff', b'\xd0', b'\x48',
    b'\xba', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    b'\x89', b'\x02', b'\x48', b'\x83', b'\xc4', b'\x28', b'\xc3',
  ]
  let stub = page + 32L
  poke_bytes(stub, Bytes::from_array(code), code.length().to_int())
  poke_bytes(stub + 6L, u64le(arg), 8)
  poke_bytes(stub + 16L, u64le(address), 8)
  poke_bytes(stub + 28L, u64le(out), 8)
  ignore(flush_instruction_cache(-1L, stub, code.length().to_int64()))
  let ok = init_once_execute_once(page, stub, 0L, 0L)
  if ok == 0 {
    -1
  } else {
    peek32(out).to_int()
  }
}

///|
pub fn call_address(address : Int64, arg : Int64) -> Int32 {
  if address == 0L {
    return -1
  }
  let page = virtual_alloc(0L, 4096L, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
  if page == 0L {
    return -1
  }
  defer ignore(virtual_free(page, 4096L, MEM_RELEASE))
  let thread = create_thread(0L, 0, address, arg, 0, 0L)
  if thread == 0L {
    return -1
  }
  ignore(wait_for_single_object(thread, WAIT_INFINITE))
  ignore(get_exit_code_thread(thread, page))
  ignore(close_handle(thread))
  peek32(page).to_int()
}

///|
/// How many IAT slots the last `host_install` patched.
pub fn host_patched() -> Int32 {
  g_runtime.patched_count
}
