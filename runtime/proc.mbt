// Child-process following (L4).
//
// A virtualized program that starts another program must not escape the
// virtual tree. The hook here rewrites such a request into a start of our own
// launcher, which maps the real program in its own process and installs the
// same hooks - so a grandchild follows too, without a single remote-injection
// call: no CreateRemoteThread, no WriteProcessMemory on another process, no
// remote LoadLibrary, no CREATE_SUSPENDED.
//
// The virtual tree travels in a named shared section. The parent writes the
// exported blob into it, puts the section name into the environment block it
// hands to the child, and the child maps the section and imports the blob
// before it maps anything. No file is written and no archive format is
// involved.
//
// Everything is inert unless LUNAPACK_BOOTSTRAP is set, which the launcher
// does for itself: a plain lpvirt.dll loaded into an ordinary process keeps
// behaving like an ordinary in-process virtualizer.

///|
const FILE_MAP_WRITE : Int32 = 2

///|
const FILE_MAP_READ : Int32 = 4

///|
const CREATE_UNICODE_ENVIRONMENT : Int32 = 0x00000400

///|
extern "C" fn real_create_process_w(
  app : Int64,
  cmd : Int64,
  pa : Int64,
  ta : Int64,
  inherit_handles : Int32,
  flags : Int32,
  env : Int64,
  dir : Int64,
  si : Int64,
  pi : Int64,
) -> Int32 = "CreateProcessW"

///|
extern "C" fn real_create_process_a(
  app : Int64,
  cmd : Int64,
  pa : Int64,
  ta : Int64,
  inherit_handles : Int32,
  flags : Int32,
  env : Int64,
  dir : Int64,
  si : Int64,
  pi : Int64,
) -> Int32 = "CreateProcessA"

///|
extern "C" fn create_file_mapping_w(
  file : Int64,
  attrs : Int64,
  protect : Int32,
  hi : Int32,
  lo : Int32,
  name : Int64,
) -> Int64 = "CreateFileMappingW"

///|
extern "C" fn open_file_mapping_w(
  access : Int32,
  inherit_handles : Int32,
  name : Int64,
) -> Int64 = "OpenFileMappingW"

///|
extern "C" fn map_view_of_file(
  handle : Int64,
  access : Int32,
  hi : Int32,
  lo : Int32,
  n : Int64,
) -> Int64 = "MapViewOfFile"

///|
extern "C" fn unmap_view_of_file(addr : Int64) -> Int32 = "UnmapViewOfFile"

///|
extern "C" fn get_environment_variable_w(
  name : Int64,
  buf : Int64,
  cap : Int32,
) -> Int32 = "GetEnvironmentVariableW"

///|
extern "C" fn set_environment_variable_w(name : Int64, value : Int64) -> Int32 = "SetEnvironmentVariableW"

///|
extern "C" fn get_environment_strings_w() -> Int64 = "GetEnvironmentStringsW"

///|
extern "C" fn free_environment_strings_w(p : Int64) -> Int32 = "FreeEnvironmentStringsW"

///|
extern "C" fn get_current_process_id() -> Int32 = "GetCurrentProcessId"

///|
fn proc_poke_u32(addr : Int64, v : Int32) -> Unit {
  poke_bytes(addr, u32le(v.to_int64()), 4)
}

///|
/// Copy `s` into a fresh writable block of our own process, NUL included, and
/// return its address, or 0 when the allocation failed.
fn scratch_wide(s : String) -> Int64 {
  let w = utf16le(s)
  let p = virtual_alloc(0L, w.length().to_int64(), MEM_COMMIT, PAGE_READWRITE)
  if p == 0L {
    return 0L
  }
  poke_bytes(p, w, w.length())
  p
}

///|
/// Read an environment variable of this process into a MoonBit string.
fn env_get(key : String) -> String {
  let nptr = scratch_wide(key)
  if nptr == 0L {
    return ""
  }
  let cap = 8192
  let buf = virtual_alloc(0L, cap.to_int64(), MEM_COMMIT, PAGE_READWRITE)
  let mut out = ""
  if buf != 0L {
    let n = get_environment_variable_w(nptr, buf, cap)
    if n > 0 && n < cap {
      out = wide_exact(buf, n * 2)
    }
    ignore(virtual_free(buf, 0L, MEM_RELEASE))
  }
  ignore(virtual_free(nptr, 0L, MEM_RELEASE))
  out
}

///|
/// Number of UTF-16 units in a NUL-terminated wide string, terminator
/// excluded.
fn wide_units(p : Int64) -> Int32 {
  let mut n = 0
  while true {
    if peek16(p + (n * 2).to_int64()).to_int() == 0 {
      break
    }
    n = n + 1
  }
  n
}

///|
/// Append one NUL-terminated entry, converted to wide, to the block under
/// construction.
fn push_env_entry(out : Array[Byte], src : Int64, wide : Bool) -> Unit {
  if wide {
    let n = wide_units(src)
    let b = peek_bytes(src, n * 2)
    for i = 0; i < b.length(); i = i + 1 {
      out.push(b[i])
    }
  } else {
    let n = lstrlen_a(src)
    for i = 0; i < n; i = i + 1 {
      out.push(peek_bytes(src + i.to_int64(), 1)[0])
      out.push(b'\x00')
    }
  }
  out.push(b'\x00')
  out.push(b'\x00')
}

///|
/// Build a wide environment block that is the caller's block plus `extra`.
///
/// `original` is what the program passed to CreateProcess: zero means "inherit
/// mine". `wide` says how to read a non-zero block, which is what the
/// CREATE_UNICODE_ENVIRONMENT flag in the original call described. The result
/// is always wide, so the redirected call sets that flag itself.
fn build_child_env(
  original : Int64,
  wide : Bool,
  extra : Array[(String, String)],
) -> Int64 {
  let out : Array[Byte] = []
  let inherited_owned = original == 0L
  let src = if inherited_owned { get_environment_strings_w() } else { original }
  if src != 0L {
    let src_wide = if inherited_owned { true } else { wide }
    let mut p = src
    while true {
      if src_wide {
        if peek16(p).to_int() == 0 {
          break
        }
        push_env_entry(out, p, true)
        p = p + ((wide_units(p) + 1) * 2).to_int64()
      } else {
        if peek_bytes(p, 1)[0].to_int() == 0 {
          break
        }
        push_env_entry(out, p, false)
        p = p + lstrlen_a(p).to_int64() + 1L
      }
    }
    if inherited_owned {
      ignore(free_environment_strings_w(src))
    }
  }
  for i = 0; i < extra.length(); i = i + 1 {
    let (k, v) = extra[i]
    let line = utf16le(k + "=" + v)
    for j = 0; j < line.length(); j = j + 1 {
      out.push(line[j])
    }
  }
  out.push(b'\x00')
  out.push(b'\x00')
  let bytes = blob_to_bytes(out)
  let p = virtual_alloc(
    0L,
    bytes.length().to_int64(),
    MEM_COMMIT,
    PAGE_READWRITE,
  )
  if p == 0L {
    return 0L
  }
  poke_bytes(p, bytes, bytes.length())
  p
}

///|
/// Publish `blob` in a named shared section and return its name. The blob is
/// preceded by its own u32 length, so the child does not have to trust the
/// section size. The handle is kept open in `g_runtime.sections` for the life
/// of the process: closing it before the child has opened the section by name
/// would race.
fn publish_blob(blob : Bytes) -> String? {
  let pid = get_current_process_id()
  let seq = g_runtime.sections.length() + 1
  let name = "Local\\LunaPackVfs-" + pid.to_string() + "-" + seq.to_string()
  let nptr = scratch_wide(name)
  if nptr == 0L {
    return None
  }
  let need = blob.length() + 4
  let size = if need < 4096 { 4096 } else { need }
  let h = create_file_mapping_w(
    INVALID_HANDLE_VALUE,
    0L,
    PAGE_READWRITE,
    0,
    size,
    nptr,
  )
  ignore(virtual_free(nptr, 0L, MEM_RELEASE))
  if h == 0L {
    return None
  }
  let view = map_view_of_file(h, FILE_MAP_WRITE, 0, 0, 0L)
  if view == 0L {
    ignore(real_close_handle(h))
    return None
  }
  proc_poke_u32(view, blob.length())
  poke_bytes(view + 4L, blob, blob.length())
  ignore(unmap_view_of_file(view))
  g_runtime.sections.push(h)
  Some(name)
}

///|
/// Export the current tree and publish it. Returns the section name, or an
/// empty string when the tree could not be published.
fn publish_state() -> String {
  let blob = state_vfs().export_blob(state_reg())
  match publish_blob(blob) {
    Some(n) => n
    None => ""
  }
}

///|
/// True when this process has been told how to reach the launcher. Both the
/// recorded field and the environment are consulted, because the field is what
/// the launcher set on itself and the environment is what a redirected child
/// inherited.
fn bootstrap_configured() -> Bool {
  g_runtime.bootstrap_path != "" || env_get("LUNAPACK_BOOTSTRAP") != ""
}

///|
/// Split a Windows command line into its program token and the rest of the
/// line, separator included.
///
/// A quoted token ends at its closing quote; an unquoted one ends at the first
/// space or tab. The C harness reads `LUNAPACK_CHILD_CMD` the same way, and the
/// child has to agree with the parent about which part is the image and which
/// part is passed on to it.
fn split_program(line : String) -> (String, String) {
  let n = line.length()
  let mut i = 0
  while i < n && (line[i] == ' ' || line[i] == '\t') {
    i = i + 1
  }
  let mut start = i
  let mut quoted = false
  if i < n && line[i] == '"' {
    quoted = true
    start = i + 1
    i = i + 1
    while i < n && line[i] != '"' {
      i = i + 1
    }
  } else {
    while i < n && line[i] != ' ' && line[i] != '\t' {
      i = i + 1
    }
  }
  let program = str_slice(line, start, i)
  let rest = if quoted && i < n { i + 1 } else { i }
  (program, str_slice(line, rest, n))
}

///|
/// The image a CreateProcess call names, and the arguments that follow it.
///
/// `lpApplicationName` wins when it is present: the command line's first token
/// is then only `argv[0]`, which a caller may write as anything. Everything
/// after that first token belongs to the program on both counts, so the same
/// tail is used whether the image came from the argument or from the line.
fn launch_parts(app : Int64, cmd : Int64, wide : Bool) -> (String, String) {
  let read = fn(p : Int64) -> String {
    if wide {
      wide_to_string(p)
    } else {
      ansi_to_string(p)
    }
  }
  let app_path = if app != 0L { read(app) } else { "" }
  let line = if cmd != 0L { read(cmd) } else { "" }
  let (line_program, tail) = if line == "" {
    ("", "")
  } else {
    split_program(line)
  }
  let program = if app_path != "" { app_path } else { line_program }
  (program, tail)
}

///|
/// True when the virtual tree owns a *file* at `path`.
fn virtual_program(path : String) -> Bool {
  match state_vfs().path_info(path) {
    Some(info) => (info.attrs & FILE_ATTRIBUTE_DIRECTORY) == 0
    None => false
  }
}

///|
/// True when `path` names something CreateProcess can be asked to start: a
/// program the virtual tree owns, or a real file on disk.
///
/// Both are followed, because both have to see the virtual tree: a program the
/// parent installed on disk still reads the files the parent virtualized. A
/// path that is in neither is left to the real API, so the caller gets the
/// "file not found" it is written to handle, from the same call as before.
fn followable_program(path : String) -> Bool {
  if virtual_program(path) {
    return true
  }
  let w = scratch_wide(path)
  if w == 0L {
    return false
  }
  let attrs = real_get_file_attributes_w(w)
  ignore(virtual_free(w, 0L, MEM_RELEASE))
  // INVALID_FILE_ATTRIBUTES is all ones, which is -1 as a signed Int32.
  attrs != -1 && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0
}

///|
/// The redirect: start the launcher on the requested program, with the virtual
/// state in the environment, and return what the caller expects from
/// CreateProcess. A negative result means "not handled, fall through".
fn redirect_launch(
  program : String,
  tail : String,
  inherit_handles : Int32,
  flags : Int32,
  env : Int64,
  dir : Int64,
  si : Int64,
  pi : Int64,
) -> Int32 {
  let bootstrap = if g_runtime.bootstrap_path != "" {
    g_runtime.bootstrap_path
  } else {
    env_get("LUNAPACK_BOOTSTRAP")
  }
  if bootstrap == "" {
    return -1
  }
  if program == "" || !followable_program(program) {
    return -1
  }
  let section = publish_state()
  if section == "" {
    g_runtime.child_failures = g_runtime.child_failures + 1
    return -1
  }
  // The child is told which image to run, and separately receives the
  // arguments on its own command line, so the program it maps sees what its
  // parent passed. The environment carries the whole call, quoted, so a path
  // with spaces survives.
  let extra : Array[(String, String)] = [
    ("LUNAPACK_CHILD_CMD", "\"" + program + "\"" + tail),
    ("LUNAPACK_VFS_SECTION", section),
  ]
  let orig_wide = (flags & CREATE_UNICODE_ENVIRONMENT) != 0
  let block = build_child_env(env, orig_wide, extra)
  if block == 0L {
    g_runtime.child_failures = g_runtime.child_failures + 1
    return -1
  }
  let cmdptr = scratch_wide("\"" + bootstrap + "\"" + tail)
  if cmdptr == 0L {
    ignore(virtual_free(block, 0L, MEM_RELEASE))
    g_runtime.child_failures = g_runtime.child_failures + 1
    return -1
  }
  // An ordinary CreateProcess. Handles are inherited only when the caller
  // asked for it; the section is reached by name, so it needs no inheritance.
  let ok = real_create_process_w(
    0L,
    cmdptr,
    0L,
    0L,
    inherit_handles,
    flags | CREATE_UNICODE_ENVIRONMENT,
    block,
    dir,
    si,
    pi,
  )
  let err = if ok == 0 { get_last_error() } else { 0 }
  ignore(virtual_free(cmdptr, 0L, MEM_RELEASE))
  ignore(virtual_free(block, 0L, MEM_RELEASE))
  if ok == 0 {
    g_runtime.child_failures = g_runtime.child_failures + 1
    g_runtime.child_last_error = err
    set_last_error(err)
    return 0
  }
  g_runtime.child_redirects = g_runtime.child_redirects + 1
  1
}

///|
/// CreateProcessW, with the redirect described at the top of the file.
#export_name("lp_create_process_w")
pub fn lp_create_process_w(
  app : Int64,
  cmd : Int64,
  pa : Int64,
  ta : Int64,
  inherit_handles : Int32,
  flags : Int32,
  env : Int64,
  dir : Int64,
  si : Int64,
  pi : Int64,
) -> Int32 {
  if bootstrap_configured() {
    let (program, tail) = launch_parts(app, cmd, true)
    let launched = redirect_launch(
      program, tail, inherit_handles, flags, env, dir, si, pi,
    )
    if launched >= 0 {
      return launched
    }
  }
  real_create_process_w(
    app, cmd, pa, ta, inherit_handles, flags, env, dir, si, pi,
  )
}

///|
/// CreateProcessA. The ANSI command line is widened for the launcher; every
/// other pointer is passed through untouched.
#export_name("lp_create_process_a")
pub fn lp_create_process_a(
  app : Int64,
  cmd : Int64,
  pa : Int64,
  ta : Int64,
  inherit_handles : Int32,
  flags : Int32,
  env : Int64,
  dir : Int64,
  si : Int64,
  pi : Int64,
) -> Int32 {
  if bootstrap_configured() {
    let (program, tail) = launch_parts(app, cmd, false)
    let launched = redirect_launch(
      program, tail, inherit_handles, flags, env, dir, si, pi,
    )
    if launched >= 0 {
      return launched
    }
  }
  real_create_process_a(
    app, cmd, pa, ta, inherit_handles, flags, env, dir, si, pi,
  )
}

///|
/// Tell the runtime where the launcher lives. The launcher calls this on
/// itself, so the next generation can be redirected. An empty string disables
/// the redirect again.
#export_name("lp_set_bootstrap_path")
pub fn lp_set_bootstrap_path(path : Int64) -> Int32 {
  let p = wide_to_string(path)
  g_runtime.bootstrap_path = p
  if p == "" {
    return 0
  }
  let nptr = scratch_wide("LUNAPACK_BOOTSTRAP")
  let vptr = scratch_wide(p)
  if nptr == 0L || vptr == 0L {
    if nptr != 0L {
      ignore(virtual_free(nptr, 0L, MEM_RELEASE))
    }
    if vptr != 0L {
      ignore(virtual_free(vptr, 0L, MEM_RELEASE))
    }
    return -1
  }
  let ok = set_environment_variable_w(nptr, vptr)
  ignore(virtual_free(nptr, 0L, MEM_RELEASE))
  ignore(virtual_free(vptr, 0L, MEM_RELEASE))
  if ok == 0 {
    -1
  } else {
    0
  }
}

///|
/// Open the section named in the environment and import it. Called by a
/// launcher that was started as a child: after this the process sees the
/// parent's virtual tree.
///
/// Returns 0 on success, 1 when nothing was inherited (not an error), and
/// 2..5 for the specific failure step.
#export_name("lp_import_inherited_state")
pub fn lp_import_inherited_state() -> Int32 {
  let name = env_get("LUNAPACK_VFS_SECTION")
  if name == "" {
    return 1
  }
  let nptr = scratch_wide(name)
  if nptr == 0L {
    return 2
  }
  let h = open_file_mapping_w(FILE_MAP_READ, 0, nptr)
  ignore(virtual_free(nptr, 0L, MEM_RELEASE))
  if h == 0L {
    return 3
  }
  let view = map_view_of_file(h, FILE_MAP_READ, 0, 0, 0L)
  if view == 0L {
    ignore(real_close_handle(h))
    return 4
  }
  let len = peek32(view).to_int()
  let ok = if len > 0 {
    state_vfs().import_blob(state_reg(), peek_bytes(view + 4L, len))
  } else {
    false
  }
  ignore(unmap_view_of_file(view))
  ignore(real_close_handle(h))
  if ok {
    0
  } else {
    5
  }
}

///|
/// Counters for the child-following path. Layout, four Int32 slots:
/// redirects, failures, sections kept open, last error from a failed redirect.
#export_name("lp_proc_stats")
pub fn lp_proc_stats(out : Int64, cap : Int32) -> Int32 {
  if out == 0L || cap < 16 {
    return -1
  }
  proc_poke_u32(out, g_runtime.child_redirects)
  proc_poke_u32(out + 4L, g_runtime.child_failures)
  proc_poke_u32(out + 8L, g_runtime.sections.length())
  proc_poke_u32(out + 12L, g_runtime.child_last_error)
  4
}
