// Self-extracting bundle support.
//
// `bundle` produces a file that is a copy of the LunaPack executable with the
// package archive appended. Starting such a file makes LunaPack notice the
// appended archive, extract the payload and run the bundled program - the same
// trick a WinRAR / 7-Zip self-extracting archive uses.
//
// The extracted payload is cached next to the executable so that starting the
// bundle a second time is instant.

///|
/// Is this build a native (directly runnable) target?
#cfg(target="native")
pub fn is_native_target() -> Bool {
  true
}

///|
#cfg(target="wasm")
pub fn is_native_target() -> Bool {
  false
}

///|
#cfg(target="llvm")
pub fn is_native_target() -> Bool {
  false
}

///|
/// Path of the running executable, when it can be determined.
///
/// The path of the running *image* is asked of the operating system, never
/// taken from `argv[0]`: the first argument of a process is a string that
/// whoever started it chose, and a program that reads its own archive from
/// it can be made to run an archive of somebody else's. `CreateProcess`
/// takes the command line and the application name apart, so the two can
/// name different files.
pub fn current_exe_path() -> String? {
  native_exe_path()
}

///|
/// The path of the running image, on a native Windows build.
///
/// The Windows API is guarded at compile time, not at run time: an
/// `extern "C"` declaration is a link-time reference, so a build for
/// Linux or macOS cannot carry one even when the branch is never taken.
#cfg(all(target="native", platform="windows"))
fn native_exe_path() -> String? {
  match windows_exe_path() {
    Some(p) => Some(p)
    None => fallback_exe_path()
  }
}

///|
/// The path of the running image, on a native build for another platform.
#cfg(all(target="native", not(platform="windows")))
fn native_exe_path() -> String? {
  fallback_exe_path()
}

///|
/// The path of the running image, on the Wasm backend.
///
/// There is no image to ask about: the program runs inside a host that
/// carries the files, so the argument is all there is.
#cfg(target="wasm")
fn native_exe_path() -> String? {
  fallback_exe_path()
}

///|
/// The path of the running image, from `argv[0]`.
///
/// This is the last resort, and it is only safe where the program cannot be
/// started with a name that names another file.
fn fallback_exe_path() -> String? {
  let argv = @env.args()
  if argv.length() == 0 {
    return None
  }
  let p = argv[0]
  if p == "" {
    return None
  }
  if is_absolute(p) {
    return Some(p)
  }
  match @env.current_dir() {
    Some(dir) => Some(dir + "/" + p)
    None => Some(p)
  }
}

///|
/// The path of the running image, from the Windows API.
///
/// `GetModuleFileNameW` returns the file the image was loaded from, which is
/// the one thing that cannot be forged by the caller.
#cfg(all(target="native", platform="windows"))
fn windows_exe_path() -> String? {
  // The buffer is UTF-16, as the "W" in the name of the function says.
  let size = 1024
  let buf = Bytes::make(size, b'\x00')
  // A null module handle asks for the file of the running process.
  let n = get_module_filename(0L, buf, size)
  if n == 0 {
    return None
  }
  let path = @utf16.decode(buf[:n * 2]) catch { _ => return None }
  Some(path)
}

///|
/// `GetModuleFileNameW(HMODULE, LPWSTR, DWORD)`.
#cfg(all(target="native", platform="windows"))
#borrow(buf)
extern "C" fn get_module_filename(
  handle : Int64,
  buf : Bytes,
  size : Int32,
) -> Int32 = "GetModuleFileNameW"

///|
/// `GetCurrentProcessId()`.
#cfg(all(target="native", platform="windows"))
extern "C" fn get_current_process_id() -> Int32 = "GetCurrentProcessId"

///|
/// `GetConsoleProcessList(LPDWORD, DWORD)`.
#cfg(all(target="native", platform="windows"))
#borrow(buf)
extern "C" fn get_console_process_list(buf : Bytes, slots : Int32) -> Int32 = "GetConsoleProcessList"

///|
/// `CreateProcessW(...)`: the command line and the working directory are
/// UTF-16 with a terminator, and the last two buffers are written by the call.
#cfg(all(target="native", platform="windows"))
#borrow(command, cwd, startup, info)
extern "C" fn create_process_w(
  application : Int64,
  command : Bytes,
  process_attr : Int64,
  thread_attr : Int64,
  inherit_handles : Int32,
  flags : Int32,
  environment : Int64,
  cwd : Bytes,
  startup : Bytes,
  info : Bytes,
) -> Int32 = "CreateProcessW"

///|
/// `WaitForSingleObject(HANDLE, DWORD)`.
#cfg(all(target="native", platform="windows"))
extern "C" fn wait_for_single_object(
  handle : Int64,
  milliseconds : Int32,
) -> Int32 = "WaitForSingleObject"

///|
/// `GetExitCodeProcess(HANDLE, LPDWORD)`.
#cfg(all(target="native", platform="windows"))
#borrow(code)
extern "C" fn get_exit_code_process(handle : Int64, code : Bytes) -> Int32 = "GetExitCodeProcess"

///|
/// `CloseHandle(HANDLE)`.
#cfg(all(target="native", platform="windows"))
extern "C" fn close_handle(handle : Int64) -> Int32 = "CloseHandle"

///|
/// `FreeConsole()`.
#cfg(all(target="native", platform="windows"))
extern "C" fn free_console() -> Int32 = "FreeConsole"

///|
/// The size of `STARTUPINFOW`, which is what its `cb` field has to say.
#cfg(all(target="native", platform="windows"))
const STARTUPINFO_SIZE : Int32 = 104

///|
/// `INFINITE`: wait for as long as the program runs.
#cfg(all(target="native", platform="windows"))
const INFINITE : Int32 = -1

///|
/// Is the console this process is attached to one that Windows made for it?
///
/// `GetConsoleProcessList` lists every process attached to the console. A
/// program started from a terminal shares the terminal's console with the
/// shell, so the list holds more than one process; a program started by a
/// double-click is given a console of its own and is alone on it. Only the
/// second kind may be taken away — the first kind is the window the user is
/// typing into.
fn console_is_ours(ids : Array[Int32], own_pid : Int32) -> Bool {
  if ids.length() != 1 {
    return false
  }
  ids[0] == own_pid
}

///|
/// `GetStdHandle(DWORD)`.
#cfg(all(target="native", platform="windows"))
extern "C" fn get_std_handle(which : Int32) -> Int64 = "GetStdHandle"

///|
/// `WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)`.
#cfg(all(target="native", platform="windows"))
#borrow(buffer, written)
extern "C" fn write_file(
  handle : Int64,
  buffer : Bytes,
  length : Int32,
  written : Bytes,
  overlapped : Int64,
) -> Int32 = "WriteFile"

///|
/// `ReadConsoleW(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID)`.
#cfg(all(target="native", platform="windows"))
#borrow(buffer, read)
extern "C" fn read_console_w(
  handle : Int64,
  buffer : Bytes,
  length : Int32,
  read : Bytes,
  reserved : Int64,
) -> Int32 = "ReadConsoleW"

///|
/// `GetConsoleMode(HANDLE, LPDWORD)`.
#cfg(all(target="native", platform="windows"))
#borrow(mode)
extern "C" fn get_console_mode(handle : Int64, mode : Bytes) -> Int32 = "GetConsoleMode"

///|
/// Can a question be asked and answered here?
///
/// A handle that is not a console — a pipe, a file, the null device — cannot
/// be answered, and waiting fifteen seconds for a key that cannot come is
/// worse than not asking. `GetConsoleMode` is the one call that says whether
/// the standard input is a console rather than something that merely looks
/// like a character device.
#cfg(all(target="native", platform="windows"))
fn stdin_is_console() -> Bool {
  let handle = get_std_handle(STD_INPUT_HANDLE)
  if handle == 0L || handle == -1L {
    return false
  }
  let mode = Bytes::make(4, b'\x00')
  get_console_mode(handle, mode) != 0
}

///|
/// Nothing to ask on a platform whose console belongs to the terminal.
#cfg(not(all(target="native", platform="windows")))
fn stdin_is_console() -> Bool {
  false
}

///|
/// `STD_INPUT_HANDLE`.
#cfg(all(target="native", platform="windows"))
const STD_INPUT_HANDLE : Int32 = -10

///|
/// `STD_OUTPUT_HANDLE`.
#cfg(all(target="native", platform="windows"))
const STD_OUTPUT_HANDLE : Int32 = -11

///|
/// How wide a progress line is, in characters.
const PROGRESS_WIDTH : Int32 = 78

///|
/// How many cells of that line the bar itself takes.
const PROGRESS_BAR_WIDTH : Int32 = 24

///|
/// How long a first start waits for an answer before it just runs the bundle.
const CHOICE_SECONDS : Int32 = 15

///|
/// Does the console this process is attached to belong to it alone?
#cfg(all(target="native", platform="windows"))
fn own_console_at_start() -> Bool {
  let slots = 16
  let buf = Bytes::make(slots * 4, b'\x00')
  let n = get_console_process_list(buf, slots)
  if n <= 0 {
    return false
  }
  let ids : Array[Int32] = []
  let mut i = 0
  while i < n && i < slots {
    ids.push(u32_at(buf, i.to_int64() * 4L).to_int())
    i = i + 1
  }
  console_is_ours(ids, get_current_process_id())
}

///|
/// There is no console of our own on any other platform: the program was
/// started from a terminal, and a bundle started from a desktop entry has none.
#cfg(not(all(target="native", platform="windows")))
fn own_console_at_start() -> Bool {
  false
}

///|
/// Write to the console without a newline, so that a line can be rewritten in
/// place.
#cfg(all(target="native", platform="windows"))
fn console_write(text : String) -> Unit {
  let handle = get_std_handle(STD_OUTPUT_HANDLE)
  if handle == 0L || handle == -1L {
    return
  }
  let data = string_to_utf8_bytes(text)
  let written = Bytes::make(4, b'\x00')
  write_file(handle, data, data.length(), written, 0L) |> ignore
}

///|
/// The same, on a platform where the bar is never drawn: a bundle started from
/// a terminal has no console of its own, so nothing asks for a line.
#cfg(not(all(target="native", platform="windows")))
fn console_write(text : String) -> Unit {
  ignore(text)
}

///|
/// One line from the console, or `None` when nothing arrives in `timeout_ms`.
///
/// A negative timeout waits for as long as it takes. The wait is on the input
/// handle itself, which Windows signals as soon as a key is pressed: that is
/// what lets the caller count down between two waits instead of blocking.
#cfg(all(target="native", platform="windows"))
fn read_console_line(timeout_ms : Int32) -> String? {
  let handle = get_std_handle(STD_INPUT_HANDLE)
  if handle == 0L || handle == -1L {
    return None
  }
  if timeout_ms >= 0 {
    // WAIT_OBJECT_0 is zero, and it is the only answer that means input.
    if wait_for_single_object(handle, timeout_ms) != 0 {
      return None
    }
  }
  let buffer = Bytes::make(1024, b'\x00')
  let read = Bytes::make(4, b'\x00')
  if read_console_w(handle, buffer, 1024, read, 0L) == 0 {
    return None
  }
  let n = u32_at(read, 0L).to_int()
  if n <= 0 {
    return None
  }
  // ReadConsoleW hands back the line endings as well.
  let text = @utf16.decode(buffer[:n * 2]) catch { _ => return None }
  Some(text)
}

///|
/// Nothing to read: there is no menu on a platform whose console belongs to
/// the terminal.
#cfg(not(all(target="native", platform="windows")))
fn read_console_line(timeout_ms : Int32) -> String? {
  None
}

///|
/// `text` without the whitespace or the line ending around it.
fn trim_line(text : String) -> String {
  let mut start = 0
  let mut end = text.length()
  while start < end {
    let c = text[start]
    if c == '\r' || c == '\n' || c == ' ' || c == '\t' {
      start = start + 1
    } else {
      break
    }
  }
  while end > start {
    let c = text[end - 1]
    if c == '\r' || c == '\n' || c == ' ' || c == '\t' {
      end = end - 1
    } else {
      break
    }
  }
  text[start:end].to_owned()
}

///|
/// A callback that draws the bar: one line, rewritten in place.
///
/// `tag` says which of the two passes is running — the unpacking or the
/// read-back that follows it — because both of them walk the same list of
/// files, and a bar without a tag looks like it started over.
fn progress_reporter(
  tag : String,
  total_files : Int32,
) -> (Int32, Int64, Int64, String) -> Unit {
  fn(done_files, done_bytes, total_bytes, name) {
    console_write(
      "\r" +
      fit_line(
        tag +
        " " +
        progress_line(
          done_files,
          total_files,
          done_bytes,
          total_bytes,
          name,
          PROGRESS_BAR_WIDTH,
        ),
        PROGRESS_WIDTH,
      ),
    )
  }
}

///|
/// Ask what a first start should do: install the payload to a folder, or
/// unpack it next to the bundle and run it from there.
///
/// Returns true for "install". The default is "run", and it is taken after
/// fifteen seconds without an answer: a bundle that nobody is watching has to
/// start on its own.
#cfg(all(target="native", platform="windows"))
fn ask_install_or_run(m : Manifest) -> Bool {
  console_write(
    "LunaPack: " +
    m.name +
    " " +
    m.version +
    "\n" +
    "  [1] install it to a folder\n" +
    "  [2] run it from the folder next to this file\n",
  )
  let mut left = CHOICE_SECONDS
  while left > 0 {
    console_write("\r  your choice [1/2], 2 in " + left.to_string() + " s:    ")
    match read_console_line(1000) {
      Some(line) => {
        console_write("\n")
        return trim_line(line) == "1"
      }
      None => ()
    }
    left = left - 1
  }
  console_write("\r  your choice [1/2]: 2 (nobody chose)                    \n")
  false
}

///|
/// There is no menu on a platform whose console belongs to the terminal.
#cfg(not(all(target="native", platform="windows")))
fn ask_install_or_run(m : Manifest) -> Bool {
  false
}

///|
/// The folder an install goes to when the user just presses Enter.
fn default_install_dir(m : Manifest) -> String {
  match @env.get_env_var("LOCALAPPDATA") {
    Some(base) =>
      if base == "" {
        "./" + m.name
      } else {
        base + "\\Programs\\" + m.name
      }
    None => "./" + m.name
  }
}

///|
/// Install the payload where the user says, and start it from there.
///
/// This is the path of `unpack` with the scripts of the package in place, so
/// an install of a bundle is the same thing as unpacking it by hand, with a
/// bar over the part that takes the time.
#cfg(all(target="native", platform="windows"))
async fn install_and_start(
  exe : String,
  m : Manifest,
  key : PackageKey?,
) -> Unit {
  let fallback = default_install_dir(m)
  console_write("  install to [" + fallback + "]: ")
  let dest = match read_console_line(-1) {
    Some(line) => {
      let answer = trim_line(line)
      if answer == "" {
        fallback
      } else {
        answer
      }
    }
    None => fallback
  }
  console_write("\n  unpacking " + m.entries.length().to_string() + " files\n")
  unpack_reporting(
    exe,
    dest,
    true,
    key,
    Some(progress_reporter("unpack", m.entries.length())),
  )
  console_write("\n")
  println("LunaPack: installed " + m.name + " to " + dest)
  let program = dest + "/" + m.main_program
  let args = bundled_arguments()
  let code = match start_without_console(program, args, dest) {
    Some(code) => code
    None =>
      try {
        let r = @process.run(program, args, cwd=dest)
        r.exit_code
      } catch {
        err => {
          println("LunaPack: cannot start " + program + ": " + err.to_string())
          1
        }
      }
  }
  exit_with(code)
}

///|
/// Nothing to install on a platform whose console belongs to the terminal.
#cfg(not(all(target="native", platform="windows")))
async fn install_and_start(
  exe : String,
  m : Manifest,
  key : PackageKey?,
) -> Unit {

}

///|
/// Start the program of the bundle and take the console away, when the console
/// is the one Windows made for this bundle and the program has a window.
///
/// Returns the exit code of the program when it was started here, and `None`
/// when the caller should start it the ordinary way.
///
/// The bundle keeps the console subsystem of the launcher, and that is not a
/// detail: a program with no standard streams at all does not survive the
/// start of the MoonBit runtime — it is gone before the first line of `main`
/// runs — so a bundle that says "windowed" cannot be started at all. That is
/// what every double-clicked bundle of an application with a window did, and
/// the leak of it was that nothing at all happened: no window, no message, no
/// cache folder.
///
/// The console that comes with the console subsystem is taken away instead. It
/// belongs to the bundle when the bundle was double-clicked, and the window
/// would otherwise stand next to the application for as long as the application
/// runs, because a launcher waits for the program it started.
///
/// The program is started before the console goes away, and with a call of its
/// own rather than through the process API of the runtime: after `FreeConsole`
/// the console handles this process held no longer lead anywhere, and a spawn
/// that hands them on fails with "the handle is invalid". Nothing that has to
/// do with strings or files happens after the console is gone — the command
/// line and the working directory are built first, and the rest is three
/// Windows calls.
#cfg(all(target="native", platform="windows"))
async fn start_without_console(
  program : String,
  args : Array[String],
  dir : String,
) -> Int32? {
  if !own_console_at_start() {
    return None
  }
  // A console program keeps its console: that window is where its output goes,
  // and taking it away would make the bundle say nothing at all.
  if pe_subsystem_of(program) != PE_SUBSYSTEM_GUI {
    return None
  }
  let command = wide_terminated(quoted_command_line(program, args))
  let cwd = wide_terminated(dir)
  let startup = startup_info()
  let info = Bytes::make(24, b'\x00')
  let started = create_process_w(
    0L, command, 0L, 0L, 0, 0, 0L, cwd, startup, info,
  )
  if started == 0 {
    return None
  }
  free_console() |> ignore
  let process = i64_at(info, 0)
  let thread = i64_at(info, 8)
  wait_for_single_object(process, INFINITE) |> ignore
  let code = Bytes::make(4, b'\x00')
  get_exit_code_process(process, code) |> ignore
  close_handle(process) |> ignore
  close_handle(thread) |> ignore
  Some(u32_at(code, 0L).to_int())
}

///|
/// Nothing to do: on every other platform a console belongs to the terminal the
/// program was started from, and a bundle started from a desktop entry has none
/// at all.
#cfg(not(all(target="native", platform="windows")))
async fn start_without_console(
  program : String,
  args : Array[String],
  dir : String,
) -> Int32? {
  None
}

///|
/// The command line of the program, with the program and every argument in
/// quotes.
///
/// An argument that carries a quote of its own is not escaped here: the quotes
/// are what keeps a path with a space in one piece, which is the case a bundle
/// meets.
#cfg(all(target="native", platform="windows"))
fn quoted_command_line(program : String, args : Array[String]) -> String {
  let mut line = "\"" + program + "\""
  let mut i = 0
  while i < args.length() {
    line = line + " \"" + args[i] + "\""
    i = i + 1
  }
  line
}

///|
/// A string as UTF-16 with a terminator, which is what the `W` calls read.
#cfg(all(target="native", platform="windows"))
fn wide_terminated(s : String) -> Bytes {
  let units = @utf16.encode(s)
  let out : Array[Byte] = []
  let mut i = 0
  while i < units.length() {
    out.push(units.at(i))
    i = i + 1
  }
  out.push(b'\x00')
  out.push(b'\x00')
  Bytes::from_array(out)
}

///|
/// A `STARTUPINFOW` with its size filled in and everything else zero.
#cfg(all(target="native", platform="windows"))
fn startup_info() -> Bytes {
  let bytes = FixedArray::make(STARTUPINFO_SIZE, b'\x00')
  bytes[0] = (STARTUPINFO_SIZE & 0xff).to_byte()
  bytes[1] = ((STARTUPINFO_SIZE >> 8) & 0xff).to_byte()
  bytes[2] = ((STARTUPINFO_SIZE >> 16) & 0xff).to_byte()
  bytes[3] = ((STARTUPINFO_SIZE >> 24) & 0xff).to_byte()
  Bytes::from_array(bytes[:])
}

///|
/// The integer of eight bytes at `at`, little endian.
#cfg(all(target="native", platform="windows"))
fn i64_at(data : Bytes, at : Int32) -> Int64 {
  let mut v = 0L
  let mut i = 7
  while i >= 0 {
    v = (v << 8) | data.at(at + i).to_int().to_int64()
    i = i - 1
  }
  v
}

///|
/// Does the path look absolute?
fn is_absolute(p : String) -> Bool {
  if p.has_prefix("/") {
    return true
  }
  // Windows drive letters, e.g. "C:\..." or "C:/..."
  if p.length() >= 3 && p[1] == ':' {
    return true
  }
  false
}

///|
/// Short, stable identifier of a package, used to name the cache folder.
pub fn package_tag(m : Manifest) -> String {
  package_tag_of(manifest_to_json(m))
}

///|
/// Short, stable identifier for arbitrary text.
pub fn package_tag_of(text : String) -> String {
  let full = sha256_hex_of_string(text)
  full[0:16].to_owned()
}

///|
/// Folder that caches the extracted payload of a bundle.
///
/// The folder next to the executable is the best place for it: the payload
/// stays with the file it belongs to. When that folder cannot be written
/// to - a read-only medium, a folder the user may not touch - the payload
/// goes to the temporary folder of the system instead, under a name that
/// depends on the package, so that it is found again on the next start.
async fn cache_dir(exe_path : String, tag : String) -> String {
  let dir = dirname(exe_path)
  if dir != "" {
    let near = dir + "/.lunapack/" + tag
    if @fs.exists(near) || writable_dir(near) {
      return near
    }
  }
  // The temporary folder of the system, under a name of its own, so that
  // the payload is only unpacked once.
  @fs.tmpdir(prefix="lunapack-" + tag)
}

///|
/// Can a folder be created at `path`?
async fn writable_dir(path : String) -> Bool {
  // The cache holds the payload of the bundle, and only the user who owns
  // it has any business in it.
  @fs.mkdir(path, recursive=true, allow_exist=true, permission=0o700) catch {
    _ => return false
  }
  true
}

///|
/// Do the files in `dir` still hold what the package carries?
///
/// The cache is used again only when it is the cache of this package: a
/// file that was changed after it was unpacked is not what the package says
/// it is, and the payload is unpacked again in that case.
async fn cache_matches(m : Manifest, dir : String) -> Bool {
  cache_matches_reporting(m, dir, None)
}

///|
/// The same, telling a caller how far it has come after every file.
///
/// This is the pass that reads a hundred megabytes back from the disk, so it
/// is half of what a first start spends its time on, and a bar that covered
/// only the unpacking would stop at 50% and then sit there.
async fn cache_matches_reporting(
  m : Manifest,
  dir : String,
  report : ((Int32, Int64, Int64, String) -> Unit)?,
) -> Bool {
  let total_bytes = total_bytes_of(m.entries)
  let mut done_bytes = 0L
  let mut index = 0
  for e in m.entries {
    let path = dir + "/" + e.path
    if !@fs.exists(path) {
      return false
    }
    let data = @fs.read_binary(path)
    if redundant_sha256(data) != e.checksum {
      return false
    }
    index = index + 1
    done_bytes = done_bytes + e.size
    match report {
      Some(tell) => tell(index, done_bytes, total_bytes, e.path)
      None => ()
    }
  }
  true
}

///|
/// Does the file at `path` still hold what the package says it holds?
///
/// This is what runs before the program of a bundle is started: the file is
/// read back from the disk and compared with the checksum of the package, so
/// that a file that was changed after it was unpacked is not started.
async fn program_matches(m : Manifest, path : String) -> Bool {
  for e in m.entries {
    if e.path != m.main_program {
      continue
    }
    if !@fs.exists(path) {
      return false
    }
    let data = @fs.read_binary(path)
    return redundant_sha256(data) == e.checksum
  }
  false
}

///|
/// Has this package already been unpacked next to the bundle?
///
/// Only the marker is looked at. The files behind it are checked when the
/// cache is used, and checking them here as well would pay for the whole
/// payload twice on every start.
async fn complete_cache(exe_path : String, m : Manifest) -> Bool {
  let dir = cache_dir(exe_path, package_tag(m))
  if dir == "" {
    return false
  }
  @fs.exists(dir + "/.lunapack-complete")
}

///|
/// Extract the payload into the cache folder next to the executable.
///
/// Returns the folder, or None when that location cannot be used.
async fn extract_to_cache(
  pkg : String,
  exe_path : String,
  m : Manifest,
  key : PackageKey?,
  unpack_report : ((Int32, Int64, Int64, String) -> Unit)?,
  verify_report : ((Int32, Int64, Int64, String) -> Unit)?,
) -> String? {
  let dir = cache_dir(exe_path, package_tag(m))
  if dir == "" {
    return None
  }
  let marker = dir + "/.lunapack-complete"
  if @fs.exists(marker) && cache_matches(m, dir) {
    // The cache holds the files the package carries, so it is used again.
    return Some(dir)
  }
  // The payload is unpacked into a folder of its own and only then does it
  // take the place of the cache. A cache therefore never holds a payload
  // that was only half unpacked, and a payload that was unpacked into the
  // old cache is gone before the new one is put in its place. The folder is
  // read back once it has arrived, because the move is the one step whose
  // result is not known here.
  let staging = dir + ".staging"
  remove_dir(staging)
  @fs.mkdir(staging, recursive=true, allow_exist=true, permission=0o700)
  try {
    extract_to_reporting(pkg, staging, key, unpack_report)
    @fs.write_text(staging + "/.lunapack-complete", "ok")
    remove_dir(dir)
    @fs.rename(staging, dir, replace=true)
    accept_cache_reporting(m, dir, verify_report)
  } catch {
    _ => {
      remove_dir(staging)
      None
    }
  }
}

///|
/// Hand out the folder at `dir` as the cache of `m`, or take it away and say
/// that there is nothing to hand out.
///
/// The step that makes a cache is a move: the payload is unpacked into a
/// folder of its own and then takes the place of the cache. A move is not
/// something the launcher can check by having done it, and the folder that
/// arrives is named like a complete cache whether all of it arrived or only
/// part of it did. What the launcher used to hand out was therefore the name,
/// not the payload: a folder that held most of the files started a program
/// that then failed to load a library it needs, a long way from here.
///
/// So the payload is read back from where it landed. A folder that does not
/// hold what the package carries is removed rather than started, and the cost
/// of a torn folder becomes a bundle that refuses to start and says why.
async fn accept_cache_reporting(
  m : Manifest,
  dir : String,
  report : ((Int32, Int64, Int64, String) -> Unit)?,
) -> String? {
  if cache_matches_reporting(m, dir, report) {
    return Some(dir)
  }
  remove_dir(dir)
  None
}

///|
/// Remove the folder at `path` and everything below it, whether it is there
/// or not.
///
/// `@fs.rmdir` takes `allow_missing`, but the flag only covers the removal of
/// the folder itself: a recursive removal opens the folder first, and that
/// fails when there is none. So the folder is looked at before it is
/// removed.
pub async fn remove_dir(path : String) -> Unit {
  if !@fs.exists(path) {
    return
  }
  @fs.rmdir(path, recursive=true, allow_missing=true) catch {
    _ => ()
  }
}

///|
/// The path of the file that holds the secret key of an encrypted package.
///
/// The environment variable LUNAPACK_SECRET_KEY names the file; without it
/// the file `<executable>.key` next to the executable is used.
fn secret_key_path(exe_path : String) -> String {
  match @env.get_env_var("LUNAPACK_SECRET_KEY") {
    Some(p) => p
    None => exe_path + ".key"
  }
}

///|
/// The path of the file that holds the passphrase of an encrypted package.
///
/// The environment variable LUNAPACK_PASSPHRASE_FILE names the file; without
/// it the file `<executable>.pass` next to the executable is used.
fn passphrase_path(exe_path : String) -> String {
  match @env.get_env_var("LUNAPACK_PASSPHRASE_FILE") {
    Some(p) => p
    None => exe_path + ".pass"
  }
}

///|
/// The passphrase of an encrypted package, read from a file.
async fn read_passphrase_file(path : String) -> String {
  let text = utf8_bytes_to_string(@fs.read_binary(path))
  let mut end = text.length()
  while end > 0 {
    let c = text[end - 1]
    if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
      end = end - 1
    } else {
      break
    }
  }
  text[0:end].to_owned()
}

///|
/// The key of an encrypted package, found next to the executable.
///
/// Returns None when the package is not encrypted or when the key cannot be
/// found.
async fn resolve_key(m : Manifest, exe_path : String) -> PackageKey? {
  match m.encryption {
    None => {
      // The package says that it is not encrypted. A key that waits for it
      // anyway says that the package is not the one it says it is, so the
      // bundle is refused instead of being started.
      if @fs.exists(secret_key_path(exe_path)) {
        fail(
          "the package says that it is not encrypted, but a secret key file is next to it: the package was changed",
        )
      }
      if @fs.exists(passphrase_path(exe_path)) {
        fail(
          "the package says that it is not encrypted, but a passphrase file is next to it: the package was changed",
        )
      }
      None
    }
    Some(info) => {
      let passphrase = if info.method_name == METHOD_PASSPHRASE {
        let path = passphrase_path(exe_path)
        if !@fs.exists(path) {
          println(
            "LunaPack: the package is encrypted and the passphrase file " +
            path +
            " is missing",
          )
          return None
        }
        read_passphrase_file(path)
      } else {
        ""
      }
      let key_path = secret_key_path(exe_path)
      if info.method_name != METHOD_PASSPHRASE && !@fs.exists(key_path) {
        println(
          "LunaPack: the package is encrypted and the secret key file " +
          key_path +
          " is missing",
        )
        return None
      }
      Some(recover_encryption(info, key_path, passphrase))
    }
  }
}

///|
/// Extract the payload carried by the running executable and start the
/// bundled program.
///
/// The arguments of the bundle are the arguments of the bundled program,
/// and the exit code of the bundle is the exit code of the bundled program.
/// A bundle that is started therefore behaves like the program it carries.
///
/// Returns false when the executable carries no archive, in which case the
/// caller should behave like an ordinary command line tool.
pub async fn try_launch_self_extracting() -> Bool {
  let exe = match current_exe_path() {
    Some(p) => p
    None => return false
  }
  if !@fs.exists(exe) {
    return false
  }
  let m = match probe_archive(exe) {
    Some((_, m)) => m
    None => return false
  }
  if m.main_program == "" {
    return false
  }
  let key = resolve_key(m, exe)
  if m.encryption is Some(_) && key is None {
    eprintln("LunaPack: cannot decrypt the package")
    return false
  }
  // The arguments of the bundle belong to the bundled program.
  let args = bundled_arguments()
  // A bundle that was started by a double-click, with no argument of its own,
  // and whose payload has never been unpacked, asks what to do first: install
  // it to a folder, or unpack it next to itself and run it from there.
  // Everything else goes straight to the program — a start from a terminal, a
  // start with an argument, and every start after the first one.
  let interactive = args.length() == 0 && own_console_at_start()
  if interactive && stdin_is_console() && !complete_cache(exe, m) {
    if ask_install_or_run(m) {
      install_and_start(exe, m, key)
      return true
    }
  }
  let unpack_report = if interactive {
    Some(progress_reporter("unpack", m.entries.length()))
  } else {
    None
  }
  let verify_report = if interactive {
    Some(progress_reporter("verify", m.entries.length()))
  } else {
    None
  }
  let dir = match
    extract_to_cache(exe, exe, m, key, unpack_report, verify_report) {
    Some(d) => d
    None => {
      // The folder next to the executable is not usable, fall back to a
      // temporary directory. What is unpacked there is read back in the same
      // way, because a payload that did not arrive in full is not something
      // to start from anywhere.
      let d = @fs.tmpdir(prefix="lunapack")
      eprintln("LunaPack: extracting " + m.main_program + " to " + d)
      extract_to_reporting(exe, d, key, unpack_report)
      match accept_cache_reporting(m, d, verify_report) {
        Some(d) => d
        None => {
          eprintln(
            "LunaPack: the payload does not match the package after it was unpacked: refusing to start it",
          )
          exit_with(1)
          return true
        }
      }
    }
  }
  // The bar is rewritten in place, and the line that follows it starts on a
  // line of its own.
  if interactive {
    console_write("\n")
  }
  let program = dir + "/" + m.main_program
  // The file that is about to be started is read back from the disk and
  // compared with the package, so that a file that was changed after it was
  // unpacked is not started.
  if !program_matches(m, program) {
    eprintln(
      "LunaPack: the program in the cache does not match the package: refusing to start it",
    )
    exit_with(1)
    return true
  }
  eprintln("LunaPack: starting " + program)
  // A bundle that was started by a double-click has a console of its own, and
  // the program about to start draws its own window. That console is taken
  // away while the program runs, and the program is started by the same call,
  // so the ordinary way is only the fall back: a terminal keeps the console
  // the user is typing into, and a console program keeps the window its output
  // goes to.
  let code = match start_without_console(program, args, dir) {
    Some(code) => code
    None =>
      try {
        let r = @process.run(program, args, cwd=dir)
        r.exit_code
      } catch {
        err => {
          eprintln("LunaPack: cannot start " + program + ": " + err.to_string())
          1
        }
      }
  }
  // The exit code of the bundle is the exit code of the program it
  // carries, so that a script that starts the bundle sees it.
  exit_with(code)
  true
}

///|
/// The arguments that the bundled program receives.
///
/// The first argument is the path of the bundle itself, which the program
/// does not need: it knows its own path. The rest are the arguments of the
/// bundle, and they belong to the program.
fn bundled_arguments() -> Array[String] {
  let argv = @env.args()
  let out = []
  let mut i = 1
  while i < argv.length() {
    out.push(argv[i])
    i = i + 1
  }
  out
}
