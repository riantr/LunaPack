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
  for e in m.entries {
    let path = dir + "/" + e.path
    if !@fs.exists(path) {
      return false
    }
    let data = @fs.read_binary(path)
    if redundant_sha256(data) != e.checksum {
      return false
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
/// Extract the payload into the cache folder next to the executable.
///
/// Returns the folder, or None when that location cannot be used.
async fn extract_to_cache(
  pkg : String,
  exe_path : String,
  m : Manifest,
  key : PackageKey?,
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
    extract_to(pkg, staging, key)
    @fs.write_text(staging + "/.lunapack-complete", "ok")
    remove_dir(dir)
    @fs.rename(staging, dir, replace=true)
    accept_cache(m, dir)
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
async fn accept_cache(m : Manifest, dir : String) -> String? {
  if cache_matches(m, dir) {
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
  let dir = match extract_to_cache(exe, exe, m, key) {
    Some(d) => d
    None => {
      // The folder next to the executable is not usable, fall back to a
      // temporary directory. What is unpacked there is read back in the same
      // way, because a payload that did not arrive in full is not something
      // to start from anywhere.
      let d = @fs.tmpdir(prefix="lunapack")
      eprintln("LunaPack: extracting " + m.main_program + " to " + d)
      extract_to(exe, d, key)
      match accept_cache(m, d) {
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
  // The arguments of the bundle belong to the bundled program.
  let args = bundled_arguments()
  let code = try {
    let r = @process.run(program, args, cwd=dir)
    r.exit_code
  } catch {
    err => {
      eprintln("LunaPack: cannot start " + program + ": " + err.to_string())
      1
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
