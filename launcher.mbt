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
/// Path of the running executable, when it can be determined.
pub fn current_exe_path() -> String? {
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
  @fs.mkdir(path, recursive=true, allow_exist=true) catch {
    _ => return false
  }
  true
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
  if @fs.exists(marker) {
    return Some(dir)
  }
  try {
    extract_to(pkg, dir, key)
    @fs.write_text(marker, "ok")
    Some(dir)
  } catch {
    _ => None
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
    None => None
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
      // temporary directory.
      let d = @fs.tmpdir(prefix="lunapack")
      eprintln("LunaPack: extracting " + m.main_program + " to " + d)
      extract_to(exe, d, key)
      d
    }
  }
  let program = dir + "/" + m.main_program
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
