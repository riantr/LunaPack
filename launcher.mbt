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
fn cache_dir(exe_path : String, tag : String) -> String {
  let dir = dirname(exe_path)
  if dir == "" {
    return ""
  }
  dir + "/.lunapack/" + tag
}

///|
/// Extract the payload into the cache folder next to the executable.
///
/// Returns the folder, or None when that location cannot be used.
async fn extract_to_cache(
  pkg : String,
  exe_path : String,
  m : Manifest,
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
    extract_to(pkg, dir)
    @fs.write_file(marker, "ok")
    Some(dir)
  } catch {
    _ => None
  }
}

///|
/// Extract the payload carried by the running executable and start the
/// bundled program.
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
  let dir = match extract_to_cache(exe, exe, m) {
    Some(d) => d
    None => {
      // The folder next to the executable is not usable, fall back to a
      // temporary directory.
      let d = @fs.tmpdir(prefix="lunapack")
      println("LunaPack: extracting " + m.main_program + " to " + d)
      extract_to(exe, d)
      d
    }
  }
  let program = dir + "/" + m.main_program
  println("LunaPack: starting " + program)
  let _ = @process.run(program, [], cwd=dir)
  true
}
