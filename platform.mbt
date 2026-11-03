// Platform detection, path helpers and shell selection.
//
// The *host* platform is resolved at compile time, but every downstream
// decision is driven by a plain platform string. That keeps the Unix code
// path compiled - and unit-testable - on any host.

///|
/// The platform this binary was compiled for.
#cfg(all(target="native", platform="windows"))
fn compiled_platform() -> String {
  "windows"
}

///|
#cfg(all(target="native", platform="linux"))
fn compiled_platform() -> String {
  "linux"
}

///|
#cfg(all(target="native", platform="macos"))
fn compiled_platform() -> String {
  "macos"
}

///|
#cfg(target="wasm")
fn compiled_platform() -> String {
  "wasm"
}

///|
#cfg(target="llvm")
fn compiled_platform() -> String {
  "llvm"
}

///|
/// Does the environment variable `key` exist?
fn env_has(key : String) -> Bool {
  match @env.get_env_var(key) {
    Some(_) => true
    None => false
  }
}

///|
/// Does the environment variable `key` contain `needle`?
fn env_contains(key : String, needle : String) -> Bool {
  match @env.get_env_var(key) {
    Some(v) => v.contains(needle)
    None => false
  }
}

///|
/// Detect the host OS from environment variables.
///
/// Under Wasm the compile-time platform is "wasm", but the program still runs
/// on a real operating system, so the environment is consulted instead.
fn detect_platform_from_env() -> String {
  if env_contains("OS", "Windows") || env_has("COMSPEC") {
    "windows"
  } else if env_contains("OSTYPE", "darwin") ||
    env_contains("HOSTTYPE", "darwin") {
    "macos"
  } else if env_has("HOME") || env_has("OSTYPE") || env_has("HOSTTYPE") {
    "linux"
  } else {
    "unknown"
  }
}

///|
/// Name of the platform the program is running on.
pub fn host_platform() -> String {
  let c = compiled_platform()
  if c == "windows" || c == "linux" || c == "macos" {
    c
  } else {
    detect_platform_from_env()
  }
}

///|
/// How a script must be executed on `platform`:
/// (interpreter, extra arguments, script file extension).
///
/// Windows batch scripts need `cmd /c`; POSIX shells need plain `sh`.
pub fn shell_for(platform : String) -> (String, Array[String], String) {
  if platform == "windows" {
    ("cmd", ["/c"], ".cmd")
  } else {
    ("sh", [], ".sh")
  }
}

///|
/// Set UNIX permission bits on `path`.
///
/// Windows has no UNIX permission bits and the async runtime's `chmod` is not
/// implemented there, so the call is skipped on Windows.
pub async fn set_permissions(
  platform : String,
  path : String,
  mode : Int32,
) -> Unit {
  if platform != "windows" {
    // The async runtime does not implement chmod on Windows at all, and some
    // filesystems reject it outright; permissions are best-effort.
    @fs.chmod(path, mode) catch {
      _ => ()
    }
  }
}

///|
/// Normalize path separators to '/' so host FS calls work uniformly on
/// Windows (which returns '\' from realpath) and inside the package format.
pub fn norm_sep(p : String) -> String {
  p.replace_all(old="\\", new="/")
}

///|
/// Map a machine-specific architecture name onto a portable one.
fn normalize_arch(raw : String) -> String {
  if raw == "AMD64" || raw == "amd64" || raw == "x86_64" || raw == "x64" {
    "x86_64"
  } else if raw == "ARM64" || raw == "arm64" || raw == "aarch64" {
    "aarch64"
  } else if raw == "x86" || raw == "i386" || raw == "i686" {
    "x86"
  } else {
    raw
  }
}

///|
/// Best-effort detection of the host CPU architecture.
/// Windows exposes PROCESSOR_ARCHITECTURE; some POSIX shells export HOSTTYPE.
pub fn default_arch() -> String {
  match @env.get_env_var("PROCESSOR_ARCHITECTURE") {
    Some(v) => normalize_arch(v)
    None =>
      match @env.get_env_var("PROCESSOR_ARCHITEW6432") {
        Some(v) => normalize_arch(v)
        None =>
          match @env.get_env_var("HOSTTYPE") {
            Some(v) => normalize_arch(v)
            None => "unknown"
          }
      }
  }
}

///|
/// The directory part of a path, or "" when the path has no directory.
pub fn dirname(p : String) -> String {
  let n = p.length()
  let mut i = n - 1
  while i >= 0 {
    let c = p[i]
    if c == '/' || c == '\\' {
      if i == 0 {
        return "/"
      }
      return p[:i].to_owned()
    }
    i = i - 1
  }
  ""
}

///|
/// Create the parent directory of `path` when it does not exist yet.
pub async fn ensure_parent_dir(path : String) -> Unit {
  let parent = dirname(path)
  if parent != "" {
    @fs.mkdir(parent, recursive=true, allow_exist=true)
  }
}

///|
/// The base name of a path, without any directory part.
pub fn basename(p : String) -> String {
  let n = p.length()
  let mut i = n - 1
  while i >= 0 {
    let c = p[i]
    if c == '/' || c == '\\' {
      return p[i + 1:].to_owned()
    }
    i = i - 1
  }
  p
}

///|
/// Path of `full` relative to `base`.
pub fn relpath(base : String, full : String) -> String {
  let n = base.length()
  if full.length() > n && (full[n] == '/' || full[n] == '\\') {
    full[n + 1:].to_owned()
  } else if full.length() == n {
    basename(full)
  } else {
    full[n:].to_owned()
  }
}
