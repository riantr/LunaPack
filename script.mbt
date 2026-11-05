// Execution of the optional pre_install / post_install scripts.
//
// The script body is stored verbatim inside the manifest together with the
// platform it targets. At unpack time the script is written into the
// destination directory and executed with the interpreter that matches the
// host; a script for a different platform is skipped.
//
// The script receives:
//   - the destination directory as its working directory
//   - $LUNAPACK_DEST pointing at the destination directory
//   - $LUNAPACK_PHASE set to "pre_install" or "post_install"

///|
/// Does a script targeting `script_platform` apply on `host`?
///
/// "any" always applies, "posix" covers Linux and macOS.
pub fn script_applies(script_platform : String, host : String) -> Bool {
  if script_platform == "any" {
    true
  } else if script_platform == host {
    true
  } else if script_platform == "posix" {
    host == "linux" || host == "macos"
  } else {
    false
  }
}

///|
/// Infer the target platform of a script from its file extension.
pub fn script_platform_of(path : String) -> String {
  let lower = path.to_lower()
  if lower.has_suffix(".cmd") || lower.has_suffix(".bat") {
    "windows"
  } else if lower.has_suffix(".sh") {
    "posix"
  } else if lower.has_suffix(".ps1") {
    "windows"
  } else {
    "any"
  }
}

///|
/// The name of the file the script of `kind` is written to.
///
/// The name is the same on every platform, and it is a name and not a path:
/// the script is written into the directory the interpreter runs in.
pub fn script_file_name(platform : String, kind : String) -> String {
  let (_, _, ext) = shell_for(platform)
  ".lunapack_" + kind + ext
}

///|
/// The absolute path of `dest`.
///
/// The script is told where it is going to work, and a relative path says
/// that only to the shell that happens to be in that directory. The path is
/// asked of the file system, which knows the answer even when the directory
/// was named relatively.
async fn absolute_dest(dest : String) -> String {
  let real = @fs.realpath(dest) catch { _ => return dest }
  norm_sep(real)
}

///|
/// Write `script` into `dest` as a runnable file for `platform`.
async fn write_script(
  platform : String,
  kind : String,
  script : Script,
  dest : String,
) -> String {
  let path = dest + "/" + script_file_name(platform, kind)
  @fs.write_binary(path, string_to_utf8_bytes(script.body))
  // Make the script executable on POSIX; a no-op on Windows.
  set_permissions(platform, path, 0o755)
  path
}

///|
/// Run the interpreter `interp` with `args` in `cwd` and return its exit status.
///
/// The interpreter is named in the error, because the spawn failure of the
/// runtime names no file: "The system cannot find the file specified." says
/// nothing about which interpreter was missing.
async fn run_interpreter(
  interp : String,
  args : Array[String],
  cwd : String,
) -> Int32 {
  @shell.Cmd(interp, args, cwd~).status() catch {
    err =>
      fail("cannot run the interpreter `" + interp + "`: " + err.to_string())
  }
}

///|
/// Write `script` into `dest`, run it with `interp`, and return its exit status.
///
/// The temporary file is removed on every path, including the one where the
/// interpreter could not be started: a script that was written into the
/// installation directory must not stay there.
async fn run_script(
  interp : String,
  extra : Array[String],
  platform : String,
  kind : String,
  script : Script,
  dest : String,
) -> Int32 {
  let path = write_script(platform, kind, script, dest)
  let args = []
  for a in extra {
    args.push(a)
  }
  // The interpreter is started in `dest`, where the script was written, so
  // the script is named by its name alone. A path would not do: the command
  // line of `cmd` reads a forward slash as the start of a switch, so
  // `cmd /c dir/script.cmd` does not run the script but complains that `.`
  // is not a command.
  args.push(script_file_name(platform, kind))
  @env.set_env_var("LUNAPACK_DEST", absolute_dest(dest))
  @env.set_env_var("LUNAPACK_PHASE", kind)
  // `status` inherits stdout/stderr so the user sees the script output.
  let status = run_interpreter(interp, args, dest) catch {
    err => {
      @fs.remove(path) catch {
        _ => ()
      }
      fail(err.to_string())
    }
  }
  @fs.remove(path) catch {
    _ => ()
  }
  status
}

///|
/// Run an install script of `kind` inside `dest` and return its exit status.
///
/// `platform` selects the interpreter, which makes the POSIX path testable on
/// any host.
pub async fn run_install_script(
  platform : String,
  kind : String,
  script : Script,
  dest : String,
) -> Int32 {
  let (interp, extra, _) = shell_for(platform)
  run_script(interp, extra, platform, kind, script, dest)
}
