///|
/// Pure argument building, kept away from Proton's native runtime so it can be
/// tested by a plain native test binary.
///
/// The CLI that makes the bundle is the LunaPack executable itself: it is the
/// stub appended to the archive, so a bundle made with it can unpack and run
/// its payload. A GUI process is not a usable stub, which is why the backend
/// starts the CLI instead of importing the packing code into this process.
pub fn default_cli() -> String {
  "../LunaPack/_build/native/release/build/LunaPack.exe"
}

///|
pub fn cli_candidates() -> Array[String] {
  [
    "../LunaPack/_build/native/release/build/LunaPack.exe", "../LunaPack/_build/native/debug/build/LunaPack.exe",
    "LunaPack.exe",
  ]
}

///|
/// Build the argument array for `LunaPack.exe bundle`. Arguments are passed as
/// an array, never through a shell, so paths with spaces or quotes are safe.
///
/// The `bundle` subcommand reads `--input` / `--output` (or `-i` / `-o`).
/// The documented `--input-exe` / `--output-exe` spellings are accepted by the
/// flag checker but only read by the no-subcommand `moonx` front end, so using
/// them here would make bundle report "requires -i and -o" and exit.
pub fn bundle_arguments(request : @shared.ProcessRequest) -> Array[String] {
  let args : Array[String] = [
    "bundle",
    "--input",
    request.input_exe,
    "--output",
    request.output_exe,
  ]
  for dir in request.file_dirs {
    if dir != "" {
      args.push("--Files")
      args.push(dir)
    }
  }
  if request.compression != "" {
    args.push("--compression-method")
    args.push(request.compression)
  }
  if request.name != "" {
    args.push("--name")
    args.push(request.name)
  }
  if request.version != "" {
    args.push("--version")
    args.push(request.version)
  }
  if request.target_os != "" {
    args.push("--os")
    args.push(request.target_os)
  }
  if request.arch != "" {
    args.push("--arch")
    args.push(request.arch)
  }
  if request.launcher != "" {
    args.push("--launcher")
    args.push(request.launcher)
  }
  args
}
