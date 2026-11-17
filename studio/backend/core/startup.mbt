///|
/// Startup argument parsing, kept pure so it can be tested by a plain native
/// test binary. Proton's native runtime cannot be linked into a test process
/// without a window, which is why nothing here touches the bridge.
///
/// `lunapack --GUI` forwards the flags the user already typed. Every alias the
/// CLI accepts is understood here, in both `--flag value` and `--flag=value`
/// form. Unknown flags and positional arguments are ignored rather than
/// treated as errors: the window has to open even when it is handed something
/// it does not understand.

///|
priv struct FlagPair {
  key : String
  value : String
}

///|
fn normalize_key(raw : String) -> String {
  let mut start = 0
  while start < raw.length() && raw[start] == '-' {
    start = start + 1
  }
  raw[start:].to_owned().to_lower()
}

///|
/// Does this flag take a value? Gate-like switches such as `--GUI` do not, so
/// the next word must not be swallowed as their value.
fn takes_value(key : String) -> Bool {
  key != "gui" && key != "skip-scripts"
}

///|
fn flag_pairs(argv : Array[String]) -> Array[FlagPair] {
  let out : Array[FlagPair] = []
  // argv[0] is the executable. A window started directly has no flags at all.
  let mut i = 1
  while i < argv.length() {
    let arg = argv[i]
    if !arg.has_prefix("-") || arg == "-" {
      i = i + 1
      continue
    }
    match arg.find("=") {
      Some(pos) => {
        out.push({
          key: normalize_key(arg[:pos].to_owned()),
          value: arg[pos + 1:].to_owned(),
        })
        i = i + 1
      }
      None => {
        let key = normalize_key(arg)
        if takes_value(key) &&
          i + 1 < argv.length() &&
          !argv[i + 1].has_prefix("-") {
          out.push({ key, value: argv[i + 1], })
          i = i + 2
        } else {
          out.push({ key, value: "", })
          i = i + 1
        }
      }
    }
  }
  out
}

///|
pub fn empty_startup_reply() -> @shared.StartupReply {
  {
    input_exe: "",
    output_exe: "",
    file_dirs: [],
    cli_path: "",
    launcher: "",
    compression: "",
    name: "",
    version: "",
    target_os: "",
    arch: "",
    has_args: false,
  }
}

///|
/// Parse the process command line into the fields of the window. Later flags
/// win for single-valued fields, exactly as they would on the CLI; `--Files`
/// is repeatable and keeps its order.
pub fn parse_startup_args(argv : Array[String]) -> @shared.StartupReply {
  let mut reply = empty_startup_reply()
  for pair in flag_pairs(argv) {
    if pair.value == "" {
      continue
    }
    reply = { ..reply, has_args: true, }
    match pair.key {
      "i" | "input" | "input-exe" | "input-file" =>
        reply = { ..reply, input_exe: pair.value, }
      "o" | "output" | "output-exe" | "output-file" =>
        reply = { ..reply, output_exe: pair.value, }
      "files" | "file-dirs" | "file-dir" => reply.file_dirs.push(pair.value)
      "cli" => reply = { ..reply, cli_path: pair.value, }
      "launcher" => reply = { ..reply, launcher: pair.value, }
      "compression" | "compression-method" =>
        reply = { ..reply, compression: pair.value, }
      "name" => reply = { ..reply, name: pair.value, }
      "version" => reply = { ..reply, version: pair.value, }
      "os" => reply = { ..reply, target_os: pair.value, }
      "arch" => reply = { ..reply, arch: pair.value, }
      _ => ()
    }
  }
  reply
}
