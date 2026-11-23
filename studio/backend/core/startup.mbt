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
  key != "gui" && key != "skip-scripts" && key != "no-virtual"
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
    virtual_enabled: false,
    virtual_root: "",
    virtual_temp: "",
    registry_json: "",
    runtime_image: "",
    has_args: false,
  }
}

///|
/// Parse the process command line into the fields of the window. Later flags
/// win for single-valued fields, exactly as they would on the CLI; `--Files`
/// is repeatable and keeps its order.
pub fn parse_startup_args(argv : Array[String]) -> @shared.StartupReply {
  let mut reply = empty_startup_reply()
  let mut no_virtual = false
  for pair in flag_pairs(argv) {
    // Bare switches carry no value. They still change the form: `--virtual`
    // turns the layer on, `--no-virtual` turns it off.
    if pair.key == "no-virtual" {
      no_virtual = true
      reply = { ..reply, virtual_enabled: false, has_args: true, }
      continue
    }
    if pair.key == "virtual" && pair.value == "" {
      reply = { ..reply, virtual_enabled: true, has_args: true, }
      continue
    }
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
      "virtual" =>
        if pair.value == "false" || pair.value == "0" {
          reply = { ..reply, virtual_enabled: false, }
        } else if pair.value == "true" || pair.value == "1" {
          reply = { ..reply, virtual_enabled: true, }
        } else {
          // `--virtual C:\myroot` is the short form of --virtual-root.
          reply = { ..reply, virtual_enabled: true, virtual_root: pair.value, }
        }
      "virtual-root" =>
        reply = { ..reply, virtual_enabled: true, virtual_root: pair.value, }
      "virtual-temp" =>
        reply = { ..reply, virtual_enabled: true, virtual_temp: pair.value, }
      // The handler turns a forwarded registry path into the file's contents.
      "registry" =>
        reply = { ..reply, virtual_enabled: true, registry_json: pair.value, }
      "runtime" => reply = { ..reply, runtime_image: pair.value, }
      _ => ()
    }
  }
  if no_virtual {
    {
      ..reply,
      virtual_enabled: false,
      virtual_root: "",
      virtual_temp: "",
      registry_json: "",
      runtime_image: "",
    }
  } else {
    reply
  }
}
