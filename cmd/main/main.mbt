// LunaPack CLI entry point.
//
// Two equivalent front ends are supported.
//
// 1. The `moonx` style, used when the package is published to Mooncakes:
//
//      moonx riantr/LunaPack@latest \
//        --input-exe=[input-exe-path] \
//        --output-exe=[output-exe-path] \
//        --Files=[Pack-Folder]
//
//    `--input-exe` is the application executable to distribute, `--Files` is a
//    folder of extra files to bundle with it (repeatable), and `--output-exe`
//    is the produced single file. The result is the input executable with a
//    LunaPack archive appended, so it stays runnable while carrying the
//    bundled files.
//
// 2. Subcommands, which expose the full feature set:
//
//      lunapack pack   -i <input_dir> -o <output.appkg> [options]
//      lunapack unpack -i <package>   -o <dest_dir>    [--skip-scripts]
//      lunapack verify <package>
//      lunapack info   <package>
//
// Flags accept both `--flag=value` and `--flag value`.
//
// NOTE: in this MoonBit version `main` must return `Unit`, so process exit
// codes cannot be set. Status is reported on stdout:
//   "VERIFY OK" / "VERIFY FAILED" / "error: <msg>"

///|
/// One `--flag value` pair.
type Flag = (String, String)

///|
/// Parse `-f value`, `--flag=value` and `--flag value` pairs from `start`.
///
/// The leading dashes are stripped, so `-i` and `--input` both yield the key
/// "i" and "input" respectively.
fn parse_flags(args : ArrayView[String], start : Int32) -> Array[Flag] {
  let out = []
  let mut i = start
  while i < args.length() {
    let a = args[i]
    if a.has_prefix("-") && a.length() > 1 {
      // Skip the leading dashes.
      let mut key_start : Int32 = 0
      while key_start < a.length() && a[key_start] == '-' {
        key_start = key_start + 1
      }
      match a.find("=") {
        Some(pos) => {
          out.push((a[key_start:pos].to_owned(), a[pos + 1:].to_owned()))
          i = i + 1
        }
        None => {
          let key = a[key_start:].to_owned()
          if i + 1 < args.length() && !args[i + 1].has_prefix("-") {
            out.push((key, args[i + 1]))
            i = i + 2
          } else {
            out.push((key, "true"))
            i = i + 1
          }
        }
      }
    } else {
      i = i + 1
    }
  }
  out
}

///|
/// The value of the first occurrence of `key`, or "".
fn flag_value(flags : Array[Flag], key : String) -> String {
  for f in flags {
    if f.0 == key {
      return f.1
    }
  }
  ""
}

///|
/// The value of the first of `keys` that is present, or "".
fn flag_value_any(flags : Array[Flag], keys : Array[String]) -> String {
  for k in keys {
    let v = flag_value(flags, k)
    if v != "" {
      return v
    }
  }
  ""
}

///|
/// Every value of `key`, in order.
fn flag_values(flags : Array[Flag], key : String) -> Array[String] {
  let out = []
  for f in flags {
    if f.0 == key {
      out.push(f.1)
    }
  }
  out
}

///|
/// Read the whole content of a file as UTF-8 text.
async fn read_text_file(path : String) -> String {
  let data = @fs.read_file(path)
  @lib.utf8_bytes_to_string(data.binary())
}

///|
/// Build the pack options shared by both front ends.
async fn build_options(flags : Array[Flag]) -> @lib.PackOptions {
  let empty = @lib.new_pack_options("", "", "", "", None, None, "auto")
  let pre_path = flag_value(flags, "pre-install")
  let post_path = flag_value(flags, "post-install")
  let pre = if pre_path == "" {
    None
  } else {
    let body = read_text_file(pre_path) catch {
      err => {
        println("error: cannot read --pre-install script: " + err.to_string())
        return empty
      }
    }
    Some(@lib.new_script(@lib.script_platform_of(pre_path), body))
  }
  let post = if post_path == "" {
    None
  } else {
    let body = read_text_file(post_path) catch {
      err => {
        println("error: cannot read --post-install script: " + err.to_string())
        return empty
      }
    }
    Some(@lib.new_script(@lib.script_platform_of(post_path), body))
  }
  let compression = flag_value(flags, "compression")
  @lib.new_pack_options(
    flag_value(flags, "name"),
    flag_value(flags, "version"),
    flag_value(flags, "os"),
    flag_value(flags, "arch"),
    pre,
    post,
    if compression == "" {
      "auto"
    } else {
      compression
    },
  )
}

///|
fn usage() -> Unit {
  println("LunaPack - application distribution packer (MoonBit)")
  println("")
  println("usage (moonx):")
  println("  moonx riantr/LunaPack@latest --input-exe=[input-exe-path] \\")
  println("       --output-exe=[output-exe-path] --Files=[Pack-Folder]")
  println("")
  println("usage (native):")
  println("  lunapack pack   -i <input_dir> -o <output.appkg> [options]")
  println("  lunapack unpack -i <package>   -o <dest_dir> [--skip-scripts]")
  println("  lunapack verify <package>")
  println("  lunapack info   <package>")
  println("")
  println("options:")
  println("  --input-exe <path>      application executable to distribute")
  println("  --output-exe <path>     produced single-file bundle")
  println("  --Files <dir>           folder of files to bundle (repeatable)")
  println("  --name <name>           package name (default: input dir name)")
  println("  --version <version>     package version (default: 0.1.0)")
  println("  --os <os>               target OS tag (default: detected)")
  println("  --arch <arch>           target arch tag (default: detected)")
  println("  --pre-install <file>    script executed before extraction")
  println("  --post-install <file>   script executed after extraction")
  println("  --compression <mode>    none | gzip | auto (default: auto)")
}

///|
/// The `moonx` style front end.
async fn do_flags(flags : Array[Flag]) -> Unit {
  let input_exe = flag_value(flags, "input-exe")
  let output_exe = flag_value(flags, "output-exe")
  let file_dirs = flag_values(flags, "Files")
  if input_exe == "" && output_exe == "" && file_dirs.length() == 0 {
    usage()
    return
  }
  let base = build_options(flags)
  let name = if base.name == "" {
    if input_exe == "" {
      "app"
    } else {
      @lib.basename(input_exe)
    }
  } else {
    base.name
  }
  let opts = @lib.with_defaults(
    base,
    name,
    if base.version == "" {
      "0.1.0"
    } else {
      base.version
    },
    if base.os == "" {
      @lib.host_platform()
    } else {
      base.os
    },
    if base.arch == "" {
      @lib.default_arch()
    } else {
      base.arch
    },
  )
  try {
    if input_exe == "" {
      // No executable given: write a plain archive instead.
      let first = if file_dirs.length() > 0 { file_dirs[0] } else { "." }
      @lib.pack(first, output_exe, opts)
    } else {
      @lib.bundle(input_exe, output_exe, file_dirs, opts)
    }
  } catch {
    err => println("error: " + err.to_string())
  }
}

///|
/// The `pack` subcommand.
async fn do_pack(args : ArrayView[String]) -> Unit {
  let flags = parse_flags(args, 1)
  let input = flag_value_any(flags, ["input", "i"])
  let output = flag_value_any(flags, ["output", "o"])
  if input == "" || output == "" {
    println("error: pack requires -i <input_dir> and -o <output.appkg>")
    usage()
    return
  }
  let compression = flag_value(flags, "compression")
  if compression != "" &&
    compression != "none" &&
    compression != "gzip" &&
    compression != "auto" {
    println("error: --compression must be none, gzip or auto")
    return
  }
  let base = build_options(flags)
  let opts = @lib.with_defaults(
    base,
    if base.name == "" {
      @lib.basename(input)
    } else {
      base.name
    },
    if base.version == "" {
      "0.1.0"
    } else {
      base.version
    },
    if base.os == "" {
      @lib.host_platform()
    } else {
      base.os
    },
    if base.arch == "" {
      @lib.default_arch()
    } else {
      base.arch
    },
  )
  @lib.pack(input, output, opts) catch {
    err => println("error: " + err.to_string())
  }
}

///|
/// The `unpack` subcommand.
async fn do_unpack(args : ArrayView[String]) -> Unit {
  let flags = parse_flags(args, 1)
  let input = flag_value_any(flags, ["input", "i"])
  let output = flag_value_any(flags, ["output", "o"])
  if input == "" || output == "" {
    println("error: unpack requires -i <package> and -o <dest_dir>")
    usage()
    return
  }
  let skip = flag_value(flags, "skip-scripts") == "true"
  @lib.unpack(input, output, !skip) catch {
    err => println("error: " + err.to_string())
  }
}

///|
/// The `verify` subcommand.
async fn do_verify(args : ArrayView[String]) -> Unit {
  if args.length() < 2 {
    println("error: verify requires a package path")
    usage()
    return
  }
  try {
    let ok = @lib.verify(args[1])
    if ok {
      println("VERIFY OK")
    } else {
      println("VERIFY FAILED")
    }
  } catch {
    err => println("error: " + err.to_string())
  }
}

///|
/// The `info` subcommand.
async fn do_info(args : ArrayView[String]) -> Unit {
  if args.length() < 2 {
    println("error: info requires a package path")
    usage()
    return
  }
  try {
    let m = @lib.read_package_manifest(args[1])
    println("name:         " + m.name)
    println("version:      " + m.version)
    println("format:       v" + m.format_version.to_string())
    println("os/arch:      " + m.os + " / " + m.arch)
    println("checksum:     " + m.checksum_algo)
    println("compression:  " + m.compression)
    println("created_at:   " + m.created_at)
    println(
      "main program: " +
      (if m.main_program == "" { "-" } else { m.main_program }),
    )
    println(
      "scripts:      pre=" +
      (if m.pre_install is Some(_) { "yes" } else { "no" }) +
      " post=" +
      (if m.post_install is Some(_) { "yes" } else { "no" }),
    )
    println("entries:      " + m.entries.length().to_string())
    let mut total = 0L
    let mut stored = 0L
    for e in m.entries {
      total = total + e.size
      stored = stored + e.stored_size
      println(
        "  " +
        e.path +
        "  " +
        e.size.to_string() +
        " B  [" +
        e.codec +
        "]  " +
        e.checksum,
      )
    }
    println("total size:   " + total.to_string() + " B")
    println("stored size:  " + stored.to_string() + " B")
    if total > 0 {
      let pct = stored * 100L / total
      println("ratio:        " + pct.to_string() + "%")
    }
  } catch {
    err => println("error: " + err.to_string())
  }
}

///|
async fn main {
  // A self-extracting bundle carries its payload inside this executable:
  // start the bundled program instead of acting as a command line tool.
  let launched = @lib.try_launch_self_extracting() catch {
    err => {
      println("LunaPack: cannot start the bundled program: " + err.to_string())
      false
    }
  }
  if launched {
    return
  }
  let argv = @env.args()[1:]
  if argv.length() == 0 {
    usage()
    return
  }
  let first = argv[0]
  if first == "pack" {
    do_pack(argv)
  } else if first == "unpack" {
    do_unpack(argv)
  } else if first == "verify" {
    do_verify(argv)
  } else if first == "info" {
    do_info(argv)
  } else if first == "--help" || first == "-h" || first == "help" {
    usage()
  } else {
    do_flags(parse_flags(argv, 0))
  }
}
