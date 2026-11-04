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
/// Is `key` present at all?
///
/// A flag that switches something on does not need a value, and the parser
/// cannot tell a bare `--flag` from `--flag value`, so the presence of the
/// flag is what counts.
fn flag_has(flags : Array[Flag], key : String) -> Bool {
  for f in flags {
    if f.0 == key {
      return true
    }
  }
  false
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
  let data = @fs.read_binary(path)
  utf8_bytes_to_string(data)
}

///|
/// The passphrase of the encryption, from a file or from the command line.
///
/// The file is the better choice: a passphrase that is given on the command
/// line can be seen by every process on the machine.
async fn read_passphrase(flags : Array[Flag]) -> String {
  let file = flag_value(flags, "passphrase-file")
  if file != "" {
    let text = read_text_file(file) catch {
      err => fail("cannot read the passphrase file: " + err.to_string())
    }
    // The line ending at the end of the file is not part of the passphrase.
    let mut end = text.length()
    while end > 0 {
      let c = text[end - 1]
      if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
        end = end - 1
      } else {
        break
      }
    }
    return text[0:end].to_owned()
  }
  flag_value(flags, "passphrase")
}

///|
/// The encryption of the package, from the flags.
///
/// Returns None when the package is not to be encrypted.
async fn encryption_options(flags : Array[Flag]) -> EncryptionOptions? {
  let mut kind = flag_value(flags, "encryption-method")
  if kind == "" {
    kind = flag_value(flags, "encryption")
  }
  if kind == "" || kind == "none" {
    return None
  }
  if kind != METHOD_X25519 && kind != METHOD_PASSPHRASE {
    fail("--encryption-method must be x25519 or passphrase")
  }
  let public_key = flag_value(flags, "public-key")
  let passphrase = if kind == METHOD_PASSPHRASE {
    read_passphrase(flags)
  } else {
    ""
  }
  if kind == METHOD_X25519 && public_key == "" {
    fail("--encryption-method x25519 needs --public-key")
  }
  if kind == METHOD_PASSPHRASE && passphrase == "" {
    fail("--encryption-method passphrase needs --passphrase-file")
  }
  Some(
    new_encryption_options(kind, public_key, passphrase, PASSPHRASE_ITERATIONS),
  )
}

///|
/// The key of an encrypted package, from the flags.
///
/// Returns None when the package is not encrypted.
async fn package_key(flags : Array[Flag], m : Manifest) -> PackageKey? {
  match m.encryption {
    None => None
    Some(info) => {
      // The passphrase is needed in two places: for a package that is sealed
      // with one, and for a secret key file that one protects. The same
      // flag serves both.
      let passphrase = read_passphrase(flags)
      let secret = flag_value(flags, "secret-key")
      if info.method_name != METHOD_PASSPHRASE && secret == "" {
        fail("the package is encrypted: it needs --secret-key")
      }
      Some(recover_encryption(info, secret, passphrase))
    }
  }
}

///|
/// Build the pack options shared by both front ends.
async fn build_options(flags : Array[Flag]) -> PackOptions {
  let empty = new_pack_options("", "", "", "", None, None, "auto")
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
    Some(new_script(script_platform_of(pre_path), body))
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
    Some(new_script(script_platform_of(post_path), body))
  }
  // The compression method; `--compression` is the older name of the flag.
  let mut compression = flag_value(flags, "compression-method")
  if compression == "" {
    compression = flag_value(flags, "compression")
  }
  new_pack_options(
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
  println(
    "  lunapack bundle -i <exe> -o <output.exe> [--Files <dir>]... [options]",
  )
  println("  lunapack unpack -i <package>   -o <dest_dir> [--skip-scripts]")
  println("  lunapack verify <package> [--extracted <dir>]")
  println("  lunapack info   <package>")
  println("  lunapack keygen --public-key <file> --secret-key <file>")
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
  println("  --compression-method <m> none | gzip | lz4 | auto (default: auto)")
  println(
    "  --launcher <file>       launcher for the single file (default: this one)",
  )
  println("")
  println("encryption:")
  println("  --encryption-method <m>  x25519 | passphrase")
  println("  --public-key <file>      public key of the recipient")
  println("  --secret-key <file>      secret key of the recipient")
  println("  --passphrase-file <file> file that holds the passphrase")
  println(
    "  --passphrase <text>      the passphrase (visible in the process list)",
  )
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
      basename(input_exe)
    }
  } else {
    base.name
  }
  let opts = with_defaults(
    base,
    name,
    if base.version == "" {
      "0.1.0"
    } else {
      base.version
    },
    if base.os == "" {
      host_platform()
    } else {
      base.os
    },
    if base.arch == "" {
      default_arch()
    } else {
      base.arch
    },
  )
  try {
    let opts = match encryption_options(flags) {
      Some(e) => with_encryption(opts, e)
      None => opts
    }
    if input_exe == "" {
      // No executable given: write a plain archive instead.
      let first = if file_dirs.length() > 0 { file_dirs[0] } else { "." }
      pack(first, output_exe, opts)
    } else {
      bundle(
        input_exe,
        output_exe,
        file_dirs,
        opts,
        flag_value(flags, "launcher"),
      )
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
  let compression = flag_value_any(flags, ["compression-method", "compression"])
  if compression != "" &&
    compression != "none" &&
    compression != "gzip" &&
    compression != "lz4" &&
    compression != "auto" {
    println("error: --compression-method must be none, gzip, lz4 or auto")
    return
  }
  try {
    let base = build_options(flags)
    let opts = with_defaults(
      base,
      if base.name == "" {
        basename(input)
      } else {
        base.name
      },
      if base.version == "" {
        "0.1.0"
      } else {
        base.version
      },
      if base.os == "" {
        host_platform()
      } else {
        base.os
      },
      if base.arch == "" {
        default_arch()
      } else {
        base.arch
      },
    )
    let opts = match encryption_options(flags) {
      Some(e) => with_encryption(opts, e)
      None => opts
    }
    pack(input, output, opts)
  } catch {
    err => println("error: " + err.to_string())
  }
}

///|
/// The `bundle` subcommand.
///
/// It makes a single file that starts on its own: the program, the files it
/// needs and a launcher that unpacks them and starts the program.
async fn do_bundle(args : ArrayView[String]) -> Unit {
  let flags = parse_flags(args, 1)
  let input = flag_value_any(flags, ["input", "i"])
  let output = flag_value_any(flags, ["output", "o"])
  if input == "" || output == "" {
    println("error: bundle requires -i <input_exe> and -o <output_exe>")
    usage()
    return
  }
  try {
    let base = build_options(flags)
    let opts = with_defaults(
      base,
      if base.name == "" {
        basename(input)
      } else {
        base.name
      },
      if base.version == "" {
        "0.1.0"
      } else {
        base.version
      },
      if base.os == "" {
        host_platform()
      } else {
        base.os
      },
      if base.arch == "" {
        default_arch()
      } else {
        base.arch
      },
    )
    let opts = match encryption_options(flags) {
      Some(e) => with_encryption(opts, e)
      None => opts
    }
    bundle(
      input,
      output,
      flag_values(flags, "Files"),
      opts,
      flag_value(flags, "launcher"),
    )
  } catch {
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
  let skip = flag_has(flags, "skip-scripts")
  try {
    let m = read_package_manifest(input)
    let key = package_key(flags, m)
    unpack(input, output, !skip, key)
  } catch {
    err => println("error: " + err.to_string())
  }
}

///|
/// The `verify` subcommand.
///
/// `verify <package>` checks the package itself. `verify <package> --extracted
/// <dir>` also checks the files that are already in `dir` against the
/// fingerprints of the package.
async fn do_verify(args : ArrayView[String]) -> Unit {
  if args.length() < 2 {
    println("error: verify requires a package path")
    usage()
    return
  }
  try {
    let flags = parse_flags(args, 1)
    let extracted = flag_value(flags, "extracted")
    let m = read_package_manifest(args[1])
    let key = package_key(flags, m)
    let ok = verify(args[1], key)
    if extracted != "" {
      if verify_extracted_dir(args[1], extracted) {
        println("VERIFY OK")
      } else {
        println("VERIFY FAILED")
      }
      return
    }
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
/// The `keygen` subcommand.
///
/// It makes a pair of keys: the public key goes to the machine that seals
/// the packages, the secret key to the machine that opens them.
async fn do_keygen(args : ArrayView[String]) -> Unit {
  let flags = parse_flags(args, 1)
  let public_path = flag_value(flags, "public-key")
  let secret_path = flag_value(flags, "secret-key")
  if public_path == "" || secret_path == "" {
    println(
      "error: keygen requires --public-key <file> and --secret-key <file>",
    )
    usage()
    return
  }
  try {
    let secret = random_bytes(32)
    let public = x25519_public_key(secret)
    save_public_key(public_path, public)
    let passphrase = read_passphrase(flags)
    if passphrase == "" {
      save_secret_key_raw(secret_path, secret)
    } else {
      save_secret_key(secret_path, secret, passphrase)
    }
    println("wrote the public key to " + public_path)
    println("wrote the secret key to " + secret_path)
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
    let m = read_package_manifest(args[1])
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
    println(
      "encryption:   " +
      (match m.encryption {
        Some(e) => e.method_name
        None => "none"
      }),
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
      if e.md5 != "" {
        println("      md5  " + e.md5)
      }
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
  let launched = try_launch_self_extracting() catch {
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
  } else if first == "bundle" {
    do_bundle(argv)
  } else if first == "unpack" {
    do_unpack(argv)
  } else if first == "verify" {
    do_verify(argv)
  } else if first == "info" {
    do_info(argv)
  } else if first == "keygen" {
    do_keygen(argv)
  } else if first == "--help" || first == "-h" || first == "help" {
    usage()
  } else {
    do_flags(parse_flags(argv, 0))
  }
}
