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
//    folder of extra files to bundle with it (repeatable, and `--files` is the
//    same flag), and `--output-exe` is the produced single file. The result is
//    the input executable with a LunaPack archive appended, so it stays
//    runnable while carrying the bundled files.
//
// 2. Subcommands, which expose the full feature set:
//
//      lunapack pack   -i <input_dir> -o <output.appkg> [options]
//      lunapack unpack -i <package>   -o <dest_dir>    [--skip-scripts]
//      lunapack verify <package>
//      lunapack info   <package>
//
// 3. `--GUI`, which opens LunaPack Studio with the same flags already filled
//    in. Studio is part of this release, not a separate package; it is
//    downloaded on first use when it is not installed beside the CLI.
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
    // `i` only advances while `i < args.length()`, so `args[i]` is always a
    // valid index; the index is provably within the array bounds.
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
/// Every folder of `--Files`, in the order the folders were given.
///
/// `--Files` and `--files` are one flag with two spellings, and the walk is
/// one pass over the arguments rather than two lists joined together: that is
/// what keeps the order of a command line that mixes the two, and the order is
/// the one thing a caller can see here.
fn file_dirs_of(flags : Array[Flag]) -> Array[String] {
  let out = []
  for f in flags {
    if f.0 == "Files" || f.0 == "files" {
      out.push(f.1)
    }
  }
  out
}

///|
/// The flags the tool knows.
///
/// A flag that is not in this list is a mistake, and a mistake that is
/// silently ignored is the worst kind: the command then does something
/// else than what was asked, and says nothing about it. `--input-file` for
/// instance is not `--input-exe`, and taking it for one would leave the
/// output path empty.
///
/// The one flag with two spellings is `--Files`: it is written with a capital
/// letter in this documentation and in every example, and a command line that
/// reaches for `--files` means the same thing. Both are listed here, so
/// neither is a mistake, and `file_dirs_of` reads the two as one flag.
fn known_flags() -> Array[String] {
  [
    "Files", "GUI", "arch", "cli", "compression", "compression-method", "encryption",
    "encryption-method", "gui", "expected-sha256", "extracted", "files", "i", "input",
    "input-exe", "input-file", "launcher", "name", "no-auto-deps", "o", "os", "output",
    "output-exe", "output-file", "passphrase", "passphrase-file", "post-install",
    "pre-install", "public-key", "secret-key", "signature", "skip-scripts", "version",
  ]
}

///|
/// The names of the flags of `flags` that the tool does not know.
///
/// The names come back in the order they were given, and each of them only
/// once.
fn unknown_flags(flags : Array[Flag]) -> Array[String] {
  let known = known_flags()
  let out = []
  for f in flags {
    if !known.contains(f.0) && !out.contains(f.0) {
      out.push(f.0)
    }
  }
  out
}

///|
/// The message that names the flags the tool does not know.
///
/// The flags the tool does know are named with their dashes, so that the
/// list can be read and used as it is.
fn unknown_flags_message(flags : Array[Flag]) -> String {
  let names = []
  for f in unknown_flags(flags) {
    names.push("--" + f)
  }
  let all = []
  for f in known_flags() {
    all.push("--" + f)
  }
  if names.length() == 1 {
    "unknown flag " + names[0] + " (the flags are: " + all.join(" ") + ")"
  } else {
    "unknown flags " +
    names.join(" ") +
    " (the flags are: " +
    all.join(" ") +
    ")"
  }
}

///|
/// Fail when a flag of `flags` is not one the tool knows.
fn check_flags(flags : Array[Flag]) -> Unit raise {
  if unknown_flags(flags).length() > 0 {
    fail(unknown_flags_message(flags))
  }
}

///|
/// The path the output of a command goes to, or an error when it is empty.
///
/// An empty path is what a mistyped flag leaves behind, and a command that
/// writes to it fails with a message about the file system instead of about
/// the flag that was wrong.
fn require_output(output : String, flag_name : String) -> String raise {
  if output == "" {
    fail("the output path is empty: " + flag_name + " must name a file")
  }
  output
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
    None => {
      // The package says that it is not encrypted. A key that was given
      // anyway says that the package is not the one it says it is, so it is
      // refused instead of being opened.
      if flag_value(flags, "secret-key") != "" ||
        flag_value(flags, "passphrase-file") != "" {
        fail(
          "the package says that it is not encrypted, but a key was given: the package was changed",
        )
      }
      None
    }
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
  let pre_path = flag_value(flags, "pre-install")
  let post_path = flag_value(flags, "post-install")
  let pre = if pre_path == "" {
    None
  } else {
    // An unreadable script is an error. Returning empty options would throw
    // away every other flag the caller gave, and the package would be built
    // with defaults while the command looked as though it had succeeded.
    let body = read_text_file(pre_path) catch {
      err => fail("cannot read --pre-install script: " + err.to_string())
    }
    Some(new_script(script_platform_of(pre_path), body))
  }
  let post = if post_path == "" {
    None
  } else {
    let body = read_text_file(post_path) catch {
      err => fail("cannot read --post-install script: " + err.to_string())
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
  println("  lunapack sign   <package> --secret-key <file> [--output <file>]")
  println("  lunapack info   <package>")
  println("  lunapack keygen --public-key <file> --secret-key <file>")
  println(
    "  lunapack --GUI [--input-file <exe>] [--output-file <exe>] [--Files <dir>]...",
  )
  println("")
  println("graphical front end:")
  println(
    "  --GUI                   open LunaPack Studio with the flags above filled in",
  )
  println(
    "                          (downloaded from this release on first use)",
  )
  println("")
  println("options:")
  println("  --input-exe <path>      application executable to distribute")
  println("  --output-exe <path>     produced single-file bundle")
  println(
    "  --Files <dir>           folder of files to bundle (repeatable; --files too)",
  )
  println(
    "  --no-auto-deps          do not add the libraries the program needs next to it",
  )
  println("  --input-file <path>     another name for --input-exe")
  println("  --output-file <path>    another name for --output-exe")
  println("  --name <name>           package name (default: input dir name)")
  println("  --version <version>     package version (default: 0.1.0)")
  println("  --os <os>               target OS tag (default: detected)")
  println("  --arch <arch>           target arch tag (default: detected)")
  println("  --pre-install <file>    script executed before extraction")
  println("  --post-install <file>   script executed after extraction")
  println("  --compression-method <m> none | gzip | lz4 | auto (default: auto)")
  println(
    "  --launcher [file]       native launcher for the single file (default: this one)",
  )
  println(
    "                          give no file to download the launcher for this system automatically",
  )
  println("")
  println("verification:")
  println(
    "  --signature <file>      signature the host published for the package",
  )
  println(
    "  --public-key <file>     public key of the host that signed it (ed25519)",
  )
  println("  --expected-sha256 <hex> digest the host published for the package")
  println("")
  println("encryption:")
  println("  --encryption-method <m>  x25519 | passphrase")
  println("  --public-key <file>      public key of the recipient (x25519)")
  println("  --secret-key <file>      secret key of the recipient")
  println("  --passphrase-file <file> file that holds the passphrase")
  println(
    "  --passphrase <text>      the passphrase (visible in the process list)",
  )
}

///|
/// The libraries next to the program that it needs, unless the caller said
/// not to.
///
/// The list is printed, because a bundle that quietly carries a file nobody
/// asked for is a bundle whose size nobody can explain.
async fn auto_dependency_files(
  exe : String,
  flags : Array[Flag],
) -> Array[String] {
  if flag_has(flags, "no-auto-deps") {
    return []
  }
  let found = discover_dependencies(exe)
  if found.length() == 0 {
    return []
  }
  println(
    "discovered " +
    found.length().to_string() +
    " dependencies next to the program:",
  )
  for f in found {
    println("  " + basename(f))
  }
  found
}

///|
/// Bundle the program at `input_exe` into the file at `output_exe`.
///
/// The files the caller named are carried, and so are the libraries the
/// program needs from the folder it sits in: a bundle that carries only the
/// program starts and then stops with STATUS_DLL_NOT_FOUND. The flag
/// `--no-auto-deps` says that only the named files are carried.
async fn bundle_program(
  input_exe : String,
  output_exe : String,
  file_dirs : Array[String],
  flags : Array[Flag],
  opts : PackOptions,
) -> Unit {
  let extra = auto_dependency_files(input_exe, flags)
  bundle_with_files(
    input_exe,
    output_exe,
    file_dirs,
    extra,
    opts,
    resolve_launcher(flags),
  )
}

///|
/// The `moonx` style front end.
async fn do_flags(flags : Array[Flag]) -> Unit {
  let input_exe = flag_value_any(flags, ["input-exe", "input-file"])
  let output_exe = flag_value_any(flags, ["output-exe", "output-file"])
  let file_dirs = file_dirs_of(flags)
  if input_exe == "" && output_exe == "" && file_dirs.length() == 0 {
    usage()
    return
  }
  try {
    check_flags(flags)
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
    let opts = match encryption_options(flags) {
      Some(e) => with_encryption(opts, e)
      None => opts
    }
    if input_exe == "" {
      // No executable given: write a plain archive instead.
      let first = if file_dirs.length() > 0 { file_dirs[0] } else { "." }
      pack(first, require_output(output_exe, "--output-exe"), opts)
    } else {
      bundle_program(
        input_exe,
        require_output(output_exe, "--output-exe"),
        file_dirs,
        flags,
        opts,
      )
    }
  } catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
    }
  }
}

///|
/// The `pack` subcommand.
async fn do_pack(args : ArrayView[String]) -> Unit {
  let flags = parse_flags(args, 1)
  check_flags(flags) catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
      return
    }
  }
  let input = flag_value_any(flags, ["input", "i"])
  let output = flag_value_any(flags, ["output", "o"])
  if input == "" || output == "" {
    println("error: pack requires -i <input_dir> and -o <output.appkg>")
    usage()
    exit_with(1)
    return
  }
  let compression = flag_value_any(flags, ["compression-method", "compression"])
  if compression != "" &&
    compression != "none" &&
    compression != "gzip" &&
    compression != "lz4" &&
    compression != "auto" {
    println("error: --compression-method must be none, gzip, lz4 or auto")
    exit_with(1)
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
    err => {
      println("error: " + err.to_string())
      exit_with(1)
    }
  }
}

///|
/// The `bundle` subcommand.
///
/// It makes a single file that starts on its own: the program, the files it
/// needs and a launcher that unpacks them and starts the program.
async fn do_bundle(args : ArrayView[String]) -> Unit {
  let flags = parse_flags(args, 1)
  check_flags(flags) catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
      return
    }
  }
  let input = flag_value_any(flags, ["input", "i"])
  let output = flag_value_any(flags, ["output", "o"])
  if input == "" || output == "" {
    println("error: bundle requires -i <input_exe> and -o <output_exe>")
    usage()
    exit_with(1)
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
    bundle_program(input, output, file_dirs_of(flags), flags, opts)
  } catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
    }
  }
}

///|
/// The `unpack` subcommand.
async fn do_unpack(args : ArrayView[String]) -> Unit {
  let flags = parse_flags(args, 1)
  check_flags(flags) catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
      return
    }
  }
  let input = flag_value_any(flags, ["input", "i"])
  let output = flag_value_any(flags, ["output", "o"])
  if input == "" || output == "" {
    println("error: unpack requires -i <package> and -o <dest_dir>")
    usage()
    exit_with(1)
    return
  }
  let skip = flag_has(flags, "skip-scripts")
  try {
    // A signature or a digest that the host published is checked before the
    // package is opened at all. The flags are honoured here as well as in
    // `verify`, because a flag that is accepted and then ignored is worse
    // than a flag that is refused: the user believes the package was
    // checked, and it was not.
    let signature_path = flag_value(flags, "signature")
    let public_path = flag_value(flags, "public-key")
    let expected = flag_value(flags, "expected-sha256")
    if signature_path != "" {
      let text = read_text_file(signature_path) catch {
        err => fail("cannot read the signature file: " + err.to_string())
      }
      let signature = match signature_from_text(text) {
        Some(s) => s
        None => fail("the signature file is not one")
      }
      if public_path == "" {
        fail(
          "a signature is checked against a public key: --public-key is missing",
        )
      }
      let public = load_signing_public_key(public_path)
      if !verify_package_signature(input, signature, public) {
        fail(
          "the signature of the package does not hold: the package is refused",
        )
      }
      println("the signature of the package holds")
    }
    if expected != "" {
      if !verify_package_digest(input, expected) {
        fail(
          "the digest of the package is not the one that was expected: the package is refused",
        )
      }
      println("the digest of the package is the one that was expected")
    }
    let m = read_package_manifest(input)
    let key = package_key(flags, m)
    unpack(input, output, !skip, key)
  } catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
    }
  }
}

///|
/// The `verify` subcommand.
///
/// `verify <package>` checks the package itself. `verify <package> --extracted
/// <dir>` also checks the files that are already in `dir` against the
/// fingerprints of the package.
///
/// `verify <package> --signature <file> --public-key <file>` checks the
/// signature that the host published next to the package, and
/// `verify <package> --expected-sha256 <digest>` checks the digest that the
/// host published. Both are the material of the host, so they are checked
/// before the package is opened at all.
async fn do_verify(args : ArrayView[String]) -> Unit {
  if args.length() < 2 {
    println("error: verify requires a package path")
    usage()
    exit_with(1)
    return
  }
  try {
    let flags = parse_flags(args, 1)
    check_flags(flags)
    let signature_path = flag_value(flags, "signature")
    let public_path = flag_value(flags, "public-key")
    let expected = flag_value(flags, "expected-sha256")
    if signature_path != "" {
      let text = read_text_file(signature_path) catch {
        err => fail("cannot read the signature file: " + err.to_string())
      }
      let signature = match signature_from_text(text) {
        Some(s) => s
        None => fail("the signature file is not one")
      }
      if public_path == "" {
        fail(
          "a signature is checked against a public key: --public-key is missing",
        )
      }
      let public = load_signing_public_key(public_path)
      if !verify_package_signature(args[1], signature, public) {
        println("VERIFY FAILED")
        exit_with(1)
        return
      }
      println("the signature of the package holds")
    }
    if expected != "" {
      if !verify_package_digest(args[1], expected) {
        println("VERIFY FAILED")
        exit_with(1)
        return
      }
      println("the digest of the package is the one that was expected")
    }
    let extracted = flag_value(flags, "extracted")
    let m = read_package_manifest(args[1])
    let key = package_key(flags, m)
    let ok = verify(args[1], key)
    // The package and the extracted directory are two separate checks, and
    // both of them have to hold: a package that is damaged is not made whole
    // by an extracted directory that is intact.
    let extracted_ok = if extracted == "" {
      true
    } else {
      verify_extracted_dir(args[1], extracted)
    }
    if ok && extracted_ok {
      println("VERIFY OK")
    } else {
      println("VERIFY FAILED")
      exit_with(1)
    }
  } catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
    }
  }
}

///|
/// The `sign` subcommand.
///
/// It signs a package with the secret key and writes the signature next to
/// it, so that whoever holds the public key can tell that the package is
/// the one that was published.
async fn do_sign(args : ArrayView[String]) -> Unit {
  if args.length() < 2 {
    println("error: sign requires a package path")
    usage()
    exit_with(1)
    return
  }
  let flags = parse_flags(args, 1)
  check_flags(flags) catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
      return
    }
  }
  let secret_path = flag_value(flags, "secret-key")
  if secret_path == "" {
    println("error: sign requires --secret-key <file>")
    usage()
    exit_with(1)
    return
  }
  let output = flag_value(flags, "output")
  try {
    let passphrase = read_passphrase(flags)
    let secret = load_secret_key(secret_path, passphrase)
    let signature = sign_package(args[1], secret)
    let text = signature_to_text(signature)
    if output == "" {
      println(text)
    } else {
      @fs.write_text(output, text)
      println("wrote the signature to " + output)
    }
  } catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
    }
  }
}

///|
/// The `keygen` subcommand.
///
/// It makes a pair of keys: the public key goes to the machine that seals
/// the packages, the secret key to the machine that opens them.
async fn do_keygen(args : ArrayView[String]) -> Unit {
  let flags = parse_flags(args, 1)
  check_flags(flags) catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
      return
    }
  }
  let public_path = flag_value(flags, "public-key")
  let secret_path = flag_value(flags, "secret-key")
  if public_path == "" || secret_path == "" {
    println(
      "error: keygen requires --public-key <file> and --secret-key <file>",
    )
    usage()
    exit_with(1)
    return
  }
  try {
    let secret = random_bytes(32)
    let pair = public_key_pair(secret)
    save_public_key_pair(public_path, pair.encryption, pair.signing)
    let passphrase = read_passphrase(flags)
    if passphrase == "" {
      save_secret_key_raw(secret_path, secret)
    } else {
      save_secret_key(secret_path, secret, passphrase)
    }
    println("wrote the public key to " + public_path)
    println("wrote the secret key to " + secret_path)
  } catch {
    err => {
      println("error: " + err.to_string())
      exit_with(1)
    }
  }
}

///|
/// The `info` subcommand.
async fn do_info(args : ArrayView[String]) -> Unit {
  if args.length() < 2 {
    println("error: info requires a package path")
    usage()
    exit_with(1)
    return
  }
  try {
    let flags = parse_flags(args, 1)
    check_flags(flags)
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
    err => {
      println("error: " + err.to_string())
      exit_with(1)
    }
  }
}

///|
async fn main {
  // A self-extracting bundle carries its payload inside this executable:
  // start the bundled program instead of acting as a command line tool.
  //
  // A bundle that is damaged is refused: the error is not swallowed, because
  // a bundle that cannot be unpacked is not a program without arguments.
  let launched = try_launch_self_extracting() catch {
    err => {
      eprintln("LunaPack: " + err.to_string())
      exit_with(1)
      true
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
  // `--GUI` is a front end of its own: the flags that follow belong to the
  // window, not to a pack operation here.
  if wants_gui(argv) {
    launch_studio(argv)
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
  } else if first == "sign" {
    do_sign(argv)
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
