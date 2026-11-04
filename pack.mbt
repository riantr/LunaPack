// Pack logic: turn files into a .appkg archive, and bundle an executable
// together with extra files into a single distributable file.

///|
/// Collect every regular file under `root`, recursively.
pub async fn collect_files(root : String) -> Array[String] {
  let result = []
  let stack = [norm_sep(root)]
  while true {
    match stack.pop() {
      Some(dir) => {
        let names = @fs.readdir(dir)
        for name in names {
          let full = dir + "/" + name
          match @fs.kind(full) {
            @fs.FileKind::Regular => result.push(full)
            @fs.FileKind::Directory => stack.push(full)
            _ => ()
          }
        }
      }
      None => break
    }
  }
  result
}

///|
/// Lowercase hex MD5 of the content of the file at `path`.
///
/// The file is read as a whole, so it needs to fit in memory; that is the
/// same limitation the packing code has.
pub async fn file_md5_hex(path : String) -> String {
  md5_hex(@fs.read_binary(path))
}

///|
/// Print the MD5 fingerprint of the file at `path`.
///
/// The fingerprint of the produced file is what a user compares against the
/// value the platform tooling shows, so it is printed under a clear label.
pub async fn report_output_md5(path : String) -> Unit {
  if @fs.exists(path) {
    println("output md5  " + file_md5_hex(path) + "  " + basename(path))
  }
}

///|
/// Print a fingerprint that was computed while the file was written.
///
/// The file does not have to be read back for that, which matters when it is
/// a large application.
pub fn report_md5(path : String, digest : String) -> Unit {
  println("output md5  " + digest + "  " + basename(path))
}

///|
/// Write an archive containing `items`.
///
/// Every item is a pair of (source file path, path inside the archive).
/// Returns the manifest that was written.
///
/// The MD5 fingerprint of every source file is computed before it is written
/// and printed as a scan list, so the fingerprints that go into the package
/// can be compared with what the platform tooling reports.
///
/// When `digest` is given, the bytes that go into the archive are hashed as
/// they are written, so the fingerprint of the archive is known without
/// reading the file back.
async fn write_archive(
  items : Array[(String, String)],
  output : String,
  opts : PackOptions,
  digest : Md5?,
) -> Manifest {
  if @fs.exists(output) {
    @fs.remove(output)
  }
  ensure_parent_dir(output)
  let pkg = @fs.create(output, allow_existing=true, permission=0o644)
  defer pkg.close()
  let magic = magic_bytes()
  pkg.write(magic)
  match digest {
    Some(d) => d.update(magic)
    None => ()
  }
  let mut cursor : Int64 = 8
  let entries = []
  let mut scanned = 0
  for it in items {
    let (src, target) = it
    let raw = @fs.read_binary(src)
    let sum = sha256_hex(raw)
    let fingerprint = md5_hex(raw)
    // The scan list shows the fingerprint of every file before it goes into
    // the package.
    println("  md5  " + fingerprint + "  " + target)
    scanned = scanned + 1
    // Preserve the executable bit in a portable way: `can_execute` maps to
    // the POSIX x-bit and to executable extensions on Windows.
    let exec = @fs.can_execute(src)
    let mode : Int32 = if exec { 0o755 } else { 0o644 }
    let (stored, codec) = compress_with(raw, opts.compression)
    pkg.write(stored)
    match digest {
      Some(d) => d.update(stored)
      None => ()
    }
    entries.push({
      path: target,
      mode,
      size: raw.length().to_int64(),
      stored_size: stored.length().to_int64(),
      codec,
      checksum: sum,
      md5: fingerprint,
      offset: cursor,
    })
    cursor = cursor + stored.length().to_int64()
  }
  println("scanned " + scanned.to_string() + " files")
  let manifest = {
    format_version: FORMAT_VERSION,
    name: opts.name,
    version: opts.version,
    os: opts.os,
    arch: opts.arch,
    checksum_algo: CHECKSUM_ALGO,
    compression: opts.compression,
    created_at: iso8601_utc(@env.now()),
    main_program: opts.main_program,
    pre_install: opts.pre_install,
    post_install: opts.post_install,
    entries,
  }
  let mjson = manifest_to_json(manifest)
  let mbytes = string_to_utf8_bytes(mjson)
  let moff = cursor
  pkg.write(mbytes)
  let mlen : Int64 = Int64::from_int(mbytes.length())
  let footer = magic_bytes()
  pkg.write(footer)
  pkg.write(i64_to_le8(moff))
  pkg.write(i64_to_le8(mlen))
  match digest {
    Some(d) => {
      d.update(mbytes)
      d.update(footer)
      d.update(i64_to_le8(moff))
      d.update(i64_to_le8(mlen))
    }
    None => ()
  }
  manifest
}

///|
/// Bundle every file under `input` into a `.appkg` file at `output`.
pub async fn pack(input : String, output : String, opts : PackOptions) -> Unit {
  let base = norm_sep(@fs.realpath(input))
  let files = collect_files(base)
  let items = []
  for f in files {
    items.push((f, relpath(base, f)))
  }
  let digest = Md5::Md5()
  let m = write_archive(items, output, opts, Some(digest))
  println("packed " + m.entries.length().to_string() + " files -> " + output)
  report_md5(output, digest.finish())
}

///|
/// Append the content of `src_path` to `dst` starting at `position`.
///
/// Copying in chunks keeps the memory usage bounded, which matters for large
/// application folders.
async fn append_file(
  dst : @fs.File,
  src_path : String,
  position : Int64,
  digest : Md5?,
) -> Unit {
  let src = @fs.open(src_path, mode=@fs.Mode::ReadOnly)
  defer src.close()
  let total = src.size()
  let chunk : Int64 = 1 << 20
  let mut off : Int64 = 0
  while off < total {
    let rest = total - off
    let n = if rest < chunk { rest } else { chunk }
    let buf = src.read_exactly_at(n.to_int(), position=off)
    dst.write_at(buf, position=position + off)
    match digest {
      Some(d) => d.update(buf)
      None => ()
    }
    off = off + n
  }
}

///|
/// Bundle `input_exe` together with the contents of every directory in
/// `file_dirs` into the single file `output_exe`.
///
/// The result is the original executable with a LunaPack archive appended, so
/// it stays a runnable executable while carrying the extra files. Use
/// `unpack` on the result to extract the payload again.
///
/// The contents of a single `--Files` directory land at the root of the
/// archive, next to the main program, so an extracted application is directly
/// runnable. With several directories each one gets a subdirectory named after
/// it, to keep the paths unique.
pub async fn bundle(
  input_exe : String,
  output_exe : String,
  file_dirs : Array[String],
  opts : PackOptions,
) -> Unit {
  let exe_real = norm_sep(@fs.realpath(input_exe))
  let items = []
  let main_name = basename(input_exe)
  items.push((input_exe, main_name))
  let single = file_dirs.length() == 1
  for d in file_dirs {
    let base = norm_sep(@fs.realpath(d))
    let files = collect_files(base)
    let prefix = if single { "" } else { basename(base) }
    for f in files {
      // The main program is stored already; do not keep a second copy.
      if norm_sep(@fs.realpath(f)) == exe_real {
        continue
      }
      let rel = relpath(base, f)
      items.push((f, if prefix == "" { rel } else { prefix + "/" + rel }))
    }
  }
  let opts2 = with_main_program(opts, main_name)
  let mut icon_copied = false
  // Build the archive next to the target, then append it to the stub.
  ensure_parent_dir(output_exe)
  let tmp = output_exe + ".lunapack-archive.tmp"
  let m = write_archive(items, tmp, opts2, None)
  // The stub that makes the result runnable is the LunaPack executable
  // itself: starting it notices the appended archive, extracts the payload
  // and starts the bundled program. That is the same trick a WinRAR or 7-Zip
  // self-extracting archive uses.
  let stub = match current_exe_path() {
    Some(p) => if is_native_target() && @fs.exists(p) { Some(p) } else { None }
    None => None
  }
  if @fs.exists(output_exe) {
    @fs.remove(output_exe)
  }
  // The fingerprint of the produced file is computed while it is written, so
  // the file never has to be read back.
  let digest = Md5::Md5()
  match stub {
    Some(s) => {
      // Write the launcher stub first and close it again: the icon is
      // written with the Windows resource API, which rewrites the file and
      // therefore needs it to be closed.
      {
        let out = @fs.create(output_exe, allow_existing=true, permission=0o644)
        defer out.close()
        append_file(out, s, 0, None)
      }
      // Give the bundle the icon of the application it carries. This has to
      // happen before the payload is appended, because writing resources
      // rewrites the file.
      if copy_icon(input_exe, output_exe) {
        icon_copied = true
      }
      // The stub is hashed now, because the icon has changed its bytes.
      let stub_size = @fs.file_size(output_exe)
      digest.update(@fs.read_binary(output_exe))
      // Finally append the archive. The stub may have grown by the icon.
      let out = @fs.open(output_exe, mode=@fs.Mode::ReadWrite)
      defer out.close()
      append_file(out, tmp, stub_size, Some(digest))
    }
    None => {
      // Without a native launcher (for example when running under Wasm) the
      // application executable itself carries the archive. The result still
      // holds the payload, but it cannot extract itself.
      println(
        "warning: no native launcher available, the bundle will not extract itself",
      )
      let out = @fs.create(output_exe, allow_existing=true, permission=0o644)
      defer out.close()
      append_file(out, input_exe, 0, Some(digest))
      let exe_size = @fs.file_size(input_exe)
      append_file(out, tmp, exe_size, Some(digest))
    }
  }
  @fs.remove(tmp)
  println(
    "bundled " +
    m.entries.length().to_string() +
    " files -> " +
    output_exe +
    (if icon_copied { " (icon copied)" } else { "" }),
  )
  report_md5(output_exe, digest.finish())
}
