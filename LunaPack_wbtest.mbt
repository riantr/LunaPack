// Whitebox tests: they run inside the package scope and may use internal
// helpers that are not part of the public API.

///|
test "little-endian int64 encoding round-trips" {
  assert_true(le8_to_i64(i64_to_le8(0L), 0) == 0L)
  assert_true(le8_to_i64(i64_to_le8(1L), 0) == 1L)
  assert_true(le8_to_i64(i64_to_le8(255L), 0) == 255L)
  assert_true(le8_to_i64(i64_to_le8(256L), 0) == 256L)
  assert_true(le8_to_i64(i64_to_le8(-1L), 0) == -1L)
  assert_true(le8_to_i64(i64_to_le8(1793664000000L), 0) == 1793664000000L)
}

///|
test "the manifest footer encodes the offset and length" {
  let footer = i64_to_le8(49L) + i64_to_le8(359L)
  assert_true(footer.length() == 16)
  assert_true(le8_to_i64(footer, 0) == 49L)
  assert_true(le8_to_i64(footer, 8) == 359L)
}

///|
test "json escaping" {
  assert_true(json_escape("plain") == "plain")
  assert_true(json_escape("say \"hi\"") == "say \\\"hi\\\"")
  assert_true(json_escape("a\\b") == "a\\\\b")
  assert_true(json_escape("line\nbreak") == "line\\nbreak")
}

///|
test "the magic marker is exactly eight bytes" {
  assert_true(MAGIC.length() == 8)
  assert_true(magic_bytes().length() == 8)
  assert_true(utf8_bytes_to_string(magic_bytes()) == MAGIC)
}

///|
async test "the extracted files are checked against their md5 fingerprint" {
  let src = @fs.tmpdir(prefix="lunapack_md5_src")
  @fs.write_text(src + "/a.txt", "hello\n")
  let pkg = src + "/demo.appkg"
  let opts = with_defaults(
    new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
  )
  pack(src, pkg, opts)
  let dest = @fs.tmpdir(prefix="lunapack_md5_dest")
  unpack(pkg, dest, false, None)
  // Every file is written back with the fingerprint it had in the package.
  let data = @fs.read_binary(dest + "/a.txt")
  assert_true(md5_hex(data) == md5_hex_of_string("hello\n"))
}

///|
async test "a changed file is reported as an md5 mismatch" {
  let src = @fs.tmpdir(prefix="lunapack_md5_src2")
  @fs.write_text(src + "/a.txt", "hello\n")
  let pkg = src + "/demo.appkg"
  let opts = with_defaults(
    new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
  )
  pack(src, pkg, opts)
  let dest = @fs.tmpdir(prefix="lunapack_md5_dest2")
  unpack(pkg, dest, false, None)
  // Change the file on the disk after it was extracted.
  @fs.write_text(dest + "/a.txt", "tampered\n")
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let manifest = read_archive(file).manifest
  let mismatches = verify_extracted_md5(manifest, dest)
  assert_true(mismatches == 1)
}

///|
async test "a missing file is reported as an md5 mismatch" {
  let src = @fs.tmpdir(prefix="lunapack_md5_src3")
  @fs.write_text(src + "/a.txt", "hello\n")
  let pkg = src + "/demo.appkg"
  let opts = with_defaults(
    new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
  )
  pack(src, pkg, opts)
  let dest = @fs.tmpdir(prefix="lunapack_md5_dest3")
  unpack(pkg, dest, false, None)
  @fs.remove(dest + "/a.txt")
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let manifest = read_archive(file).manifest
  let mismatches = verify_extracted_md5(manifest, dest)
  assert_true(mismatches == 1)
}

///|
async test "an extracted folder can be audited against the package" {
  let src = @fs.tmpdir(prefix="lunapack_audit_src")
  @fs.write_text(src + "/a.txt", "hello\n")
  let pkg = src + "/demo.appkg"
  let opts = with_defaults(
    new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
  )
  pack(src, pkg, opts)
  let dest = @fs.tmpdir(prefix="lunapack_audit_dest")
  unpack(pkg, dest, false, None)
  // The extracted folder matches the package.
  assert_true(verify_extracted_dir(pkg, dest))
  // A file that changed on the disk is reported.
  @fs.write_text(dest + "/a.txt", "tampered\n")
  assert_true(!verify_extracted_dir(pkg, dest))
  // A file that is gone is reported too.
  @fs.write_text(dest + "/a.txt", "hello\n")
  @fs.remove(dest + "/a.txt")
  assert_true(!verify_extracted_dir(pkg, dest))
}

///|
/// A missing interpreter has to be named in the error.
///
/// The spawn failure of the runtime names no file - "The system cannot find
/// the file specified." - so without the name of the interpreter the message
/// says nothing about what is missing. The interpreter here is one that
/// cannot exist on any host, so the path is the same everywhere.
async test "a missing interpreter is named in the error" {
  let message = try {
    let status = run_interpreter(
      "lunapack-no-such-interpreter",
      ["--version"],
      ".",
    )
    "no error was raised, the status was " + status.to_string()
  } catch {
    err => err.to_string()
  }
  assert_true(message.contains("lunapack-no-such-interpreter"))
}

///|
/// A script whose interpreter cannot be started must not stay behind.
///
/// The temporary script file is written into the destination directory, so a
/// failure that skipped the cleanup would leave it there. The interpreter is
/// one that cannot exist on any host, so the path is the same everywhere.
async test "a script that could not be started is removed again" {
  let dir = @fs.tmpdir(prefix="lunapack_cleanup")
  let script = new_script("posix", "#!/bin/sh\nexit 0\n")
  let message = try {
    let status = run_script(
      "lunapack-no-such-interpreter",
      [],
      "posix",
      "pre_install",
      script,
      dir,
    )
    "no error was raised, the status was " + status.to_string()
  } catch {
    err => err.to_string()
  }
  // The interpreter is named in the error.
  assert_true(message.contains("lunapack-no-such-interpreter"))
  // And the script file is gone. The hidden files are included, because the
  // script is written under a dot-prefixed name.
  for name in @fs.readdir(dir) {
    assert_true(!name.has_prefix(".lunapack_"))
  }
}

///|
/// A path that walks out of the destination is not a path that may be
/// written.
test "a path that walks out of the destination is refused" {
  assert_true(is_safe_path("a.txt"))
  assert_true(is_safe_path("sub/a.txt"))
  assert_true(is_safe_path("a/b/c.txt"))
  assert_true(!is_safe_path("../a.txt"))
  assert_true(!is_safe_path("sub/../../a.txt"))
  assert_true(!is_safe_path(".."))
  assert_true(!is_safe_path("/a.txt"))
  assert_true(!is_safe_path("C:/a.txt"))
  assert_true(!is_safe_path("a\\b.txt"))
  assert_true(!is_safe_path(""))
}

///|
/// A checksum that is not the same the second time is not to be trusted.
test "a checksum that is not the same twice is refused" {
  let data = string_to_utf8_bytes("hello")
  let mut calls = 0
  let refused = try {
    ignore(
      redundant_with(data, fn(d : Bytes) -> String {
        calls = calls + 1
        if calls == 1 {
          sha256_hex(d)
        } else {
          "0000000000000000"
        }
      }),
    )
    false
  } catch {
    _ => true
  }
  assert_true(refused)
}

///|
/// A checksum that is the same twice is the checksum.
test "a checksum that is the same twice is accepted" {
  let data = string_to_utf8_bytes("hello")
  let result = redundant_with(data, fn(d : Bytes) -> String { sha256_hex(d) })
  assert_true(result == sha256_hex(data))
}

///|
/// The cache of a bundle is used again only when it holds what the package
/// carries.
async test "the cache is only used again when it holds what the package carries" {
  let src = @fs.tmpdir(prefix="lunapack_cache_src")
  @fs.write_text(src + "/a.txt", "hello\n")
  let pkg = src + "/demo.appkg"
  let opts = with_defaults(
    new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
  )
  pack(src, pkg, opts)
  let manifest = read_package_manifest(pkg)
  let dir = @fs.tmpdir(prefix="lunapack_cache_dir")
  extract_to(pkg, dir, None)
  assert_true(cache_matches(manifest, dir))
  // The file in the cache is changed after it was unpacked.
  @fs.write_text(dir + "/a.txt", "tampered\n")
  assert_true(!cache_matches(manifest, dir))
}

///|
/// The progress bar tells the truth about what is left.
test "the progress bar tells the truth about what is left" {
  // Nothing done, half done, everything done.
  assert_eq(percent_done(0L, 200L), 0)
  assert_eq(percent_done(100L, 200L), 50)
  assert_eq(percent_done(200L, 200L), 100)
  // More than everything is still 100, and nothing to do is done.
  assert_eq(percent_done(300L, 200L), 100)
  assert_eq(percent_done(0L, 0L), 100)
  // A bar of ten cells is ten cells, whatever it says.
  assert_eq(progress_bar(0, 10).length(), 10)
  assert_eq(progress_bar(100, 10).length(), 10)
  assert_eq(progress_bar(50, 10), "#####-----")
  // The line is what the numbers say it is.
  assert_eq(
    progress_line(3, 12, 3145728L, 12582912L, "a.txt", 20),
    "[#####---------------] 25%  3/12 files  3.0/12.0 MB  a.txt",
  )
  // A name a console cannot show is left out rather than guessed at.
  assert_eq(
    progress_line(1, 1, 1L, 1L, "文件.txt", 10),
    "[##########] 100%  1/1 files  0.0/0.0 MB",
  )
  assert_true(is_ascii("a.txt"))
  assert_true(!is_ascii("文件.txt"))
  // Every line is the same width, which is what lets it be rewritten in place.
  assert_eq(fit_line("x", 8), "x       ")
  assert_eq(fit_line("0123456789", 4), "0123")
  // Nothing to count is not a bar of one file.
  assert_eq(total_bytes_of([]), 0L)
}

///|
/// Only a console that Windows made for this process may be taken away.
///
/// A bundle keeps the console subsystem, because a program with no standard
/// streams at all does not survive the start of the runtime. The console that
/// comes with it is taken away before a windowed program starts — but only
/// when it is the console of the bundle and not the terminal the bundle was
/// started from.
test "the console of the terminal is not taken away" {
  // A console of its own: one process on it, and it is this one.
  assert_true(console_is_ours([4242], 4242))
  // A terminal: the shell is on that console as well.
  assert_true(!console_is_ours([4242, 17], 4242))
  // No console at all.
  assert_true(!console_is_ours([], 4242))
  // One process, but not this one.
  assert_true(!console_is_ours([17], 4242))
}

///|
/// A folder that does not hold what the package carries is not handed out as
/// the cache of that package.
async test "a cache that does not hold the payload is not handed out" {
  let src = @fs.tmpdir(prefix="lunapack_accept_src")
  @fs.write_text(src + "/a.txt", "hello\n")
  @fs.write_text(src + "/b.txt", "world\n")
  let pkg = src + "/demo.appkg"
  let opts = with_defaults(
    new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
  )
  pack(src, pkg, opts)
  let manifest = read_package_manifest(pkg)
  let dir = @fs.tmpdir(prefix="lunapack_accept_dir")
  extract_to(pkg, dir, None)
  // A folder that holds what the package carries is handed out.
  assert_true(accept_cache_reporting(manifest, dir, None) is Some(_))
  // One of the files is gone from the folder, which is what a move that did
  // not finish leaves behind.
  @fs.remove(dir + "/b.txt", allow_missing=true)
  assert_true(accept_cache_reporting(manifest, dir, None) is None)
  // The folder is taken away rather than left for the next run to trust.
  assert_true(!@fs.exists(dir))
}

///|
/// The program of a bundle is not started when it was changed after it was
/// unpacked.
async test "the program of a bundle is checked before it is started" {
  let src = @fs.tmpdir(prefix="lunapack_program_src")
  @fs.write_text(src + "/a.txt", "hello\n")
  let pkg = src + "/demo.appkg"
  let opts = with_main_program(
    with_defaults(
      new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
      "demo",
      "1.0.0",
      "windows",
      "x86_64",
    ),
    "a.txt",
  )
  pack(src, pkg, opts)
  let manifest = read_package_manifest(pkg)
  let dir = @fs.tmpdir(prefix="lunapack_program_dir")
  extract_to(pkg, dir, None)
  assert_true(program_matches(manifest, dir + "/a.txt"))
  // The program is changed after it was unpacked.
  @fs.write_text(dir + "/a.txt", "tampered\n")
  assert_true(!program_matches(manifest, dir + "/a.txt"))
}

///|
/// A flag the tool does not know is reported, not ignored.
///
/// A flag that is ignored is the worst kind of mistake: the command does
/// something else than what was asked, and says nothing about it. The empty
/// output path that `--input-file` used to leave behind is what made the
/// mistake visible at all.
test "a flag the tool does not know is reported" {
  let flags = parse_flags(["--input-exe=app.exe", "--bogus", "value"], 0)
  assert_eq(unknown_flags(flags).length(), 1)
  assert_true(unknown_flags(flags)[0] == "bogus")
  // A flag the tool knows is not reported.
  let known = parse_flags(["--input-exe=app.exe", "--Files=dir"], 0)
  assert_eq(unknown_flags(known).length(), 0)
  // The same unknown flag twice is reported once.
  let twice = parse_flags(["--bogus=1", "--bogus=2"], 0)
  assert_eq(unknown_flags(twice).length(), 1)
}

///|
/// The message that reports an unknown flag names the flag and the rest.
test "the message of an unknown flag names the flag" {
  let flags = parse_flags(["--nope"], 0)
  let message = unknown_flags_message(flags)
  assert_true(message.contains("--nope"))
  assert_true(message.contains("--input-exe"))
}

///|
/// Every flag the tool reads is a flag the tool knows.
///
/// A flag that is read but not listed would be reported as unknown, and a
/// flag that is listed but not read would be ignored - both are mistakes.
test "every flag the tool reads is a flag the tool knows" {
  let known = known_flags()
  for
    name in [
      "Files", "arch", "compression", "compression-method", "encryption", "encryption-method",
      "expected-sha256", "extracted", "i", "input", "input-exe", "input-file", "launcher",
      "name", "o", "output", "output-exe", "output-file", "passphrase", "passphrase-file",
      "post-install", "pre-install", "public-key", "secret-key", "signature", "skip-scripts",
      "version",
    ] {
    assert_true(known.contains(name))
  }
}

///|
/// The name of an install script is a name and not a path.
///
/// The command line of the Windows shell reads a forward slash as the start
/// of a switch, so a path made of forward slashes does not run the script
/// but complains that `.` is not a command.
test "the name of an install script is a name" {
  assert_eq(
    script_file_name("windows", "pre_install"),
    ".lunapack_pre_install.cmd",
  )
  assert_eq(
    script_file_name("posix", "post_install"),
    ".lunapack_post_install.sh",
  )
  assert_true(!script_file_name("windows", "pre_install").contains("/"))
}

///|
/// Format 6 brought the integrity block. A package that says it is format 6
/// but carries no block is not an old package: it is one whose marker was
/// broken so the reader would skip the check. It has to be refused.
test "a v6 package with no integrity block is refused" {
  let message = try {
    let m = json_to_manifest(
      "{\"format_version\":6,\"name\":\"t\",\"version\":\"1\",\"os\":\"windows\"," +
      "\"arch\":\"x86_64\",\"checksum_algo\":\"sha256\",\"compression\":\"none\"," +
      "\"created_at\":\"\",\"main_program\":\"\",\"pre_install\":null," +
      "\"post_install\":null,\"entries\":[]}",
    )
    let archive = Archive::{
      base: 0L,
      manifest: m,
      manifest_bytes: Bytes::from_array([]),
      manifest_offset: 0L,
      manifest_length: 0L,
      integrity: Legacy,
    }
    verify_integrity(archive, None)
    "no error was raised"
  } catch {
    err => err.to_string()
  }
  assert_true(message.contains("integrity block"))
}

///|
/// A package that really is of the old format is still read, with a warning.
test "an old package with no integrity block is still read" {
  let message = try {
    let m = json_to_manifest(
      "{\"format_version\":5,\"name\":\"t\",\"version\":\"1\",\"os\":\"windows\"," +
      "\"arch\":\"x86_64\",\"checksum_algo\":\"sha256\",\"compression\":\"none\"," +
      "\"created_at\":\"\",\"main_program\":\"\",\"pre_install\":null," +
      "\"post_install\":null,\"entries\":[]}",
    )
    let archive = Archive::{
      base: 0L,
      manifest: m,
      manifest_bytes: Bytes::from_array([]),
      manifest_offset: 0L,
      manifest_length: 0L,
      integrity: Legacy,
    }
    verify_integrity(archive, None)
    ""
  } catch {
    err => err.to_string()
  }
  assert_eq(message, "")
}
