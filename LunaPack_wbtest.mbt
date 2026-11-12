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
  assert_true(cache_matches_reporting(manifest, dir, None))
  // The file in the cache is changed after it was unpacked.
  @fs.write_text(dir + "/a.txt", "tampered\n")
  assert_true(!cache_matches_reporting(manifest, dir, None))
}

///|
/// The files of a cache that is used again are checked one by one, and the
/// caller is told.
///
/// The check of a cache that is used again reads the whole payload back from
/// the disk, and that is half of what a warm start spends its time on. A
/// start that says nothing while it does so looks like a start that hangs.
async test "the files of a cache that is used again are counted one by one" {
  let src = @fs.tmpdir(prefix="lunapack_warm_src")
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
  // The bundle is in a folder of its own, so the cache is the one next to it.
  let home = @fs.tmpdir(prefix="lunapack_warm_home")
  let exe = home + "/demo.exe"
  // The first start unpacks the payload and leaves the cache behind.
  assert_true(extract_to_cache(pkg, exe, manifest, None, None, None) is Some(_))
  // The second start finds that cache, and the check of it is reported.
  let told : Array[Int32] = []
  let tell = fn(
    _index : Int32,
    _done : Int64,
    _total : Int64,
    _path : String,
  ) -> Unit {
    told.push(1)
  }
  assert_true(
    extract_to_cache(pkg, exe, manifest, None, None, Some(tell)) is Some(_),
  )
  assert_eq(told.length(), manifest.entries.length())
}

///|
/// The cache of a bundle that cannot be written next to it is found again on
/// the next start.
///
/// The folder next to the executable is the best place for the payload, but
/// there are places where it cannot be written to. The payload goes to the
/// cache of the user then, and that folder has to be the same on every start:
/// a folder of its own on every start is a payload that is unpacked again on
/// every start, and the unpacking is the whole cost of a start.
async test "the cache of a bundle that cannot be written next to it is found again" {
  let src = @fs.tmpdir(prefix="lunapack_fallback_src")
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
  // The folder of the bundle cannot be a folder: a file is in the way of it.
  let blocked = src + "/blocked"
  @fs.write_text(blocked, "a file where a folder should be\n")
  let exe = blocked + "/demo.exe"
  // The cache of the user is named by the environment.
  let home = norm_sep(@fs.tmpdir(prefix="lunapack_fallback_home"))
  @env.set_env_var("LUNAPACK_CACHE_HOME", home)
  let first = cache_dir(exe, package_tag(manifest))
  let second = cache_dir(exe, package_tag(manifest))
  @env.set_env_var("LUNAPACK_CACHE_HOME", "")
  // The same folder on both starts, and it is the one that was named.
  assert_eq(first, second)
  assert_true(first.length() > home.length())
  assert_eq(first[0:home.length()], home)
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
/// Only a key press answers a question; anything else on the console is noise.
///
/// A console signals its input handle for a window that gained focus, for a
/// window that was resized and for the mouse, and it reports the key that was
/// let go just as it reports the one that was pressed. Treating any of those
/// as an answer is what makes the launcher read for a line that nobody is
/// typing, and the countdown never moves.
test "only a key press answers a question" {
  let s = INPUT_RECORD_SIZE
  let raw = FixedArray::make(s * 4, b'\x00')
  // 0: a focus change — not a key event at all.
  raw[0] = b'\x10'
  // 1: a key event that reports the key going up, with a character on it.
  raw[s] = b'\x01'
  raw[s + 14] = b'\x32'
  // 2: a key that went down but carries no character, such as an arrow key.
  raw[s * 2] = b'\x01'
  raw[s * 2 + 4] = b'\x01'
  // 3: the "2" pressed.
  raw[s * 3] = b'\x01'
  raw[s * 3 + 4] = b'\x01'
  raw[s * 3 + 14] = b'\x32'
  let records = Bytes::from_array(raw[:])
  // Nothing on the buffer is not an answer either.
  assert_true(!has_key_press(records, 0))
  // Each of the four conditions has to hold for the answer to be a key.
  assert_true(!has_key_press(records, 1))
  assert_true(!has_key_press(records, 2))
  assert_true(!has_key_press(records, 3))
  assert_true(has_key_press(records, 4))
  // A count that claims more records than the buffer holds is not read past
  // the end of it: the one record here is a focus change, so the walk runs
  // out of buffer before it runs out of records, and the answer is "no".
  let one = FixedArray::make(s, b'\x00')
  one[0] = b'\x10'
  let short = Bytes::from_array(one[:])
  assert_true(!has_key_press(short, 1))
  assert_true(!has_key_press(short, 2))
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
/// The folder flag is read under both of its spellings, in the order given.
///
/// `--Files` is how the flag is written in the documentation and in every
/// example, and a command line that says `--files` means the same folders.
/// Refusing it over the height of one letter is pedantry rather than care: the
/// two spellings are one flag, and neither is reported as unknown. The order
/// is checked because the two can be mixed in one command line, and collecting
/// them into two lists that are then joined would lose it.
test "the folder flag is read under both spellings" {
  let flags = parse_flags(["--files=a", "--Files=b", "--files=c"], 0)
  assert_eq(unknown_flags(flags).length(), 0)
  let dirs = file_dirs_of(flags)
  assert_eq(dirs.length(), 3)
  assert_true(dirs[0] == "a")
  assert_true(dirs[1] == "b")
  assert_true(dirs[2] == "c")
  // The space-separated form of both spellings works as well.
  let spaced = parse_flags(["--files", "x", "--Files", "y"], 0)
  let sdirs = file_dirs_of(spaced)
  assert_eq(sdirs.length(), 2)
  assert_true(sdirs[0] == "x")
  assert_true(sdirs[1] == "y")
  // A flag that only looks like it is still a mistake, and is not a folder.
  let other = parse_flags(["--file=z"], 0)
  assert_eq(unknown_flags(other).length(), 1)
  assert_eq(file_dirs_of(other).length(), 0)
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
      "expected-sha256", "extracted", "files", "i", "input", "input-exe", "input-file",
      "launcher", "name", "o", "os", "output", "output-exe", "output-file", "passphrase",
      "passphrase-file", "post-install", "pre-install", "public-key", "secret-key",
      "signature", "skip-scripts", "version",
    ] {
    assert_true(known.contains(name))
  }
}

///|
/// The platform flag is a flag the tool knows.
///
/// `build_options` read `--os` and the README documented it, but the name was
/// missing from the list of known flags, so every command line that named it
/// was refused with `unknown flag --os` and a package for another platform
/// could not be made at all. A flag that is read and not listed is refused; a
/// flag that is listed and not read is ignored; both are mistakes, and this is
/// the one that survived because the list in the test above was written by
/// hand.
test "the platform flag is a flag the tool knows" {
  let flags = parse_flags(["--os=linux", "--arch=x86_64"], 0)
  assert_eq(unknown_flags(flags).length(), 0)
  assert_true(flag_value(flags, "os") == "linux")
  assert_true(flag_value(flags, "arch") == "x86_64")
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
/// The directory of a path is what is in front of the last separator.
///
/// The statement that returns it is a slice of the path, and an analyzer
/// that does not model a slice calls that line unreachable. This test is what
/// says otherwise: it runs the line, on the two shapes that reach it.
test "the directory of a path is in front of the last separator" {
  assert_eq(dirname("/a/b/c.txt"), "/a/b")
  assert_eq(dirname("/a"), "/")
  assert_eq(dirname("c.txt"), "")
}

///|
/// A passphrase that is read from a file has no line ending in it.
///
/// The line that trims the ending is a slice of the text, and the same
/// analyzer calls it unreachable. Reading a passphrase from a file is what
/// runs it.
async test "a passphrase that is read from a file has no line ending" {
  let dir = @fs.tmpdir(prefix="lunapack_passphrase")
  let path = dir + "/pass.txt"
  @fs.write_text(path, "a secret\n")
  let flags = parse_flags(["--passphrase-file=" + path], 0)
  assert_eq(read_passphrase(flags), "a secret")
}

///|
/// The signing key is the one the public key file holds.
///
/// The line that takes the key out of its line is a slice, and the same
/// analyzer calls it unreachable. A key file is what runs it.
test "the signing key is the one the public key file holds" {
  let signing = Bytes::make(4, b'\x01')
  let encryption = Bytes::make(4, b'\x02')
  let text = PUBLIC_KEY_HEADER +
    "\n" +
    PUBLIC_KEY_ENCRYPTION +
    " " +
    bytes_to_hex(encryption) +
    "\n" +
    PUBLIC_KEY_SIGNING +
    " " +
    bytes_to_hex(signing) +
    "\n"
  let found = public_key_of(string_to_utf8_bytes(text), PUBLIC_KEY_SIGNING)
  assert_true(found is Some(_))
  match found {
    Some(key) => assert_true(key == signing)
    None => assert_true(false)
  }
  // A key of another algorithm is not handed out under this one.
  assert_true(
    public_key_of(string_to_utf8_bytes(text), PUBLIC_KEY_ENCRYPTION) is Some(_),
  )
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

///|
/// The launcher asset name matches the running system.
///
/// The release ships one build per platform, so the name has to resolve to one
/// of them: `lunapack-<os>-<arch>` with a `.exe` suffix on Windows. A name
/// that guessed an unshipped architecture would only 404.
test "the launcher asset name matches the running system" {
  let name = launcher_asset_name()
  assert_true(name.has_prefix("lunapack-"))
  // The host platform is part of the name, so a download lands on the build
  // that runs here.
  assert_true(name.contains(host_platform()))
  // Windows ships the executable with its extension; the others do not.
  if host_platform() == "windows" {
    assert_true(name.has_suffix(".exe"))
  } else {
    assert_true(!name.has_suffix(".exe"))
  }
  // macOS ships aarch64, the rest ship x86_64.
  if host_platform() == "macos" {
    assert_true(name.has_suffix("-aarch64"))
  } else {
    assert_true(
      name.has_suffix(
        "-x86_64" + (if host_platform() == "windows" { ".exe" } else { "" }),
      ),
    )
  }
}

///|
/// The `--launcher` value that asks for a download is recognised.
///
/// A bare `--launcher` parses to "true"; `auto`, `download`, `yes` and `1`
/// are accepted as well, while a path or an empty value is not.
test "the launcher auto markers are recognised" {
  assert_true(is_launcher_auto("true"))
  assert_true(is_launcher_auto("auto"))
  assert_true(is_launcher_auto("download"))
  assert_true(is_launcher_auto("yes"))
  assert_true(is_launcher_auto("1"))
  // A path and an empty value are not auto markers.
  assert_true(!is_launcher_auto(""))
  assert_true(!is_launcher_auto("/usr/bin/lunapack"))
  assert_true(!is_launcher_auto("lunapack-linux-x86_64"))
  assert_true(!is_launcher_auto("this"))
}

///|
/// `resolve_launcher` keeps an explicit launcher and the default.
///
/// An empty value keeps the running-program default, and a path is returned
/// unchanged: the existence check belongs to `bundle`. The auto markers are
/// the only ones that trigger a download, so the no-network cases here do not
/// touch the network.
async test "resolve_launcher keeps the default and an explicit file" {
  // No `--launcher` at all: the default (empty) is returned.
  let none = resolve_launcher(parse_flags(["--input-exe=app.exe"], 0))
  assert_eq(none, "")
  // An explicit file path is passed through untouched.
  let path = resolve_launcher(parse_flags(["--launcher=/tmp/lp"], 0))
  assert_eq(path, "/tmp/lp")
}

// ------------------------------------------------- dependency discovery ---

///|
/// Write a value into a file, two bytes, least significant first.
fn pe_put16(arr : Array[Byte], off : Int32, v : Int32) -> Unit {
  arr[off] = (v & 0xff).to_byte()
  arr[off + 1] = ((v >> 8) & 0xff).to_byte()
}

///|
/// Write a value into a file, four bytes, least significant first.
fn pe_put32(arr : Array[Byte], off : Int32, v : Int32) -> Unit {
  arr[off] = (v & 0xff).to_byte()
  arr[off + 1] = ((v >> 8) & 0xff).to_byte()
  arr[off + 2] = ((v >> 16) & 0xff).to_byte()
  arr[off + 3] = ((v >> 24) & 0xff).to_byte()
}

///|
/// A PE image that imports `names` and loads `delayed` later.
///
/// The image has the shape the format asks for: a DOS header with the
/// offset of the PE header in it, the PE signature, a COFF header, an
/// optional header with sixteen data directories, one section, the import
/// directory in that section and the delay-load directory next to it. A
/// reader that reads it the way it reads a program a compiler wrote is
/// therefore reading something of the same kind.
fn build_pe(names : Array[String], delayed : Array[String]) -> Bytes {
  let pe_off = 0x40
  let opt = pe_off + 24
  let sec_table = opt + 240
  let data_off = 0x200
  let rva_base = 0x1000
  // The import directory: one descriptor per library, and a descriptor that
  // is all zeroes at the end.
  let dir_size = (names.length() + 1) * 20
  // The delay-load directory has descriptors of its own.
  let delay_size = (delayed.length() + 1) * 32
  // The names come after both directories.
  let mut name_len = 0
  for n in names {
    name_len = name_len + string_to_utf8_bytes(n).length() + 1
  }
  for n in delayed {
    name_len = name_len + string_to_utf8_bytes(n).length() + 1
  }
  let body_size = dir_size + delay_size + name_len
  let arr = Array::make(data_off + body_size, b'\x00')
  // The DOS header.
  arr[0] = b'M'
  arr[1] = b'Z'
  pe_put32(arr, 0x3c, pe_off)
  // The PE signature.
  arr[pe_off] = b'P'
  arr[pe_off + 1] = b'E'
  // The COFF header.
  pe_put16(arr, pe_off + 4, 0x8664)
  pe_put16(arr, pe_off + 6, 1)
  pe_put32(arr, pe_off + 8, 0)
  pe_put32(arr, pe_off + 12, 0)
  pe_put32(arr, pe_off + 16, 0)
  pe_put16(arr, pe_off + 20, 240)
  pe_put16(arr, pe_off + 22, 0x22)
  // The optional header: the magic, the number of data directories, the
  // import directory and the delay-load directory.
  pe_put16(arr, opt, 0x20b)
  pe_put32(arr, opt + 108, 16)
  pe_put32(arr, opt + 112 + 8, rva_base)
  pe_put32(arr, opt + 112 + 12, dir_size)
  pe_put32(arr, opt + 112 + 13 * 8, rva_base + dir_size)
  pe_put32(arr, opt + 112 + 13 * 8 + 4, delay_size)
  // The section table.
  arr[sec_table] = b'.'
  arr[sec_table + 1] = b't'
  arr[sec_table + 2] = b'e'
  arr[sec_table + 3] = b'x'
  pe_put32(arr, sec_table + 8, body_size)
  pe_put32(arr, sec_table + 12, rva_base)
  pe_put32(arr, sec_table + 16, body_size)
  pe_put32(arr, sec_table + 20, data_off)
  pe_put32(arr, sec_table + 36, 0x60000020)
  // The names of the libraries, and where each of them is written down.
  let mut at = data_off + dir_size + delay_size
  let mut i = 0
  while i < names.length() {
    // The name of the library is the fourth field of the descriptor.
    pe_put32(arr, data_off + i * 20 + 12, rva_base + (at - data_off))
    for b in string_to_utf8_bytes(names[i]) {
      arr[at] = b
      at = at + 1
    }
    arr[at] = b'\x00'
    at = at + 1
    i = i + 1
  }
  i = 0
  while i < delayed.length() {
    // The name of the library is the second field of the descriptor.
    pe_put32(arr, data_off + dir_size + i * 32 + 4, rva_base + (at - data_off))
    for b in string_to_utf8_bytes(delayed[i]) {
      arr[at] = b
      at = at + 1
    }
    arr[at] = b'\x00'
    at = at + 1
    i = i + 1
  }
  Bytes::from_array(arr)
}

///|
/// The names of the libraries a program imports are read from its image.
test "the import table of a PE image names the libraries it imports" {
  let names = pe_import_dlls(build_pe(["alpha.dll", "beta.dll"], []))
  assert_eq(names.length(), 2)
  assert_eq(names[0], "alpha.dll")
  assert_eq(names[1], "beta.dll")
}

///|
/// A program that imports nothing has no libraries to carry.
test "an image that imports nothing names no library" {
  assert_eq(pe_import_dlls(build_pe([], [])).length(), 0)
}

///|
/// A library that is loaded later is a library the program needs as well.
test "the libraries that are loaded later are named as well" {
  let names = pe_delay_import_dlls(build_pe(["alpha.dll"], ["beta.dll"]))
  assert_eq(names.length(), 1)
  assert_eq(names[0], "beta.dll")
}

///|
/// A file that is not a Windows program has no libraries to carry.
test "a file that is not a PE image names no library" {
  assert_eq(pe_import_dlls(b"not a program at all").length(), 0)
}

///|
/// The name of an API set is the name of a library that does not exist.
test "the name of an API set is not a library of the program" {
  assert_true(is_api_set_dll("api-ms-win-crt-runtime-l1-1-0.dll"))
  assert_true(is_api_set_dll("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL"))
  assert_true(is_api_set_dll("ext-ms-win-ntuser-dialogbox-l1-1-0.dll"))
  assert_true(!is_api_set_dll("mylib.dll"))
}

///|
/// A library of the system is loaded from the system, whatever the program
/// carries next to itself.
test "the name of a library of the system is not a library of the program" {
  assert_true(is_known_dll("kernel32.dll"))
  assert_true(is_known_dll("KERNEL32.DLL"))
  assert_true(is_known_dll("user32.dll"))
  assert_true(!is_known_dll("mylib.dll"))
}

///|
/// The libraries next to a program are the ones it needs from there.
async test "the libraries next to a program are found" {
  let dir = @fs.tmpdir(prefix="lunapack_deps")
  @fs.write_binary(dir + "/app.exe", build_pe(["alpha.dll", "beta.dll"], []))
  @fs.write_text(dir + "/alpha.dll", "not a real library")
  @fs.write_text(dir + "/beta.dll", "not a real library")
  let found = discover_dependencies(dir + "/app.exe")
  assert_eq(found.length(), 2)
  assert_eq(basename(found[0]), "alpha.dll")
  assert_eq(basename(found[1]), "beta.dll")
}

///|
/// A library that is not next to the program is not something a bundle can
/// carry: it is either part of the system or one the program finds elsewhere.
async test "a library that is not next to the program is not carried" {
  let dir = @fs.tmpdir(prefix="lunapack_deps")
  @fs.write_binary(dir + "/app.exe", build_pe(["gamma.dll"], []))
  let found = discover_dependencies(dir + "/app.exe")
  assert_eq(found.length(), 0)
}

///|
/// A library needs libraries of its own, and they are found in the same
/// folder.
async test "the libraries of a library are found as well" {
  let dir = @fs.tmpdir(prefix="lunapack_deps")
  @fs.write_binary(dir + "/app.exe", build_pe(["alpha.dll"], []))
  @fs.write_binary(dir + "/alpha.dll", build_pe(["beta.dll"], []))
  @fs.write_text(dir + "/beta.dll", "not a real library")
  let found = discover_dependencies(dir + "/app.exe")
  assert_eq(found.length(), 2)
  assert_eq(basename(found[0]), "alpha.dll")
  assert_eq(basename(found[1]), "beta.dll")
}

///|
/// The libraries of the system are left out, even when a file with that
/// name sits next to the program. The API sets are left out as well, and
/// they are not libraries of the program at all.
async test "a library of the system next to the program is left out" {
  let dir = @fs.tmpdir(prefix="lunapack_deps")
  @fs.write_binary(
    dir + "/app.exe",
    build_pe(
      ["kernel32.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "alpha.dll"],
      [],
    ),
  )
  @fs.write_text(dir + "/kernel32.dll", "not a real library")
  @fs.write_text(
    dir + "/api-ms-win-crt-runtime-l1-1-0.dll",
    "not a real library",
  )
  @fs.write_text(dir + "/alpha.dll", "not a real library")
  let found = discover_dependencies(dir + "/app.exe")
  assert_eq(found.length(), 1)
  assert_eq(basename(found[0]), "alpha.dll")
}

///|
/// Windows does not care about the case of a file name.
async test "a library is found whatever the case of the file is" {
  let dir = @fs.tmpdir(prefix="lunapack_deps")
  @fs.write_binary(dir + "/app.exe", build_pe(["Alpha.dll"], []))
  @fs.write_text(dir + "/alpha.dll", "not a real library")
  let found = discover_dependencies(dir + "/app.exe")
  assert_eq(found.length(), 1)
  assert_eq(basename(found[0]), "alpha.dll")
}

///|
/// The libraries the program needs are carried in the bundle, next to the
/// program itself.
async test "the libraries next to the program are carried in the bundle" {
  let dir = @fs.tmpdir(prefix="lunapack_deps")
  @fs.write_binary(dir + "/app.exe", build_pe(["alpha.dll"], []))
  @fs.write_text(dir + "/alpha.dll", "not a real library")
  // The launcher is not a program here: the bundle only needs something to
  // carry the archive.
  let launcher = dir + "/launcher.exe"
  @fs.write_text(launcher, "pretend this is a launcher")
  let out = dir + "/bundle.exe"
  let opts = with_defaults(
    new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
  )
  bundle_program(dir + "/app.exe", out, [], [("launcher", launcher)], opts)
  let m = read_package_manifest(out)
  assert_eq(m.main_program, "app.exe")
  // The program and the library it needs, and nothing else.
  assert_eq(m.entries.length(), 2)
  let mut has_lib = false
  for e in m.entries {
    if e.path == "alpha.dll" {
      has_lib = true
    }
  }
  assert_true(has_lib)
}

///|
/// A library that the caller named as well is not carried twice: the file
/// the caller named is the one that is kept.
async test "a library that the caller named is not carried twice" {
  let dir = @fs.tmpdir(prefix="lunapack_deps")
  @fs.write_binary(dir + "/app.exe", build_pe(["alpha.dll"], []))
  @fs.write_text(dir + "/alpha.dll", "not a real library")
  // The launcher is somewhere else, so the folder of the program holds the
  // program and the library and nothing else.
  let elsewhere = @fs.tmpdir(prefix="lunapack_deps")
  let launcher = elsewhere + "/launcher.exe"
  @fs.write_text(launcher, "pretend this is a launcher")
  let out = dir + "/bundle.exe"
  let opts = with_defaults(
    new_pack_options("demo", "1.0.0", "windows", "x86_64", None, None, "none"),
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
  )
  bundle_program(dir + "/app.exe", out, [dir], [("launcher", launcher)], opts)
  let m = read_package_manifest(out)
  // The program and the library, and the library is not there twice.
  assert_eq(m.entries.length(), 2)
}

///|
/// The flag `--no-auto-deps` says that only the named files are carried.
async test "the flag --no-auto-deps leaves the libraries out" {
  let dir = @fs.tmpdir(prefix="lunapack_deps")
  @fs.write_binary(dir + "/app.exe", build_pe(["alpha.dll"], []))
  @fs.write_text(dir + "/alpha.dll", "not a real library")
  let none = auto_dependency_files(dir + "/app.exe", [("no-auto-deps", "true")])
  assert_eq(none.length(), 0)
  // Without the flag the libraries are found.
  let found = auto_dependency_files(dir + "/app.exe", [])
  assert_eq(found.length(), 1)
  assert_eq(basename(found[0]), "alpha.dll")
}

///|
/// The flag is a flag the tool knows, and not a mistake.
test "the flag --no-auto-deps is a flag the tool knows" {
  assert_true(known_flags().contains("no-auto-deps"))
  check_flags([("no-auto-deps", "true")]) catch {
    _ => fail("the flag --no-auto-deps must be known")
  }
}
