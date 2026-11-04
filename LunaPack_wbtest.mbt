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
  let (_base, manifest) = locate_archive(file)
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
  let (_base, manifest) = locate_archive(file)
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
