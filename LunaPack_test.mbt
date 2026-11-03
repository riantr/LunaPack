// Unit and integration tests for the LunaPack core.
//
// NOTE: this file is a blackbox test package, so it can only use `pub` items
// and must go through constructors instead of record literals.

///|
test "sha256 matches the NIST test vectors" {
  assert_true(
    @LunaPack.sha256_hex_of_string("") ==
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert_true(
    @LunaPack.sha256_hex_of_string("abc") ==
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_true(
    @LunaPack.sha256_hex_of_string(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    ) ==
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
  assert_true(
    @LunaPack.sha256_hex_of_string(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ) ==
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
  )
}

///|
test "sha256 handles multi-block input" {
  // 1000 * 100 'a' characters exercises several compression blocks.
  let mut s = ""
  let mut i = 0
  while i < 1000 {
    s = s +
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    i = i + 1
  }
  assert_true(
    @LunaPack.sha256_hex_of_string(s) ==
    "6d1cf22d7cc09b085dfc25ee1a1f3ae0265804c607bc2074ad253bcc82fd81ee",
  )
}

///|
test "utf8 codec round-trips" {
  let s = "hello 世界 🎉"
  assert_true(
    @LunaPack.utf8_bytes_to_string(@LunaPack.string_to_utf8_bytes(s)) == s,
  )
}

///|
test "iso8601 formats epoch milliseconds" {
  assert_true(@LunaPack.iso8601_utc(0UL) == "1970-01-01T00:00:00Z")
  assert_true(@LunaPack.iso8601_utc(1793664000000UL) == "2026-11-03T00:00:00Z")
  assert_true(@LunaPack.iso8601_utc(951827696000UL) == "2000-02-29T12:34:56Z")
}

///|
test "script platform matching" {
  assert_true(@LunaPack.script_applies("any", "windows"))
  assert_true(@LunaPack.script_applies("any", "linux"))
  assert_true(@LunaPack.script_applies("windows", "windows"))
  assert_false(@LunaPack.script_applies("windows", "linux"))
  assert_false(@LunaPack.script_applies("linux", "windows"))
  assert_true(@LunaPack.script_applies("posix", "linux"))
  assert_true(@LunaPack.script_applies("posix", "macos"))
  assert_false(@LunaPack.script_applies("posix", "windows"))
}

///|
test "shell selection per platform" {
  let (w_int, w_args, w_ext) = @LunaPack.shell_for("windows")
  assert_true(w_int == "cmd")
  assert_true(w_args.length() == 1 && w_args[0] == "/c")
  assert_true(w_ext == ".cmd")
  let (u_int, u_args, u_ext) = @LunaPack.shell_for("linux")
  assert_true(u_int == "sh")
  assert_true(u_args.length() == 0)
  assert_true(u_ext == ".sh")
}

///|
test "script platform inferred from extension" {
  assert_true(@LunaPack.script_platform_of("setup.cmd") == "windows")
  assert_true(@LunaPack.script_platform_of("setup.BAT") == "windows")
  assert_true(@LunaPack.script_platform_of("setup.sh") == "posix")
  assert_true(@LunaPack.script_platform_of("setup.ps1") == "windows")
  assert_true(@LunaPack.script_platform_of("setup.txt") == "any")
}

///|
test "path helpers" {
  assert_true(@LunaPack.basename("/a/b/c.txt") == "c.txt")
  assert_true(@LunaPack.basename("c.txt") == "c.txt")
  assert_true(@LunaPack.relpath("/a/b", "/a/b/c/d.txt") == "c/d.txt")
  assert_true(@LunaPack.norm_sep("C:\\a\\b") == "C:/a/b")
}

///|
async test "gzip round trip" {
  let data = @LunaPack.string_to_utf8_bytes(
    "hello gzip hello gzip hello gzip 1234567890",
  )
  let gz = @LunaPack.gzip_compress(data)
  assert_true(gz.length() > 0)
  let back = @LunaPack.gzip_decompress(gz)
  assert_true(back == data)
}

///|
async test "compression is skipped when it does not help" {
  // A tiny payload grows when gzipped, so it must stay uncompressed.
  let tiny = @LunaPack.string_to_utf8_bytes("hi")
  let (stored, codec) = @LunaPack.compress_if_smaller(tiny, false)
  assert_true(codec == "raw")
  assert_true(stored == tiny)
  // A large repetitive payload must shrink.
  let mut big = ""
  let mut i = 0
  while i < 200 {
    big = big + "the quick brown fox jumps over the lazy dog "
    i = i + 1
  }
  let bigb = @LunaPack.string_to_utf8_bytes(big)
  let (stored2, codec2) = @LunaPack.compress_if_smaller(bigb, false)
  assert_true(codec2 == "gzip")
  assert_true(stored2.length() < bigb.length())
  assert_true(@LunaPack.gzip_decompress(stored2) == bigb)
}

///|
async test "pack produces a manifest that round-trips" {
  let src = @fs.tmpdir(prefix="lunapack_src")
  @fs.write_file(src + "/hello.txt", "hello")
  @fs.mkdir(src + "/sub", recursive=true, allow_exist=true)
  @fs.write_file(src + "/sub/nested.txt", "nested")
  let outdir = @fs.tmpdir(prefix="lunapack_out")
  let pkg = outdir + "/test.appkg"
  let opts = @LunaPack.new_pack_options(
    "demo",
    "1.0.0",
    "linux",
    "x86_64",
    Some(@LunaPack.new_script("posix", "echo pre\n")),
    None,
    "auto",
  )
  @LunaPack.pack(src, pkg, opts)
  let m = @LunaPack.read_package_manifest(pkg)
  assert_true(m.format_version == 2)
  assert_true(m.name == "demo")
  assert_true(m.version == "1.0.0")
  assert_true(m.os == "linux")
  assert_true(m.arch == "x86_64")
  assert_true(m.checksum_algo == "sha256")
  assert_true(m.compression == "auto")
  assert_true(m.created_at.contains("T"))
  assert_true(m.entries.length() == 2)
  match m.pre_install {
    Some(sc) => {
      assert_true(sc.platform == "posix")
      assert_true(sc.body == "echo pre\n")
    }
    None => assert_true(false)
  }
  assert_true(m.post_install is None)
  // The JSON representation must survive a round trip unchanged.
  let back = @LunaPack.json_to_manifest(@LunaPack.manifest_to_json(m))
  assert_true(back.name == m.name)
  assert_true(back.entries.length() == m.entries.length())
  assert_true(back.entries[0].path == m.entries[0].path)
  assert_true(back.entries[0].checksum == m.entries[0].checksum)
  assert_true(back.entries[0].size == m.entries[0].size)
  // And the package itself must verify.
  assert_true(@LunaPack.verify(pkg))
}

///|
async test "unpack restores the original tree" {
  let src = @fs.tmpdir(prefix="lunapack_src")
  @fs.write_file(src + "/hello.txt", "hello")
  @fs.mkdir(src + "/sub", recursive=true, allow_exist=true)
  @fs.write_file(src + "/sub/nested.txt", "nested")
  let outdir = @fs.tmpdir(prefix="lunapack_out")
  let pkg = outdir + "/test.appkg"
  let dest = outdir + "/unpacked"
  let opts = @LunaPack.new_pack_options(
    "demo",
    "1.0.0",
    "linux",
    "x86_64",
    None,
    None,
    "auto",
  )
  @LunaPack.pack(src, pkg, opts)
  @LunaPack.unpack(pkg, dest, false)
  let a = @fs.read_file(dest + "/hello.txt")
  assert_true(@LunaPack.utf8_bytes_to_string(a.binary()) == "hello")
  let b = @fs.read_file(dest + "/sub/nested.txt")
  assert_true(@LunaPack.utf8_bytes_to_string(b.binary()) == "nested")
}

///|
async test "posix install script runs through sh" {
  // Exercises the POSIX code path (the one used on Linux/macOS). It needs a
  // `sh` on PATH: /bin/sh on Linux, Git Bash / MSYS on Windows.
  let dir = @fs.tmpdir(prefix="lunapack_test")
  let script = @LunaPack.new_script(
    "posix", "#!/bin/sh\nprintf 'ran-%s' \"$LUNAPACK_PHASE\" > out.txt\n",
  )
  let st = @LunaPack.run_install_script("linux", "pre_install", script, dir)
  assert_true(st == 0)
  let out = @fs.read_file(dir + "/out.txt")
  assert_true(@LunaPack.utf8_bytes_to_string(out.binary()) == "ran-pre_install")
}

///|
async test "bundle appends an archive to the executable" {
  let src = @fs.tmpdir(prefix="lunapack_src")
  let app = src + "/app.exe"
  @fs.write_file(app, "pretend this is an executable")
  let res = @fs.tmpdir(prefix="lunapack_res")
  @fs.write_file(res + "/data.txt", "resource")
  let outdir = @fs.tmpdir(prefix="lunapack_out")
  let bundle_path = outdir + "/app.exe"
  let opts = @LunaPack.new_pack_options(
    "demo",
    "1.0.0",
    "windows",
    "x86_64",
    None,
    None,
    "auto",
  )
  @LunaPack.bundle(app, bundle_path, [res], opts)
  // The bundle is the launcher stub with the archive appended, so it is
  // larger than the application it carries.
  let app_bytes = @fs.read_file(app).binary()
  let bundle_bytes = @fs.read_file(bundle_path).binary()
  assert_true(bundle_bytes.length() > app_bytes.length())
  // The manifest must be reachable inside the bundle.
  let m = @LunaPack.read_package_manifest(bundle_path)
  assert_true(m.main_program == "app.exe")
  assert_true(m.entries.length() == 2)
  // And the payload must extract byte-identically.
  let dest = outdir + "/extracted"
  @LunaPack.unpack(bundle_path, dest, false)
  let a = @fs.read_file(dest + "/app.exe")
  assert_true(
    @LunaPack.utf8_bytes_to_string(a.binary()) ==
    "pretend this is an executable",
  )
  // A single --Files directory is stored at the archive root, next to the
  // main program, so the extracted application is directly runnable.
  let b = @fs.read_file(dest + "/data.txt")
  assert_true(@LunaPack.utf8_bytes_to_string(b.binary()) == "resource")
}

///|
async test "with_defaults and with_main_program copy the options" {
  let opts = @LunaPack.new_pack_options(
    "n",
    "v",
    "os",
    "arch",
    None,
    None,
    "none",
  )
  assert_true(opts.main_program == "")
  let a = @LunaPack.with_main_program(opts, "app.exe")
  assert_true(a.main_program == "app.exe")
  assert_true(a.name == "n")
  assert_true(a.compression == "none")
  let b = @LunaPack.with_defaults(opts, "n2", "v2", "os2", "arch2")
  assert_true(b.name == "n2")
  assert_true(b.version == "v2")
  assert_true(b.os == "os2")
  assert_true(b.arch == "arch2")
  assert_true(b.compression == "none")
  assert_true(b.main_program == "")
}

///|
test "the package tag is stable and short" {
  let tag1 = @LunaPack.package_tag_of("some manifest text")
  let tag2 = @LunaPack.package_tag_of("some manifest text")
  assert_true(tag1 == tag2)
  assert_true(tag1.length() == 16)
  assert_true(tag1 != @LunaPack.package_tag_of("other text"))
}

///|
test "the running executable path is known" {
  match @LunaPack.current_exe_path() {
    Some(p) => assert_true(p.length() > 0)
    None => assert_true(false)
  }
}
