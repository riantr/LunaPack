// Whitebox tests for the `--GUI` front end. Everything that can be checked
// without a network or a window lives here; the download itself is covered by
// an end-to-end run against a local HTTP server.

///|
test "--GUI is recognised in any spelling and any position" {
  for
    flag in [
      "--GUI", "--gui", "-GUI", "-gui", "--GUI=true", "--gui=true", "-GUI=true",
      "-gui=true",
    ] {
    assert_true(wants_gui([flag]))
    assert_true(wants_gui(["--input-file", "app.exe", flag]))
  }
  assert_false(wants_gui([]))
  assert_false(wants_gui(["bundle", "-i", "app.exe", "-o", "out.exe"]))
  assert_false(wants_gui(["--guide", "--guinea"]))
}

///|
test "the GUI switch is removed but the rest of the command line is kept" {
  let args = [
    "--input-file", "app.exe", "--GUI", "--output-file", "out.exe", "--Files", "assets",
    "--compression-method", "lz4",
  ]
  let kept = without_gui_flags(args)
  assert_true(kept.length() == args.length() - 1)
  assert_true(kept[0] == "--input-file")
  assert_true(kept[1] == "app.exe")
  assert_true(kept[2] == "--output-file")
  assert_true(kept[3] == "out.exe")
  assert_true(kept[4] == "--Files")
  assert_true(kept[5] == "assets")
  assert_true(kept[6] == "--compression-method")
  assert_true(kept[7] == "lz4")
}

///|
test "Studio receives the flags the user typed plus the CLI to drive" {
  let args = studio_arguments([
    "--GUI", "--input-file", "app.exe", "--output-file", "out.exe", "--Files", "assets",
  ])
  assert_true(args[0] == "--input-file")
  assert_true(args[1] == "app.exe")
  assert_true(args[2] == "--output-file")
  assert_true(args[3] == "out.exe")
  assert_true(args[4] == "--Files")
  assert_true(args[5] == "assets")
  let cli_flags = args.filter(a => a.has_prefix("--cli="))
  assert_true(cli_flags.length() == 1)
  assert_true(cli_flags[0].length() > "--cli=".length())
}

///|
test "an explicit --cli is never overridden by the launcher" {
  let args = studio_arguments([
    "--GUI", "--cli=C:/tools/lunapack.exe", "--input-file", "app.exe",
  ])
  let cli_flags = args.filter(a => a.has_prefix("--cli"))
  assert_true(cli_flags.length() == 1)
  assert_true(cli_flags[0] == "--cli=C:/tools/lunapack.exe")
}

///|
test "the Studio asset is named after this platform and architecture" {
  let asset = studio_asset_name()
  assert_true(asset.has_prefix("lunapack-studio-"))
  assert_true(asset.has_suffix(".zip"))
  assert_true(
    asset == "lunapack-studio-" + host_platform() + "-" + studio_arch() + ".zip",
  )
}

///|
test "the default download URL points at this version's release" {
  @env.set_env_var("LUNAPACK_STUDIO_URL", "")
  let url = studio_release_url()
  assert_true(
    url.has_prefix("https://github.com/riantr/LunaPack/releases/download/"),
  )
  assert_true(url.contains("/v" + CLI_VERSION + "/"))
  assert_true(url.has_suffix(studio_asset_name()))
  @env.set_env_var("LUNAPACK_STUDIO_URL", "http://127.0.0.1:8765/studio.zip")
  assert_true(studio_release_url() == "http://127.0.0.1:8765/studio.zip")
  @env.set_env_var("LUNAPACK_STUDIO_URL", "")
}

///|
async test "the download URL version is the module version" {
  // The URL is built from CLI_VERSION. A release that forgets to bump it
  // would download the previous Studio, so the two are pinned together.
  let mut text = ""
  let mut found = false
  for
    candidate in [
      "moon.mod", "../moon.mod", "../../moon.mod", "../../../moon.mod",
    ] {
    if !found && @fs.exists(candidate) {
      text = @fs.read_text(candidate)
      found = true
    }
  }
  assert_true(found, msg="moon.mod must be reachable from the tests")
  let mut version_line = ""
  let mut count = 0
  for line in text_lines(text) {
    if line.has_prefix("version") {
      version_line = line
      count = count + 1
    }
  }
  assert_true(count == 1)
  assert_true(
    version_line.contains("\"" + CLI_VERSION + "\""),
    msg="moon.mod says " + version_line + " but CLI_VERSION is " + CLI_VERSION,
  )
}

///|
test "loopback mirrors never go through a proxy" {
  assert_true(is_loopback_url("http://127.0.0.1:8765/studio.zip"))
  assert_true(is_loopback_url("http://localhost/studio.zip"))
  assert_true(is_loopback_url("https://LOCALHOST:8443/a.zip"))
  assert_true(is_loopback_url("http://[::1]:8080/a.zip"))
  assert_true(is_loopback_url("http://user@127.0.0.1:8080/a.zip"))
  assert_false(is_loopback_url("https://github.com/riantr/LunaPack"))
  assert_false(is_loopback_url("http://192.168.1.10/a.zip"))
  assert_true(proxy_bypassed("http://127.0.0.1:8765/studio.zip"))
}

///|
test "NO_PROXY is honoured for named hosts" {
  @env.set_env_var("NO_PROXY", "example.com,.internal.test")
  assert_true(proxy_bypassed("https://example.com/a.zip"))
  assert_true(proxy_bypassed("https://cdn.internal.test/a.zip"))
  assert_false(proxy_bypassed("https://github.com/a.zip"))
  @env.set_env_var("NO_PROXY", "*")
  assert_true(proxy_bypassed("https://github.com/a.zip"))
  @env.set_env_var("NO_PROXY", "")
}

///|
test "redirect targets are resolved against the previous URL" {
  assert_true(
    absolute_url(
      "https://github.com/a/b/c.zip", "https://objects.example.com/x",
    ) ==
    "https://objects.example.com/x",
  )
  assert_true(
    absolute_url("https://github.com/a/b/c.zip", "/other.zip") ==
    "https://github.com/other.zip",
  )
  assert_true(
    absolute_url("https://github.com/a/b/c.zip", "next.zip") ==
    "https://github.com/a/b/next.zip",
  )
  assert_true(
    absolute_url("http://127.0.0.1:8765/studio.zip", "mirror/studio.zip") ==
    "http://127.0.0.1:8765/mirror/studio.zip",
  )
}

///|
test "content-length parsing stops at the first non-digit" {
  assert_true(decimal("188743680") == 188743680L)
  assert_true(decimal("0") == 0L)
  assert_true(decimal("123 bytes") == 123L)
  assert_true(decimal("") == 0L)
}

///|
test "zip entry names cannot escape the destination" {
  assert_true(safe_zip_name("lunapack-studio/lunapack-studio.exe"))
  assert_true(safe_zip_name("./readme.txt"))
  assert_false(safe_zip_name("../evil.exe"))
  assert_false(safe_zip_name("a/../../evil.exe"))
  assert_false(safe_zip_name("a/../.."))
  assert_false(safe_zip_name("..\\evil.exe"))
  assert_false(safe_zip_name("/etc/passwd"))
  assert_false(safe_zip_name("C:/Windows/evil.exe"))
}

///|
test "Windows zip separators are normalised before a path is built" {
  assert_eq(
    normalized_zip_name("lunapack-studio\\Resources\\frontend\\"),
    "lunapack-studio/Resources/frontend/",
  )
  assert_eq(
    normalized_zip_name("lunapack-studio\\lunapack-studio.exe"),
    "lunapack-studio/lunapack-studio.exe",
  )
  assert_eq(normalized_zip_name("readme.txt"), "readme.txt")
  // The safety check must see through a Windows separator too.
  assert_false(safe_zip_name("..\\evil.exe"))
  assert_false(safe_zip_name("a\\..\\..\\evil.exe"))
}

///|
test "the progress line shows both a bar and the transferred size" {
  let line = download_line(94371840L, 188743680L)
  assert_true(line.contains("50%"))
  assert_true(line.contains("MB"))
  assert_true(line.contains("["))
  let unknown = download_line(1048576L, 0L)
  assert_true(unknown.contains("1.0 MB downloaded"))
}

///|
async test "a damaged archive is refused instead of unpacked" {
  let refused = try {
    extract_zip(@utf8.encode("this is not a zip file"), ".")
    false
  } catch {
    _ => true
  }
  assert_true(refused)
}
