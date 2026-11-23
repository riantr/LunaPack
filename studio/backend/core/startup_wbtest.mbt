///|
fn forwarded() -> Array[String] {
  [
    "lunapack-studio.exe", "--input-file", "D:/apps/myapp.exe", "--output-file=D:/out/myapp-bundle.exe",
    "--Files", "D:/assets", "--files", "D:/docs", "--cli=D:/src/WorkBuddy/Moonbit/LunaPack/_build/native/release/build/LunaPack.exe",
    "--compression-method", "lz4", "--name", "demo", "--version", "0.2.0", "--os",
    "windows", "--arch", "x86_64",
  ]
}

///|
test "the forwarded command line fills every field" {
  let r = parse_startup_args(forwarded())
  assert_eq(r.has_args, true)
  assert_eq(r.input_exe, "D:/apps/myapp.exe")
  assert_eq(r.output_exe, "D:/out/myapp-bundle.exe")
  assert_eq(r.file_dirs.length(), 2)
  assert_eq(r.file_dirs[0], "D:/assets")
  assert_eq(r.file_dirs[1], "D:/docs")
  assert_eq(r.compression, "lz4")
  assert_eq(r.name, "demo")
  assert_eq(r.version, "0.2.0")
  assert_eq(r.target_os, "windows")
  assert_eq(r.arch, "x86_64")
  assert_eq(r.cli_path.has_prefix("D:/"), true)
}

///|
test "both short and long input/output aliases are understood" {
  let r = parse_startup_args([
    "studio", "-i", "a.exe", "-o", "b.exe", "--input", "c.exe", "--output", "d.exe",
  ])
  assert_eq(r.input_exe, "c.exe")
  assert_eq(r.output_exe, "d.exe")
  let r2 = parse_startup_args([
    "studio", "--input-exe", "e.exe", "--output-exe", "f.exe",
  ])
  assert_eq(r2.input_exe, "e.exe")
  assert_eq(r2.output_exe, "f.exe")
}

///|
test "a bare window has defaults, not stale values" {
  let r = parse_startup_args(["lunapack-studio.exe"])
  assert_eq(r.has_args, false)
  assert_eq(r.input_exe, "")
  assert_eq(r.output_exe, "")
  assert_eq(r.cli_path, "")
  assert_eq(r.file_dirs.length(), 0)
}

///|
test "unknown flags are ignored and do not eat the next value" {
  let r = parse_startup_args([
    "studio", "--unknown-thing", "--input-file", "app.exe", "stray.txt",
  ])
  assert_eq(r.input_exe, "app.exe")
  assert_eq(r.file_dirs.length(), 0)
}

///|
test "the GUI switch itself never becomes a field" {
  let r = parse_startup_args(["studio", "--GUI", "--input-file", "app.exe"])
  assert_eq(r.input_exe, "app.exe")
  assert_eq(r.has_args, true)
}

///|
test "an explicit --cli from the launcher is kept" {
  let r = parse_startup_args([
    "studio", "--cli=C:/tools/LunaPack.exe", "--input-file", "app.exe",
  ])
  assert_eq(r.cli_path, "C:/tools/LunaPack.exe")
}

///|
test "paths with spaces survive inline values" {
  let r = parse_startup_args([
    "studio", "--input-file=C:/Program Files/My App/app.exe",
  ])
  assert_eq(r.input_exe, "C:/Program Files/My App/app.exe")
}

///|
test "virtual flags prefill the whole layer" {
  let r = parse_startup_args([
    "studio", "--virtual", "--virtual-root=D:/virt", "--virtual-temp=D:/virt/tmp",
    "--registry=D:/seeds.json", "--runtime=D:/lpvirt.dll",
  ])
  assert_eq(r.virtual_enabled, true)
  assert_eq(r.virtual_root, "D:/virt")
  assert_eq(r.virtual_temp, "D:/virt/tmp")
  assert_eq(r.registry_json, "D:/seeds.json")
  assert_eq(r.runtime_image, "D:/lpvirt.dll")
}

///|
test "no-virtual wins even when other layer flags follow it" {
  let r = parse_startup_args([
    "studio", "--virtual", "--no-virtual", "--registry=D:/seeds.json",
  ])
  assert_eq(r.virtual_enabled, false)
  assert_eq(r.registry_json, "")
}
