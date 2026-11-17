///|
test "folder helpers copy instead of mutating the model" {
  let folders = ["a", "b"]
  let added = append_folder(folders, "c")
  assert_eq(added.length(), 3)
  assert_eq(folders.length(), 2)
  let removed = remove_folder_at(added, 1)
  assert_eq(removed.length(), 2)
  assert_eq(removed[0], "a")
  assert_eq(removed[1], "c")
  let replaced = replace_folder_at(added, 1, "z")
  assert_eq(replaced[1], "z")
  assert_eq(added[1], "b")
}

///|
test "the initial model is empty and ready" {
  let model = initial_model()
  assert_eq(model.input_exe, "")
  assert_eq(model.output_exe, "")
  assert_eq(model.tab, "files")
  assert_eq(model.busy, false)
  assert_eq(model.folders.length(), 0)
}

///|
fn startup_sample() -> @shared.StartupReply {
  {
    input_exe: "D:/apps/myapp.exe",
    output_exe: "D:/out/bundle.exe",
    file_dirs: ["D:/assets", "D:/docs"],
    cli_path: "D:/LunaPack.exe",
    launcher: "",
    compression: "gzip",
    name: "demo",
    version: "0.2.0",
    target_os: "linux",
    arch: "aarch64",
    has_args: true,
  }
}

///|
test "forwarded command-line flags prefill the whole form" {
  let model = apply_startup(initial_model(), startup_sample())
  assert_eq(model.input_exe, "D:/apps/myapp.exe")
  assert_eq(model.output_exe, "D:/out/bundle.exe")
  assert_eq(model.folders.length(), 2)
  assert_eq(model.selected, 0)
  assert_eq(model.cli_path, "D:/LunaPack.exe")
  assert_eq(model.compression, "gzip")
  assert_eq(model.name, "demo")
  assert_eq(model.version, "0.2.0")
  assert_eq(model.target_os, "linux")
  assert_eq(model.arch, "aarch64")
  assert_eq(model.status.contains("Command line loaded"), true)
}

///|
test "an empty startup reply leaves the defaults untouched" {
  let before = initial_model()
  let after = apply_startup(before, {
    input_exe: "",
    output_exe: "",
    file_dirs: [],
    cli_path: "",
    launcher: "",
    compression: "",
    name: "",
    version: "",
    target_os: "",
    arch: "",
    has_args: false,
  })
  assert_eq(after.input_exe, before.input_exe)
  assert_eq(after.compression, before.compression)
  assert_eq(after.name, before.name)
  assert_eq(after.status, before.status)
  assert_eq(after.folders.length(), 0)
}

///|
test "empty forwarded fields keep values already in the form" {
  let seeded = {
    ..initial_model(),
    input_exe: "already.exe",
    compression: "lz4",
  }
  let after = apply_startup(seeded, {
    ..startup_sample(),
    input_exe: "",
    compression: "",
    has_args: true,
  })
  assert_eq(after.input_exe, "already.exe")
  assert_eq(after.compression, "lz4")
  assert_eq(after.output_exe, "D:/out/bundle.exe")
}
