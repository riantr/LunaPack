///|
fn sample_request() -> @shared.ProcessRequest {
  @shared.ProcessRequest::{
    input_exe: "myapp.exe",
    output_exe: "myapp-bundle.exe",
    file_dirs: ["assets", "docs"],
    cli_path: "LunaPack.exe",
    launcher: "",
    compression: "lz4",
    name: "myapp",
    version: "0.1.0",
    target_os: "windows",
    arch: "x86_64",
    virtual_enabled: false,
    virtual_root: "C:\\virt",
    virtual_temp: "",
    registry_json: "[]",
    runtime_image: "",
  }
}

///|
test "bundle arguments keep folder order and repeat --Files" {
  let args = bundle_arguments(sample_request())
  assert_eq(args[0], "bundle")
  assert_eq(args[1], "--input")
  assert_eq(args[2], "myapp.exe")
  assert_eq(args[3], "--output")
  assert_eq(args[4], "myapp-bundle.exe")
  assert_eq(args[5], "--Files")
  assert_eq(args[6], "assets")
  assert_eq(args[7], "--Files")
  assert_eq(args[8], "docs")
}

///|
test "optional flags are emitted only when set" {
  let request = @shared.ProcessRequest::{
    ..sample_request(),
    compression: "lz4",
    name: "myapp",
    version: "0.1.0",
    target_os: "windows",
    arch: "x86_64",
    launcher: "stub.exe",
  }
  let args = bundle_arguments(request)
  assert_eq(args[9], "--compression-method")
  assert_eq(args[10], "lz4")
  assert_eq(args[args.length() - 2], "--launcher")
  assert_eq(args[args.length() - 1], "stub.exe")
}

///|
test "empty optional fields are not passed to the CLI" {
  let empty_dirs : Array[String] = []
  let request = @shared.ProcessRequest::{
    ..sample_request(),
    compression: "",
    name: "",
    version: "",
    target_os: "",
    arch: "",
    launcher: "",
    file_dirs: empty_dirs,
  }
  assert_eq(bundle_arguments(request).length(), 5)
}

///|
test "virtual bundles emit the layer, seeds and a store-only codec" {
  let request = @shared.ProcessRequest::{
    ..sample_request(),
    compression: "lz4",
    launcher: "lpvhost.exe",
    virtual_enabled: true,
    virtual_root: "C:\\app",
    virtual_temp: "C:\\app\\tmp",
    runtime_image: "D:\\lpvirt.dll",
  }
  let args = bundle_arguments_with_registry(request, "D:/seeds.json")
  assert_eq(args[9], "--compression-method")
  assert_eq(args[10], "none")
  assert_eq(args[21], "--virtual")
  assert_eq(args[22], "--virtual-root")
  assert_eq(args[23], "C:\\app")
  assert_eq(args[24], "--virtual-temp")
  assert_eq(args[25], "C:\\app\\tmp")
  assert_eq(args[26], "--registry")
  assert_eq(args[27], "D:/seeds.json")
  assert_eq(args[28], "--runtime")
  assert_eq(args[29], "D:\\lpvirt.dll")
}

///|
test "an empty registry editor does not pass --registry" {
  let request = @shared.ProcessRequest::{
    ..sample_request(),
    virtual_enabled: true,
    virtual_root: "",
  }
  let args = bundle_arguments(request)
  assert_eq(args[args.length() - 1], "--virtual")
}

///|
test "the default CLI is a sibling of this project" {
  assert_eq(cli_candidates()[0], default_cli())
}
