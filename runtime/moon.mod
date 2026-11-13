// The in-process virtualization runtime is a separate module on purpose.
//
// It is Windows-only, it is a `foreign_library` (a C ABI DLL is linked from
// the static archive it produces), and its test executables need advapi32.
// Keeping it out of the root module means the cross-platform CLI keeps
// building for native and wasm on Linux, macOS and Windows without any
// Windows-only link flags leaking into those builds.

name = "riantr/lunapack_runtime"

version = "0.1.24"

preferred_target = "native"

license = "MIT"

description = "Windows in-process VFS, virtual registry and memory PE loader for LunaPack"
