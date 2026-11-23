// The virtual launcher: map the runtime out of the bundle, then hand over.
//
// A virtual bundle is one file that carries three things: this launcher, the
// runtime, and an archive with the program and the files it reads. Starting it
// must not unpack anything, so the program is mapped into this process and
// answered from memory.
//
// The runtime is where that happens, and it is not linked in - it is mapped out
// of the same bundle, because the thunks that answer the program's calls are
// exported from it, and MoonBit can only give a function a C name inside a
// package that may not have a `main`. So this program does four things and
// nothing else: find the runtime the bundle carries, map it, run its entry
// point, and end with the code the program inside ended with.
//
// Between those two worlds pass an address and a number. Nothing else may:
// this process holds two copies of the MoonBit runtime, each with its own
// allocator, and a MoonBit value handed from one to the other would be freed
// by the heap that did not allocate it.

///|
fn main {
  let image = @rt.host_bundle_runtime_image()
  if image.length() == 0 {
    eprintln(
      "lpvhost: this file carries no LunaPack virtual bundle: start it with " +
      "lp unpack, or make it again with --virtual",
    )
    @rt.host_exit(1)
    return
  }
  // The runtime is an ordinary image to the mapper: headers, sections,
  // relocations, imports. It is not registered with the loader, so from here
  // on the only way to reach into it is its own export table.
  let base = @rt.host_map(image)
  if base == 0L {
    eprintln(
      "lpvhost: cannot map the runtime the bundle carries (reason " +
      @rt.host_map_error().to_string() +
      ")",
    )
    @rt.host_exit(1)
    return
  }
  // MoonBit's own initialisation, then the runtime's entry point. Both are
  // numbers from the mapped image's export table, and both are called by
  // Windows on this program's behalf.
  let init = @rt.host_image_export(base, "moonbit_init")
  if init == 0L {
    eprintln("lpvhost: the runtime in this bundle cannot be initialised")
    @rt.host_exit(1)
    return
  }
  // A hand-mapped DLL is not in the loader's module list, so nobody delivers
  // DllMain to it. Its CRT sets up the heap here; without this the first
  // allocation in `moonbit_init` calls HeapAlloc with a zero heap handle.
  ignore(@rt.host_attach_image(base))
  // `moonbit_init` has to run on this thread: the C host does the same, and a
  // worker thread leaves the runtime's thread-local state behind when it ends.
  ignore(@rt.host_call_sync(init, 0L))
  // The attach note is bookkeeping for lifecycle checks. It touches runtime
  // state, so it comes after init, like every other `lp_*` call.
  let attach = @rt.host_image_export(base, "lp_mapped_attach")
  if attach == 0L {
    eprintln("lpvhost: the runtime in this bundle has no mapped-image attach")
    @rt.host_exit(1)
    return
  }
  ignore(@rt.host_call_sync(attach, base))
  let run = @rt.host_image_export(base, "lp_run_bundle")
  if run == 0L {
    eprintln("lpvhost: the runtime in this bundle does not run bundles")
    @rt.host_exit(1)
    return
  }
  // The base is the whole message: the runtime records it, so that the hooks it
  // installs can name their own thunks, and reads the archive itself.
  @rt.host_exit(@rt.call_address(run, base))
}
