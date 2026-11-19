// Running a mapped image's entry point.
//
// A DLL that was mapped by hand never receives DllMain, because it is not in
// the loader's module list and nothing else knows it exists. For the in-proc
// servers combase loads out of the archive (L5.3) that is a real gap rather
// than a detail: global constructors, TLS setup and the module's own one-time
// initialisation live behind that call, and a component that skipped them
// faults on its first method.
//
// MoonBit cannot call an address it computed at run time, and the whole point
// of the runtime is to stay dependency-free, so the call is handed to the
// system instead of being written in C. A few bytes of machine code are placed
// in a page the runtime owns, and `InitOnceExecuteOnce` — a documented Win32
// entry point that takes a function pointer and calls it synchronously on the
// calling thread — is used as the caller. The stub performs exactly
// `DllMain(base, DLL_PROCESS_ATTACH, NULL)`, so the image sees the same call
// the real loader would have made.

///|
/// Win32: call `callback(init_once, param, context)` once, on this thread. Used
/// only as a "call this pointer" primitive; the once-state is a fresh page per
/// image, so the once-ness never suppresses a second module's attach.
///
/// The real prototype takes four arguments - (InitOnce, InitFn, Parameter,
/// Context) - and the callback receives the last three.
extern "C" fn init_once_execute_once(
  init_once : Int64,
  callback : Int64,
  param : Int64,
  context : Int64,
) -> Int32 = "InitOnceExecuteOnce"

///|
const ENTRY_STUB_SIZE : Int64 = 4096

///|
/// `DLL_PROCESS_ATTACH`. The only notification the runtime sends by itself.
const DLL_PROCESS_ATTACH : Int64 = 1

///|
/// Offset of the stub inside its page. The first 8 bytes hold the INIT_ONCE
/// cell, which must stay zeroed for `InitOnceExecuteOnce` to run the callback.
const ENTRY_STUB_OFFSET : Int64 = 32

///|
/// x64 stub: `DllMain(base, DLL_PROCESS_ATTACH, NULL)`.
///
///   48 83 EC 28              sub  rsp, 28h      ; shadow space + alignment
///   48 B9 <base>             mov  rcx, base     ; HINSTANCE
///   BA 01 00 00 00           mov  edx, 1        ; DLL_PROCESS_ATTACH
///   45 31 C0                 xor  r8d, r8d      ; lpReserved = NULL
///   48 B8 <entry>            mov  rax, entry
///   FF D0                    call rax
///   48 83 C4 28              add  rsp, 28h
///   C3                       ret
///
/// The two 8-byte fields are filled in per call, at offsets 6 and 24.
fn entry_stub_code() -> FixedArray[Byte] {
  [
    b'\x48', b'\x83', b'\xec', b'\x28', // sub rsp, 28h
     b'\x48', b'\xb9', // mov rcx, imm64
     b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\xba',
    b'\x01', b'\x00', b'\x00', b'\x00', // mov edx, 1
     b'\x45', b'\x31', b'\xc0', // xor r8d, r8d
     b'\x48', b'\xb8', // mov rax, imm64
     b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\xff',
    b'\xd0', // call rax
     b'\x48', b'\x83', b'\xc4', b'\x28', // add rsp, 28h
     b'\xc3', // ret
  ]
}

///|
/// Invoke `base`'s entry point with DLL_PROCESS_ATTACH. Returns 0 when the
/// image has no entry point (a `/NOENTRY` server), 1 when DllMain returned
/// TRUE, -1 when the stub could not be built or DllMain returned FALSE.
fn run_entry_point(base : Int64, entry : Int64) -> Int32 {
  if base == 0L || entry == 0L {
    return 0
  }
  let page = virtual_alloc(
    0L,
    ENTRY_STUB_SIZE,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
  )
  if page == 0L {
    return -1
  }
  let code = entry_stub_code()
  let stub = page + ENTRY_STUB_OFFSET
  poke_bytes(stub, Bytes::from_array(code), code.length().to_int())
  poke_bytes(stub + 6L, u64le(base), 8)
  poke_bytes(stub + 24L, u64le(entry), 8)
  ignore(flush_instruction_cache(-1L, stub, code.length().to_int64()))
  // The stub ignores its three arguments; the INIT_ONCE cell at the page head
  // is what makes this a legal call rather than an indirect jump of our own.
  let ok = init_once_execute_once(page, stub, 0L, 0L)
  if ok != 0 {
    1
  } else {
    -1
  }
}
