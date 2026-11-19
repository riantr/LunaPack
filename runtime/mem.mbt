// Raw memory access inside our own process.
//
// These are the only "unsafe" primitives in the runtime. Everything happens
// in the current address space: no OpenProcess, no VirtualAllocEx, no
// WriteProcessMemory, no CreateRemoteThread. Reading and writing a pointer is
// done through the C runtime's memcpy/memmove, which MoonBit's native backend
// links anyway.

///|
/// Copy `n` bytes from a raw address into a MoonBit buffer.
#borrow(dst)
extern "C" fn memcpy_into(dst : Bytes, src : Int64, n : Int64) -> Int64 = "memcpy"

///|
/// Copy `n` bytes from a MoonBit buffer to a raw address. `memmove` is a
/// distinct C symbol, so the two extern blocks do not collide in link-core.
#borrow(src)
extern "C" fn memmove_out(dst : Int64, src : Bytes, n : Int64) -> Int64 = "memmove"

///|
#borrow(name)
extern "C" fn get_module_handle_a(name : Bytes) -> Int64 = "GetModuleHandleA"

///|
/// Full path of a loaded module. L2.2 uses this to skip Windows system DLLs:
/// patching their own LoadLibrary IAT slots makes the OS loader's internal
/// calls re-enter our thunk and recurse until the stack overflows.
#borrow(buf)
extern "C" fn get_module_file_name_a(
  hmod : Int64,
  buf : Bytes,
  cap : Int32,
) -> Int32 = "GetModuleFileNameA"

///|
#borrow(name)
extern "C" fn real_get_proc_address(hmod : Int64, name : Bytes) -> Int64 = "GetProcAddress"

///|
/// Real wide / extended loader entry points. A LoadLibrary thunk calls the real
/// loader, then installs our IAT hooks in whatever module it just loaded.
/// LoadLibraryA reuses mapper.mbt's `load_library_a` binding (a C symbol may
/// have only one MoonBit extern). L2.2.
extern "C" fn real_load_library_w(name : Int64) -> Int64 = "LoadLibraryW"

///|
extern "C" fn real_load_library_ex_a(
  name : Int64,
  file : Int64,
  flags : Int32,
) -> Int64 = "LoadLibraryExA"

///|
extern "C" fn real_load_library_ex_w(
  name : Int64,
  file : Int64,
  flags : Int32,
) -> Int64 = "LoadLibraryExW"

///|
extern "C" fn lstrlen_w(s : Int64) -> Int32 = "lstrlenW"

///|
/// Length of a NUL-terminated ANSI (single-byte) string. L2.1 ANSI variants
/// use this so they read exactly the string, not a fixed 260-byte window.
extern "C" fn lstrlen_a(s : Int64) -> Int32 = "lstrlenA"

///|
/// Read a NUL-terminated ANSI string. Virtual paths are ASCII-only; a path
/// with non-ASCII bytes will simply fail to match the virtual tree and fall
/// through to the real API.
fn ansi_to_string(addr : Int64) -> String {
  if addr == 0L {
    return ""
  }
  let n = lstrlen_a(addr)
  if n <= 0 {
    return ""
  }
  bytes_to_ascii(peek_bytes(addr, n))
}

///|
extern "C" fn set_last_error(code : Int32) -> Unit = "SetLastError"

///|
/// Signal a Win32 event handle. Used to complete an overlapped in-memory I/O.
extern "C" fn set_event(handle : Int64) -> Int32 = "SetEvent"

///|
/// Terminate only the calling thread. The ExitProcess thunk redirects here so
/// a mapped CRT image can finish without ending the whole launcher process.
extern "C" fn exit_thread(code : Int32) -> Unit = "ExitThread"

///|
/// Write a Win32 FILETIME (two little-endian DWORDs: low then high) at `addr`.
fn poke_filetime(addr : Int64, ticks : Int64) -> Unit {
  let low = ticks & 0xFFFFFFFFL
  let high = (ticks >> 32) & 0xFFFFFFFFL
  poke_bytes(addr, u32le(low), 4)
  poke_bytes(addr + 4L, u32le(high), 4)
}

///|
/// OVERLAPPED.Offset (x64 layout: Internal@0, InternalHigh@8, Offset@16,
/// OffsetHigh@20, hEvent@24). Returns the 64-bit positioned I/O offset.
fn ov_offset(addr : Int64) -> Int64 {
  if addr == 0L {
    return 0L
  }
  let lo = peek32(addr + 16L)
  let hi = peek32(addr + 20L)
  lo | (hi << 32)
}

///|
/// Fill the OVERLAPPED status fields once an in-memory I/O completes.
fn ov_complete(addr : Int64, status : Int64, bytes : Int64) -> Unit {
  if addr == 0L {
    return
  }
  poke64(addr, status)
  poke64(addr + 8L, bytes)
}

///|
/// The hEvent field of an OVERLAPPED structure (x64 offset 24).
fn ov_event(addr : Int64) -> Int64 {
  if addr == 0L {
    return 0L
  }
  peek64(addr + 24L)
}

///|
#borrow(old)
extern "C" fn virtual_protect(
  addr : Int64,
  size : Int64,
  protect : Int32,
  old : Bytes,
) -> Int32 = "VirtualProtect"

///|
fn peek_bytes(addr : Int64, n : Int32) -> Bytes {
  let b = Bytes::make(n, b'\x00')
  ignore(memcpy_into(b, addr, n.to_int64()))
  b
}

///|
fn poke_bytes(addr : Int64, data : Bytes, n : Int32) -> Unit {
  if n > 0 {
    ignore(memmove_out(addr, data, n.to_int64()))
  }
}

///|
fn le_u16(b : Bytes, off : Int32) -> Int32 {
  b[off].to_int() | (b[off + 1].to_int() << 8)
}

///|
fn le_u32(b : Bytes, off : Int32) -> Int64 {
  b[off].to_int64() |
  (b[off + 1].to_int64() << 8) |
  (b[off + 2].to_int64() << 16) |
  (b[off + 3].to_int64() << 24)
}

///|
fn le_u64(b : Bytes, off : Int32) -> Int64 {
  let mut v = 0L
  let mut i = 7
  while i >= 0 {
    v = (v << 8) | b[off + i].to_int64()
    i = i - 1
  }
  v
}

///|
fn peek16(addr : Int64) -> Int32 {
  le_u16(peek_bytes(addr, 2), 0)
}

///|
fn peek32(addr : Int64) -> Int64 {
  le_u32(peek_bytes(addr, 4), 0)
}

///|
fn peek64(addr : Int64) -> Int64 {
  le_u64(peek_bytes(addr, 8), 0)
}

///|
fn u32le(v : Int64) -> Bytes {
  let a = FixedArray::make(4, b'\x00')
  let mut x = v
  for i = 0; i < 4; i = i + 1 {
    a[i] = (x & 255L).to_byte()
    x = x >> 8
  }
  Bytes::from_array(a[:])
}

///|
fn u64le(v : Int64) -> Bytes {
  let a = FixedArray::make(8, b'\x00')
  let mut x = v
  for i = 0; i < 8; i = i + 1 {
    a[i] = (x & 255L).to_byte()
    x = x >> 8
  }
  Bytes::from_array(a[:])
}

///|
fn poke64(addr : Int64, value : Int64) -> Unit {
  poke_bytes(addr, u64le(value), 8)
}

///|
/// NUL-terminated ASCII string, for C API names and DLL names.
fn cstring(s : String) -> Bytes {
  let a = FixedArray::make(s.length() + 1, b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = s[i].to_byte()
  }
  Bytes::from_array(a[:])
}

///|
/// Read a NUL-terminated ASCII string at `addr`.
fn ascii_at(addr : Int64, max : Int32) -> String {
  let b = peek_bytes(addr, max)
  let mut out = ""
  let mut i = 0
  while i < max {
    let c = b[i].to_int()
    if c == 0 {
      return out
    }
    out = out + String::make(1, b[i].to_char())
    i = i + 1
  }
  out
}

///|
/// Read a NUL-terminated UTF-16LE string at `addr`.
fn wide_to_string(addr : Int64) -> String {
  if addr == 0L {
    return ""
  }
  let n = lstrlen_w(addr)
  if n <= 0 {
    return ""
  }
  let b = peek_bytes(addr, n * 2)
  @utf16.decode(b) catch {
    _ => ""
  }
}

///|
/// Read an exact-length UTF-16LE string. UNICODE_STRING.Length (used by the
/// ntdll thunks) counts bytes and is not NUL-terminated, so wide_to_string
/// cannot be used for it.
fn wide_exact(addr : Int64, byte_len : Int32) -> String {
  if addr == 0L || byte_len <= 0 {
    return ""
  }
  let units = byte_len / 2
  if units <= 0 {
    return ""
  }
  @utf16.decode(peek_bytes(addr, units * 2)) catch {
    _ => ""
  }
}

///|
/// Decode a UTF-16LE string that already sits in a byte buffer, for callers
/// that receive a structure with an inline string.
fn wide_from_bytes(b : Bytes, off : Int32, byte_len : Int32) -> String {
  if off < 0 || byte_len <= 0 || off + byte_len > b.length() {
    return ""
  }
  @utf16.decode(bytes_slice(b, off, off + byte_len)) catch {
    _ => ""
  }
}

///|
/// Encode an ASCII-only MoonBit string as UTF-16LE without a terminator.
fn utf16le_no_nul(s : String) -> Bytes {
  let a = FixedArray::make(s.length() * 2, b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i * 2] = s[i].to_byte()
  }
  Bytes::from_array(a[:])
}

///|
fn bytes_to_ascii(b : Bytes) -> String {
  let mut out = ""
  for i = 0; i < b.length(); i = i + 1 {
    out = out + String::make(1, b[i].to_char())
  }
  out
}

///|
/// Plain ASCII bytes, for test fixtures.
fn ascii_bytes(s : String) -> Bytes {
  let a = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = s[i].to_byte()
  }
  Bytes::from_array(a[:])
}

///|
/// Encode an ASCII-only MoonBit string as UTF-16LE with a terminating NUL.
fn utf16le(s : String) -> Bytes {
  let a = FixedArray::make((s.length() + 1) * 2, b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i * 2] = s[i].to_byte()
  }
  Bytes::from_array(a[:])
}

///|
/// Write UTF-16LE `s` into a caller-owned wide buffer of `cap` bytes.
fn write_wide(addr : Int64, s : String, cap : Int32) -> Int32 {
  let b = utf16le(s)
  let n = if b.length() < cap { b.length() } else { cap }
  poke_bytes(addr, b, n)
  n
}
