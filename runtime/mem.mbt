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
#borrow(name)
extern "C" fn real_get_proc_address(hmod : Int64, name : Bytes) -> Int64 = "GetProcAddress"

///|
extern "C" fn lstrlen_w(s : Int64) -> Int32 = "lstrlenW"

///|
extern "C" fn set_last_error(code : Int32) -> Unit = "SetLastError"

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
