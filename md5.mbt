// MD5 (RFC 1321) implemented in pure MoonBit.
//
// MoonBit has no `to_uint32` conversion, so the algorithm runs on `UInt64`
// with every intermediate value masked back to 32 bits. That keeps the
// modular-2^32 semantics MD5 requires while using only APIs that exist in
// this toolchain.
//
// MD5 is not collision resistant and must not be used where that matters. It
// is here because it is the fingerprint format the Windows tooling and the
// file listings of the target platforms use, so it can be compared against
// what the user already has. The package integrity itself is protected by the
// SHA-256 checksum of every entry.

///|
const MD5_M32 : UInt64 = 0xffffffffUL

///|
/// Per-round shift amounts.
fn md5_s() -> Array[Int32] {
  [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
     5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
     4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
     6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ]
}

///|
/// Per-round additive constants: floor(2^32 * abs(sin(i + 1))).
fn md5_t() -> Array[UInt64] {
  [
    0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL, 0xf57c0fafUL, 0x4787c62aUL,
    0xa8304613UL, 0xfd469501UL, 0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL,
    0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL, 0xf61e2562UL, 0xc040b340UL,
    0x265e5a51UL, 0xe9b6c7aaUL, 0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
    0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL, 0xa9e3e905UL, 0xfcefa3f8UL,
    0x676f02d9UL, 0x8d2a4c8aUL, 0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL,
    0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL, 0x289b7ec6UL, 0xeaa127faUL,
    0xd4ef3085UL, 0x04881d05UL, 0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,
    0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL, 0x655b59c3UL, 0x8f0ccc92UL,
    0xffeff47dUL, 0x85845dd1UL, 0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL,
    0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL,
  ]
}

///|
/// Add two 32-bit words, truncated to 32 bits.
fn md5_add32(x : UInt64, y : UInt64) -> UInt64 {
  (x + y) & MD5_M32
}

///|
/// Rotate a 32-bit word left by `n` bits (1 <= n <= 31).
fn md5_rotl32(x : UInt64, n : Int32) -> UInt64 {
  ((x << n) | (x >> (32 - n))) & MD5_M32
}

///|
/// Lowercase hex MD5 digest of `data` (32 characters).
pub fn md5_hex(data : Bytes) -> String {
  let s = md5_s()
  let t = md5_t()
  let n = data.length()
  // Message length in bits, as a 64-bit value.
  let bitlen = n.to_int64() * 8
  // Build the padded message: data || 0x80 || zeros || 64-bit little-endian
  // length.
  let msg : Array[Byte] = []
  let mut i = 0
  while i < n {
    msg.push(data.at((i : Int32)))
    i = i + 1
  }
  msg.push(b'\x80')
  while msg.length() % 64 != 56 {
    msg.push(b'\x00')
  }
  // MD5 stores the length little-endian, unlike SHA-256.
  let mut j = 0
  while j < 8 {
    msg.push(((bitlen >> (j * 8)) & 0xffL).to_byte())
    j = j + 1
  }
  let mut a0 : UInt64 = 0x67452301UL
  let mut b0 : UInt64 = 0xefcdab89UL
  let mut c0 : UInt64 = 0x98badcfeUL
  let mut d0 : UInt64 = 0x10325476UL
  // Compress each 64-byte block.
  let mut off = 0
  while off < msg.length() {
    let x : Array[UInt64] = []
    let mut k = 0
    while k < 16 {
      let b0b = msg[off + k * 4].to_uint64()
      let b1b = msg[off + k * 4 + 1].to_uint64()
      let b2b = msg[off + k * 4 + 2].to_uint64()
      let b3b = msg[off + k * 4 + 3].to_uint64()
      // The words are read little-endian.
      x.push(b0b | (b1b << 8) | (b2b << 16) | (b3b << 24))
      k = k + 1
    }
    let mut a = a0
    let mut b = b0
    let mut c = c0
    let mut d = d0
    k = 0
    while k < 64 {
      let (f, g) = if k < 16 {
        // F(b, c, d) = (b AND c) OR (NOT b AND d)
        ((b & c) | ((b ^ MD5_M32) & d), k)
      } else if k < 32 {
        // G(b, c, d) = (b AND d) OR (c AND NOT d)
        ((b & d) | (c & (d ^ MD5_M32)), (5 * k + 1) % 16)
      } else if k < 48 {
        // H(b, c, d) = b XOR c XOR d
        (b ^ c ^ d, (3 * k + 5) % 16)
      } else {
        // I(b, c, d) = c XOR (b OR NOT d)
        (c ^ (b | (d ^ MD5_M32)), 7 * k % 16)
      }
      let tmp = d
      d = c
      c = b
      let sum = md5_add32(md5_add32(md5_add32(a, f), t[k]), x[g])
      b = md5_add32(b, md5_rotl32(sum, s[k]))
      a = tmp
      k = k + 1
    }
    a0 = md5_add32(a0, a)
    b0 = md5_add32(b0, b)
    c0 = md5_add32(c0, c)
    d0 = md5_add32(d0, d)
    off = off + 64
  }
  // The digest is the four state words in little-endian order.
  let mut out = ""
  for v in [a0, b0, c0, d0] {
    let mut byte_idx = 0
    while byte_idx < 4 {
      let byte = ((v >> (byte_idx * 8)) & 0xffUL).to_int()
      out = out +
        String::make(1, hex_digit(byte >> 4)) +
        String::make(1, hex_digit(byte & 0x0f))
      byte_idx = byte_idx + 1
    }
  }
  out
}

///|
/// Lowercase hex MD5 of the UTF-8 encoding of `s`.
pub fn md5_hex_of_string(s : String) -> String {
  md5_hex(string_to_utf8_bytes(s))
}

///|
/// Hex digit of a nibble.
fn hex_digit(n : Int32) -> Char {
  match n {
    0 => '0'
    1 => '1'
    2 => '2'
    3 => '3'
    4 => '4'
    5 => '5'
    6 => '6'
    7 => '7'
    8 => '8'
    9 => '9'
    10 => 'a'
    11 => 'b'
    12 => 'c'
    13 => 'd'
    14 => 'e'
    15 => 'f'
    _ => '0'
  }
}
