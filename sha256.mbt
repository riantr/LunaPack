// SHA-256 (FIPS 180-4) implemented in pure MoonBit.
//
// MoonBit has no `to_uint32` conversion, so the algorithm runs on `UInt64`
// with every intermediate value masked back to 32 bits. That keeps the
// modular-2^32 semantics SHA-256 requires while using only APIs that exist
// in this toolchain.

///|
const M32 : UInt64 = 0xffffffffUL

///|
fn sha256_k() -> Array[UInt64] {
  [
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL,
    0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL,
    0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL, 0xa2bfe8a1UL, 0xa81a664bUL,
    0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL,
    0x5b9cca4fUL, 0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
  ]
}

///|
/// Add two 32-bit words, truncated to 32 bits.
fn add32(x : UInt64, y : UInt64) -> UInt64 {
  (x + y) & M32
}

///|
/// Rotate a 32-bit word right by `n` bits (1 <= n <= 31).
fn rotr32(x : UInt64, n : Int32) -> UInt64 {
  ((x >> n) | (x << (32 - n))) & M32
}

///|
/// Logical shift right of a 32-bit word.
fn shr32(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) & M32
}

///|
/// Bitwise complement of a 32-bit word.
fn lnot32(x : UInt64) -> UInt64 {
  x ^ M32
}

///|
fn hex_char(n : Int32) -> Char {
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

///|
/// Lowercase hex SHA-256 digest of `data` (64 characters).
pub fn sha256_hex(data : Bytes) -> String {
  let k = sha256_k()
  let h : Array[UInt64] = [
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL, 0x510e527fUL, 0x9b05688cUL,
    0x1f83d9abUL, 0x5be0cd19UL,
  ]
  let n = data.length()
  // Message length in bits, as a 64-bit value.
  let bitlen = n.to_int64() * 8
  // Build the padded message: data || 0x80 || zeros || 64-bit big-endian length.
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
  let mut j = 0
  while j < 8 {
    msg.push(((bitlen >> (56 - j * 8)) & 0xffL).to_byte())
    j = j + 1
  }
  // Compress each 64-byte block.
  let mut off = 0
  while off < msg.length() {
    let w : Array[UInt64] = []
    let mut t = 0
    while t < 16 {
      let b0 = msg[off + t * 4].to_uint64()
      let b1 = msg[off + t * 4 + 1].to_uint64()
      let b2 = msg[off + t * 4 + 2].to_uint64()
      let b3 = msg[off + t * 4 + 3].to_uint64()
      w.push((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
      t = t + 1
    }
    t = 16
    while t < 64 {
      let s0 = rotr32(w[t - 15], 7) ^
        rotr32(w[t - 15], 18) ^
        shr32(w[t - 15], 3)
      let s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ shr32(w[t - 2], 10)
      w.push(add32(add32(w[t - 16], s0), add32(w[t - 7], s1)))
      t = t + 1
    }
    let mut a = h[0]
    let mut b = h[1]
    let mut c = h[2]
    let mut d = h[3]
    let mut e = h[4]
    let mut f = h[5]
    let mut g = h[6]
    let mut hh = h[7]
    t = 0
    while t < 64 {
      let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
      let ch = (e & f) ^ (lnot32(e) & g)
      let t1 = add32(add32(add32(hh, s1), add32(ch, k[t])), w[t])
      let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let t2 = add32(s0, maj)
      hh = g
      g = f
      f = e
      e = add32(d, t1)
      d = c
      c = b
      b = a
      a = add32(t1, t2)
      t = t + 1
    }
    h[0] = add32(h[0], a)
    h[1] = add32(h[1], b)
    h[2] = add32(h[2], c)
    h[3] = add32(h[3], d)
    h[4] = add32(h[4], e)
    h[5] = add32(h[5], f)
    h[6] = add32(h[6], g)
    h[7] = add32(h[7], hh)
    off = off + 64
  }
  let mut out = ""
  let mut idx = 0
  while idx < 8 {
    let v = h[idx]
    let mut s = 4
    while s > 0 {
      let byte = ((v >> ((s - 1) * 8)) & 0xffUL).to_int()
      out = out +
        String::make(1, hex_char(byte >> 4)) +
        String::make(1, hex_char(byte & 0x0f))
      s = s - 1
    }
    idx = idx + 1
  }
  out
}

///|
/// Lowercase hex SHA-256 of the UTF-8 encoding of `s`.
pub fn sha256_hex_of_string(s : String) -> String {
  sha256_hex(string_to_utf8_bytes(s))
}
