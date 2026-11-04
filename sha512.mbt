// SHA-512 (FIPS 180-4) and HMAC-SHA512 (RFC 2104), in pure MoonBit.
//
// The toolchain ships no SHA-512, and the key derivation of the encryption
// needs one: HKDF-SHA512 is what RFC 5869 is written for, and the reference
// implementation this package follows uses it as well.
//
// `UInt64` has native 64-bit wrapping arithmetic in this toolchain, so the
// algorithm needs no masking the way the 32-bit SHA-256 above it does.
//
// A word of the message schedule is built from eight bytes in big-endian
// order, and the length that is appended at the end is a 128-bit big-endian
// bit count. Everything that fits into 64 bits has a zero high half, which is
// what the code below writes.

///|
/// The eighty round constants: the first 64 bits of the fractional parts of
/// the cube roots of the first eighty primes.
fn sha512_k() -> Array[UInt64] {
  [
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
  ]
}

///|
/// The eight initial state words: the first 64 bits of the fractional parts
/// of the square roots of the first eight primes.
fn sha512_h() -> Array[UInt64] {
  [
    0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
    0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
  ]
}

///|
/// Rotate a 64-bit word right by `n` bits (1 <= n <= 63).
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// The state of a SHA-512 that is fed in pieces.
pub struct Sha512 {
  /// The eight state words.
  state : Array[UInt64]
  /// The bytes that did not fill a block yet.
  pending : Array[Byte]
  /// The number of bytes that were fed in.
  mut length : UInt64
}

///|
/// A fresh SHA-512 computation.
pub fn Sha512::Sha512() -> Sha512 {
  { state: sha512_h(), pending: [], length: 0UL, }
}

///|
/// Compress one 128-byte block of `block` into `state`.
fn sha512_compress(
  state : Array[UInt64],
  block : Array[Byte],
  off : Int32,
) -> Unit {
  let k = sha512_k()
  // The message schedule: sixteen words from the block, then sixty-four more.
  let w : Array[UInt64] = Array(capacity=80)
  let mut t = 0
  while t < 16 {
    let mut v : UInt64 = 0UL
    let mut b = 0
    while b < 8 {
      v = (v << 8) | block[off + t * 8 + b].to_uint64()
      b = b + 1
    }
    w.push(v)
    t = t + 1
  }
  t = 16
  while t < 80 {
    let w15 = w[t - 15]
    let w2 = w[t - 2]
    // The small sigma is three rotations and a *shift*, not four rotations:
    // sigma0(x) = ROTR1 ^ ROTR8 ^ SHR7, sigma1(x) = ROTR19 ^ ROTR61 ^ SHR6.
    let s0 = rotr64(w15, 1) ^ rotr64(w15, 8) ^ (w15 >> 7)
    let s1 = rotr64(w2, 19) ^ rotr64(w2, 61) ^ (w2 >> 6)
    w.push(w[t - 16] + s0 + w[t - 7] + s1)
    t = t + 1
  }
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]
  t = 0
  while t < 80 {
    // The big sigma uses three rotations: SIGMA0 = ROTR28 ^ ROTR34 ^ ROTR39,
    // SIGMA1 = ROTR14 ^ ROTR18 ^ ROTR41.
    let big0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
    let big1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
    let ch = (e & f) ^ ((e ^ 0xffffffffffffffffUL) & g)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let t1 = h + big1 + ch + k[t] + w[t]
    let t2 = big0 + maj
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
    t = t + 1
  }
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

///|
/// Feed `data` into the computation.
pub fn Sha512::update(self : Sha512, data : Bytes) -> Unit {
  let n = data.length()
  self.length = self.length + n.to_uint64()
  let mut i = 0
  while i < n {
    self.pending.push(data.at(i))
    i = i + 1
    if self.pending.length() == 128 {
      sha512_compress(self.state, self.pending, 0)
      self.pending.clear()
    }
  }
}

///|
/// The digest of everything that was fed in: 64 raw bytes.
pub fn Sha512::finish(self : Sha512) -> Bytes {
  let bitlen = self.length * 8UL
  // The padded message: the pending bytes, then 0x80, then zeros, then the
  // length as a 128-bit big-endian bit count. The high half is zero for
  // everything that fits into 64 bits.
  self.pending.push(b'\x80')
  while self.pending.length() % 128 != 112 {
    self.pending.push(b'\x00')
  }
  let mut j = 0
  while j < 8 {
    self.pending.push(b'\x00')
    j = j + 1
  }
  j = 7
  while j >= 0 {
    self.pending.push(((bitlen >> (j * 8)) & 0xffUL).to_byte())
    j = j - 1
  }
  let mut off = 0
  while off < self.pending.length() {
    sha512_compress(self.state, self.pending, off)
    off = off + 128
  }
  // The digest is the eight state words in big-endian order.
  let out = []
  for v in self.state {
    let mut b = 7
    while b >= 0 {
      out.push(((v >> (b * 8)) & 0xffUL).to_byte())
      b = b - 1
    }
  }
  Bytes::from_array(out[:])
}

///|
/// The SHA-512 digest of `data`: 64 raw bytes.
pub fn sha512(data : Bytes) -> Bytes {
  let digest = Sha512::Sha512()
  digest.update(data)
  digest.finish()
}

///|
/// The SHA-512 digest of `data`, lowercase hex (128 characters).
pub fn sha512_hex(data : Bytes) -> String {
  bytes_to_hex(sha512(data))
}

///|
/// HMAC-SHA512 (RFC 2104) of `data` under `key`: 64 raw bytes.
///
/// A key that is longer than the block size is hashed first, a key that is
/// shorter is padded with zeros.
pub fn hmac_sha512(key : Bytes, data : Bytes) -> Bytes {
  let block = 128
  let keylen = key.length()
  let shortened = if keylen > block { sha512(key) } else { key }
  let padded = FixedArray::make(block, b'\x00')
  let mut i = 0
  while i < shortened.length() {
    padded[i] = shortened.at(i)
    i = i + 1
  }
  let inner = FixedArray::make(block, b'\x00')
  let outer = FixedArray::make(block, b'\x00')
  i = 0
  while i < block {
    let b = padded[i]
    inner[i] = b ^ 0x36
    outer[i] = b ^ 0x5c
    i = i + 1
  }
  let inner_hash = Sha512::Sha512()
  inner_hash.update(Bytes::from_array(inner[:]))
  inner_hash.update(data)
  let inner_digest = inner_hash.finish()
  let outer_hash = Sha512::Sha512()
  outer_hash.update(Bytes::from_array(outer[:]))
  outer_hash.update(inner_digest)
  outer_hash.finish()
}
