// ChaCha20 (RFC 8439), Poly1305 (RFC 8439) and the authenticated
// encryption that the two make together (section 2.8 of the same document).
//
// The toolchain ships neither, so both are written here. The reference
// implementation this package follows seals a container with
// ChaCha20-Poly1305, so the same construction is used.

///|
/// "expand 32-byte k", the four constants of the ChaCha state.
const CHACHA_C0 : UInt32 = 0x61707865U

///|
const CHACHA_C1 : UInt32 = 0x3320646eU

///|
const CHACHA_C2 : UInt32 = 0x79622d32U

///|
const CHACHA_C3 : UInt32 = 0x6b206574U

///|
/// Rotate a 32-bit word left by `n` bits.
fn rotl32(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
/// The 32-bit word at `at`, read little-endian.
fn le32(data : Bytes, at : Int32) -> UInt32 {
  let mut v : UInt32 = 0U
  let mut i = 0
  while i < 4 {
    v = v | (data.at(at + i).to_uint() << (i * 8))
    i = i + 1
  }
  v
}

///|
/// One round of the ChaCha state.
fn quarter_round(
  s : FixedArray[UInt32],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
) -> Unit {
  s[a] = s[a] + s[b]
  s[d] = rotl32(s[d] ^ s[a], 16)
  s[c] = s[c] + s[d]
  s[b] = rotl32(s[b] ^ s[c], 12)
  s[a] = s[a] + s[b]
  s[d] = rotl32(s[d] ^ s[a], 8)
  s[c] = s[c] + s[d]
  s[b] = rotl32(s[b] ^ s[c], 7)
}

///|
/// The 64-byte keystream block of ChaCha20.
///
/// The key is 32 bytes and the nonce is 12 bytes, which is the shape the
/// authenticated encryption of RFC 8439 uses.
fn chacha20_block(key : Bytes, counter : UInt32, nonce : Bytes) -> Bytes {
  let state = FixedArray::make(16, 0U)
  state[0] = CHACHA_C0
  state[1] = CHACHA_C1
  state[2] = CHACHA_C2
  state[3] = CHACHA_C3
  let mut i = 0
  while i < 8 {
    state[4 + i] = le32(key, i * 4)
    i = i + 1
  }
  state[12] = counter
  state[13] = le32(nonce, 0)
  state[14] = le32(nonce, 4)
  state[15] = le32(nonce, 8)
  let w = FixedArray::make(16, 0U)
  i = 0
  while i < 16 {
    w[i] = state[i]
    i = i + 1
  }
  // Twenty rounds, ten of them double.
  let mut round = 0
  while round < 10 {
    quarter_round(w, 0, 4, 8, 12)
    quarter_round(w, 1, 5, 9, 13)
    quarter_round(w, 2, 6, 10, 14)
    quarter_round(w, 3, 7, 11, 15)
    quarter_round(w, 0, 5, 10, 15)
    quarter_round(w, 1, 6, 11, 12)
    quarter_round(w, 2, 7, 8, 13)
    quarter_round(w, 3, 4, 9, 14)
    round = round + 1
  }
  let out = FixedArray::make(64, b'\x00')
  i = 0
  while i < 16 {
    let v = w[i] + state[i]
    out[i * 4] = (v & 0xffU).to_byte()
    out[i * 4 + 1] = ((v >> 8) & 0xffU).to_byte()
    out[i * 4 + 2] = ((v >> 16) & 0xffU).to_byte()
    out[i * 4 + 3] = ((v >> 24) & 0xffU).to_byte()
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// The ChaCha20 encryption of `data`: the keystream of the key and the nonce,
/// starting at `counter`, exclusive-ored with the data.
pub fn chacha20_xor(
  key : Bytes,
  nonce : Bytes,
  counter : UInt32,
  data : BytesView,
) -> Bytes {
  let n = data.length()
  let out = FixedArray::make(n, b'\x00')
  let mut at = 0
  let mut c = counter
  while at < n {
    let block = chacha20_block(key, c, nonce)
    let rest = n - at
    let take = if rest < 64 { rest } else { 64 }
    let mut i = 0
    while i < take {
      out[at + i] = (data.at(at + i).to_int() ^ block.at(i).to_int()).to_byte()
      i = i + 1
    }
    at = at + take
    c = c + 1U
  }
  Bytes::from_array(out[:])
}

///|
/// Poly1305 (RFC 8439), the one-time authenticator.
///
/// The accumulator is kept as five limbs of 26 bits, which is the shape the
/// reference implementation uses.
pub struct Poly1305 {
  /// The key, clamped and split into limbs.
  r0 : UInt64
  r1 : UInt64
  r2 : UInt64
  r3 : UInt64
  r4 : UInt64
  /// The second half of the key, added to the result at the end.
  s0 : UInt64
  s1 : UInt64
  s2 : UInt64
  s3 : UInt64
  /// The accumulator.
  mut h0 : UInt64
  mut h1 : UInt64
  mut h2 : UInt64
  mut h3 : UInt64
  mut h4 : UInt64
  /// The bytes of the block that is not full yet.
  buffer : Array[Byte]
}

///|
/// A fresh Poly1305 computation under the 32-byte `key`.
pub fn Poly1305::Poly1305(key : Bytes) -> Poly1305 {
  let t0 = le32(key, 0).to_uint64()
  let t1 = le32(key, 4).to_uint64()
  let t2 = le32(key, 8).to_uint64()
  let t3 = le32(key, 12).to_uint64()
  {
    // The key is clamped: the four bits that are not used are cleared and
    // the two top and the two bottom bits of the other ones are cleared too.
    r0: t0 & 0x3ffffffUL,
    r1: ((t0 >> 26) | (t1 << 6)) & 0x3ffff03UL,
    r2: ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffUL,
    r3: ((t2 >> 14) | (t3 << 18)) & 0x3f03fffUL,
    r4: (t3 >> 8) & 0x00fffffUL,
    s0: le32(key, 16).to_uint64(),
    s1: le32(key, 20).to_uint64(),
    s2: le32(key, 24).to_uint64(),
    s3: le32(key, 28).to_uint64(),
    h0: 0UL,
    h1: 0UL,
    h2: 0UL,
    h3: 0UL,
    h4: 0UL,
    buffer: [],
  }
}

///|
/// Multiply the accumulator by the key and add `block` to it.
///
/// `hibit` is the high bit that a full block carries; the last block of a
/// message carries a one in its padding instead.
fn Poly1305::block(
  self : Poly1305,
  block : FixedArray[Byte],
  hibit : UInt64,
) -> Unit {
  let t0 = le32(Bytes::from_array(block[:]), 0).to_uint64()
  let t1 = le32(Bytes::from_array(block[:]), 4).to_uint64()
  let t2 = le32(Bytes::from_array(block[:]), 8).to_uint64()
  let t3 = le32(Bytes::from_array(block[:]), 12).to_uint64()
  self.h0 = self.h0 + (t0 & 0x3ffffffUL)
  self.h1 = self.h1 + (((t0 >> 26) | (t1 << 6)) & 0x3ffffffUL)
  self.h2 = self.h2 + (((t1 >> 20) | (t2 << 12)) & 0x3ffffffUL)
  self.h3 = self.h3 + (((t2 >> 14) | (t3 << 18)) & 0x3ffffffUL)
  self.h4 = self.h4 + ((t3 >> 8) | hibit)
  // The five times of the key, for the products that need it.
  let s1 = self.r1 * 5UL
  let s2 = self.r2 * 5UL
  let s3 = self.r3 * 5UL
  let s4 = self.r4 * 5UL
  let d0 = self.h0 * self.r0 +
    self.h1 * s4 +
    self.h2 * s3 +
    self.h3 * s2 +
    self.h4 * s1
  let d1 = self.h0 * self.r1 +
    self.h1 * self.r0 +
    self.h2 * s4 +
    self.h3 * s3 +
    self.h4 * s2
  let d2 = self.h0 * self.r2 +
    self.h1 * self.r1 +
    self.h2 * self.r0 +
    self.h3 * s4 +
    self.h4 * s3
  let d3 = self.h0 * self.r3 +
    self.h1 * self.r2 +
    self.h2 * self.r1 +
    self.h3 * self.r0 +
    self.h4 * s4
  let d4 = self.h0 * self.r4 +
    self.h1 * self.r3 +
    self.h2 * self.r2 +
    self.h3 * self.r1 +
    self.h4 * self.r0
  // The carries of the 26 bit limbs.
  let mut c = d0 >> 26
  self.h0 = d0 & 0x3ffffffUL
  let d1 = d1 + c
  c = d1 >> 26
  self.h1 = d1 & 0x3ffffffUL
  let d2 = d2 + c
  c = d2 >> 26
  self.h2 = d2 & 0x3ffffffUL
  let d3 = d3 + c
  c = d3 >> 26
  self.h3 = d3 & 0x3ffffffUL
  let d4 = d4 + c
  c = d4 >> 26
  self.h4 = d4 & 0x3ffffffUL
  self.h0 = self.h0 + c * 5UL
  c = self.h0 >> 26
  self.h0 = self.h0 & 0x3ffffffUL
  self.h1 = self.h1 + c
}

///|
/// Feed `data` into the computation.
pub fn Poly1305::update(self : Poly1305, data : BytesView) -> Unit {
  let n = data.length()
  let mut at = 0
  while at < n {
    let room = 16 - self.buffer.length()
    let rest = n - at
    let take = if rest < room { rest } else { room }
    let mut i = 0
    while i < take {
      self.buffer.push(data.at(at + i))
      i = i + 1
    }
    at = at + take
    if self.buffer.length() == 16 {
      let block = FixedArray::make(16, b'\x00')
      let mut k = 0
      while k < 16 {
        block[k] = self.buffer[k]
        k = k + 1
      }
      self.buffer.clear()
      self.block(block, 1UL << 24)
    }
  }
}

///|
/// The tag of everything that was fed in: 16 bytes.
pub fn Poly1305::finish(self : Poly1305) -> Bytes {
  // The last block, with the one in its padding.
  if self.buffer.length() > 0 {
    let n = self.buffer.length()
    let block = FixedArray::make(16, b'\x00')
    let mut i = 0
    while i < n {
      block[i] = self.buffer[i]
      i = i + 1
    }
    block[n] = b'\x01'
    self.buffer.clear()
    self.block(block, 0UL)
  }
  // Carry the accumulator completely.
  let mut c = self.h1 >> 26
  self.h1 = self.h1 & 0x3ffffffUL
  self.h2 = self.h2 + c
  c = self.h2 >> 26
  self.h2 = self.h2 & 0x3ffffffUL
  self.h3 = self.h3 + c
  c = self.h3 >> 26
  self.h3 = self.h3 & 0x3ffffffUL
  self.h4 = self.h4 + c
  c = self.h4 >> 26
  self.h4 = self.h4 & 0x3ffffffUL
  self.h0 = self.h0 + c * 5UL
  c = self.h0 >> 26
  self.h0 = self.h0 & 0x3ffffffUL
  self.h1 = self.h1 + c
  // The candidate that is the accumulator reduced by 2^130 - 5.
  let mut g0 = self.h0 + 5UL
  c = g0 >> 26
  g0 = g0 & 0x3ffffffUL
  let mut g1 = self.h1 + c
  c = g1 >> 26
  g1 = g1 & 0x3ffffffUL
  let mut g2 = self.h2 + c
  c = g2 >> 26
  g2 = g2 & 0x3ffffffUL
  let mut g3 = self.h3 + c
  c = g3 >> 26
  g3 = g3 & 0x3ffffffUL
  let g4 = self.h4 + c - (1UL << 26)
  // The candidate is the right one when the accumulator was not smaller than
  // 2^130 - 5, which is what the top bit of g4 tells.
  let mask = (g4 >> 63) - 1UL
  let g0 = g0 & mask
  let g1 = g1 & mask
  let g2 = g2 & mask
  let g3 = g3 & mask
  let g4 = g4 & mask
  let other = mask ^ 0xffffffffffffffffUL
  let a0 = (self.h0 & other) | g0
  let a1 = (self.h1 & other) | g1
  let a2 = (self.h2 & other) | g2
  let a3 = (self.h3 & other) | g3
  let a4 = (self.h4 & other) | (g4 & mask)
  // The limbs are recombined into the 128-bit value, which is the number
  // the second half of the key is added to.
  let mut h0 = (a0 | (a1 << 26)) & 0xffffffffUL
  let mut h1 = ((a1 >> 6) | (a2 << 20)) & 0xffffffffUL
  let mut h2 = ((a2 >> 12) | (a3 << 14)) & 0xffffffffUL
  let mut h3 = ((a3 >> 18) | (a4 << 8)) & 0xffffffffUL
  // Add the second half of the key.
  let mut f = h0 + self.s0
  h0 = f & 0xffffffffUL
  f = h1 + self.s1 + (f >> 32)
  h1 = f & 0xffffffffUL
  f = h2 + self.s2 + (f >> 32)
  h2 = f & 0xffffffffUL
  f = h3 + self.s3 + (f >> 32)
  h3 = f & 0xffffffffUL
  let out = FixedArray::make(16, b'\x00')
  out[0] = (h0 & 0xffUL).to_byte()
  out[1] = ((h0 >> 8) & 0xffUL).to_byte()
  out[2] = ((h0 >> 16) & 0xffUL).to_byte()
  out[3] = ((h0 >> 24) & 0xffUL).to_byte()
  out[4] = (h1 & 0xffUL).to_byte()
  out[5] = ((h1 >> 8) & 0xffUL).to_byte()
  out[6] = ((h1 >> 16) & 0xffUL).to_byte()
  out[7] = ((h1 >> 24) & 0xffUL).to_byte()
  out[8] = (h2 & 0xffUL).to_byte()
  out[9] = ((h2 >> 8) & 0xffUL).to_byte()
  out[10] = ((h2 >> 16) & 0xffUL).to_byte()
  out[11] = ((h2 >> 24) & 0xffUL).to_byte()
  out[12] = (h3 & 0xffUL).to_byte()
  out[13] = ((h3 >> 8) & 0xffUL).to_byte()
  out[14] = ((h3 >> 16) & 0xffUL).to_byte()
  out[15] = ((h3 >> 24) & 0xffUL).to_byte()
  Bytes::from_array(out[:])
}

///|
/// The tag of `data` under the 32-byte `key`.
pub fn poly1305(key : Bytes, data : BytesView) -> Bytes {
  let mac = Poly1305::Poly1305(key)
  mac.update(data)
  mac.finish()
}

///|
/// Seal `plaintext` with ChaCha20-Poly1305.
///
/// The additional data is authenticated but not encrypted. The result is the
/// ciphertext followed by the 16-byte tag.
pub fn chacha20poly1305_seal(
  key : Bytes,
  nonce : Bytes,
  plaintext : BytesView,
  aad : BytesView,
) -> Bytes {
  // The one-time key of the authenticator is the first 32 bytes of the
  // keystream with the counter at zero.
  let one_time = chacha20_xor(key, nonce, 0U, zero_bytes(32))
  let ciphertext = chacha20_xor(key, nonce, 1U, plaintext)
  let mac = Poly1305::Poly1305(one_time)
  mac.update(aad)
  mac.update(zero_bytes((16 - aad.length() % 16) % 16))
  mac.update(ciphertext)
  mac.update(zero_bytes((16 - ciphertext.length() % 16) % 16))
  mac.update(le64_of(aad.length()))
  mac.update(le64_of(ciphertext.length()))
  bytes_concat(ciphertext, mac.finish())
}

///|
/// Open a ciphertext that was sealed with ChaCha20-Poly1305.
///
/// The sealed data is the ciphertext followed by the 16-byte tag. Returns
/// None when the tag does not match, which means that the data was damaged
/// or that the key is wrong.
pub fn chacha20poly1305_open(
  key : Bytes,
  nonce : Bytes,
  sealed_data : BytesView,
  aad : BytesView,
) -> Bytes? {
  let n = sealed_data.length()
  if n < TAG_BYTES {
    return None
  }
  let split = n - TAG_BYTES
  let ciphertext = sealed_data.clamped_view(end=split)
  let one_time = chacha20_xor(key, nonce, 0U, zero_bytes(32))
  let mac = Poly1305::Poly1305(one_time)
  mac.update(aad)
  mac.update(zero_bytes((16 - aad.length() % 16) % 16))
  mac.update(ciphertext)
  mac.update(zero_bytes((16 - split % 16) % 16))
  mac.update(le64_of(aad.length()))
  mac.update(le64_of(split))
  // The tag is the last 16 bytes of the sealed data.
  let expected = mac.finish()
  let mut diff = 0
  let mut i = 0
  while i < TAG_BYTES {
    diff = diff | (expected.at(i).to_int() ^ sealed_data.at(split + i).to_int())
    i = i + 1
  }
  if diff != 0 {
    return None
  }
  Some(chacha20_xor(key, nonce, 1U, ciphertext))
}

///|
/// The length of the tag of the authenticated encryption.
pub const TAG_BYTES : Int32 = 16

///|
/// A 64-bit number as eight little-endian bytes.
fn le64_of(value : Int32) -> Bytes {
  let v = value.to_uint64()
  let out = FixedArray::make(8, b'\x00')
  let mut i = 0
  while i < 8 {
    out[i] = ((v >> (i * 8)) & 0xffUL).to_byte()
    i = i + 1
  }
  Bytes::from_array(out[:])
}
