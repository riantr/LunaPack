// X25519 (RFC 7748) on top of the big integers of the core.
//
// The toolchain has no curve arithmetic, so the Montgomery ladder of
// RFC 7748 section 5 is written here. The field arithmetic uses the big
// integers of `moonbitlang/core/bigint`, which is a package of the core and
// not a dependency of its own.
//
// NOTE: the big integers of the core are not constant time, so a caller
// that needs that has to look elsewhere. The control flow of the ladder does
// not depend on the secret either: the conditional swap is done with
// arithmetic and not with a branch.

///|
/// The prime of the field: 2^255 - 19.
fn field_prime() -> BigInt {
  (BigInt::from_int(1) << 255) - BigInt::from_int(19)
}

///|
/// The remainder of `value` in the field, always between 0 and p - 1.
fn fmod(value : BigInt, p : BigInt) -> BigInt {
  let r = value.mod(p)
  if r.compare_int(0) < 0 {
    r + p
  } else {
    r
  }
}

///|
/// The big integer of the little-endian bytes `data`.
fn big_from_le(data : Bytes) -> BigInt {
  let reversed = FixedArray::make(data.length(), b'\x00')
  let mut i = 0
  while i < data.length() {
    reversed[i] = data.at(data.length() - 1 - i)
    i = i + 1
  }
  BigInt::from_octets(Bytes::from_array(reversed[:]))
}

///|
/// The little-endian bytes of `value`, exactly `length` of them.
fn big_to_le(value : BigInt, length : Int32) -> Bytes {
  let bytes = value.to_octets(length~)
  let reversed = FixedArray::make(length, b'\x00')
  let mut i = 0
  while i < length {
    reversed[i] = bytes.at(length - 1 - i)
    i = i + 1
  }
  Bytes::from_array(reversed[:])
}

///|
/// `a` when the bit is zero and `b` when it is one.
///
/// The choice is made with arithmetic and not with a branch, so the control
/// flow does not depend on the secret.
fn select(a : BigInt, b : BigInt, bit : BigInt) -> BigInt {
  a + bit * (b - a)
}

///|
/// The clamped scalar of RFC 7748 section 5.
fn clamp_scalar(scalar : Bytes) -> BigInt {
  let bytes = FixedArray::make(32, b'\x00')
  let mut i = 0
  while i < 32 {
    bytes[i] = if i < scalar.length() { scalar.at(i) } else { b'\x00' }
    i = i + 1
  }
  // The three lowest bits of the first byte are cleared, the highest bit of
  // the last byte is cleared and the second highest is set.
  bytes[0] = (bytes[0].to_int() & 248).to_byte()
  bytes[31] = (bytes[31].to_int() & 127).to_byte()
  bytes[31] = (bytes[31].to_int() | 64).to_byte()
  big_from_le(Bytes::from_array(bytes[:]))
}

///|
/// The u-coordinate of `point`.
///
/// The most significant bit is masked, as RFC 7748 section 5 requires for
/// X25519.
fn decode_point(point : Bytes) -> BigInt {
  let bytes = FixedArray::make(32, b'\x00')
  let mut i = 0
  while i < 32 {
    bytes[i] = if i < point.length() { point.at(i) } else { b'\x00' }
    i = i + 1
  }
  bytes[31] = (bytes[31].to_int() & 127).to_byte()
  big_from_le(Bytes::from_array(bytes[:]))
}

///|
/// The X25519 function of RFC 7748: the shared secret of the private key
/// `scalar` and the public key `point`.
///
/// Returns 32 bytes. A shared secret of all zeros means that the peer sent
/// a point of a small order, which the caller has to refuse.
pub fn x25519(scalar : Bytes, point : Bytes) -> Bytes {
  let p = field_prime()
  let k = clamp_scalar(scalar)
  let u = decode_point(point)
  // The Montgomery ladder.
  let x1 = u
  let mut x2 = BigInt::from_int(1)
  let mut z2 = BigInt::from_int(0)
  let mut x3 = u
  let mut z3 = BigInt::from_int(1)
  let mut swap = BigInt::from_int(0)
  let mut t = 254
  while t >= 0 {
    let bit = k.shr(t).land(BigInt::from_int(1))
    swap = swap.lxor(bit)
    let new_x2 = select(x2, x3, swap)
    let new_x3 = select(x3, x2, swap)
    x2 = new_x2
    x3 = new_x3
    let new_z2 = select(z2, z3, swap)
    let new_z3 = select(z3, z2, swap)
    z2 = new_z2
    z3 = new_z3
    swap = bit
    let a = fmod(x2 + z2, p)
    let aa = fmod(a * a, p)
    let b = fmod(x2 - z2, p)
    let bb = fmod(b * b, p)
    let e = fmod(aa - bb, p)
    let c = fmod(x3 + z3, p)
    let d = fmod(x3 - z3, p)
    let da = fmod(d * a, p)
    let cb = fmod(c * b, p)
    let sum = fmod(da + cb, p)
    let diff = fmod(da - cb, p)
    x3 = fmod(sum * sum, p)
    z3 = fmod(x1 * fmod(diff * diff, p), p)
    x2 = fmod(aa * bb, p)
    z2 = fmod(e * fmod(aa + BigInt::from_int(121665) * e, p), p)
    t = t - 1
  }
  let final_x2 = select(x2, x3, swap)
  let final_z2 = select(z2, z3, swap)
  // The inverse of z2 is z2^(p-2), because the field is a prime.
  let inverse = final_z2.pow(p - BigInt::from_int(2), modulus=p)
  let result = fmod(final_x2 * inverse, p)
  big_to_le(result, 32)
}

///|
/// The public key of the private key `scalar`: the point with the base point
/// of the curve.
pub fn x25519_public_key(scalar : Bytes) -> Bytes {
  let base = FixedArray::make(32, b'\x00')
  base[0] = b'\x09'
  x25519(scalar, Bytes::from_array(base[:]))
}

///|
/// Is the shared secret all zeros?
///
/// A shared secret of all zeros means that the peer sent a point of a small
/// order, which RFC 7748 section 6.1 says to refuse.
pub fn is_all_zero(data : Bytes) -> Bool {
  let mut i = 0
  while i < data.length() {
    if data.at(i).to_int() != 0 {
      return false
    }
    i = i + 1
  }
  true
}
