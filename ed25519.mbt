// Ed25519 (RFC 8032) on top of the big integers of the core.
//
// The signature is the verification material that a host publishes next to a
// package: the host holds the secret key, everybody else holds the public
// key, and the signature says that the package is the one the host
// published. It is the layer that no self-check of the package can replace,
// because the material is with the host and not with the package.
//
// The implementation follows RFC 8032: the points of the curve are in
// extended coordinates, the scalars are reduced modulo the order of the
// group, and the hash is SHA-512.
//
// NOTE: the big integers of the core are not constant time, so neither is
// this implementation. The loop that walks the scalar does not branch on the
// value of the secret in a way a caller can turn into a timing signal, but
// the arithmetic behind it is not constant time either.

///|
/// A point of the curve in extended coordinates: (X, Y, Z, T).
///
/// The point is (X/Z, Y/Z) and T is X*Y/Z. The extra coordinate is what
/// makes the addition formulas of RFC 8032 work without an inversion.
type EdPoint = (BigInt, BigInt, BigInt, BigInt)

///|
/// The prime of the field: 2^255 - 19.
fn ed_p() -> BigInt {
  (BigInt::from_int(1) << 255) - BigInt::from_int(19)
}

///|
/// The order of the group: 2^252 + 27742317777372353535851937790883648493.
fn ed_l() -> BigInt {
  (BigInt::from_int(1) << 252) +
  BigInt::from_string("27742317777372353535851937790883648493")
}

///|
/// The remainder of `value` modulo `m`, always between 0 and m - 1.
fn ed_mod(value : BigInt, m : BigInt) -> BigInt {
  let r = value.mod(m)
  if r.compare_int(0) < 0 {
    r + m
  } else {
    r
  }
}

///|
/// The product of two field elements.
fn ed_fmul(a : BigInt, b : BigInt, p : BigInt) -> BigInt {
  ed_mod(a * b, p)
}

///|
/// A power in the field.
fn ed_fpow(a : BigInt, e : BigInt, p : BigInt) -> BigInt {
  a.pow(e, modulus=p)
}

///|
/// The inverse of a field element.
fn ed_finv(a : BigInt, p : BigInt) -> BigInt {
  a.pow(p - BigInt::from_int(2), modulus=p)
}

///|
/// The bytes from `start` up to `end`, copied into a new buffer.
fn ed_slice(data : Bytes, start : Int32, end : Int32) -> Bytes {
  let out = FixedArray::make(end - start, b'\x00')
  let mut i = start
  while i < end {
    out[i - start] = data.at(i)
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// The big integer of the little-endian bytes `data`.
fn ed_big_from_le(data : Bytes) -> BigInt {
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
fn ed_big_to_le(value : BigInt, length : Int32) -> Bytes {
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
/// The constant d of the curve, and twice of it, which the addition formula
/// needs.
fn ed_d(p : BigInt) -> BigInt {
  ed_mod(BigInt::from_int(-121665) * ed_finv(BigInt::from_int(121666), p), p)
}

///|
/// The x coordinate of the point with the y coordinate `y`.
///
/// The sign of x is the parity of x, so `want_odd` says which of the two
/// points with that y coordinate is meant. Returns None when y is not the y
/// coordinate of a point of the curve.
fn ed_recover_x(y : BigInt, want_odd : Bool, p : BigInt) -> BigInt? {
  let y2 = ed_fmul(y, y, p)
  let u = ed_mod(y2 - BigInt::from_int(1), p)
  let v = ed_mod(ed_fmul(ed_d(p), y2, p) + BigInt::from_int(1), p)
  let v3 = ed_fmul(ed_fmul(v, v, p), v, p)
  let v7 = ed_fmul(ed_fmul(v3, v3, p), v, p)
  // x = u * v^3 * (u * v^7)^((p-5)/8)
  let e = (p - BigInt::from_int(5)) / BigInt::from_int(8)
  let mut x = ed_fmul(ed_fmul(u, v3, p), ed_fpow(ed_fmul(u, v7, p), e, p), p)
  if ed_fmul(v, ed_fmul(x, x, p), p).compare(u) != 0 {
    // The candidate is not a root, so it is multiplied by the square root
    // of -1 and tried again.
    let sqrt_m1 = ed_fpow(
      BigInt::from_int(2),
      (p - BigInt::from_int(1)) / BigInt::from_int(4),
      p,
    )
    x = ed_fmul(x, sqrt_m1, p)
    if ed_fmul(v, ed_fmul(x, x, p), p).compare(u) != 0 {
      return None
    }
  }
  let is_odd = x.land(BigInt::from_int(1)).compare_int(0) != 0
  if is_odd != want_odd {
    x = p - x
  }
  Some(x)
}

///|
/// The neutral element of the group.
fn ed_identity() -> EdPoint {
  (
    BigInt::from_int(0),
    BigInt::from_int(1),
    BigInt::from_int(1),
    BigInt::from_int(0),
  )
}

///|
/// The sum of two points, in extended coordinates.
fn ed_add(p1 : EdPoint, p2 : EdPoint, p : BigInt, d2 : BigInt) -> EdPoint {
  let (x1, y1, z1, t1) = p1
  let (x2, y2, z2, t2) = p2
  let a = ed_fmul(ed_mod(y1 - x1, p), ed_mod(y2 - x2, p), p)
  let b = ed_fmul(ed_mod(y1 + x1, p), ed_mod(y2 + x2, p), p)
  let c = ed_fmul(ed_fmul(t1, d2, p), t2, p)
  let d = ed_fmul(ed_fmul(z1, BigInt::from_int(2), p), z2, p)
  let e = ed_mod(b - a, p)
  let f = ed_mod(d - c, p)
  let g = ed_mod(d + c, p)
  let h = ed_mod(b + a, p)
  (ed_fmul(e, f, p), ed_fmul(g, h, p), ed_fmul(f, g, p), ed_fmul(e, h, p))
}

///|
/// The double of a point, in extended coordinates.
///
/// The formulas are the affine ones of the curve written in projective
/// form: with x = X/Z, y = Y/Z and T = X*Y/Z, the double of a point is
///
///   x3 = 2*x*y / (1 + d*x^2*y^2)
///   y3 = (y^2 + x^2) / (1 - d*x^2*y^2)
///
/// which in extended coordinates becomes
///
///   X3 = 2*T*Z * (Z^2 - d*T^2)
///   Y3 = (X^2 + Y^2) * (Z^2 + d*T^2)
///   Z3 = (Z^2 + d*T^2) * (Z^2 - d*T^2)
///   T3 = 2*T*Z * (X^2 + Y^2)
///
/// The neutral element is doubled to itself, which a formula that is not
/// written this way does not always do.
fn ed_double(pt : EdPoint, p : BigInt) -> EdPoint {
  let (x1, y1, z1, t1) = pt
  let xx = ed_fmul(x1, x1, p)
  let yy = ed_fmul(y1, y1, p)
  let zz = ed_fmul(z1, z1, p)
  let tt = ed_fmul(t1, t1, p)
  let dtt = ed_fmul(ed_d(p), tt, p)
  let plus = ed_mod(zz + dtt, p)
  let minus = ed_mod(zz - dtt, p)
  let sum = ed_mod(xx + yy, p)
  let two = BigInt::from_int(2)
  let tz = ed_fmul(two, t1, p)
  let tz = ed_fmul(tz, z1, p)
  (
    ed_fmul(tz, minus, p),
    ed_fmul(sum, plus, p),
    ed_fmul(plus, minus, p),
    ed_fmul(tz, sum, p),
  )
}

///|
/// `scalar` times `point`.
///
/// The scalar is walked from its highest bit to its lowest one, and the
/// result is doubled on every step and the point is added on the steps
/// where the bit is set. That is the method that needs one doubling and at
/// most one addition per bit.
fn ed_mul(scalar : BigInt, point : EdPoint, p : BigInt, d2 : BigInt) -> EdPoint {
  let mut result = ed_identity()
  let mut i = 255
  while i >= 0 {
    result = ed_double(result, p)
    let bit = scalar.shr(i).land(BigInt::from_int(1))
    if bit.compare_int(0) != 0 {
      result = ed_add(result, point, p, d2)
    }
    i = i - 1
  }
  result
}

///|
/// The base point of the curve.
fn ed_base(p : BigInt) -> EdPoint raise {
  // The y coordinate of the base point is 4/5, and its x coordinate is the
  // even one of the two that go with it.
  let y = ed_mod(BigInt::from_int(4) * ed_finv(BigInt::from_int(5), p), p)
  match ed_recover_x(y, false, p) {
    Some(x) => (x, y, BigInt::from_int(1), ed_fmul(x, y, p))
    None => fail("the base point of the curve could not be computed")
  }
}

///|
/// The 32 bytes that encode a point.
fn ed_encode(pt : EdPoint, p : BigInt) -> Bytes {
  let (x, y, z, _t) = pt
  let zi = ed_finv(z, p)
  let xa = ed_mod(x * zi, p)
  let ya = ed_mod(y * zi, p)
  let out = FixedArray::make(32, b'\x00')
  let le = ed_big_to_le(ya, 32)
  let mut i = 0
  while i < 32 {
    out[i] = le.at(i)
    i = i + 1
  }
  // The sign of x is the highest bit of the last byte.
  if xa.land(BigInt::from_int(1)).compare_int(0) != 0 {
    out[31] = (out[31].to_int() | 0x80).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// The point that the 32 bytes encode, or None when they do not encode a
/// point of the curve.
fn ed_decode(encoded : Bytes, p : BigInt) -> EdPoint? {
  if encoded.length() != 32 {
    return None
  }
  let out = FixedArray::make(32, b'\x00')
  let mut i = 0
  while i < 32 {
    out[i] = encoded.at(i)
    i = i + 1
  }
  let want_odd = (out[31].to_int() & 0x80) != 0
  out[31] = (out[31].to_int() & 0x7f).to_byte()
  let y = ed_big_from_le(Bytes::from_array(out[:]))
  if y.compare(p) >= 0 {
    // The y coordinate is not a field element.
    return None
  }
  match ed_recover_x(y, want_odd, p) {
    Some(x) => Some((x, y, BigInt::from_int(1), ed_fmul(x, y, p)))
    None => None
  }
}

///|
/// The scalar of the secret key: the first half of its hash, clamped the way
/// RFC 8032 says.
fn ed_clamp(secret : Bytes) -> BigInt {
  let out = FixedArray::make(32, b'\x00')
  let mut i = 0
  while i < 32 {
    out[i] = if i < secret.length() { secret.at(i) } else { b'\x00' }
    i = i + 1
  }
  out[0] = (out[0].to_int() & 248).to_byte()
  out[31] = (out[31].to_int() & 127).to_byte()
  out[31] = (out[31].to_int() | 64).to_byte()
  ed_big_from_le(Bytes::from_array(out[:]))
}

///|
/// A scalar reduced modulo the order of the group.
fn ed_reduce_l(value : BigInt) -> BigInt {
  ed_mod(value, ed_l())
}

///|
/// The public key of the secret key `secret`: 32 bytes.
///
/// The secret key is 32 random bytes. They are hashed with SHA-512, the
/// lower half is clamped into the scalar and the upper half is the prefix
/// that the signature uses.
pub fn ed25519_public_key(secret : Bytes) -> Bytes raise {
  let h = sha512(secret)
  let a = ed_clamp(ed_slice(h, 0, 32))
  let p = ed_p()
  let d2 = ed_fmul(ed_d(p), BigInt::from_int(2), p)
  ed_encode(ed_mul(a, ed_base(p), p, d2), p)
}

///|
/// The signature of `message` with the secret key `secret`: 64 bytes.
///
/// The signature is the encoded point R followed by the scalar S, as
/// RFC 8032 says.
pub fn ed25519_sign(secret : Bytes, message : Bytes) -> Bytes raise {
  let h = sha512(secret)
  let a = ed_clamp(ed_slice(h, 0, 32))
  let prefix = ed_slice(h, 32, 64)
  let p = ed_p()
  let d2 = ed_fmul(ed_d(p), BigInt::from_int(2), p)
  let base = ed_base(p)
  let public = ed_encode(ed_mul(a, base, p, d2), p)
  let r = ed_reduce_l(ed_big_from_le(sha512(bytes_concat(prefix, message))))
  let rpoint = ed_encode(ed_mul(r, base, p, d2), p)
  let k = ed_reduce_l(
    ed_big_from_le(sha512(bytes_concat(bytes_concat(rpoint, public), message))),
  )
  let s = ed_reduce_l(r + k * a)
  bytes_concat(rpoint, ed_big_to_le(s, 32))
}

///|
/// Does the signature of `message` hold for the public key `public`?
///
/// The signature is checked against the group equation of RFC 8032, and a
/// signature whose scalar is not reduced is refused: such a signature is
/// one of the many ways to write the same signature, and accepting it would
/// make the signature malleable.
pub fn ed25519_verify(
  public : Bytes,
  message : Bytes,
  signature : Bytes,
) -> Bool raise {
  if public.length() != 32 || signature.length() != 64 {
    return false
  }
  let p = ed_p()
  let d2 = ed_fmul(ed_d(p), BigInt::from_int(2), p)
  let rbytes = ed_slice(signature, 0, 32)
  let s = ed_big_from_le(ed_slice(signature, 32, 64))
  if s.compare(ed_l()) >= 0 {
    return false
  }
  let a_point = match ed_decode(public, p) {
    Some(pt) => pt
    None => return false
  }
  let r_point = match ed_decode(rbytes, p) {
    Some(pt) => pt
    None => return false
  }
  let k = ed_reduce_l(
    ed_big_from_le(sha512(bytes_concat(bytes_concat(rbytes, public), message))),
  )
  // The equation of RFC 8032: [S]B = R + [k]A.
  let left = ed_mul(s, ed_base(p), p, d2)
  let right = ed_add(r_point, ed_mul(k, a_point, p, d2), p, d2)
  ed_encode(left, p) == ed_encode(right, p)
}
