// HKDF-SHA512 (RFC 5869) and PBKDF2-HMAC-SHA512 (RFC 8018).
//
// HKDF turns a secret of high entropy into a key of any length; PBKDF2
// turns a passphrase into a key, at the cost of a deliberate slowness that
// makes a dictionary attack expensive.
//
// The reference implementation this package follows uses HKDF-SHA512 for the
// key of a container and PBKDF2 for the passphrase that protects a secret
// key on disk, so both are here.

///|
/// The length of a SHA-512 digest.
pub const SHA512_BYTES : Int32 = 64

///|
/// The HKDF extract step of RFC 5869: PRK = HMAC-Hash(salt, IKM).
pub fn hkdf_extract_sha512(salt : Bytes, ikm : Bytes) -> Bytes {
  hmac_sha512(salt, ikm)
}

///|
/// The HKDF expand step of RFC 5869: OKM = T(1) || T(2) || ...
///
/// T(0) is empty and T(i) = HMAC-Hash(PRK, T(i-1) || info || i), where the
/// counter is a single byte.
pub fn hkdf_expand_sha512(prk : Bytes, info : Bytes, length : Int32) -> Bytes {
  let out = FixedArray::make(length, b'\x00')
  let mut written = 0
  let mut counter = 1
  let mut previous = zero_bytes(0)
  while written < length {
    let block_input = bytes_concat(
      bytes_concat(previous, info),
      Bytes::from_array([counter.to_byte()]),
    )
    let block = hmac_sha512(prk, block_input)
    let take = if length - written < SHA512_BYTES {
      length - written
    } else {
      SHA512_BYTES
    }
    let mut i = 0
    while i < take {
      out[written + i] = block.at(i)
      i = i + 1
    }
    written = written + take
    previous = block
    counter = counter + 1
  }
  Bytes::from_array(out[:])
}

///|
/// HKDF-SHA512: the extract step followed by the expand step.
///
/// A salt of zero length is the same as no salt at all: RFC 5869 says that
/// a string of HashLen zeros is used then.
pub fn hkdf_sha512(
  ikm : Bytes,
  salt : Bytes,
  info : Bytes,
  length : Int32,
) -> Bytes {
  let real_salt = if salt.length() == 0 {
    zero_bytes(SHA512_BYTES)
  } else {
    salt
  }
  let prk = hkdf_extract_sha512(real_salt, ikm)
  hkdf_expand_sha512(prk, info, length)
}

///|
/// PBKDF2-HMAC-SHA512 (RFC 8018): a key of `length` bytes from a passphrase.
///
/// The result is the concatenation of T(1) || T(2) || ..., where
/// T(i) = U(1) xor U(2) xor ... xor U(iterations) and
/// U(1) = HMAC(password, salt || INT_BE32(i)) and U(j) = HMAC(password, U(j-1)).
pub fn pbkdf2_sha512(
  password : Bytes,
  salt : Bytes,
  iterations : Int32,
  length : Int32,
) -> Bytes {
  let out = FixedArray::make(length, b'\x00')
  let mut written = 0
  let mut block_index = 1
  while written < length {
    let counter = Bytes::from_array([
      ((block_index >> 24) & 0xff).to_byte(),
      ((block_index >> 16) & 0xff).to_byte(),
      ((block_index >> 8) & 0xff).to_byte(),
      (block_index & 0xff).to_byte(),
    ])
    let mut u = hmac_sha512(password, bytes_concat(salt, counter))
    let acc = FixedArray::make(SHA512_BYTES, b'\x00')
    let mut i = 0
    while i < SHA512_BYTES {
      acc[i] = u.at(i)
      i = i + 1
    }
    let mut iteration = 1
    while iteration < iterations {
      u = hmac_sha512(password, u)
      i = 0
      while i < SHA512_BYTES {
        acc[i] = (acc[i].to_int() ^ u.at(i).to_int()).to_byte()
        i = i + 1
      }
      iteration = iteration + 1
    }
    let take = if length - written < SHA512_BYTES {
      length - written
    } else {
      SHA512_BYTES
    }
    i = 0
    while i < take {
      out[written + i] = acc[i]
      i = i + 1
    }
    written = written + take
    block_index = block_index + 1
  }
  Bytes::from_array(out[:])
}
