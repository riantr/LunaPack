// The key files.
//
// A public key is stored as the 32 raw bytes. A secret key is stored raw as
// well, but the form that a passphrase protects is the one to use: the raw
// form leaves the long-term secret key in clear text on disk, and anyone
// who reads it can decrypt every package that was ever sealed for it.
//
// The layout of the protected form is the one of the reference
// implementation, with a magic of its own:
//
//   offset  size  field
//   0       8     magic "LUNAPK01"
//   8       1     format version (1)
//   9       1     algorithm (1)
//   10      4     iterations, big endian
//   14      16    salt
//   30      12    nonce
//   42            end of the header
//   42      32    the secret key, encrypted
//   74      16    the tag
//
// The header is the additional data of the encryption, so it cannot be
// changed without the tag failing.

///|
/// The magic of a protected key file.
pub const KEY_MAGIC : String = "LUNAPK01"

///|
/// The version of the protected key file format.
pub const KEY_VERSION : Int32 = 1

///|
/// The algorithm of the protected key file format.
pub const KEY_ALGORITHM : Int32 = 1

///|
/// The number of bytes of the salt of the protected key file.
pub const KEY_SALT_BYTES : Int32 = 16

///|
/// The number of bytes of the header of the protected key file.
pub const KEY_HEADER_BYTES : Int32 = 42

///|
/// Write the public key of a pair to `path`.
pub async fn save_public_key(path : String, public_key : Bytes) -> Unit {
  @fs.write_binary(path, public_key)
}

///|
/// Read the public key from `path`.
pub async fn load_public_key(path : String) -> Bytes {
  let data = @fs.read_binary(path)
  if data.length() != KEY_BYTES {
    fail(
      "the public key file must hold exactly " +
      KEY_BYTES.to_string() +
      " bytes, but it holds " +
      data.length().to_string(),
    )
  }
  data
}

///|
/// Write the secret key of a pair to `path`, protected by a passphrase.
pub async fn save_secret_key(
  path : String,
  secret_key : Bytes,
  passphrase : String,
) -> Unit {
  let salt = random_bytes(KEY_SALT_BYTES)
  let nonce = random_bytes(NONCE_BYTES)
  let wrapping_key = pbkdf2_sha512(
    string_to_utf8_bytes(passphrase),
    salt,
    PASSPHRASE_ITERATIONS,
    KEY_BYTES,
  )
  let header = key_header(PASSPHRASE_ITERATIONS, salt, nonce)
  let sealed_data = chacha20poly1305_seal(
    wrapping_key, nonce, secret_key, header,
  )
  @fs.write_binary(path, bytes_concat(header, sealed_data))
}

///|
/// Write the secret key of a pair to `path`, without a passphrase.
///
/// The key is in clear text on disk, so anyone who reads the file can
/// decrypt every package that was sealed for it. Use the protected form
/// unless there is a reason not to.
pub async fn save_secret_key_raw(path : String, secret_key : Bytes) -> Unit {
  @fs.write_binary(path, secret_key)
}

///|
/// The header of a protected key file.
fn key_header(iterations : Int32, salt : Bytes, nonce : Bytes) -> Bytes {
  let out = FixedArray::make(KEY_HEADER_BYTES, b'\x00')
  let magic = string_to_utf8_bytes(KEY_MAGIC)
  let mut i = 0
  while i < 8 {
    out[i] = magic.at(i)
    i = i + 1
  }
  out[8] = KEY_VERSION.to_byte()
  out[9] = KEY_ALGORITHM.to_byte()
  let n = iterations
  out[10] = ((n >> 24) & 0xff).to_byte()
  out[11] = ((n >> 16) & 0xff).to_byte()
  out[12] = ((n >> 8) & 0xff).to_byte()
  out[13] = (n & 0xff).to_byte()
  i = 0
  while i < KEY_SALT_BYTES {
    out[14 + i] = salt.at(i)
    i = i + 1
  }
  i = 0
  while i < NONCE_BYTES {
    out[30 + i] = nonce.at(i)
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// Is the file at `path` a key file that a passphrase protects?
pub async fn is_protected_key_file(path : String) -> Bool {
  if !@fs.exists(path) {
    return false
  }
  let data = @fs.read_binary(path)
  if data.length() < KEY_HEADER_BYTES {
    return false
  }
  let magic = string_to_utf8_bytes(KEY_MAGIC)
  let mut i = 0
  while i < 8 {
    if data.at(i) != magic.at(i) {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Read the secret key of a pair from `path`.
///
/// A file that a passphrase protects needs the passphrase; a file that holds
/// the raw key is read as it is, and the passphrase is not used.
pub async fn load_secret_key(path : String, passphrase : String) -> Bytes {
  if !is_protected_key_file(path) {
    let data = @fs.read_binary(path)
    if data.length() != KEY_BYTES {
      fail(
        "the secret key file must hold exactly " +
        KEY_BYTES.to_string() +
        " bytes, but it holds " +
        data.length().to_string(),
      )
    }
    return data
  }
  let file = @fs.read_binary(path)
  if file.length() < KEY_HEADER_BYTES + KEY_BYTES + 16 {
    fail("the secret key file is too short")
  }
  let magic = string_to_utf8_bytes(KEY_MAGIC)
  let mut i = 0
  while i < 8 {
    if file.at(i) != magic.at(i) {
      fail("the secret key file has a bad magic")
    }
    i = i + 1
  }
  if file.at(8) != KEY_VERSION.to_byte() {
    fail("the secret key file has an unsupported version")
  }
  if file.at(9) != KEY_ALGORITHM.to_byte() {
    fail("the secret key file has an unsupported algorithm")
  }
  let iterations = (file.at(10).to_int() << 24) |
    (file.at(11).to_int() << 16) |
    (file.at(12).to_int() << 8) |
    file.at(13).to_int()
  let salt = FixedArray::make(KEY_SALT_BYTES, b'\x00')
  i = 0
  while i < KEY_SALT_BYTES {
    salt[i] = file.at(14 + i)
    i = i + 1
  }
  let nonce = FixedArray::make(NONCE_BYTES, b'\x00')
  i = 0
  while i < NONCE_BYTES {
    nonce[i] = file.at(30 + i)
    i = i + 1
  }
  let header = truncate_bytes(file, KEY_HEADER_BYTES)
  let sealed_data = FixedArray::make(file.length() - KEY_HEADER_BYTES, b'\x00')
  i = 0
  while i < sealed_data.length() {
    sealed_data[i] = file.at(KEY_HEADER_BYTES + i)
    i = i + 1
  }
  let wrapping_key = pbkdf2_sha512(
    string_to_utf8_bytes(passphrase),
    Bytes::from_array(salt[:]),
    iterations,
    KEY_BYTES,
  )
  let secret = chacha20poly1305_open(
    wrapping_key,
    Bytes::from_array(nonce[:]),
    Bytes::from_array(sealed_data[:]),
    header,
  )
  match secret {
    Some(k) => k
    None => fail("the passphrase is wrong, or the secret key file is damaged")
  }
}
