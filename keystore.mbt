// The key files.
//
// A secret key is stored raw, or protected by a passphrase: the raw form
// leaves the long-term secret key in clear text on disk, and anyone who reads
// it can decrypt every package that was ever sealed for it.
//
// A pair of keys serves two purposes, and each purpose has a public key of
// its own. The X25519 one is the key a package is sealed to, and the Ed25519
// one is the key a signature is checked with. The two are derived from the
// same secret with a label of their own, so that the key that opens a package
// is not the key that signs one.
//
// The public key file therefore holds both of them, as a text a person can
// read:
//
//   lunapack-public-key v1
//   x25519 <the hex of the encryption public key>
//   ed25519 <the hex of the signing public key>
//
// A public key file of the older form holds the 32 raw bytes of the
// encryption public key alone, and is still read as such.
//
// The layout of the protected secret key file is the one of the reference
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
/// The first line of a public key file.
pub const PUBLIC_KEY_HEADER : String = "lunapack-public-key v1"

///|
/// The name of the encryption public key in a public key file.
pub const PUBLIC_KEY_ENCRYPTION : String = "x25519"

///|
/// The name of the signing public key in a public key file.
pub const PUBLIC_KEY_SIGNING : String = "ed25519"

///|
/// The label of the derivation of the signing seed.
const LABEL_SIGNING_SEED : String = "lunapack-v6|ed25519-seed"

///|
/// The two public keys of a pair.
pub struct PublicKeyPair {
  /// The X25519 public key: the key a package is sealed to.
  encryption : Bytes
  /// The Ed25519 public key: the key a signature is checked with.
  signing : Bytes
}

///|
/// The seed of the signing key of the secret key `secret`.
///
/// The seed is derived with HKDF-SHA512 and a label of its own, so the key
/// that signs is not the key that decrypts: the two roles cannot be taken for
/// one another, and a fault in one of them does not hand the other over.
pub fn ed25519_seed(secret : Bytes) -> Bytes {
  hkdf_sha512(
    secret,
    zero_bytes(SHA512_BYTES),
    string_to_utf8_bytes(LABEL_SIGNING_SEED),
    KEY_BYTES,
  )
}

///|
/// The two public keys of the secret key `secret`.
pub fn public_key_pair(secret : Bytes) -> PublicKeyPair raise {
  {
    encryption: x25519_public_key(secret),
    signing: ed25519_public_key(ed25519_seed(secret)),
  }
}

///|
/// Write the public key of a pair to `path`.
///
/// This is the older form: the 32 raw bytes of the encryption public key
/// alone. A file written this way cannot be used to check a signature; use
/// `save_public_key_pair` for a pair that serves both purposes.
pub async fn save_public_key(path : String, public_key : Bytes) -> Unit {
  @fs.write_binary(path, public_key)
}

///|
/// Write the two public keys of a pair to `path`.
///
/// The file is a text, so that a person can read what it holds.
pub async fn save_public_key_pair(
  path : String,
  encryption : Bytes,
  signing : Bytes,
) -> Unit {
  let text = PUBLIC_KEY_HEADER +
    "\n" +
    PUBLIC_KEY_ENCRYPTION +
    " " +
    bytes_to_hex(encryption) +
    "\n" +
    PUBLIC_KEY_SIGNING +
    " " +
    bytes_to_hex(signing) +
    "\n"
  @fs.write_text(path, text)
}

///|
/// Read the encryption public key from `path`.
///
/// A file that holds the two public keys of a pair gives the X25519 one, and
/// a file that holds the 32 raw bytes of an older pair gives those: the
/// encryption public key is the same in both.
pub async fn load_public_key(path : String) -> Bytes {
  let data = @fs.read_binary(path)
  if data.length() == KEY_BYTES {
    return data
  }
  match public_key_of(data, PUBLIC_KEY_ENCRYPTION) {
    Some(key) => key
    None =>
      fail(
        "the public key file does not hold a public key of the kind that is needed",
      )
  }
}

///|
/// Read the signing public key from `path`.
///
/// It is the Ed25519 public key of the pair: the one a signature of a package
/// is checked with. A file of the older form holds the encryption public key
/// alone, so it cannot be used here.
pub async fn load_signing_public_key(path : String) -> Bytes {
  let data = @fs.read_binary(path)
  if data.length() == KEY_BYTES {
    fail(
      "this public key file holds only the encryption public key of an older pair: make a new pair with keygen to sign with it",
    )
  }
  match public_key_of(data, PUBLIC_KEY_SIGNING) {
    Some(key) => key
    None =>
      fail(
        "the public key file does not hold the signing public key that is needed",
      )
  }
}

///|
/// The public key named `algorithm` in the bytes of a public key file.
///
/// Returns None when the file is not a public key file or does not hold a
/// key of that algorithm.
fn public_key_of(data : Bytes, algorithm : String) -> Bytes? {
  let lines = text_lines(utf8_bytes_to_string(data))
  if lines.length() < 3 {
    return None
  }
  if lines[0] != PUBLIC_KEY_HEADER {
    return None
  }
  let prefix = algorithm + " "
  for line in lines {
    if line.has_prefix(prefix) {
      return hex_to_bytes(line[prefix.length():].to_owned())
    }
  }
  None
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
