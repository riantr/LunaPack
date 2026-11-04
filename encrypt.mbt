// The encryption of a package.
//
// The mechanism is the one of the reference implementation this package
// follows: a key is established with the recipient, HKDF-SHA512 turns it
// into the key of the package, and every entry is sealed on its own with
// ChaCha20-Poly1305 under a key and a nonce that are derived for it.
//
// What is different is the key exchange. The reference uses the sntrup761
// KEM, which the toolchain has no counterpart of, so the key exchange here
// is X25519, which the reference itself carries as a part of the
// sntrup761x25519-sha512 method.
//
// The parts of the mechanism that are above the key exchange are the same
// as the ones of the reference: the labels of the derivation, the check
// that tells a wrong key from a damaged file, and the sealing of every
// entry on its own.

///|
/// The number of bytes of the salt of the key derivation.
pub const SALT_BYTES : Int32 = 16

///|
/// The number of bytes of a key.
pub const KEY_BYTES : Int32 = 32

///|
/// The number of bytes of the nonce of an entry.
pub const NONCE_BYTES : Int32 = 12

///|
/// The number of iterations of the passphrase derivation.
pub const PASSPHRASE_ITERATIONS : Int32 = 210000

///|
/// The label of the derivation of the key of the package.
const LABEL_MASTER : String = "lunapack-v1|master"

///|
/// The label of the derivation of the key of an entry.
const LABEL_ENTRY_KEY : String = "lunapack-v1|entry-key"

///|
/// The label of the derivation of the nonce of an entry.
const LABEL_ENTRY_NONCE : String = "lunapack-v1|entry-nonce"

///|
/// The label of the check that tells a wrong key from a damaged file.
const LABEL_KEY_CHECK : String = "lunapack-v1|key-check"

///|
/// The label of the additional data of an entry.
const LABEL_ENTRY : String = "lunapack-v1|entry"

///|
/// The method that seals a package to the owner of a public key.
pub const METHOD_X25519 : String = "x25519"

///|
/// The method that seals a package with a passphrase.
pub const METHOD_PASSPHRASE : String = "passphrase"

///|
/// How a package is encrypted.
pub struct Encryption {
  /// "x25519" or "passphrase".
  method_name : String
  /// The public key of the recipient, hex. Empty for the passphrase method.
  recipient : String
  /// The public key of the ephemeral key, hex. Empty for the passphrase.
  ephemeral : String
  /// The salt of the derivation, hex.
  salt : String
  /// The number of iterations of the passphrase derivation.
  iterations : Int32
  /// The check that tells a wrong key from a damaged package, hex.
  key_check : String
}

///|
/// Constructor so callers in other packages can build an Encryption.
pub fn new_encryption(
  method_name : String,
  recipient : String,
  ephemeral : String,
  salt : String,
  iterations : Int32,
  key_check : String,
) -> Encryption {
  { method_name, recipient, ephemeral, salt, iterations, key_check, }
}

///|
/// The key that protects the entries of a package.
///
/// It is derived from the shared secret of the key exchange and never goes
/// into the package.
pub struct PackageKey {
  /// The key of the package.
  master : Bytes
  /// The salt of the derivation.
  salt : Bytes
}

///|
/// Constructor so callers in other packages can build a PackageKey.
pub fn new_package_key(master : Bytes, salt : Bytes) -> PackageKey {
  { master, salt, }
}

///|
/// Random bytes from the generator of the core.
pub fn random_bytes(count : Int32) -> Bytes {
  let rand = @random.Rand::Rand()
  let out = FixedArray::make(count, b'\x00')
  let mut i = 0
  while i < count {
    let value = rand.uint64()
    let mut j = 0
    while j < 8 && i + j < count {
      out[i + j] = ((value >> (j * 8)) & 0xffUL).to_byte()
      j = j + 1
    }
    i = i + 8
  }
  Bytes::from_array(out[:])
}

///|
/// The salt of the entry with the given index.
fn record_salt(salt : Bytes, index : Int32) -> Bytes {
  let out = FixedArray::make(salt.length() + 4, b'\x00')
  let mut i = 0
  while i < salt.length() {
    out[i] = salt.at(i)
    i = i + 1
  }
  let n = index
  out[salt.length()] = ((n >> 24) & 0xff).to_byte()
  out[salt.length() + 1] = ((n >> 16) & 0xff).to_byte()
  out[salt.length() + 2] = ((n >> 8) & 0xff).to_byte()
  out[salt.length() + 3] = (n & 0xff).to_byte()
  Bytes::from_array(out[:])
}

///|
/// The additional data of an entry.
///
/// It binds the entry to its place in the package and to its name, so that
/// neither the order nor the name of an entry can be changed without the
/// seal of the entry breaking.
fn entry_aad(index : Int32, path : String) -> Bytes {
  let head = FixedArray::make(4, b'\x00')
  let n = index
  head[0] = ((n >> 24) & 0xff).to_byte()
  head[1] = ((n >> 16) & 0xff).to_byte()
  head[2] = ((n >> 8) & 0xff).to_byte()
  head[3] = (n & 0xff).to_byte()
  bytes_concat(
    bytes_concat(string_to_utf8_bytes(LABEL_ENTRY), Bytes::from_array(head[:])),
    string_to_utf8_bytes(path),
  )
}

///|
/// The key of the entry with the given index.
fn entry_key(key : PackageKey, index : Int32) -> Bytes {
  hkdf_sha512(
    key.master,
    record_salt(key.salt, index),
    string_to_utf8_bytes(LABEL_ENTRY_KEY),
    KEY_BYTES,
  )
}

///|
/// The nonce of the entry with the given index.
fn entry_nonce(key : PackageKey, index : Int32) -> Bytes {
  hkdf_sha512(
    key.master,
    record_salt(key.salt, index),
    string_to_utf8_bytes(LABEL_ENTRY_NONCE),
    NONCE_BYTES,
  )
}

///|
/// Derive the key that protects the entries of a package.
///
/// The input is the shared secret of the key exchange, or the result of the
/// derivation of a passphrase. The result never goes into the package.
pub fn derive_package_key(shared : Bytes, salt : Bytes) -> PackageKey {
  {
    master: hkdf_sha512(
      shared,
      salt,
      string_to_utf8_bytes(LABEL_MASTER),
      KEY_BYTES,
    ),
    salt,
  }
}

///|
/// Seal the payload of the entry with the given index.
///
/// The result is the ciphertext followed by the 16-byte tag.
pub fn seal_entry(
  key : PackageKey,
  index : Int32,
  path : String,
  payload : Bytes,
) -> Bytes {
  chacha20poly1305_seal(
    entry_key(key, index),
    entry_nonce(key, index),
    payload,
    entry_aad(index, path),
  )
}

///|
/// Open the payload of the entry with the given index.
///
/// Returns None when the seal does not hold, which means that the key is
/// wrong or that the package was damaged.
pub fn open_entry(
  key : PackageKey,
  index : Int32,
  path : String,
  stored : Bytes,
) -> Bytes? {
  chacha20poly1305_open(
    entry_key(key, index),
    entry_nonce(key, index),
    stored,
    entry_aad(index, path),
  )
}

///|
/// The check that tells a wrong key from a damaged package.
///
/// It is a truncated HMAC-SHA512 over the shared secret and the public
/// numbers of the package, so it holds even for a package that carries no
/// entry at all.
pub fn compute_key_check(
  shared : Bytes,
  recipient : Bytes,
  ephemeral : Bytes,
  salt : Bytes,
) -> Bytes {
  let data = bytes_concat(
    bytes_concat(string_to_utf8_bytes(LABEL_KEY_CHECK), recipient),
    bytes_concat(ephemeral, salt),
  )
  truncate_bytes(hmac_sha512(shared, data), 32)
}

///|
/// The first `count` bytes of `data`.
pub fn truncate_bytes(data : Bytes, count : Int32) -> Bytes {
  let out = FixedArray::make(count, b'\x00')
  let mut i = 0
  let n = if count < data.length() { count } else { data.length() }
  while i < n {
    out[i] = data.at(i)
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// The shared secret of a package that is sealed to the owner of the public
/// key `recipient`, together with the public numbers of the package.
pub struct SealedPackage {
  /// The shared secret.
  shared : Bytes
  /// The public key of the ephemeral key.
  ephemeral : Bytes
  /// The public key of the recipient.
  recipient : Bytes
  /// The salt of the derivation.
  salt : Bytes
}

///|
/// Constructor so callers in other packages can build a SealedPackage.
pub fn new_sealed_package(
  shared : Bytes,
  ephemeral : Bytes,
  recipient : Bytes,
  salt : Bytes,
) -> SealedPackage {
  { shared, ephemeral, recipient, salt, }
}

///|
/// Establish the shared secret of a package that is sealed to the owner of
/// the public key `recipient`.
///
/// An ephemeral key is made for every package, so that the same recipient
/// gets a different shared secret for every package.
pub fn seal_to_public_key(recipient : Bytes) -> SealedPackage {
  let ephemeral_secret = random_bytes(KEY_BYTES)
  let ephemeral_public = x25519_public_key(ephemeral_secret)
  let shared = x25519(ephemeral_secret, recipient)
  {
    shared,
    ephemeral: ephemeral_public,
    recipient,
    salt: random_bytes(SALT_BYTES),
  }
}

///|
/// The shared secret of a package, seen from the side of the recipient.
pub fn shared_with_secret_key(secret : Bytes, ephemeral : Bytes) -> Bytes {
  x25519(secret, ephemeral)
}

///|
/// The shared secret of a package that is sealed with a passphrase.
pub fn passphrase_secret(
  passphrase : String,
  salt : Bytes,
  iterations : Int32,
) -> Bytes {
  pbkdf2_sha512(string_to_utf8_bytes(passphrase), salt, iterations, KEY_BYTES)
}

///|
/// How a package is encrypted when it is packed.
pub struct EncryptionOptions {
  /// "x25519" or "passphrase".
  method_name : String
  /// The path of the file that holds the public key of the recipient.
  public_key : String
  /// The passphrase.
  passphrase : String
  /// The number of iterations of the passphrase derivation.
  iterations : Int32
}

///|
/// Constructor so callers in other packages can build EncryptionOptions.
pub fn new_encryption_options(
  method_name : String,
  public_key : String,
  passphrase : String,
  iterations : Int32,
) -> EncryptionOptions {
  { method_name, public_key, passphrase, iterations, }
}

///|
/// The encryption of a package that is being packed.
pub struct ActiveEncryption {
  /// The key that protects the entries.
  key : PackageKey
  /// What goes into the manifest.
  info : Encryption
}

///|
/// Establish the encryption of a package that is packed.
///
/// The key exchange happens here, before the first entry is written,
/// because the place of an entry in the package is part of its seal.
pub async fn establish_encryption(opts : EncryptionOptions) -> ActiveEncryption {
  if opts.method_name == METHOD_X25519 {
    let recipient = load_public_key(opts.public_key)
    let sealed_pkg = seal_to_public_key(recipient)
    let key = derive_package_key(sealed_pkg.shared, sealed_pkg.salt)
    let check = compute_key_check(
      sealed_pkg.shared,
      sealed_pkg.recipient,
      sealed_pkg.ephemeral,
      sealed_pkg.salt,
    )
    {
      key,
      info: new_encryption(
        METHOD_X25519,
        bytes_to_hex(sealed_pkg.recipient),
        bytes_to_hex(sealed_pkg.ephemeral),
        bytes_to_hex(sealed_pkg.salt),
        0,
        bytes_to_hex(check),
      ),
    }
  } else {
    let salt = random_bytes(SALT_BYTES)
    let shared = passphrase_secret(opts.passphrase, salt, opts.iterations)
    let key = derive_package_key(shared, salt)
    let check = compute_key_check(shared, zero_bytes(0), zero_bytes(0), salt)
    {
      key,
      info: new_encryption(
        METHOD_PASSPHRASE,
        "",
        "",
        bytes_to_hex(salt),
        opts.iterations,
        bytes_to_hex(check),
      ),
    }
  }
}

///|
/// Recover the key of a package that was sealed.
///
/// The path of the file that holds the secret key is only used by the
/// x25519 method; the passphrase method needs the passphrase.
pub async fn recover_encryption(
  info : Encryption,
  secret_key : String,
  passphrase : String,
) -> PackageKey {
  let salt = match hex_to_bytes(info.salt) {
    Some(s) => s
    None => fail("the package carries a damaged encryption")
  }
  if info.method_name == METHOD_X25519 {
    let ephemeral = match hex_to_bytes(info.ephemeral) {
      Some(e) => e
      None => fail("the package carries a damaged encryption")
    }
    let recipient = match hex_to_bytes(info.recipient) {
      Some(r) => r
      None => fail("the package carries a damaged encryption")
    }
    let key = load_secret_key(secret_key, passphrase)
    let shared = shared_with_secret_key(key, ephemeral)
    let check = compute_key_check(shared, recipient, ephemeral, salt)
    if bytes_to_hex(check) != info.key_check {
      fail("the secret key is wrong, or the package is damaged")
    }
    derive_package_key(shared, salt)
  } else {
    let shared = passphrase_secret(passphrase, salt, info.iterations)
    let check = compute_key_check(shared, zero_bytes(0), zero_bytes(0), salt)
    if bytes_to_hex(check) != info.key_check {
      fail("the passphrase is wrong, or the package is damaged")
    }
    derive_package_key(shared, salt)
  }
}
