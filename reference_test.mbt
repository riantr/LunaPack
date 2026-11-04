// The tests that compare the encryption with the reference implementation.
//
// The reference implementation is a C# port of the OpenSSH key exchange
// `sntrup761x25519-sha512`. What LunaPack takes from it is the mechanism
// above the key exchange:
//
//   - the master key of a container is HKDF-SHA512 of the shared secret,
//   - every record gets its own key and its own nonce, derived from the
//     master key, the salt of the container and the number of the record,
//   - the check of the key is a truncated HMAC-SHA512 over the shared
//     secret and the public numbers of the container,
//   - every record is sealed with ChaCha20-Poly1305 over additional data
//     that holds the header and the number of the record.
//
// The key exchange itself is different: the toolchain has no sntrup761, so
// LunaPack uses X25519, which the reference carries as a part of its own
// method.
//
// The values below are the ones that the reference computes, with the
// labels and the layout of the reference. LunaPack uses labels of its own,
// but the chain of derivations has to be the same.

///|
/// The label of the master key of the reference.
fn reference_master_label() -> Bytes {
  @LunaPack.string_to_utf8_bytes("sntrup761-file-v1|master")
}

///|
/// The label of the key of a record of the reference.
fn reference_chunk_key_label() -> Bytes {
  @LunaPack.string_to_utf8_bytes("sntrup761-file-v1|chunk-key")
}

///|
/// The label of the nonce of a record of the reference.
fn reference_chunk_nonce_label() -> Bytes {
  @LunaPack.string_to_utf8_bytes("sntrup761-file-v1|chunk-nonce")
}

///|
/// The label of the check of the key of the reference.
fn reference_key_check_label() -> Bytes {
  @LunaPack.string_to_utf8_bytes("sntrup761-file-v1|key-check")
}

///|
/// The shared secret of the vectors.
fn reference_kem_key() -> Bytes {
  hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
}

///|
/// The salt of the vectors.
fn reference_salt() -> Bytes {
  hex_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
}

///|
/// The salt of the record with the given number: the salt of the container
/// followed by the number in big-endian.
fn reference_record_salt(salt : Bytes, index : Int32) -> Bytes {
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
/// The additional data of a record of the reference: the header of the
/// container followed by the number of the record.
fn reference_aad(header : Bytes, index : Int32) -> Bytes {
  let out = FixedArray::make(header.length() + 4, b'\x00')
  let mut i = 0
  while i < header.length() {
    out[i] = header.at(i)
    i = i + 1
  }
  let n = index
  out[header.length()] = ((n >> 24) & 0xff).to_byte()
  out[header.length() + 1] = ((n >> 16) & 0xff).to_byte()
  out[header.length() + 2] = ((n >> 8) & 0xff).to_byte()
  out[header.length() + 3] = (n & 0xff).to_byte()
  Bytes::from_array(out[:])
}

///|
/// The derivation of the reference implementation, step by step.
///
/// Every value is compared with the one that the reference produces for the
/// same inputs.
test "the derivation matches the reference implementation" {
  let kem_key = reference_kem_key()
  let salt = reference_salt()
  let public_key = hex_bytes(
    "1111111111111111111111111111111111111111111111111111111111111111",
  )
  let ciphertext = hex_bytes(
    "2222222222222222222222222222222222222222222222222222222222222222",
  )
  let header = hex_bytes(
    "3333333333333333333333333333333333333333333333333333333333333333",
  )
  let index = 7
  // The master key of the container.
  let master = @LunaPack.hkdf_sha512(
    kem_key,
    salt,
    reference_master_label(),
    32,
  )
  assert_true(
    @LunaPack.bytes_to_hex(master) ==
    "72b71489505d1e4204d63847ea54a0eaee07fa13a1d741a04eb5ef13e7a2b15f",
  )
  // The salt of the record.
  let record_salt = reference_record_salt(salt, index)
  assert_true(
    @LunaPack.bytes_to_hex(record_salt) ==
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000007",
  )
  // The key and the nonce of the record.
  let chunk_key = @LunaPack.hkdf_sha512(
    master,
    record_salt,
    reference_chunk_key_label(),
    32,
  )
  assert_true(
    @LunaPack.bytes_to_hex(chunk_key) ==
    "fdb9c08c1293e0a558aca6f572624b9797e894c97e83bc51b562d776fe09a3f7",
  )
  let chunk_nonce = @LunaPack.hkdf_sha512(
    master,
    record_salt,
    reference_chunk_nonce_label(),
    12,
  )
  assert_true(@LunaPack.bytes_to_hex(chunk_nonce) == "7f44e9aed180cd70c3081d4a")
  // The check of the key.
  let check_data = @LunaPack.bytes_concat(
    @LunaPack.bytes_concat(reference_key_check_label(), public_key),
    ciphertext,
  )
  let key_check = @LunaPack.truncate_bytes(
    @LunaPack.hmac_sha512(kem_key, check_data),
    32,
  )
  assert_true(
    @LunaPack.bytes_to_hex(key_check) ==
    "901636bd2bd30b4f0595d4fd24a4f9e30537eb2bb4141718aee98cd0fefd355d",
  )
  // The additional data of the record.
  let aad = reference_aad(header, index)
  assert_true(
    @LunaPack.bytes_to_hex(aad) ==
    "333333333333333333333333333333333333333333333333333333333333333300000007",
  )
  // The record itself.
  let plaintext = @LunaPack.string_to_utf8_bytes("the payload of the record")
  let record = @LunaPack.chacha20poly1305_seal(
    chunk_key, chunk_nonce, plaintext, aad,
  )
  assert_true(
    @LunaPack.bytes_to_hex(record) ==
    "c5fbd8b7076c0321daf292ab4f5107d51fdaac38d1e29024ac" +
    "5278403d0b9f589412f43a0bb947ef62",
  )
  // And it opens again.
  let back = @LunaPack.chacha20poly1305_open(
    chunk_key, chunk_nonce, record, aad,
  )
  assert_true(back == Some(plaintext))
}
