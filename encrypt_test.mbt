// The tests of the encryption.
//
// The mechanism is the one of the reference implementation this package
// follows: a key is established with the recipient, HKDF-SHA512 turns it
// into the key of the package, and every entry is sealed on its own.

///|
/// The key of a package, for the tests.
fn test_key() -> @LunaPack.PackageKey {
  @LunaPack.derive_package_key(
    hex_bytes(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ),
    hex_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
  )
}

///|
/// A payload that is sealed and opened again.
test "an entry is sealed and opened again" {
  let key = test_key()
  let payload = hex_bytes("48656c6c6f2c204c756e615061636b")
  let stored = @LunaPack.seal_entry(key, 0, "hello.txt", payload)
  // The seal is longer than the payload: the tag is 16 bytes.
  assert_true(stored.length() == payload.length() + 16)
  // And it is not the payload.
  assert_true(stored != payload)
  let back = @LunaPack.open_entry(key, 0, "hello.txt", stored)
  assert_true(back == Some(payload))
}

///|
/// The seal of an entry holds its place and its name.
test "the seal of an entry holds its place and its name" {
  let key = test_key()
  let payload = hex_bytes("48656c6c6f")
  let stored = @LunaPack.seal_entry(key, 3, "hello.txt", payload)
  // Another place.
  assert_true(@LunaPack.open_entry(key, 4, "hello.txt", stored) is None)
  // Another name.
  assert_true(@LunaPack.open_entry(key, 3, "other.txt", stored) is None)
  // The right place and the right name.
  assert_true(
    @LunaPack.open_entry(key, 3, "hello.txt", stored) == Some(payload),
  )
}

///|
/// A seal that was damaged does not open.
test "a damaged seal does not open" {
  let key = test_key()
  let payload = hex_bytes("48656c6c6f")
  let stored = @LunaPack.seal_entry(key, 0, "hello.txt", payload)
  let broken = FixedArray::make(stored.length(), b'\x00')
  let mut i = 0
  while i < stored.length() {
    broken[i] = stored.at(i)
    i = i + 1
  }
  // A byte of the ciphertext.
  broken[0] = (broken[0].to_int() ^ 0xff).to_byte()
  assert_true(
    @LunaPack.open_entry(key, 0, "hello.txt", Bytes::from_array(broken[:]))
    is None,
  )
  // A byte of the tag.
  let broken2 = FixedArray::make(stored.length(), b'\x00')
  i = 0
  while i < stored.length() {
    broken2[i] = stored.at(i)
    i = i + 1
  }
  broken2[stored.length() - 1] = (broken2[stored.length() - 1].to_int() ^ 0xff).to_byte()
  assert_true(
    @LunaPack.open_entry(key, 0, "hello.txt", Bytes::from_array(broken2[:]))
    is None,
  )
}

///|
/// Another key does not open the seal.
test "another key does not open the seal" {
  let key = test_key()
  let other = @LunaPack.derive_package_key(
    hex_bytes(
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    hex_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
  )
  let payload = hex_bytes("48656c6c6f")
  let stored = @LunaPack.seal_entry(key, 0, "hello.txt", payload)
  assert_true(@LunaPack.open_entry(other, 0, "hello.txt", stored) is None)
}

///|
/// The check of the key tells a wrong key from a damaged package.
test "the check of the key" {
  let shared = hex_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let recipient = hex_bytes(
    "1111111111111111111111111111111111111111111111111111111111111111",
  )
  let ephemeral = hex_bytes(
    "2222222222222222222222222222222222222222222222222222222222222222",
  )
  let salt = hex_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
  let check = @LunaPack.compute_key_check(shared, recipient, ephemeral, salt)
  // It is 32 bytes.
  assert_true(check.length() == 32)
  // It is the same for the same numbers.
  assert_true(
    @LunaPack.compute_key_check(shared, recipient, ephemeral, salt) == check,
  )
  // And it is another one for another secret.
  assert_true(
    @LunaPack.compute_key_check(
      hex_bytes(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
      recipient,
      ephemeral,
      salt,
    ) !=
    check,
  )
}

///|
/// The key of a package is derived from the shared secret and the salt.
test "the key of a package is derived from the secret and the salt" {
  let shared = hex_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let salt = hex_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
  let key = @LunaPack.derive_package_key(shared, salt)
  let payload = hex_bytes("00")
  let seal = @LunaPack.seal_entry(key, 0, "a.txt", payload)
  // The same inputs give the same key, so the seal is the same.
  assert_true(
    @LunaPack.seal_entry(
      @LunaPack.derive_package_key(shared, salt),
      0,
      "a.txt",
      payload,
    ) ==
    seal,
  )
  // Another salt gives another key, so the seal is another one.
  assert_true(
    @LunaPack.seal_entry(
      @LunaPack.derive_package_key(
        shared,
        hex_bytes("00000000000000000000000000000000"),
      ),
      0,
      "a.txt",
      payload,
    ) !=
    seal,
  )
}

///|
/// The pair of keys of a recipient agrees with itself.
test "the pair of keys of a recipient agrees" {
  let secret = @LunaPack.random_bytes(32)
  let public = @LunaPack.x25519_public_key(secret)
  // The public key is 32 bytes and it is not the secret.
  assert_true(public.length() == 32)
  assert_true(public != secret)
  // The shared secret is the same on both sides.
  let other_secret = @LunaPack.random_bytes(32)
  let other_public = @LunaPack.x25519_public_key(other_secret)
  let mine = @LunaPack.x25519(secret, other_public)
  let theirs = @LunaPack.x25519(other_secret, public)
  assert_true(mine == theirs)
  // And it is not all zeros, which is what a point of a small order gives.
  assert_true(!@LunaPack.is_all_zero(mine))
}

///|
/// The manifest carries the encryption of the package.
test "the manifest carries the encryption" {
  let m = @LunaPack.json_to_manifest(
    "{\"format_version\":5,\"name\":\"t\",\"version\":\"1\",\"os\":\"windows\"," +
    "\"arch\":\"x86_64\",\"checksum_algo\":\"sha256\",\"compression\":\"gzip\"," +
    "\"created_at\":\"2026-11-04T00:00:00Z\",\"main_program\":\"\"," +
    "\"pre_install\":null,\"post_install\":null," +
    "\"encryption\":{\"method\":\"x25519\",\"recipient\":\"aa\"," +
    "\"ephemeral\":\"bb\",\"salt\":\"cc\",\"iterations\":0," +
    "\"key_check\":\"dd\"},\"entries\":[]}",
  )
  match m.encryption {
    Some(e) => {
      assert_true(e.method_name == "x25519")
      assert_true(e.recipient == "aa")
      assert_true(e.ephemeral == "bb")
      assert_true(e.salt == "cc")
      assert_true(e.iterations == 0)
      assert_true(e.key_check == "dd")
    }
    None => assert_true(false)
  }
  // And it survives the round trip through the JSON.
  let text = @LunaPack.manifest_to_json(m)
  let back = @LunaPack.json_to_manifest(text)
  match back.encryption {
    Some(e) => assert_true(e.method_name == "x25519" && e.salt == "cc")
    None => assert_true(false)
  }
}

///|
/// A package without an encryption has none.
test "a package without an encryption has none" {
  let m = @LunaPack.json_to_manifest(
    "{\"format_version\":4,\"name\":\"t\",\"version\":\"1\",\"os\":\"windows\"," +
    "\"arch\":\"x86_64\",\"checksum_algo\":\"sha256\",\"compression\":\"none\"," +
    "\"created_at\":\"\",\"main_program\":\"\",\"pre_install\":null," +
    "\"post_install\":null,\"entries\":[]}",
  )
  assert_true(m.encryption is None)
}

///|
/// The key files survive the round trip.
async test "the key files survive the round trip" {
  let dir = scratch_dir("lunapack_key")
  defer drop_scratch(dir)
  let public_path = dir + "/a.pub"
  let secret_path = dir + "/a.key"
  let secret = @LunaPack.random_bytes(32)
  let public = @LunaPack.x25519_public_key(secret)
  @LunaPack.save_public_key(public_path, public)
  @LunaPack.save_secret_key_raw(secret_path, secret)
  assert_true(@LunaPack.load_public_key(public_path) == public)
  assert_true(@LunaPack.load_secret_key(secret_path, "") == secret)
  // The protected form needs the passphrase.
  let protected_path = dir + "/b.key"
  @LunaPack.save_secret_key(protected_path, secret, "a passphrase")
  assert_true(@LunaPack.is_protected_key_file(protected_path))
  assert_true(
    @LunaPack.load_secret_key(protected_path, "a passphrase") == secret,
  )
  // Another passphrase does not open it.
  let wrong = @LunaPack.load_secret_key(protected_path, "another passphrase") catch {
    _ => Default::default()
  }
  assert_true(wrong != secret)
}

///|
/// The passphrase derives the same secret every time.
test "the passphrase derives the same secret every time" {
  let salt = hex_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
  let one = @LunaPack.passphrase_secret("a passphrase", salt, 1000)
  let two = @LunaPack.passphrase_secret("a passphrase", salt, 1000)
  assert_true(one == two)
  assert_true(one.length() == 32)
  // Another passphrase gives another secret.
  assert_true(
    @LunaPack.passphrase_secret("another passphrase", salt, 1000) != one,
  )
  // And another salt as well.
  assert_true(
    @LunaPack.passphrase_secret("a passphrase", zero_bytes_of_salt(), 1000) !=
    one,
  )
}

///|
/// Sixteen zero bytes.
fn zero_bytes_of_salt() -> Bytes {
  @LunaPack.zero_bytes(16)
}
