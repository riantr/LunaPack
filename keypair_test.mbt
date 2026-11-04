// The pair of keys and the signature of a package.
//
// A pair of keys serves two purposes: the X25519 one is the key a package is
// sealed to, and the Ed25519 one is the key a signature is checked with. The
// two are derived from the same secret, so a defect in one of them can leave
// the other one broken.
//
// The tests here hold the whole chain that the command line walks: make a
// pair, sign a package with the secret key, and check the signature with the
// public key of the pair. The chain does not need a host with a POSIX shell,
// so it is checked on every machine that runs the tests.

///|
/// A package with one file in it.
async fn make_demo_package(prefix : String) -> String {
  let src = @fs.tmpdir(prefix~)
  @fs.write_text(src + "/hello.txt", "hello")
  let pkg = src + "/test.appkg"
  let opts = @LunaPack.with_defaults(
    @LunaPack.new_pack_options(
      "demo",
      "1.0.0",
      "linux",
      "x86_64",
      None,
      None,
      "none",
    ),
    "demo",
    "1.0.0",
    "linux",
    "x86_64",
  )
  @LunaPack.pack(src, pkg, opts)
  pkg
}

///|
/// The files of a pair, written the way `keygen` writes them.
async fn make_key_pair(dir : String, secret : Bytes) -> (String, String) {
  let pair = @LunaPack.public_key_pair(secret)
  let public_path = dir + "/a.pub"
  let secret_path = dir + "/a.key"
  @LunaPack.save_public_key_pair(public_path, pair.encryption, pair.signing)
  @LunaPack.save_secret_key_raw(secret_path, secret)
  (public_path, secret_path)
}

///|
async test "the signing key of a pair checks a signature made with it" {
  let pkg = make_demo_package("lunapack_keypair")
  let prefix = "lunapack_keypair"
  let dir = @fs.tmpdir(prefix~)
  let secret = @LunaPack.random_bytes(32)
  let (public_path, secret_path) = make_key_pair(dir, secret)
  // The secret key file gives back the secret it was written from.
  let loaded = @LunaPack.load_secret_key(secret_path, "")
  assert_true(loaded == secret)
  // The host signs the package with it.
  let sig = @LunaPack.sign_package(pkg, loaded)
  // Whoever holds the public key checks the signature.
  let public = @LunaPack.load_signing_public_key(public_path)
  assert_true(@LunaPack.verify_package_signature(pkg, sig, public))
}

///|
async test "a signature does not hold for another pair" {
  let pkg = make_demo_package("lunapack_keypair_other")
  let prefix = "lunapack_keypair_other"
  let dir = @fs.tmpdir(prefix~)
  let secret = @LunaPack.random_bytes(32)
  let (public_path, secret_path) = make_key_pair(dir, secret)
  let sig = @LunaPack.sign_package(
    pkg,
    @LunaPack.load_secret_key(secret_path, ""),
  )
  // Another pair has another public key, and the signature is not its own.
  let other = @LunaPack.random_bytes(32)
  let other_pair = @LunaPack.public_key_pair(other)
  assert_true(!@LunaPack.verify_package_signature(pkg, sig, other_pair.signing))
  // The encryption public key of the pair is not the signing one.
  assert_true(other_pair.encryption != other_pair.signing)
  assert_true(public_path != "")
}

///|
async test "a package that was changed after it was signed does not match" {
  let pkg = make_demo_package("lunapack_keypair_changed")
  let prefix = "lunapack_keypair_changed"
  let dir = @fs.tmpdir(prefix~)
  let secret = @LunaPack.random_bytes(32)
  let (public_path, secret_path) = make_key_pair(dir, secret)
  let sig = @LunaPack.sign_package(
    pkg,
    @LunaPack.load_secret_key(secret_path, ""),
  )
  let public = @LunaPack.load_signing_public_key(public_path)
  // A byte is added to the package, so it is not the one that was signed.
  @fs.write_binary(pkg + ".copy", @fs.read_binary(pkg) + b"x")
  assert_true(!@LunaPack.verify_package_signature(pkg + ".copy", sig, public))
}

///|
async test "the two roles of a pair are separated" {
  let secret = @LunaPack.random_bytes(32)
  let pair = @LunaPack.public_key_pair(secret)
  // The encryption public key is the one of the secret itself.
  assert_true(@LunaPack.x25519_public_key(secret) == pair.encryption)
  // The signing public key is the one of the seed that is derived from it.
  let seed = @LunaPack.ed25519_seed(secret)
  assert_true(@LunaPack.ed25519_public_key(seed) == pair.signing)
  // The seed is not the secret, and the two roles are not the same key.
  assert_true(seed != secret)
  assert_true(pair.encryption != pair.signing)
}

///|
async test "a public key file holds both public keys of the pair" {
  let prefix = "lunapack_keypair_file"
  let dir = @fs.tmpdir(prefix~)
  let secret = @LunaPack.random_bytes(32)
  let pair = @LunaPack.public_key_pair(secret)
  let path = dir + "/a.pub"
  @LunaPack.save_public_key_pair(path, pair.encryption, pair.signing)
  // Each role reads the key it needs.
  assert_true(@LunaPack.load_public_key(path) == pair.encryption)
  assert_true(@LunaPack.load_signing_public_key(path) == pair.signing)
  // The file says what it is.
  let text = @LunaPack.utf8_bytes_to_string(@fs.read_binary(path))
  assert_true(text.has_prefix(@LunaPack.PUBLIC_KEY_HEADER))
}

///|
async test "a public key file of the older form cannot sign" {
  let prefix = "lunapack_keypair_old"
  let dir = @fs.tmpdir(prefix~)
  let secret = @LunaPack.random_bytes(32)
  let pair = @LunaPack.public_key_pair(secret)
  let path = dir + "/old.pub"
  // The older form holds the encryption public key alone.
  @LunaPack.save_public_key(path, pair.encryption)
  assert_true(@LunaPack.load_public_key(path) == pair.encryption)
  // It cannot be used to check a signature, and it says so.
  let refused = @LunaPack.load_signing_public_key(path) catch {
    _ => Default::default()
  }
  assert_true(refused.length() != 32)
}
