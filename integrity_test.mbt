// Tests for the integrity of a package.
//
// The layers that are tested here are the ones that stand between a package
// and whoever holds it: the digest of the manifest, the MAC of the manifest,
// the refusal to open a package that is damaged, the paths of the entries
// and the signature that the host publishes.
//
// A test that passes because the layer is not there is a test that says
// nothing, so every layer is also taken out of the code once to see that
// the test goes red for that reason alone.

///|
/// The bytes of `data` from `start`, `count` of them.
fn at(data : Bytes, start : Int32, count : Int32) -> Bytes {
  let out = FixedArray::make(count, b'\x00')
  let mut i = 0
  while i < count {
    out[i] = data.at(start + i)
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// The 64-bit number at `start`.
fn number_at(data : Bytes, start : Int32) -> Int64 {
  @LunaPack.le8_to_i64(at(data, start, 8), 0)
}

///|
/// The place of the manifest in a package: the offset of the archive, the
/// offset of the manifest inside it and the length of the manifest.
fn manifest_place(data : Bytes) -> (Int64, Int64, Int64) {
  let total = data.length().to_int64()
  let footer = (total - 24L).to_int()
  let moff = number_at(data, footer + 8)
  let mlen = number_at(data, footer + 16)
  let base = total - (moff + mlen + 24L)
  (base, moff, mlen)
}

///|
/// The data with the byte at `pos` replaced by `value`.
fn with_byte(data : Bytes, pos : Int32, value : Byte) -> Bytes {
  let out = FixedArray::make(data.length(), b'\x00')
  let mut i = 0
  while i < data.length() {
    out[i] = if i == pos { value } else { data.at(i) }
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// The data with the bytes of `old` at `pos` replaced by `new`.
///
/// The two have to be the same length: the package holds the length of its
/// manifest in its footer.
fn with_text_at(data : Bytes, pos : Int32, old : String, new : String) -> Bytes {
  let out = FixedArray::make(data.length(), b'\x00')
  let mut i = 0
  while i < data.length() {
    out[i] = data.at(i)
    i = i + 1
  }
  let old_bytes = @LunaPack.string_to_utf8_bytes(old)
  let new_bytes = @LunaPack.string_to_utf8_bytes(new)
  let mut i = 0
  while i + old_bytes.length() <= data.length() - pos {
    let mut same = true
    let mut j = 0
    while j < old_bytes.length() {
      if out[pos + i + j] != old_bytes.at(j) {
        same = false
      }
      j = j + 1
    }
    if same {
      let mut j = 0
      while j < new_bytes.length() {
        out[pos + i + j] = new_bytes.at(j)
        j = j + 1
      }
    }
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// A package with one file in it.
async fn make_package(prefix : String) -> String {
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
/// A package that is sealed with a passphrase.
async fn make_sealed_package(prefix : String) -> (String, String, String) {
  let src = @fs.tmpdir(prefix~)
  @fs.write_text(src + "/hello.txt", "hello")
  let pkg = src + "/sealed.appkg"
  let opts = @LunaPack.with_encryption(
    @LunaPack.with_defaults(
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
    ),
    @LunaPack.new_encryption_options(
      @LunaPack.METHOD_PASSPHRASE,
      "",
      "the passphrase",
      1000,
    ),
  )
  @LunaPack.pack(src, pkg, opts)
  (pkg, "the passphrase", src)
}

///|
/// The key of a sealed package.
async fn key_of(pkg : String, passphrase : String) -> @LunaPack.PackageKey {
  let manifest = @LunaPack.read_package_manifest(pkg)
  let info = match manifest.encryption {
    Some(i) => i
    None => fail("the package is not encrypted")
  }
  @LunaPack.recover_encryption(info, "", passphrase)
}

///|
async test "a package carries the integrity block of its manifest" {
  let pkg = make_package("lunapack_integrity")
  let data = @fs.read_binary(pkg)
  let (base, moff, mlen) = manifest_place(data)
  let position = (base + moff).to_int()
  // The block of a package that is not encrypted sits right in front of the
  // manifest.
  let block = at(data, position - 40, 40)
  assert_true(@LunaPack.is_integrity_block(block))
  let manifest = at(data, position, mlen.to_int())
  let digest = @LunaPack.manifest_digest(moff, mlen, manifest)
  assert_true(at(block, 8, 32) == digest)
}

///|
async test "a package whose manifest was changed is refused" {
  let pkg = make_package("lunapack_tampered")
  let data = @fs.read_binary(pkg)
  let (base, moff, _mlen) = manifest_place(data)
  let position = (base + moff).to_int()
  // The name in the manifest of the package is changed.
  let patched = with_text_at(data, position, "demo", "dexo")
  @fs.write_binary(pkg, patched)
  let ok = try {
    ignore(@LunaPack.verify(pkg, None))
    true
  } catch {
    _ => false
  }
  assert_true(!ok)
}

///|
async test "a package whose footer was changed is refused" {
  let pkg = make_package("lunapack_footer")
  let data = @fs.read_binary(pkg)
  let total = data.length()
  // The length of the manifest in the footer: a number that is not the one
  // that was written.
  @fs.write_binary(pkg, with_byte(data, total - 24 + 16, b'\x07'))
  let ok = try {
    ignore(@LunaPack.verify(pkg, None))
    true
  } catch {
    _ => false
  }
  assert_true(!ok)
}

///|
async test "a sealed package carries the MAC of its manifest" {
  let (pkg, passphrase, _src) = make_sealed_package("lunapack_sealed")
  let data = @fs.read_binary(pkg)
  let (base, moff, mlen) = manifest_place(data)
  let position = (base + moff).to_int()
  // The block of an encrypted package is longer: it holds the MAC as well.
  let block = at(data, position - 72, 72)
  assert_true(@LunaPack.is_integrity_block_encrypted(block))
  let manifest = at(data, position, mlen.to_int())
  let key = key_of(pkg, passphrase)
  let mac = @LunaPack.manifest_mac(key, moff, mlen, manifest)
  assert_true(at(block, 40, 32) == mac)
}

///|
async test "a sealed package whose manifest was changed is refused" {
  let (pkg, passphrase, _src) = make_sealed_package("lunapack_sealed_tampered")
  let data = @fs.read_binary(pkg)
  let (base, moff, mlen) = manifest_place(data)
  let position = (base + moff).to_int()
  // The name in the manifest of the package is changed, and the digest of
  // the manifest is written again. That is what whoever holds the file can
  // do: the digest is not a secret. The MAC of the manifest is the guard
  // that is left, because it is keyed with the key of the package.
  let patched = with_text_at(data, position, "demo", "dexo")
  let manifest = at(patched, position, mlen.to_int())
  let digest = @LunaPack.manifest_digest(moff, mlen, manifest)
  let out = FixedArray::make(patched.length(), b'\x00')
  let mut i = 0
  while i < patched.length() {
    out[i] = patched.at(i)
    i = i + 1
  }
  // The digest goes into the block; the MAC stays as it was.
  let mut i = 0
  while i < 32 {
    out[position - 72 + 8 + i] = digest.at(i)
    i = i + 1
  }
  @fs.write_binary(pkg, Bytes::from_array(out[:]))
  let key = key_of(pkg, passphrase)
  let ok = try {
    ignore(@LunaPack.verify(pkg, Some(key)))
    true
  } catch {
    _ => false
  }
  assert_true(!ok)
}

///|
async test "a sealed package opens with the right key" {
  let (pkg, passphrase, _src) = make_sealed_package("lunapack_sealed_open")
  let dest = @fs.tmpdir(prefix="lunapack_sealed_dest")
  let key = key_of(pkg, passphrase)
  @LunaPack.unpack(pkg, dest, false, Some(key))
  assert_true(@fs.read_text(dest + "/hello.txt") == "hello")
}

///|
async test "a damaged package is not taken for a file that is not a package" {
  let pkg = make_package("lunapack_damaged")
  let data = @fs.read_binary(pkg)
  // Cut the package in half: it still carries the marker of a package.
  let half = at(data, 0, data.length() / 2)
  @fs.write_binary(pkg, half)
  let failed = try {
    match @LunaPack.probe_archive(pkg) {
      Some(_) => false
      None => false
    }
  } catch {
    _ => true
  }
  assert_true(failed)
}

///|
async test "a file that is not a package is not a damaged package" {
  let dir = @fs.tmpdir(prefix="lunapack_notapackage")
  let path = dir + "/plain.txt"
  @fs.write_text(path, "not a package at all")
  let result = @LunaPack.probe_archive(path)
  assert_true(result is None)
}

///|
async test "a path that walks out of the destination is refused" {
  let pkg = make_package("lunapack_escape")
  let data = @fs.read_binary(pkg)
  let (base, moff, mlen) = manifest_place(data)
  let position = (base + moff).to_int()
  // The path of the entry in the manifest is replaced by one that walks out
  // of the destination. The digest of the manifest is written again, so the
  // path is the only thing that is wrong with the package.
  let patched = with_text_at(data, position, "hello.txt", "../hi.txt")
  let manifest = at(patched, position, mlen.to_int())
  let block = @LunaPack.integrity_block(moff, mlen, manifest)
  let out = FixedArray::make(patched.length(), b'\x00')
  let mut i = 0
  while i < patched.length() {
    out[i] = patched.at(i)
    i = i + 1
  }
  let mut i = 0
  while i < 40 {
    out[position - 40 + i] = block.at(i)
    i = i + 1
  }
  @fs.write_binary(pkg, Bytes::from_array(out[:]))
  let ok = try {
    ignore(@LunaPack.verify(pkg, None))
    true
  } catch {
    _ => false
  }
  assert_true(!ok)
}

///|
async test "the signature of a package holds" {
  let pkg = make_package("lunapack_signed")
  let secret = @LunaPack.random_bytes(32)
  let public = @LunaPack.ed25519_public_key(secret)
  let signature = @LunaPack.sign_package(pkg, secret)
  assert_true(@LunaPack.verify_package_signature(pkg, signature, public))
}

///|
async test "a package that was changed after it was signed does not match" {
  let pkg = make_package("lunapack_signed_changed")
  let secret = @LunaPack.random_bytes(32)
  let public = @LunaPack.ed25519_public_key(secret)
  let signature = @LunaPack.sign_package(pkg, secret)
  let data = @fs.read_binary(pkg)
  @fs.write_binary(pkg, with_byte(data, 30, b'Z'))
  assert_true(!@LunaPack.verify_package_signature(pkg, signature, public))
}

///|
async test "a signature does not hold for another public key" {
  let pkg = make_package("lunapack_signed_other")
  let secret = @LunaPack.random_bytes(32)
  let other = @LunaPack.ed25519_public_key(@LunaPack.random_bytes(32))
  let signature = @LunaPack.sign_package(pkg, secret)
  assert_true(!@LunaPack.verify_package_signature(pkg, signature, other))
}

///|
async test "a signature file keeps what it says" {
  let pkg = make_package("lunapack_signature_file")
  let secret = @LunaPack.random_bytes(32)
  let signature = @LunaPack.sign_package(pkg, secret)
  let text = @LunaPack.signature_to_text(signature)
  match @LunaPack.signature_from_text(text) {
    Some(p) => {
      assert_true(p.package_digest == signature.package_digest)
      assert_true(p.manifest_digest == signature.manifest_digest)
      assert_true(p.signature == signature.signature)
    }
    None => assert_true(false)
  }
}

///|
async test "a text that is not a signature file is refused" {
  assert_true(@LunaPack.signature_from_text("hello\n") is None)
  assert_true(
    @LunaPack.signature_from_text(
      "lunapack-signature v1\nalgorithm ed25519\nnonsense\n",
    )
    is None,
  )
}

///|
async test "the digest that the host published is checked" {
  let pkg = make_package("lunapack_expected_digest")
  let digest = @LunaPack.sha256_hex(@fs.read_binary(pkg))
  assert_true(@LunaPack.verify_package_digest(pkg, digest))
  assert_true(!@LunaPack.verify_package_digest(pkg, "00"))
}

///|
async test "the package is written in one piece" {
  let pkg = make_package("lunapack_atomic")
  // Nothing of the writing is left behind next to the package.
  assert_true(!@fs.exists(pkg + ".lunapack-tmp"))
  // The package is a whole package.
  assert_true(@LunaPack.verify(pkg, None))
}

///|
/// A pack that fails leaves the target alone.
///
/// The encryption of a package is established after the file of the package
/// has been opened, so a package that is sealed for a key that cannot be
/// read fails while the package is being written. The package that was at
/// the target has to be there afterwards, whole.
async test "a pack that fails leaves the target alone" {
  let pkg = make_package("lunapack_atomic_fail")
  let before = @fs.read_binary(pkg)
  let src = @fs.tmpdir(prefix="lunapack_atomic_fail_src")
  @fs.write_text(src + "/hello.txt", "hello")
  let opts = @LunaPack.with_encryption(
    @LunaPack.with_defaults(
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
    ),
    // The public key of the recipient cannot be read, so the pack fails
    // while it is written.
    @LunaPack.new_encryption_options(
      @LunaPack.METHOD_X25519,
      src + "/no-such-key.pub",
      "",
      0,
    ),
  )
  let failed = try {
    @LunaPack.pack(src, pkg, opts)
    false
  } catch {
    _ => true
  }
  assert_true(failed)
  // The target still holds the package that was there before.
  assert_true(@fs.read_binary(pkg) == before)
  assert_true(@LunaPack.verify(pkg, None))
  // Nothing of the writing is left behind.
  assert_true(!@fs.exists(pkg + ".lunapack-tmp"))
}

///|
/// A package that says that it is not encrypted is refused when a key is
/// given for it.
///
/// The key is the claim of the reader that the package is encrypted to
/// them. A package that says the opposite is a package that was changed.
async test "a package that says it is not encrypted is refused when a key is given" {
  let pkg = make_package("lunapack_key_refused")
  let key = key_of(
    make_sealed_package("lunapack_key_refused_sealed").0,
    "the passphrase",
  )
  let refused = try {
    ignore(@LunaPack.verify(pkg, Some(key)))
    false
  } catch {
    _ => true
  }
  assert_true(refused)
}
