// The integrity of a package.
//
// A package carries a manifest that says what the entries are, where they
// are and which one of them is the program to start. The manifest is
// therefore the part of a package that an attacker wants to change: a
// manifest that names another program, or an install script, turns a package
// into something else.
//
// Three mechanisms protect the manifest, and each of them answers a different
// attack.
//
//   * The digest of the integrity block says that the manifest is the one the
//     packer wrote. It finds corruption, a write that was cut short and a
//     manifest that was changed in place. It is not a secret, so it does not
//     stop an attacker who rewrites the whole file: such an attacker simply
//     computes a digest that matches the manifest they wrote.
//
//   * The MAC of the same block is keyed with the key of the package. It is
//     what stops that attacker for an encrypted package, because the key is
//     not in the package.
//
//   * The signature that the host publishes next to the package is what stops
//     them for an unencrypted package, because the verification material is
//     with the host and not with the package.
//
// The block sits between the last entry and the manifest, so a package that
// carries one is still a package that an older LunaPack can read: the older
// reader steps over the block and finds the manifest where it expects it.
//
// The block has two shapes, and the shape says whether the package is
// encrypted:
//
//   [marker 8][digest 32]              40 bytes, an unencrypted package
//   [marker 8][digest 32][mac 32]      72 bytes, an encrypted package
//
// The two shapes have different lengths on purpose. The reader finds the
// block by looking for its marker at the two places it can be, so an
// attacker cannot turn an encrypted package into an unencrypted one by
// rewriting a marker: the block would no longer be where the reader looks
// for it, and the reader would find no block at all.

///|
/// The marker of the integrity block of a package that is not encrypted.
pub const INTEGRITY_MARKER : String = "LPMANIFU"

///|
/// The marker of the integrity block of an encrypted package.
pub const INTEGRITY_MARKER_ENCRYPTED : String = "LPMANIFE"

///|
/// The number of bytes of the marker of the integrity block.
pub const INTEGRITY_MARKER_BYTES : Int32 = 8

///|
/// The number of bytes of the digest of the manifest.
pub const INTEGRITY_DIGEST_BYTES : Int32 = 32

///|
/// The number of bytes of the MAC of the manifest.
pub const INTEGRITY_MAC_BYTES : Int32 = 32

///|
/// The number of bytes of the integrity block of a package that is not
/// encrypted: the marker and the digest.
pub const INTEGRITY_BLOCK_BYTES : Int32 = INTEGRITY_MARKER_BYTES +
  INTEGRITY_DIGEST_BYTES

///|
/// The number of bytes of the integrity block of an encrypted package: the
/// marker, the digest and the MAC.
pub const INTEGRITY_BLOCK_BYTES_ENCRYPTED : Int32 = INTEGRITY_MARKER_BYTES +
  INTEGRITY_DIGEST_BYTES +
  INTEGRITY_MAC_BYTES

///|
/// The label of the derivation of the key of the MAC of the manifest.
///
/// It is a label of its own, so that the key of the MAC is neither the key of
/// the package nor the key of an entry.
const LABEL_MANIFEST_MAC : String = "lunapack-v6|manifest-mac"

///|
/// The key of the MAC of the manifest, derived from the key of the package.
///
/// The derivation uses the salt of the package and a label of its own, so
/// that the MAC key cannot be used for anything else.
pub fn manifest_mac_key(key : PackageKey) -> Bytes {
  hkdf_sha512(
    key.master,
    key.salt,
    string_to_utf8_bytes(LABEL_MANIFEST_MAC),
    KEY_BYTES,
  )
}

///|
/// The bytes that the digest and the MAC of the manifest are computed over.
///
/// The two numbers that place the manifest are part of them, so that a footer
/// that points somewhere else does not pass the check.
fn manifest_input(moff : Int64, mlen : Int64, mbytes : Bytes) -> Bytes {
  bytes_concat(bytes_concat(i64_to_le8(moff), i64_to_le8(mlen)), mbytes)
}

///|
/// The digest of the manifest: the SHA-256 of the manifest and of the two
/// numbers that place it.
pub fn manifest_digest(
  moff : Int64,
  mlen : Int64,
  mbytes : Bytes,
) -> Bytes raise {
  match hex_to_bytes(sha256_hex(manifest_input(moff, mlen, mbytes))) {
    Some(b) => b
    None => fail("the digest of the manifest could not be read")
  }
}

///|
/// The MAC of the manifest, keyed with the key of the package.
///
/// It is the truncated HMAC-SHA512 of the manifest and of the two numbers
/// that place it, under a key that is derived from the key of the package.
pub fn manifest_mac(
  key : PackageKey,
  moff : Int64,
  mlen : Int64,
  mbytes : Bytes,
) -> Bytes {
  truncate_bytes(
    hmac_sha512(manifest_mac_key(key), manifest_input(moff, mlen, mbytes)),
    INTEGRITY_MAC_BYTES,
  )
}

///|
/// The integrity block of a package that is not encrypted: the marker and the
/// digest of the manifest.
pub fn integrity_block(
  moff : Int64,
  mlen : Int64,
  mbytes : Bytes,
) -> Bytes raise {
  bytes_concat(
    string_to_utf8_bytes(INTEGRITY_MARKER),
    manifest_digest(moff, mlen, mbytes),
  )
}

///|
/// The integrity block of an encrypted package: the marker, the digest of the
/// manifest and the MAC of the manifest.
pub fn integrity_block_encrypted(
  key : PackageKey,
  moff : Int64,
  mlen : Int64,
  mbytes : Bytes,
) -> Bytes raise {
  bytes_concat(
    bytes_concat(
      string_to_utf8_bytes(INTEGRITY_MARKER_ENCRYPTED),
      manifest_digest(moff, mlen, mbytes),
    ),
    manifest_mac(key, moff, mlen, mbytes),
  )
}

///|
/// Do the first `count` bytes of `block` hold `marker`?
fn block_starts_with(block : Bytes, marker : String, count : Int32) -> Bool {
  if block.length() < count {
    return false
  }
  let want = string_to_utf8_bytes(marker)
  let mut i = 0
  while i < count {
    if block.at(i) != want.at(i) {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Is the block the integrity block of a package that is not encrypted?
pub fn is_integrity_block(block : Bytes) -> Bool {
  block_starts_with(block, INTEGRITY_MARKER, INTEGRITY_MARKER_BYTES)
}

///|
/// Is the block the integrity block of an encrypted package?
pub fn is_integrity_block_encrypted(block : Bytes) -> Bool {
  block_starts_with(block, INTEGRITY_MARKER_ENCRYPTED, INTEGRITY_MARKER_BYTES)
}

///|
/// A checksum that is computed twice, compared with itself.
///
/// The computation is passed in, so that the comparison itself can be
/// tested with a machine that computes a different answer the second time.
///
/// A checksum that is computed once can be wrong in two ways at once: the
/// data can be wrong, and the computation can be wrong. Comparing the
/// checksum against a stored value catches the first kind and says nothing
/// about the second, so the checksum is computed a second time and the two
/// answers are compared. A machine that computes a different answer the
/// second time is not to be trusted with the answer at all.
fn redundant_with(data : Bytes, compute : (Bytes) -> String) -> String raise {
  let first = compute(data)
  let second = compute(data)
  if first != second {
    fail(
      "the checksum of the data was not the same twice: the machine is not reliable",
    )
  }
  first
}

///|
/// The SHA-256 of `data`, computed twice.
pub fn redundant_sha256(data : Bytes) -> String raise {
  redundant_with(data, fn(d : Bytes) -> String { sha256_hex(d) })
}

///|
/// The MD5 of `data`, computed twice.
///
/// The MD5 is not a security checksum, but it is what the platform tooling
/// shows, and it is an algorithm that is independent of SHA-256. Two
/// independent algorithms that agree are stronger evidence than one of them
/// twice.
pub fn redundant_md5(data : Bytes) -> String raise {
  redundant_with(data, fn(d : Bytes) -> String { md5_hex(d) })
}
