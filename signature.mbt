// The detached signature of a package.
//
// Everything a package says about itself can be rewritten by whoever holds
// the file: the manifest is in the file, and the digest that goes with it is
// not a secret. So a package cannot tell the host that it is the package the
// host published.
//
// The signature is the material that can. The host holds the secret key,
// signs the digest of the package and publishes the signature next to it.
// Whoever holds the public key can then check that the package is the one
// the host published, without trusting anything the package says about
// itself.
//
// The signature covers the digest of the package and not the package itself,
// so signing a package does not need the package to be held in memory and
// the signature stays the same size whatever the package holds.
//
// The signature is an Ed25519 one, so the public key is enough to check it
// and the secret key is enough to make it.

///|
/// The label that the signature of a package is computed over.
///
/// The label keeps a signature of a package from being a signature of
/// anything else that happens to have the same digest.
const LABEL_PACKAGE_SIGNATURE : String = "lunapack-v6|package-signature"

///|
/// The first line of a signature file.
pub const SIGNATURE_HEADER : String = "lunapack-signature v1"

///|
/// The algorithm of a signature file.
pub const SIGNATURE_ALGORITHM : String = "ed25519"

///|
/// A detached signature of a package.
pub struct PackageSignature {
  /// The SHA-256 of the package, hex.
  package_digest : String
  /// The SHA-256 of the manifest of the package, hex.
  manifest_digest : String
  /// The signature itself, hex.
  signature : String
}

///|
/// Constructor so callers in other packages can build a PackageSignature.
pub fn new_package_signature(
  package_digest : String,
  manifest_digest : String,
  signature : String,
) -> PackageSignature {
  { package_digest, manifest_digest, signature, }
}

///|
/// The bytes that the signature of a package is computed over.
fn signature_message(package_digest : Bytes) -> Bytes {
  bytes_concat(string_to_utf8_bytes(LABEL_PACKAGE_SIGNATURE), package_digest)
}

///|
/// Sign the package at `path` with the secret key `secret`.
///
/// The result says which package it belongs to: the digest of the package
/// and the digest of its manifest.
pub async fn sign_package(path : String, secret : Bytes) -> PackageSignature {
  let data = @fs.read_binary(path)
  let digest = sha256_hex(data)
  let digest_bytes = match hex_to_bytes(digest) {
    Some(b) => b
    None => fail("the digest of the package could not be read")
  }
  let manifest_digest = package_manifest_digest(path)
  let signature = ed25519_sign(secret, signature_message(digest_bytes))
  new_package_signature(digest, manifest_digest, bytes_to_hex(signature))
}

///|
/// The text of a signature file.
///
/// The file is a text, so that a person can read what it says and a script
/// can check it without a library.
pub fn signature_to_text(sig : PackageSignature) -> String {
  let mut out = SIGNATURE_HEADER + "\n"
  out = out + "algorithm " + SIGNATURE_ALGORITHM + "\n"
  out = out + "package " + sig.package_digest + "\n"
  out = out + "manifest " + sig.manifest_digest + "\n"
  out = out + "signature " + sig.signature + "\n"
  out
}

///|
/// The lines of a text, without the line endings.
fn text_lines(text : String) -> Array[String] {
  let out = []
  let mut start = 0
  let mut i = 0
  while i < text.length() {
    if text[i] == '\n' {
      out.push(text[start:i].trim().to_owned())
      start = i + 1
    }
    i = i + 1
  }
  if start < text.length() {
    out.push(text[start:].trim().to_owned())
  }
  out
}

///|
/// Are the two texts the same hexadecimal digest?
///
/// The digest of a package is written in small letters, and the one that is
/// given may be written in big ones, so the letters of the hexadecimal
/// alphabet are compared without regard to their case.
fn same_hex(a : String, b : String) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut i = 0
  while i < a.length() {
    let x = a[i].to_int()
    let y = b[i].to_int()
    let small_x = if x >= 65 && x <= 70 { x + 32 } else { x }
    let small_y = if y >= 65 && y <= 70 { y + 32 } else { y }
    if small_x != small_y {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// The signature in the text of a signature file.
///
/// Returns None when the text is not a signature file or when a field of it
/// is not what it has to be.
pub fn signature_from_text(text : String) -> PackageSignature? {
  let lines = text_lines(text)
  if lines.length() < 5 {
    return None
  }
  if lines[0] != SIGNATURE_HEADER {
    return None
  }
  if lines[1] != "algorithm " + SIGNATURE_ALGORITHM {
    return None
  }
  let package_digest = lines[2]
  let manifest_digest = lines[3]
  let signature = lines[4]
  if !package_digest.has_prefix("package ") ||
    !manifest_digest.has_prefix("manifest ") ||
    !signature.has_prefix("signature ") {
    return None
  }
  Some(
    new_package_signature(
      package_digest["package ".length():].to_owned(),
      manifest_digest["manifest ".length():].to_owned(),
      signature["signature ".length():].to_owned(),
    ),
  )
}

///|
/// Does the signature hold for the package at `path`?
///
/// The digest of the package is computed again and compared with the digest
/// the signature was made over, and the signature itself is checked with
/// the public key. A package that was changed after it was signed does not
/// match the digest, and a signature that was made over another package
/// does not hold.
pub async fn verify_package_signature(
  path : String,
  sig : PackageSignature,
  public : Bytes,
) -> Bool {
  let data = @fs.read_binary(path)
  let digest = sha256_hex(data)
  if digest != sig.package_digest {
    println(
      "verify: the package does not have the digest the signature was made over",
    )
    return false
  }
  let digest_bytes = match hex_to_bytes(digest) {
    Some(b) => b
    None => return false
  }
  let signature = match hex_to_bytes(sig.signature) {
    Some(b) => b
    None => {
      println("verify: the signature is not hexadecimal")
      return false
    }
  }
  if !ed25519_verify(public, signature_message(digest_bytes), signature) {
    println("verify: the signature does not hold for the public key")
    return false
  }
  true
}

///|
/// Does the package at `path` have the digest `expected`?
///
/// The digest is the anchor that a host publishes next to a package. It
/// needs no key at all, so it works for a package that anybody may hold.
pub async fn verify_package_digest(path : String, expected : String) -> Bool {
  let data = @fs.read_binary(path)
  let digest = sha256_hex(data)
  if !same_hex(digest, expected.trim().to_owned()) {
    println(
      "verify: the package has the digest " +
      digest +
      ", but " +
      expected +
      " was expected",
    )
    return false
  }
  true
}
