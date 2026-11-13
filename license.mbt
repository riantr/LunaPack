// Offline licensing.
//
// A package can say what it holds, but it cannot say who is allowed to use
// it. That claim has to come from the host, and it has to be a thing the
// host signed: a license is a short text the publisher signs with Ed25519
// and the reader checks with the public key. No server is contacted, so a
// machine that never reaches the network can still be checked.
//
// The signature covers every field of the license, in a fixed order, under
// a label of its own. A field that was changed, a field that was added and
// a license that was signed for something else all break the signature.
// What a signature cannot do is keep a reader from ignoring the check: the
// program has to ask, and it has to act on the answer.
//
// The machine binding is deliberately modest. The toolchain has no API for
// a hardware serial number, and one written with FFI would only work on one
// platform, so `local_machine_id` builds an identifier from what every
// platform has. It is stable and it is cheap, and it is also forgeable: it
// is a binding to an installation, not a hardware lock. A host that needs a
// stronger one passes its own identifier to `license_verify`.

///|
/// The label that a license signature is computed over.
///
/// As with the package signature, the label keeps a signature of a license
/// from being a signature of anything else that happens to have the same
/// bytes.
const LABEL_LICENSE_SIGNATURE : String = "lunapack-v1|license-signature"

///|
/// The first line of a license file.
pub const LICENSE_HEADER : String = "lunapack-license v1"

///|
/// The algorithm of a license file.
pub const LICENSE_ALGORITHM : String = "ed25519"

///|
/// The machine field of a license that is not bound to a machine.
pub const LICENSE_ANY_MACHINE : String = "*"

///|
/// An offline license.
///
/// `not_before` and `not_after` are epoch milliseconds; `0` means "no
/// limit". `machine` is the lowercase SHA-256 of an identifier, or `*`.
/// `features` is an opaque comma-separated list of labels: the publisher
/// decides what the names mean, and the reader asks for one of them.
pub struct License {
  subject : String
  machine : String
  not_before : Int64
  not_after : Int64
  features : String
  serial : String
  signature : String
}

///|
/// The answer to a license check.
///
/// A refusal always says why, because "invalid" is not a thing a caller can
/// act on: an expired license and one written for another machine need
/// different answers from the program that asked.
pub struct LicenseCheck {
  valid : Bool
  reason : String
  /// The labels of a license that was accepted, empty for one that was not.
  features : Array[String]
}

///|
/// Constructor so callers outside this file can build a license to sign.
pub fn new_license(
  subject : String,
  machine : String,
  not_before : Int64,
  not_after : Int64,
  features : String,
  serial : String,
) -> License {
  { subject, machine, not_before, not_after, features, serial, signature: "", }
}

///|
/// The fields of a license in the one order that is signed.
///
/// The signature line is not part of this: a signature cannot cover itself.
/// Everything else is, including the header and the algorithm, so a license
/// cannot be turned into a file of another format without breaking it.
/// The text fields are trimmed here, and not only when they are read back:
/// `text_lines` trims every line, so a field written with a leading or
/// trailing space would be read as a shorter one and the signature would no
/// longer be over the bytes it was made over.
pub fn license_payload(lic : License) -> String {
  let mut out = LICENSE_HEADER + "\n"
  out = out + "algorithm " + LICENSE_ALGORITHM + "\n"
  out = out + "subject " + lic.subject.trim().to_owned() + "\n"
  out = out + "machine " + lic.machine.trim().to_owned() + "\n"
  out = out + "not-before " + lic.not_before.to_string() + "\n"
  out = out + "not-after " + lic.not_after.to_string() + "\n"
  out = out + "features " + lic.features.trim().to_owned() + "\n"
  out = out + "serial " + lic.serial.trim().to_owned() + "\n"
  out
}

///|
/// The bytes the signature of a license is computed over.
fn license_message(lic : License) -> Bytes {
  bytes_concat(
    string_to_utf8_bytes(LABEL_LICENSE_SIGNATURE + "\n"),
    string_to_utf8_bytes(license_payload(lic)),
  )
}

///|
/// Sign a license with the secret key of a pair.
///
/// The signing seed is derived from the secret with a label of its own, so
/// the key that signs a license is not the key that opens a sealed package
/// and not the key that signs a package digest.
///
/// None is returned when a field would break the format or when the signer
/// refuses the key. A license that was not signed is never handed back as
/// one that was, because a reader cannot tell an empty signature from an old
/// format.
pub fn license_sign(lic : License, secret : Bytes) -> License? {
  // A line break in a field would add a line to the signed payload and let
  // a reader parse a different license than the one that was signed.
  if lic.subject.contains("\n") ||
    lic.subject.contains("\r") ||
    lic.machine.contains("\n") ||
    lic.machine.contains("\r") ||
    lic.features.contains("\n") ||
    lic.features.contains("\r") ||
    lic.serial.contains("\n") ||
    lic.serial.contains("\r") {
    return None
  }
  let signed = ed25519_sign(ed25519_seed(secret), license_message(lic)) catch {
    _ => return None
  }
  Some({
    subject: lic.subject,
    machine: lic.machine,
    not_before: lic.not_before,
    not_after: lic.not_after,
    features: lic.features,
    serial: lic.serial,
    signature: bytes_to_hex(signed),
  })
}

///|
/// The text of a license file.
///
/// A text, like the public key and the detached signature: a person can read
/// what it grants and a script can check it without a library.
pub fn license_to_text(lic : License) -> String {
  license_payload(lic) + "signature " + lic.signature + "\n"
}

///|
/// A decimal integer of ASCII digits, or None.
///
/// The timestamps of a license are written as decimal epoch milliseconds so
/// that a reader needs no calendar. Too many digits are refused rather than
/// wrapped: a license whose expiry overflowed into the past would look like
/// an expired one, not like a broken one.
pub fn parse_decimal(text : String) -> Int64? {
  if text.length() == 0 || text.length() > 18 {
    return None
  }
  let mut value : Int64 = 0L
  let mut i = 0
  while i < text.length() {
    let c = text[i].to_int()
    if c < 48 || c > 57 {
      return None
    }
    value = value * 10L + (c - 48).to_int64()
    i = i + 1
  }
  Some(value)
}

///|
/// The value of a line that starts with `name`, or None.
/// A field with no value is written as `"features "` and read back by
/// `text_lines` as just `"features"`, so the bare key is a value of its own
/// rather than a malformed line.
fn license_field(line : String, name : String) -> String? {
  if line == name.trim().to_owned() {
    return Some("")
  }
  if line.has_prefix(name) {
    Some(line[name.length():].trim().to_owned())
  } else {
    None
  }
}

///|
/// The license in the text of a license file.
///
/// The lines are read in a fixed order and every one of them has to be
/// there. A file with a reordered field is refused instead of being taken
/// for a license that says the same thing in another way: the order is a
/// part of what was signed.
pub fn license_from_text(text : String) -> License? {
  let lines = text_lines(text)
  if lines.length() < 9 {
    return None
  }
  if lines[0] != LICENSE_HEADER {
    return None
  }
  if lines[1] != "algorithm " + LICENSE_ALGORITHM {
    return None
  }
  let subject = match license_field(lines[2], "subject ") {
    Some(v) => v
    None => return None
  }
  let machine = match license_field(lines[3], "machine ") {
    Some(v) => v
    None => return None
  }
  let before = match license_field(lines[4], "not-before ") {
    Some(v) => v
    None => return None
  }
  let after = match license_field(lines[5], "not-after ") {
    Some(v) => v
    None => return None
  }
  let features = match license_field(lines[6], "features ") {
    Some(v) => v
    None => return None
  }
  let serial = match license_field(lines[7], "serial ") {
    Some(v) => v
    None => return None
  }
  let signature = match license_field(lines[8], "signature ") {
    Some(v) => v
    None => return None
  }
  let not_before = match parse_decimal(before) {
    Some(v) => v
    None => return None
  }
  let not_after = match parse_decimal(after) {
    Some(v) => v
    None => return None
  }
  match hex_to_bytes(signature) {
    Some(b) => if b.length() != 64 { return None }
    None => return None
  }
  Some({ subject, machine, not_before, not_after, features, serial, signature, })
}

///|
/// A refusal that names its reason.
fn license_denied(reason : String) -> LicenseCheck {
  { valid: false, reason, features: [], }
}

///|
/// Are two hexadecimal identifiers the same, whatever their case?
fn hex_equal(a : String, b : String) -> Bool {
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
/// Check a license against a public key, an installation and a clock.
///
/// `now_millis` is given rather than read here so that a check can be
/// tested at any date and so that a host with a trusted clock can supply
/// one. `machine_id` is ignored when the license is not bound to a machine.
///
/// The signature is checked first: a license that was edited must not be
/// reported as an expired one, because an expiry is a claim about a license
/// that was really issued.
pub fn license_verify(
  lic : License,
  public : Bytes,
  machine_id : String,
  now_millis : Int64,
) -> LicenseCheck {
  let signature = match hex_to_bytes(lic.signature) {
    Some(b) => b
    None => return license_denied("the signature is not hexadecimal")
  }
  if signature.length() != 64 {
    return license_denied("the signature has the wrong length")
  }
  // A malformed public key makes the verifier raise, not return false. A
  // check has to answer, so the refusal is stated like every other one.
  let holds = ed25519_verify(public, license_message(lic), signature) catch {
    _ => false
  }
  if !holds {
    return license_denied("the signature does not hold for the public key")
  }
  if lic.not_before > 0L && now_millis < lic.not_before {
    return license_denied("the license is not valid yet")
  }
  if lic.not_after > 0L && now_millis > lic.not_after {
    return license_denied("the license has expired")
  }
  if lic.machine != LICENSE_ANY_MACHINE {
    if machine_id == "" {
      return license_denied(
        "the license is bound to a machine but no identifier was given",
      )
    }
    if !hex_equal(lic.machine, machine_id) {
      return license_denied("the license was issued for another machine")
    }
  }
  { valid: true, reason: "ok", features: split_features(lic.features), }
}

///|
/// The labels of a comma-separated list of features.
///
/// An empty label is not a feature, so a trailing comma and a list of only
/// commas leave the list empty instead of granting something unnamed.
pub fn split_features(text : String) -> Array[String] {
  let out = []
  let mut start = 0
  let mut i = 0
  while i < text.length() {
    if text[i] == ',' {
      let part = text[start:i].trim().to_owned()
      if part != "" {
        out.push(part)
      }
      start = i + 1
    }
    i = i + 1
  }
  if start < text.length() {
    let last = text[start:].trim().to_owned()
    if last != "" {
      out.push(last)
    }
  }
  out
}

///|
/// Does an accepted license grant the label `name`?
pub fn license_has_feature(check : LicenseCheck, name : String) -> Bool {
  if !check.valid {
    return false
  }
  check.features.contains(name)
}

///|
/// The identifier built from a list of parts the host supplies.
///
/// The parts are joined with a separator that cannot appear in the digest,
/// so ["ab", "c"] and ["a", "bc"] do not name the same installation.
pub fn machine_id_of(parts : Array[String]) -> String {
  sha256_hex_of_string(parts.join("|"))
}

///|
/// The name of an environment variable, or "" when it is not set.
fn env_value(name : String) -> String {
  match @env.get_env_var(name) {
    Some(v) => v
    None => ""
  }
}

///|
/// The identifier of this installation.
///
/// It is built from what every platform has: the name of the host, the name
/// of the user, the operating system and the architecture. It is stable
/// across starts and it needs no FFI, which is what lets it compile for the
/// WebAssembly build too.
///
/// It is also forgeable, and it is not a hardware lock. A host that needs a
/// stronger binding collects its own identifier and passes it to
/// `license_verify`; the license only ever holds a digest of one.
pub fn local_machine_id() -> String {
  machine_id_of([
    env_value("COMPUTERNAME"),
    env_value("HOSTNAME"),
    env_value("USERNAME"),
    env_value("USER"),
    host_platform(),
    default_arch(),
  ])
}
