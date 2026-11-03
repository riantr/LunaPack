// LunaPack core: data model, package format, JSON & binary helpers.
// Package: riantr/LunaPack
//
// Package layout (v2):
//
//   [0..8)      magic "APPKGD02"
//   [8..)       entry payloads, stored back to back
//   [moff..)    manifest, UTF-8 JSON
//   last 24 B   footer: magic(8) + manifest_offset(8 LE) + manifest_length(8 LE)

///|
/// Magic marker at the head and inside the footer of every .appkg file.
/// v2 = SHA-256 checksums + optional gzip compression + install scripts.
pub const MAGIC : String = "APPKGD02"

///|
/// Format version recorded in the manifest.
pub const FORMAT_VERSION : Int32 = 2

///|
/// Checksum algorithm used for every entry payload.
pub const CHECKSUM_ALGO : String = "sha256"

// ---------------------------------------------------------------- UTF-8 ---

///|
/// Encode a String into UTF-8 bytes.
/// NOTE: MoonBit strings are UTF-16 internally, so `String::to_bytes` yields
/// UTF-16 and must not be used for on-disk data. The bundled `@utf8` codec
/// gives real UTF-8.
pub fn string_to_utf8_bytes(s : String) -> Bytes {
  @utf8.encode(s)
}

///|
/// Decode UTF-8 bytes into a String.
/// NOTE: `Bytes::to_string()` returns the debug representation `b'\x..'`,
/// not the decoded text, so it must not be used here.
pub fn utf8_bytes_to_string(bs : Bytes) -> String {
  @utf8.decode_lossy(bs[:])
}

///|
/// The 8 magic bytes that open the package and close the footer.
pub fn magic_bytes() -> Bytes {
  string_to_utf8_bytes(MAGIC)
}

// -------------------------------------------------------------- structs ---

///|
/// One file inside the package.
pub struct Entry {
  /// Path relative to the package root, always using '/' as separator.
  path : String
  /// UNIX permission bits (0o644 / 0o755). Ignored on Windows.
  mode : Int32
  /// Size of the original file in bytes.
  size : Int64
  /// Number of bytes this entry occupies inside the package.
  stored_size : Int64
  /// How the payload is stored: "raw" or "gzip".
  codec : String
  /// Lowercase hex SHA-256 of the ORIGINAL (decompressed) content.
  checksum : String
  /// Byte offset of the payload inside the package.
  offset : Int64
}

///|
/// An install script together with the platform it targets.
///
/// A package built on Windows can carry a Windows batch script while a
/// package built on Linux carries a POSIX shell script; the matching one is
/// executed at unpack time and the other is skipped.
pub struct Script {
  /// "windows", "linux", "macos", "posix" (linux+macos) or "any".
  platform : String
  /// The script body.
  body : String
}

///|
/// Constructor so other packages can build a Script.
pub fn new_script(platform : String, body : String) -> Script {
  { platform, body, }
}

///|
/// Package metadata plus the list of entries.
pub struct Manifest {
  format_version : Int32
  name : String
  version : String
  os : String
  arch : String
  checksum_algo : String
  /// Compression policy requested at pack time: "none", "gzip" or "auto".
  compression : String
  /// ISO-8601 UTC timestamp of creation.
  created_at : String
  /// Name of the entry that is the main program, empty if there is none.
  main_program : String
  /// Script executed in the destination directory before extraction.
  pre_install : Script?
  /// Script executed in the destination directory after extraction.
  post_install : Script?
  entries : Array[Entry]
}

///|
/// Options accepted by `pack`.
pub struct PackOptions {
  name : String
  version : String
  os : String
  arch : String
  pre_install : Script?
  post_install : Script?
  /// "none" | "gzip" | "auto"
  compression : String
  /// Name of the entry that is the main program, empty if there is none.
  main_program : String
}

///|
/// Constructor so callers in other packages can build PackOptions without
/// relying on cross-package struct literals (which MoonBit disallows).
pub fn new_pack_options(
  name : String,
  version : String,
  os : String,
  arch : String,
  pre_install : Script?,
  post_install : Script?,
  compression : String,
) -> PackOptions {
  {
    name,
    version,
    os,
    arch,
    pre_install,
    post_install,
    compression,
    main_program: "",
  }
}

///|
/// Return a copy of `opts` whose main program is `name`.
pub fn with_main_program(opts : PackOptions, name : String) -> PackOptions {
  {
    name: opts.name,
    version: opts.version,
    os: opts.os,
    arch: opts.arch,
    pre_install: opts.pre_install,
    post_install: opts.post_install,
    compression: opts.compression,
    main_program: name,
  }
}

///|
/// Return a copy of `opts` with the given metadata fields replaced.
pub fn with_defaults(
  opts : PackOptions,
  name : String,
  version : String,
  os : String,
  arch : String,
) -> PackOptions {
  {
    name,
    version,
    os,
    arch,
    pre_install: opts.pre_install,
    post_install: opts.post_install,
    compression: opts.compression,
    main_program: opts.main_program,
  }
}

// ----------------------------------------------------------------- JSON ---

///|
fn json_escape(s : String) -> String {
  let mut out = ""
  let mut i = 0
  while i < s.length() {
    let c = s[i]
    if c == '"' {
      out = out + "\\\""
    } else if c == '\\' {
      out = out + "\\\\"
    } else if c == '\n' {
      out = out + "\\n"
    } else if c == '\r' {
      out = out + "\\r"
    } else if c == '\t' {
      out = out + "\\t"
    } else {
      // `s[i]` yields a UTF-16 code unit; convert it back to a character.
      match c.to_int().to_char() {
        Some(x) => out = out + String::make(1, x)
        None => out = out + "?"
      }
    }
    i = i + 1
  }
  out
}

///|
/// Serialize an optional script as a nested JSON object.
fn script_to_json(o : Script?) -> String {
  match o {
    Some(sc) =>
      "{\"platform\":\"" +
      json_escape(sc.platform) +
      "\",\"body\":\"" +
      json_escape(sc.body) +
      "\"}"
    None => "null"
  }
}

///|
/// Serialize a manifest into the canonical UTF-8 JSON representation.
pub fn manifest_to_json(m : Manifest) -> String {
  let mut s = "{"
  s = s + "\"format_version\":" + m.format_version.to_string()
  s = s + ",\"name\":\"" + json_escape(m.name) + "\""
  s = s + ",\"version\":\"" + json_escape(m.version) + "\""
  s = s + ",\"os\":\"" + json_escape(m.os) + "\""
  s = s + ",\"arch\":\"" + json_escape(m.arch) + "\""
  s = s + ",\"checksum_algo\":\"" + json_escape(m.checksum_algo) + "\""
  s = s + ",\"compression\":\"" + json_escape(m.compression) + "\""
  s = s + ",\"created_at\":\"" + json_escape(m.created_at) + "\""
  s = s + ",\"main_program\":\"" + json_escape(m.main_program) + "\""
  s = s + ",\"pre_install\":" + script_to_json(m.pre_install)
  s = s + ",\"post_install\":" + script_to_json(m.post_install)
  s = s + ",\"entries\":["
  let mut i = 0
  while i < m.entries.length() {
    let e = m.entries[i]
    if i > 0 {
      s = s + ","
    }
    s = s + "{\"path\":\"" + json_escape(e.path) + "\""
    s = s + ",\"mode\":" + e.mode.to_string()
    s = s + ",\"size\":" + e.size.to_string()
    s = s + ",\"stored_size\":" + e.stored_size.to_string()
    s = s + ",\"codec\":\"" + json_escape(e.codec) + "\""
    s = s + ",\"checksum\":\"" + e.checksum + "\""
    s = s + ",\"offset\":" + e.offset.to_string()
    s = s + "}"
    i = i + 1
  }
  s = s + "]}"
  s
}

///|
/// Read a field out of a JSON object.
///
/// `Json::value` is deprecated; the pattern match is the recommended form.
fn json_field(obj : @builtin.Json, key : String) -> @builtin.Json? {
  match obj {
    Object(o) => o.get(key)
    _ => None
  }
}

///|
/// The string carried by a JSON node, if it is a string.
fn json_string(j : @builtin.Json) -> String? {
  match j {
    String(s) => Some(s)
    _ => None
  }
}

///|
/// The number carried by a JSON node, if it is a number.
fn json_number(j : @builtin.Json) -> Double? {
  match j {
    Number(n, ..) => Some(n)
    _ => None
  }
}

///|
/// The array carried by a JSON node, if it is an array.
fn json_array(j : @builtin.Json) -> Array[@builtin.Json]? {
  match j {
    Array(a) => Some(a)
    _ => None
  }
}

///|
/// Parse the manifest JSON back into a `Manifest`.
pub fn json_to_manifest(text : String) -> Manifest raise {
  let j = @json.parse(text) catch {
    err => fail("invalid manifest JSON: " + err.to_string())
  }
  let get_str = fn(obj : @builtin.Json, k : String) -> String raise {
    match json_field(obj, k) {
      Some(v) =>
        match json_string(v) {
          Some(x) => x
          None => fail("field " + k + " is not a string")
        }
      None => fail("missing field " + k)
    }
  }
  let get_str_def = fn(
    obj : @builtin.Json,
    k : String,
    dflt : String,
  ) -> String {
    match json_field(obj, k) {
      Some(v) =>
        match json_string(v) {
          Some(x) => x
          None => dflt
        }
      None => dflt
    }
  }
  let get_i64 = fn(obj : @builtin.Json, k : String) -> Int64 raise {
    match json_field(obj, k) {
      Some(v) =>
        match json_number(v) {
          Some(n) => n.to_int64()
          None => fail("field " + k + " is not a number")
        }
      None => fail("missing field " + k)
    }
  }
  let get_i64_def = fn(obj : @builtin.Json, k : String, dflt : Int64) -> Int64 {
    match json_field(obj, k) {
      Some(v) =>
        match json_number(v) {
          Some(n) => n.to_int64()
          None => dflt
        }
      None => dflt
    }
  }
  let get_int_def = fn(obj : @builtin.Json, k : String, dflt : Int32) -> Int32 {
    match json_field(obj, k) {
      Some(v) =>
        match json_number(v) {
          Some(n) => n.to_int()
          None => dflt
        }
      None => dflt
    }
  }
  let get_script = fn(obj : @builtin.Json, k : String) -> Script? {
    match json_field(obj, k) {
      Some(v) =>
        match json_field(v, "body") {
          Some(b) =>
            match json_string(b) {
              Some(body) => {
                let plat = match json_field(v, "platform") {
                  Some(p) =>
                    match json_string(p) {
                      Some(x) => x
                      None => "any"
                    }
                  None => "any"
                }
                Some(Script::{ platform: plat, body, })
              }
              None => None
            }
          None => None
        }
      None => None
    }
  }
  let entries_arr = match json_field(j, "entries") {
    Some(v) =>
      match json_array(v) {
        Some(a) => a
        None => fail("entries is not an array")
      }
    None => fail("missing entries")
  }
  let entries = []
  for e in entries_arr {
    let size = get_i64(e, "size")
    entries.push({
      path: get_str(e, "path"),
      mode: get_int_def(e, "mode", 0o644),
      size,
      stored_size: get_i64_def(e, "stored_size", size),
      codec: get_str_def(e, "codec", "raw"),
      checksum: get_str(e, "checksum"),
      offset: get_i64(e, "offset"),
    })
  }
  {
    format_version: get_i64_def(j, "format_version", 1L).to_int(),
    name: get_str_def(j, "name", "unknown"),
    version: get_str_def(j, "version", "0.0.0"),
    os: get_str_def(j, "os", "unknown"),
    arch: get_str_def(j, "arch", "unknown"),
    checksum_algo: get_str_def(j, "checksum_algo", "sha256"),
    compression: get_str_def(j, "compression", "none"),
    created_at: get_str_def(j, "created_at", ""),
    main_program: get_str_def(j, "main_program", ""),
    pre_install: get_script(j, "pre_install"),
    post_install: get_script(j, "post_install"),
    entries,
  }
}

// --------------------------------------------------------------- binary ---

///|
/// 8-byte little-endian encoding of an Int64 into Bytes.
pub fn i64_to_le8(v : Int64) -> Bytes {
  let buf = []
  let mut i = 0
  while i < 8 {
    buf.push(((v >> (i * 8)) & 0xffL).to_byte())
    i = i + 1
  }
  Bytes::from_array(buf)
}

///|
/// Read an 8-byte little-endian Int64 from `b` starting at byte `start`.
pub fn le8_to_i64(b : Bytes, start : Int32) -> Int64 {
  let mut v : Int64 = 0
  let mut i = 0
  while i < 8 {
    v = v | (b.at((start + i : Int32)).to_int64() << (i * 8))
    i = i + 1
  }
  v
}

// ----------------------------------------------------------------- time ---

///|
fn pad2(n : Int32) -> String {
  if n < 10 {
    "0" + n.to_string()
  } else {
    n.to_string()
  }
}

///|
fn pad4(n : Int32) -> String {
  if n < 10 {
    "000" + n.to_string()
  } else if n < 100 {
    "00" + n.to_string()
  } else if n < 1000 {
    "0" + n.to_string()
  } else {
    n.to_string()
  }
}

///|
/// Convert a day count since 1970-01-01 into a civil (y, m, d) date.
/// Uses Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z0 : Int64) -> (Int32, Int32, Int32) {
  let z = z0 + 719468
  let era = (if z >= 0 { z } else { z - 146096 }) / 146097
  let doe = z - era * 146097
  let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  let y = yoe + era * 400
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
  let mp = (5L * doy + 2L) / 153L
  let d = doy - (153L * mp + 2L) / 5L + 1L
  let m = if mp < 10L { mp + 3L } else { mp - 9L }
  let y = if m <= 2L { y + 1L } else { y }
  (y.to_int(), m.to_int(), d.to_int())
}

///|
/// Format epoch milliseconds as an ISO-8601 UTC timestamp, e.g.
/// 2026-11-03T14:35:55Z. (`@env.now()` reports milliseconds.)
pub fn iso8601_utc(epoch_millis : UInt64) -> String {
  let epoch_secs = epoch_millis / 1000UL
  let days = (epoch_secs / 86400UL).reinterpret_as_int64()
  let sod = (epoch_secs % 86400UL).reinterpret_as_int64()
  let (y, m, d) = civil_from_days(days)
  let hh = (sod / 3600).to_int()
  let mm = (sod % 3600 / 60).to_int()
  let ss = (sod % 60).to_int()
  pad4(y) +
  "-" +
  pad2(m) +
  "-" +
  pad2(d) +
  "T" +
  pad2(hh) +
  ":" +
  pad2(mm) +
  ":" +
  pad2(ss) +
  "Z"
}
