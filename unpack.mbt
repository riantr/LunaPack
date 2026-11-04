// Unpack & verify logic: read a .appkg and extract it to a destination dir.
//
// Reading a package is where the trust of the package is decided. A package
// that carries a manifest says what it holds, and a manifest that nobody
// checked is a manifest that whoever holds the file wrote. So everything
// that is read is checked, and everything that cannot be checked is
// refused:
//
//   * the archive itself has to be whole: the marker has to be there, the
//     footer has to point at a manifest that is inside the file and the
//     manifest has to be one that can be read;
//   * the manifest has to match the digest in the integrity block of the
//     package, and the MAC of that block has to hold when the package is
//     encrypted and the reader holds the key;
//   * the paths of the entries have to stay inside the destination.
//
// A file that is not a package at all is not an error: a program that is
// started with the wrong arguments is an ordinary program. A file that is a
// damaged package is an error, because a damaged package that is taken for
// something else is how a package that was cut short gets run.

///|
/// The number of bytes of the footer of a package.
const FOOTER_BYTES : Int64 = 24

///|
/// The integrity block of a package.
enum Integrity {
  /// The package is a legacy package: it carries no block.
  Legacy
  /// The block of a package that is not encrypted.
  Plain(Bytes)
  /// The block of an encrypted package.
  Sealed(Bytes)
}

///|
/// The archive of a package: where it is and what it says.
struct Archive {
  /// The offset of the archive inside the file.
  base : Int64
  /// The manifest of the archive.
  manifest : Manifest
  /// The bytes of the manifest.
  manifest_bytes : Bytes
  /// The offset of the manifest inside the archive.
  manifest_offset : Int64
  /// The length of the manifest.
  manifest_length : Int64
  /// The integrity block of the archive.
  integrity : Integrity
}

///|
/// The bytes of `block` from `start` up to `end`.
fn block_part(block : Bytes, start : Int32, end : Int32) -> Bytes {
  let out = FixedArray::make(end - start, b'\x00')
  let mut i = start
  while i < end {
    out[i - start] = block.at(i)
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// Do the first eight bytes of `data` hold the marker of a package?
fn has_marker(data : Bytes) -> Bool {
  if data.length() < 8 {
    return false
  }
  let mb = magic_bytes()
  let mut i = 0
  while i < 8 {
    if data.at(i) != mb.at(i) {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Does the file start with the marker of a package?
///
/// A file that does is a package that was cut short, and a file that does
/// not is simply not a package.
async fn carries_marker(file : @fs.File) -> Bool {
  if file.size() < 8 {
    return false
  }
  has_marker(file.read_exactly_at(8, position=0))
}

///|
/// The integrity block of the archive, if it carries one.
///
/// The block of an encrypted package and the block of a package that is not
/// encrypted have different lengths, and each of them is looked for where it
/// can be. A package that carries one therefore cannot be taken for a
/// package that carries the other.
async fn find_integrity(
  file : @fs.File,
  base : Int64,
  moff : Int64,
) -> Integrity {
  if moff >= INTEGRITY_BLOCK_BYTES_ENCRYPTED.to_int64() + 8L {
    let block = file.read_exactly_at(
      INTEGRITY_BLOCK_BYTES_ENCRYPTED,
      position=base + moff - INTEGRITY_BLOCK_BYTES_ENCRYPTED.to_int64(),
    )
    if is_integrity_block_encrypted(block) {
      return Sealed(block)
    }
  }
  if moff >= INTEGRITY_BLOCK_BYTES.to_int64() + 8L {
    let block = file.read_exactly_at(
      INTEGRITY_BLOCK_BYTES,
      position=base + moff - INTEGRITY_BLOCK_BYTES.to_int64(),
    )
    if is_integrity_block(block) {
      return Plain(block)
    }
  }
  Legacy
}

///|
/// Read the archive of an open file.
///
/// Every inconsistency is an error. A file that carries the marker of a
/// package is a package, and one that is damaged is refused instead of
/// being taken for something else.
async fn read_archive(file : @fs.File) -> Archive {
  let total = file.size()
  if total < FOOTER_BYTES {
    if carries_marker(file) {
      fail(
        "the file carries the marker of a LunaPack file, but it is too small to be one: it is damaged",
      )
    }
    fail("not a LunaPack file (too small)")
  }
  let footer = file.read_exactly_at(24, position=total - 24)
  if !has_marker(footer) {
    if carries_marker(file) {
      fail(
        "the file carries the marker of a LunaPack file, but its footer is damaged: it is damaged",
      )
    }
    fail("not a LunaPack file (bad magic)")
  }
  let moff = le8_to_i64(footer, 8)
  let mlen = le8_to_i64(footer, 16)
  if moff < 0L || mlen < 0L {
    fail("not a LunaPack file (bad footer)")
  }
  // The archive is [magic][payload][manifest][footer], so its total length is
  // manifest_offset + manifest_length + footer_size.
  let archive_len = moff + mlen + FOOTER_BYTES
  let base = total - archive_len
  if base < 0L {
    fail("not a LunaPack file (bad footer)")
  }
  // The archive must start with the magic as well.
  let head = file.read_exactly_at(8, position=base)
  if !has_marker(head) {
    fail("not a LunaPack file (bad magic)")
  }
  let mbytes = file.read_exactly_at(mlen.to_int(), position=base + moff)
  let manifest = json_to_manifest(utf8_bytes_to_string(mbytes))
  let integrity = find_integrity(file, base, moff)
  {
    base,
    manifest,
    manifest_bytes: mbytes,
    manifest_offset: moff,
    manifest_length: mlen,
    integrity,
  }
}

///|
/// May the path of an entry be written inside the destination?
///
/// A path has to be relative and has to stay inside the destination: a path
/// that walks up with ".." would write outside of it, and a path that names
/// a folder of the system would write into it.
fn is_safe_path(rel : String) -> Bool {
  if rel == "" {
    return false
  }
  if rel.has_prefix("/") {
    return false
  }
  // A drive letter names a place of its own.
  if rel.length() >= 2 && rel[1] == ':' {
    return false
  }
  // A backslash separates on Windows, so a path that holds one names a
  // place that this check cannot look at.
  if rel.contains("\\") {
    return false
  }
  // No part of the path may be "..".
  let mut start = 0
  let mut i = 0
  while i <= rel.length() {
    if i == rel.length() || rel[i] == '/' {
      if i - start == 2 && rel[start] == '.' && rel[start + 1] == '.' {
        return false
      }
      start = i + 1
    }
    i = i + 1
  }
  true
}

///|
/// Check that every path of the manifest stays inside the destination.
fn check_entry_paths(manifest : Manifest) -> Unit raise {
  for e in manifest.entries {
    if !is_safe_path(e.path) {
      fail(
        "the package holds the path \"" +
        e.path +
        "\", which does not stay inside the destination",
      )
    }
  }
}

///|
/// Check the manifest of the archive against the integrity block of the
/// package.
///
/// The digest of the manifest is checked whenever the package carries a
/// block. The MAC of the manifest is checked when the reader holds the key
/// of the package: a manifest that is not authenticated is a manifest that
/// whoever holds the file can write, and the key is what stops that for an
/// encrypted package.
///
/// A package that carries no block is a package of the old format. It is
/// read, but it is said out loud that its manifest was not checked.
fn verify_integrity(archive : Archive, key : PackageKey?) -> Unit raise {
  match archive.integrity {
    Legacy => {
      if key is Some(_) {
        fail(
          "the package is in the old format and carries no authenticated manifest: it cannot be opened with a key",
        )
      }
      println(
        "warning: the package is in the old format and carries no manifest authentication",
      )
    }
    Plain(block) => {
      let stored = block_part(
        block,
        INTEGRITY_MARKER_BYTES,
        INTEGRITY_MARKER_BYTES + INTEGRITY_DIGEST_BYTES,
      )
      let expected = manifest_digest(
        archive.manifest_offset,
        archive.manifest_length,
        archive.manifest_bytes,
      )
      if stored != expected {
        fail(
          "the manifest of the package does not match its digest: the package is damaged or was changed",
        )
      }
      if archive.manifest.encryption is Some(_) {
        fail(
          "the package says that it is encrypted, but it carries no authenticated manifest: the package was changed",
        )
      }
      if key is Some(_) {
        fail(
          "a key was given, but the package carries no authenticated manifest: the package was changed",
        )
      }
    }
    Sealed(block) => {
      let stored = block_part(
        block,
        INTEGRITY_MARKER_BYTES,
        INTEGRITY_MARKER_BYTES + INTEGRITY_DIGEST_BYTES,
      )
      let expected = manifest_digest(
        archive.manifest_offset,
        archive.manifest_length,
        archive.manifest_bytes,
      )
      if stored != expected {
        fail(
          "the manifest of the package does not match its digest: the package is damaged or was changed",
        )
      }
      if archive.manifest.encryption is None {
        fail(
          "the package carries an authenticated manifest, but it says that it is not encrypted: the package was changed",
        )
      }
      match key {
        None => fail("the package is encrypted and no key was given")
        Some(k) => {
          let stored_mac = block_part(
            block,
            INTEGRITY_MARKER_BYTES + INTEGRITY_DIGEST_BYTES,
            INTEGRITY_BLOCK_BYTES_ENCRYPTED,
          )
          let expected_mac = manifest_mac(
            k,
            archive.manifest_offset,
            archive.manifest_length,
            archive.manifest_bytes,
          )
          if stored_mac != expected_mac {
            fail(
              "the manifest of the package is not the one that was sealed: the package is damaged or was changed",
            )
          }
        }
      }
    }
  }
}

///|
/// Locate the archive inside `path`, when there is one.
///
/// Returns the offset of the archive and its manifest, or None when the file
/// carries no LunaPack archive at all.
///
/// A file that carries the marker of a LunaPack file but is damaged is an
/// error and not None: a damaged package is not the same thing as a file
/// that is not a package, and a caller that cannot tell the two apart would
/// take a damaged package for something else.
pub async fn probe_archive(path : String) -> (Int64, Manifest)? {
  let file = @fs.open(path, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let total = file.size()
  if total < 24 {
    if carries_marker(file) {
      fail(
        "the file carries the marker of a LunaPack file, but it is too small to be one: it is damaged",
      )
    }
    return None
  }
  let footer = file.read_exactly_at(24, position=total - 24)
  if !has_marker(footer) {
    if carries_marker(file) {
      fail(
        "the file carries the marker of a LunaPack file, but its footer is damaged: it is damaged",
      )
    }
    return None
  }
  let archive = read_archive(file)
  Some((archive.base, archive.manifest))
}

///|
/// Read the manifest of a package file.
pub async fn read_package_manifest(pkg : String) -> Manifest {
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let archive = read_archive(file)
  archive.manifest
}

///|
/// The SHA-256 of the manifest of a package, hex.
pub async fn package_manifest_digest(pkg : String) -> String {
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let archive = read_archive(file)
  sha256_hex(archive.manifest_bytes)
}

///|
/// Fetch and (if needed) decrypt and decompress the payload of one entry.
///
/// The index of the entry is part of its seal, so it has to be the place the
/// entry has in the manifest.
async fn entry_payload(
  file : @fs.File,
  e : Entry,
  base : Int64,
  index : Int32,
  key : PackageKey?,
) -> Bytes {
  let stored = file.read_exactly_at(
    e.stored_size.to_int(),
    position=base + e.offset,
  )
  let plain = match key {
    Some(k) =>
      match open_entry(k, index, e.path, stored) {
        Some(d) => d
        None =>
          fail(
            "the seal of " +
            e.path +
            " does not hold: the key is wrong, or the package is damaged",
          )
      }
    None => stored
  }
  if e.codec == "gzip" {
    gzip_decompress(plain)
  } else if e.codec == "lz4" {
    lz4_decompress_frame(plain, e.size.to_int())
  } else {
    plain
  }
}

///|
/// Read the file at `path` back and confirm that it is still the file the
/// package carries.
///
/// The payload is checked against the SHA-256 checksum while it is written,
/// but that only proves that the bytes in the archive are intact. Reading
/// the file back from the disk proves that what landed on the disk is the
/// same as what went in, which is what the user asked for.
///
/// Two algorithms that are independent of each other are used, and each of
/// them is computed twice, so that a fault in the machine is not mistaken
/// for a fault in the package.
///
/// `expected_md5` may be empty, in which case the file comes from a package
/// that was written before the MD5 fingerprint was stored.
async fn verify_written_file(
  path : String,
  expected_md5 : String,
  expected_sha256 : String,
) -> Unit {
  let data = @fs.read_binary(path)
  if expected_sha256 != "" && redundant_sha256(data) != expected_sha256 {
    fail("checksum mismatch for the file that was written: " + path)
  }
  if expected_md5 != "" && redundant_md5(data) != expected_md5 {
    fail(
      "md5 mismatch for the file that was written: " +
      path +
      ": expected " +
      expected_md5 +
      " got " +
      md5_hex(data),
    )
  }
}

///|
/// Write a file without ever showing a half-written one.
///
/// The content goes into a file of its own next to the target, it is
/// flushed to the disk, and only then does it take the place of the target.
/// A reader therefore sees either the old file or the new one, and never a
/// file that was cut short.
async fn write_file_atomic(
  path : String,
  data : Bytes,
  mode : Int32,
  host : String,
) -> Unit {
  let tmp = path + ".lunapack-tmp"
  let file = @fs.create(tmp, allow_existing=true, permission=mode)
  file.write(data)
  file.sync()
  file.close()
  // `write_binary`'s permission is subject to the umask, so set it explicitly.
  set_permissions(host, tmp, mode)
  @fs.rename(tmp, path, replace=true)
}

///|
/// Write every entry of `manifest` into `dest`, without printing anything.
async fn write_entries(
  file : @fs.File,
  archive : Archive,
  dest : String,
  host : String,
  key : PackageKey?,
) -> Unit {
  let mut index = 0
  for e in archive.manifest.entries {
    let data = entry_payload(file, e, archive.base, index, key)
    index = index + 1
    if redundant_sha256(data) != e.checksum {
      fail("checksum mismatch for " + e.path)
    }
    if data.length().to_int64() != e.size {
      fail("size mismatch for " + e.path)
    }
    let out_path = dest + "/" + e.path
    mkdir_parent(dest, e.path)
    write_file_atomic(out_path, data, e.mode, host)
    // Read the file back and confirm that the fingerprint is unchanged.
    verify_written_file(out_path, e.md5, e.checksum)
  }
}

///|
/// Check every entry of the package against its checksum, without writing
/// anything.
///
/// This is what runs before the install scripts of a package: a script must
/// not run for a package whose payload is damaged.
async fn verify_entries(
  file : @fs.File,
  archive : Archive,
  key : PackageKey?,
) -> Bool {
  let mut index = 0
  for e in archive.manifest.entries {
    let data = entry_payload(file, e, archive.base, index, key)
    index = index + 1
    if redundant_sha256(data) != e.checksum {
      println("verify: checksum mismatch for " + e.path)
      return false
    }
    if e.md5 != "" && redundant_md5(data) != e.md5 {
      println("verify: md5 mismatch for " + e.path)
      return false
    }
    if data.length().to_int64() != e.size {
      println("verify: size mismatch for " + e.path)
      return false
    }
  }
  true
}

///|
/// Extract the payload of `pkg` into `dest` silently.
///
/// Used by the self-extracting launcher, which does not want to list every
/// file it writes.
pub async fn extract_to(pkg : String, dest : String, key : PackageKey?) -> Unit {
  let dest = norm_sep(dest)
  @fs.mkdir(dest, recursive=true, allow_exist=true)
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let archive = read_archive(file)
  verify_integrity(archive, key)
  check_entry_paths(archive.manifest)
  write_entries(file, archive, dest, host_platform(), key)
}

///|
/// Re-read every extracted file and confirm that its MD5 fingerprint is
/// still the one that went into the package.
///
/// The payload is checked against the SHA-256 checksum while it is written,
/// but that only proves the bytes in the archive are intact. Reading the
/// files back from the disk proves that what landed on the disk is the same
/// as what went in, which is what the user asked for.
///
/// Returns the number of files whose fingerprint did not match.
async fn verify_extracted_md5(manifest : Manifest, dest : String) -> Int32 {
  let mut mismatches = 0
  let mut checked = 0
  for e in manifest.entries {
    let out_path = dest + "/" + e.path
    if !@fs.exists(out_path) {
      println("  md5 MISMATCH  " + e.path + "  (file is missing)")
      mismatches = mismatches + 1
      continue
    }
    let data = @fs.read_binary(out_path)
    let actual = redundant_md5(data)
    checked = checked + 1
    if e.md5 != "" && actual != e.md5 {
      println(
        "  md5 MISMATCH  " + e.path + "  expected " + e.md5 + " got " + actual,
      )
      mismatches = mismatches + 1
    } else {
      println("  md5  " + actual + "  " + e.path)
    }
  }
  println(
    "verified " +
    checked.to_string() +
    " files, " +
    mismatches.to_string() +
    " mismatches",
  )
  mismatches
}

///|
/// Extract a package into `dest`.
///
/// `run_scripts` controls whether the embedded pre_install / post_install
/// scripts are executed.
pub async fn unpack(
  pkg : String,
  dest : String,
  run_scripts : Bool,
  key : PackageKey?,
) -> Unit {
  let dest = norm_sep(dest)
  @fs.mkdir(dest, recursive=true, allow_exist=true)
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let archive = read_archive(file)
  verify_integrity(archive, key)
  check_entry_paths(archive.manifest)
  let manifest = archive.manifest
  if manifest.encryption is Some(_) && key is None {
    fail("the package is encrypted and no key was given")
  }
  let host = host_platform()
  // The scripts of a package run before the payload is in place, so the
  // payload is checked first: a script must not run for a package whose
  // payload is damaged.
  if run_scripts &&
    (manifest.pre_install is Some(_) || manifest.post_install is Some(_)) {
    if !verify_entries(file, archive, key) {
      fail("the payload of the package is damaged: no script was run")
    }
  }
  // pre_install runs before the payload is written.
  if run_scripts {
    match manifest.pre_install {
      Some(sc) =>
        if script_applies(sc.platform, host) {
          println("running pre_install script (" + sc.platform + ")...")
          let st = run_install_script(host, "pre_install", sc, dest)
          if st != 0 {
            fail("pre_install script failed with exit code " + st.to_string())
          }
        } else {
          println("skipping pre_install script for " + sc.platform)
        }
      None => ()
    }
  }
  write_entries(file, archive, dest, host, key)
  // post_install runs once every file is in place.
  if run_scripts {
    match manifest.post_install {
      Some(sc) =>
        if script_applies(sc.platform, host) {
          println("running post_install script (" + sc.platform + ")...")
          let st = run_install_script(host, "post_install", sc, dest)
          if st != 0 {
            fail("post_install script failed with exit code " + st.to_string())
          }
        } else {
          println("skipping post_install script for " + sc.platform)
        }
      None => ()
    }
  }
  println(
    "unpacked " + manifest.entries.length().to_string() + " files -> " + dest,
  )
  // Read the extracted files back and confirm that every MD5 fingerprint is
  // still the one that went into the package. This is the scan the user asked
  // for, and it covers every file, so the files are not read back twice.
  let mismatches = verify_extracted_md5(manifest, dest)
  if mismatches > 0 {
    fail(
      "md5 mismatch for " + mismatches.to_string() + " file(s) after unpacking",
    )
  }
}

///|
/// Check the files in `dir` against the manifest of `pkg`.
///
/// This audits what is already on the disk, which is what the user asked
/// for: the files that were extracted must still carry the fingerprint they
/// had in the package. It works on a folder that was filled by `unpack` and
/// on the cache folder of a self-extracting bundle.
///
/// Returns false when a file is missing or its fingerprint changed.
pub async fn verify_extracted_dir(pkg : String, dir : String) -> Bool {
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let archive = read_archive(file)
  let dir = norm_sep(dir)
  let mut ok = true
  let mut checked = 0
  for e in archive.manifest.entries {
    let out_path = dir + "/" + e.path
    if !@fs.exists(out_path) {
      println("verify: missing " + e.path)
      ok = false
      continue
    }
    let data = @fs.read_binary(out_path)
    checked = checked + 1
    if e.md5 != "" && redundant_md5(data) != e.md5 {
      println(
        "verify: md5 mismatch for " +
        e.path +
        ": expected " +
        e.md5 +
        " got " +
        md5_hex(data),
      )
      ok = false
    }
  }
  if ok {
    println("verify: OK (" + checked.to_string() + " files in " + dir + ")")
  } else {
    println("verify: FAILED (" + checked.to_string() + " files checked)")
  }
  ok
}

///|
/// Check every entry of a package: magic, sizes, SHA-256 and MD5 digests.
pub async fn verify(pkg : String, key : PackageKey?) -> Bool {
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let archive = read_archive(file)
  verify_integrity(archive, key)
  check_entry_paths(archive.manifest)
  if archive.manifest.encryption is Some(_) && key is None {
    fail("the package is encrypted and no key was given")
  }
  let mut index = 0
  for e in archive.manifest.entries {
    let data = entry_payload(file, e, archive.base, index, key)
    index = index + 1
    if redundant_sha256(data) != e.checksum {
      println("verify: checksum mismatch for " + e.path)
      return false
    }
    if e.md5 != "" && redundant_md5(data) != e.md5 {
      println("verify: md5 mismatch for " + e.path)
      return false
    }
    if data.length().to_int64() != e.size {
      println("verify: size mismatch for " + e.path)
      return false
    }
  }
  println(
    "verify: OK (" + archive.manifest.entries.length().to_string() + " files)",
  )
  true
}

///|
/// Create every missing parent directory of `rel` under `dest`.
async fn mkdir_parent(dest : String, rel : String) -> Unit {
  let mut i = rel.length() - 1
  while i >= 0 {
    if rel[i] == '/' {
      break
    }
    i = i - 1
  }
  if i > 0 {
    let dir_rel = rel[:i].to_owned()
    let d = dest + "/" + dir_rel
    @fs.mkdir(d, recursive=true, allow_exist=true)
  }
}
