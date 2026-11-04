// Unpack & verify logic: read a .appkg and extract it to a destination dir.

///|
/// Locate the archive inside an open file.
///
/// Returns the offset of the archive within the file and its manifest.
/// A plain package holds the archive at offset 0; an executable with an
/// appended archive holds it at the tail.
async fn locate_archive(file : @fs.File) -> (Int64, Manifest) {
  let total = file.size()
  if total < 24 {
    fail("not a LunaPack file (too small)")
  }
  let footer = file.read_exactly_at(24, position=total - 24)
  let mb = magic_bytes()
  let mut magic_ok = true
  let mut i = 0
  while i < 8 {
    if footer.at((i : Int32)) != mb.at((i : Int32)) {
      magic_ok = false
    }
    i = i + 1
  }
  if magic_ok {

  } else {
    fail("not a LunaPack file (bad magic)")
  }
  let moff = le8_to_i64(footer, 8)
  let mlen = le8_to_i64(footer, 16)
  // The archive is [magic][payload][manifest][footer], so its total length is
  // manifest_offset + manifest_length + footer_size.
  let archive_len = moff + mlen + 24
  let base = total - archive_len
  if base < 0 {
    fail("not a LunaPack file (bad magic)")
  }
  // The archive must start with the magic as well.
  let head = file.read_exactly_at(8, position=base)
  let mut head_ok = true
  i = 0
  while i < 8 {
    if head.at((i : Int32)) != mb.at((i : Int32)) {
      head_ok = false
    }
    i = i + 1
  }
  if head_ok {

  } else {
    fail("not a LunaPack file (bad magic)")
  }
  let mbytes = file.read_exactly_at(mlen.to_int(), position=base + moff)
  (base, json_to_manifest(utf8_bytes_to_string(mbytes)))
}

///|
/// Locate the archive inside `path`, when there is one.
///
/// Returns the offset of the archive and its manifest, or None when the file
/// carries no LunaPack archive.
pub async fn probe_archive(path : String) -> (Int64, Manifest)? {
  let file = @fs.open(path, mode=@fs.Mode::ReadOnly)
  defer file.close()
  try {
    let (base, m) = locate_archive(file)
    Some((base, m))
  } catch {
    _ => None
  }
}

///|
/// Read the manifest of a package file.
pub async fn read_package_manifest(pkg : String) -> Manifest {
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let (_, m) = locate_archive(file)
  m
}

///|
/// Fetch and (if needed) decompress the payload of one entry.
async fn entry_payload(file : @fs.File, e : Entry, base : Int64) -> Bytes {
  let stored = file.read_exactly_at(
    e.stored_size.to_int(),
    position=base + e.offset,
  )
  if e.codec == "gzip" {
    gzip_decompress(stored)
  } else {
    stored
  }
}

///|
/// Read the file at `path` back and confirm that its MD5 fingerprint is
/// still `expected`.
///
/// The payload is checked against the SHA-256 checksum while it is written,
/// but that only proves the bytes in the archive are intact. Reading the file
/// back from the disk proves that what landed on the disk is the same as what
/// went in, which is what the user asked for.
///
/// `expected` may be empty, in which case the file comes from a package that
/// was written before the MD5 fingerprint was stored.
async fn verify_written_file(path : String, expected : String) -> Unit {
  if expected == "" {
    return
  }
  let actual = md5_hex(@fs.read_file(path).binary())
  if actual != expected {
    fail(
      "md5 mismatch for " + path + ": expected " + expected + " got " + actual,
    )
  }
}

///|
/// Write every entry of `manifest` into `dest`, without printing anything.
async fn write_entries(
  file : @fs.File,
  manifest : Manifest,
  base : Int64,
  dest : String,
  host : String,
) -> Unit {
  for e in manifest.entries {
    let data = entry_payload(file, e, base)
    if sha256_hex(data) != e.checksum {
      fail("checksum mismatch for " + e.path)
    }
    if data.length().to_int64() != e.size {
      fail("size mismatch for " + e.path)
    }
    let out_path = dest + "/" + e.path
    mkdir_parent(dest, e.path)
    @fs.write_file(out_path, data, permission=e.mode)
    // `write_file`'s permission is subject to the umask, so set it explicitly.
    set_permissions(host, out_path, e.mode)
    // Read the file back and confirm that the fingerprint is unchanged.
    verify_written_file(out_path, e.md5)
  }
}

///|
/// Extract the payload of `pkg` into `dest` silently.
///
/// Used by the self-extracting launcher, which does not want to list every
/// file it writes.
pub async fn extract_to(pkg : String, dest : String) -> Unit {
  let dest = norm_sep(dest)
  @fs.mkdir(dest, recursive=true, allow_exist=true)
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let (base, manifest) = locate_archive(file)
  write_entries(file, manifest, base, dest, host_platform())
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
    let actual = md5_hex(@fs.read_file(out_path).binary())
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
pub async fn unpack(pkg : String, dest : String, run_scripts : Bool) -> Unit {
  let dest = norm_sep(dest)
  @fs.mkdir(dest, recursive=true, allow_exist=true)
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let (base, manifest) = locate_archive(file)
  let host = host_platform()
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
  for e in manifest.entries {
    let data = entry_payload(file, e, base)
    if sha256_hex(data) != e.checksum {
      fail("checksum mismatch for " + e.path)
    }
    if data.length().to_int64() != e.size {
      fail("size mismatch for " + e.path)
    }
    let out_path = dest + "/" + e.path
    mkdir_parent(dest, e.path)
    @fs.write_file(out_path, data, permission=e.mode)
    // `write_file`'s permission is subject to the umask, so set it explicitly.
    set_permissions(host, out_path, e.mode)
    println("  " + e.path)
    // Read the file back and confirm that the fingerprint is unchanged.
    verify_written_file(out_path, e.md5)
  }
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
  // still the one that went into the package.
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
  let (_base, manifest) = locate_archive(file)
  let dir = norm_sep(dir)
  let mut ok = true
  let mut checked = 0
  for e in manifest.entries {
    let out_path = dir + "/" + e.path
    if !@fs.exists(out_path) {
      println("verify: missing " + e.path)
      ok = false
      continue
    }
    let actual = md5_hex(@fs.read_file(out_path).binary())
    checked = checked + 1
    if e.md5 != "" && actual != e.md5 {
      println(
        "verify: md5 mismatch for " +
        e.path +
        ": expected " +
        e.md5 +
        " got " +
        actual,
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
pub async fn verify(pkg : String) -> Bool {
  let file = @fs.open(pkg, mode=@fs.Mode::ReadOnly)
  defer file.close()
  let (base, manifest) = locate_archive(file)
  for e in manifest.entries {
    let data = entry_payload(file, e, base)
    if sha256_hex(data) != e.checksum {
      println("verify: checksum mismatch for " + e.path)
      return false
    }
    if e.md5 != "" && md5_hex(data) != e.md5 {
      println("verify: md5 mismatch for " + e.path)
      return false
    }
    if data.length().to_int64() != e.size {
      println("verify: size mismatch for " + e.path)
      return false
    }
  }
  println("verify: OK (" + manifest.entries.length().to_string() + " files)")
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
