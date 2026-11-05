# The mutation battery of LunaPack.
#
# A test that passes because the guard is not there says nothing. This script
# takes every guard of the integrity stack out of the code once, runs the
# suite again and checks that the test which covers that guard goes red.
#
# The file it changed is restored afterwards, so a run leaves the tree exactly
# as it was.
#
# It is a development tool and not part of the build: the gates of the
# repository do not run it, because a gate that fails when a guard is missing
# is a gate that has to be told which guard is missing.

$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$env:PATH = "D:\Program Files\Git\bin;" + $env:PATH
$enc = New-Object System.Text.UTF8Encoding($false)

function Run-Mutation {
  param(
    [string]$label,
    [string]$file,
    [string]$old1,
    [string]$new1,
    [string]$old2,
    [string]$new2,
    [string]$expect
  )
  $path = Join-Path $repo $file
  $backup = [System.IO.File]::ReadAllText($path)
  $text = $backup
  foreach ($pair in @(@($old1, $new1), @($old2, $new2))) {
    if ($pair[0] -eq "") { continue }
    if (-not $text.Contains($pair[0])) {
      Write-Output "$label : ANCHOR NOT FOUND in $file"
      [System.IO.File]::WriteAllText($path, $backup, $enc)
      return
    }
    $text = $text.Replace($pair[0], $pair[1])
  }
  [System.IO.File]::WriteAllText($path, $text, $enc)
  $out = (moon -C $repo test --target native 2>&1) | Out-String
  $summary = ([regex]::Match($out, 'Total tests: \d+, passed: \d+, failed: \d+')).Value
  $red = $out.Contains($expect)
  $status = if ($red) { 'RED as expected' } else { '*** DID NOT GO RED ***' }
  Write-Output "$label : $status | $summary"
  [System.IO.File]::WriteAllText($path, $backup, $enc)
}

# 1. The digest of the manifest is not checked.
Run-Mutation 'L1 digest' 'unpack.mbt' `
  '      if stored != expected {
        fail(
          "the manifest of the package does not match its digest: the package is damaged or was changed",
        )
      }
      if archive.manifest.encryption is Some(_) {' `
  '      if archive.manifest.encryption is Some(_) {' `
  '' '' `
  'a package whose manifest was changed is refused'

# 2. The MAC of the manifest is not checked.
Run-Mutation 'L2 mac' 'unpack.mbt' `
  '          if stored_mac != expected_mac {
            fail(
              "the manifest of the package is not the one that was sealed: the package is damaged or was changed",
            )
          }
' `
  '' `
  '' '' `
  'a sealed package whose manifest was changed is refused'

# 3. The cache is used again even when it was changed.
Run-Mutation 'L3 cache' 'launcher.mbt' `
  '    let data = @fs.read_binary(path)
    if redundant_sha256(data) != e.checksum {
      return false
    }
  }
  true
}' `
  '    let data = @fs.read_binary(path)
  }
  true
}' `
  '' '' `
  'the cache is only used again when it holds what the package carries'

# 4. The program of the bundle is started even when it was changed.
Run-Mutation 'L3 program' 'launcher.mbt' `
  '    return redundant_sha256(data) == e.checksum' `
  '    return true' `
  '' '' `
  'the program of a bundle is checked before it is started'

# 5. A damaged package is taken for a file that is not a package.
Run-Mutation 'L4 fail closed' 'unpack.mbt' `
  '    if carries_marker(file) {
      fail(
        "the file carries the marker of a LunaPack file, but its footer is damaged: it is damaged",
      )
    }
    return None' `
  '    if carries_marker(file) {
      return None
    }
    return None' `
  '' '' `
  'a damaged package is not taken for a file that is not a package'

# 6. The package is written in place instead of in one piece.
Run-Mutation 'L5 atomic' 'pack.mbt' `
  '  let tmp = output + ".lunapack-tmp"
  @fs.remove(tmp, allow_missing=true)
  errdefer @fs.remove(tmp, allow_missing=true)' `
  '  let tmp = output
  @fs.remove(tmp, allow_missing=true)' `
  '  @fs.rename(tmp, output, replace=true)
  manifest
}' `
  '  manifest
}' `
  'a pack that fails leaves the target alone'

# 7. The checksum is not compared with itself.
Run-Mutation 'L6 redundancy' 'integrity.mbt' `
  '  if first != second {
    fail(
      "the checksum of the data was not the same twice: the machine is not reliable",
    )
  }
' `
  '' `
  '' '' `
  'a checksum that is not the same twice is refused'

# 8. The signature is not checked.
Run-Mutation 'L7 signature' 'signature.mbt' `
  '  if !ed25519_verify(public, signature_message(digest_bytes), signature) {
    println("verify: the signature does not hold for the public key")
    return false
  }
' `
  '' `
  '' '' `
  'a signature does not hold for another public key'

# 9. The paths of the entries are not checked.
Run-Mutation 'path safety' 'unpack.mbt' `
  '  verify_integrity(archive, key)
  check_entry_paths(archive.manifest)' `
  '  verify_integrity(archive, key)' `
  '' '' `
  'a path that walks out of the destination is refused'

# 10. The signing key of a pair is the encryption key.
#
# This is the defect that the Linux end-to-end suite found in 0.1.8: the
# public key file held the key a package is sealed to, and the signature was
# checked against a key that was not the one that made it. The chain that the
# command line walks is held here, so that it does not depend on a host with
# a POSIX shell.
Run-Mutation 'L7 key pair' 'keystore.mbt' `
  '  {
    encryption: x25519_public_key(secret),
    signing: ed25519_public_key(ed25519_seed(secret)),
  }' `
  '  {
    encryption: x25519_public_key(secret),
    signing: x25519_public_key(secret),
  }' `
  '' '' `
  'the signing key of a pair checks a signature made with it'

# 11. The signing key is not separated from the encryption key.
Run-Mutation 'L7 separation' 'keystore.mbt' `
  '  hkdf_sha512(
    secret,
    zero_bytes(SHA512_BYTES),
    string_to_utf8_bytes(LABEL_SIGNING_SEED),
    KEY_BYTES,
  )' `
  '  secret' `
  '' '' `
  'the two roles of a pair are separated'

# 12. The archive of a refused bundle is left behind.
#
# The archive is written before the launcher is looked at, so the cleanup has
# to cover it from that point on. With the cleanup taken out, a bundle that
# fails leaves `*.lunapack-archive.tmp` in the directory it was asked to
# write to -- a file from a bundle that was never made.
Run-Mutation 'L5 archive cleanup' 'pack.mbt' `
  '  @fs.remove(tmp, allow_missing=true)
  // The archive is written before the launcher is looked at, so the cleanup
  // has to reach it from that point on: a launcher that turns out to be
  // missing leaves the archive behind otherwise, and a directory that keeps
  // a file from a bundle that was never made is exactly the mess the
  // write-in-one-piece rule exists to prevent.
  errdefer @fs.remove(tmp, allow_missing=true)
  let m = write_archive(items, tmp, opts2, None)' `
  '  @fs.remove(tmp, allow_missing=true)
  let m = write_archive(items, tmp, opts2, None)' `
  '' '' `
  'a refused bundle leaves nothing behind'

# 13. A bundle that cannot start on its own is not reported as one.
#
# The two files look the same from the outside -- same name, same size, a
# whole payload inside -- and what tells them apart is the warning. It is the
# last line now, so that a list of a few hundred checksums cannot hide it.
Run-Mutation 'L4 self-extracting' 'pack.mbt' `
  '  output + " does not start on its own: it carries the payload but no launcher"' `
  '  output + " is fine"' `
  '' '' `
  'the two kinds of bundle are told apart'

Write-Output '--- the tree is back to what it was ---'
git -C $repo status --short
