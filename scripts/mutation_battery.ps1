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
  # The anchors are written in this file with LF endings, and this file keeps
  # CRLF on disk because `.gitattributes` says a `.ps1` does. The sources it
  # looks into are LF. A search for one inside the other therefore never
  # matches, and every anchor that spans more than one line looks as though it
  # had rotted away. The comparison is done on one ending, and the sources are
  # written back with LF, which is what they are stored as.
  $text = $backup -replace "`r`n", "`n"
  foreach ($pair in @(@($old1, $new1), @($old2, $new2))) {
    if ($pair[0] -eq "") { continue }
    $old = $pair[0] -replace "`r`n", "`n"
    $new = $pair[1] -replace "`r`n", "`n"
    if (-not $text.Contains($old)) {
      Write-Output "$label : ANCHOR NOT FOUND in $file"
      [System.IO.File]::WriteAllText($path, $backup, $enc)
      return
    }
    $text = $text.Replace($old, $new)
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
    }' `
  '    let data = @fs.read_binary(path)' `
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

# 14. A cache is handed out on its name rather than on what it holds.
#
# The folder arrives by a move, and the move is the one step whose result the
# launcher never looked at: with the read-back taken out, a folder that got
# only part of the payload is handed out as the cache of the package and the
# bundled program is started from it. That is what the reported crash was --
# a program that started and then could not load a library the move had left
# behind.
Run-Mutation 'L3 cache handover' 'launcher.mbt' `
  '  if cache_matches_reporting(m, dir, report) {
    return Some(dir)
  }' `
  '  if true {
    return Some(dir)
  }' `
  '' '' `
  'a cache that does not hold the payload is not handed out'

# 15. The console of the terminal is taken away with the console of the
# bundle.
#
# The bundle keeps the console subsystem, so a double-click gives it a console
# of its own; that one is taken away before a windowed program starts. The
# console of a terminal is the window the user is typing into, and with the
# decision taken out of the code the launcher cannot tell the two apart.
Run-Mutation 'console ownership' 'launcher.mbt' `
  '  if ids.length() != 1 {
    return false
  }
  ids[0] == own_pid
}' `
  '  true
}' `
  '' '' `
  'the console of the terminal is not taken away'

# 16. The bar says more is done than there is.
#
# The line counts bytes, and a count bigger than the total is what a package
# whose last file is bigger than the sum of the manifest would produce. Without
# the clamp the bar says 150% and reads as a defect in the unpacking.
Run-Mutation 'progress clamp' 'progress.mbt' `
  '  let p = done * 100L / total
  if p > 100L {
    return 100
  }
  p.to_int()' `
  '  let p = done * 100L / total
  p.to_int()' `
  '' '' `
  'the progress bar tells the truth about what is left'

# 17. Anything the console reports is taken for an answer.
#
# This is the defect 0.1.15 shipped. A console signals its input handle for a
# window that gained focus, for a window that was resized and for the mouse as
# well, and the wait in read_console_line is a wait on that handle. With the
# question "is this actually a key press" answered by "yes", the launcher goes
# on to ReadConsoleW, which in the line-input mode of a console waits for a
# whole line -- for ever, when nobody is typing. The countdown then never
# counts a second and a double-clicked bundle never starts on its own.
Run-Mutation 'console answer' 'launcher.mbt' `
  '    if kind == KEY_EVENT_TYPE && down && ch != 0 {
      return true
    }' `
  '    if true {
      return true
    }' `
  '' '' `
  'only a key press answers a question'

# 18. The folder flag is read under one spelling only.
#
# `--files` and `--Files` are one flag. A collector that reads only the
# capitalised spelling accepts the lowercase one as a known flag and then
# quietly bundles nothing from it -- the command succeeds and the payload is
# missing the folders the caller asked for.
Run-Mutation 'folder flag spelling' 'cli.mbt' `
  '    if f.0 == "Files" || f.0 == "files" {' `
  '    if f.0 == "Files" {' `
  '' '' `
  'the folder flag is read under both spellings'

# 19. A flag the tool reads is not a flag the tool knows.
#
# `build_options` reads `--os` and the README documents it, but the name was
# missing from the list of known flags for as long as the list has existed, so
# every command line that named it was refused as unknown and a package for
# another platform could not be made at all. The test that lists the flags the
# tool reads is what catches it -- and only if that list is complete, which is
# why the flag is written down in two places on purpose.
Run-Mutation 'platform flag' 'cli.mbt' `
  '    "input-exe", "input-file", "launcher", "name", "o", "os", "output", "output-exe",' `
  '    "input-exe", "input-file", "launcher", "name", "o", "output", "output-exe",' `
  '' '' `
  'the platform flag is a flag the tool knows'

Write-Output '--- the tree is back to what it was ---'
git -C $repo status --short
