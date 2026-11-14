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

# A run can be narrowed to some of the mutations, which is what one does when
# a single guard has to be looked at again:
#   $env:LUNAPACK_MUTATIONS = 'api set rule,known dll rule'
$script:only = if ($env:LUNAPACK_MUTATIONS) {
  $env:LUNAPACK_MUTATIONS.Split(',') | ForEach-Object { $_.Trim() }
} else {
  @()
}

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
  if ($script:only.Count -gt 0 -and -not ($script:only -contains $label)) {
    return
  }
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
  '    "input-exe", "input-file", "launcher", "name", "no-auto-deps", "o", "os", "output",' `
  '    "input-exe", "input-file", "launcher", "name", "no-auto-deps", "o", "output",' `
  '' '' `
  'the platform flag is a flag the tool knows'

# 20. The check of a cache that is used again is not reported.
#
# The cache of a bundle is checked against the package on every start, and
# that check reads the whole payload back from the disk: it is half of what a
# warm start spends its time on. With the reporter taken out of it, a warm
# start draws nothing while it reads a hundred megabytes back, and a start
# that says nothing looks like a start that hangs.
Run-Mutation 'warm check report' 'launcher.mbt' `
  '  if path_exists(marker) && cache_matches_reporting(m, dir, verify_report) {' `
  '  if path_exists(marker) && cache_matches_reporting(m, dir, None) {' `
  '' '' `
  'the files of a cache that is used again are counted one by one'

# 21. The cache of a bundle is a folder of its own on every start.
#
# The folder next to the executable cannot always be written to, and the
# payload goes to the cache of the user then. That folder has to be the same
# on every start: `@fs.tmpdir` makes a folder of its own on every call and
# never uses one twice, so a payload kept there is unpacked again on the next
# start, and the unpacking is the whole cost of a start.
Run-Mutation 'stable fallback cache' 'launcher.mbt' `
  '  fallback_cache_dir(tag)' `
  '  @fs.tmpdir(prefix="lunapack-" + tag)' `
  '' '' `
  'the cache of a bundle that cannot be written next to it is found again'

# 22. The import table of the program is not read.
#
# A Windows program is not one file: it is the executable and the libraries it
# loads. The names of those libraries are written in the import table of the
# executable, and a bundle that does not read that table carries the program
# alone. The bundle then starts and stops with STATUS_DLL_NOT_FOUND.
Run-Mutation 'import table' 'pe.mbt' `
  '  let (rva, _size) = data_dir(data, 1)' `
  '  let (rva, _size) = data_dir(data, 2)' `
  '' '' `
  'the import table of a PE image names the libraries it imports'

# 23. The libraries that are loaded later are not read.
#
# A program that loads a library when it needs it writes the name into the
# delay-load directory and not into the import directory, and such a program
# cannot start without that library either.
Run-Mutation 'delay load table' 'pe.mbt' `
  '  let (rva, _size) = data_dir(data, 13)' `
  '  let (rva, _size) = data_dir(data, 12)' `
  '' '' `
  'the libraries that are loaded later are named as well'

# 24. The name of an API set is taken for a library of the program.
#
# An API set is a virtual library: there is no such file on the disk, and the
# system resolves the name when the program starts. A bundle that carries one
# carries nothing.
Run-Mutation 'api set rule' 'deps.mbt' `
  '      if is_api_set_dll(name) {
        continue
      }' `
  '      if false {
        continue
      }' `
  '' '' `
  'a library of the system next to the program is left out'

# 25. The name of a library of the system is taken for a library of the
# program.
#
# The system loads these from its own copy, whatever the program carries next
# to itself, so the file next to the program is never the one that is used.
Run-Mutation 'known dll rule' 'deps.mbt' `
  '      if is_known_dll(name) {
        continue
      }' `
  '      if false {
        continue
      }' `
  '' '' `
  'a library of the system next to the program is left out'

# 26. A library that is not next to the program is carried as well.
#
# A library that is not next to the program is either part of the system or
# one the program finds somewhere else, and neither is something a bundle can
# carry: the bundle has no way of putting it where the program looks for it.
Run-Mutation 'libraries beside the program' 'deps.mbt' `
  '      match find_in(files, name) {' `
  '      match Some(name) {' `
  '' '' `
  'a library that is not next to the program is not carried'

# 27. The libraries of a library are not looked for.
#
# A library needs libraries of its own, and they sit next to it. A bundle
# that carries the program and the library it names, but not the library that
# the library names, fails on the second one.
Run-Mutation 'transitive libraries' 'deps.mbt' `
  '          out.push(path)
          // A library needs libraries of its own, and they are looked for in
          // the same folder: that is where Windows looks for them too.
          queue.push(path)' `
  '          out.push(path)' `
  '' '' `
  'the libraries of a library are found as well'

# 28. A file is not found when the case of the letters is different.
#
# The name in an import table is spelled the way the library was built, and
# the file on the disk may be spelled differently: Windows does not care
# about the case.
Run-Mutation 'name case' 'deps.mbt' `
  '  for f in files {
    if same_name(f, name) {
      return Some(f)
    }
  }
  None' `
  '  None' `
  '' '' `
  'a library is found whatever the case of the file is'

# 29. The libraries the program needs are not carried in the bundle.
#
# The bundle is built from the program, the folders the caller named and the
# libraries the program needs. A bundle that leaves the libraries out starts
# and stops with STATUS_DLL_NOT_FOUND.
Run-Mutation 'libraries in the bundle' 'pack.mbt' `
  '  for f in extra_files {
    let name = basename(f)
    if item_path_taken(items, name) {
      continue
    }
    items.push((f, name))
  }' `
  '  for f in extra_files {
    let name = basename(f)
    if item_path_taken(items, name) {
      continue
    }
  }' `
  '' '' `
  'the libraries next to the program are carried in the bundle'

# 30. The libraries are not carried next to the program.
#
# The program looks for its libraries next to itself, so a library that is
# carried somewhere else in the bundle is a library the program does not find.
Run-Mutation 'libraries beside the program in the bundle' 'pack.mbt' `
  '    items.push((f, name))' `
  '    items.push((f, "libs/" + name))' `
  '' '' `
  'the libraries next to the program are carried in the bundle'

# 31. The flag that says "do not add the libraries" is ignored.
#
# The flag is the way out for a program whose libraries are not the ones the
# bundle should carry, and a bundle that ignores it carries files the caller
# did not ask for.
Run-Mutation 'no auto deps flag' 'cli.mbt' `
  '  if flag_has(flags, "no-auto-deps") {
    return []
  }' `
  '  if false {
    return []
  }' `
  '' '' `
  'the flag --no-auto-deps leaves the libraries out'

# 32. The flag is not a flag the tool knows.
#
# A flag that is not known is refused, and a flag that is refused is a command
# that cannot be run at all.
Run-Mutation 'no auto deps known' 'cli.mbt' `
  '    "input-exe", "input-file", "launcher", "name", "no-auto-deps", "o", "os", "output",' `
  '    "input-exe", "input-file", "launcher", "name", "o", "os", "output",' `
  '' '' `
  'the flag --no-auto-deps is a flag the tool knows'

# 33. A library that the caller named is carried twice.
#
# The file the caller named comes first, and it is the one that is kept: two
# entries with the same name in the archive fight over the same file when the
# bundle is unpacked.
Run-Mutation 'no duplicate library' 'pack.mbt' `
  '    if item_path_taken(items, name) {
      continue
    }' `
  '    if false {
      continue
    }' `
  '' '' `
  'a library that the caller named is not carried twice'

# 34. A folder that is named like a library is carried.
#
# The name in an import table says nothing about what is on the disk: a folder
# can be named like a library. A folder is not a library, and carrying it
# fails when the bundle is made.
Run-Mutation 'folder is not a library' 'deps.mbt' `
  '          if !is_regular_file(path) {
            continue
          }' `
  '          if false {
            continue
          }' `
  '' '' `
  'a folder named like a library is not carried'

# 35. The name of a library is not cut off.
#
# A name in an import table is a file name, and a file name is not long. A
# damaged image can point at bytes that are never closed, and without the
# limit one such name is read as the rest of the image.
Run-Mutation 'the name of a library is cut off' 'pe.mbt' `
  'const MAX_IMPORT_NAME : Int64 = 256' `
  'const MAX_IMPORT_NAME : Int64 = 4096' `
  '' '' `
  'the name of a library that is not closed is cut off'

# 36. A folder to bundle without a path is not refused.
#
# The path that the system gives back for a name that is not there is not an
# answer anybody can use, so the mistake is said out loud instead of being
# carried on.
Run-Mutation 'a folder to bundle without a path' 'pack.mbt' `
  '    if d == "" {
      fail(
        "the path of the folder to bundle is empty: give the folder to carry",
      )
    }' `
  '    if d == "" {
      continue
    }' `
  '' '' `
  'a folder without a path is refused with a clear message'

# 37. A folder to pack without a path is not refused.
#
# The same mistake, on the other way of making a package: the folder to pack
# is a path, and an empty path is not a folder.
Run-Mutation 'a folder to pack without a path' 'pack.mbt' `
  '  if input == "" {
    fail("the path of the folder to pack is empty: give the folder to pack")
  }' `
  '  if input == "" {
    return
  }' `
  '' '' `
  'a folder without a path is refused with a clear message'

# 38. The path of --Files is not checked.
#
# The flag is written by hand, and a flag written without a path is a
# mistake. The mistake has to be said out loud: the path that the system
# gives back for a name that is not there is not an answer anybody can use.
Run-Mutation 'the path of --Files is checked' 'cli.mbt' `
  '    if d == "" || d == "true" {
      fail("the path of --Files is empty: give the folder to carry")
    }' `
  '    if false {
      fail("the path of --Files is empty: give the folder to carry")
    }' `
  '' '' `
  'the path of --Files is checked'

# 39. The scratch of a test is not taken away again.
#
# Every run of the suite makes a few hundred folders of scratch, and without
# the removal every one of them would still be there the next morning: a
# machine that has run the suite a few hundred times holds tens of thousands
# of them. The removal is the whole point of the scratch.
Run-Mutation 'the scratch is taken away' 'scratch_test.mbt' `
  'async fn drop_scratch(dir : String) -> Unit nocancel {
  @fs.rmdir(dir, recursive=true, allow_missing=true) catch {
    _ => ()
  }
}' `
  'async fn drop_scratch(dir : String) -> Unit nocancel {
  let _ = dir
}' `
  '' '' `
  'a folder of scratch is taken away again'

# 40. The scratch a package was made in is not taken away again.
#
# The package lies in the folder it was made in, so the folder above it is
# the one that has to go. A package whose scratch is left behind is a folder
# of scratch that nobody ever cleans up.
Run-Mutation 'the scratch of a package is taken away' 'scratch_test.mbt' `
  'async fn drop_package_scratch(pkg : String) -> Unit nocancel {
  drop_scratch(@LunaPack.dirname(pkg))
}' `
  'async fn drop_package_scratch(pkg : String) -> Unit nocancel {
  let _ = pkg
}' `
  '' '' `
  'the scratch of a package is taken away again'

# 41. The scratch of a whitebox test is not taken away again.
#
# The whitebox tests are a package of their own, so they carry their own copy
# of the removal. A copy that does not remove anything leaves the scratch of
# every whitebox test behind.
Run-Mutation 'the scratch of a whitebox test is taken away' 'LunaPack_wbtest.mbt' `
  'async fn drop_scratch(dir : String) -> Unit nocancel {
  @fs.rmdir(dir, recursive=true, allow_missing=true) catch {
    _ => ()
  }
}' `
  'async fn drop_scratch(dir : String) -> Unit nocancel {
  let _ = dir
}' `
  '' '' `
  'a folder of scratch of a whitebox test is taken away again'
Write-Output '--- the tree is back to what it was ---'
git -C $repo status --short
