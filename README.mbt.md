# LunaPack

![LunaPack](LunaPack.png)

[![mooncakes](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fmooncakes.io%2Fapi%2Fv0%2Fmodules%2Friantr%2FLunaPack&query=%24.version&label=mooncakes&prefix=v)](https://mooncakes.io/docs/riantr/LunaPack)
[![release](https://img.shields.io/github/v/release/riantr/LunaPack)](https://github.com/riantr/LunaPack/releases)
[![license](https://img.shields.io/github/license/riantr/LunaPack)](LICENSE)

**LunaPack** is an application-distribution packer written in
[MoonBit](https://www.moonbitlang.com/). It bundles an application executable
together with the files it needs into a single distributable file, and unpacks
it again on the target machine with integrity checking.

The result is a **self-extracting bundle** — the trick a WinRAR or 7-Zip
self-extracting archive uses — with three properties the usual archiver does
not offer: every entry carries a SHA-256 checksum and an MD5 fingerprint, the
entries can be **encrypted** to a public key or to a passphrase, and the
produced file **behaves like the program it carries** — its arguments and its
exit code are the ones of the bundled program, and a program that draws a
window is started without a console window standing next to it.

One container, two front ends: a native binary that is built for the platform
it runs on, and a WebAssembly build that `moonx` runs from the Mooncakes
registry. The package has **no dependencies**, so nothing has to be resolved
when it is fetched.

Repository: [github.com/riantr/LunaPack](https://github.com/riantr/LunaPack)

## Features

* A bundle that is the program, not a wrapper around it

  The archive is appended to the LunaPack launcher, so the produced file *is*
  the launcher — and the launcher is the program the user starts. The
  arguments of the bundle are the arguments of the bundled program, the exit
  code is its exit code, and a bundle that was started by a double-click takes
  its own console window away before a program that draws a window starts, so
  the application is alone on the desktop. A copy of the executable would not
  do this; a plain archiver cannot do it at all.

* Every entry is checksummed, and every entry is fingerprinted

  The SHA-256 checksum of an entry is computed over the **original** content,
  so it validates the data the user actually gets and not the compressed form.
  The MD5 fingerprint of the same content is carried next to it, because the
  MD5 is what the platform tooling shows, and a user who wants to compare the
  file with what their file manager reports has nothing to compare against
  otherwise. The fingerprint of the **produced** file is reported as well, and
  it is computed while the file is written, so a 300 MB package is never read
  back for it.

* Compression that is a choice, not a default

  `--compression-method` picks `none`, `gzip`, `lz4` or `auto`. `auto` compresses
  every entry with gzip but keeps the raw bytes when gzip would make the entry
  bigger. The **LZ4 implementation lives in this package**, because the
  MoonBit toolchain ships none, and what it produces is a standard `.lz4`
  frame: the `lz4` tool decompresses it and this package decompresses what
  that tool produces. The frames are checked against the values the format
  publishes, not against the tool — see [Verification](#verification).

* Encryption to a public key, or to a passphrase

  The mechanism is the one of the reference implementation this package
  follows: a key is established with the recipient, HKDF-SHA512 turns it into
  the key of the package, and every entry is sealed on its own with
  ChaCha20-Poly1305 under a key and a nonce derived for it. The additional
  data of an entry holds its place in the package and its name, so neither can
  be changed without the seal breaking. A check in the manifest tells a wrong
  key from a damaged package.

* Every primitive is implemented here, and checked against its vector

  SHA-512, HMAC, HKDF, PBKDF2, ChaCha20, Poly1305, X25519 and Ed25519 — the
  toolchain ships none of them. Each one is checked against the vector that its
  standard publishes (FIPS 180-4, RFC 4231, RFC 5869, RFC 8439, RFC 7748,
  RFC 8032), and the derivation is checked against the reference implementation
  itself: the master key, the key and the nonce of a record, and the sealed
  record are compared byte for byte with the values the reference produces.

* A package that says what it is, and a host that can prove it

  The manifest of a package carries the SHA-256 of its own bytes, and a sealed
  package carries a MAC of it as well, so a manifest that was changed is
  refused instead of being obeyed. A damaged package is refused rather than
  taken for something else, the package is written in one piece so a crash
  cannot leave half of one behind, and the program of a bundle is checked
  before it is started.

  The one thing a package cannot settle by itself is whether it is the package
  the publisher meant, because the digest inside it is not a secret. The host
  settles it: `lunapack sign` writes a detached Ed25519 signature next to the
  package and `lunapack verify --signature` checks it, or the host publishes
  the digest and `lunapack verify --expected-sha256` checks that.

* An icon that survives the round trip

  When the application carries an icon, the bundle gets it as well, so Explorer
  shows the application's own icon instead of the launcher's. The icon is read
  from the application executable with a small PE reader and written into the
  bundle with the Windows resource API, which creates the resource section the
  launcher does not have. All icon sizes are copied, so the bundle looks right
  at every zoom level.

* Install scripts that run on the platform they were written for

  The script body is stored verbatim in the manifest together with the
  platform it targets, which is inferred from the file extension. At unpack
  time the script matching the host platform runs and a script for a different
  platform is skipped, so one package can safely be unpacked anywhere.

* One format, two front ends

  The same library and the same container behind `lunapack` (a native binary)
  and `moonx riantr/LunaPack@latest` (the WebAssembly build on the
  registry). The archive is found from the tail of the file in both cases, so
  `verify`, `info` and `unpack` work on a bundle exactly as they work on a
  plain package.

## What you get

The module is a library **and** an executable, so "what you get" is a set of
data structures, reports and one command line. Concretely:

| You call | You get back | Shape |
|---|---|---|
| `@LunaPack.pack(dir, pkg, opts)` | the package, written | `Unit` (the manifest is in the file) |
| `@LunaPack.bundle(exe, out, dirs, opts, launcher)` | the self-extracting single file | `Unit` |
| `@LunaPack.unpack(pkg, dest, run_scripts, key)` | the tree, extracted and verified | `Unit` |
| `@LunaPack.verify(pkg, key)` | whether every entry is intact | `Bool` |
| `@LunaPack.read_package_manifest(pkg)` | the manifest of a package | `Manifest` |
| `@LunaPack.probe_archive(path)` | the offset of the archive and its manifest | `(Int64, Manifest)?` |
| `@LunaPack.verify_extracted_dir(pkg, dir)` | whether the files in `dir` still match the package | `Bool` |
| `@LunaPack.new_pack_options(...)` | the options of a package | `PackOptions` |
| `@LunaPack.new_script(platform, body)` | an install script | `Script` |
| `@LunaPack.recover_encryption(info, key, passphrase)` | the key of a sealed package | `PackageKey` |
| `@LunaPack.x25519_public_key(secret)` | the public key of a secret key | `Bytes` |
| `@LunaPack.ed25519_public_key(seed)` | the public key of a signing seed | `Bytes` |
| `@LunaPack.ed25519_sign(seed, message)` | a signature of a message | `Bytes` |
| `@LunaPack.ed25519_verify(public, message, signature)` | whether a signature holds | `Bool` |
| `@LunaPack.public_key_pair(secret)` | the two public keys of a secret key | `PublicKeyPair` |
| `@LunaPack.ed25519_seed(secret)` | the signing seed of a secret key | `Bytes` |
| `@LunaPack.save_public_key_pair(path, encryption, signing)` | the public key file of a pair | `Unit` |
| `@LunaPack.load_public_key(path)` | the encryption public key of a file | `Bytes` |
| `@LunaPack.load_signing_public_key(path)` | the signing public key of a file | `Bytes` |
| `@LunaPack.sign_package(pkg, secret)` | the signature of a package | `PackageSignature` |
| `@LunaPack.verify_package_signature(pkg, sig, public)` | whether the signature holds | `Bool` |
| `@LunaPack.verify_package_digest(pkg, digest)` | whether the package has that digest | `Bool` |
| `@LunaPack.manifest_digest(offset, length, bytes)` | the digest of a manifest | `Bytes` |
| `@LunaPack.manifest_mac(key, offset, length, bytes)` | the MAC of a manifest | `Bytes` |

Every one of those is an explicit data value or a plain function: there is no
hidden global state, and the same inputs give the same bytes — which is why
`moon test` can assert on them and why the end-to-end suite can compare a
bundle with its own payload byte for byte.

## Install

```sh
moon add riantr/LunaPack@0.1.18
```

That is a **module** dependency, and it belongs in the consumer's `moon.mod`.
`moon add` writes it for you, so the file ends up holding:

```toml
import {
  "riantr/LunaPack@0.1.18",
}
```

The library is the package `riantr/LunaPack`, and the **package** import
belongs in the consumer's `moon.pkg`:

```moonbit nocheck
///|
import {
  "riantr/LunaPack" @lib,
}
```

The two blocks look alike and are not the same thing. `moon.mod` names a
*module* and pins the version it resolved; `moon.pkg` names a *package* inside
a module and takes **no version at all**. A version in a `moon.pkg` import is
not a newer spelling — it is an import the toolchain cannot find.

For the same reason there is no `@latest`: the version is parsed as semver, so
`latest`, `^0.1.18`, `>=0.1.18`, `0.1` and `v0.1.18` are all rejected. A bare
`moon add riantr/LunaPack` resolves the newest release and pins the concrete
version it found — that is the "latest" this toolchain has.

The package can be given a shorter name, which is the closest thing here to
Python's `from x import y as z`:

```moonbit nocheck
///|
import {
  "riantr/LunaPack" @lp,
}
```

so that the call is `@lp.pack(...)`. The alias belongs to the **package**, not
to a file: every file in that package sees it, and an import statement inside
a `.mbt` file is rejected outright — *"Invalid import declaration here. Move
this declaration to `moon.pkg`."*

The module is published as **one package that is both the library and the
executable**: the root package `riantr/LunaPack` carries the whole public API
*and* the entry point, so the registry stores the prebuilt WebAssembly module
under the module's own name and the coordinate that runs it is the short
`riantr/LunaPack@latest`. There is no second package to name.

The module carries **no dependencies**: everything it needs comes with the
MoonBit toolchain, so the published module carries none either and nothing has
to be resolved when it is fetched.

### What the release was checked on

`moon 0.1.20261102` — the toolchain every number in this file was measured on.

The workflow installs the toolchain from the official install script, which
serves the **current** release, so the runner's version moves with it. That is
the toolchain this release was **verified** against, not a tested **minimum**:
no older toolchain has been exercised here, and quoting a lower bound nobody
ran would be a claim, not a fact.

That moving target is not theoretical. `moonbitlang/core/async/process`
changed its output API between those two generations: `redirect_to_file()`
used to return a `&ProcessOutput` trait object and now returns a
`SharedProcessOutput`, while `spawn_orphan()` now expects a `ProcessOutput`
enum variant instead. The first 0.1.18 tag failed on every runner for exactly
this reason. The Studio launcher was rewritten to use only the arguments the
two signatures share, so the published source compiles on either toolchain.

### What changed in 0.1.18

- **LunaPack and LunaPack Studio are one product.** There is one version, one
  tag and one GitHub release. Studio is an optional asset of that release, not
  a second package on Mooncakes and not a separately numbered program. The
  `0.1.18` in `moon.mod`, in `CLI_VERSION` and in the Studio window are the
  same number; a whitebox test reads `moon.mod` and refuses to let them drift.

- **`--GUI` opens the graphical front end.** `lunapack --GUI` finds a Studio
  build next to the CLI (or in the versioned cache), downloads
  `lunapack-studio-<os>-<arch>.zip` from this version's release when it is
  missing, and shows a live progress bar while it streams the archive. The
  download is extracted in pure MoonBit - no `unzip`, `tar` or PowerShell is
  needed - and entry names are checked so a crafted archive cannot write
  outside the install directory. `HTTPS_PROXY` / `NO_PROXY` are honoured, and
  loopback mirrors always bypass the proxy.

  ```bash
  lunapack --GUI
  lunapack --GUI --input-file=./myapp.exe --output-file=./myapp-bundle.exe \
           --Files=./assets --Files=./docs --compression-method=lz4
  ```

  The flags are **forwarded, not acted on**: the window opens with those
  fields already filled in. `--cli=<path>` is added automatically so the
  window drives the very LunaPack that started it, even when Studio was
  downloaded into a cache folder far from the checkout. Override the location
  with `LUNAPACK_STUDIO`, the cache with `LUNAPACK_STUDIO_HOME`, or the source
  with `LUNAPACK_STUDIO_URL` (useful for a mirror or an air-gapped install).

- **The flag documentation now matches the parser.** The no-subcommand
  (`moonx riantr/LunaPack@latest ...`) front end reads `--input-exe` /
  `--input-file` and `--output-exe` / `--output-file`. The `bundle`
  **subcommand** reads `-i` / `--input` and `-o` / `--output`. The long
  `-exe` / `-file` spellings pass the unknown-flag check but are ignored by
  `bundle`, which then reports *"bundle requires -i <input_exe> and -o
  <output_exe>"*. This was found by driving a real `bundle` with those flags;
  the examples below now say which form each flag belongs to.

- **Startup arguments are part of the contract.** Studio parses every alias in
  both `--flag value` and `--flag=value` form, including repeatable `--Files`,
  and folds them into its form. Empty forwarded fields keep the defaults; an
  explicit `--cli` is never overwritten by auto-discovery.

- **Two defects found by running the real 188 MB asset.** Windows packers
  write `\` as the separator inside a zip; taken verbatim those names became
  mixed-separator paths and `@fs.mkdir` reported *"The system cannot find the
  path specified"*. Entry names are normalised to `/` before any path is
  built, and a trailing separator no longer turns a directory entry into a
  file. A real 246-file / 419 MB extraction now completes. The other defect
  was a window that inherits the CLI's stdout and keeps a pipe open, so
  `lunapack --GUI | ...` never saw EOF. Redirecting the child's streams into
  `studio.log` fixed it on the development toolchain, but the `@process`
  output API then changed shape (see above) and no `stdout=`/`stderr=`
  argument can be written that compiles on every toolchain. Since this module
  ships as source, portability wins: the streams are inherited and a piped
  invocation reaches EOF when the window is closed.

- The suite grew from 135 to **150 tests** on both the native and the Wasm
  backend. The new cases cover GUI-flag detection, argument forwarding,
  download URL construction, proxy bypass, redirect resolution, Windows zip
  separators, zip-slip rejection and the version/asset-name drift detector.

### What changed in 0.1.17

- **`--files` and `--Files` are the same flag.** This documentation and every
  example write `--Files`, and the parser matched a flag name exactly, so a
  command line that reached for `--files` was refused with `unknown flag
  --files`. It is read as the same flag now, in the `moonx` form and in the
  subcommand form alike, and the two spellings can be mixed in one command
  line: the folders come back in the order they were given, because the values
  are collected in one pass over the arguments rather than as two lists that
  are joined afterwards.
- **Nothing else became case-insensitive.** `--file` is still a mistake and is
  still reported, as is every other near miss. An exact list is what turns a
  misspelled flag into an error instead of a command that quietly does
  something else, and that property is kept: the one flag with two spellings is
  listed twice, deliberately, and the test that lists every flag the tool reads
  now checks both.
- **`--os` is accepted, which it never was.** `build_options` read `--os` and
  this page documented it, but the name was missing from the list of known
  flags, so every command line that set the platform was refused with
  `unknown flag --os`: a package for another platform could not be made at all.
  It was found by putting the flags the tool reads next to the flags the tool
  knows and looking for the difference, and it was the only flag in that gap.
- **A test that failed about once in 256 runs does not any more.** The test
  that changes a signed package wrote `Z` over byte 30 to break the signature.
  Byte 30 is inside the random salt of the manifest block, so one time in 256
  it was already a `Z`, nothing changed, and the signature still held — which
  is what happened to one wasm run of the gate sweep before this release, while
  two runs straight after it passed. The byte is turned into a **different**
  one now instead of into a fixed one.

Two of these changes have their guards in the battery. One test holds the two
spellings of the folder flag, a command line that mixes them, and the
space-separated form of each; the mutation that drops the lowercase spelling
from the collector — leaving it a known flag that contributes no folder, which
is the quiet kind of wrong — turns that test red and only that test. The
platform flag is held by the test that names it, and the mutation that takes
`os` back out of the list of known flags turns it red, together with the test
that lists every flag the tool reads — two witnesses, because a flag that is
read and refused is visible from both sides.

The `--launcher` default is unchanged, and it is worth writing down because it
is the question this release was asked about. On a native build the launcher
defaults to **the executable that is running**, so `--launcher` may be left out
entirely: measured here, `bundle` with `--launcher <the tool itself>` and
`bundle` without it produce **byte-identical** output. Under `moonx` there is no
native executable to default to, and omitting the flag produces a file that
carries the payload but cannot extract itself — the warning and the hint at the
end of `bundle` say exactly that, and the file is still usable with
`lunapack unpack`.

### What changed in 0.1.16

- **The fifteen seconds of the menu now pass.** 0.1.15 counted down by waiting
  one second on the console input handle and reading when the wait said there
  was something. That wait is on the handle, and a console signals the handle
  for **anything at all**: a window that gained focus, a window that was
  resized, the mouse. Measured on this machine: a wait on the input handle of a
  console with no key pressed returns `WAIT_OBJECT_0` in **0–95 ms**, every
  time. The read that followed is `ReadConsoleW`, which in the line-input mode
  of a console waits for a whole line — for ever, when nobody is typing. The
  countdown therefore never counted a second: a double-clicked bundle with a
  cache that is not complete sat on the menu showing `2 in 15 s` and never
  started.
- **The wait is no longer taken for an answer.** What is on the buffer is
  looked at before anything is read: only a `KEY_EVENT` that went **down** and
  carries a **character** is an answer. Everything else — the focus change, the
  resize, the mouse, the key that was let go, the arrow key with no character —
  is taken off the buffer with `ReadConsoleInputW` instead of being read as
  text, because leaving it there would signal the very next wait and no second
  would pass either.
- **The rule is a plain function, so it can be tested without a console.**
  `has_key_press(records, count)` walks the 20-byte `INPUT_RECORD`s and says
  whether one of them can answer a question. The test holds four buffers — a
  focus change, a key going up, an arrow key, and the `2` pressed — and each of
  the four conditions has to hold for the last one to be the answer. The
  mutation that takes the condition out — "anything the console reports is an
  answer", which is exactly what 0.1.15 shipped — turns that test red and only
  that test.

The defect was found by starting a bundle on a console that belonged to it and
reading the screen: after several minutes it still said `2 in 15 s`, and typing
`2` and Enter let it through at once — so the menu itself was usable and only
the "nobody chose" path was dead. With this release the same run counts 15, 14,
13 … 1, prints `2 (nobody chose)`, unpacks behind the two bars and starts the
program.

One limit is worth stating: a key that carries no character is not an answer.
An arrow key or a function key therefore does not move the menu along, and the
countdown keeps going. That is deliberate — the question is `[1/2]` — but it
means the menu is answered by typing a digit and not by pressing whatever key
is nearest.

### What changed in 0.1.15

- **A first start asks what it should do.** A bundle that is double-clicked,
  carries no argument of its own, and has never unpacked its payload prints
  three lines before it does anything:

  ```
  LunaPack: <name> <version>
    [1] install it to a folder
    [2] run it from the folder next to this file
    your choice [1/2], 2 in 15 s:
  ```

  Fifteen seconds without an answer take `2`, and the line then says so —
  `your choice [1/2]: 2 (nobody chose)` — rather than leaving the wait
  unexplained. A bundle that nobody is watching still starts on its own.
- **`1` is the `unpack` path and not a second implementation of it.** It asks
  for a folder, offering `%LOCALAPPDATA%\Programs\<name>` when Enter is
  pressed, and then runs the code `unpack` runs — **the pre and post scripts
  of the package included** — and starts the program from that folder with the
  folder as its working directory. What a bundle installs is therefore what
  `lunapack unpack` produces, and the two cannot drift apart.
- **The menu is only for a person.** It needs all four of: no argument, a
  console the bundle created for itself, **stdin that is a real console**
  (asked of `GetConsoleMode`), and a payload that is not already cached in
  full. A script, a pipe, a start from a terminal and every start after the
  first one go straight to the program, so nothing waits fifteen seconds for
  an answer that cannot come.
- **The unpacking shows a bar.** The line is rewritten in place: a bar of 24
  cells, the percentage, the files done out of the total, the megabytes done
  out of the total, and the name of the entry being written. The whole line,
  its `unpack`/`verify` label included, is `78` characters — cut or padded to
  exactly that, so the tail of the line before it cannot be left on the
  screen. On the path that unpacks next to the bundle there are **two** bars,
  `unpack` and then `verify`, because the payload is read back after it
  arrives; the install path shows the first one.
- **The bar cannot claim more than the whole.** A count of bytes larger than
  the total the manifest gives is clamped at `100%`, so a package whose last
  entry is bigger than the sum of the manifest reads as finished rather than
  as a defect in the unpacking. The mutation that removes the clamp turns the
  test of the bar red.
- **A name the console cannot show is left out.** The entries of a package are
  whatever the packer put in it, so the name at the end of the line is printed
  only when it is plain ASCII; guessing at a code page would turn the bar into
  noise.
- **The bar is written to the console handle, not through a buffer.** The
  launcher calls `WriteFile` on the standard output handle it got from
  `GetStdHandle`, which is what lets it write while a package is being
  unpacked and after a console was handed on. Nothing of this is visible to
  the interface of the package: `progress.mbt` is private, `extract_to`,
  `unpack` and `cache_matches` keep the signatures they had, and a bar is an
  optional argument the launcher passes.

Three limits are worth stating plainly. The install path shows the bar of the
unpacking only: the digest re-read that `unpack` does at the end is silent, so
the last seconds of an install look idle. A first start **from a terminal**
shows no bar either, because that console is the terminal's and the line would
be mixed into the output of the program the bundle is about to start; the bar
belongs to the console the bundle made for itself. And on a platform whose
console belongs to the terminal there is no menu at all —
`ask_install_or_run` answers `2` there, because "install to a folder" is what
`unpack` already does and there is no console to ask on.

### What changed in 0.1.14

- **A double-clicked bundle of an application with a window starts at all.**
  `bundle` used to copy the subsystem of the bundled program onto the launcher,
  so an application that draws a window produced a bundle that says "windowed".
  A windowed program has **no standard streams at all**, and the MoonBit
  runtime does not survive that: the process is gone before the first line of
  `main` runs — no window, no message, and not even a cache folder. That is
  what every double-clicked bundle of a GUI application did, and it is why the
  same file worked from a command line (a console was there) and did nothing at
  all from the desktop. Measured on this machine: the tool's own binary, its
  subsystem field changed to GUI and nothing else, exits with 1 and writes
  nothing when it is started with no standard streams; the same bytes started
  from a console print their usage.
- **The console the bundle is given is taken away instead.** The bundle keeps
  the **console subsystem of the launcher**, which is what makes it start, and
  the launcher takes away the console that comes with it. It asks
  `GetConsoleProcessList` whether the console has only this process on it — the
  console of a terminal has the shell on it as well, and that one is never
  touched, because it is the window the user is typing into — and it does so
  only for a program whose PE header says it draws a window; a console program
  keeps the window its output goes to.
- **The program is started before the console goes away.** `FreeConsole`
  destroys a console that has no other process on it, and after that the
  standard handles of the launcher lead nowhere: a spawn that hands them on
  fails with *"the handle is invalid"*. The launcher therefore starts the
  program with `CreateProcessW` of its own, keeps the process handle, frees the
  console, and waits — so the exit code of the bundle is still the exit code of
  the program, which is the contract the command line depends on.
- **The subsystem of the launcher is no longer rewritten.** `(windowed)` no
  longer appears in the summary of `bundle`, and a non-PE input can no longer
  dictate anything about the bundle. `set_pe_subsystem` and `pe_subsystem_of`
  are unchanged for library users; the launcher reads the subsystem of the
  program it starts.

Two limits are worth stating plainly. While the payload is unpacked on the
first run — **38 s** for the 375 files and 123 MB of the application this was
reproduced with — the console window is visible and empty, and a warm cache
starts in **8 s**. And a failure of a double-clicked bundle is silent, because
the console it would print to is gone by then; a message box for that case is
not in this release.

### What changed in 0.1.13

- **A cache is handed out on what it holds, not on its name.** The payload is
  unpacked into a folder of its own and moved into the place the next run
  looks at, and the move was the one step the launcher never looked at: the
  folder that arrived was named like a complete cache whether all of it
  arrived or only part of it did. The reported cache held **296 of the 376
  files** the package carries — the missing 80 were a contiguous tail — with
  the completion marker in it, and the bundle started the application from
  it. The application then failed to load `Microsoft.WindowsAppRuntime.dll`,
  which was one of the files the move had left behind: a
  `DllNotFoundException` from deep inside an application that has nothing to
  do with unpacking. The folder is **read back after it arrives** now, and a
  folder that does not hold what the package carries is removed rather than
  started. The fall back to a temporary directory — used when no cache can be
  written next to the executable — is read back in the same way; it checked
  the main program only, so a sibling library that did not arrive was never
  noticed, which is the same failure by another road.
- **The module is MIT.** `LICENSE` carried the Apache-2.0 text and `moon.mod`
  carried its identifier. Nothing in this package needs the patent grant or
  the notice file that Apache-2.0 asks for: every primitive is written here
  rather than taken from another project, so there is no third-party notice
  to preserve. The license of a published version cannot be changed after the
  fact, so it takes effect here.

The honest limit of the first one is worth stating. What a unit test can prove
is that **a folder which does not match the package is not handed out** — that
is what the test and the mutation that takes the read-back out cover. Whether a
given host can deliver a folder in part is not something a test reproduces: a
rename that loses most of its contents is an operating-system event, not a code
path. The guard is proven by taking it out; the event it guards against is
argued from the cache that was found, not simulated.

### What changed in 0.1.12

- **A bundle that cannot start says so.** Through `moonx` there is no native
  launcher, so the application itself becomes the stub: the result holds the
  whole payload and cannot unpack itself. The warning that said so was printed
  *before* the summary, where a list of a few hundred checksums hides it, and
  the command still ended with `bundled N files`. It is the last line now, it
  names the file, it says that the file carries the payload but no launcher,
  and it goes to stderr as well as to stdout. This cost a real user an
  afternoon: a 124 MB file that held every dependency and could not start.
- **A bundle that is refused leaves nothing behind.** The archive is written
  before the launcher is looked at, so a launcher that turns out to be missing
  left `*.lunapack-archive.tmp` in the directory that was asked for the
  bundle. The cleanup reaches the archive from the moment it is written.
- **The mutation battery runs on a Windows checkout again.** Its anchors are
  written with LF endings and `.gitattributes` keeps a `.ps1` on CRLF, so every
  anchor that spanned more than one line stopped matching and reported
  `ANCHOR NOT FOUND` — the battery quietly stopped proving anything. The
  comparison is made on one line ending now.

Failing outright when no launcher is available was the other way to go, and it
was not taken: the `moonx` flow is documented above, and a payload-only bundle
is a real deliverable that `unpack` reads. What was wrong was not the
capability but the way it reported itself. A bundle that is meant to be
*started* needs `--launcher`.

### What changed in 0.1.11

- **The native build builds on every platform again.** The Windows-only
  `GetModuleFileNameW` declaration was guarded with `target="native"`, which
  is true on Linux and macOS as well, so the linker looked for a Windows
  symbol there and the release workflow could not build those two binaries.
  The declaration and its caller are guarded with
  `all(target="native", platform="windows")` now; on other platforms the
  launcher keeps the `argv[0]` fallback it had before 0.1.10. The Windows
  build and the Wasm build were never affected, and the container layout
  does not change.

Version 0.1.10 had already reached the registry when the release workflow
reported this, and a published version cannot be replaced, so this is a
patch release. `moonx riantr/LunaPack@latest` resolves to 0.1.11.

### What changed in 0.1.10

- **The command that was typed is the command that runs.** `--input-file` and
  `--output-file` are names for `--input-exe` and `--output-exe` now, and a
  flag the tool does not know is refused instead of being dropped. An empty
  output path is refused as well. Without those three changes an unknown flag
  could scan a whole directory and then fail with a rename to an empty file
  name — which is exactly what a real `moonx riantr/LunaPack@latest` run
  with the two aliases did.
- **A failure says that it failed.** Every command that cannot do what it was
  asked now exits with `1` instead of `0`. The `VERIFY OK` / `VERIFY FAILED` /
  `error: ...` markers on stdout stay, so a script that reads the output keeps
  working.
- **A check that was asked for is a check that is made.** `verify --extracted`
  no longer lets an intact extracted directory hide a damaged package, and
  `unpack` honours `--signature`, `--public-key` and `--expected-sha256`
  before it writes a single file.
- **On Windows the launcher knows which file it is.** It locates itself with
  `GetModuleFileNameW` instead of `argv[0]`, which a caller can forge. A
  bundle carries its own copy of the launcher, so a bundle made before this
  release has to be rebuilt to pick up the fix. On other platforms the
  launcher keeps the `argv[0]` fallback it had before.
- **A package cannot turn off its own integrity.** A format 6 package whose
  integrity marker is missing or damaged is refused rather than downgraded to
  "legacy"; real format 5 packages are still read, with a warning. A non-PE
  file can no longer dictate the subsystem the launcher reads, because the PE
  signature and the header bounds are checked before the field is believed.
- **Malformed input is damage, not a crash.** The LZ4 decoder checks its
  bounds, caps the expansion of a hostile frame and reads the DictID flag from
  the bit the format assigns to it. Windows install scripts get their bare
  file name, so `cmd` does not read the path as a switch, `LUNAPACK_DEST` is
  absolute, and an unreadable `--pre-install` script fails the command instead
  of discarding every other option.

A deep QA pass found these defects. **127 tests pass on the native backend and
on the Wasm backend** now. The container layout does not change, so a package
written by 0.1.9 is still read by 0.1.11, and the other way round.

### What changed in 0.1.9

- **The public key of a pair holds both of its public keys.** A pair serves two
  purposes — the key a package is sealed to, and the key a signature is checked
  with — and the file held only the first of them. `keygen` writes both now,
  and the two are derived from the secret with a label of their own, so the key
  that opens a package is not the key that signs one.
- **The signature of a package holds.** In 0.1.8 the signature was checked
  against the encryption public key, so a signature made with the secret key of
  the pair never held: the feature was published and it did not work. The Linux
  end-to-end suite found it, and the chain that the command line walks is held
  by a unit test now, so it does not depend on a POSIX host to be checked.
- **A damaged package says that it is damaged.** `verify` on a file that
  carries the marker of a package but is not one says so, and a file that
  carries no marker at all says that it is not a package. The two are not the
  same thing, and the wording keeps them apart.

A public key file of the older form — the 32 raw bytes of the encryption key —
still seals a package. It cannot be used to check a signature, and it says so.

### What changed in 0.1.8

- **The manifest carries its own integrity.** Every package now holds a block
  with the SHA-256 of its manifest, and a sealed package holds a MAC of it as
  well. A manifest that was changed is refused, and the reason is named.
- **A damaged package is refused instead of being taken for something else.**
  A file that carries the marker of a package but is not one is an error, not
  a file that is not a package. A bundle that cannot be unpacked does not
  fall back to printing its usage.
- **A package is written in one piece.** The package is written into a file of
  its own, flushed to the disk and only then does it take the place of the
  target. A target that was a whole package is still a whole package after a
  crash, and a file that is written is never half-written.
- **The cache of a bundle is checked on every start, and the program is
  checked before it runs.** A payload that was changed after it was unpacked is
  unpacked again, and a program that does not match the package is not
  started.
- **The paths of the entries are checked.** A path that walks out of the
  destination with `..` is refused before anything is written.
- **Every checksum is computed twice**, and the MD5 is computed as well, so
  that a fault in the machine is not mistaken for a fault in the package.
- **The host can sign a package.** `lunapack sign` writes a detached
  Ed25519 signature next to the package, and `lunapack verify --signature`
  checks it. `lunapack verify --expected-sha256` checks a digest the host
  published. Both are checked before the package is opened.
- **The Ed25519 implementation is new**, and it is checked against vectors
  that another implementation produced, so a signature that is right here is
  right against every other implementation of RFC 8032.

The published surface grows by the signature functions and the Ed25519 ones.
The container layout does not change: the integrity block sits between the last
entry and the manifest, so a package that carries one is still a package that
an older LunaPack can read.

### What changed in 0.1.7

- **The short coordinate runs.** `moonx riantr/LunaPack@latest` resolves and
  starts the tool. The root package `riantr/LunaPack` is now the executable as
  well as the library, so the registry stores the prebuilt WebAssembly module
  under the module's own name and there is no second package to name. Before
  this release the same coordinate failed with *"Prebuilt wasm asset does not
  exist"*, because the entry point lived in a second package.
- **The entry point left `cmd/main`.** The CLI is `cli.mbt` in the root package
  and the `cmd/` directory is gone. A consumer's import path does not change:
  `import { "riantr/LunaPack" @lib }` names the same API, and the generated
  `pkg.generated.mbti` is byte-identical to the one 0.1.6 published.
- **The price of the short coordinate is named, not hidden.** A main package's
  blackbox tests are on a deprecation path and a dependency that imports a main
  package is deprecated. Both are described under *Packages and targets*, with
  the alternative that avoids them.

### What changed in 0.1.6

- **There is a logo.** `LunaPack.png` is what the README shows and what the
  registry's docs page renders; `LunaPack_Logo.png` is the same artwork at
  1024×1024, for anyone who wants the full-resolution file. Both are published
  with the module, and the README's image path is relative, so the registry
  rewrites it to the asset URL.
- **A missing interpreter is named in the error.** The runtime's spawn failure
  says *"The system cannot find the file specified."* and names no file, so a
  missing `sh` read like a defect. The error now says which interpreter was
  missing — `cannot run the interpreter \`sh\`: …` — and the temporary script
  file is removed on that path too, instead of being left in the installation
  directory.
- **The README was restructured** to the shape the sibling
  [`riantr/tesseract`](https://mooncakes.io/docs/riantr/tesseract@0.1.15)
  uses — title, logo, intro, `Features`, `What you get`, `Install`, then the
  technical sections, `Quick Start`, `Example`, `Gates and drift detectors`,
  `Used By` and `Attribution` — because a reader who has seen one of those
  modules should not have to learn a second layout. The technical content is
  the same content; the sections around it are new.

The published surface grows by nothing: the two helpers that carry the change
are private to the package, and `run_install_script` keeps its signature.

### What changed in 0.1.5

- **The single file behaves like the program it carries.** The arguments, the
  exit code, the subsystem and the standard streams of the bundle are the ones
  of the bundled program, so a windowed application does not flash a console
  window and a program that asks a question gets an answer.
- **The end-to-end suite covers the bundle subcommand and the named launcher.**
  A bundle that is made with `--launcher` now starts with the launcher that
  was named — byte for byte — and a launcher that does not exist is refused
  instead of producing a bundle that cannot start.

### Packages and targets

| Package | Kind | Native | Wasm |
|---|---|---:|---:|
| `riantr/LunaPack` | library **and** executable | yes | yes |

There is **one** package. It carries the whole public API *and* the entry
point, which is what lets the coordinate be `riantr/LunaPack@latest`: the
registry stores the prebuilt WebAssembly module per package, and the module's
own name is the package's name.

The package declares `supported_targets = "native+wasm"`, and the module
type-checks on both backends — `moon check --target native` and `moon check
--target wasm` are exit 0 for each. There is no `wasm-gc` target and no `js`
target: a check for those has nothing to do, because no package of the module
claims one.

The checks are not warning-free, and the numbers are in the open rather than in
a footnote: `--target native` reports **2 warnings** (a deprecated call in a
test, and the one below) and `--target wasm` reports **6** (the same two,
three in the Windows-only icon helpers, which the WebAssembly backend does not
use, and one for the UTF-16 import that only the Windows native launcher
needs). No gate runs with `--deny-warn`, and none of the warnings is an error.

The second warning is the price of the short coordinate, and it is worth naming
exactly: *"Main package `riantr/LunaPack` uses blackbox-only test inputs
(`_test.mbt` files) … Main packages will stop generating blackbox tests in a
future release."* The blackbox tests of the public API run today, and a
toolchain that stops generating them would take that coverage with it. The
alternative — a library in a non-main package under `src/`, with the root as
the entry point — keeps the tests and the import path of the library safe, at
the price of the library moving to `riantr/LunaPack/src/lunapack`.

## Releases

The binaries of a release are attached to its
[GitHub release page](https://github.com/riantr/LunaPack/releases):

| Asset | Platform |
| --- | --- |
| `lunapack-windows-x86_64.exe` | Windows |
| `lunapack-linux-x86_64` | Linux |
| `lunapack-macos-aarch64` | macOS (Apple Silicon) |
| `lunapack.wasm` | WebAssembly, for `moonx` |
| `lunapack.core` | the compiled package the WebAssembly module needs |
| `lunapack-studio-windows-x86_64.zip` | **LunaPack Studio**, the graphical front end of this same release |

LunaPack and LunaPack Studio are **not two packages**. Studio has no version
of its own and is not published to Mooncakes: it is an optional asset attached
to the same release as the CLI, and the CLI knows which asset to ask for
because both carry the version in `moon.mod`. `lunapack --GUI` downloads it
on first use, so a user who only wants the command line never pays for the
188 MB window and a user who wants the window never has to find a second
download. Assets for other platforms are named
`lunapack-studio-<os>-<arch>.zip` and are added as those builds exist.

The release is built by a GitHub workflow when a version tag such as `v0.1.18`
is pushed; the same tag is published to the Mooncakes registry, so
`moonx riantr/LunaPack@latest` resolves to it. The tag is the source
of truth: the workflow compares it against the version in `moon.mod` before it
builds anything, so a tag and the published module cannot disagree.

The macOS runners are the scarce ones, and a tag that is pushed when none of
them is free leaves the macOS binary unbuilt. The release is made anyway, with
the binaries that were built, and its notes name the one that is missing. A
release that says what it holds is worth more than one that waits for a runner
that may not come.

The release *run* shows red in that case, and the run is not the release: the
job that publishes the release is green and the release page holds the
binaries. The red comes from the macOS leg, which GitHub cancels when it has
waited for a runner for a quarter of an hour. A run that is red because a
runner was not free is a fact about the runners, not about the release.

The registry refuses a version that already exists, and it wants a `0.x.y`
version while it is in its early stage, so the releases are numbered `0.1.0`,
`0.1.1`, `0.1.2`, `0.1.3`, `0.1.4`, `0.1.5` and so on.

### Publishing to Mooncakes

`moonx` resolves a package from the registry, so the module has to be published
first. The release workflow does that with the registry token it holds as a
secret; locally the commands are:

```bash
moon login                 # once
moon publish --dry-run     # validate
moon publish               # publish riantr/LunaPack
moonx riantr/LunaPack@latest --input-exe=... --output-exe=... --Files=...
```

The module publishes with `supported_targets = "native+wasm"`; `moonx` runs
the Wasm build, which reads and writes the real filesystem through the MoonBit
runtime.

## The bundle

```
myapp.exe  =  [ LunaPack launcher ]  +  [ archive: myapp.exe, res/app.cfg, ... ]
```

Starting it extracts the payload and launches the bundled program:

```
$ ./myapp.exe
LunaPack: starting D:/apps/.lunapack/9c445884d23653fb/myapp.exe
```

The payload is cached in `.lunapack/<hash>/` next to the executable, so the
second start is immediate. Delete that folder to force a fresh extraction.

Because the launcher does the extraction, the application finds its own
dependencies (`.dll`, `.json`, assets) exactly like it would in its build
folder — a plain copy of the executable would not run at all.

### The launcher

The launcher is the program that unpacks the payload and starts the program it
carries. It has to run on the machine the bundle is started on, so it has to be
built for that machine.

By default the running LunaPack binary is used, which is the right choice for a
bundle that is made for the machine that makes it. `--launcher` names a
different one:

```bash
# A bundle for Windows, made with the launcher of the release.
lunapack bundle -i ./myapp.exe -o ./myapp.exe \
  --Files=./build --launcher ./lunapack-windows-x86_64.exe
```

This is what makes a bundle for another operating system possible: the
launcher of that operating system is named, and the bundle runs there.

> The bundle is self-extracting when the launcher is a **native** LunaPack
> binary. The one that runs on this machine is used by default, so a native
> LunaPack always produces a self-extracting file. A bundle produced through
> `moonx` runs on WebAssembly and has no native binary of its own, so it needs
> one named with `--launcher` — see above.
>
> Without one, `moonx` still writes a file that holds the whole payload, and
> that file **does not start on its own**: starting it runs the bundled
> program with none of its files unpacked next to it, which for most programs
> means it fails at once. The two files look identical from the outside —
> same name, same size, a whole payload inside — so the last line that the
> command prints says which of the two was made, and it also goes to stderr.
> A bundle that is only meant to carry a payload can be unpacked with
> `lunapack unpack`; a bundle that is meant to be started needs the launcher.

### A single file that behaves like the program

The bundle is not only a container: it is the program, with the files it needs
around it.

- The **arguments** of the bundle are the arguments of the bundled program.
- The **exit code** of the bundle is the exit code of the bundled program.
- The bundle keeps the **console subsystem of the launcher**, because a program
  with no standard streams at all does not survive the start of the runtime on
  Windows. A bundle that was started by a double-click takes that console away
  before it starts a program that draws a window, so a windowed program is
  started without a console window standing next to it, and a console program
  keeps the window its output goes to.
- The **standard input, output and error** are the ones of the bundle, so a
  program that asks a question gets an answer.

```bash
$ ./myapp.exe --version
myapp 2.6.0
$ echo $?
0
```

### The icon

When the application carries an icon, the bundle gets it as well, so Explorer
shows the application's own icon instead of the launcher's:

```
$ lunapack --input-exe=./myapp.exe --output-exe=./myapp.exe --Files=./build
  md5  6b1b1e1f0a2c3d4e5f60718293a4b5c6  myapp.exe
  ...
scanned 392 files
bundled 392 files -> ./myapp.exe (icon copied)
output md5  0f1e2d3c4b5a69788796a5b4c3d2e1f0  myapp.exe
```

This is a Windows feature: an icon is a Windows resource, so on Linux and macOS
the bundle keeps the icon of the launcher. Use `--Files` with the application's
own `.ico` file there, or install the icon separately.

`lunapack unpack` recognises the appended archive automatically, so the same
file can be verified and extracted again:

```bash
lunapack verify  myapp.exe
lunapack info    myapp.exe
lunapack unpack  -i myapp.exe -o ./out
```

## The package

### The format

The container layout has not changed since v2: the marker names the layout, and
the manifest carries its own `format_version`. The current manifest is version
6, which adds the integrity block. A package written by an older version still
unpacks, because the fingerprint, the encryption and the integrity block are
all optional.

```
+--------------------+  offset 0
| magic "APPKGD02"   |  8 bytes
+--------------------+  offset 8
| entry payloads     |  stored back to back, raw, gzip, lz4 or sealed
+--------------------+
| integrity block    |  40 bytes, or 72 for a sealed package
+--------------------+
| manifest (UTF-8    |
| JSON)              |
+--------------------+
| magic "APPKGD02"   |  8 bytes
| manifest offset    |  8 bytes, little-endian int64
| manifest length    |  8 bytes, little-endian int64
+--------------------+  end of file
```

A bundle is the same archive appended to an executable. The archive length is
`manifest_offset + manifest_length + 24`, so the archive can be located from
the tail of the file without scanning it.

The integrity block sits between the last entry and the manifest, which keeps
the layout above unchanged: a package that carries one is still a package that
an older LunaPack can read, because the older reader steps over the block and
finds the manifest where it expects it. The block holds a marker, the SHA-256
of the manifest and — for a sealed package — the MAC of the manifest. What it
is for is described under *The integrity of a package*.

The manifest records the package metadata plus one record per entry:

```json
{
  "format_version": 6,
  "name": "myapp",
  "version": "1.4.0",
  "os": "linux",
  "arch": "x86_64",
  "checksum_algo": "sha256",
  "compression": "auto",
  "created_at": "2026-11-04T04:10:20Z",
  "main_program": "myapp.exe",
  "pre_install": { "platform": "posix", "body": "#!/bin/sh\n..." },
  "post_install": null,
  "entries": [
    {
      "path": "res/app.cfg",
      "mode": 420,
      "size": 22500,
      "stored_size": 913,
      "codec": "gzip",
      "checksum": "0a77c24c45d0c61f906862c4706f5dd739166985e8fc5c6344dadd9220507b28",
      "md5": "1520e796ba25554696b3cef6e913cc90",
      "offset": 8
    }
  ]
}
```

- `size` is the original file size, `stored_size` the space it occupies in the
  package.
- `checksum` is the SHA-256 of the **original** content, so it validates the
  data the user actually gets, not the compressed form.
- `md5` is the MD5 fingerprint of the same content. It is a convenience for
  comparing against what the platform tooling shows, not the integrity
  guarantee.
- `mode` holds UNIX permission bits (`0o644` / `0o755`); they are ignored on
  Windows.
- `main_program` names the entry that is the application executable.
- `encryption` says how the package is sealed, and is `null` when it is not
  sealed at all.

### The integrity of a package

A package is a file that anyone can change. The question is not whether the
file can be changed — it can — but **what a change gets you**, and how much of
it the reader notices. LunaPack answers that in layers, and each layer answers
a different question.

| Layer | What it is | What it stops |
|---|---|---|
| SHA-256 of every entry | in the manifest | a payload that was changed or corrupted |
| MD5 of every entry | in the manifest | the same, by a second and independent algorithm |
| SHA-256 of the manifest | in the integrity block | a manifest that was changed in place, a truncated write |
| HMAC-SHA512 of the manifest | in the integrity block of a sealed package | a manifest that was rewritten by whoever holds the file |
| The cache is checked on every start | in the launcher | a payload that was changed after it was unpacked |
| The program is checked before it runs | in the launcher | a program that was changed between the check and the start |
| The cache is read back after it arrives | in the launcher | a payload that only part of a move delivered |
| A damaged package is refused | everywhere | a package that was cut short being taken for something else |
| The paths of the entries are checked | everywhere | a path that writes outside the destination |
| The package is written in one piece | everywhere | a target that is half a package after a crash |
| The checksum is computed twice | in every checker | a fault in the machine that computes it |
| The signature of the host | next to the package | a package that was rewritten from top to bottom |

The honest limit of all of this is worth stating plainly. **The manifest of an
unencrypted package cannot be authenticated by the package itself.** The digest
that goes with it is not a secret, so whoever rewrites the file can compute a
digest that matches the manifest they wrote. What the digest does catch is
corruption, a write that was cut short and a manifest that was changed in
place — which is what a transient fault does.

Format 6 is the format that brought the integrity block, and a package that
says it is format 6 must carry one. A damaged or deliberately broken marker is
refused, not taken for a package of the old format: silently downgrading would
let a one-byte change turn off the check altogether. Packages whose manifest
says format 5 or less are the old ones; they are still read, with a warning
that their manifest was not authenticated.

For the case that nothing inside the file can settle, the host holds the
material:

```bash
# The host signs the package with its secret key.
lunapack sign myapp.appkg --secret-key host.key --output myapp.appkg.sig

# Whoever holds the public key checks the signature.
lunapack verify myapp.appkg --signature myapp.appkg.sig --public-key host.pub
```

The signature is an **Ed25519** one (RFC 8032), so the public key is enough to
check it and the secret key is enough to make it. The same check works with
nothing but a digest, for a channel that publishes one:

```bash
lunapack verify myapp.appkg --expected-sha256 <the digest the host published>
```

A pair of keys serves two purposes, so the public key of a pair holds **both**
of its public keys:

```
lunapack-public-key v1
x25519 751d2616ba1be8341b35f6cf2d73978e2cccecd1decd0f898b421a99618bc35f
ed25519 a8414c851959a5449aad50fe53b9d976028fd3122248cf87331bd0e0a8ea526e
```

The `x25519` line is the key a package is **sealed to**, and the `ed25519` line
is the key a signature is **checked with**. `pack` reads the first and `verify`
reads the second. The two are derived from the same secret with a label of
their own, so the key that opens a package is not the key that signs one, and
a fault in one of them does not hand the other one over. A public key file of
the older form holds the 32 raw bytes of the encryption key alone: it still
seals a package, and it cannot be used to check a signature.

The Ed25519 implementation in this module is checked against vectors that were
produced by an implementation that is not this one, so a signature that is
right here is right against every other implementation of RFC 8032.

What the layers mean for the reader in practice:

- A package that was damaged is **refused**, not taken for a file that is not a
  package. A bundle that cannot be unpacked is not a program without
  arguments.
- A package whose manifest was changed is refused, with the reason named.
- A **sealed** package is refused when the key is wrong, when the manifest was
  changed, and when a key is given for a package that says it is not sealed.
  The key is the claim of the reader that the package is encrypted to them,
  and a package that says the opposite has been changed.
- A path in the manifest that walks out of the destination with `..` is refused
  before anything is written.


### Compression

`--compression-method` picks the codec of the entries:

| Method | What it does |
| --- | --- |
| `none` | store the files as they are |
| `gzip` | gzip every entry |
| `lz4` | LZ4 every entry |
| `auto` | gzip every entry, but keep the raw bytes when gzip would make the entry bigger (the default) |

LZ4 does no entropy coding at all, so it is much faster than gzip while
producing a larger result. That is the trade to make when a package is built
often and unpacked rarely. Measured on an application of 392 files and 332 MB:

| | gzip | LZ4 |
| --- | --- | --- |
| packing | 39 s | **16 s** |
| unpacking | 21 s | **19 s** |
| size of the package | **139 MB** | 175 MB |

The LZ4 implementation lives in this package, because the MoonBit toolchain
ships none. What it produces is a standard `.lz4` frame, so the `lz4` tool
decompresses it, and this package decompresses what that tool produces. The
suite checks the frames against the values the format publishes; it does not
run the `lz4` tool.

### Encryption

`--encryption-method` seals the entries of a package. There are two methods:

| Method | What it does |
| --- | --- |
| `x25519` | the package is sealed to the owner of a public key; only the owner of the secret key can open it |
| `passphrase` | the package is sealed with a passphrase |

The mechanism is the one of the reference implementation this package follows.
A key is established with the recipient, HKDF-SHA512 turns it into the key of
the package, and every entry is sealed on its own with ChaCha20-Poly1305 under
a key and a nonce that are derived for it. The additional data of an entry
holds its place in the package and its name, so that neither can be changed
without the seal breaking. A check in the manifest tells a wrong key from a
damaged package.

The key exchange is the one part that is different. The reference uses the
sntrup761 KEM, which the toolchain has no counterpart of, so this package uses
X25519 — the curve that the reference itself carries as a part of its own
`sntrup761x25519-sha512` method. An ephemeral key is made for every package, so
the same recipient gets a different shared secret for every package.

```bash
# Make a pair of keys. The public key goes to the machine that seals the
# packages, the secret key to the machine that opens them.
lunapack keygen --public-key recipient.pub --secret-key recipient.key

# Seal a package to the owner of the public key.
lunapack pack -i ./app -o app.appkg \
  --encryption-method x25519 --public-key recipient.pub

# Open it again with the secret key.
lunapack unpack -i app.appkg -o ./out --secret-key recipient.key

# Or with a passphrase.
lunapack pack -i ./app -o app.appkg \
  --encryption-method passphrase --passphrase-file passphrase.txt
lunapack unpack -i app.appkg -o ./out --passphrase-file passphrase.txt
```

The public key of a pair holds both of its public keys, because a pair serves
two purposes: the key a package is sealed to and the key a signature is checked
with. The file is a text, so a person can read what it holds:

```
lunapack-public-key v1
x25519 751d2616ba1be8341b35f6cf2d73978e2cccecd1decd0f898b421a99618bc35f
ed25519 a8414c851959a5449aad50fe53b9d976028fd3122248cf87331bd0e0a8ea526e
```

A secret key that a passphrase protects is the better form: the raw form
leaves the secret key in clear text on disk, and anyone who reads it can open
every package that was ever sealed for it.

```bash
lunapack keygen --public-key recipient.pub --secret-key recipient.key \
  --passphrase-file passphrase.txt
```

The self-extracting bundle finds its key next to itself: the file
`<bundle>.key` for a public key, the file `<bundle>.pass` for a passphrase.
The environment variables `LUNAPACK_SECRET_KEY` and
`LUNAPACK_PASSPHRASE_FILE` name the files instead.

### Install scripts

The script body is stored verbatim inside the manifest together with the
platform it targets. The platform is inferred from the file extension:

| Extension | Target platform |
| --- | --- |
| `.cmd`, `.bat`, `.ps1` | `windows` |
| `.sh` | `posix` (Linux + macOS) |
| anything else | `any` |

At unpack time the script matching the host platform runs; a script for a
different platform is skipped, so one package can safely be unpacked anywhere.
On Windows the script runs through `cmd /c`, on Linux/macOS through `sh`.

The script runs with the destination directory as its working directory and
receives two environment variables:

- `LUNAPACK_DEST` — absolute path of the destination directory
- `LUNAPACK_PHASE` — `pre_install` or `post_install`

Use `--skip-scripts` to unpack without running them.

## Running it

### Via `moonx` (published on Mooncakes)

```bash
moonx riantr/LunaPack@latest \
  --input-exe=[input-exe-path] \
  --output-exe=[output-exe-path] \
  --Files=[Pack-Folder]
```

The coordinate names the package that holds the entry point, because the
registry stores the prebuilt WebAssembly module per package. The entry point
lives in the module's own package, so the coordinate is
`riantr/LunaPack@latest` — the module name and the package name are the same
string.

| Flag | Meaning |
| --- | --- |
| `--input-exe` | the application executable to distribute |
| `--output-exe` | the produced single-file bundle |
| `--Files` | folder of files to bundle with it (repeatable; `--files` is the same flag) |

`--input-file` is another name for `--input-exe`, and `--output-file` for
`--output-exe`. A flag that the tool does not know is refused with a message
that names it and the flags that it does know, so a mistyped flag never
turns into a command that quietly does something else. The form a Windows
prompt tends to produce therefore works as written:

```bash
moonx riantr/LunaPack@latest \
  --input-file="x64/Release/App.exe" \
  --output-file="App.exe" \
  --Files="x64/Release"
```

The result is a **self-extracting bundle**: the LunaPack launcher with the
archive appended, exactly the trick a WinRAR or 7-Zip self-extracting archive
uses.

The bundled program runs with the **cache directory as its working
directory**, not the directory the bundle was started from. That is what lets a
program find the files that were packed next to it. A relative path given on
the command line is therefore read relative to the cache directory; pass an
absolute path if the caller's directory is what matters.

### The graphical front end (`--GUI`)

```bash
lunapack --GUI
lunapack --GUI --input-file=./myapp.exe --output-file=./myapp-bundle.exe \
         --Files=./assets --compression-method=lz4 --name=demo --version=1.0.0
```

`--GUI` is a front end of its own, not a flag on a subcommand. It opens
**LunaPack Studio** with the flags above already filled in, so the window is a
review-and-press-Process step rather than a form to start from scratch. The
switch may appear anywhere on the command line. Everything the user typed is
forwarded unchanged, plus `--cli=<this executable>` so the window drives the
same LunaPack.

Studio is looked for in this order:

| Where | Controlled by |
| --- | --- |
| an explicit executable or directory | `LUNAPACK_STUDIO` |
| beside this CLI, or in a sibling `LunaPackGUI/dist/` checkout | - |
| `%LOCALAPPDATA%/LunaPack/Studio/<version>/` (or `$XDG_CACHE_HOME`, `$HOME/.cache`) | `LUNAPACK_STUDIO_HOME` |

If none exists, the CLI downloads `lunapack-studio-<os>-<arch>.zip` from
`https://github.com/riantr/LunaPack/releases/download/v<version>/`, prints a
progress bar on stdout while it streams, extracts it into the versioned cache
and starts it. The cache is versioned so a newer CLI never silently opens an
older window. A mirror or an offline install can set `LUNAPACK_STUDIO_URL` to
any URL (or a `file` served over loopback in a test); a bad archive is refused
with a message naming the reason.

`HTTPS_PROXY`, `HTTP_PROXY` and their lowercase forms are honoured through a
CONNECT tunnel. `NO_PROXY` (including its `*` wildcard) and all loopback hosts
are always contacted directly, so a local mirror is not sent out through a
corporate proxy. The window inherits the CLI's stdout and stderr: the
`@process` APIs that would redirect them are not stable across toolchains,
and a GUI window writes nothing to the console in normal use. A piped
`lunapack --GUI | ...` therefore reaches EOF when the window is closed.

The Wasm / `moonx` build cannot open a window. On that target `--GUI` prints
the asset URL it would have downloaded and exits with an error instead of
pretending to succeed.

### The subcommands

```bash
lunapack pack   -i <input_dir> -o <output.appkg> [options]
lunapack bundle -i <exe> -o <output.exe> [--Files <dir>]... [options]
lunapack unpack -i <package>   -o <dest_dir>    [--skip-scripts]
lunapack verify <package>      [--extracted <dir>]
lunapack sign   <package>      --secret-key <file> [--output <file>]
lunapack info   <package>
lunapack keygen --public-key <file> --secret-key <file>
```

Flags accept both `--flag=value` and `--flag value`.

> **Which flag names does `bundle` actually read?** Only `-i` / `--input` and
> `-o` / `--output`. The `--input-exe`, `--input-file`, `--output-exe` and
> `--output-file` spellings belong to the **no-subcommand** front end used by
> `moonx riantr/LunaPack@latest ...` (and to `--GUI`, which forwards them to
> the window). They are in the known-flag list so they are not reported as
> typos, but `do_bundle` does not consume them: passing them to `bundle`
> produces *"bundle requires -i <input_exe> and -o <output_exe>"*. The
> examples in this file use the form that matches the command they show.

`verify` checks the package itself. `verify <package> --extracted <dir>` also
checks the files that are already in `dir` against the fingerprints of the
package, which is what the self-extracting bundle uses its cache for. The two
checks are separate and both of them have to hold: a package that is damaged
is not made whole by an extracted directory that is intact.

```cmd
lunapack verify myapp.exe --extracted .lunapack\b7e21c9f4d0a8356
```

`verify <package> --signature <file> --public-key <file>` checks the signature
that the host published next to the package, and `verify <package>
--expected-sha256 <digest>` checks the digest the host published. Both are
checked **before** the package is opened, so a package that does not match the
material of the host is never unpacked at all.

`unpack` accepts the same two flags and honours them: a package whose
signature does not hold, or whose digest is not the one that was expected, is
refused before anything is written. A flag that is accepted and then ignored
would be worse than one that is refused, because the user would believe the
package was checked when it was not.

`sign` is the other side of that: it signs a package with the secret key of the
host and writes the signature next to it.

```cmd
lunapack sign myapp.appkg --secret-key host.key --output myapp.appkg.sig
```

The signature file is a text, so a person can read what it says:

```
lunapack-signature v1
algorithm ed25519
package 0f2a...            <- the SHA-256 of the package
manifest 8c41...           <- the SHA-256 of the manifest
signature 3b90...          <- the Ed25519 signature of the two
```

On a cache that is intact:

```
verify: OK (392 files)
verify: OK (392 files in .lunapack/b7e21c9f4d0a8356)
VERIFY OK
```

After a file was changed on the disk:

```
verify: OK (392 files)
verify: md5 mismatch for appsettings.json: expected 86ff00ef... got 3ddcb685...
verify: FAILED (392 files checked)
VERIFY FAILED
```

The bundle checks every file it writes as it extracts it, so the cache is
verified once when it is filled. The check above is for auditing a cache that
has been on the disk for a while.

### As a native binary

```bash
moon build --release
# -> _build/native/release/build/LunaPack.exe   (every platform)
```

The toolchain names the executable after the package, and calls it `LunaPack.exe`
on every platform, Windows included, so the path is the same everywhere.

### Options

| Option | Meaning |
| --- | --- |
| `--input-file <path>` | another name for `--input-exe` in the no-subcommand / `--GUI` form only |
| `--output-file <path>` | another name for `--output-exe` in the no-subcommand / `--GUI` form only |
| `--input <path>` / `-i` | the input of the `bundle`, `pack` and `unpack` subcommands |
| `--output <path>` / `-o` | the output of those subcommands |
| `--name <name>` | package name (default: input dir / exe name) |
| `--version <ver>` | package version (default: `0.1.0`) |
| `--os <os>` | target OS tag (default: detected) |
| `--arch <arch>` | target arch tag (default: detected) |
| `--pre-install <file>` | script executed *before* extraction |
| `--post-install <file>` | script executed *after* extraction |
| `--compression-method <m>` | `none`, `gzip`, `lz4` or `auto` (default: `auto`) |
| `--launcher <file>` | the launcher of the single file (default: this one) |
| `--encryption-method <m>` | `x25519` or `passphrase` (default: none) |
| `--public-key <file>` | the public key of the recipient, or of the host that signed the package |
| `--secret-key <file>` | the secret key of the recipient |
| `--passphrase-file <file>` | the file that holds the passphrase |
| `--passphrase <text>` | the passphrase itself (visible in the process list) |
| `--skip-scripts` | unpack without running the install scripts |
| `--extracted <dir>` | with `verify`: also check the files already in `<dir>` |
| `--signature <file>` | with `verify` or `unpack`: the signature the host published |
| `--expected-sha256 <hex>` | with `verify` or `unpack`: the digest the host published |
| `--output <file>` | with `sign`: where the signature is written |

### A worked example

```bash
# Bundle an application and its resources into one self-extracting file.
lunapack --input-exe=./build/myapp \
         --output-exe=./dist/myapp \
         --Files=./build

# Or produce a plain archive instead.
lunapack pack -i ./myapp -o myapp.appkg \
  --name myapp --version 1.4.0 \
  --pre-install setup.sh --post-install setup.sh

lunapack verify  myapp.appkg
lunapack unpack  -i myapp.appkg -o /opt/myapp
```

Packing prints the MD5 fingerprint of every file it scans, and the fingerprint
of the file it produces:

```
  md5  6f5902ac237024bdd0c176cb93063dc4  a.txt
  md5  3db2050fcf84bb631dcae417d3db518c  sub/b.txt
scanned 2 files
packed 2 files -> myapp.appkg
output md5  63da650c906fe3ab1446b121a4edd4ca  myapp.appkg
```

The fingerprint of the produced file changes from run to run, because the
manifest records the time of creation.

Unpacking reads every extracted file back and checks its fingerprint against
the one that went into the package, so a file that changed on the way to the
disk is reported:

```
unpacked 2 files -> /opt/myapp
  md5  6f5902ac237024bdd0c176cb93063dc4  a.txt
  md5  3db2050fcf84bb631dcae417d3db518c  sub/b.txt
verified 2 files, 0 mismatches
```

MD5 is not collision resistant, so it is only the fingerprint that can be
compared with what the platform tooling shows; the integrity of the package
rests on the SHA-256 checksum of every entry.

On Windows, with the paths of a real .NET application:

```cmd
lunapack ^
  --input-exe="D:/src/App/bin/Release/net10.0-windows/App.exe" ^
  --output-exe="D:/dist/App.exe" ^
  --Files="D:/src/App/bin/Release/net10.0-windows"
```

The contents of a single `--Files` directory are stored at the root of the
archive next to the main program, so the extracted application is directly
runnable. With several `--Files` directories each one gets a subdirectory
named after it. The main program is never stored twice, even when it also
lives inside the `--Files` folder.

## Verification

`moon fmt --check`, the two `moon check` targets, `moon test --target native`
and the two release builds are the baseline, and `bash scripts/test_linux.sh`
is the end-to-end suite on top of it.

| Gate | What it checks |
|---|---|
| `moon fmt --check` | that the source is formatted the way the toolchain formats it |
| `moon check --target native` / `--target wasm` | that the module type-checks on both backends it claims |
| `moon test --target native` | the format, the compression, the encryption, the primitives |
| `moon build --release --target native` / `--target wasm` | that the binary and the WebAssembly module are produced |
| `moon info` + `git diff --exit-code -- '*.mbti'` | that the published interface is not stale |
| `bash scripts/test_linux.sh` | the round trip the unit tests do not cover |

Measured on this machine (Windows, `moon 0.1.20261102`): `moon test --target
native` reports **150 tests, 150 passed, 0 failed**, and `--target wasm`
reports the same.

One of those tests needs a POSIX `sh`, because it exercises the POSIX branch of
the install-script runner on a Windows host. Without a shell on `PATH` it
cannot run, and before 0.1.6 it failed with the runtime's *"The system cannot
find the file specified."* — a message that names no file and reads like a
defect. The error now names the interpreter that was missing. A host with Git
for Windows' `sh` (or Cygwin's) on `PATH` runs the whole suite.

The two tests that cover the error itself name an interpreter that cannot
exist on any host, so they are the same everywhere: they check that the error
names the interpreter, and that the temporary script file is removed again when
the interpreter could not be started.

CI runs on Linux, macOS and Windows, and the Windows runner has Git for
Windows, whose `sh` is on `PATH`, so the whole suite runs there. The macOS
leg is optional — a run that lands while no runner of that kind is free is
cancelled without failing the run — so a green run is not a claim that the
macOS leg was scheduled. The gap was a developer machine without a POSIX
shell, not the code.

The end-to-end suite needs a real POSIX host, because it runs the install
scripts and checks the permission bits, so CI runs it on the Linux runner. It
has **19 sections**: the environment, the build, the unit tests, the fixture,
packing, the manifest, the checksums, the unpack, the content integrity, the
executable bit, compression, the bundle, the MD5 fingerprints, the LZ4 codec,
the encryption, the corruption detection, the integrity of the manifest, the
signature of the host and `--skip-scripts`. It compares the bundled
executable with the original byte for byte.

The unit tests cover the LZ4 implementation as well: the round trip for every
shape of payload — empty, short, repetitive, random, a sentence, a sentence
with other periods, and one that crosses the block boundary — the magic number
of the frame, and the xxHash of the frame header against the value the
reference implementation produces.

There is **no test that runs the `lz4` tool**: the frames are compared against
the values the format publishes, not against the tool. That is a gap, not a
claim of coverage, and it is named here rather than left implied.

The tests of the encryption check every primitive against the vector that its
standard publishes — FIPS 180-4 for SHA-512, RFC 4231 for HMAC, RFC 5869 for
HKDF, RFC 8439 for ChaCha20-Poly1305, RFC 7748 for X25519 and RFC 8032 for
Ed25519 — and the derivation against the reference implementation itself: the
master key, the key and the nonce of a record, the check of the key and the
sealed record are compared byte for byte with the values that the reference
produces.

### Every guard was taken out once

A test that passes because the guard is not there says nothing, so every
guard of the integrity stack was **removed from the code once** and the suite
was run again. The test that covers the guard has to go red, for that reason
alone, or the guard is not covered by a test at all.

| Guard that was removed | The test that went red |
|---|---|
| the SHA-256 of the manifest | a package whose manifest was changed is refused |
| the MAC of the manifest | a sealed package whose manifest was changed is refused |
| the check of the cache | the cache is only used again when it holds what the package carries |
| the check of the program | the program of a bundle is checked before it is started |
| the refusal of a damaged package | a damaged package is not taken for a file that is not a package |
| the write in one piece | a pack that fails leaves the target alone |
| the comparison of the two checksums | a checksum that is not the same twice is refused |
| the check of the signature | a signature does not hold for another public key |
| the check of the paths | a path that walks out of the destination is refused |
| the signing key of a pair | the signing key of a pair checks a signature made with it |
| the separation of the two roles | the two roles of a pair are separated |
| the cleanup of the archive of a refused bundle | a refused bundle leaves nothing behind |
| the warning that tells the two kinds of bundle apart | the two kinds of bundle are told apart |
| the read-back of the cache after it arrives | a cache that does not hold the payload is not handed out |
| the ownership of the console | the console of the terminal is not taken away |
| the clamp of the bar | the progress bar tells the truth about what is left |
| the answer of the console | only a key press answers a question |
| the second spelling of the folder flag | the folder flag is read under both spellings |
| the platform flag | the platform flag is a flag the tool knows |

The battery that does this is `scripts/mutation_battery.ps1`. It restores the
file it changed, so a run leaves the tree exactly as it was.

One of the two guards of the *sealed* manifest needed a second look, and the
reason is worth stating because it is the whole point of the design: a test
that changes the manifest of a sealed package is caught by the **digest**
first, so it proves nothing about the MAC. The test that covers the MAC
therefore changes the manifest *and* recomputes the digest, which is exactly
what an attacker who holds the file can do — and the MAC still catches it,
because the MAC is keyed with the key of the package and the key is not in
the package.

The guards `the signing key of a pair` and `the separation of the two roles`
are there because of a defect the Linux end-to-end suite found in 0.1.8 and
the unit tests had not: `keygen`
wrote the **encryption** public key, and the signature was checked against it,
so a signature made with the secret key of the pair never held. The public key
file holds both public keys now, and the chain that the command line walks —
make a pair, sign a package, check the signature — is held by a unit test, so
it no longer depends on a host with a POSIX shell to be checked.


## What this is not

- The exit code of a command says whether it worked: `0` when it did, `1`
  when it did not. The status is on stdout as well (`VERIFY OK` /
  `VERIFY FAILED` / `error: ...`), so a script that reads the output still
  works. A single-file bundle reports the exit code of the program it
  carries, exactly.
- UNIX permission bits cannot be set on Windows, so they are only applied on
  POSIX hosts.
- The checksum is computed over the original content; `verify` therefore has
  to decompress every entry.
- The fingerprint of the produced file is computed while it is written, so the
  file is never read back for that. The launcher stub is the one exception: it
  is hashed after the icon was written into it, because writing the icon
  changes its bytes.
- The big integers of the core are not constant time, so the X25519 of this
  package is not either. The control flow of the ladder does not depend on the
  secret, but the time of the arithmetic does. For the use here — a key
  exchange on the machine that holds the secret key — that is not the threat,
  but it is a reason to look elsewhere when it is.
- The encryption protects the content of the entries. The names of the entries
  and their sizes are in the manifest, which is not encrypted.
- The launcher stub is the LunaPack executable of the machine that built the
  bundle, so a bundle runs on the platform it was created on. Under `moonx`
  (Wasm) no native stub exists, so the bundle falls back to carrying the
  payload inside the application executable — such a bundle holds the data but
  does not extract itself.
- The extraction cache lives next to the bundle (`.lunapack/<hash>/`). When
  that folder cannot be written, a temporary directory is used instead.
- Copying the icon is Windows only, because an icon is a Windows resource.
- Bundling writes the archive to a temporary file next to the output, so there
  must be enough free disk space for it.
- The package is built on `moonbitlang/core/async`, which the toolchain ships
  as an experimental package. The MoonBit developers have confirmed that the
  stable releases will use it, so the package follows the toolchain rather
  than pinning an older release of the runtime.

## Quick Start

Add the module:

```sh
moon add riantr/LunaPack
```

Bundle an application and the files it needs into one self-extracting file:

```sh
lunapack bundle -i ./build/myapp -o ./dist/myapp --Files ./build
./dist/myapp --version
```

Or review the same job in a window. Studio is part of this release and is
downloaded on first use:

```sh
lunapack --GUI --input-file=./build/myapp --output-file=./dist/myapp --Files=./build
```

Or produce a plain archive and take it apart again:

```sh
lunapack pack   -i ./myapp -o myapp.appkg
lunapack verify myapp.appkg
lunapack unpack -i myapp.appkg -o /opt/myapp
```

From this repository:

```sh
moon test                                  # 150 tests
moon build --release --target native       # the binary
moon build --release --target wasm         # the WebAssembly module
```

## Example

```moonbit nocheck
///|
async fn main {
  // A plain archive: a directory, compressed per entry, checksummed per entry.
  let opts = @lp.new_pack_options(
    "myapp", // the name of the package
    "1.4.0", // the version of the package
    "linux", // the os tag
    "x86_64", // the arch tag
    None, // the pre-install script
    None, // the post-install script
    "auto", // the compression
  )
  @lp.pack("./myapp", "myapp.appkg", opts)

  // The same application as a single self-extracting file. The launcher is the
  // running program itself, and the main program is recorded by the bundle.
  @lp.bundle("./build/myapp", "./dist/myapp", ["./build"], opts, "")

  // Read the manifest back, and check the package.
  let m = @lp.read_package_manifest("myapp.appkg")
  let ok = @lp.verify("myapp.appkg", None)
  @lp.unpack("myapp.appkg", "/opt/myapp", true, None)
}
```

The archive is found from the tail of the file, so the same three calls work
on a bundle as on a plain package:

```moonbit nocheck
///|
async fn main {
  match @lp.probe_archive("./dist/myapp") {
    Some((offset, manifest)) => {
      println("the archive starts at " + offset.to_string())
      println("it holds " + manifest.entries.length().to_string() + " entries")
    }
    None => println("this file carries no LunaPack archive")
  }
}
```

An encrypted package carries its own key material in the manifest, and the key
is recovered from the secret key file or from the passphrase:

```moonbit nocheck
///|
async fn main {
  let m = @lp.read_package_manifest("secret.appkg")
  match m.encryption {
    Some(info) => {
      let key = @lp.recover_encryption(info, "recipient.key", "")
      @lp.unpack("secret.appkg", "./out", true, Some(key))
    }
    None => ()
  }
}
```

## Gates and drift detectors

`moon fmt --check`, the two `moon check` targets, `moon test --target native`
and `moon build --release` are the baseline. Each of them catches a specific
drift, because a green suite says nothing about a claim written in prose:

| Gate | Catches |
|---|---|
| `moon fmt --check` | a source file that is not formatted the way the toolchain formats it — a diff the next contributor would have to make |
| `moon check --target native` / `--target wasm` | a package that does not type-check on one of the two backends it claims to support |
| `moon test --target native` | a change in the format, the compression, the encryption or one of the primitives — every one of them is checked against a vector or against the reference implementation |
| `moon info` + `git diff --exit-code -- '*.mbti'` | a published interface that is stale: a symbol changed and the `.mbti` was not regenerated |
| `bash scripts/test_linux.sh` | a round trip the unit tests do not cover — the install scripts, the permission bits, the corruption detection, the bundle as a byte-identical round trip |
| the tag check of the release workflow | a tag that disagrees with the version in `moon.mod`, which would publish a module that is not the tree it was cut from |

**There are no separate drift detectors here.** The gates above are the whole
gate, and the numbers in this file come from running them by hand. A gate that
only runs when someone remembers it is a gate that drifts, and that gap is
worth closing rather than papering over.

**Which of them CI runs.** The CI workflow (`.github/workflows/ci.yml`) runs
`moon check --target native`, `moon test --target native`, both release
builds, `bash scripts/test_linux.sh` on the Linux runner, `moon fmt --check`
and the `moon info` diff. The `moon check --target wasm` and the
`moon test` on the Wasm backend are **not** in CI: they are listed here
because they were run by hand, not because CI depends on them.

## Used By

- `cli.mbt` — the command line of this module, the front end over the library
  that lives in the same package.
- `integrity.mbt` — the integrity block: the digest and the MAC of the
  manifest, and the checksums that are computed twice.
- `ed25519.mbt` — the signature that the host publishes next to a package.
- `signature.mbt` — the signature file and the checks of the host material.
- `scripts/test_linux.sh` — the end-to-end suite, which drives the binary that
  the module builds.
- `scripts/mutation_battery.ps1` — the development tool that takes every guard
  out of the code once and checks that the test covering it goes red.

Outside this repository: **none that the registry knows about.** The registry
lists **0 dependents** for `riantr/LunaPack`, and nothing is claimed here that
cannot be named.

## Attribution

- License: MIT (see `LICENSE`).
- The mechanism of the encryption and the shape of the container follow the
  reference implementation this package follows. Every primitive it needs is
  implemented in this package, because the MoonBit toolchain ships none of
  them, and each one is checked against the vector that its standard
  publishes.
- The LZ4 codec is an implementation of the format, not a port of a library:
  what it produces is a standard `.lz4` frame, and the test suite checks the
  frames against the values the format publishes.
- The Ed25519 signature is an implementation of RFC 8032, not a port of a
  library. It is checked against vectors that another implementation produced,
  so a signature that is right here is right against every other
  implementation of the standard.

