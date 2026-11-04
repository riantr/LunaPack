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
produced file **behaves like the program it carries** — its arguments, its exit
code, its subsystem and its standard streams are the ones of the bundled
program.

One container, two front ends: a native binary that is built for the platform
it runs on, and a WebAssembly build that `moonx` runs from the Mooncakes
registry. The package has **no dependencies**, so nothing has to be resolved
when it is fetched.

Repository: [github.com/riantr/LunaPack](https://github.com/riantr/LunaPack)
(mirrored to [gitee.com/ren-yongxiang/lunaPack](https://gitee.com/ren-yongxiang/lunaPack)
for everyday storage).

## Features

* A bundle that is the program, not a wrapper around it

  The archive is appended to the LunaPack launcher, so the produced file *is*
  the launcher — and the launcher is the program the user starts. The
  arguments of the bundle are the arguments of the bundled program, the exit
  code is its exit code, the Windows subsystem is its subsystem (so a windowed
  program does not flash a console window), and the standard streams are the
  ones of the bundle. A copy of the executable would not do this; a plain
  archiver cannot do it at all.

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
| `@LunaPack.ed25519_public_key(secret)` | the public key of a signing key | `Bytes` |
| `@LunaPack.ed25519_sign(secret, message)` | a signature of a message | `Bytes` |
| `@LunaPack.ed25519_verify(public, message, signature)` | whether a signature holds | `Bool` |
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
moon add riantr/LunaPack@0.1.8
```

That is a **module** dependency, and it belongs in the consumer's `moon.mod`.
`moon add` writes it for you, so the file ends up holding:

```toml
import {
  "riantr/LunaPack@0.1.8",
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
`latest`, `^0.1.8`, `>=0.1.8`, `0.1` and `v0.1.8` are all rejected. A bare
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
test, and the one below) and `--target wasm` reports **6** (the same two, plus
four in the Windows-only icon helpers, which the WebAssembly backend does not
use). No gate runs with `--deny-warn`, and none of the warnings is an error.

The second warning is the price of the short coordinate, and it is worth naming
exactly: *"Main package `riantr/LunaPack` uses blackbox-only test inputs
(`_test.mbt` files) … Main packages will stop generating blackbox tests in a
future release."* The blackbox tests of the public API run today, and a
toolchain that stops generating them would take that coverage with it. The
alternative — a library in a non-main package under `src/`, with the root as
the entry point — keeps the tests and the import path of the library safe, at
the price of the library moving to `riantr/LunaPack/src/lunapack`.

## Releases

Prebuilt binaries are attached to every
[GitHub release](https://github.com/riantr/LunaPack/releases):

| Asset | Platform |
| --- | --- |
| `lunapack-windows-x86_64.exe` | Windows |
| `lunapack-linux-x86_64` | Linux |
| `lunapack-macos-aarch64` | macOS (Apple Silicon) |
| `lunapack.wasm` | WebAssembly, for `moonx` |
| `lunapack.core` | the compiled package the WebAssembly module needs |

The release is built by a GitHub workflow when a version tag such as `v0.1.8`
is pushed; the same tag is published to the Mooncakes registry, so
`moonx riantr/LunaPack@latest` resolves to it. The tag is the source
of truth: the workflow compares it against the version in `moon.mod` before it
builds anything, so a tag and the published module cannot disagree.

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

### A single file that behaves like the program

The bundle is not only a container: it is the program, with the files it needs
around it.

- The **arguments** of the bundle are the arguments of the bundled program.
- The **exit code** of the bundle is the exit code of the bundled program.
- The **subsystem** of the bundle is the subsystem of the bundled program, so a
  windowed program does not flash a console window when it is started.
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
$ lunapack --input-exe=./BRLabeler.exe --output-exe=./BRLabeler.exe --Files=./build
  md5  cb77181515d4680a960433f65ba05bef  BRLabeler.exe
  ...
scanned 392 files
bundled 392 files -> ./BRLabeler.exe (icon copied)
output md5  f5f06ca638d59a31e773c0a28358804d  BRLabeler.exe
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
| `--Files` | folder of files to bundle with it (repeatable) |

The result is a **self-extracting bundle**: the LunaPack launcher with the
archive appended, exactly the trick a WinRAR or 7-Zip self-extracting archive
uses.

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

`verify` checks the package itself. `verify <package> --extracted <dir>` also
checks the files that are already in `dir` against the fingerprints of the
package, which is what the self-extracting bundle uses its cache for:

```cmd
lunapack verify BRLabeler.exe --extracted .lunapack\60844df795cb7f31
```

`verify <package> --signature <file> --public-key <file>` checks the signature
that the host published next to the package, and `verify <package>
--expected-sha256 <digest>` checks the digest the host published. Both are
checked **before** the package is opened, so a package that does not match the
material of the host is never unpacked at all.

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
verify: OK (392 files in .lunapack/60844df795cb7f31)
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
| `--name <name>` | package name (default: input dir / exe name) |
| `--version <ver>` | package version (default: `0.1.0`) |
| `--os <os>` | target OS tag (default: detected) |
| `--arch <arch>` | target arch tag (default: detected) |
| `--pre-install <file>` | script executed *before* extraction |
| `--post-install <file>` | script executed *after* extraction |
| `--compression-method <m>` | `none`, `gzip`, `lz4` or `auto` (default: `auto`) |
| `--launcher <file>` | the launcher of the single file (default: this one) |
| `--encryption-method <m>` | `x25519` or `passphrase` (default: none) |
| `--public-key <file>` | the public key of the recipient |
| `--secret-key <file>` | the secret key of the recipient |
| `--passphrase-file <file>` | the file that holds the passphrase |
| `--passphrase <text>` | the passphrase itself (visible in the process list) |
| `--skip-scripts` | unpack without running the install scripts |
| `--extracted <dir>` | with `verify`: also check the files already in `<dir>` |
| `--signature <file>` | with `verify`: the signature the host published |
| `--expected-sha256 <hex>` | with `verify`: the digest the host published |
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
native` reports **109 tests, 109 passed, 0 failed**.

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

CI is green on all three runners — Linux, macOS and Windows — because the
Windows runner has Git for Windows, whose `sh` is on `PATH`. The gap was a
developer machine without a POSIX shell, not the code.

The end-to-end suite needs a real POSIX host, because it runs the install
scripts and checks the permission bits, so CI runs it on the Linux runner. It
has **17 sections**: the environment, the build, the unit tests, the fixture,
packing, the manifest, the checksums, the unpack, the content integrity, the
executable bit, compression, the bundle, the MD5 fingerprints, the LZ4 codec,
the encryption, the corruption detection and `--skip-scripts`. It compares the
bundled executable with the original byte for byte.

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


## What this is not

- `main` must return `Unit` in this MoonBit version, so the process exit code
  is always `0`. Status is reported on stdout (`VERIFY OK` / `VERIFY FAILED` /
  `error: ...`); scripts that need an exit code should grep for those markers.
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

Or produce a plain archive and take it apart again:

```sh
lunapack pack   -i ./myapp -o myapp.appkg
lunapack verify myapp.appkg
lunapack unpack -i myapp.appkg -o /opt/myapp
```

From this repository:

```sh
moon test                                  # 75 tests
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

- License: Apache-2.0 (see `LICENSE`).
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

