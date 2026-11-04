# LunaPack

**LunaPack** is an application-distribution packer written in
[MoonBit](https://www.moonbitlang.com/). It bundles an application
executable together with its resources into a single distributable file, and
unpacks it again on the target machine with integrity checking.

Repository: [github.com/riantr/LunaPack](https://github.com/riantr/LunaPack)
(mirrored to [gitee.com/ren-yongxiang/lunaPack](https://gitee.com/ren-yongxiang/lunaPack)
for everyday storage).

- **SHA-256** checksums for every entry (verified on unpack).
- **MD5** fingerprints for every entry: the files are scanned before they go
  into the package, the fingerprints are listed, and after unpacking every
  extracted file is read back and checked against the fingerprint it had.
  The fingerprint of the produced file is reported as well.
- **gzip** and **LZ4** compression per entry. LZ4 is implemented in this
  package and trades a larger result for a much shorter packing time.
- **Cross-platform**: runs on Windows, Linux and macOS; packages carry their
  install scripts with the platform they target.
- **Native and Wasm**: usable as a standalone binary or through `moonx`.

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

The release is built by a GitHub workflow when a version tag such as
`v0.1.2` is pushed; the same version is published to the Mooncakes registry,
so `moonx riantr/LunaPack/cmd/main@latest` resolves to it.

The registry requires a `0.x.y` version while it is in its early stage, so
the releases are numbered `0.1.0`, `0.1.1`, `0.1.2` and so on.

## Usage

### Via `moonx` (published on Mooncakes)

```bash
moonx riantr/LunaPack/cmd/main@latest \
  --input-exe=[input-exe-path] \
  --output-exe=[output-exe-path] \
  --Files=[Pack-Folder]
```

The coordinate names the package that holds the entry point, because the
registry stores the prebuilt WebAssembly module per package. The entry point
lives in `cmd/main`, so the coordinate is `riantr/LunaPack/cmd/main@latest`.

| Flag | Meaning |
| --- | --- |
| `--input-exe` | the application executable to distribute |
| `--output-exe` | the produced single-file bundle |
| `--Files` | folder of files to bundle with it (repeatable) |

The result is a **self-extracting bundle**: the LunaPack launcher with the
archive appended, exactly the trick a WinRAR or 7-Zip self-extracting archive
uses.

> The bundle is self-extracting only when it is produced by a **native**
> LunaPack binary, because the launcher stub is the binary itself. A bundle
> produced through `moonx` runs on WebAssembly and therefore carries the
> payload without a native launcher; use the native binary to get a
> self-extracting file.

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
folder - a plain copy of the executable would not run at all.

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

The icon is read from the application executable with a small PE reader and
written into the bundle with the Windows resource API, which creates the
resource section the launcher does not have. All icon sizes are copied, so the
bundle looks right at every zoom level.

This is a Windows feature: an icon is a Windows resource, so on Linux and
macOS the bundle keeps the icon of the launcher. Use `--Files` with the
application's own `.ico` file there, or install the icon separately.

`lunapack unpack` recognises the appended archive automatically, so the same
file can be verified and extracted again:

```bash
lunapack verify  myapp.exe
lunapack info    myapp.exe
lunapack unpack  -i myapp.exe -o ./out
```

### As a native binary

```bash
moon build --release
# -> _build/native/release/build/cmd/main/main.exe   (every platform)
```

The toolchain calls the executable `main.exe` on every platform, Windows
included, so the path is the same everywhere.

The package has **no dependencies**: everything it needs comes with the
MoonBit toolchain, so there is nothing to download and `moon update` is not
needed.

```
lunapack pack   -i <input_dir> -o <output.appkg> [options]
lunapack unpack -i <package>   -o <dest_dir>    [--skip-scripts]
lunapack verify <package>      [--extracted <dir>]
lunapack info   <package>
```

Flags accept both `--flag=value` and `--flag value`.

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
| `--skip-scripts` | unpack without running the install scripts |
| `--extracted <dir>` | with `verify`: also check the files already in `<dir>` |

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
decompresses it, and this package decompresses what that tool produces. Both
directions are covered by the test suite.

### Example

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

Packing prints the MD5 fingerprint of every file it scans, and the
fingerprint of the file it produces:

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

Files that are already on the disk can be audited against the package, which
is what the self-extracting bundle uses its cache for:

```cmd
lunapack verify BRLabeler.exe --extracted .lunapack\60844df795cb7f31
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
verified once when it is filled. The check above is for auditing a cache
that has been on the disk for a while.

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

The binary to use is the one from the release, not `moonx`:

```cmd
D://src//WorkBuddy//Moonbit//LunaPack//_build//native//release//build//cmd//main//main.exe ^
  --input-exe="D://zkhongtuo//src//MOlabeler_V2.6//bin//x64//Release//net10.0-windows10.0.22000.0//BRLabeler.exe" ^
  --output-exe="D://zkhongtuo//src//MOLabeler_V2.6//bin//BRLabeler.exe" ^
  --Files="D://zkhongtuo//src//MOlabeler_V2.6//bin//x64//Release//net10.0-windows10.0.22000.0"
```

## Publishing to Mooncakes

`moonx` resolves a package from the registry, so publish the module first:

```bash
moon login                 # once
moon publish --dry-run     # validate
moon publish               # publish riantr/LunaPack
moonx riantr/LunaPack/cmd/main@latest --input-exe=... --output-exe=... --Files=...
```

The registry refuses a version that already exists, so a release needs a new
number in `moon.mod`.

The module publishes with `supported_targets = "native+wasm"`; `moonx` runs
the Wasm build, which reads and writes the real filesystem through the MoonBit
runtime.

Because the package has no dependencies, the published module carries none
either: nothing has to be resolved when it is fetched.

## Install scripts

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

- `LUNAPACK_DEST` - absolute path of the destination directory
- `LUNAPACK_PHASE` - `pre_install` or `post_install`

Use `--skip-scripts` to unpack without running them.

## Package format

The container layout has not changed since v2: the marker names the layout,
and the manifest carries its own `format_version`. The current manifest is
version 4, which adds the MD5 fingerprint of every entry and the LZ4 codec.
A package written
by an older version still unpacks, because the fingerprint is optional.

```
+--------------------+  offset 0
| magic "APPKGD02"   |  8 bytes
+--------------------+  offset 8
| entry payloads     |  stored back to back, raw, gzip or lz4
+--------------------+
| manifest (UTF-8    |
| JSON)              |
+--------------------+
| magic "APPKGD02"   |  8 bytes
| manifest offset    |  8 bytes, little-endian int64
| manifest length    |  8 bytes, little-endian int64
+--------------------+  end of file
```

The manifest records the package metadata plus one record per entry:

```json
{
  "format_version": 4,
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

A bundle is the same archive appended to an executable. The archive length is
`manifest_offset + manifest_length + 24`, so the archive can be located from
the tail of the file without scanning it.

## Testing

```bash
moon test                      # unit + integration tests
bash scripts/test_linux.sh     # end-to-end suite (Linux / WSL)
```

`scripts/test_linux.sh` covers packing, bundling, checksums, the MD5
fingerprints, compression, the executable bit, install-script execution,
corruption detection and `--skip-scripts`. It needs a real POSIX host, so the
CI runs it on the Linux runner.

The unit tests cover the LZ4 implementation as well: the round trip for
every shape of payload, the xxHash of the frame header against the value the
reference implementation produces, and the interoperability with the `lz4`
tool in both directions. That last test is skipped where the tool is not
installed.

## Notes and limitations

- `main` must return `Unit` in this MoonBit version, so the process exit code
  is always `0`. Status is reported on stdout (`VERIFY OK` / `VERIFY FAILED` /
  `error: ...`); scripts that need an exit code should grep for those markers.
- UNIX permission bits cannot be set on Windows, so they are only applied on
  POSIX hosts.
- The checksum is computed over the original content; `verify` therefore has
  to decompress every entry.
- The fingerprint of the produced file is computed while it is written, so the
  file is never read back for that. The launcher stub is the one exception:
  it is hashed after the icon was written into it, because writing the icon
  changes its bytes.
- The launcher stub is the LunaPack executable of the machine that built the
  bundle, so a bundle runs on the platform it was created on. Under `moonx`
  (Wasm) no native stub exists, so the bundle falls back to carrying the
  payload inside the application executable - such a bundle holds the data but
  does not extract itself.
- The extraction cache lives next to the bundle (`.lunapack/<hash>/`). When
  that folder cannot be written, a temporary directory is used instead.
- Copying the icon is Windows only, because an icon is a Windows resource.
- Bundling writes the archive to a temporary file next to the output, so
  there must be enough free disk space for it.
- The package is built on `moonbitlang/core/async`, which the toolchain
  ships as an experimental package. The MoonBit developers have confirmed
  that the stable releases will use it, so the package follows the toolchain
  rather than pinning an older release of the runtime.
