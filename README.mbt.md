# LunaPack

**LunaPack** is an application-distribution packer written in
[MoonBit](https://www.moonbitlang.com/). It bundles an application
executable together with its resources into a single distributable file, and
unpacks it again on the target machine with integrity checking.

- **SHA-256** checksums for every entry (verified on unpack).
- **gzip** compression per entry, with an `auto` mode that only compresses
  when it actually helps.
- **Cross-platform**: runs on Windows, Linux and macOS; packages carry their
  install scripts with the platform they target.
- **Native and Wasm**: usable as a standalone binary or through `moonx`.

## Usage

### Via `moonx` (published on Mooncakes)

```bash
moonx riantr/LunaPack@latest \
  --input-exe=[input-exe-path] \
  --output-exe=[output-exe-path] \
  --Files=[Pack-Folder]
```

| Flag | Meaning |
| --- | --- |
| `--input-exe` | the application executable to distribute |
| `--output-exe` | the produced single-file bundle |
| `--Files` | folder of files to bundle with it (repeatable) |

The result is a **self-extracting bundle**: the LunaPack launcher with the
archive appended, exactly the trick a WinRAR or 7-Zip self-extracting archive
uses.

```
myapp.exe  =  [ LunaPack launcher ]  +  [ archive: myapp.exe, res/app.cfg, ... ]
```

Starting it extracts the payload and launches the bundled program:

```
$ ./myapp.exe
LunaPack: starting D:/apps/.lunapack/8e75898941d4c137/myapp.exe
```

The payload is cached in `.lunapack/<hash>/` next to the executable, so the
second start is immediate. Delete that folder to force a fresh extraction.

Because the launcher does the extraction, the application finds its own
dependencies (`.dll`, `.json`, assets) exactly like it would in its build
folder - a plain copy of the executable would not run at all.

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
# -> _build/native/release/build/cmd/main/main.exe   (Windows)
# -> _build/native/release/build/cmd/main/main        (Linux / macOS)
```

```
lunapack pack   -i <input_dir> -o <output.appkg> [options]
lunapack unpack -i <package>   -o <dest_dir>    [--skip-scripts]
lunapack verify <package>
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
| `--compression <mode>` | `none`, `gzip` or `auto` (default: `auto`) |

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

## Publishing to Mooncakes

`moonx` resolves a package from the registry, so publish the module first:

```bash
moon login                 # once
moon publish --dry-run     # validate
moon publish               # publish riantr/LunaPack
moonx riantr/LunaPack@latest --input-exe=... --output-exe=... --Files=...
```

The module publishes with `supported_targets = "native+wasm"`; `moonx` runs
the Wasm build, which reads and writes the real filesystem through the MoonBit
runtime.

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

## Package format (v2)

```
+--------------------+  offset 0
| magic "APPKGD02"   |  8 bytes
+--------------------+  offset 8
| entry payloads     |  stored back to back, raw or gzip
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
  "format_version": 2,
  "name": "myapp",
  "version": "1.4.0",
  "os": "linux",
  "arch": "x86_64",
  "checksum_algo": "sha256",
  "compression": "auto",
  "created_at": "2026-11-03T06:55:56Z",
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
      "offset": 8
    }
  ]
}
```

- `size` is the original file size, `stored_size` the space it occupies in the
  package.
- `checksum` is the SHA-256 of the **original** content, so it validates the
  data the user actually gets, not the compressed form.
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

`scripts/test_linux.sh` covers packing, bundling, checksums, compression, the
executable bit, install-script execution, corruption detection and
`--skip-scripts`.

## Notes and limitations

- `main` must return `Unit` in this MoonBit version, so the process exit code
  is always `0`. Status is reported on stdout (`VERIFY OK` / `VERIFY FAILED` /
  `error: ...`); scripts that need an exit code should grep for those markers.
- UNIX permission bits cannot be set on Windows, so they are only applied on
  POSIX hosts.
- The checksum is computed over the original content; `verify` therefore has
  to decompress every entry.
- The launcher stub is the LunaPack executable of the machine that built the
  bundle, so a bundle runs on the platform it was created on. Under `moonx`
  (Wasm) no native stub exists, so the bundle falls back to carrying the
  payload inside the application executable - such a bundle holds the data but
  does not extract itself.
- The extraction cache lives next to the bundle (`.lunapack/<hash>/`). When
  that folder cannot be written, a temporary directory is used instead.
- Bundling writes the archive to a temporary file next to the output, so
  there must be enough free disk space for it.
