#!/usr/bin/env bash
# Linux / WSL test suite for LunaPack.
#
# Usage (inside WSL):
#   cd /mnt/d/src/WorkBuddy/Moonbit/LunaPack
#   bash scripts/test_linux.sh
#
# Requires the MoonBit toolchain (`moon`) on PATH.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${LUNAPACK_TEST_DIR:-/tmp/lunapack_linux_test}"
# The toolchain calls the executable LunaPack.exe on every platform.
BIN="$PROJECT_DIR/_build/native/debug/build/LunaPack.exe"

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

section "environment"
command -v moon >/dev/null || { fail "moon not found on PATH"; }
moon version 2>/dev/null | head -1 || true
uname -srm
printf 'work dir: %s\n' "$WORK_DIR"

section "build"
cd "$PROJECT_DIR"
moon build 2>&1 | grep -E "Finished|error" || true
[ -x "$BIN" ] || fail "binary not built at $BIN"
pass "native binary built"

section "unit tests"
moon test 2>&1 | grep -E "Total tests" || fail "unit tests did not run"

section "fixture"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/src/sub" "$WORK_DIR/src/bin"
printf 'hello lunapack\n' > "$WORK_DIR/src/hello.txt"
printf 'nested payload\n'   > "$WORK_DIR/src/sub/world.txt"
# A highly compressible file and an incompressible one.
python3 - "$WORK_DIR" <<'PY'
import os, sys
w = sys.argv[1]
open(os.path.join(w, "src", "big.txt"), "w").write("The quick brown fox jumps over the lazy dog. " * 500)
open(os.path.join(w, "src", "bin", "blob.dat"), "wb").write(os.urandom(4096))
PY
# An executable file, to check that the x-bit survives the round trip.
cat > "$WORK_DIR/src/run.sh" <<'SH'
#!/bin/sh
echo "hello from the packaged script"
SH
chmod 755 "$WORK_DIR/src/run.sh"
# POSIX install scripts.
cat > "$WORK_DIR/pre_install.sh" <<'SH'
#!/bin/sh
echo "PRE_INSTALL phase=$LUNAPACK_PHASE dest=$LUNAPACK_DEST"
printf 'pre\n' > "$LUNAPACK_DEST/pre_install_ran.txt"
SH
cat > "$WORK_DIR/post_install.sh" <<'SH'
#!/bin/sh
echo "POST_INSTALL phase=$LUNAPACK_PHASE dest=$LUNAPACK_DEST"
printf 'post\n' > "$LUNAPACK_DEST/post_install_ran.txt"
SH
chmod 755 "$WORK_DIR/pre_install.sh" "$WORK_DIR/post_install.sh"
pass "fixture created"

section "pack"
"$BIN" pack -i "$WORK_DIR/src" -o "$WORK_DIR/pkg.appkg" \
  --name "linux-demo" --version "1.0.0" \
  --pre-install "$WORK_DIR/pre_install.sh" \
  --post-install "$WORK_DIR/post_install.sh" \
  --compression auto
[ -f "$WORK_DIR/pkg.appkg" ] || fail "package not created"
pass "package created"

section "info"
"$BIN" info "$WORK_DIR/pkg.appkg"
"$BIN" info "$WORK_DIR/pkg.appkg" | grep -q "linux" || fail "os tag is not linux"
pass "manifest reports linux"

section "verify"
"$BIN" verify "$WORK_DIR/pkg.appkg"
pass "checksums verified"

section "unpack (runs POSIX install scripts)"
"$BIN" unpack -i "$WORK_DIR/pkg.appkg" -o "$WORK_DIR/out"
[ -f "$WORK_DIR/out/pre_install_ran.txt" ]  || fail "pre_install did not run"
[ -f "$WORK_DIR/out/post_install_ran.txt" ] || fail "post_install did not run"
pass "install scripts executed"

section "content integrity"
diff -r "$WORK_DIR/src" "$WORK_DIR/out" \
  --exclude='pre_install_ran.txt' --exclude='post_install_ran.txt' \
  && pass "extracted tree is identical to the source" \
  || fail "extracted tree differs from the source"

section "executable bit"
[ -x "$WORK_DIR/out/run.sh" ] || fail "executable bit was not preserved"
pass "executable bit preserved"

section "compression"
"$BIN" info "$WORK_DIR/pkg.appkg" | grep -q "gzip" || fail "no gzip entry produced"
pass "gzip compression applied"

section "bundle"
# --input-exe / --output-exe / --Files
mkdir -p "$WORK_DIR/dist"
printf 'MY APP\n' > "$WORK_DIR/myapp"
"$BIN" --input-exe="$WORK_DIR/myapp" \
       --output-exe="$WORK_DIR/dist/myapp" \
       --Files="$WORK_DIR/src"
[ -f "$WORK_DIR/dist/myapp" ] || fail "bundle was not created"
# The bundle starts with the LunaPack launcher, not with the application:
# the launcher is what extracts the payload and starts the program.
"$BIN" info "$WORK_DIR/dist/myapp" | grep -q "main program: myapp" \
  || fail "bundle manifest does not record the main program"
"$BIN" verify "$WORK_DIR/dist/myapp" >/dev/null || fail "bundle does not verify"
rm -rf "$WORK_DIR/bundle_out"
"$BIN" unpack -i "$WORK_DIR/dist/myapp" -o "$WORK_DIR/bundle_out"
cmp "$WORK_DIR/myapp" "$WORK_DIR/bundle_out/myapp" \
  || fail "bundled executable did not round-trip byte-identically"
# The contents of a single --Files directory land at the root of the archive,
# next to the main program.
diff -r --exclude=myapp "$WORK_DIR/src" "$WORK_DIR/bundle_out" \
  || fail "bundled resources did not round-trip"

# The bundle subcommand makes the same thing without the flags of the
# moonx front end.
"$BIN" bundle -i "$WORK_DIR/myapp" -o "$WORK_DIR/dist/myapp2" \
  --Files "$WORK_DIR/src" > /dev/null
[ -f "$WORK_DIR/dist/myapp2" ] || fail "the bundle subcommand made nothing"
"$BIN" verify "$WORK_DIR/dist/myapp2" >/dev/null \
  || fail "the bundle of the subcommand does not verify"
pass "the bundle subcommand makes a bundle"

# A launcher can be named, so that a bundle can be made for another
# machine than the one that makes it.
cp "$BIN" "$WORK_DIR/launcher"
"$BIN" bundle -i "$WORK_DIR/myapp" -o "$WORK_DIR/dist/myapp3" \
  --Files "$WORK_DIR/src" --launcher "$WORK_DIR/launcher" > /dev/null
# The bundle starts with the launcher that was named.
head -c "$(wc -c < "$WORK_DIR/launcher")" "$WORK_DIR/dist/myapp3" \
  > "$WORK_DIR/head.bin"
cmp "$WORK_DIR/launcher" "$WORK_DIR/head.bin" \
  || fail "the named launcher is not the head of the bundle"
pass "a named launcher is used"

# A launcher that does not exist is refused.
if "$BIN" bundle -i "$WORK_DIR/myapp" -o "$WORK_DIR/dist/myapp4" \
     --launcher "$WORK_DIR/nothing-here" 2>&1 | grep -q "error:"; then
  pass "a launcher that does not exist is refused"
else
  fail "a launcher that does not exist was NOT refused"
fi
pass "bundle round-trips byte-identically"

section "md5 fingerprints"
# Packing lists the fingerprint of every file it scans.
"$BIN" pack -i "$WORK_DIR/src" -o "$WORK_DIR/fp.appkg" \
  --name "fp-demo" --version "1.0.0" > "$WORK_DIR/scan.txt"
grep -qE '^  md5  [0-9a-f]{32}  ' "$WORK_DIR/scan.txt" \
  || fail "pack did not print the md5 fingerprints"
grep -qE "^output md5  [0-9a-f]{32}" "$WORK_DIR/scan.txt" \
  || fail "pack did not print the md5 of the produced file"
# The fingerprints in the scan list are the ones of the source files.
python3 - "$WORK_DIR" <<'PY2'
import hashlib, os, re, sys
work = sys.argv[1]
listed = {}
for line in open(os.path.join(work, "scan.txt"), encoding="utf-8"):
    m = re.match(r"^  md5  ([0-9a-f]{32})  (.+)$", line.rstrip("\n"))
    if m:
        listed[m.group(2)] = m.group(1)
if not listed:
    raise SystemExit("no fingerprints in the scan list")
for rel, want in listed.items():
    got = hashlib.md5(open(os.path.join(work, "src", rel), "rb").read()).hexdigest()
    if got != want:
        raise SystemExit(f"fingerprint mismatch for {rel}: {got} != {want}")
print(f"  {len(listed)} fingerprints match the reference implementation")
PY2
pass "pack lists the fingerprints of the source files"

# Unpacking checks the fingerprints of the extracted files.
rm -rf "$WORK_DIR/fp_out"
"$BIN" unpack -i "$WORK_DIR/fp.appkg" -o "$WORK_DIR/fp_out" > "$WORK_DIR/fp_unpack.txt"
grep -q "verified .* files, 0 mismatches" "$WORK_DIR/fp_unpack.txt" \
  || fail "unpack did not report the fingerprints as verified"
pass "unpack verified the fingerprints"

# A file that changed on the disk is reported.
printf 'tampered\n' > "$WORK_DIR/fp_out/hello.txt"
if "$BIN" verify "$WORK_DIR/fp.appkg" --extracted "$WORK_DIR/fp_out" | grep -q "VERIFY FAILED"; then
  pass "a changed file is reported"
else
  fail "a changed file was NOT reported"
fi

section "the lz4 codec"
# LZ4 has to round-trip through the package as well.
"$BIN" pack -i "$WORK_DIR/src" -o "$WORK_DIR/lz4.appkg" \
  --name "lz4-demo" --version "1.0.0" --compression-method lz4 > /dev/null
"$BIN" info "$WORK_DIR/lz4.appkg" | grep -q '\[lz4\]' \
  || fail "the lz4 codec was not recorded in the manifest"
rm -rf "$WORK_DIR/lz4_out"
"$BIN" unpack -i "$WORK_DIR/lz4.appkg" -o "$WORK_DIR/lz4_out" > /dev/null
diff -r "$WORK_DIR/src" "$WORK_DIR/lz4_out" \
  || fail "the lz4 package did not round-trip"
pass "the lz4 codec round-trips"

section "the encryption"
# A package that is sealed to a recipient round-trips with the secret key.
"$BIN" keygen --public-key "$WORK_DIR/recipient.pub" --secret-key "$WORK_DIR/recipient.key" > /dev/null
"$BIN" pack -i "$WORK_DIR/src" -o "$WORK_DIR/secret.appkg" \
  --name "secret-demo" --version "1.0.0" \
  --encryption-method x25519 --public-key "$WORK_DIR/recipient.pub" > /dev/null
"$BIN" info "$WORK_DIR/secret.appkg" | grep -q 'encryption:   x25519' \
  || fail "the encryption was not recorded in the manifest"
rm -rf "$WORK_DIR/secret_out"
"$BIN" unpack -i "$WORK_DIR/secret.appkg" -o "$WORK_DIR/secret_out" \
  --secret-key "$WORK_DIR/recipient.key" > /dev/null
diff -r "$WORK_DIR/src" "$WORK_DIR/secret_out" \
  || fail "the encrypted package did not round-trip"
pass "the encrypted package round-trips"

# The content of a file is not readable in the package any more.
if grep -q "hello lunapack" "$WORK_DIR/secret.appkg" 2>/dev/null; then
  fail "the content is still readable in the package"
fi
pass "the content is not readable in the package"

# Another secret key does not open it.
"$BIN" keygen --public-key "$WORK_DIR/other.pub" --secret-key "$WORK_DIR/other.key" > /dev/null
if "$BIN" unpack -i "$WORK_DIR/secret.appkg" -o "$WORK_DIR/secret_out2" \
  --secret-key "$WORK_DIR/other.key" 2>&1 | grep -q "error:"; then
  pass "a wrong secret key is refused"
else
  fail "a wrong secret key was NOT refused"
fi

# The passphrase method works as well.
printf 'a passphrase\n' > "$WORK_DIR/pass.txt"
"$BIN" pack -i "$WORK_DIR/src" -o "$WORK_DIR/pass.appkg" \
  --name "pass-demo" --version "1.0.0" \
  --encryption-method passphrase --passphrase-file "$WORK_DIR/pass.txt" > /dev/null
rm -rf "$WORK_DIR/pass_out"
"$BIN" unpack -i "$WORK_DIR/pass.appkg" -o "$WORK_DIR/pass_out" \
  --passphrase-file "$WORK_DIR/pass.txt" > /dev/null
diff -r "$WORK_DIR/src" "$WORK_DIR/pass_out" \
  || fail "the package with a passphrase did not round-trip"
pass "the passphrase method round-trips"

# A secret key that a passphrase protects works as well.
"$BIN" keygen --public-key "$WORK_DIR/prot.pub" --secret-key "$WORK_DIR/prot.key" \
  --passphrase-file "$WORK_DIR/pass.txt" > /dev/null
"$BIN" pack -i "$WORK_DIR/src" -o "$WORK_DIR/prot.appkg" \
  --name "prot-demo" --version "1.0.0" \
  --encryption-method x25519 --public-key "$WORK_DIR/prot.pub" > /dev/null
rm -rf "$WORK_DIR/prot_out"
"$BIN" unpack -i "$WORK_DIR/prot.appkg" -o "$WORK_DIR/prot_out" \
  --secret-key "$WORK_DIR/prot.key" --passphrase-file "$WORK_DIR/pass.txt" > /dev/null
diff -r "$WORK_DIR/src" "$WORK_DIR/prot_out" \
  || fail "the package with a protected secret key did not round-trip"
pass "a protected secret key round-trips"

section "corruption detection"
cp "$WORK_DIR/pkg.appkg" "$WORK_DIR/bad.appkg"
python3 - "$WORK_DIR/bad.appkg" <<'PY'
import json, struct, sys
p = sys.argv[1]
d = bytearray(open(p, "rb").read())
# The manifest is at the end of the file: the magic, the offset and the
# length of the manifest.
mlen = struct.unpack_from("<q", d, len(d) - 8)[0]
m = json.loads(d[len(d) - 24 - mlen:len(d) - 24].decode("utf-8"))
# The checksum of an entry covers the content, not the compressed form, so
# the byte that is flipped has to be one that the content is built from: the
# data of a stored entry, or the deflate stream of a compressed one. The
# header of a gzip stream carries a timestamp that no checksum covers.
for e in m["entries"]:
    at = e["offset"] + (16 if e["codec"] == "gzip" else 0)
    if at < e["offset"] + e["stored_size"]:
        d[at] ^= 0xFF
        print(f"flipped a byte of {e['path']} at {at}")
        break
open(p, "wb").write(d)
PY
if "$BIN" verify "$WORK_DIR/bad.appkg" | grep -q "VERIFY FAILED"; then
  pass "corrupted package is rejected"
else
  fail "corrupted package was NOT rejected"
fi

section "skip-scripts"
rm -rf "$WORK_DIR/out2"
"$BIN" unpack -i "$WORK_DIR/pkg.appkg" -o "$WORK_DIR/out2" --skip-scripts
[ ! -f "$WORK_DIR/out2/pre_install_ran.txt" ] || fail "--skip-scripts did not skip"
pass "--skip-scripts honoured"

printf '\n\033[32mAll Linux tests passed.\033[0m\n'
