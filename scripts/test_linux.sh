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
if [ -x "$PROJECT_DIR/_build/native/debug/build/cmd/main/main.exe" ]; then
  BIN="$PROJECT_DIR/_build/native/debug/build/cmd/main/main.exe"
else
  BIN="$PROJECT_DIR/_build/native/debug/build/cmd/main/main"
fi

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

section "moonx style bundle"
# --input-exe / --output-exe / --Files
mkdir -p "$WORK_DIR/dist"
printf 'MY APP\n' > "$WORK_DIR/myapp"
"$BIN" --input-exe="$WORK_DIR/myapp" \
       --output-exe="$WORK_DIR/dist/myapp" \
       --Files="$WORK_DIR/src"
[ -f "$WORK_DIR/dist/myapp" ] || fail "bundle was not created"
head -c 7 "$WORK_DIR/dist/myapp" | grep -q "MY APP" \
  || fail "bundle does not start with the original executable"
"$BIN" info "$WORK_DIR/dist/myapp" | grep -q "main program: myapp" \
  || fail "bundle manifest does not record the main program"
"$BIN" verify "$WORK_DIR/dist/myapp" >/dev/null || fail "bundle does not verify"
rm -rf "$WORK_DIR/bundle_out"
"$BIN" unpack -i "$WORK_DIR/dist/myapp" -o "$WORK_DIR/bundle_out"
cmp "$WORK_DIR/myapp" "$WORK_DIR/bundle_out/myapp" \
  || fail "bundled executable did not round-trip byte-identically"
diff -r "$WORK_DIR/src" "$WORK_DIR/bundle_out/src" \
  || fail "bundled resources did not round-trip"
pass "bundle round-trips byte-identically"

section "corruption detection"
cp "$WORK_DIR/pkg.appkg" "$WORK_DIR/bad.appkg"
python3 - "$WORK_DIR/bad.appkg" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[30] ^= 0xFF
open(p, "wb").write(b)
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
