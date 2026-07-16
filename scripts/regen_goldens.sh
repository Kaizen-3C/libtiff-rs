#!/usr/bin/env bash
# Rebuild the C reference from the UPSTREAM libtiff 4.7.0 tarball and verify the differential
# from first principles:
#   1. download tiff-4.7.0.tar.gz (or use $TIFF_TARBALL), pin sha256
#   2. cref/assemble.py slices the VERBATIM decoder bodies (PackBits / Thunder / NeXT and the
#      LZW decoder) from tif_packbits.c / tif_thunder.c / tif_next.c / tif_lzw.c and stitches
#      them with cref/_prelude.c (the minimal TIFF shim) and cref/_driver.c (dispatching driver)
#   3. compile, run over tests/vectors/tiff_inputs.txt, byte-compare against the Rust
#      differential_driver and the checked-in golden.
# Exits nonzero on any mismatch.
set -euo pipefail
cd "$(dirname "$0")/.."

SHA=67160e3457365ab96c5b3286a0903aa6e78bdc44c4bc737d2e486bcecb6ba976
URL=https://download.osgeo.org/libtiff/tiff-4.7.0.tar.gz
BUILD=cref/_build
CC="${CC:-clang}"
mkdir -p "$BUILD"

TARBALL="${TIFF_TARBALL:-$BUILD/tiff-4.7.0.tar.gz}"
if [ ! -f "$TARBALL" ]; then
  echo "== downloading $URL"
  curl -sSL -o "$TARBALL" "$URL"
fi
echo "$SHA  $TARBALL" | sha256sum -c -

cp "$TARBALL" "$BUILD/_tiff.tgz"
tar xzf "$BUILD/_tiff.tgz" -C "$BUILD"
UP="$BUILD/tiff-4.7.0/libtiff"

echo "== assembling legacy.c from upstream tif_*.c (4 verbatim decoders + shim + driver)"
TIFF_SRC="$UP" OUT="$BUILD" python cref/assemble.py

echo "== compiling C reference ($CC)"
"$CC" -O2 -D_CRT_SECURE_NO_WARNINGS -o "$BUILD/cref_driver" "$BUILD/legacy.c"

echo "== building Rust driver"
cargo build --release --quiet
RUST_DRV=target/release/differential_driver
[ -x "$RUST_DRV" ] || RUST_DRV=target/release/differential_driver.exe

fail=0
inp=tests/vectors/tiff_inputs.txt
gold=tests/vectors/tiff_golden.txt
"$BUILD/cref_driver" < "$inp" | tr -d '\r' > "$BUILD/tiff_c.out"
"$RUST_DRV"          < "$inp" | tr -d '\r' > "$BUILD/tiff_rs.out"
tr -d '\r' < "$gold" > "$BUILD/tiff_gold.norm"
if cmp -s "$BUILD/tiff_c.out" "$BUILD/tiff_rs.out"; then
  echo "OK  tiff: upstream-built C == Rust ($(wc -l < "$inp") cases)"
else
  echo "FAIL tiff: upstream-built C != Rust"; fail=1
fi
if cmp -s "$BUILD/tiff_c.out" "$BUILD/tiff_gold.norm"; then
  echo "OK  tiff: upstream-built C == checked-in golden"
else
  echo "FAIL tiff: upstream-built C != checked-in golden"; fail=1
fi
exit $fail
