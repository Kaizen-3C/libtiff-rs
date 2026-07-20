#!/usr/bin/env bash
# End-to-end decode certification (Slice 6), re-provable from the pinned libtiff 4.7.0 source:
#   1. build a minimal static libtiff.a (all optional codecs/deps OFF — core decode needs none)
#   2. build the ORACLE (cref/_e2e_ref.c, links real libtiff) + the GENERATOR (cref/_e2e_gen.c)
#   3. build the Rust decoder (bin e2e_decode, #![forbid(unsafe_code)])
#   4. generate the test-TIFF envelope (LE/BE x {none,packbits,lzw} x strip layouts)
#   5. decode each with BOTH and byte-compare the pixel output; refresh tests/vectors/e2e_golden.txt
# Exits nonzero on any mismatch. Mirrors scripts/regen_goldens.sh for the codec/IFD slices.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$PWD"
TIFF_SRC_TREE="$ROOT/cref/_build/tiff-4.7.0"
SRC="$TIFF_SRC_TREE/libtiff"                 # tiffio.h, tiff.h
BUILD="$TIFF_SRC_TREE/_e2e_build"
LIBDIR="$BUILD/libtiff"                      # generated tif_config.h/tiffconf.h + libtiff.a
LIB="$LIBDIR/libtiff.a"
CC="${CC:-clang}"

if [ ! -f "$SRC/tif_dirread.c" ]; then
  echo "FAIL: $SRC not found — run scripts/regen_goldens.sh once first to extract the pinned tarball."
  exit 1
fi

if [ ! -f "$LIB" ]; then
  echo "== configuring minimal static libtiff (optional codecs/deps OFF)"
  cmake -S "$TIFF_SRC_TREE" -B "$BUILD" -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE=Release \
    -Dtiff-tools=OFF -Dtiff-tests=OFF -Dtiff-docs=OFF -Dtiff-contrib=OFF \
    -Djpeg=OFF -Dold-jpeg=OFF -Djbig=OFF -Dlzma=OFF -Dzstd=OFF -Dwebp=OFF -Dzlib=OFF \
    -Dpixarlog=OFF -Dlerc=OFF -Dlibdeflate=OFF -DBUILD_SHARED_LIBS=OFF >/dev/null
  echo "== building libtiff.a"
  make -C "$BUILD" tiff -j"$(nproc)" >/dev/null
fi

echo "== building oracle + generator (link real libtiff.a)"
"$CC" -O2 -I"$LIBDIR" -I"$SRC" -o "$BUILD/e2e_ref" cref/_e2e_ref.c "$LIB" -lm
"$CC" -O2 -I"$LIBDIR" -I"$SRC" -o "$BUILD/e2e_gen" cref/_e2e_gen.c "$LIB" -lm

echo "== building Rust decoder"
cargo build --release --quiet --bin e2e_decode
RUST="$ROOT/target/release/e2e_decode"

TIFDIR="$BUILD/e2e_tifs"
rm -rf "$TIFDIR"; mkdir -p "$TIFDIR"
"$BUILD/e2e_gen" "$TIFDIR" > "$BUILD/e2e_list.txt"

echo "== decoding each TIFF with real libtiff vs the Rust port"
GOLDEN="$ROOT/tests/vectors/e2e_golden.txt"
: > "$GOLDEN"
pass=0; fail=0
while read -r f; do
  [ -f "$f" ] || continue
  "$BUILD/e2e_ref" "$f" > "$BUILD/_c.out" 2>/dev/null
  "$RUST" "$f"          > "$BUILD/_r.out" 2>/dev/null
  cat "$BUILD/_c.out" >> "$GOLDEN"
  if diff -q "$BUILD/_c.out" "$BUILD/_r.out" >/dev/null 2>&1; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    echo "MISMATCH $(basename "$f")"
    echo "  C:    $(cut -c1-100 "$BUILD/_c.out")"
    echo "  RUST: $(cut -c1-100 "$BUILD/_r.out")"
  fi
done < "$BUILD/e2e_list.txt"

echo "-----"
echo "e2e decode: real libtiff == Rust — pass=$pass fail=$fail"
[ "$fail" -eq 0 ] || { echo "CERTIFICATION FAILED"; exit 1; }
echo "OK — golden refreshed at tests/vectors/e2e_golden.txt"
