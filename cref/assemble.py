"""Assemble the self-contained C reference `legacy.c` for the libtiff LZW-decoder differential:
the shim (_prelude.c) + VERBATIM LZW decoder bodies sliced from an upstream libtiff 4.7.0
checkout (tif_lzw.c: LZWSetupDecode / LZWPreDecode / LZWDecode + the code-table state and the
bit-reader macros) + the op-script driver (_driver.c).

Usage:  TIFF_SRC=<unpacked tiff-4.7.0/libtiff dir> OUT=<build dir> python cref/assemble.py
The verbatim line ranges below are pinned to libtiff 4.7.0; regen_goldens.sh verifies the
tarball sha256 before calling this.
"""
import io
import os

G = os.environ["TIFF_SRC"]
OUT = os.environ.get("OUT", ".")
HERE = os.path.dirname(os.path.abspath(__file__))


def slc(a, b):
    with io.open(os.path.join(G, "tif_lzw.c"), encoding="utf-8", errors="replace") as f:
        return "\n".join(f.read().splitlines()[a - 1:b])


pre = io.open(os.path.join(HERE, "_prelude.c"), encoding="utf-8").read()
drv = io.open(os.path.join(HERE, "_driver.c"), encoding="utf-8").read()

parts = [
    pre,
    "/*==== tif_lzw.c: constants + state + LZWSetupDecode (verbatim) ====*/", slc(63, 240),
    "/*==== tif_lzw.c: LZWPreDecode (verbatim) ====*/", slc(245, 322),
    "/*==== tif_lzw.c: bit-reader macros + LZWDecode (verbatim) ====*/", slc(328, 756),
    drv,
]
with io.open(os.path.join(OUT, "legacy.c"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(parts) + "\n")
print("legacy.c assembled from libtiff 4.7.0 tif_lzw.c (verbatim LZW decoder + shim + driver)")
