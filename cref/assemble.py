"""Assemble the self-contained C reference `legacy.c` for the libtiff codec-decoder differential:
the shim (_prelude.c) + VERBATIM decoder bodies sliced from an upstream libtiff 4.7.0 checkout
(tif_lzw.c / tif_packbits.c / tif_thunder.c / tif_next.c) + the dispatching driver (_driver.c).

Usage:  TIFF_SRC=<unpacked tiff-4.7.0/libtiff dir> OUT=<build dir> python cref/assemble.py
The verbatim line ranges below are pinned to libtiff 4.7.0; regen_goldens.sh verifies the
tarball sha256 before calling this.
"""
import io
import os

G = os.environ["TIFF_SRC"]
OUT = os.environ.get("OUT", ".")
HERE = os.path.dirname(os.path.abspath(__file__))


def slc(fname, a, b):
    with io.open(os.path.join(G, fname), encoding="utf-8", errors="replace") as f:
        return "\n".join(f.read().splitlines()[a - 1:b])


pre = io.open(os.path.join(HERE, "_prelude.c"), encoding="utf-8").read()
drv = io.open(os.path.join(HERE, "_driver.c"), encoding="utf-8").read()

parts = [
    pre,
    "/*==== tif_lzw.c: constants + state + LZWSetupDecode (verbatim) ====*/", slc("tif_lzw.c", 63, 240),
    "/*==== tif_lzw.c: LZWPreDecode (verbatim) ====*/", slc("tif_lzw.c", 245, 322),
    "/*==== tif_lzw.c: bit-reader macros + LZWDecode (verbatim) ====*/", slc("tif_lzw.c", 328, 756),
    "/*==== tif_packbits.c: PackBitsDecode (verbatim) ====*/", slc("tif_packbits.c", 234, 309),
    "/*==== tif_thunder.c: constants/tables/SETPIXEL + ThunderDecode (verbatim) ====*/",
    slc("tif_thunder.c", 44, 67), slc("tif_thunder.c", 85, 170), "#undef SETPIXEL",
    "/*==== tif_next.c: SETPIXEL/constants + NeXTDecode (verbatim) ====*/",
    slc("tif_next.c", 33, 54), slc("tif_next.c", 57, 168), "#undef SETPIXEL",
    drv,
]
with io.open(os.path.join(OUT, "legacy.c"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(parts) + "\n")
print("legacy.c assembled from libtiff 4.7.0 (4 verbatim codec decoders + shim + driver)")
