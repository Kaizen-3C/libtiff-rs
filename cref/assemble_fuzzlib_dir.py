"""Assemble `legacy_fuzzlib_dir.c`: the IFD shim (_prelude_dir.c) + the VERBATIM entry-reader slice
(identical to assemble_dir.py, callee-before-caller order) + the in-process callable wrapper
(_fuzzlib_driver_dir.c) instead of the op-script main() in _driver_dir.c. Used by fuzz/build.rs so
the Slice-1 fuzz oracle is built from the same verbatim slice as the certified differential.

Usage:  TIFF_SRC=<unpacked tiff-4.7.0/libtiff dir> OUT=<build dir> python cref/assemble_fuzzlib_dir.py
"""
import io
import os

G = os.environ["TIFF_SRC"]
OUT = os.environ.get("OUT", ".")
HERE = os.path.dirname(os.path.abspath(__file__))


def slc(fname, a, b):
    with io.open(os.path.join(G, fname), encoding="utf-8", errors="replace") as f:
        return "\n".join(f.read().splitlines()[a - 1:b])


pre = io.open(os.path.join(HERE, "_prelude_dir.c"), encoding="utf-8").read()
drv = io.open(os.path.join(HERE, "_fuzzlib_driver_dir.c"), encoding="utf-8").read()

parts = [
    pre,
    "/*==== tif_dir.h: TIFFDirEntry struct + tdir_offset union (verbatim) ====*/",
    slc("tif_dir.h", 53, 66),
    "/*==== tif_dirread.c: enum TIFFReadDirEntryErr (verbatim) ====*/",
    slc("tif_dirread.c", 54, 64),
    "/*==== tif_dirread.c: TIFFReadDirEntryData (verbatim) ====*/",
    slc("tif_dirread.c", 3889, 3914),
    "/*==== tif_dirread.c: TIFFReadDirEntryChecked{Byte..Slong8} (verbatim) ====*/",
    slc("tif_dirread.c", 3305, 3390),
    "/*==== tif_dirread.c: TIFFReadDirEntryCheckRangeByte* (verbatim) ====*/",
    slc("tif_dirread.c", 3545, 3606),
    "/*==== tif_dirread.c: TIFFReadDirEntryByte (verbatim) ====*/",
    slc("tif_dirread.c", 295, 385),
    drv,
]
with io.open(os.path.join(OUT, "legacy_fuzzlib_dir.c"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(parts) + "\n")
print("legacy_fuzzlib_dir.c assembled from libtiff 4.7.0 (IFD entry-reader slice + shim + fuzz wrapper)")
