"""Assemble `legacy_dir2.c` for the TIFFFetchDirectory (Slice 2) differential: the shim
(_prelude_dir2.c) + TIFFDirEntry + the VERBATIM TIFFReadUInt64 and TIFFFetchDirectory bodies sliced
from tif_dirread.c + the driver (_driver_dir2.c). Slices pinned to libtiff 4.7.0, callee-before-caller.

Usage:  TIFF_SRC=<unpacked tiff-4.7.0/libtiff dir> OUT=<build dir> python cref/assemble_dir2.py
(set DRIVER=_fuzzlib_driver_dir2.c for the fuzz variant -> legacy_fuzzlib_dir2.c)
"""
import io
import os

G = os.environ["TIFF_SRC"]
OUT = os.environ.get("OUT", ".")
HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.environ.get("DRIVER", "_driver_dir2.c")
OUTNAME = "legacy_fuzzlib_dir2.c" if "fuzzlib" in DRIVER else "legacy_dir2.c"


def slc(fname, a, b):
    with io.open(os.path.join(G, fname), encoding="utf-8", errors="replace") as f:
        return "\n".join(f.read().splitlines()[a - 1:b])


pre = io.open(os.path.join(HERE, "_prelude_dir2.c"), encoding="utf-8").read()
drv = io.open(os.path.join(HERE, DRIVER), encoding="utf-8").read()

parts = [
    pre,
    "/*==== tif_dir.h: TIFFDirEntry struct + tdir_offset union (verbatim) ====*/",
    slc("tif_dir.h", 53, 66),
    "/*==== tif_dirread.c: TIFFReadUInt64 (verbatim) ====*/",
    slc("tif_dirread.c", 279, 293),
    "/*==== tif_dirread.c: TIFFFetchDirectory — directory-structure parse (verbatim) ====*/",
    slc("tif_dirread.c", 5966, 6256),
    drv,
]
with io.open(os.path.join(OUT, OUTNAME), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(parts) + "\n")
print(f"{OUTNAME} assembled from libtiff 4.7.0 (TIFFFetchDirectory slice + shim + driver)")
