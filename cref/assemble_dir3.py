"""Assemble `legacy_dir3.c` for the value-array fetch (Slice 3) differential: the shim
(_prelude_dir3.c) + the VERBATIM enum, TIFFDirEntry, CheckRangeByte* range guards,
TIFFReadDirEntryData, TIFFReadDirEntryArrayWithLimit/Array, and TIFFReadDirEntryByteArray sliced
from libtiff 4.7.0 + the driver (_driver_dir3.c). Slices pinned, callee-before-caller.

Usage:  TIFF_SRC=<unpacked tiff-4.7.0/libtiff dir> OUT=<build dir> python cref/assemble_dir3.py
(set DRIVER=_fuzzlib_driver_dir3.c for the fuzz variant -> legacy_fuzzlib_dir3.c)
"""
import io
import os

G = os.environ["TIFF_SRC"]
OUT = os.environ.get("OUT", ".")
HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.environ.get("DRIVER", "_driver_dir3.c")
OUTNAME = "legacy_fuzzlib_dir3.c" if "fuzzlib" in DRIVER else "legacy_dir3.c"


def slc(fname, a, b):
    with io.open(os.path.join(G, fname), encoding="utf-8", errors="replace") as f:
        return "\n".join(f.read().splitlines()[a - 1:b])


pre = io.open(os.path.join(HERE, "_prelude_dir3.c"), encoding="utf-8").read()
drv = io.open(os.path.join(HERE, DRIVER), encoding="utf-8").read()

# Non-mapped realloc-read path: dead here (isMapped always true), but referenced by
# TIFFReadDirEntryArrayWithLimit, so it must be defined (after the enum, before that caller).
realloc_stub = (
    "/*==== non-mapped realloc-read stub (never reached; isMapped always true) ====*/\n"
    "static enum TIFFReadDirEntryErr TIFFReadDirEntryDataAndRealloc(TIFF *tif, uint64_t offset,\n"
    "                                                              tmsize_t size, void **pdest) {\n"
    "    (void)tif; (void)offset; (void)size; (void)pdest;\n"
    "    return TIFFReadDirEntryErrIo;\n"
    "}"
)

parts = [
    pre,
    "/*==== tif_dirread.c: enum TIFFReadDirEntryErr (verbatim) ====*/",
    slc("tif_dirread.c", 54, 64),
    realloc_stub,
    "/*==== tif_dir.h: TIFFDirEntry struct + tdir_offset union (verbatim) ====*/",
    slc("tif_dir.h", 53, 66),
    "/*==== tif_dirread.c: CheckRangeByte* range guards (verbatim) ====*/",
    slc("tif_dirread.c", 3545, 3606),
    "/*==== tif_dirread.c: TIFFReadDirEntryData — offset+size overflow / tif_size bounds (verbatim) ====*/",
    slc("tif_dirread.c", 3889, 3914),
    "/*==== tif_dirread.c: MAX_SIZE_TAG_DATA + TIFFReadDirEntryArrayWithLimit/Array (verbatim) ====*/",
    slc("tif_dirread.c", 1248, 1385),
    "/*==== tif_dirread.c: TIFFReadDirEntryByteArray — per-type range-checked conversion (verbatim) ====*/",
    slc("tif_dirread.c", 1386, 1566),
    drv,
]
with io.open(os.path.join(OUT, OUTNAME), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(parts) + "\n")
print(f"{OUTNAME} assembled from libtiff 4.7.0 (value-array fetch slice + shim + driver)")
