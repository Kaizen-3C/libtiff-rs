"""Assemble `legacy_dir4.c` for the Long8 strip-array reader (Slice 4) differential: the shim
(_prelude_dir4.c) + the VERBATIM enum, TIFFDirEntry, CheckRangeLong8* guards, TIFFReadDirEntryData,
TIFFReadDirEntryArrayWithLimit/Array (S3 core), and TIFFReadDirEntryLong8Array[WithLimit] sliced from
libtiff 4.7.0 + the driver (_driver_dir4.c). Slices pinned, callee-before-caller.

Usage:  TIFF_SRC=<unpacked tiff-4.7.0/libtiff dir> OUT=<build dir> python cref/assemble_dir4.py
(set DRIVER=_fuzzlib_driver_dir4.c for the fuzz variant -> legacy_fuzzlib_dir4.c)
"""
import io
import os

G = os.environ["TIFF_SRC"]
OUT = os.environ.get("OUT", ".")
HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.environ.get("DRIVER", "_driver_dir4.c")
OUTNAME = "legacy_fuzzlib_dir4.c" if "fuzzlib" in DRIVER else "legacy_dir4.c"


def slc(fname, a, b):
    with io.open(os.path.join(G, fname), encoding="utf-8", errors="replace") as f:
        return "\n".join(f.read().splitlines()[a - 1:b])


pre = io.open(os.path.join(HERE, "_prelude_dir4.c"), encoding="utf-8").read()
drv = io.open(os.path.join(HERE, DRIVER), encoding="utf-8").read()

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
    "/*==== tif_dirread.c: CheckRangeLong8* sign guards (verbatim) ====*/",
    slc("tif_dirread.c", 3844, 3888),
    "/*==== tif_dirread.c: TIFFReadDirEntryData — offset+size overflow / tif_size bounds (verbatim) ====*/",
    slc("tif_dirread.c", 3889, 3914),
    "/*==== tif_dirread.c: MAX_SIZE_TAG_DATA + TIFFReadDirEntryArrayWithLimit/Array (verbatim) ====*/",
    slc("tif_dirread.c", 1248, 1385),
    "/*==== tif_dirread.c: TIFFReadDirEntryLong8ArrayWithLimit — u64-widening strip reader (verbatim) ====*/",
    slc("tif_dirread.c", 2421, 2588),
    drv,
]
with io.open(os.path.join(OUT, OUTNAME), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(parts) + "\n")
print(f"{OUTNAME} assembled from libtiff 4.7.0 (Long8 strip-array reader slice + shim + driver)")
