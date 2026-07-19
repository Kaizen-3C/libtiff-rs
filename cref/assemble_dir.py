"""Assemble the self-contained C reference `legacy_dir.c` for the libtiff IFD directory-entry
reader differential (Slice 1): the shim (_prelude_dir.c) + the TIFFDirEntry struct + the VERBATIM
typed-entry-reader bodies sliced from tif_dirread.c + the driver (_driver_dir.c).

Slices are pinned to libtiff 4.7.0 and ordered callee-before-caller (Data -> Checked -> CheckRange
-> Byte) so no forward declarations are needed.

Usage:  TIFF_SRC=<unpacked tiff-4.7.0/libtiff dir> OUT=<build dir> python cref/assemble_dir.py
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
drv = io.open(os.path.join(HERE, "_driver_dir.c"), encoding="utf-8").read()

parts = [
    pre,
    "/*==== tif_dir.h: TIFFDirEntry struct + tdir_offset union (verbatim) ====*/",
    slc("tif_dir.h", 53, 66),
    "/*==== tif_dirread.c: enum TIFFReadDirEntryErr (verbatim) ====*/",
    slc("tif_dirread.c", 54, 64),
    "/*==== tif_dirread.c: TIFFReadDirEntryData — offset+size overflow / tif_size bounds (verbatim) ====*/",
    slc("tif_dirread.c", 3889, 3914),
    "/*==== tif_dirread.c: TIFFReadDirEntryChecked{Byte..Slong8} raw typed reads (verbatim) ====*/",
    slc("tif_dirread.c", 3305, 3390),
    "/*==== tif_dirread.c: TIFFReadDirEntryCheckRangeByte* range guards (verbatim) ====*/",
    slc("tif_dirread.c", 3545, 3606),
    "/*==== tif_dirread.c: TIFFReadDirEntryByte type-dispatch promotion reader (verbatim) ====*/",
    slc("tif_dirread.c", 295, 385),
    drv,
]
with io.open(os.path.join(OUT, "legacy_dir.c"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(parts) + "\n")
print("legacy_dir.c assembled from libtiff 4.7.0 (IFD entry-reader slice + shim + driver)")
