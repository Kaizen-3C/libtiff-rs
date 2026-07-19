"""Assemble `legacy_dir5.c` for the strip/tile geometry-count (Slice 5) differential: the shim
(_prelude_dir5.c) + the VERBATIM _TIFFMultiply32 (tif_aux.c), TIFFNumberOfStrips (tif_strip.c) and
TIFFNumberOfTiles (tif_tile.c) + the driver (_driver_dir5.c). Slices pinned, callee-before-caller.

Usage:  TIFF_SRC=<unpacked tiff-4.7.0/libtiff dir> OUT=<build dir> python cref/assemble_dir5.py
(set DRIVER=_fuzzlib_driver_dir5.c for the fuzz variant -> legacy_fuzzlib_dir5.c)
"""
import io
import os

G = os.environ["TIFF_SRC"]
OUT = os.environ.get("OUT", ".")
HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.environ.get("DRIVER", "_driver_dir5.c")
OUTNAME = "legacy_fuzzlib_dir5.c" if "fuzzlib" in DRIVER else "legacy_dir5.c"


def slc(fname, a, b):
    with io.open(os.path.join(G, fname), encoding="utf-8", errors="replace") as f:
        return "\n".join(f.read().splitlines()[a - 1:b])


pre = io.open(os.path.join(HERE, "_prelude_dir5.c"), encoding="utf-8").read()
drv = io.open(os.path.join(HERE, DRIVER), encoding="utf-8").read()

parts = [
    pre,
    "/*==== tif_aux.c: _TIFFMultiply32 — the overflow-guarded multiply (verbatim) ====*/",
    "static " + slc("tif_aux.c", 35, 45),
    "/*==== tif_strip.c: TIFFNumberOfStrips (verbatim) ====*/",
    "static " + slc("tif_strip.c", 64, 82),
    "/*==== tif_tile.c: TIFFNumberOfTiles (verbatim) ====*/",
    "static " + slc("tif_tile.c", 108, 135),
    drv,
]
with io.open(os.path.join(OUT, OUTNAME), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(parts) + "\n")
print(f"{OUTNAME} assembled from libtiff 4.7.0 (strip/tile geometry-count slice + shim + driver)")
