# libtiff-rs

[![CI](https://github.com/Kaizen-3C/libtiff-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Kaizen-3C/libtiff-rs/actions/workflows/ci.yml)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](src/lib.rs)
[![license: libtiff](https://img.shields.io/badge/license-libtiff-blue.svg)](LICENSE)

A memory-safe Rust reimplementation of libtiff 4.7.0's **TIFF decode path**, built bottom-up and
**differentially certified byte-identical to the upstream C** — not a clean-room rewrite, a proven
drop-in. The entire crate is **`#![forbid(unsafe_code)]`**.

A real TIFF file decodes to pixels in safe Rust, byte-for-byte identical to what `libtiff` itself
produces (see **End-to-end decode** below). The pieces underneath — the codec decoders, the
directory/IFD parser, and the strip geometry — are each certified against the verbatim upstream C
over an adversarial test envelope, re-provable from the sha256-pinned release.

## What's implemented and certified

| Layer | Module | Certification (vs verbatim libtiff 4.7.0 C) |
|---|---|---|
| **Codec decoders** — LZW (`tif_lzw.c`), PackBits/Thunder/NeXT (`tif_packbits`/`_thunder`/`_next.c`) | `lzw`, `rle` | **538/538** cases byte-identical; re-proven **in CI every commit** (`regen_goldens.sh`) |
| **IFD entry readers** — typed value promotion + the offset/size-overflow & `tif_size` bounds core | `dirread` | **1692** cases byte-identical |
| **Directory scan** — `TIFFFetchDirectory` (entry-count/offset overflow guards, BigTIFF) | `dirread` | **25**-case adversarial envelope |
| **Tag value arrays** — `TIFFReadDirEntryByteArray`/`…Array` (2 GB size-sanity, multiply-overflow) | `dirread` | **26**-case |
| **Strip offset/bytecount arrays** — `TIFFReadDirEntryLong8Array` | `dirread` | **28**-case |
| **Strip/tile geometry** — `TIFFNumberOfStrips`/`…Tiles` (count multiply-overflow) | `geometry` | **20,743**-case near-exhaustive boundary sweep |
| **End-to-end decode** — header → directory → tags → strip read → codec → pixels | `decode` | **12/12** byte-identical **vs the real `libtiff`** |

Every layer's differential is re-provable from the upstream tarball. The IFD and geometry surfaces
are also hardened with coverage-guided **differential fuzzing** (safe Rust vs. verbatim C under
AddressSanitizer); a reproducible 4-hour, ~7.6-billion-execution soak across the IFD surface ran
clean — zero crashes, zero differential mismatches, across independent runs (see `FUZZING.md`).

## End-to-end decode

`decode::decode_tiff(&file_bytes)` parses a TIFF header, reads its directory, extracts the geometry
and codec tags, reads each strip, and dispatches to the certified codec — producing the same pixel
bytes `TIFFReadEncodedStrip` produces. `scripts/e2e_certify.sh` proves this from first principles: it
builds a minimal static `libtiff` from the pinned 4.7.0 source, decodes a matrix of generated TIFFs
(little- and big-endian × uncompressed / PackBits / LZW × single-, multi-, and partial-strip
layouts) with **both** the real library and this crate, and byte-compares. Current result: **12/12
identical**.

**Scope of the current decode path** (deliberately minimal, proven end-to-end): classic TIFF, 8-bit
contiguous samples, single-plane, Compression NONE / PackBits / LZW. Not yet covered: tiles, BigTIFF
end-to-end, the predictors (`tif_predict.c`), sub-8-bit / >8-bit samples, planar-separate, and the
remaining codecs (e.g. CCITT fax) — the breadth that turns this from a proven core into a full
production decoder.

## Certification methodology

The crate was not reviewed into correctness — it was **measured** into it. For each layer, the
verbatim upstream C (re-sliced from the sha256-pinned `tiff-4.7.0.tar.gz`) and the Rust port are
driven by an identical op-script / structured-input harness over a declared envelope, and their
complete observable output is byte-compared. Valid inputs are generated so the corpus is genuinely
well-formed where it claims to be and genuinely hostile (truncation, corruption, overflow triggers,
pure-garbage fuzz) where it claims to be. `cargo test` replays the checked-in goldens. The `scripts/`
harnesses rebuild the C reference from upstream and re-prove the differential — `regen_goldens.sh`
for the codecs, `e2e_certify.sh` for the end-to-end decode. **Both run in CI on every commit.** The
end-to-end job builds a minimal static `libtiff` from the pinned tarball and byte-compares its pixel
output against this crate's.

## How the port handles the C structure

libtiff's C is raw-pointer-heavy — `goto` state machines, a `code_t` linked-list code table walked by
pointer (with a one-before-the-array sentinel), a `tdir_offset` union read through pointer casts, and
`size_t`/`uint32` overflow-guarded arithmetic throughout. The safe-Rust ports reindex pointer chains
to array indices, read the union's bytes at explicit offsets (no casts), and preserve the C's exact
overflow guards and accept/reject/bounds behaviour on every input — with **zero `unsafe`**.

## Provenance

- Ported from `tiff-4.7.0.tar.gz`, sha256
  `67160e3457365ab96c5b3286a0903aa6e78bdc44c4bc737d2e486bcecb6ba976` (download.osgeo.org).
- Licensed under the libtiff license, identical to upstream; see `LICENSE` (Sam Leffler /
  Silicon Graphics copyright retained).

## Layout

- `src/lzw.rs`, `src/rle.rs` — the codec decoders
- `src/dirread.rs` — the IFD directory/entry parser (readers, directory scan, value + strip arrays)
- `src/geometry.rs` — strip/tile geometry counts
- `src/decode.rs` — the end-to-end `decode_tiff` path
- `src/bin/*` — the certification op-script drivers (each mirrors a `cref/_driver_*.c`)
- `cref/` — the C reference harnesses (minimal shims + `assemble*.py`, slicing the verbatim C from an
  upstream checkout) and the end-to-end oracle/generator (`_e2e_ref.c`, `_e2e_gen.c`)
- `tests/vectors/` — the checked-in goldens · `scripts/` — `regen_goldens.sh`, `e2e_certify.sh`
- `fuzz/` — the coverage-guided differential fuzz targets (see `FUZZING.md`)
