# Roadmap

`libtiff-rs` is building a memory-safe, differentially-certified drop-in for libtiff's decode path,
bottom-up. Every item ships as certified, fuzzed, CI-gated code with its own byte-identical
differential proof against the pinned upstream C — so "done" is objectively checkable, not asserted.

## Done

- **Codec decoders** — LZW, PackBits, Thunder, NeXT — 538/538 byte-identical vs libtiff 4.7.0, in CI.
- **Directory / IFD parser core** — typed entry readers, offset/size-overflow and bounds guards,
  directory scan, tag value arrays, strip offset/bytecount arrays, BigTIFF 64-bit offsets — certified
  and hardened with a multi-hour differential fuzz soak (see `FUZZING.md`).
- **Strip/tile geometry** — `TIFFNumberOfStrips`/`…Tiles` count arithmetic — near-exhaustive boundary
  sweep, certified.
- **End-to-end decode (minimal)** — header → directory → tags → strip read → codec → pixels, proven
  byte-identical to a real libtiff across little/big-endian × NONE/PackBits/LZW × single/multi/partial
  strip layouts.

## Next

1. **Complete the directory parser** — full `TIFFFetchNormalTag` field dispatch across the remaining
   tag types, complete `TIFFReadDirectory` integration (multi-IFD / sub-IFD traversal,
   default/inherited fields), and the remaining validation paths — all to the same certification bar.
2. **Production strip/tile read path** — the tile read path + geometry, the horizontal/floating-point
   **predictors** (`tif_predict.c`), sub-8-bit and >8-bit samples, planar-separate configuration, and
   BigTIFF end-to-end.

## Later — the harder surfaces (explicitly sequenced after the native decode path)

The native decode path above is the lowest-novelty, highest-value slice and comes first. The
surfaces below are more involved and are taken on incrementally, each still gated on byte-identical
equivalence to the C:

3. **Remaining native codecs** — chiefly **CCITT Group 3 / Group 4 fax** (`tif_fax3.c`), a
   table-driven 2D state machine. (Its large code tables are handled by *generating* them from the
   spec, not transcribing — transcription is error-prone.)
4. **The high-level RGBA / image path** (`tif_getimage.c`) — photometric interpretation and colour
   conversion (YCbCr→RGB, CIELab, palette/colormap). This is fixed-point colour math rather than
   parsing, so the work is reproducing libtiff's exact rounding byte-for-byte.
5. **External-library codecs** (JPEG, Deflate/zlib, LZMA, Zstd, WebP, LERC) — upstream libtiff
   *delegates* these to external C libraries. Rather than re-porting third-party libraries, the plan
   is to **bridge to maintained Rust crates** (e.g. `jpeg-decoder`, `flate2`/`zlib-rs`) so the decode
   crate keeps its `#![forbid(unsafe_code)]` guarantee. Which of these land, and in what order, is
   driven by real-world demand.
6. **Drop-in packaging + adoption** — a C-ABI shim (via `cbindgen`) so C consumers (e.g. GDAL,
   ImageMagick) can trial the decoder without a Rust toolchain, a crates.io release,
   reproducible-certification CI, and documentation. The shim is the one place the crate crosses the
   FFI boundary and holds *contained* `unsafe` (raw C handles/buffers), checked sound with `miri`;
   the decode library itself stays `#![forbid(unsafe_code)]`.

Sustained differential fuzzing and coordinated disclosure of any upstream memory-safety issues run
throughout.

## Non-goals (for now)

- The TIFF **encode** path — this project is scoped to decoding untrusted input, the highest-risk
  surface.
- **Re-porting third-party codec libraries** (libjpeg, zlib, …) — those are bridged to existing Rust
  crates, not rewritten here.
- Beating libtiff on performance — the goal is memory-safety and byte-identical behavior; near-source
  performance (the cost of bounds-checking, not a rewrite) is acceptable.

Scope and progress are tracked honestly in the README's "Scope of the current decode path" section;
this roadmap is the plan to grow that scope into a full production decoder.
