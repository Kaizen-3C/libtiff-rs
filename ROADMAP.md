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

## Later

3. **Codec-surface breadth + hardening** — the remaining common decode codecs and tag paths, sustained
   differential fuzzing, and coordinated disclosure of any upstream memory-safety issues surfaced.
4. **Drop-in packaging + adoption** — a C-ABI shim (via `cbindgen`) so C consumers (e.g. GDAL,
   ImageMagick) can trial the decoder without a Rust toolchain, a crates.io release,
   reproducible-certification CI, and documentation.

## Non-goals (for now)

- The TIFF **encode** path — this project is scoped to decoding untrusted input, the highest-risk
  surface.
- Beating libtiff on performance — the goal is memory-safety and byte-identical behavior; near-source
  performance (the cost of bounds-checking, not a rewrite) is acceptable.

Scope and progress are tracked honestly in the README's "Scope of the current decode path" section;
this roadmap is the plan to grow that scope into a full production decoder.
