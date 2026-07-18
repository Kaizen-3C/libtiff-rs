# Differential fuzzing

Coverage-guided fuzzing that generates op-script lines and checks the Rust port against the
upstream C reference **automatically**, on top of the curated 538-case envelope in
`tests/vectors/` (see `HARNESS.md`). Complements, doesn't replace, the differential test suite.
Scoped in [`../DIFFERENTIAL-FUZZING-SCOPE.md`](../DIFFERENTIAL-FUZZING-SCOPE.md).

## What it does

`fuzz/fuzz_targets/differential.rs` treats one fuzz input as a single op-script line
(`P`/`T`/`N`/`L <args...> <hex>`) and runs it two ways per iteration, in the same process:

- **Rust:** `libtiff_rs::driver_core::run_line` — the *same* interpreter
  `src/bin/differential_driver.rs` uses, not a duplicate copy.
- **C:** a copy of `cref/_driver.c`'s dispatcher (`cref/_fuzzlib_driver.c`, harness code — not
  the verbatim libtiff port, which is the 4 codec decoders, compiled in unmodified) with every
  `printf` redirected to a caller-owned buffer instead of stdout. Built with
  `-fsanitize=address,fuzzer-no-link` so it contributes to libFuzzer's coverage feedback
  alongside the Rust side.

A mismatch between the two traces — or a Rust panic — is a libFuzzer crash with a minimized
repro.

## Running it

Linux/WSL only (cargo-fuzz + ASan tooling; not attempted on native Windows).

```bash
# one-time setup
rustup toolchain install nightly
cargo install cargo-fuzz
bash scripts/regen_goldens.sh   # populates cref/_build/tiff-4.7.0 (build.rs needs it)
python3 fuzz/seed_corpus.py     # decode tests/vectors/tiff_inputs.txt into fuzz/corpus/differential/

# smoke: replay the seed corpus only, no new inputs generated
cargo +nightly fuzz run differential -- -runs=0 fuzz/corpus/differential

# fuzz for N seconds
cargo +nightly fuzz run differential -- -max_total_time=60 -max_len=4096 fuzz/corpus/differential
```

`fuzz/corpus/` and `fuzz/artifacts/` are gitignored (cargo-fuzz convention) — not checked in;
`seed_corpus.py` regenerates the starting corpus from what *is* checked in.

## Findings

Ported two fixes over proactively from libogg-rs's differential-fuzz session (same bug classes,
same root cause), before ever running the fuzzer here:

- **`atol()` used Rust's strict `str::parse`** instead of C's lenient leading-digit-run-then-stop
  semantics. `cref/_driver.c` parses every numeric field with real `atol()`.
- Added the same helper (`c`-compatible `atol` in `driver_core.rs`) proactively.

Then, on the actual first fuzz run:

1. **~1,200 executions in — embedded-NUL truncation** (`src/driver_core.rs`, harness-only, same
   class as libogg-rs finding #3's neighbor). `strtok` treats the op-script line as a
   NUL-terminated C string; an embedded `0x00` anywhere silently ends it there for every
   downstream C string function, but Rust strings can contain interior NULs freely. Fixed by
   truncating at the first NUL before tokenizing, in `driver_core.rs` only (matches what
   `_driver.c`/`_fuzzlib_driver.c` already do implicitly via `strtok`). Also fixed the
   tokenizer itself in the same pass: it used `str::split_whitespace()` (full Unicode
   White_Space set) instead of matching `strtok`'s exact 4-byte delimiter set (`" \t\r\n"`),
   which could shift where an argument starts on inputs containing `\v`/`\f`/NBSP/etc.

2. **~3,770 executions in — Thunder `maxpixels`/buffer-size inconsistency** (`cref/_driver.c`
   *and* `driver_core.rs`, a genuine harness-only bug present in **both** the certified C
   reference and the certified Rust driver, not introduced by the fuzz work — it was already
   there). The `T` (Thunder) op clamps the *allocated output buffer* to `MAXBUF` (1MB) but was
   passing the **unclamped** `maxpixels` straight through to `thunder_decode`/`ThunderDecode` —
   the parameter that tells the decoder how much room it has. A `maxpixels` around 7 billion
   made the C reference write ~3.5GB past a 1MB buffer (ASan: `global-buffer-overflow WRITE of
   size 3500922044`). **Not reachable via any real malicious TIFF file** — real libtiff callers
   always derive both the buffer size and `maxpixels` from the same source (e.g.
   `tif_scanlinesize`), so they can never disagree; this was purely an artifact of the test
   driver's own inconsistent clamping. Fixed by clamping `maxpixels` itself (not just the
   derived buffer size) identically in `cref/_driver.c`, `cref/_fuzzlib_driver.c`, and
   `driver_core.rs` — re-verified 538/538 byte-identical against the pinned tarball after the
   change (this is a change to the certified C reference and the certified Rust driver, unlike
   libogg-rs's finding #5, which only touched the fuzz-only wrapper).

A subsequent 15-minute run was clean: **865,705 executions, ~960 exec/s, zero crashes.**

## Status (2026-07-18)

Built and validated, two harness-only findings fixed (above) — no bugs found in the certified
codec decoders themselves (`lzw.rs`/`rle.rs`). Wired into CI (`fuzz-smoke`, 60s on every
commit). Not yet run for the multi-hour depth the `fuzz_getimage` libtiff campaign used, and not
yet wired into the pre-RFC gate (see "Process integration" in the scope doc for what that
requires).
