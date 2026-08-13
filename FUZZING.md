# Differential fuzzing

Coverage-guided fuzzing that generates op-script lines and checks the Rust port against the
upstream C reference **automatically**, on top of the curated 538-case envelope in
`tests/vectors/` (see `HARNESS.md`). Complements, doesn't replace, the differential test suite.

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

Two harness-only parse-semantics gaps were closed before the first fuzz run, by auditing the
op-script interpreter against `cref/_driver.c`'s exact C string handling:

- **`atol()` used Rust's strict `str::parse`** instead of C's lenient leading-digit-run-then-stop
  semantics. `cref/_driver.c` parses every numeric field with real `atol()`.
- Added the same helper (`c`-compatible `atol` in `driver_core.rs`).

Then, on the actual first fuzz run:

1. **~1,200 executions in — embedded-NUL truncation** (`src/driver_core.rs`, harness-only).
   `strtok` treats the op-script line as a
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
   change (this is a change to the certified C reference and the certified Rust driver, not just
   a fuzz-only wrapper).

## Soak results

The 4-hour multi-process soak (32 cores) across the IFD differential targets
(`differential_dir` … `differential_dir5`, 4 libFuzzer processes each) plus the codec
`differential` target is **reproducible**: two independent runs, each from a clean rebuild of the
C reference off the pinned tarball, both landed in the **~7.6-billion-execution** range with
**zero crashes and zero differential mismatches**.

| target | run 1 execs | run 2 execs |
|---|---|---|
| `differential_dir`  | 2,364,763,304 | 2,358,078,199 |
| `differential_dir2` |   643,448,120 |   741,435,886 |
| `differential_dir3` | 1,208,141,141 | 1,185,966,173 |
| `differential_dir4` | 1,152,642,162 | 1,169,174,776 |
| `differential_dir5` | 2,254,072,689 | 2,289,397,114 |
| `differential` (codecs) | 14,046,039 | 13,273,681 |
| **IFD total** | **~7.62 B** | **~7.74 B** |

An earlier 15-minute single-process baseline was likewise clean (865,705 executions, ~960
exec/s), as was a shorter 10-minute repro pass. Zero new artifacts across all runs.

## Status

Built and validated; two harness-only findings fixed (above) — no bugs found in the certified
codec decoders themselves (`lzw.rs`/`rle.rs`) or across the multi-hour IFD soak. Wired into CI
(`fuzz-smoke`, 60s on every commit); the long soak is run out-of-band before releases.
