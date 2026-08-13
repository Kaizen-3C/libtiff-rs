# Contributing to libtiff-rs

Thanks for your interest. `libtiff-rs` is a memory-safe (`#![forbid(unsafe_code)]`) reimplementation
of libtiff's TIFF decode path whose defining property is that it is **differentially certified
byte-identical to the upstream C** — so the contribution bar is a little different from a typical
crate: *behavior is measured against libtiff, not reviewed by opinion.* That discipline is also what
keeps the project maintainable by more than one person — anyone can re-run the proof.

## Ground rules

1. **The crate stays `#![forbid(unsafe_code)]`.** No exceptions in the library.
2. **Every change keeps the differential green.** A ported function's output must remain
   byte-identical to the verbatim upstream C over the declared envelope. If you change behavior, you
   change it to match libtiff, and you show the differential still passes.
3. **New behavior comes with new differential coverage.** If you add a codec, tag path, or geometry
   case, add the corresponding vectors so the new surface is certified, not just exercised.
4. **Preserve the C's exact arithmetic.** libtiff relies on defined overflow/bounds behavior; the
   port mirrors it (`wrapping_*`, explicit guards) rather than letting Rust panic or silently differ.

## Local checks (what CI runs)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo test --release            # replays the checked-in goldens in tests/vectors/
bash scripts/regen_goldens.sh   # rebuilds the C reference from the pinned tarball and re-proves
bash scripts/e2e_certify.sh     # proves the end-to-end decode byte-identical to a real libtiff
```

Differential fuzzing (Linux/WSL; nightly + `cargo-fuzz`) is documented in `FUZZING.md`.

## Submitting

- Keep PRs focused; describe what upstream C behavior the change matches and how you verified the
  differential.
- CI (fmt, clippy `-D warnings`, build, test, the differential rebuild, and a 60s fuzz smoke) must be
  green.
- By contributing you agree your work is licensed under the crate's license (see `LICENSE`).

## Reporting security issues

Please use the private channel in `SECURITY.md`, not a public issue.
