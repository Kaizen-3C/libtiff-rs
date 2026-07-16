# The differential harness

How the correctness claim is produced, so it can be verified without trusting this repository.

## The claim

The Rust port and upstream libtiff 4.7.0, driven by the same op-script driver over the 261-case
envelope in `tests/vectors/`, produce **byte-identical stdout**.

## How the C reference is built (`scripts/regen_goldens.sh`)

1. Download `tiff-4.7.0.tar.gz` from download.osgeo.org and verify sha256
   `67160e3457365ab96c5b3286a0903aa6e78bdc44c4bc737d2e486bcecb6ba976`.
2. `cref/assemble.py` slices the **verbatim** LZW decoder from the upstream `tif_lzw.c` by
   pinned line range: the code-table constants/state (`code_t`, `LZWCodecState`, `CSIZE`,
   `BITS_MIN/MAX`, `CODE_*`), `LZWSetupDecode`, `LZWPreDecode`, the `GetNextData`/
   `GetNextCodeLZW` bit-reader macros, and `LZWDecode`.
3. It prepends `cref/_prelude.c` — the minimal `TIFF` struct (only the fields the decode path
   touches), the `WordType`/`SIZEOF_WORDTYPE` typedefs, and small allocator/predictor/
   diagnostic stubs — and appends `cref/_driver.c`, the op-script driver. **The prelude/shim is
   the only added code; the decoder body is verbatim upstream.** `LZW_COMPAT` is left undefined,
   so old-style streams take the upstream reject branch (which the envelope exercises).
4. Compile and run over `tests/vectors/tiff_inputs.txt`; byte-compare the C output against the
   Rust `differential_driver` and the checked-in golden.

CI runs this on every commit, so "byte-identical to upstream" is re-proven from libtiff's own
code, not taken on faith.

## The op-script format

Each stdin line is `<occ> <hex>`: the requested output byte count and the raw LZW-compressed
input as hex. The driver decodes and prints:

- `R <ret> <occ> <fnv> <rawcc>` — decoder return code (1 ok / 0 error), requested size, FNV-1a
  of the decoded output buffer (the decoder zeroes the tail on short/erroneous input, so the
  hash is always defined), and `tif_rawcc` after decode (input bytes left unconsumed)
- a `.` separator line

Full op semantics are documented at the top of `cref/_driver.c`.

## Corpus validity

Valid LZW streams in the envelope are produced by a TIFF-LZW encoder that was verified to
round-trip through the C decoder (encode → C-decode → original) before the corpus was frozen,
so the "valid" cases are genuinely well-formed and the "adversarial" cases (truncation,
bit-flips into undefined codes, missing EOI, fuzz) genuinely exercise the reject/bounds paths.

## Regenerating or extending the envelope

The input vectors are plain text (`<occ> <hex>` per line). Add lines and rerun
`scripts/regen_goldens.sh` — it rebuilds goldens from the upstream C, so the reference is always
libtiff's code, never this port.
