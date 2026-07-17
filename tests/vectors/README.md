# Differential test vectors

`tiff_inputs.txt` — 538 cases across the four codecs (LZW / PackBits / Thunder / NeXT), one per
line, prefixed `L` / `P` / `T` / `N`. `tiff_golden.txt` — the reference decoder's output, one
`R …` line plus a `.` separator per case. `scripts/regen_goldens.sh` rebuilds the C reference from
the pinned upstream tarball and re-proves `C == Rust == golden`; CI runs it every commit.

## Provenance notes

### LZW code-width boundary correction

The generator behind the LZW vectors previously increased the code width one code too early — at
`nextcode == 2^bits - 1` rather than `2^bits`. libtiff's decoder uses the early-change convention
(`maxcode = 2^bits - 1`), so a matching encoder must bump at `2^bits` to stay in sync. With the
early bump, any payload that crossed a 9→10→11→12 bit boundary encoded to a stream the decoder
**rejected** (`ret=0`, "code not yet in table") instead of decoding — so those width-boundary
cases exercised the reject path, not the intended happy path, even though the corpus billed them
as valid streams.

Corrected to bump at `2^bits` and regenerated the vectors and golden from the upstream-built C
reference. Scope: **only the LZW vectors changed** (87 of 208 re-encoded); PackBits/Thunder/NeXT
are untouched. Re-attested with `regen_goldens.sh`: `C == Rust == golden` across all 538 cases.
Successful-decode (`ret=1`) coverage rises **317 → 349** — the previously-rejected width-boundary
streams now decode, which is what those cases were meant to test. The corpus now round-trips
through the C decoders wherever it claims to be well-formed, at width boundaries included.
