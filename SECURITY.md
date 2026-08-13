# Security policy

`libtiff-rs` reimplements a parser of **untrusted input** (TIFF files from the network, scanners,
and third parties), so memory-safety and correctness reports are taken seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not as a public issue:

- Preferred: open a private advisory via GitHub — **Security → Report a vulnerability** on this
  repository (GitHub Security Advisories).

Include, where possible: the input that triggers the issue (a minimal TIFF or op-script line), the
observed behavior (panic, wrong output, a divergence from upstream `libtiff`), and the commit or
release you tested.

## What to expect

- **Acknowledgement** within a few days.
- An initial assessment (reproduced / not reproduced, severity) as soon as we have triaged it.
- **Coordinated disclosure:** we will agree a disclosure timeline with you and credit you in the
  advisory and changelog unless you prefer to remain anonymous.

## Scope

- **In scope:** the safe-Rust decode path in this crate — the codec decoders, the directory/IFD
  parser, strip/tile geometry, and the end-to-end `decode` path. Because the crate is
  `#![forbid(unsafe_code)]`, any memory-unsafety would be a compiler/toolchain bug rather than a
  crate bug; a *panic* or a *behavioral divergence from upstream `libtiff`* on a valid input is the
  more likely class of report and is in scope.
- **Also welcome:** any input on which this crate's output differs from the pinned upstream
  `libtiff` 4.7.0 C reference. Divergences are treated as correctness bugs even when they are not
  security-relevant, and the differential harness can usually turn a report into a permanent
  regression test.

## Supported versions

The project is pre-1.0 and moving quickly; fixes land on `main`. Please test against the latest
`main` (or the most recent tag) before reporting.
