//! # libtiff-rs
//!
//! Memory-safe Rust ports of libtiff 4.7.0's codec-core decoders, each differentially
//! certified byte-identical to the upstream C build (see README.md):
//!   - [`lzw`]  : the LZW decoder (tif_lzw.c) — the 9-12-bit code-table decoder
//!   - [`rle`]  : PackBits, Thunder, and NeXT (tif_packbits.c / tif_thunder.c / tif_next.c)
//!
//! These are libtiff's separable, pure-C, untrusted-input decompressors; their bounds
//! guards are the codec-overflow CVE surface. The entire crate is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]
// The decoders mirror upstream tif_*.c structure (goto state machines, `_TIFFmemcpy` byte
// loops, index-based table init), which produces a few benign machine-generated patterns.
// Each decoder is certified byte-identical to upstream; see README.
#![allow(unused_assignments)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::manual_memcpy)]

pub mod driver_core;
pub mod lzw;
pub mod rle;

pub use lzw::lzw_decode;
pub use rle::{next_decode_mem, packbits_decode, thunder_decode};
