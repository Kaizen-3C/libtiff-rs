//! End-to-end decode driver (Slice 6): read a whole TIFF file (path in argv[1]) as raw bytes,
//! decode it with the `#![forbid(unsafe_code)]` Rust path, and print the differential line —
//! byte-for-byte matching `cref/_e2e_ref.c`'s output for the same file.

use std::io::{self, BufWriter, Write};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: e2e_decode <file.tif>");
    let buf = std::fs::read(&path).expect("read tiff");
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let line = libtiff_rs::decode::format_decode(libtiff_rs::decode::decode_tiff(&buf));
    out.write_all(line.as_bytes()).unwrap();
}
