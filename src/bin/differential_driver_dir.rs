//! Differential op-script driver for the IFD directory-entry readers (Slice 1). Reads stdin line
//! by line, runs each `E ...` line through `libtiff_rs::dirread::run_line`, and prints its trace —
//! byte-for-byte matching `cref/_driver_dir.c`. See BUG-HUNT-OPS.md for the op-script format.

use std::io::{self, BufWriter, Read, Write};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for line in input.lines() {
        out.write_all(libtiff_rs::dirread::run_line(line).as_bytes())
            .unwrap();
    }
}
