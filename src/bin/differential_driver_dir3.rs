//! Differential op-script driver for the value-array fetch (Slice 3). Reads stdin `A ...` lines,
//! runs each through `libtiff_rs::dirread::run_line_arr`, prints its trace — byte-for-byte matching
//! `cref/_driver_dir3.c`.

use std::io::{self, BufWriter, Read, Write};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for line in input.lines() {
        out.write_all(libtiff_rs::dirread::run_line_arr(line).as_bytes())
            .unwrap();
    }
}
