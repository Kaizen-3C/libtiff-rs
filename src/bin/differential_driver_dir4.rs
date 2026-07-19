//! Differential op-script driver for the Long8 strip-array reader (Slice 4). Reads stdin `L ...`
//! lines, runs each through `libtiff_rs::dirread::run_line_arr8`, prints its trace — byte-for-byte
//! matching `cref/_driver_dir4.c`.

use std::io::{self, BufWriter, Read, Write};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for line in input.lines() {
        out.write_all(libtiff_rs::dirread::run_line_arr8(line).as_bytes())
            .unwrap();
    }
}
