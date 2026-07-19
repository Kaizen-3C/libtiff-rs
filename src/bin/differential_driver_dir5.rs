//! Differential op-script driver for strip/tile geometry counts (Slice 5). Reads stdin `G ...`
//! lines, runs each through `libtiff_rs::geometry::run_line_geom`, prints its trace — byte-for-byte
//! matching `cref/_driver_dir5.c`.

use std::io::{self, BufWriter, Read, Write};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for line in input.lines() {
        out.write_all(libtiff_rs::geometry::run_line_geom(line).as_bytes())
            .unwrap();
    }
}
