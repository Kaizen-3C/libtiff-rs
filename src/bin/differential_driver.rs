//! Differential op-script driver: reads stdin line by line, runs each through
//! `libtiff_rs::driver_core::run_line` (the shared interpreter also used by the differential
//! fuzz target), and prints its trace. See HARNESS.md for the op-script format.

use std::io::{self, BufWriter, Read, Write};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for line in input.lines() {
        out.write_all(libtiff_rs::driver_core::run_line(line).as_bytes())
            .unwrap();
    }
}
