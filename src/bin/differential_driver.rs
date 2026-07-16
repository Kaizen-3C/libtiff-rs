//! Differential op-script driver: `<occ> <hex>` per stdin line, decoded through the
//! public `lzw_decode` API; prints a trace byte-compared against the upstream C reference.

use std::io::{self, BufWriter, Read, Write};

use libtiff_rs::lzw_decode;

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn atol_like(s: &str) -> i64 {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    let mut sign: i64 = 1;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        if bytes[i] == b'-' {
            sign = -1;
        }
        i += 1;
    }
    let mut val: i64 = 0;
    let mut any = false;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        any = true;
        val = val
            .saturating_mul(10)
            .saturating_add((bytes[i] - b'0') as i64);
        i += 1;
    }
    if !any {
        return 0;
    }
    sign.saturating_mul(val)
}

fn fnv32(data: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

const MAXBUF: usize = 1 << 20;

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for line in input.lines() {
        let mut it = line.split_whitespace();
        let tok = match it.next() {
            Some(t) => t,
            None => continue,
        };
        let mut occ = atol_like(tok);
        let hex = it.next();

        let mut inbuf: Vec<u8> = Vec::new();
        if let Some(hex) = hex {
            let hb = hex.as_bytes();
            let mut i = 0usize;
            loop {
                if 2 * i + 1 >= hb.len() {
                    break;
                }
                let hi = hexval(hb[2 * i]);
                let lo = hexval(hb[2 * i + 1]);
                let (hi, lo) = match (hi, lo) {
                    (Some(a), Some(b)) => (a, b),
                    _ => break,
                };
                if inbuf.len() >= MAXBUF {
                    break;
                }
                inbuf.push((hi << 4) | lo);
                i += 1;
            }
        }

        if occ < 0 {
            occ = 0;
        }
        if occ > MAXBUF as i64 {
            occ = MAXBUF as i64;
        }
        let occ_usize = occ as usize;

        let (ret, output, rawcc) = lzw_decode(&inbuf, occ_usize);

        let fnv = fnv32(&output);
        writeln!(out, "R {} {} {:08x} {}", ret, occ, fnv, rawcc).unwrap();
        writeln!(out, ".").unwrap();
    }
}
