//! Differential op-script driver: one codec-tagged op per stdin line, dispatched to the
//! matching decoder module; prints a trace byte-compared against the upstream C reference
//! (mirrors cref/_driver.c). Dispatch:
//!   P <occ> <hex>                 -> rle::packbits_decode
//!   T <maxpixels> <hex>           -> rle::thunder_decode   (output = (maxpixels+1)/2 bytes)
//!   N <occ> <scanline> <iw> <hex> -> rle::next_decode_mem
//!   L <occ> <hex>                 -> lzw::lzw_decode

use std::io::{self, BufWriter, Read, Write};

use libtiff_rs::{lzw_decode, next_decode_mem, packbits_decode, thunder_decode};

const MAXBUF: usize = 1 << 20;

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn atol(s: &str) -> i64 {
    s.trim().parse::<i64>().unwrap_or(0)
}

fn load_hex(hex: Option<&str>) -> Vec<u8> {
    let mut v = Vec::new();
    if let Some(hex) = hex {
        let hb = hex.as_bytes();
        let mut i = 0usize;
        while 2 * i + 1 < hb.len() {
            match (hexval(hb[2 * i]), hexval(hb[2 * i + 1])) {
                (Some(hi), Some(lo)) => {
                    if v.len() >= MAXBUF {
                        break;
                    }
                    v.push((hi << 4) | lo);
                    i += 1;
                }
                _ => break,
            }
        }
    }
    v
}

fn fnv32(buf: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &b in buf {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for line in input.lines() {
        let mut it = line.split_whitespace();
        let codec = match it.next() {
            Some(t) if !t.is_empty() => t.as_bytes()[0],
            _ => continue,
        };

        // (ret, reported-output-size, fnv, rawcc)
        let (ret, outsize, fnv, rawcc) = match codec {
            b'P' => {
                let occ = atol(it.next().unwrap_or("0")).clamp(0, MAXBUF as i64);
                let raw = load_hex(it.next());
                let mut buf = vec![0u8; occ as usize];
                let (ret, rawcc) = packbits_decode(&raw, &mut buf);
                (ret, occ, fnv32(&buf), rawcc)
            }
            b'T' => {
                let maxpixels = atol(it.next().unwrap_or("0")).max(0);
                let raw = load_hex(it.next());
                let outbytes = ((maxpixels + 1) / 2).min(MAXBUF as i64);
                let mut buf = vec![0u8; outbytes as usize];
                let (ret, rawcc) = thunder_decode(&raw, &mut buf, maxpixels);
                (ret, outbytes, fnv32(&buf), rawcc)
            }
            b'N' => {
                let occ = atol(it.next().unwrap_or("0")).clamp(0, MAXBUF as i64);
                let scan = atol(it.next().unwrap_or("1"));
                let iw = atol(it.next().unwrap_or("0")) as u32;
                let raw = load_hex(it.next());
                let mut buf = vec![0u8; occ as usize];
                let (ret, rawcc) = next_decode_mem(&raw, &mut buf, occ, scan, iw);
                (ret, occ, fnv32(&buf), rawcc)
            }
            _ => {
                // 'L' (and any unknown tag) -> LZW
                let occ = atol(it.next().unwrap_or("0")).clamp(0, MAXBUF as i64);
                let raw = load_hex(it.next());
                let (ret, output, rawcc) = lzw_decode(&raw, occ as usize);
                (ret, occ, fnv32(&output), rawcc)
            }
        };

        writeln!(out, "R {} {} {:08x} {}", ret, outsize, fnv, rawcc).unwrap();
        writeln!(out, ".").unwrap();
    }
}
