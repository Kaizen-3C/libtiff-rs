//! The op-script interpreter shared by `src/bin/differential_driver.rs` (stdout) and the
//! differential fuzz target (in-process, string return) — one implementation, two callers, so
//! there's no risk of the fuzz oracle drifting from the certified driver. Mirrors
//! `cref/_driver.c`'s per-line dispatch; see `HARNESS.md` for the op-script format.

use crate::{lzw_decode, next_decode_mem, packbits_decode, thunder_decode};

const MAXBUF: usize = 1 << 20;

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Matches C's `atol(s)` (== `(long)strtol(s, NULL, 10)`, and `long` is 64-bit on this LP64
/// target): skip leading isspace() (space/\t/\n/\v/\f/\r), optional sign, then a run of decimal
/// digits, stopping at the first non-digit — not Rust's `str::parse`, which rejects the whole
/// string on any trailing garbage. `cref/_driver.c` parses every numeric op-script field with
/// real `atol()`, so the port matches that exactly to keep the two engines' tokenization in
/// lockstep. Overflow saturates to i64::MAX/MIN, matching atol's ERANGE-then-ignore
/// behavior; every caller here additionally clamps the result to a small sane range, so the
/// saturation direction rarely matters in practice, but the leading-digit-then-stop parsing does.
fn atol(s: &str) -> i64 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r') {
        i += 1;
    }
    let neg = i < b.len() && b[i] == b'-';
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let mut val: i64 = 0;
    let mut saturated = false;
    let mut any = false;
    while i < b.len() && b[i].is_ascii_digit() {
        any = true;
        if !saturated {
            let d = (b[i] - b'0') as i64;
            match val.checked_mul(10).and_then(|v| v.checked_add(d)) {
                Some(v) => val = v,
                None => saturated = true,
            }
        }
        i += 1;
    }
    if !any {
        return 0;
    }
    if saturated {
        return if neg { i64::MIN } else { i64::MAX };
    }
    if neg {
        -val
    } else {
        val
    }
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

/// Runs one op-script line and returns its trace ("R ...\n.\n"), or "" for an empty/tag-less
/// line (matching `cref/_driver.c`'s `if (!codec) continue;`, which skips the whole iteration —
/// no output at all).
pub fn run_line(line: &str) -> String {
    // _driver.c's `strtok` operates on a NUL-terminated C string: an embedded 0x00 anywhere in
    // the line silently ends it there for every downstream C string function (strtok, atol),
    // even though Rust strings can contain interior NULs freely. Truncate up front so both
    // engines tokenize identical content — the differential fuzzer surfaced this gap within the
    // first ~1,200 executions.
    let line = match line.find('\0') {
        Some(pos) => &line[..pos],
        None => line,
    };

    // `strtok(line, " \t\r\n")` splits on exactly those 4 ASCII bytes — not `split_whitespace`'s
    // full Unicode White_Space set (which also treats \v/\f/NBSP/etc. as separators). A byte
    // strtok keeps as part of a token, split_whitespace would treat as a boundary, silently
    // shifting where each argument starts.
    let mut it = line
        .split([' ', '\t', '\r', '\n'])
        .filter(|s| !s.is_empty());
    let codec = match it.next() {
        Some(t) if !t.is_empty() => t.as_bytes()[0],
        _ => return String::new(),
    };

    let (ret, outsize, fnv, rawcc) = match codec {
        b'P' => {
            let occ = atol(it.next().unwrap_or("0")).clamp(0, MAXBUF as i64);
            let raw = load_hex(it.next());
            let mut buf = vec![0u8; occ as usize];
            let (ret, rawcc) = packbits_decode(&raw, &mut buf);
            (ret, occ, fnv32(&buf), rawcc)
        }
        b'T' => {
            // maxpixels tells thunder_decode how many bytes of `buf` it may write
            // ((maxpixels+1)/2); clamp maxpixels itself (not just outbytes) so the two can
            // never disagree — an unclamped maxpixels with a clamped buffer allocation is a
            // driver-only global-buffer-overflow in the C reference (found by the differential
            // fuzz target; real libtiff callers always derive both from the same source, so
            // this was never reachable via a real TIFF, only via this driver's own
            // inconsistent clamping — see the matching fix in cref/_driver.c).
            let maxpixels = atol(it.next().unwrap_or("0"))
                .max(0)
                .min(2 * MAXBUF as i64 - 1);
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

    format!("R {} {} {:08x} {}\n.\n", ret, outsize, fnv, rawcc)
}
