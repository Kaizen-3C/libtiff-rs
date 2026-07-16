//! libtiff 4.7.0 RLE-family codec decoders: PackBitsDecode (tif_packbits.c),
//! ThunderDecode (tif_thunder.c), NeXTDecode (tif_next.c) — each ported and certified
//! byte-identical to upstream. See README for the differential methodology.

// PackBits
pub fn packbits_decode(inbuf: &[u8], buf: &mut [u8]) -> (i32, i64) {
    let mut bp: usize = 0;
    let mut cc: i64 = inbuf.len() as i64;
    let mut occ: i64 = buf.len() as i64;
    let mut op: usize = 0;
    while cc > 0 && occ > 0 {
        let nb = inbuf[bp] as i8 as i64;
        bp += 1;
        cc -= 1;
        let mut n: i64 = nb;
        if n < 0 {
            if n == -128 {
                continue;
            }
            n = -n + 1;
            if occ < n {
                n = occ;
            }
            if cc == 0 {
                break;
            }
            occ -= n;
            let b = inbuf[bp];
            bp += 1;
            cc -= 1;
            while n > 0 {
                buf[op] = b;
                op += 1;
                n -= 1;
            }
        } else {
            if occ < n + 1 {
                n = occ - 1;
            }
            if cc < n + 1 {
                break;
            }
            n += 1;
            for i in 0..n as usize {
                buf[op + i] = inbuf[bp + i];
            }
            op += n as usize;
            occ -= n;
            bp += n as usize;
            cc -= n;
        }
    }
    if occ > 0 {
        for i in op..(op + occ as usize) {
            buf[i] = 0;
        }
        return (0, cc);
    }
    (1, cc)
}

// Thunder
pub fn thunder_decode(inbuf: &[u8], buf: &mut [u8], maxpixels: i64) -> (i32, i64) {
    let twobitdeltas: [i32; 4] = [0, 1, 0, -1];
    let threebitdeltas: [i32; 8] = [0, 1, 2, 3, 0, -3, -2, -1];

    let mut bp: usize = 0;
    let mut cc: i64 = inbuf.len() as i64;
    let mut lastpixel: u32 = 0;
    let mut npixels: i64 = 0;
    let mut op: usize = 0;

    macro_rules! setpixel {
        ($v:expr) => {{
            let val: i32 = $v;
            lastpixel = (val & 0xf) as u32;
            if npixels < maxpixels {
                let odd = npixels & 1;
                npixels += 1;
                if odd != 0 {
                    if op < buf.len() {
                        buf[op] |= lastpixel as u8;
                    }
                    op += 1;
                } else {
                    if op < buf.len() {
                        buf[op] = ((lastpixel & 0xf) << 4) as u8;
                    }
                }
            }
        }};
    }

    while cc > 0 && npixels < maxpixels {
        let n0 = inbuf[bp] as i32;
        bp += 1;
        cc -= 1;
        let mut n: i32 = n0;
        match n & 0xc0 {
            0x00 => {
                // pixel run
                if n == 0 {
                    // break
                } else {
                    if (npixels & 1) != 0 {
                        if op < buf.len() {
                            buf[op] |= lastpixel as u8;
                        }
                        lastpixel = if op < buf.len() { buf[op] as u32 } else { 0 };
                        op += 1;
                        npixels += 1;
                        n -= 1;
                    } else {
                        lastpixel |= lastpixel << 4;
                    }
                    npixels += n as i64;
                    if npixels > maxpixels {
                        // break
                    } else {
                        while n > 0 {
                            if op < buf.len() {
                                buf[op] = lastpixel as u8;
                            }
                            op += 1;
                            n -= 2;
                        }
                        if n == -1 {
                            op -= 1;
                            if op < buf.len() {
                                buf[op] &= 0xf0;
                            }
                        }
                        lastpixel &= 0xf;
                    }
                }
            }
            0x40 => {
                // 2-bit deltas
                let mut delta = (n >> 4) & 3;
                if delta != 2 {
                    setpixel!(lastpixel as i32 + twobitdeltas[delta as usize]);
                }
                delta = (n >> 2) & 3;
                if delta != 2 {
                    setpixel!(lastpixel as i32 + twobitdeltas[delta as usize]);
                }
                delta = n & 3;
                if delta != 2 {
                    setpixel!(lastpixel as i32 + twobitdeltas[delta as usize]);
                }
            }
            0x80 => {
                // 3-bit deltas
                let mut delta = (n >> 3) & 7;
                if delta != 4 {
                    setpixel!(lastpixel as i32 + threebitdeltas[delta as usize]);
                }
                delta = n & 7;
                if delta != 4 {
                    setpixel!(lastpixel as i32 + threebitdeltas[delta as usize]);
                }
            }
            _ => {
                // raw
                setpixel!(n);
            }
        }
    }

    if npixels != maxpixels {
        let op_end = ((maxpixels as i128) + 1) / 2;
        let end = if op_end > buf.len() as i128 {
            buf.len()
        } else if op_end < 0 {
            0
        } else {
            op_end as usize
        };
        let start = if op > end { end } else { op };
        for i in start..end {
            buf[i] = 0;
        }
        return (0, cc);
    }
    (1, cc)
}

// NeXT
pub struct Tiff {
    rawdata: Vec<u8>,
    rawcp: usize,
    rawcc: i64,
    scanlinesize: i64,
    imagewidth: u32,
}

pub fn next_decode(tif: &mut Tiff, buf: &mut [u8], occ: i64) -> i32 {
    let occ_us = occ as usize;
    for i in 0..occ_us {
        buf[i] = 0xff;
    }

    let mut bp = tif.rawcp;
    let mut cc = tif.rawcc;
    let scanline = tif.scanlinesize;

    if occ % scanline != 0 {
        return 0;
    }

    let mut occ_rem = occ;
    let mut row: i64 = 0;

    while cc > 0 && occ_rem > 0 {
        if bp >= tif.rawdata.len() {
            break;
        }
        let mut n: i64 = tif.rawdata[bp] as i64;
        bp += 1;
        cc -= 1;

        match n {
            0x00 => {
                if cc < scanline {
                    return 0;
                }
                let row_us = row as usize;
                let scan_us = scanline as usize;
                buf[row_us..row_us + scan_us].copy_from_slice(&tif.rawdata[bp..bp + scan_us]);
                bp += scan_us;
                cc -= scanline;
            }
            0x40 => {
                if cc < 4 {
                    return 0;
                }
                let off = (tif.rawdata[bp] as i64) * 256 + (tif.rawdata[bp + 1] as i64);
                let nn = (tif.rawdata[bp + 2] as i64) * 256 + (tif.rawdata[bp + 3] as i64);
                if cc < 4 + nn || off + nn > scanline {
                    return 0;
                }
                let row_us = row as usize;
                let off_us = off as usize;
                let n_us = nn as usize;
                buf[row_us + off_us..row_us + off_us + n_us]
                    .copy_from_slice(&tif.rawdata[bp + 4..bp + 4 + n_us]);
                bp += 4 + n_us;
                cc -= 4 + nn;
            }
            _ => {
                let mut npixels: u32 = 0;
                let mut op_offset: i64 = 0;
                let imagewidth = tif.imagewidth;

                loop {
                    let grey = ((n >> 6) & 0x3) as u8;
                    let mut n_local = n & 0x3f;
                    while n_local > 0 && npixels < imagewidth && op_offset < scanline {
                        n_local -= 1;
                        let idx = (row + op_offset) as usize;
                        match npixels & 3 {
                            0 => {
                                buf[idx] = grey << 6;
                            }
                            1 => {
                                buf[idx] |= grey << 4;
                            }
                            2 => {
                                buf[idx] |= grey << 2;
                            }
                            3 => {
                                buf[idx] |= grey;
                                op_offset += 1;
                            }
                            _ => unreachable!(),
                        }
                        npixels += 1;
                    }
                    if npixels >= imagewidth {
                        break;
                    }
                    if op_offset >= scanline {
                        return 0;
                    }
                    if cc == 0 {
                        return 0;
                    }
                    n = tif.rawdata[bp] as i64;
                    bp += 1;
                    cc -= 1;
                }
            }
        }

        occ_rem -= scanline;
        row += scanline;
    }

    tif.rawcp = bp;
    tif.rawcc = cc;
    1
}

/// Uniform memory-buffer entry point for NeXTDecode: returns (ret, rawcc).
pub fn next_decode_mem(
    inbuf: &[u8],
    buf: &mut [u8],
    occ: i64,
    scanline: i64,
    imagewidth: u32,
) -> (i32, i64) {
    let mut tif = Tiff {
        rawdata: inbuf.to_vec(),
        rawcp: 0,
        rawcc: inbuf.len() as i64,
        scanlinesize: if scanline <= 0 { 1 } else { scanline },
        imagewidth,
    };
    let ret = next_decode(&mut tif, buf, occ);
    (ret, tif.rawcc)
}
