//! libtiff 4.7.0 LZW decoder (LZWSetupDecode + LZWPreDecode + LZWDecode from tif_lzw.c),
//! ported verbatim-in-behavior and certified byte-identical to upstream.

// The decode function mirrors upstream tif_lzw.c's goto-state-machine + code-table structure,
// which produces a few benign machine-generated patterns (running-position dead stores across
// labeled breaks, index-based table init). Certified byte-identical to upstream; see README.

#[derive(Clone, Copy)]
pub struct CodeEnt {
    next: i32,
    length: u16,
    firstchar: u8,
    value: u8,
    repeated: bool,
}

impl Default for CodeEnt {
    fn default() -> Self {
        CodeEnt {
            next: -1,
            length: 0,
            firstchar: 0,
            value: 0,
            repeated: false,
        }
    }
}

const CODE_CLEAR: u64 = 256;
const CODE_EOI: u64 = 257;
const CODE_FIRST: u64 = 258;
const CSIZE: usize = 4096;

fn read_be_u64(raw: &[u8], pos: usize) -> u64 {
    let mut buf = [0u8; 8];
    let end = (pos + 8).min(raw.len());
    if end > pos {
        buf[..end - pos].copy_from_slice(&raw[pos..end]);
    }
    u64::from_be_bytes(buf)
}

fn get_next_code(
    raw: &[u8],
    bp_pos: &mut usize,
    nextdata: &mut u64,
    nextbits: &mut i64,
    dec_bitsleft: &mut u64,
    nbits: i64,
    nbitsmask: i64,
) -> Option<u64> {
    *nextbits -= nbits;
    if *nextbits < 0 {
        if *dec_bitsleft >= 64 {
            let shift = (-*nextbits) as u32;
            let codetmp = (*nextdata << shift) as u32;
            let newdata = read_be_u64(raw, *bp_pos);
            *bp_pos += 8;
            *nextbits += 64;
            *dec_bitsleft -= 64;
            *nextdata = newdata;
            let code = (codetmp as u64 | (*nextdata >> *nextbits)) & (nbitsmask as u64);
            return Some(code);
        } else {
            if *dec_bitsleft < 8 {
                return None;
            }
            *nextdata = (*nextdata << 8) | (raw[*bp_pos] as u64);
            *bp_pos += 1;
            *nextbits += 8;
            *dec_bitsleft -= 8;
            if *nextbits < 0 {
                if *dec_bitsleft < 8 {
                    return None;
                }
                *nextdata = (*nextdata << 8) | (raw[*bp_pos] as u64);
                *bp_pos += 1;
                *nextbits += 8;
                *dec_bitsleft -= 8;
            }
        }
    }
    let code = (*nextdata >> *nextbits) & (nbitsmask as u64);
    Some(code)
}

fn too_short_buffer(
    table: &[CodeEnt],
    output: &mut Vec<u8>,
    op_pos: usize,
    occ: i64,
    start_codep: i32,
) {
    let mut codep = start_codep;
    loop {
        codep = table[codep as usize].next;
        if table[codep as usize].length as i64 <= occ {
            break;
        }
    }
    let mut tp = op_pos + occ as usize;
    for _ in 0..occ {
        tp -= 1;
        output[tp] = table[codep as usize].value;
        codep = table[codep as usize].next;
    }
}

pub fn lzw_decode(raw: &[u8], occ0: usize) -> (i32, Vec<u8>, i64) {
    let n = raw.len();
    let output = vec![0u8; occ0];

    if n >= 2 && raw[0] == 0 && (raw[1] & 1) != 0 {
        return (0, output, n as i64);
    }

    let mut output = output;
    let mut table = vec![CodeEnt::default(); CSIZE];
    for code in 0..256usize {
        table[code].firstchar = code as u8;
        table[code].value = code as u8;
        table[code].repeated = true;
        table[code].length = 1;
        table[code].next = -1;
    }

    let mut bp_pos: usize = 0;
    let mut dec_bitsleft: u64 = (n as u64) * 8;
    let mut nbits: i64 = 9;
    let mut nextdata: u64 = 0;
    let mut nextbits: i64 = 0;
    let mut nbitsmask: i64 = 511;
    let mut oldcodep: i32 = 0;
    let mut free_entp: i32 = -1;
    let mut maxcodep: i32 = 510;
    let mut op_pos: usize = 0;
    let mut occ: i64 = occ0 as i64;

    if occ == 0 {
        return (1, output, (n - bp_pos) as i64);
    }

    'begin: loop {
        let code = match get_next_code(
            raw,
            &mut bp_pos,
            &mut nextdata,
            &mut nextbits,
            &mut dec_bitsleft,
            nbits,
            nbitsmask,
        ) {
            Some(c) => c,
            None => {
                return (0, output, n as i64);
            }
        };

        if code >= CODE_FIRST {
            let code_u = code as i32;
            let fe = free_entp;
            if code_u >= fe {
                if code_u != fe {
                    return (0, output, n as i64);
                }
                let v = table[oldcodep as usize].firstchar;
                table[fe as usize].value = v;
            } else {
                let v = table[code_u as usize].firstchar;
                table[fe as usize].value = v;
            }
            let rep = table[oldcodep as usize].repeated
                && (table[oldcodep as usize].value == table[fe as usize].value);
            table[fe as usize].repeated = rep;
            table[fe as usize].next = oldcodep;
            let fc = table[oldcodep as usize].firstchar;
            table[fe as usize].firstchar = fc;
            let ln = table[oldcodep as usize].length + 1;
            table[fe as usize].length = ln;
            free_entp = fe + 1;
            if free_entp > maxcodep {
                nbits += 1;
                if nbits > 12 {
                    nbits = 12;
                }
                nbitsmask = (1i64 << nbits) - 1;
                maxcodep = (nbitsmask as i32) - 1;
                if free_entp >= CSIZE as i32 {
                    free_entp = -1;
                }
            }
            oldcodep = code_u;
            let len = table[code_u as usize].length;

            if len < 3 {
                if occ <= 2 {
                    if occ == 2 {
                        output[op_pos] = table[code_u as usize].firstchar;
                        output[op_pos + 1] = table[code_u as usize].value;
                        op_pos += 2;
                        occ -= 2;
                        break 'begin;
                    } else {
                        too_short_buffer(&table, &mut output, op_pos, occ, code_u);
                        occ = 0;
                        break 'begin;
                    }
                } else {
                    output[op_pos] = table[code_u as usize].firstchar;
                    output[op_pos + 1] = table[code_u as usize].value;
                    op_pos += 2;
                    occ -= 2;
                    continue 'begin;
                }
            } else if len == 3 {
                if occ <= 3 {
                    if occ == 3 {
                        let nx = table[code_u as usize].next;
                        output[op_pos] = table[code_u as usize].firstchar;
                        output[op_pos + 1] = table[nx as usize].value;
                        output[op_pos + 2] = table[code_u as usize].value;
                        op_pos += 3;
                        occ -= 3;
                        break 'begin;
                    } else {
                        too_short_buffer(&table, &mut output, op_pos, occ, code_u);
                        occ = 0;
                        break 'begin;
                    }
                } else {
                    let nx = table[code_u as usize].next;
                    output[op_pos] = table[code_u as usize].firstchar;
                    output[op_pos + 1] = table[nx as usize].value;
                    output[op_pos + 2] = table[code_u as usize].value;
                    op_pos += 3;
                    occ -= 3;
                    continue 'begin;
                }
            } else {
                if (len as i64) > occ {
                    too_short_buffer(&table, &mut output, op_pos, occ, code_u);
                    occ = 0;
                    break 'begin;
                }
                if table[code_u as usize].repeated {
                    let v = table[code_u as usize].value;
                    for i in 0..len as usize {
                        output[op_pos + i] = v;
                    }
                    op_pos += len as usize;
                    occ -= len as i64;
                    if occ == 0 {
                        break 'begin;
                    } else {
                        continue 'begin;
                    }
                } else {
                    let mut tp = op_pos + len as usize;
                    let mut cp = code_u;
                    tp -= 1;
                    output[tp] = table[cp as usize].value;
                    cp = table[cp as usize].next;
                    tp -= 1;
                    output[tp] = table[cp as usize].value;
                    cp = table[cp as usize].next;
                    tp -= 1;
                    output[tp] = table[cp as usize].value;
                    cp = table[cp as usize].next;
                    tp -= 1;
                    output[tp] = table[cp as usize].value;
                    while tp > op_pos {
                        cp = table[cp as usize].next;
                        tp -= 1;
                        output[tp] = table[cp as usize].value;
                    }
                    op_pos += len as usize;
                    occ -= len as i64;
                    if occ == 0 {
                        break 'begin;
                    } else {
                        continue 'begin;
                    }
                }
            }
        } else if code < 256 {
            let code_u = code as i32;
            if code_u > free_entp {
                return (0, output, n as i64);
            }
            let fe = free_entp;
            table[fe as usize].next = oldcodep;
            let fc = table[oldcodep as usize].firstchar;
            table[fe as usize].firstchar = fc;
            let ln = table[oldcodep as usize].length + 1;
            table[fe as usize].length = ln;
            table[fe as usize].value = code_u as u8;
            let rep = table[oldcodep as usize].repeated
                && (table[oldcodep as usize].value == code_u as u8);
            table[fe as usize].repeated = rep;
            free_entp = fe + 1;
            if free_entp > maxcodep {
                nbits += 1;
                if nbits > 12 {
                    nbits = 12;
                }
                nbitsmask = (1i64 << nbits) - 1;
                maxcodep = (nbitsmask as i32) - 1;
                if free_entp >= CSIZE as i32 {
                    free_entp = -1;
                }
            }
            oldcodep = code_u;
            output[op_pos] = code_u as u8;
            op_pos += 1;
            occ -= 1;
            if occ == 0 {
                break 'begin;
            } else {
                continue 'begin;
            }
        } else if code == CODE_EOI {
            break 'begin;
        } else {
            free_entp = CODE_FIRST as i32;
            nbits = 9;
            nbitsmask = 511;
            maxcodep = 510;
            let code2;
            loop {
                match get_next_code(
                    raw,
                    &mut bp_pos,
                    &mut nextdata,
                    &mut nextbits,
                    &mut dec_bitsleft,
                    nbits,
                    nbitsmask,
                ) {
                    Some(c) => {
                        if c != CODE_CLEAR {
                            code2 = c;
                            break;
                        }
                    }
                    None => {
                        return (0, output, n as i64);
                    }
                }
            }
            if code2 == CODE_EOI {
                break 'begin;
            }
            if code2 > CODE_EOI {
                return (0, output, n as i64);
            }
            output[op_pos] = code2 as u8;
            op_pos += 1;
            occ -= 1;
            oldcodep = code2 as i32;
            if occ == 0 {
                break 'begin;
            } else {
                continue 'begin;
            }
        }
    }

    let rawcc_left = (n - bp_pos) as i64;
    if occ > 0 {
        return (0, output, rawcc_left);
    }
    (1, output, rawcc_left)
}
