//! Port of libtiff 4.7.0 `tif_dirread.c` IFD directory-entry readers (Slice 1): the typed
//! value-promotion reader `TIFFReadDirEntryByte`, its `Checked*` raw reads, the `CheckRangeByte*`
//! range guards, and `TIFFReadDirEntryData` — the offset+size-overflow / `tif_size`-bounds core
//! that is libtiff's classic integer-overflow → OOB CVE surface. `#![forbid(unsafe_code)]`.
//!
//! c2rust translation notes (distilled into ../../../C2RUST-LEARNINGS.md, for the engine):
//!  1. UNION-VIA-POINTER-CAST. The C reads `direntry->tdir_offset` (a union {u16,u32,u64}) with
//!     `*(uint8_t*)&u`, `u.toff_short`, `*(int16_t*)&u`, etc. `forbid(unsafe_code)` can't cast, so
//!     we keep the raw 8 offset-field bytes and read the low N in NATIVE order (matching the
//!     host-order union the C fills) with a conditional byte-swap. No struct/union modeling.
//!  2. OVERFLOW GUARD. C's `ma > ~(size_t)0 - size` → `usize::MAX - size` compare; the
//!     `(uint64_t)ma != offset` truncation check → `ma as u64 != offset`.
//!  3. C `enum` of error codes → a `#[repr(i32)]` Rust enum so the printed code matches exactly.

const TIFF_BYTE: u16 = 1;
const TIFF_SHORT: u16 = 3;
const TIFF_LONG: u16 = 4;
const TIFF_SBYTE: u16 = 6;
const TIFF_UNDEFINED: u16 = 7;
const TIFF_SSHORT: u16 = 8;
const TIFF_SLONG: u16 = 9;
const TIFF_LONG8: u16 = 16;
const TIFF_SLONG8: u16 = 17;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DirEntryErr {
    Ok = 0,
    Count = 1,
    Type = 2,
    Io = 3,
    Range = 4,
    Psdif = 5,
    Sizesan = 6,
    Alloc = 7,
}

/// A directory entry as filled from the file: `tdir_offset` is the raw 8-byte offset/value field
/// (in host order, exactly as the C union holds it).
pub struct DirEntry {
    pub tdir_type: u16,
    pub tdir_count: u64,
    pub tdir_offset: [u8; 8],
}

/// The reduced `TIFF` context the readers touch.
pub struct Ctx<'a> {
    pub swab: bool,
    pub bigtiff: bool,
    pub file: &'a [u8], // tif_base .. tif_base+tif_size (isMapped always true)
}

// --- Checked* raw typed reads (verbatim behaviour; union access → native-order byte reads) ---
fn checked_byte(e: &DirEntry) -> u8 {
    e.tdir_offset[0]
}
fn checked_sbyte(e: &DirEntry) -> i8 {
    e.tdir_offset[0] as i8
}
fn checked_short(ctx: &Ctx, e: &DirEntry) -> u16 {
    let mut v = u16::from_ne_bytes([e.tdir_offset[0], e.tdir_offset[1]]);
    if ctx.swab {
        v = v.swap_bytes();
    }
    v
}
fn checked_sshort(ctx: &Ctx, e: &DirEntry) -> i16 {
    checked_short(ctx, e) as i16
}
fn checked_long(ctx: &Ctx, e: &DirEntry) -> u32 {
    let mut v = u32::from_ne_bytes([
        e.tdir_offset[0],
        e.tdir_offset[1],
        e.tdir_offset[2],
        e.tdir_offset[3],
    ]);
    if ctx.swab {
        v = v.swap_bytes();
    }
    v
}
fn checked_slong(ctx: &Ctx, e: &DirEntry) -> i32 {
    checked_long(ctx, e) as i32
}
fn checked_long8(ctx: &Ctx, e: &DirEntry) -> Result<u64, DirEntryErr> {
    let mut value;
    if !ctx.bigtiff {
        // ClassicTIFF: the 8-byte value lives at an offset (the low 4 bytes of the field)
        let mut offset = u32::from_ne_bytes([
            e.tdir_offset[0],
            e.tdir_offset[1],
            e.tdir_offset[2],
            e.tdir_offset[3],
        ]);
        if ctx.swab {
            offset = offset.swap_bytes();
        }
        let mut buf = [0u8; 8];
        let err = read_dir_entry_data(ctx, offset as u64, 8, &mut buf);
        if err != DirEntryErr::Ok {
            return Err(err);
        }
        value = u64::from_ne_bytes(buf);
    } else {
        value = u64::from_ne_bytes(e.tdir_offset);
    }
    if ctx.swab {
        value = value.swap_bytes();
    }
    Ok(value)
}
fn checked_slong8(ctx: &Ctx, e: &DirEntry) -> Result<i64, DirEntryErr> {
    checked_long8(ctx, e).map(|v| v as i64)
}

// --- CheckRangeByte* pure range guards (verbatim) ---
fn range_byte_sbyte(v: i8) -> DirEntryErr {
    if v < 0 {
        DirEntryErr::Range
    } else {
        DirEntryErr::Ok
    }
}
fn range_byte_short(v: u16) -> DirEntryErr {
    if v > 0xFF {
        DirEntryErr::Range
    } else {
        DirEntryErr::Ok
    }
}
fn range_byte_sshort(v: i16) -> DirEntryErr {
    if !(0..=0xFF).contains(&v) {
        DirEntryErr::Range
    } else {
        DirEntryErr::Ok
    }
}
fn range_byte_long(v: u32) -> DirEntryErr {
    if v > 0xFF {
        DirEntryErr::Range
    } else {
        DirEntryErr::Ok
    }
}
fn range_byte_slong(v: i32) -> DirEntryErr {
    if !(0..=0xFF).contains(&v) {
        DirEntryErr::Range
    } else {
        DirEntryErr::Ok
    }
}
fn range_byte_long8(v: u64) -> DirEntryErr {
    if v > 0xFF {
        DirEntryErr::Range
    } else {
        DirEntryErr::Ok
    }
}
fn range_byte_slong8(v: i64) -> DirEntryErr {
    if !(0..=0xFF).contains(&v) {
        DirEntryErr::Range
    } else {
        DirEntryErr::Ok
    }
}

/// `TIFFReadDirEntryData`: the offset+size-overflow / `tif_size`-bounds-checked copy. The OOB core.
fn read_dir_entry_data(ctx: &Ctx, offset: u64, size: usize, dest: &mut [u8]) -> DirEntryErr {
    debug_assert!(size > 0);
    // isMapped(tif) is always true here (memory buffer).
    let ma = offset as usize;
    if ma as u64 != offset || ma > usize::MAX - size {
        return DirEntryErr::Io;
    }
    let mb = ma + size;
    if mb > ctx.file.len() {
        return DirEntryErr::Io;
    }
    dest[..size].copy_from_slice(&ctx.file[ma..mb]);
    DirEntryErr::Ok
}

/// `TIFFReadDirEntryByte`: scalar (count==1) type-dispatch + cross-type range validation → u8.
pub fn read_dir_entry_byte(ctx: &Ctx, e: &DirEntry) -> (DirEntryErr, u8) {
    if e.tdir_count != 1 {
        return (DirEntryErr::Count, 0);
    }
    match e.tdir_type {
        TIFF_BYTE | TIFF_UNDEFINED => (DirEntryErr::Ok, checked_byte(e)),
        TIFF_SBYTE => {
            let m = checked_sbyte(e);
            let err = range_byte_sbyte(m);
            if err != DirEntryErr::Ok {
                return (err, 0);
            }
            (DirEntryErr::Ok, m as u8)
        }
        TIFF_SHORT => {
            let m = checked_short(ctx, e);
            let err = range_byte_short(m);
            if err != DirEntryErr::Ok {
                return (err, 0);
            }
            (DirEntryErr::Ok, m as u8)
        }
        TIFF_SSHORT => {
            let m = checked_sshort(ctx, e);
            let err = range_byte_sshort(m);
            if err != DirEntryErr::Ok {
                return (err, 0);
            }
            (DirEntryErr::Ok, m as u8)
        }
        TIFF_LONG => {
            let m = checked_long(ctx, e);
            let err = range_byte_long(m);
            if err != DirEntryErr::Ok {
                return (err, 0);
            }
            (DirEntryErr::Ok, m as u8)
        }
        TIFF_SLONG => {
            let m = checked_slong(ctx, e);
            let err = range_byte_slong(m);
            if err != DirEntryErr::Ok {
                return (err, 0);
            }
            (DirEntryErr::Ok, m as u8)
        }
        TIFF_LONG8 => {
            let m = match checked_long8(ctx, e) {
                Ok(v) => v,
                Err(err) => return (err, 0),
            };
            let err = range_byte_long8(m);
            if err != DirEntryErr::Ok {
                return (err, 0);
            }
            (DirEntryErr::Ok, m as u8)
        }
        TIFF_SLONG8 => {
            let m = match checked_slong8(ctx, e) {
                Ok(v) => v,
                Err(err) => return (err, 0),
            };
            let err = range_byte_slong8(m);
            if err != DirEntryErr::Ok {
                return (err, 0);
            }
            (DirEntryErr::Ok, m as u8)
        }
        _ => (DirEntryErr::Type, 0),
    }
}

/// Op-script line matching `cref/_driver_dir.c`: `E <type> <count> <offset_u64> <flags> <filehex>`
/// → `R <errcode> <value>\n.\n`. `flags` bit0=SWAB, bit1=BIGTIFF.
pub fn run_line(line: &str) -> String {
    let rest = match line.strip_prefix('E') {
        Some(r) => r.trim_start(),
        None => return String::new(),
    };
    let mut it = rest.split_whitespace();
    let ty: u16 = match it.next().and_then(|s| s.parse().ok()) {
        Some(v) => v,
        None => return String::new(),
    };
    let count: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let offset: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let flags: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let file: Vec<u8> = it
        .next()
        .map(|h| {
            h.as_bytes()
                .chunks(2)
                .filter_map(|c| {
                    if c.len() == 2 {
                        let hi = (c[0] as char).to_digit(16)?;
                        let lo = (c[1] as char).to_digit(16)?;
                        Some((hi * 16 + lo) as u8)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let e = DirEntry {
        tdir_type: ty,
        tdir_count: count,
        tdir_offset: offset.to_ne_bytes(),
    };
    let ctx = Ctx {
        swab: flags & 1 != 0,
        bigtiff: flags & 2 != 0,
        file: &file,
    };
    let (err, value) = read_dir_entry_byte(&ctx, &e);
    format!("R {} {}\n.\n", err as i32, value)
}
