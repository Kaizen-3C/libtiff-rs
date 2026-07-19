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

/// Structured fuzz entry — matches `cref/_fuzzlib_driver_dir.c` byte-for-byte so the differential
/// exercises only the `TIFFReadDirEntryByte` LOGIC (no text-parsing mismatch). Layout:
/// `[0..2]`=type(u16 LE) `[2..10]`=count(u64 native) `[10..18]`=tdir_offset(raw 8) `[18]`=flags
/// (bit0 SWAB, bit1 BIGTIFF) `[19..]`=file. `< 19` bytes → empty.
pub fn run_bytes(data: &[u8]) -> String {
    if data.len() < 19 {
        return String::new();
    }
    let ty = u16::from_le_bytes([data[0], data[1]]); // C: in[0] | (in[1] << 8)
    let count = u64::from_ne_bytes(data[2..10].try_into().unwrap()); // C: memcpy (host order)
    let mut off = [0u8; 8];
    off.copy_from_slice(&data[10..18]); // raw offset/value union bytes
    let flags = data[18];
    let e = DirEntry {
        tdir_type: ty,
        tdir_count: count,
        tdir_offset: off,
    };
    let ctx = Ctx {
        swab: flags & 1 != 0,
        bigtiff: flags & 2 != 0,
        file: &data[19..],
    };
    let (err, value) = read_dir_entry_byte(&ctx, &e);
    format!("R {} {}\n.\n", err as i32, value)
}

/// A `sscanf`-compatible unsigned scan: skip leading whitespace, then a run of decimal digits,
/// stopping at the first non-digit; `None` if no digit. Wraps on overflow (like the C `%u`/`%llu`
/// store). This mirrors the C fuzz driver's `sscanf`, so the differential exercises the ported
/// TIFFReadDirEntryByte LOGIC — not an op-script-parsing mismatch between the two drivers.
fn scan_uint(b: &[u8], pos: &mut usize) -> Option<u64> {
    while *pos < b.len() && b[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
    // sscanf `%u`/`%llu` accept an optional sign (via strtoul); a `-` value wraps into the unsigned.
    let neg = if *pos < b.len() && (b[*pos] == b'+' || b[*pos] == b'-') {
        let n = b[*pos] == b'-';
        *pos += 1;
        n
    } else {
        false
    };
    let mut val: u64 = 0;
    let mut any = false;
    while *pos < b.len() && b[*pos].is_ascii_digit() {
        any = true;
        val = val.wrapping_mul(10).wrapping_add((b[*pos] - b'0') as u64);
        *pos += 1;
    }
    if any {
        Some(if neg { val.wrapping_neg() } else { val })
    } else {
        None
    }
}

/// Op-script line matching `cref/_driver_dir.c` / `_fuzzlib_driver_dir.c`'s
/// `sscanf(line, "E %u %llu %llu %u %n", ...)` >= 4 gate:
/// `E <type> <count> <offset_u64> <flags> <filehex>` → `R <errcode> <value>\n.\n`, else empty.
/// `flags` bit0=SWAB, bit1=BIGTIFF. `%u` stores into `unsigned` (32-bit) for type/flags.
pub fn run_line(line: &str) -> String {
    // C's `sscanf` runs over a NUL-terminated copy: an embedded 0x00 ends the string there. Truncate
    // up front so both drivers parse identical content.
    let line = match line.find('\0') {
        Some(p) => &line[..p],
        None => line,
    };
    let b = line.as_bytes();
    // the format's literal `E` must match the first input byte exactly (sscanf doesn't skip ws before
    // a literal); a missing field means < 4 conversions -> the C driver emits nothing.
    if b.first() != Some(&b'E') {
        return String::new();
    }
    let mut pos = 1;
    let ty32 = match scan_uint(b, &mut pos) {
        Some(v) => v as u32,
        None => return String::new(),
    };
    let count = match scan_uint(b, &mut pos) {
        Some(v) => v,
        None => return String::new(),
    };
    let offset = match scan_uint(b, &mut pos) {
        Some(v) => v,
        None => return String::new(),
    };
    let flags = match scan_uint(b, &mut pos) {
        Some(v) => v as u32,
        None => return String::new(),
    };
    // filehex starts after the whitespace following `flags` (the format's `%u %n`)
    while pos < b.len() && b[pos].is_ascii_whitespace() {
        pos += 1;
    }
    let file: Vec<u8> = b[pos..]
        .chunks(2)
        .map_while(|c| {
            if c.len() == 2 {
                let hi = (c[0] as char).to_digit(16)?;
                let lo = (c[1] as char).to_digit(16)?;
                Some((hi * 16 + lo) as u8)
            } else {
                None
            }
        })
        .collect();

    let e = DirEntry {
        tdir_type: ty32 as u16,
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

// ============================ Slice 2: TIFFFetchDirectory ============================

/// Port of libtiff `TIFFFetchDirectory` (mapped path): parse the IFD directory STRUCTURE at `diroff`
/// — entry count (u16 classic / u64 BigTIFF), the entries array (with the `m = off+size` overflow /
/// tif_size bounds guards), and the next-IFD offset. Returns `(dircount, nextdiroff, entries)` where
/// each entry is `(tag, type, count, offset)`; `None` on any guard failure (C returns 0). Byte-offset
/// reads (P1) — no pointer casts; overflow guards preserved verbatim (P2). The directory-structure
/// integer-overflow / OOB CVE surface.
/// `(dircount, nextdiroff, entries)` where each entry is `(tag, type, count, offset)`.
pub type FetchResult = Option<(u16, u64, Vec<(u16, u16, u64, u64)>)>;

pub fn fetch_directory(swab: bool, bigtiff: bool, file: &[u8], diroff: u64) -> FetchResult {
    let tif_size: i64 = file.len() as i64;
    if diroff > i64::MAX as u64 {
        return None;
    }
    let mut off: i64 = diroff as i64;

    let dircount16: u16;
    let dirsize: i64;
    if !bigtiff {
        let m = off.wrapping_add(2);
        if m < off || m < 2 || m > tif_size {
            return None;
        }
        let mut dc = u16::from_ne_bytes([file[off as usize], file[off as usize + 1]]);
        off += 2;
        if swab {
            dc = dc.swap_bytes();
        }
        if dc > 4096 {
            return None;
        }
        dircount16 = dc;
        dirsize = 12;
    } else {
        let m = off.wrapping_add(8);
        if m < off || m < 8 || m > tif_size {
            return None;
        }
        let mut dc = u64::from_ne_bytes(file[off as usize..off as usize + 8].try_into().unwrap());
        off += 8;
        if swab {
            dc = dc.swap_bytes();
        }
        if dc > 4096 {
            return None;
        }
        dircount16 = dc as u16;
        dirsize = 20;
    }
    if dircount16 == 0 {
        return None;
    }
    // before "allocating" (we read into a Vec), reject if the entries can't fit the file
    if (dircount16 as u64) * (dirsize as u64) > file.len() as u64 {
        return None;
    }
    let entries_bytes = dircount16 as i64 * dirsize;
    let m = off.wrapping_add(entries_bytes);
    if m < off || m < entries_bytes || m > tif_size {
        return None;
    }
    let entries_start = off as usize;
    off += entries_bytes;

    // next-IFD offset (0 if it doesn't fit — matches the C's non-fatal branch)
    let mut nextdiroff: u64 = 0;
    if !bigtiff {
        let m = off.wrapping_add(4);
        if !(m < off || m < 4 || m > tif_size) {
            let mut nd =
                u32::from_ne_bytes(file[off as usize..off as usize + 4].try_into().unwrap());
            if swab {
                nd = nd.swap_bytes();
            }
            nextdiroff = nd as u64;
        }
    } else {
        let m = off.wrapping_add(8);
        if !(m < off || m < 8 || m > tif_size) {
            let mut nd =
                u64::from_ne_bytes(file[off as usize..off as usize + 8].try_into().unwrap());
            if swab {
                nd = nd.swap_bytes();
            }
            nextdiroff = nd;
        }
    }

    // unpack each raw 12/20-byte entry (tag/type/count swab; offset left raw — the entry readers
    // swab it later)
    let mut entries = Vec::with_capacity(dircount16 as usize);
    let mut ma = entries_start;
    for _ in 0..dircount16 {
        let mut tag = u16::from_ne_bytes([file[ma], file[ma + 1]]);
        if swab {
            tag = tag.swap_bytes();
        }
        ma += 2;
        let mut ty = u16::from_ne_bytes([file[ma], file[ma + 1]]);
        if swab {
            ty = ty.swap_bytes();
        }
        ma += 2;
        let (count, offset);
        if !bigtiff {
            let mut c = u32::from_ne_bytes(file[ma..ma + 4].try_into().unwrap());
            if swab {
                c = c.swap_bytes();
            }
            ma += 4;
            count = c as u64;
            // tdir_offset: toff_long8 = 0, low 4 bytes = the raw offset u32 (NOT swabbed here)
            let o = u32::from_ne_bytes(file[ma..ma + 4].try_into().unwrap());
            ma += 4;
            offset = o as u64;
        } else {
            let mut c = u64::from_ne_bytes(file[ma..ma + 8].try_into().unwrap());
            if swab {
                c = c.swap_bytes();
            }
            ma += 8;
            count = c;
            // TIFFReadUInt64 (host order, NOT swabbed here)
            let o = u64::from_ne_bytes(file[ma..ma + 8].try_into().unwrap());
            ma += 8;
            offset = o;
        }
        entries.push((tag, ty, count, offset));
    }
    Some((dircount16, nextdiroff, entries))
}

fn format_fetch(res: FetchResult) -> String {
    let mut out = String::new();
    match res {
        Some((dircount, nextdiroff, entries)) => {
            use std::fmt::Write as _;
            writeln!(out, "D {} {}", dircount, nextdiroff).unwrap();
            for (tag, ty, count, offset) in entries {
                writeln!(out, "e {} {} {} {}", tag, ty, count, offset).unwrap();
            }
        }
        None => out.push_str("D 0 0\n"),
    }
    out.push_str(".\n");
    out
}

/// Op-script line matching `cref/_driver_dir2.c`'s `sscanf(line, "F %llu %u %n", ...)`:
/// `F <diroff> <flags> <filehex>` → the parsed directory. For certification.
pub fn run_line_fetch(line: &str) -> String {
    let line = match line.find('\0') {
        Some(p) => &line[..p],
        None => line,
    };
    let b = line.as_bytes();
    if b.first() != Some(&b'F') {
        return String::new();
    }
    let mut pos = 1;
    let diroff = match scan_uint(b, &mut pos) {
        Some(v) => v,
        None => return String::new(),
    };
    let flags = match scan_uint(b, &mut pos) {
        Some(v) => v as u32,
        None => return String::new(),
    };
    while pos < b.len() && b[pos].is_ascii_whitespace() {
        pos += 1;
    }
    let file: Vec<u8> = b[pos..]
        .chunks(2)
        .map_while(|c| {
            if c.len() == 2 {
                Some(((c[0] as char).to_digit(16)? * 16 + (c[1] as char).to_digit(16)?) as u8)
            } else {
                None
            }
        })
        .collect();
    format_fetch(fetch_directory(
        flags & 1 != 0,
        flags & 2 != 0,
        &file,
        diroff,
    ))
}

/// Structured fuzz entry matching `cref/_fuzzlib_driver_dir2.c`:
/// `[0..8]`=diroff(u64 native) `[8]`=flags(bit0 SWAB, bit1 BIGTIFF) `[9..]`=file. `< 9` bytes → empty.
pub fn run_bytes_fetch(data: &[u8]) -> String {
    if data.len() < 9 {
        return String::new();
    }
    let diroff = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let flags = data[8];
    format_fetch(fetch_directory(
        flags & 1 != 0,
        flags & 2 != 0,
        &data[9..],
        diroff,
    ))
}

// ============================================================================
// Slice 3 — value-array fetch (the core of TIFFFetchNormalTag's field read):
// TIFFReadDirEntryByteArray -> TIFFReadDirEntryArray -> TIFFReadDirEntryArrayWithLimit.
// The count x typesize MULTIPLY-OVERFLOW / MAX_SIZE_TAG_DATA (2GB) size-sanity /
// allocation-bounds / classic-vs-BigTIFF inline-or-offset read / per-element range-checked
// type-conversion. libtiff's tag-array integer-overflow -> under-allocation -> OOB CVE surface.
// Byte-offset reads (P1); overflow/size guards preserved verbatim (P2/P5). #![forbid(unsafe_code)].
// ============================================================================

const TIFF_ASCII: u16 = 2;
const TIFF_RATIONAL: u16 = 5;
const TIFF_SRATIONAL: u16 = 10;
const TIFF_FLOAT: u16 = 11;
const TIFF_DOUBLE: u16 = 12;
const TIFF_IFD: u16 = 13;
const TIFF_IFD8: u16 = 18;
const MAX_SIZE_TAG_DATA: u32 = 2147483647; // 2GB-1 — the tag-array size sanity ceiling

/// `TIFFDataWidth`: byte width per field type; 0 for unknown (verbatim table).
fn data_width(t: u16) -> i32 {
    match t {
        0 | TIFF_BYTE | TIFF_ASCII | TIFF_SBYTE | TIFF_UNDEFINED => 1,
        TIFF_SHORT | TIFF_SSHORT => 2,
        TIFF_LONG | TIFF_SLONG | TIFF_FLOAT | TIFF_IFD => 4,
        TIFF_RATIONAL | TIFF_SRATIONAL | TIFF_DOUBLE | TIFF_LONG8 | TIFF_SLONG8 | TIFF_IFD8 => 8,
        _ => 0,
    }
}

/// `TIFFReadDirEntryArrayWithLimit`: fetch the raw value array. Returns `(err, count, Some(bytes))`
/// where `bytes.len() == count * typesize`, or `(Ok, 0, None)` when the tag holds no data
/// (`*value = 0` in C). `toffset` = the entry's raw 8-byte offset/value field (host order).
fn read_dir_entry_array_with_limit(
    ctx: &Ctx,
    ttype: u16,
    tcount: u64,
    toffset: &[u8; 8],
    desttypesize: u32,
    maxcount: u64,
) -> (DirEntryErr, u32, Option<Vec<u8>>) {
    let typesize = data_width(ttype);
    let target_count64 = if tcount > maxcount { maxcount } else { tcount };
    if target_count64 == 0 || typesize == 0 {
        return (DirEntryErr::Ok, 0, None); // *value = 0
    }
    // Only whether the original tag size exceeds 4 (classic) / 8 (BigTIFF) bytes matters here.
    let original_datasize_clamped = (if tcount > 10 { 10 } else { tcount as i32 }) * typesize;

    // 2GB size sanity in BOTH the source and dest data type — this is the multiply-overflow guard.
    if (MAX_SIZE_TAG_DATA as u64 / typesize as u64) < target_count64 {
        return (DirEntryErr::Sizesan, 0, None);
    }
    if (MAX_SIZE_TAG_DATA as u64 / desttypesize as u64) < target_count64 {
        return (DirEntryErr::Sizesan, 0, None);
    }

    let count = target_count64 as u32;
    let datasize = count * (typesize as u32); // <= MAX_SIZE_TAG_DATA by the sanity checks; no overflow
    debug_assert!(datasize > 0);

    if datasize > 100 * 1024 * 1024 {
        // Before allocating a huge buffer for a corrupt file, require it to fit within the file.
        let filesize = ctx.file.len() as u64;
        if datasize as u64 > filesize {
            return (DirEntryErr::Alloc, 0, None);
        }
    }

    // isMapped(tif) is always true (memory buffer): the value bytes must lie within the file.
    if datasize as u64 > ctx.file.len() as u64 {
        return (DirEntryErr::Io, 0, None);
    }

    let mut data = vec![0u8; datasize as usize]; // isMapped -> always allocate
    if !ctx.bigtiff {
        if original_datasize_clamped <= 4 && datasize <= 4 {
            data.copy_from_slice(&toffset[..datasize as usize]);
        } else {
            let mut offset = u32::from_ne_bytes(toffset[0..4].try_into().unwrap());
            if ctx.swab {
                offset = offset.swap_bytes();
            }
            let err = read_dir_entry_data(ctx, offset as u64, datasize as usize, &mut data);
            if err != DirEntryErr::Ok {
                return (err, 0, None);
            }
        }
    } else if original_datasize_clamped <= 8 && datasize <= 8 {
        data.copy_from_slice(&toffset[..datasize as usize]);
    } else {
        let mut offset = u64::from_ne_bytes(*toffset);
        if ctx.swab {
            offset = offset.swap_bytes();
        }
        let err = read_dir_entry_data(ctx, offset, datasize as usize, &mut data);
        if err != DirEntryErr::Ok {
            return (err, 0, None);
        }
    }
    (DirEntryErr::Ok, count, Some(data))
}

fn read_dir_entry_array(
    ctx: &Ctx,
    ttype: u16,
    tcount: u64,
    toffset: &[u8; 8],
    desttypesize: u32,
) -> (DirEntryErr, u32, Option<Vec<u8>>) {
    read_dir_entry_array_with_limit(ctx, ttype, tcount, toffset, desttypesize, u64::MAX)
}

/// One source element (`chunk`, `typesize` bytes, host order) -> validated low byte, mirroring the
/// swab-then-range-check-then-truncate order of `TIFFReadDirEntryByteArray`'s conversion loops.
fn convert_byte_elem(swab: bool, ttype: u16, chunk: &[u8]) -> (DirEntryErr, u8) {
    match ttype {
        TIFF_SHORT => {
            let mut v = u16::from_ne_bytes([chunk[0], chunk[1]]);
            if swab {
                v = v.swap_bytes();
            }
            (range_byte_short(v), v as u8)
        }
        TIFF_SSHORT => {
            let mut r = u16::from_ne_bytes([chunk[0], chunk[1]]);
            if swab {
                r = r.swap_bytes();
            }
            let v = r as i16;
            (range_byte_sshort(v), v as u8)
        }
        TIFF_LONG => {
            let mut v = u32::from_ne_bytes(chunk[0..4].try_into().unwrap());
            if swab {
                v = v.swap_bytes();
            }
            (range_byte_long(v), v as u8)
        }
        TIFF_SLONG => {
            let mut r = u32::from_ne_bytes(chunk[0..4].try_into().unwrap());
            if swab {
                r = r.swap_bytes();
            }
            let v = r as i32;
            (range_byte_slong(v), v as u8)
        }
        TIFF_LONG8 => {
            let mut v = u64::from_ne_bytes(chunk[0..8].try_into().unwrap());
            if swab {
                v = v.swap_bytes();
            }
            (range_byte_long8(v), v as u8)
        }
        TIFF_SLONG8 => {
            let mut r = u64::from_ne_bytes(chunk[0..8].try_into().unwrap());
            if swab {
                r = r.swap_bytes();
            }
            let v = r as i64;
            (range_byte_slong8(v), v as u8)
        }
        _ => (DirEntryErr::Type, 0), // unreachable given the caller's type gate
    }
}

/// `TIFFReadDirEntryByteArray`: fetch the value array and coerce every element to a byte, with the
/// per-type range validation. Returns `(err, Some(bytes))` on success (`bytes.len() == count`), or
/// `(err, None)` on failure / no data (`*value = 0`).
pub fn read_dir_entry_byte_array(
    ctx: &Ctx,
    ttype: u16,
    tcount: u64,
    toffset: &[u8; 8],
) -> (DirEntryErr, Option<Vec<u8>>) {
    match ttype {
        TIFF_ASCII | TIFF_UNDEFINED | TIFF_BYTE | TIFF_SBYTE | TIFF_SHORT | TIFF_SSHORT
        | TIFF_LONG | TIFF_SLONG | TIFF_LONG8 | TIFF_SLONG8 => {}
        _ => return (DirEntryErr::Type, None),
    }
    let (err, count, origdata) = read_dir_entry_array(ctx, ttype, tcount, toffset, 1);
    let origdata = match origdata {
        Some(d) if err == DirEntryErr::Ok => d,
        _ => return (err, None), // (err != Ok) || origdata == 0  ->  *value = 0
    };
    match ttype {
        TIFF_ASCII | TIFF_UNDEFINED | TIFF_BYTE => (DirEntryErr::Ok, Some(origdata)),
        TIFF_SBYTE => {
            // Validate each byte as int8; the bytes are returned unchanged.
            for &b in origdata.iter().take(count as usize) {
                let e = range_byte_sbyte(b as i8);
                if e != DirEntryErr::Ok {
                    return (e, None);
                }
            }
            (DirEntryErr::Ok, Some(origdata))
        }
        _ => {
            let typesize = data_width(ttype) as usize;
            let mut data = vec![0u8; count as usize];
            for n in 0..count as usize {
                let base = n * typesize;
                let (e, byte) =
                    convert_byte_elem(ctx.swab, ttype, &origdata[base..base + typesize]);
                if e != DirEntryErr::Ok {
                    return (e, None); // C breaks the loop, frees both buffers, returns err
                }
                data[n] = byte;
            }
            (DirEntryErr::Ok, Some(data))
        }
    }
}

fn format_arr(res: (DirEntryErr, Option<Vec<u8>>)) -> String {
    use std::fmt::Write as _;
    let (err, val) = res;
    let mut out = String::new();
    match val {
        Some(v) if err == DirEntryErr::Ok => {
            write!(out, "A 0 {} ", v.len()).unwrap();
            for b in &v {
                write!(out, "{:02x}", b).unwrap();
            }
            out.push('\n');
        }
        _ => {
            writeln!(out, "A {} 0 ", err as i32).unwrap();
        }
    }
    out.push_str(".\n");
    out
}

/// Op-script line matching `cref/_driver_dir3.c`:
/// `A <flags> <type> <count> <offsethex16> <filehex>` → the fetched byte array. For certification.
pub fn run_line_arr(line: &str) -> String {
    let line = match line.find('\0') {
        Some(p) => &line[..p],
        None => line,
    };
    let b = line.as_bytes();
    if b.first() != Some(&b'A') {
        return String::new();
    }
    let mut pos = 1;
    let flags = match scan_uint(b, &mut pos) {
        Some(v) => v as u32,
        None => return String::new(),
    };
    let ttype = match scan_uint(b, &mut pos) {
        Some(v) => v as u16,
        None => return String::new(),
    };
    let tcount = match scan_uint(b, &mut pos) {
        Some(v) => v,
        None => return String::new(),
    };
    while pos < b.len() && b[pos].is_ascii_whitespace() {
        pos += 1;
    }
    // exactly 16 hex chars = 8 raw offset bytes (as the union holds them)
    if pos + 16 > b.len() {
        return String::new();
    }
    let mut toffset = [0u8; 8];
    for (i, slot) in toffset.iter_mut().enumerate() {
        let hi = (b[pos + i * 2] as char).to_digit(16);
        let lo = (b[pos + i * 2 + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => *slot = (h * 16 + l) as u8,
            _ => return String::new(),
        }
    }
    pos += 16;
    while pos < b.len() && b[pos].is_ascii_whitespace() {
        pos += 1;
    }
    let file: Vec<u8> = b[pos..]
        .chunks(2)
        .map_while(|c| {
            if c.len() == 2 {
                Some(((c[0] as char).to_digit(16)? * 16 + (c[1] as char).to_digit(16)?) as u8)
            } else {
                None
            }
        })
        .collect();
    let ctx = Ctx {
        swab: flags & 1 != 0,
        bigtiff: flags & 2 != 0,
        file: &file,
    };
    format_arr(read_dir_entry_byte_array(&ctx, ttype, tcount, &toffset))
}

/// Structured fuzz entry matching `cref/_fuzzlib_driver_dir3.c`:
/// `[0]`=flags(bit0 SWAB, bit1 BIGTIFF) `[1..3]`=type(u16 native) `[3..11]`=count(u64 native)
/// `[11..19]`=offset(8 raw bytes) `[19..]`=file. `< 19` bytes → empty.
pub fn run_bytes_arr(data: &[u8]) -> String {
    if data.len() < 19 {
        return String::new();
    }
    let flags = data[0];
    let ttype = u16::from_ne_bytes([data[1], data[2]]);
    let tcount = u64::from_ne_bytes(data[3..11].try_into().unwrap());
    let toffset: [u8; 8] = data[11..19].try_into().unwrap();
    let ctx = Ctx {
        swab: flags & 1 != 0,
        bigtiff: flags & 2 != 0,
        file: &data[19..],
    };
    format_arr(read_dir_entry_byte_array(&ctx, ttype, tcount, &toffset))
}
