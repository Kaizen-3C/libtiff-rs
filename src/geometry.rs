//! Port of libtiff 4.7.0 strip/tile **geometry counts** (Slice 5): `TIFFNumberOfStrips`
//! (tif_strip.c) and `TIFFNumberOfTiles` (tif_tile.c) over `_TIFFMultiply32` (tif_aux.c) and the
//! `TIFFhowmany_32` ceil-division macro (tiffiop.h). These counts size the strip/tile offset and
//! bytecount arrays (Slice 4) and the decode buffers, so a count that overflows silently is
//! libtiff's classic strip/tile-count integer-overflow → under-allocation → OOB CVE surface.
//! Pure arithmetic — no file I/O. `#![forbid(unsafe_code)]`.
//!
//! c2rust translation notes (see ../../../C2RUST-LEARNINGS.md):
//!  - P2d: C's guarded multiply `if (second && first > UINT32_MAX/second) return 0; return
//!    first*second;` must keep the *division-form* guard AND use `wrapping_mul` for the product —
//!    plain `*` panics on debug overflow even though the guard makes it unreachable, and the panic
//!    would be a behaviour divergence (and a DoS) the C does not have.
//!  - The `(uint32_t)-1` sentinel is `u32::MAX`; the C ternary's short-circuit matters —
//!    `TIFFNumberOfTiles` only evaluates `TIFFhowmany_32(_, dx)` when `dx != 0`, which is what
//!    keeps the division safe. Preserve the branch structure, don't flatten it.

pub const PLANARCONFIG_CONTIG: u16 = 1;
pub const PLANARCONFIG_SEPARATE: u16 = 2;

/// `TIFFhowmany_32(x, y)`: ceil(x/y), returning 0 when `x + (y-1)` would wrap (the overflow-compat
/// guard). Callers guarantee `y != 0`; the wrapping ops mirror C's unsigned arithmetic exactly.
fn howmany_32(x: u32, y: u32) -> u32 {
    if x < 0xffffffffu32.wrapping_sub(y.wrapping_sub(1)) {
        x.wrapping_add(y.wrapping_sub(1)) / y
    } else {
        0
    }
}

/// `_TIFFMultiply32`: overflow-guarded multiply; returns 0 (and upstream logs an error) on overflow.
fn multiply32(first: u32, second: u32) -> u32 {
    if second != 0 && first > u32::MAX / second {
        return 0;
    }
    first.wrapping_mul(second) // guard above makes this exact; wrapping_mul avoids a debug panic
}

/// The directory geometry fields the count functions read.
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub imagewidth: u32,
    pub imagelength: u32,
    pub imagedepth: u32,
    pub tilewidth: u32,
    pub tilelength: u32,
    pub tiledepth: u32,
    pub rowsperstrip: u32,
    pub planarconfig: u16,
    pub samplesperpixel: u16,
}

/// `TIFFNumberOfStrips`: 0 when RowsPerStrip is zero; 1 for the `(uint32_t)-1` sentinel; otherwise
/// ceil(ImageLength / RowsPerStrip), times SamplesPerPixel when the planes are separate.
pub fn number_of_strips(g: &Geometry) -> u32 {
    if g.rowsperstrip == 0 {
        return 0; // upstream warns "RowsPerStrip is zero"
    }
    let mut nstrips = if g.rowsperstrip == u32::MAX {
        1
    } else {
        howmany_32(g.imagelength, g.rowsperstrip)
    };
    if g.planarconfig == PLANARCONFIG_SEPARATE {
        nstrips = multiply32(nstrips, g.samplesperpixel as u32);
    }
    nstrips
}

/// `TIFFNumberOfTiles`: tiles-across × tiles-down × tiles-deep (each `_TIFFMultiply32`-guarded),
/// times SamplesPerPixel when the planes are separate. A zero tile dimension short-circuits to 0 —
/// which is also what keeps the `howmany_32` divisions safe.
pub fn number_of_tiles(g: &Geometry) -> u32 {
    let mut dx = g.tilewidth;
    let mut dy = g.tilelength;
    let mut dz = g.tiledepth;
    if dx == u32::MAX {
        dx = g.imagewidth;
    }
    if dy == u32::MAX {
        dy = g.imagelength;
    }
    if dz == u32::MAX {
        dz = g.imagedepth;
    }
    let mut ntiles = if dx == 0 || dy == 0 || dz == 0 {
        0
    } else {
        multiply32(
            multiply32(howmany_32(g.imagewidth, dx), howmany_32(g.imagelength, dy)),
            howmany_32(g.imagedepth, dz),
        )
    };
    if g.planarconfig == PLANARCONFIG_SEPARATE {
        ntiles = multiply32(ntiles, g.samplesperpixel as u32);
    }
    ntiles
}

fn format_geom(nstrips: u32, ntiles: u32) -> String {
    format!("G {} {}\n.\n", nstrips, ntiles)
}

/// Op-script line matching `cref/_driver_dir5.c`:
/// `G <rowsperstrip> <imagelength> <imagewidth> <imagedepth> <planarconfig> <samplesperpixel>
/// <tilewidth> <tilelength> <tiledepth>` → `G <nstrips> <ntiles>`. For certification.
pub fn run_line_geom(line: &str) -> String {
    let line = match line.find('\0') {
        Some(p) => &line[..p],
        None => line,
    };
    let b = line.as_bytes();
    if b.first() != Some(&b'G') {
        return String::new();
    }
    let mut f = [0u64; 9];
    let mut pos = 1;
    for slot in f.iter_mut() {
        match crate::dirread::scan_uint(b, &mut pos) {
            Some(v) => *slot = v,
            None => return String::new(),
        }
    }
    let g = Geometry {
        rowsperstrip: f[0] as u32,
        imagelength: f[1] as u32,
        imagewidth: f[2] as u32,
        imagedepth: f[3] as u32,
        planarconfig: f[4] as u16,
        samplesperpixel: f[5] as u16,
        tilewidth: f[6] as u32,
        tilelength: f[7] as u32,
        tiledepth: f[8] as u32,
    };
    format_geom(number_of_strips(&g), number_of_tiles(&g))
}

/// Structured fuzz entry matching `cref/_fuzzlib_driver_dir5.c`: all fields native —
/// `[0..4]`=rowsperstrip `[4..8]`=imagelength `[8..12]`=imagewidth `[12..16]`=imagedepth
/// `[16..18]`=planarconfig(u16) `[18..20]`=samplesperpixel(u16) `[20..24]`=tilewidth
/// `[24..28]`=tilelength `[28..32]`=tiledepth. `< 32` bytes → empty.
pub fn run_bytes_geom(data: &[u8]) -> String {
    if data.len() < 32 {
        return String::new();
    }
    let u32at = |o: usize| u32::from_ne_bytes(data[o..o + 4].try_into().unwrap());
    let u16at = |o: usize| u16::from_ne_bytes(data[o..o + 2].try_into().unwrap());
    let g = Geometry {
        rowsperstrip: u32at(0),
        imagelength: u32at(4),
        imagewidth: u32at(8),
        imagedepth: u32at(12),
        planarconfig: u16at(16),
        samplesperpixel: u16at(18),
        tilewidth: u32at(20),
        tilelength: u32at(24),
        tiledepth: u32at(28),
    };
    format_geom(number_of_strips(&g), number_of_tiles(&g))
}
