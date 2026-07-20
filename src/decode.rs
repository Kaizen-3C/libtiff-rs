//! Minimal **end-to-end** TIFF decode (Slice 6): a real TIFF file's bytes → decoded pixel data,
//! entirely in `#![forbid(unsafe_code)]` Rust, wiring together the already-certified pieces:
//!   header parse → [`dirread::fetch_directory`] (IFD structure, Slice 2)
//!   → tag values via [`dirread::read_dir_entry_long8_array_with_limit`] (Slice 4, uniform for
//!     scalars *and* the StripOffsets/StripByteCounts arrays)
//!   → strip geometry ([`geometry`], Slice 5) → per-strip codec dispatch to the certified
//!     PackBits / LZW / uncompressed decoders → assembled pixel buffer.
//!
//! Scope (the *minimal* end-to-end that proves the pipeline against real libtiff): classic TIFF,
//! little- or big-endian, single-plane (PlanarConfig=1), 8-bit samples, Compression NONE / PackBits
//! / LZW, single- or multi-strip. Certified byte-identical to `libtiff.a`'s `TIFFReadEncodedStrip`
//! output over a generated envelope (see `cref/_e2e_ref.c`). Deliberately not yet: tiles, BigTIFF,
//! predictors, sub-8-bit / >8-bit samples, planar-separate — those are the funded M2/M3 breadth.

use crate::dirread::{self, Ctx};
use crate::geometry::{self, Geometry};

// TIFF tag numbers we read for a minimal grayscale decode.
const TAG_IMAGEWIDTH: u16 = 256;
const TAG_IMAGELENGTH: u16 = 257;
const TAG_BITSPERSAMPLE: u16 = 258;
const TAG_COMPRESSION: u16 = 259;
const TAG_STRIPOFFSETS: u16 = 273;
const TAG_SAMPLESPERPIXEL: u16 = 277;
const TAG_ROWSPERSTRIP: u16 = 278;
const TAG_STRIPBYTECOUNTS: u16 = 279;
const TAG_PLANARCONFIG: u16 = 284;

const COMPRESSION_NONE: u64 = 1;
const COMPRESSION_LZW: u64 = 5;
const COMPRESSION_PACKBITS: u64 = 32773;

/// The decoded image: raw sample bytes exactly as `TIFFReadEncodedStrip` concatenates them,
/// plus the geometry needed to interpret them.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedImage {
    pub width: u32,
    pub length: u32,
    pub samples_per_pixel: u16,
    pub bits_per_sample: u16,
    pub compression: u64,
    pub pixels: Vec<u8>,
}

/// Why a file was declined. The decoder never panics or reads out of bounds on adversarial input;
/// it returns one of these instead.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeErr {
    BadHeader,
    NoDirectory,
    MissingTag(u16),
    Unsupported(&'static str),
    BadStrip,
}

/// Read one integer-valued tag as a `Vec<u64>` (scalars come back length-1), reusing the Slice 4
/// value-array reader so type promotion + byte-swap + the size-sanity / overflow guards all apply.
fn read_tag_values(ctx: &Ctx, entries: &[(u16, u16, u64, u64)], tag: u16) -> Option<Vec<u64>> {
    let &(_, ty, count, offset) = entries.iter().find(|e| e.0 == tag)?;
    let toffset = offset.to_ne_bytes(); // classic: raw offset in the low 4 bytes, matching the union
    let (err, vals) =
        dirread::read_dir_entry_long8_array_with_limit(ctx, ty, count, &toffset, u64::MAX);
    if err != dirread::DirEntryErr::Ok {
        return None;
    }
    Some(vals.unwrap_or_default())
}

fn scalar(ctx: &Ctx, entries: &[(u16, u16, u64, u64)], tag: u16) -> Option<u64> {
    read_tag_values(ctx, entries, tag)?.first().copied()
}

/// Decode a TIFF file to pixels. `file` is the whole file image (as `libtiff` sees it mapped).
pub fn decode_tiff(file: &[u8]) -> Result<DecodedImage, DecodeErr> {
    if file.len() < 8 {
        return Err(DecodeErr::BadHeader);
    }
    // --- header: byte order + magic + first-IFD offset ---
    let file_is_le = match &file[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return Err(DecodeErr::BadHeader),
    };
    let host_is_le = cfg!(target_endian = "little");
    let swab = file_is_le != host_is_le;
    let rd16 = |o: usize| {
        let mut v = u16::from_ne_bytes([file[o], file[o + 1]]);
        if swab {
            v = v.swap_bytes();
        }
        v
    };
    let rd32 = |o: usize| {
        let mut v = u32::from_ne_bytes(file[o..o + 4].try_into().unwrap());
        if swab {
            v = v.swap_bytes();
        }
        v
    };
    let magic = rd16(2);
    if magic != 42 {
        // 43 = BigTIFF, deliberately out of the minimal scope.
        return Err(DecodeErr::Unsupported("only classic TIFF (magic 42)"));
    }
    let diroff = rd32(4) as u64;

    // --- IFD structure (Slice 2) ---
    let (_, _, entries) =
        dirread::fetch_directory(swab, false, file, diroff).ok_or(DecodeErr::NoDirectory)?;

    let ctx = Ctx {
        swab,
        bigtiff: false,
        file,
    };

    // --- required geometry / codec tags ---
    let width =
        scalar(&ctx, &entries, TAG_IMAGEWIDTH).ok_or(DecodeErr::MissingTag(TAG_IMAGEWIDTH))? as u32;
    let length = scalar(&ctx, &entries, TAG_IMAGELENGTH)
        .ok_or(DecodeErr::MissingTag(TAG_IMAGELENGTH))? as u32;
    // Per the TIFF spec these default to 1 when absent.
    let spp = scalar(&ctx, &entries, TAG_SAMPLESPERPIXEL).unwrap_or(1) as u16;
    let bps = scalar(&ctx, &entries, TAG_BITSPERSAMPLE).unwrap_or(1) as u16;
    let compression = scalar(&ctx, &entries, TAG_COMPRESSION).unwrap_or(COMPRESSION_NONE);
    let planar = scalar(&ctx, &entries, TAG_PLANARCONFIG).unwrap_or(1) as u16;
    // RowsPerStrip defaults to "all rows in one strip" (2^32-1) when absent.
    let rows_per_strip = scalar(&ctx, &entries, TAG_ROWSPERSTRIP).unwrap_or(0xffff_ffff) as u32;

    if bps != 8 {
        return Err(DecodeErr::Unsupported(
            "only 8-bit samples in the minimal decoder",
        ));
    }
    if planar != geometry::PLANARCONFIG_CONTIG {
        return Err(DecodeErr::Unsupported("only PlanarConfig=1 (contig)"));
    }
    if !matches!(
        compression,
        COMPRESSION_NONE | COMPRESSION_PACKBITS | COMPRESSION_LZW
    ) {
        return Err(DecodeErr::Unsupported(
            "compression not in {none, packbits, lzw}",
        ));
    }

    let strip_offsets = read_tag_values(&ctx, &entries, TAG_STRIPOFFSETS)
        .ok_or(DecodeErr::MissingTag(TAG_STRIPOFFSETS))?;
    let strip_bytecounts = read_tag_values(&ctx, &entries, TAG_STRIPBYTECOUNTS)
        .ok_or(DecodeErr::MissingTag(TAG_STRIPBYTECOUNTS))?;

    // Strip count from the certified geometry (Slice 5) — must agree with the array lengths.
    let geom = Geometry {
        imagewidth: width,
        imagelength: length,
        imagedepth: 1,
        tilewidth: 0,
        tilelength: 0,
        tiledepth: 0,
        rowsperstrip: rows_per_strip,
        planarconfig: planar,
        samplesperpixel: spp,
    };
    let nstrips = geometry::number_of_strips(&geom) as usize;
    if nstrips == 0 || strip_offsets.len() < nstrips || strip_bytecounts.len() < nstrips {
        return Err(DecodeErr::BadStrip);
    }

    // scanline byte width for 8-bit contig samples
    let scanline = (width as usize)
        .checked_mul(spp as usize)
        .ok_or(DecodeErr::BadStrip)?;
    let effective_rps = if rows_per_strip == 0xffff_ffff {
        length
    } else {
        rows_per_strip
    };

    let mut pixels = Vec::with_capacity((length as usize).saturating_mul(scanline));
    for s in 0..nstrips {
        let off = strip_offsets[s] as usize;
        let len = strip_bytecounts[s] as usize;
        let end = off.checked_add(len).ok_or(DecodeErr::BadStrip)?;
        if end > file.len() {
            return Err(DecodeErr::BadStrip);
        }
        let raw = &file[off..end];

        // rows in this strip (the last strip may be short) → expected decoded byte count
        let rows_done = (s as u32) * effective_rps;
        let rows_here = effective_rps.min(length.saturating_sub(rows_done));
        let expected = (rows_here as usize) * scanline;

        match compression {
            COMPRESSION_NONE => {
                if raw.len() < expected {
                    return Err(DecodeErr::BadStrip);
                }
                pixels.extend_from_slice(&raw[..expected]);
            }
            COMPRESSION_PACKBITS => {
                let mut buf = vec![0u8; expected];
                let (_rc, _cc) = crate::rle::packbits_decode(raw, &mut buf);
                pixels.extend_from_slice(&buf);
            }
            COMPRESSION_LZW => {
                let (_rc, out, _consumed) = crate::lzw::lzw_decode(raw, expected);
                if out.len() < expected {
                    return Err(DecodeErr::BadStrip);
                }
                pixels.extend_from_slice(&out[..expected]);
            }
            _ => unreachable!(),
        }
    }

    Ok(DecodedImage {
        width,
        length,
        samples_per_pixel: spp,
        bits_per_sample: bps,
        compression,
        pixels,
    })
}

/// Line-oriented differential format matching `cref/_e2e_ref.c`:
/// `E <width> <length> <spp> <bps> <compression> <npixels> <hex pixels>` on success, or `E ERR` on
/// any decline. One TIFF file per invocation (fed as raw bytes on stdin by the driver binary).
pub fn format_decode(res: Result<DecodedImage, DecodeErr>) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    match res {
        Ok(img) => {
            write!(
                out,
                "E {} {} {} {} {} {} ",
                img.width,
                img.length,
                img.samples_per_pixel,
                img.bits_per_sample,
                img.compression,
                img.pixels.len()
            )
            .unwrap();
            for b in &img.pixels {
                write!(out, "{:02x}", b).unwrap();
            }
            out.push('\n');
        }
        Err(_) => out.push_str("E ERR\n"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built minimal classic little-endian uncompressed 2×2 8-bit grayscale TIFF, so the
    /// end-to-end path (header → IFD → tags → strip → pixels) has a `cargo test` check that needs no
    /// C toolchain. The full byte-for-byte-vs-libtiff certification is `scripts/e2e_certify.sh`.
    fn tiny_le_uncompressed() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(b"II"); // little-endian
        f.extend_from_slice(&42u16.to_le_bytes()); // classic magic
        f.extend_from_slice(&12u32.to_le_bytes()); // first IFD at offset 12
                                                   // pixel data at offset 8 (4 bytes): a 2×2 image
        f.extend_from_slice(&[10, 20, 30, 40]);
        // IFD at offset 12
        let mut ifd = Vec::new();
        ifd.extend_from_slice(&5u16.to_le_bytes()); // 5 entries
        let mut entry = |tag: u16, ty: u16, val: u32| {
            ifd.extend_from_slice(&tag.to_le_bytes());
            ifd.extend_from_slice(&ty.to_le_bytes());
            ifd.extend_from_slice(&1u32.to_le_bytes()); // count = 1
            ifd.extend_from_slice(&val.to_le_bytes());
        };
        entry(TAG_IMAGEWIDTH, 3, 2); // SHORT
        entry(TAG_IMAGELENGTH, 3, 2);
        entry(TAG_BITSPERSAMPLE, 3, 8);
        entry(TAG_STRIPOFFSETS, 4, 8); // LONG, pixels at offset 8
        entry(TAG_STRIPBYTECOUNTS, 4, 4);
        ifd.extend_from_slice(&0u32.to_le_bytes()); // no next IFD
        f.extend_from_slice(&ifd);
        f
    }

    #[test]
    fn decodes_minimal_uncompressed() {
        let img = decode_tiff(&tiny_le_uncompressed()).expect("decode");
        assert_eq!(img.width, 2);
        assert_eq!(img.length, 2);
        assert_eq!(img.samples_per_pixel, 1);
        assert_eq!(img.bits_per_sample, 8);
        assert_eq!(img.compression, COMPRESSION_NONE);
        assert_eq!(img.pixels, vec![10, 20, 30, 40]);
    }

    #[test]
    fn declines_garbage_without_panicking() {
        assert!(matches!(
            decode_tiff(b"not a tiff"),
            Err(DecodeErr::BadHeader)
        ));
        assert!(matches!(decode_tiff(&[]), Err(DecodeErr::BadHeader)));
        // valid header, truncated body → declined, never a panic/OOB
        let mut t = tiny_le_uncompressed();
        t.truncate(20);
        let _ = decode_tiff(&t); // must not panic
    }
}
