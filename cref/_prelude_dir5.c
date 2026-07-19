/* Self-contained port target: libtiff 4.7.0 strip/tile GEOMETRY (Slice 5) — TIFFNumberOfStrips +
   TIFFNumberOfTiles over the _TIFFMultiply32 overflow-guarded multiply and the TIFFhowmany_32
   ceil-division macro. This is libtiff's classic strip/tile-COUNT integer-overflow surface (the
   counts that later size strip/tile offset+bytecount arrays and decode buffers). Pure arithmetic
   over the directory geometry fields — no file I/O.

   Structured fuzz/driver input (both C and Rust interpret identically), all fields native:
     [0..4]=rowsperstrip(u32) [4..8]=imagelength(u32) [8..12]=imagewidth(u32)
     [12..16]=imagedepth(u32) [16..18]=planarconfig(u16) [18..20]=samplesperpixel(u16)
     [20..24]=tilewidth(u32) [24..28]=tilelength(u32) [28..32]=tiledepth(u32)
   Output:  G <nstrips> <ntiles>\n  then . */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#define PLANARCONFIG_CONTIG 1
#define PLANARCONFIG_SEPARATE 2

/* Ceil division with the overflow-compat guard (verbatim from tiffiop.h). */
#define TIFFhowmany_32(x, y)                                                                        \
    (((uint32_t)x < (0xffffffff - (uint32_t)(y - 1)))                                               \
         ? ((((uint32_t)(x)) + (((uint32_t)(y)) - 1)) / ((uint32_t)(y)))                            \
         : 0U)

/* Reduced TIFFDirectory: only the geometry fields the count functions touch. */
typedef struct {
    uint32_t td_imagewidth;
    uint32_t td_imagelength;
    uint32_t td_imagedepth;
    uint32_t td_tilewidth;
    uint32_t td_tilelength;
    uint32_t td_tiledepth;
    uint32_t td_rowsperstrip;
    uint16_t td_planarconfig;
    uint16_t td_samplesperpixel;
} TIFFDirectory;

struct TIFF {
    TIFFDirectory tif_dir;
};
typedef struct TIFF TIFF;

static void TIFFErrorExtR(TIFF *tif, const char *m, const char *fmt, ...) {
    (void)tif;
    (void)m;
    (void)fmt;
}
static void TIFFWarningExtR(TIFF *tif, const char *m, const char *fmt, ...) {
    (void)tif;
    (void)m;
    (void)fmt;
}
