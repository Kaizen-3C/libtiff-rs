/* Self-contained port target: libtiff 4.7.0 **codec-core decoders** — PackBitsDecode,
   ThunderDecode, NeXTDecode, and the LZW decoder (LZWSetupDecode + LZWPreDecode + LZWDecode),
   all taken verbatim from tif_packbits.c / tif_thunder.c / tif_next.c / tif_lzw.c and driven
   over a memory buffer. These are libtiff's separable, pure-C, untrusted-input decompressors;
   their bounds guards (PackBits overrun-avoidance, Thunder/NeXT npixels/scanline limits, the
   LZW code-table index guards) are the codec-overflow CVE surface. The `TIFF*` scaffolding is
   reduced to the fields these functions touch; the decode arithmetic is verbatim upstream. The
   LZW backwards-compat path (LZW_COMPAT) is left undefined (old-style streams take the reject
   branch). No file directory, no strips/tiles, no predictor, no encoder.

   Input: each stdin line dispatches by leading codec char:
     P <occ> <hex>                 PackBitsDecode (occ = output bytes)
     T <maxpixels> <hex>           ThunderDecode  (output = (maxpixels+1)/2 bytes, 4bpp)
     N <occ> <scanline> <iw> <hex> NeXTDecode     (occ output bytes; scanline size; imagewidth)
     L <occ> <hex>                 LZWDecode      (occ = output bytes)
   Output per line:  R <ret> <outbytes> <fnv> <rawcc_left>   then a "." separator.
   (Decoders zero the output tail on short/erroneous input, so the FNV is always defined.)
   The port must reproduce stdout exactly. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>

typedef int64_t tmsize_t;
typedef uint64_t WordType;
#define SIZEOF_WORDTYPE 8
/* WORDS_BIGENDIAN deliberately undefined */

#define _TIFFmemcpy memcpy
#define TIFF_SSIZE_FORMAT PRId64
#define TIFF_ISTILED 0x00400U
#define isTiled(tif) (((tif)->tif_flags & TIFF_ISTILED) != 0)
#define WHITE ((1 << 2) - 1)

struct TIFF;
typedef struct TIFF TIFF;

typedef struct { unsigned char _pad[64]; } TIFFPredictorState;

struct TIFFDirShim { uint32_t td_imagewidth; uint32_t td_tilewidth; };

struct TIFF {
    void *tif_data;
    uint8_t *tif_rawcp;
    tmsize_t tif_rawcc;
    uint8_t *tif_rawdata;
    tmsize_t tif_rawdatasize;
    uint32_t tif_row;
    uint32_t tif_curstrip;
    uint32_t tif_flags;
    tmsize_t tif_scanlinesize;
    char *tif_name;
    struct TIFFDirShim tif_dir;
    int (*tif_setupdecode)(TIFF *);
    int (*tif_decoderow)(TIFF *, uint8_t *, tmsize_t, uint16_t);
    int (*tif_decodestrip)(TIFF *, uint8_t *, tmsize_t, uint16_t);
    int (*tif_decodetile)(TIFF *, uint8_t *, tmsize_t, uint16_t);
};

static void *_TIFFmallocExt(TIFF *tif, tmsize_t n) { (void)tif; return malloc((size_t)n); }
static void *_TIFFcallocExt(TIFF *tif, tmsize_t n, tmsize_t s) { (void)tif; return calloc((size_t)n, (size_t)s); }
static void _TIFFfreeExt(TIFF *tif, void *p) { (void)tif; free(p); }
static int TIFFPredictorInit(TIFF *tif) { (void)tif; return 1; }
static void TIFFErrorExtR(TIFF *tif, const char *m, const char *fmt, ...) { (void)tif; (void)m; (void)fmt; }
static void TIFFWarningExtR(TIFF *tif, const char *m, const char *fmt, ...) { (void)tif; (void)m; (void)fmt; }

