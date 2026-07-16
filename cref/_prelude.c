/* Self-contained port target: libtiff 4.7.0 **LZW decoder** — LZWSetupDecode + LZWPreDecode +
   LZWDecode from tif_lzw.c, taken verbatim, driven over a memory buffer. This is libtiff's
   richest untrusted-input surface: a 9–12-bit LZW code-table decoder whose bounds guards
   (code-table index limits, CLEAR/EOI handling, the "bogus input" table-zeroing) are the classic
   LZW-overflow CVE territory. The `TIFF*` scaffolding is reduced to the fields the three
   functions touch; the code-table/bit-reader/goto arithmetic is verbatim upstream.

   The backwards-compat old-style path (LZW_COMPAT / LZWDecodeCompat) is intentionally NOT
   included — `LZW_COMPAT` is left undefined, so an old-style stream (rawdata[0]==0 &&
   rawdata[1]&1) takes the `#else` branch (report + return 0), which the envelope exercises.

   Input: each stdin line is `<occ> <hex>`:
     occ  = output byte count requested (the scanline/strip size)
     hex  = the raw LZW-compressed input stream, even-length hex
   Output per line:
     R <ret> <occ> <fnv> <rawcc_left>
       ret = LZWDecode return (1 ok / 0 error), fnv = FNV-1a of the occ-byte output buffer
       (the decoder zeroes the tail on short/erroneous input, so it is always fully defined),
       rawcc_left = tif_rawcc after decode.
   Every line ends with a `.` separator. The port must reproduce stdout exactly. */

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
/* WORDS_BIGENDIAN deliberately undefined (little-endian host) */

struct TIFF;
typedef struct TIFF TIFF;

/* predictor superclass placeholder — libtiff puts TIFFPredictorState first in the codec state
   for the horizontal-differencing wrapper. The direct LZW decode path never reads it; a byte
   pad of the upstream size keeps the LZWCodecState layout self-consistent (never inspected). */
typedef struct { unsigned char _pad[64]; } TIFFPredictorState;

struct TIFF {
    void *tif_data;            /* codec state block (LZWCodecState) */
    uint8_t *tif_rawcp;        /* input cursor */
    tmsize_t tif_rawcc;        /* input bytes remaining */
    uint8_t *tif_rawdata;      /* input buffer base */
    tmsize_t tif_rawdatasize;
    uint32_t tif_row;
    uint32_t tif_curstrip;
    char *tif_name;
    int (*tif_setupdecode)(TIFF *);
    int (*tif_decoderow)(TIFF *, uint8_t *, tmsize_t, uint16_t);
    int (*tif_decodestrip)(TIFF *, uint8_t *, tmsize_t, uint16_t);
    int (*tif_decodetile)(TIFF *, uint8_t *, tmsize_t, uint16_t);
};

/* allocator + predictor + diagnostics shims (tif arg ignored). Diagnostics are pure
   side-channel — they never change the output buffer or the return value — so they are no-ops. */
static void *_TIFFmallocExt(TIFF *tif, tmsize_t n) { (void)tif; return malloc((size_t)n); }
static void *_TIFFcallocExt(TIFF *tif, tmsize_t n, tmsize_t s) { (void)tif; return calloc((size_t)n, (size_t)s); }
static void _TIFFfreeExt(TIFF *tif, void *p) { (void)tif; free(p); }
static int TIFFPredictorInit(TIFF *tif) { (void)tif; return 1; }
static void TIFFErrorExtR(TIFF *tif, const char *m, const char *fmt, ...) { (void)tif; (void)m; (void)fmt; }
static void TIFFWarningExtR(TIFF *tif, const char *m, const char *fmt, ...) { (void)tif; (void)m; (void)fmt; }

