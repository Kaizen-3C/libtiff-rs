/* Self-contained port target: libtiff 4.7.0 value-array fetch (Slice 4) — the u64-widening
   strip-offset/bytecount reader: TIFFReadDirEntryLong8Array[WithLimit] over the Slice 3
   TIFFReadDirEntryArrayWithLimit core, with the CheckRangeLong8* sign guards and a maxcount limit
   (the strip-count clamp). libtiff's strip/tile geometry gateway — the tag-array integer-overflow /
   under-allocation -> OOB CVE surface feeding TIFFReadDirectory. Driven over a memory buffer
   (isMapped always true; the non-mapped Seek/Read + DataAndRealloc path is stubbed, never taken).

   Structured fuzz/driver input (both C and Rust interpret identically):
     [0]=flags(bit0 SWAB, bit1 BIGTIFF)  [1..3]=tdir_type(u16 native)  [3..11]=tdir_count(u64 native)
     [11..19]=maxcount(u64 native)  [19..27]=tdir_offset(8 raw bytes)  [27..]=file (tif_base)
   Output:  L <errcode> <n> <n space-separated u64 decimal values>\n  then . */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

typedef int64_t tmsize_t;
#define TIFF_TMSIZE_T_MAX INT64_MAX
#define _TIFFmemcpy memcpy
#define FALSE 0

#define TIFF_SWAB 0x00000001U
#define TIFF_BIGTIFF 0x00000002U
#define TIFF_MAPPED 0x00000004U
#define isMapped(tif) (((tif)->tif_flags & TIFF_MAPPED) != 0)

/* TIFF field-type codes (tiff.h TIFFDataType) — the values TIFFDataWidth + the ByteArray switch use. */
typedef int TIFFDataType;
#define TIFF_BYTE 1
#define TIFF_ASCII 2
#define TIFF_SHORT 3
#define TIFF_LONG 4
#define TIFF_RATIONAL 5
#define TIFF_SBYTE 6
#define TIFF_UNDEFINED 7
#define TIFF_SSHORT 8
#define TIFF_SLONG 9
#define TIFF_SRATIONAL 10
#define TIFF_FLOAT 11
#define TIFF_DOUBLE 12
#define TIFF_IFD 13
#define TIFF_LONG8 16
#define TIFF_SLONG8 17
#define TIFF_IFD8 18

struct TIFF {
    uint32_t tif_flags;
    uint8_t *tif_base;
    tmsize_t tif_size;
    uint64_t tif_diroff;
    char *tif_name;
};
typedef struct TIFF TIFF;

/* non-mapped path never taken (isMapped always true here); stubs just need to compile */
#define SeekOK(tif, off) (0)
#define ReadOK(tif, buf, size) (0)

static void TIFFSwabShort(uint16_t *v) {
    *v = (uint16_t)(((*v & 0x00FFU) << 8) | ((*v & 0xFF00U) >> 8));
}
static void TIFFSwabLong(uint32_t *v) {
    *v = ((*v & 0x000000FFU) << 24) | ((*v & 0x0000FF00U) << 8) | ((*v & 0x00FF0000U) >> 8) |
         ((*v & 0xFF000000U) >> 24);
}
static void TIFFSwabLong8(uint64_t *v) {
    *v = ((*v & 0x00000000000000FFULL) << 56) | ((*v & 0x000000000000FF00ULL) << 40) |
         ((*v & 0x0000000000FF0000ULL) << 24) | ((*v & 0x00000000FF000000ULL) << 8) |
         ((*v & 0x000000FF00000000ULL) >> 8) | ((*v & 0x0000FF0000000000ULL) >> 24) |
         ((*v & 0x00FF000000000000ULL) >> 40) | ((*v & 0xFF00000000000000ULL) >> 56);
}

/* TIFFDataWidth (tif_dirinfo.c, pure deterministic lookup — shimmed exactly): byte width per type. */
static int TIFFDataWidth(TIFFDataType type) {
    switch (type) {
        case 0:
        case TIFF_BYTE:
        case TIFF_ASCII:
        case TIFF_SBYTE:
        case TIFF_UNDEFINED:
            return 1;
        case TIFF_SHORT:
        case TIFF_SSHORT:
            return 2;
        case TIFF_LONG:
        case TIFF_SLONG:
        case TIFF_FLOAT:
        case TIFF_IFD:
            return 4;
        case TIFF_RATIONAL:
        case TIFF_SRATIONAL:
        case TIFF_DOUBLE:
        case TIFF_LONG8:
        case TIFF_SLONG8:
        case TIFF_IFD8:
            return 8;
        default:
            return 0;
    }
}

/* _TIFFMultiplySSize / _TIFFCheckMalloc — verbatim behaviour (overflow-checked alloc). */
static tmsize_t _TIFFMultiplySSize(TIFF *tif, tmsize_t first, tmsize_t second, const char *where) {
    (void)tif;
    (void)where;
    if (first <= 0 || second <= 0)
        return 0;
    if (first > TIFF_TMSIZE_T_MAX / second)
        return 0;
    return first * second;
}
static void *_TIFFCheckMalloc(TIFF *tif, tmsize_t nmemb, tmsize_t elem_size, const char *what) {
    (void)what;
    tmsize_t count = _TIFFMultiplySSize(tif, nmemb, elem_size, NULL);
    return count != 0 ? malloc((size_t)count) : NULL;
}
static void *_TIFFmallocExt(TIFF *tif, tmsize_t s) {
    (void)tif;
    return s > 0 ? malloc((size_t)s) : NULL;
}
static void _TIFFfreeExt(TIFF *tif, void *p) {
    (void)tif;
    free(p);
}
static uint64_t TIFFGetFileSize(TIFF *tif) { return (uint64_t)tif->tif_size; }

static void TIFFSwabArrayOfLong8(uint64_t *lp, tmsize_t n) {
    while (n-- > 0) {
        TIFFSwabLong8(lp);
        lp++;
    }
}

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
