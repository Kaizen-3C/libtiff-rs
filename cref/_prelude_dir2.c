/* Self-contained port target: libtiff 4.7.0 **TIFFFetchDirectory** (Slice 2) — the IFD
   directory-STRUCTURE parse: read the entry count (u16 classic / u64 BigTIFF), sanity-check it,
   read the entries array with the offset+size overflow / tif_size bounds guards, unpack each raw
   12/20-byte entry into a TIFFDirEntry (tag/type/count/offset, byte-swapped as needed), and read
   the next-IFD offset. This is libtiff's directory-structure integer-overflow / OOB CVE surface
   (the `m = off + size; if (m < off || m < size || m > tif_size)` checks). Driven over a memory
   buffer (isMapped always true; the non-mapped Seek/Read path is stubbed, never taken).

   Structured fuzz/driver input (both C and Rust interpret identically):
     [0..8]=diroff(u64 native)  [8]=flags(bit0 SWAB, bit1 BIGTIFF)  [9..]=file (tif_base)
   Output:  D <dircount> <nextdiroff>\n  then per entry  e <tag> <type> <count> <offset>\n  then . */

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
#define TIFF_SSIZE_FORMAT PRId64

#define TIFF_SWAB 0x00000001U
#define TIFF_BIGTIFF 0x00000002U
#define TIFF_MAPPED 0x00000004U
#define isMapped(tif) (((tif)->tif_flags & TIFF_MAPPED) != 0)

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

typedef union {
    uint8_t c[8];
    uint64_t l;
} UInt64Aligned_t;

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

/* _TIFFMultiplySSize / _TIFFCheckMalloc — verbatim behaviour (the overflow-checked alloc; bounded
   here by the dircount<=4096 sanity, but ported faithfully as it's part of the guard chain). */
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
static void _TIFFfreeExt(TIFF *tif, void *p) {
    (void)tif;
    free(p);
}
static uint64_t TIFFGetFileSize(TIFF *tif) { return (uint64_t)tif->tif_size; }

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
