/* Self-contained port target: libtiff 4.7.0 **IFD directory-entry readers** — the typed
   value-promotion path (TIFFReadDirEntryByte + the Checked* raw reads + the CheckRangeByte*
   range guards + TIFFReadDirEntryData), taken verbatim from tif_dirread.c and driven over a
   memory buffer. This is libtiff's integer-overflow / OOB CVE surface: TIFFReadDirEntryData
   does the offset+size overflow check and the tif_size bounds check before copying from
   tif_base, and the promotion readers do the type-dispatch + cross-type range validation.
   The TIFF scaffolding is reduced to the fields these functions touch; the parse arithmetic is
   verbatim upstream. isMapped is always true (memory buffer); the non-mapped Seek/Read path is
   stubbed (never taken). No full directory scan, no field dispatch, no strips/tiles (later slices).

   Input: each stdin line is one directory-entry read:
     E <tdir_type> <tdir_count> <tdir_offset_u64> <flags> <filehex>
       flags bit0 = TIFF_SWAB, bit1 = TIFF_BIGTIFF; filehex fills tif_base (for LONG8 offset reads)
   Output per line:  R <errcode> <value_u64>   then a "." separator.
   The port must reproduce stdout exactly. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

typedef int64_t tmsize_t;
#define _TIFFmemcpy memcpy

/* TIFF field types (tiff.h) */
#define TIFF_NOTYPE 0
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

/* tif_flags bits (values are internal — only need to be distinct + set consistently by the driver) */
#define TIFF_SWAB 0x00000001U
#define TIFF_BIGTIFF 0x00000002U
#define TIFF_MAPPED 0x00000004U
#define isMapped(tif) (((tif)->tif_flags & TIFF_MAPPED) != 0)

/* reduced TIFF: only the fields the sliced readers touch */
struct TIFF {
    uint32_t tif_flags;
    uint8_t *tif_base; /* memory-mapped file base */
    tmsize_t tif_size; /* mapped file size */
};
typedef struct TIFF TIFF;

/* non-mapped path is never taken (isMapped always true here); stubs just need to compile */
#define SeekOK(tif, off) (0)
#define ReadOK(tif, buf, size) (0)

static void TIFFSwabShort(uint16_t *v)
{
    *v = (uint16_t)(((*v & 0x00FFU) << 8) | ((*v & 0xFF00U) >> 8));
}
static void TIFFSwabLong(uint32_t *v)
{
    *v = ((*v & 0x000000FFU) << 24) | ((*v & 0x0000FF00U) << 8) |
         ((*v & 0x00FF0000U) >> 8) | ((*v & 0xFF000000U) >> 24);
}
static void TIFFSwabLong8(uint64_t *v)
{
    *v = ((*v & 0x00000000000000FFULL) << 56) | ((*v & 0x000000000000FF00ULL) << 40) |
         ((*v & 0x0000000000FF0000ULL) << 24) | ((*v & 0x00000000FF000000ULL) << 8) |
         ((*v & 0x000000FF00000000ULL) >> 8) | ((*v & 0x0000FF0000000000ULL) >> 24) |
         ((*v & 0x00FF000000000000ULL) >> 40) | ((*v & 0xFF00000000000000ULL) >> 56);
}
