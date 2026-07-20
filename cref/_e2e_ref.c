/* End-to-end decode ORACLE (Slice 6): open a TIFF with the REAL libtiff (static libtiff.a built
   from the pinned 4.7.0 source), read every strip through TIFFReadEncodedStrip, and print the same
   differential line the Rust e2e_decode driver prints:
     E <width> <length> <spp> <bps> <compression> <npixels> <hex pixels>   (or  E ERR  on decline)
   Usage: _e2e_ref <file.tif>
   This is the authoritative "what libtiff decodes to" reference; the Rust decoder must match byte
   for byte. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiffio.h>

static void fail(void) {
    printf("E ERR\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fail();
        return 0;
    }
    /* Silence libtiff's warning/error handlers so they don't pollute stdout. */
    TIFFSetWarningHandler(NULL);
    TIFFSetErrorHandler(NULL);

    TIFF *tif = TIFFOpen(argv[1], "r");
    if (!tif) {
        fail();
        return 0;
    }

    uint32_t width = 0, length = 0, rows_per_strip = 0;
    uint16_t spp = 1, bps = 1, compression = 1, planar = 1;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &length);
    TIFFGetFieldDefaulted(tif, TIFFTAG_SAMPLESPERPIXEL, &spp);
    TIFFGetFieldDefaulted(tif, TIFFTAG_BITSPERSAMPLE, &bps);
    TIFFGetFieldDefaulted(tif, TIFFTAG_COMPRESSION, &compression);
    TIFFGetFieldDefaulted(tif, TIFFTAG_PLANARCONFIG, &planar);
    TIFFGetFieldDefaulted(tif, TIFFTAG_ROWSPERSTRIP, &rows_per_strip);

    tstrip_t nstrips = TIFFNumberOfStrips(tif);
    tmsize_t stripsize = TIFFStripSize(tif);

    uint8_t *pixels = NULL;
    size_t total = 0, cap = 0;
    uint8_t *sbuf = (uint8_t *)malloc((size_t)stripsize);
    if (!sbuf) {
        TIFFClose(tif);
        fail();
        return 0;
    }

    for (tstrip_t s = 0; s < nstrips; s++) {
        tmsize_t n = TIFFReadEncodedStrip(tif, s, sbuf, (tmsize_t)-1);
        if (n < 0) {
            free(sbuf);
            free(pixels);
            TIFFClose(tif);
            fail();
            return 0;
        }
        if (total + (size_t)n > cap) {
            cap = (total + (size_t)n) * 2 + 64;
            pixels = (uint8_t *)realloc(pixels, cap);
        }
        memcpy(pixels + total, sbuf, (size_t)n);
        total += (size_t)n;
    }
    free(sbuf);

    printf("E %u %u %u %u %u %zu ", width, length, spp, bps, compression, total);
    for (size_t i = 0; i < total; i++)
        printf("%02x", pixels[i]);
    printf("\n");

    free(pixels);
    TIFFClose(tif);
    return 0;
}
