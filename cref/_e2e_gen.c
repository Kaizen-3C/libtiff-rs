/* End-to-end test-TIFF GENERATOR (Slice 6): use the real libtiff to write a matrix of small, valid
   8-bit grayscale TIFFs with deterministic pixel content, varying byte order, compression, and strip
   layout. These become the differential envelope: each is decoded by both _e2e_ref (real libtiff)
   and the Rust e2e_decode, and their pixel output byte-compared.
   Usage: _e2e_gen <output_dir>  -> writes e2e_XX.tif files + prints their paths, one per line. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiffio.h>

/* Deterministic pixel value from coordinates + a per-image seed — a mix that PackBits/LZW both
   compress non-trivially (runs AND variety), so the codecs actually do work. */
static uint8_t px(uint32_t x, uint32_t y, uint32_t seed) {
    uint32_t v = (x * 31u + y * 131u + seed * 2654435761u);
    v ^= v >> 7;
    /* inject runs: every few columns repeat, so PackBits has something to pack */
    if ((x & 7u) < 3u)
        v = seed + y;
    return (uint8_t)(v & 0xff);
}

static int write_one(const char *path, int bigendian, uint16_t compression, uint32_t w, uint32_t h,
                     uint32_t rows_per_strip, uint16_t spp, uint32_t seed) {
    TIFF *tif = TIFFOpen(path, bigendian ? "wb" : "wl");
    if (!tif)
        return 0;
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, w);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, h);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, spp);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, spp == 1 ? PHOTOMETRIC_MINISBLACK : PHOTOMETRIC_RGB);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
    TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rows_per_strip);

    uint8_t *row = (uint8_t *)malloc((size_t)w * spp);
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++)
            for (uint16_t s = 0; s < spp; s++)
                row[x * spp + s] = px(x * spp + s, y, seed);
        if (TIFFWriteScanline(tif, row, y, 0) < 0) {
            free(row);
            TIFFClose(tif);
            return 0;
        }
    }
    free(row);
    TIFFClose(tif);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: _e2e_gen <output_dir>\n");
        return 1;
    }
    TIFFSetWarningHandler(NULL);
    const char *dir = argv[1];

    struct {
        int be;
        uint16_t comp;
        uint32_t w, h, rps, spp, seed;
    } cases[] = {
        /* endian, compression, w, h, rows/strip, spp, seed */
        {0, COMPRESSION_NONE, 8, 8, 8, 1, 1},        /* LE, uncompressed, single strip */
        {1, COMPRESSION_NONE, 8, 8, 8, 1, 2},        /* BE, uncompressed */
        {0, COMPRESSION_NONE, 17, 13, 4, 1, 3},      /* LE, uncompressed, multi-strip, partial last */
        {0, COMPRESSION_PACKBITS, 16, 16, 4, 1, 4},  /* LE, PackBits, multi-strip */
        {1, COMPRESSION_PACKBITS, 16, 16, 4, 1, 5},  /* BE, PackBits */
        {0, COMPRESSION_PACKBITS, 23, 9, 3, 1, 6},   /* LE, PackBits, odd sizes */
        {0, COMPRESSION_LZW, 16, 16, 4, 1, 7},       /* LE, LZW, multi-strip */
        {1, COMPRESSION_LZW, 20, 12, 5, 1, 8},       /* BE, LZW */
        {0, COMPRESSION_LZW, 32, 32, 8, 1, 9},       /* LE, LZW, larger */
        {0, COMPRESSION_NONE, 12, 5, 100, 1, 10},    /* rows/strip > height => single strip */
        {0, COMPRESSION_PACKBITS, 16, 16, 16, 1, 11},/* single strip PackBits */
        {0, COMPRESSION_LZW, 7, 7, 1, 1, 12},        /* one row per strip, LZW */
    };
    int n = (int)(sizeof cases / sizeof cases[0]);
    for (int i = 0; i < n; i++) {
        char path[1024];
        snprintf(path, sizeof path, "%s/e2e_%02d.tif", dir, i);
        if (!write_one(path, cases[i].be, cases[i].comp, cases[i].w, cases[i].h, cases[i].rps,
                       (uint16_t)cases[i].spp, cases[i].seed)) {
            fprintf(stderr, "FAILED to write %s\n", path);
            return 1;
        }
        printf("%s\n", path);
    }
    return 0;
}
