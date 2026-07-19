/* In-process callable wrapper over TIFFNumberOfStrips/TIFFNumberOfTiles (Slice 5), for differential
   fuzzing. STRUCTURED input (both C and Rust interpret the same bytes) so the differential
   exercises only the ported geometry-count LOGIC (howmany ceil-division + _TIFFMultiply32 overflow
   guards), not a text-parse mismatch. All fields native:
     [0..4]=rowsperstrip [4..8]=imagelength [8..12]=imagewidth [12..16]=imagedepth
     [16..18]=planarconfig(u16) [18..20]=samplesperpixel(u16)
     [20..24]=tilewidth [24..28]=tilelength [28..32]=tiledepth
   < 32 bytes -> empty. Distinct symbol (run_case_c_dir5) to coexist with the other fuzzlibs.
   Output:  G <nstrips> <ntiles>\n  then . */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t TIFFNumberOfStrips(TIFF *tif);
static uint32_t TIFFNumberOfTiles(TIFF *tif);

char *run_case_c_dir5(const uint8_t *in, size_t n, size_t *outlen) {
    char *buf = NULL;
    size_t bufsz = 0;
    FILE *out = open_memstream(&buf, &bufsz);
    if (!out) {
        *outlen = 0;
        return NULL;
    }

    if (n >= 32) {
        TIFF tif;
        memset(&tif, 0, sizeof tif);
        memcpy(&tif.tif_dir.td_rowsperstrip, in + 0, 4);
        memcpy(&tif.tif_dir.td_imagelength, in + 4, 4);
        memcpy(&tif.tif_dir.td_imagewidth, in + 8, 4);
        memcpy(&tif.tif_dir.td_imagedepth, in + 12, 4);
        memcpy(&tif.tif_dir.td_planarconfig, in + 16, 2);
        memcpy(&tif.tif_dir.td_samplesperpixel, in + 18, 2);
        memcpy(&tif.tif_dir.td_tilewidth, in + 20, 4);
        memcpy(&tif.tif_dir.td_tilelength, in + 24, 4);
        memcpy(&tif.tif_dir.td_tiledepth, in + 28, 4);

        uint32_t nstrips = TIFFNumberOfStrips(&tif);
        uint32_t ntiles = TIFFNumberOfTiles(&tif);
        fprintf(out, "G %" PRIu32 " %" PRIu32 "\n", nstrips, ntiles);
        fprintf(out, ".\n");
    }

    fclose(out);
    *outlen = bufsz;
    return buf;
}

void free_case_c_dir5(char *p) {
    free(p);
}
