/* In-process callable wrapper over TIFFReadDirEntryByteArray (Slice 3), for differential fuzzing.
   STRUCTURED input (both C and Rust interpret the same bytes) so the differential exercises only
   the ported value-array-fetch LOGIC (count x typesize overflow / size-sanity / inline-vs-offset /
   range-checked conversion), not a text-parse mismatch:
     [0]=flags(bit0 SWAB, bit1 BIGTIFF)  [1..3]=tdir_type(u16 native)  [3..11]=tdir_count(u64 native)
     [11..19]=tdir_offset(8 raw bytes as the union holds them)  [19..]=file (tif_base)
   < 19 bytes -> empty. Distinct symbol (run_case_c_dir3) to coexist with the other fuzzlibs.
   Output:  A <errcode> <n> <hex of n returned bytes>\n  then . */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static enum TIFFReadDirEntryErr TIFFReadDirEntryByteArray(TIFF *tif, TIFFDirEntry *direntry,
                                                          uint8_t **value);

char *run_case_c_dir3(const uint8_t *in, size_t n, size_t *outlen) {
    char *buf = NULL;
    size_t bufsz = 0;
    FILE *out = open_memstream(&buf, &bufsz);
    if (!out) {
        *outlen = 0;
        return NULL;
    }

    if (n >= 19) {
        static uint8_t filebuf[1 << 16];
        size_t flen = n - 19;
        if (flen > sizeof filebuf)
            flen = sizeof filebuf;
        memcpy(filebuf, in + 19, flen);

        uint8_t flags = in[0];
        uint16_t type;
        memcpy(&type, in + 1, 2); /* native u16 */
        uint64_t count;
        memcpy(&count, in + 3, 8); /* native u64 */
        uint8_t off[8];
        memcpy(off, in + 11, 8);

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_flags =
            TIFF_MAPPED | ((flags & 1) ? TIFF_SWAB : 0) | ((flags & 2) ? TIFF_BIGTIFF : 0);
        tif.tif_base = filebuf;
        tif.tif_size = (tmsize_t)flen;

        TIFFDirEntry dp;
        memset(&dp, 0, sizeof dp);
        dp.tdir_tag = 0;
        dp.tdir_type = type;
        dp.tdir_count = count;
        memcpy(&dp.tdir_offset, off, 8);

        uint8_t *value = NULL;
        enum TIFFReadDirEntryErr err = TIFFReadDirEntryByteArray(&tif, &dp, &value);
        if (err == TIFFReadDirEntryErrOk && value != NULL) {
            uint32_t m = (uint32_t)dp.tdir_count;
            fprintf(out, "A %d %" PRIu32 " ", (int)err, m);
            for (uint32_t i = 0; i < m; i++)
                fprintf(out, "%02x", value[i]);
            fprintf(out, "\n");
        } else {
            fprintf(out, "A %d 0 \n", (int)err);
        }
        if (value)
            free(value);
        fprintf(out, ".\n");
    }

    fclose(out);
    *outlen = bufsz;
    return buf;
}

void free_case_c_dir3(char *p) {
    free(p);
}
