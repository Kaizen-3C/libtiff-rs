/* In-process callable wrapper over TIFFReadDirEntryLong8ArrayWithLimit (Slice 4), for differential
   fuzzing. STRUCTURED input (both C and Rust interpret the same bytes) so the differential exercises
   only the ported u64-widening strip-array LOGIC (count×typesize overflow / size-sanity / maxcount
   clamp / sign-checked widening), not a text-parse mismatch:
     [0]=flags(bit0 SWAB, bit1 BIGTIFF)  [1..3]=tdir_type(u16 native)  [3..11]=tdir_count(u64 native)
     [11..19]=maxcount(u64 native)  [19..27]=tdir_offset(8 raw bytes)  [27..]=file (tif_base)
   < 27 bytes -> empty. Distinct symbol (run_case_c_dir4) to coexist with the other fuzzlibs.
   Output:  L <errcode> <n> <n space-separated u64 decimal values>\n  then . */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static enum TIFFReadDirEntryErr TIFFReadDirEntryLong8ArrayWithLimit(TIFF *tif, TIFFDirEntry *direntry,
                                                                   uint64_t **value,
                                                                   uint64_t maxcount);

char *run_case_c_dir4(const uint8_t *in, size_t n, size_t *outlen) {
    char *buf = NULL;
    size_t bufsz = 0;
    FILE *out = open_memstream(&buf, &bufsz);
    if (!out) {
        *outlen = 0;
        return NULL;
    }

    if (n >= 27) {
        static uint8_t filebuf[1 << 16];
        size_t flen = n - 27;
        if (flen > sizeof filebuf)
            flen = sizeof filebuf;
        memcpy(filebuf, in + 27, flen);

        uint8_t flags = in[0];
        uint16_t type;
        memcpy(&type, in + 1, 2);
        uint64_t count, maxcount;
        memcpy(&count, in + 3, 8);
        memcpy(&maxcount, in + 11, 8);
        uint8_t off[8];
        memcpy(off, in + 19, 8);

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

        uint64_t *value = NULL;
        enum TIFFReadDirEntryErr err =
            TIFFReadDirEntryLong8ArrayWithLimit(&tif, &dp, &value, maxcount);
        if (err == TIFFReadDirEntryErrOk && value != NULL) {
            uint64_t nc = (dp.tdir_count < maxcount) ? dp.tdir_count : maxcount;
            uint32_t m = (uint32_t)nc;
            fprintf(out, "L %d %" PRIu32, (int)err, m);
            for (uint32_t i = 0; i < m; i++)
                fprintf(out, " %" PRIu64, value[i]);
            fprintf(out, "\n");
        } else {
            fprintf(out, "L %d 0\n", (int)err);
        }
        if (value)
            free(value);
        fprintf(out, ".\n");
    }

    fclose(out);
    *outlen = bufsz;
    return buf;
}

void free_case_c_dir4(char *p) {
    free(p);
}
