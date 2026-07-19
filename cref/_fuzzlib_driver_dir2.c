/* In-process callable wrapper over TIFFFetchDirectory (Slice 2), for differential fuzzing.
   STRUCTURED input (both C and Rust interpret the same bytes) so the differential exercises only
   the ported directory-parse LOGIC, not a text-parse mismatch:
     [0..8]=diroff(u64 native)  [8]=flags(bit0 SWAB, bit1 BIGTIFF)  [9..]=file (tif_base)
   < 9 bytes -> empty. Distinct symbol (run_case_c_dir2) to coexist with the other fuzzlibs.
   Output: D <dircount> <nextdiroff>\n  then per entry  e <tag> <type> <count> <offset>\n  then . */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* TIFF, TIFFDirEntry, TIFFFetchDirectory, TIFF_MAPPED/SWAB/BIGTIFF and open_memstream all come from
   the prelude + verbatim slice assembled ahead of this driver (see assemble_dir2.py). */

char *run_case_c_dir2(const uint8_t *in, size_t n, size_t *outlen) {
    char *buf = NULL;
    size_t bufsz = 0;
    FILE *out = open_memstream(&buf, &bufsz);
    if (!out) {
        *outlen = 0;
        return NULL;
    }

    if (n >= 9) {
        static uint8_t filebuf[1 << 16];
        size_t flen = n - 9;
        if (flen > sizeof filebuf)
            flen = sizeof filebuf;
        memcpy(filebuf, in + 9, flen);

        uint64_t diroff;
        memcpy(&diroff, in, 8); /* host-order u64 */
        uint8_t flags = in[8];

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_flags =
            TIFF_MAPPED | ((flags & 1) ? TIFF_SWAB : 0) | ((flags & 2) ? TIFF_BIGTIFF : 0);
        tif.tif_base = filebuf;
        tif.tif_size = (tmsize_t)flen;

        TIFFDirEntry *dir = NULL;
        uint64_t nextdiroff = 0;
        uint16_t dircount = TIFFFetchDirectory(&tif, diroff, &dir, &nextdiroff);

        fprintf(out, "D %u %llu\n", (unsigned)dircount, (unsigned long long)nextdiroff);
        if (dircount > 0 && dir) {
            for (uint16_t i = 0; i < dircount; i++)
                fprintf(out, "e %u %u %llu %llu\n", dir[i].tdir_tag, dir[i].tdir_type,
                        (unsigned long long)dir[i].tdir_count,
                        (unsigned long long)dir[i].tdir_offset.toff_long8);
        }
        if (dir)
            free(dir);
        fprintf(out, ".\n");
    }

    fclose(out);
    *outlen = bufsz;
    return buf;
}

void free_case_c_dir2(char *p) {
    free(p);
}
