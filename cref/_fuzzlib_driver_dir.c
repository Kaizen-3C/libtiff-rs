/* In-process callable wrapper over the IFD directory-entry reader (see _prelude_dir.c), for
   differential fuzzing. Unlike the op-script _driver_dir.c (text, used for certification), the FUZZ
   harness feeds STRUCTURED bytes so the differential exercises only the ported TIFFReadDirEntryByte
   LOGIC — not a text-parsing (sscanf vs Rust) mismatch between the two drivers. Both C and Rust
   interpret the same fuzz bytes identically:
     [0..2]=tdir_type(u16 LE)  [2..10]=tdir_count(u64 LE)  [10..18]=tdir_offset(raw 8 bytes)
     [18]=flags(bit0 SWAB, bit1 BIGTIFF)  [19..]=file (tif_base)
   < 19 bytes -> empty output (both sides). Distinct symbol (run_case_c_dir) to coexist with the
   codec fuzzlib. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *run_case_c_dir(const uint8_t *in, size_t n, size_t *outlen) {
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

        TIFFDirEntry entry;
        memset(&entry, 0, sizeof entry);
        entry.tdir_type = (uint16_t)(in[0] | (in[1] << 8));
        memcpy(&entry.tdir_count, in + 2, 8);   /* host-order u64 */
        memcpy(&entry.tdir_offset, in + 10, 8); /* the raw 8-byte offset/value union */

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_flags =
            TIFF_MAPPED | ((in[18] & 1) ? TIFF_SWAB : 0) | ((in[18] & 2) ? TIFF_BIGTIFF : 0);
        tif.tif_base = filebuf;
        tif.tif_size = (tmsize_t)flen;

        uint8_t value = 0;
        enum TIFFReadDirEntryErr err = TIFFReadDirEntryByte(&tif, &entry, &value);
        fprintf(out, "R %d %llu\n", (int)err, (unsigned long long)value);
        fprintf(out, ".\n");
    }

    fclose(out);
    *outlen = bufsz;
    return buf;
}

void free_case_c_dir(char *p) {
    free(p);
}
