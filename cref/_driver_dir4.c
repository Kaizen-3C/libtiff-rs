/* Op-script driver for the Long8 strip-array reader (Slice 4), for certification. One tag read per
   stdin line:  L <flags> <type> <count> <maxcount> <offsethex16> <filehex>
   flags: bit0 SWAB, bit1 BIGTIFF; offsethex16 = exactly 16 hex chars (8 raw tdir_offset bytes);
   filehex = tif_base bytes. Builds a TIFFDirEntry, calls TIFFReadDirEntryLong8ArrayWithLimit, prints
   L <errcode> <n> <n space-separated u64 decimal values>  then . */

static int hexval4(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static enum TIFFReadDirEntryErr TIFFReadDirEntryLong8ArrayWithLimit(TIFF *tif, TIFFDirEntry *direntry,
                                                                   uint64_t **value,
                                                                   uint64_t maxcount);

int main(void) {
    static char line[1 << 20];
    while (fgets(line, sizeof line, stdin)) {
        unsigned flags = 0, type = 0;
        unsigned long long count = 0, maxcount = 0;
        int consumed = 0;
        if (sscanf(line, "L %u %u %llu %llu %n", &flags, &type, &count, &maxcount, &consumed) < 4)
            continue;

        const char *h = line + consumed;
        uint8_t off[8] = {0};
        int ok = 1;
        for (int i = 0; i < 8; i++) {
            int hi = hexval4((unsigned char)h[i * 2]), lo = hexval4((unsigned char)h[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                ok = 0;
                break;
            }
            off[i] = (uint8_t)((hi << 4) | lo);
        }
        if (!ok)
            continue;
        h += 16;
        while (*h == ' ')
            h++;

        static uint8_t filebuf[1 << 16];
        unsigned flen = 0;
        while (h[0] && h[1] && flen < sizeof filebuf) {
            int hi = hexval4((unsigned char)h[0]), lo = hexval4((unsigned char)h[1]);
            if (hi < 0 || lo < 0)
                break;
            filebuf[flen++] = (uint8_t)((hi << 4) | lo);
            h += 2;
        }

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_flags =
            TIFF_MAPPED | ((flags & 1) ? TIFF_SWAB : 0) | ((flags & 2) ? TIFF_BIGTIFF : 0);
        tif.tif_base = filebuf;
        tif.tif_size = (tmsize_t)flen;

        TIFFDirEntry dp;
        memset(&dp, 0, sizeof dp);
        dp.tdir_tag = 0;
        dp.tdir_type = (uint16_t)type;
        dp.tdir_count = (uint64_t)count;
        memcpy(&dp.tdir_offset, off, 8);

        uint64_t *value = NULL;
        enum TIFFReadDirEntryErr err =
            TIFFReadDirEntryLong8ArrayWithLimit(&tif, &dp, &value, (uint64_t)maxcount);
        if (err == TIFFReadDirEntryErrOk && value != NULL) {
            /* returned element count = clamped min(tdir_count, maxcount) */
            uint64_t nc = (dp.tdir_count < maxcount) ? dp.tdir_count : maxcount;
            uint32_t n = (uint32_t)nc;
            printf("L %d %" PRIu32, (int)err, n);
            for (uint32_t i = 0; i < n; i++)
                printf(" %" PRIu64, value[i]);
            printf("\n");
        } else {
            printf("L %d 0\n", (int)err);
        }
        if (value)
            free(value);
        printf(".\n");
    }
    return 0;
}
