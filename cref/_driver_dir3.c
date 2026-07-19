/* Op-script driver for the value-array fetch (Slice 3), for certification. One tag read per stdin
   line:  A <flags> <type> <count> <offsethex16> <filehex>
   flags: bit0 SWAB, bit1 BIGTIFF; offsethex16 = exactly 16 hex chars (8 raw tdir_offset bytes as the
   union holds them); filehex = tif_base bytes. Builds a TIFFDirEntry, calls
   TIFFReadDirEntryByteArray, prints  A <errcode> <n> <hex of n returned bytes>  then . */

static int hexval3(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static enum TIFFReadDirEntryErr TIFFReadDirEntryByteArray(TIFF *tif, TIFFDirEntry *direntry,
                                                          uint8_t **value);

int main(void) {
    static char line[1 << 20];
    while (fgets(line, sizeof line, stdin)) {
        unsigned flags = 0, type = 0;
        unsigned long long count = 0;
        int consumed = 0;
        if (sscanf(line, "A %u %u %llu %n", &flags, &type, &count, &consumed) < 3)
            continue;

        const char *h = line + consumed;
        uint8_t off[8] = {0};
        int ok = 1;
        for (int i = 0; i < 8; i++) {
            int hi = hexval3((unsigned char)h[i * 2]), lo = hexval3((unsigned char)h[i * 2 + 1]);
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
            int hi = hexval3((unsigned char)h[0]), lo = hexval3((unsigned char)h[1]);
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

        uint8_t *value = NULL;
        enum TIFFReadDirEntryErr err = TIFFReadDirEntryByteArray(&tif, &dp, &value);
        if (err == TIFFReadDirEntryErrOk && value != NULL) {
            uint32_t n = (uint32_t)dp.tdir_count; /* byte output = one per element = count bytes */
            printf("A %d %" PRIu32 " ", (int)err, n);
            for (uint32_t i = 0; i < n; i++)
                printf("%02x", value[i]);
            printf("\n");
        } else {
            printf("A %d 0 \n", (int)err);
        }
        if (value)
            free(value);
        printf(".\n");
    }
    return 0;
}
