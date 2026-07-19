/* Op-script driver for TIFFFetchDirectory (Slice 2), for certification. One directory parse per
   stdin line:  F <diroff> <flags> <filehex>  (flags bit0=SWAB, bit1=BIGTIFF; filehex = tif_base).
   Output:  D <dircount> <nextdiroff>\n  then per entry  e <tag> <type> <count> <offset>\n  then . */

static int hexval2(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static uint16_t TIFFFetchDirectory(TIFF *tif, uint64_t diroff, TIFFDirEntry **pdir,
                                   uint64_t *nextdiroff);

int main(void) {
    static char line[1 << 20];
    while (fgets(line, sizeof line, stdin)) {
        unsigned flags = 0;
        unsigned long long diroff = 0;
        int consumed = 0;
        if (sscanf(line, "F %llu %u %n", &diroff, &flags, &consumed) < 2)
            continue;

        static uint8_t filebuf[1 << 16];
        unsigned n = 0;
        const char *h = line + consumed;
        while (h[0] && h[1] && n < sizeof filebuf) {
            int hi = hexval2((unsigned char)h[0]), lo = hexval2((unsigned char)h[1]);
            if (hi < 0 || lo < 0)
                break;
            filebuf[n++] = (uint8_t)((hi << 4) | lo);
            h += 2;
        }

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_flags =
            TIFF_MAPPED | ((flags & 1) ? TIFF_SWAB : 0) | ((flags & 2) ? TIFF_BIGTIFF : 0);
        tif.tif_base = filebuf;
        tif.tif_size = (tmsize_t)n;

        TIFFDirEntry *dir = NULL;
        uint64_t nextdiroff = 0;
        uint16_t dircount = TIFFFetchDirectory(&tif, (uint64_t)diroff, &dir, &nextdiroff);

        printf("D %u %llu\n", (unsigned)dircount, (unsigned long long)nextdiroff);
        if (dircount > 0 && dir) {
            for (uint16_t i = 0; i < dircount; i++)
                printf("e %u %u %llu %llu\n", dir[i].tdir_tag, dir[i].tdir_type,
                       (unsigned long long)dir[i].tdir_count,
                       (unsigned long long)dir[i].tdir_offset.toff_long8);
        }
        if (dir)
            free(dir);
        printf(".\n");
    }
    return 0;
}
