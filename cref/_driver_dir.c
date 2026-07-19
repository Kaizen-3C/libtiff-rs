/* Op-script driver for the IFD directory-entry readers (see _prelude_dir.c). One entry read per
   stdin line; reproduces the exact type-dispatch + range-validation + bounds-checked-offset-read
   path of TIFFReadDirEntryByte over a memory buffer.

     E <tdir_type> <tdir_count> <tdir_offset_u64> <flags> <filehex>
   -> R <errcode> <value_u64> \n . \n
   flags: bit0 = TIFF_SWAB, bit1 = TIFF_BIGTIFF. filehex fills tif_base (used only when a scalar
   LONG8/SLONG8 value is referenced by offset in ClassicTIFF). */

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int main(void)
{
    static char line[1 << 20];
    while (fgets(line, sizeof line, stdin))
    {
        unsigned type, flags;
        unsigned long long count, offset;
        int consumed = 0;
        if (sscanf(line, "E %u %llu %llu %u %n", &type, &count, &offset, &flags, &consumed) < 4)
            continue;

        static uint8_t filebuf[1 << 16];
        unsigned n = 0;
        const char *h = line + consumed;
        while (h[0] && h[1] && n < sizeof filebuf)
        {
            int hi = hexval((unsigned char)h[0]), lo = hexval((unsigned char)h[1]);
            if (hi < 0 || lo < 0)
                break;
            filebuf[n++] = (uint8_t)((hi << 4) | lo);
            h += 2;
        }

        TIFFDirEntry entry;
        memset(&entry, 0, sizeof entry);
        entry.tdir_tag = 0;
        entry.tdir_type = (uint16_t)type;
        entry.tdir_count = (uint64_t)count;
        entry.tdir_offset.toff_long8 = (uint64_t)offset; /* raw 8-byte offset-field value */

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_flags = TIFF_MAPPED | ((flags & 1) ? TIFF_SWAB : 0) | ((flags & 2) ? TIFF_BIGTIFF : 0);
        tif.tif_base = filebuf;
        tif.tif_size = (tmsize_t)n;

        uint8_t value = 0;
        enum TIFFReadDirEntryErr err = TIFFReadDirEntryByte(&tif, &entry, &value);
        printf("R %d %llu\n", (int)err, (unsigned long long)value);
        printf(".\n");
    }
    return 0;
}
