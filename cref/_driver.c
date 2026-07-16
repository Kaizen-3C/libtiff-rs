
/* ==== driver ==== */

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned long fnv32(const uint8_t *p, tmsize_t n) {
    unsigned long h = 2166136261UL;
    tmsize_t i;
    for (i = 0; i < n; i++) { h ^= p[i]; h = (h * 16777619UL) & 0xffffffffUL; }
    return h;
}

static uint8_t inbuf[1 << 20];
static uint8_t outbuf[1 << 20];

int main(void) {
    static char line[2 * (1 << 20) + 16];
    while (fgets(line, sizeof line, stdin)) {
        char *tok = strtok(line, " \t\r\n");
        if (!tok) continue;
        tmsize_t occ = atol(tok);
        char *hex = strtok(NULL, " \t\r\n");

        tmsize_t n = 0;
        if (hex) {
            for (long i = 0; hex[2*i] && hex[2*i+1]; i++) {
                int hi = hexval((unsigned char)hex[2*i]);
                int lo = hexval((unsigned char)hex[2*i+1]);
                if (hi < 0 || lo < 0) break;
                if (n >= (tmsize_t)sizeof(inbuf)) break;
                inbuf[n++] = (uint8_t)((hi << 4) | lo);
            }
        }
        if (occ < 0) occ = 0;
        if (occ > (tmsize_t)sizeof(outbuf)) occ = sizeof(outbuf);

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_setupdecode = LZWSetupDecode;
        tif.tif_row = 0;

        int ret = 0;
        if (LZWSetupDecode(&tif)) {
            tif.tif_rawdata = inbuf;
            tif.tif_rawdatasize = n;
            tif.tif_rawcp = inbuf;
            tif.tif_rawcc = n;
            memset(outbuf, 0, (size_t)occ);
            if (LZWPreDecode(&tif, 0)) {
                ret = LZWDecode(&tif, outbuf, occ, 0);
            }
        }

        printf("R %d %" PRId64 " %08lx %" PRId64 "\n", ret, (int64_t)occ,
               fnv32(outbuf, occ) & 0xffffffffUL, (int64_t)tif.tif_rawcc);
        printf(".\n");

        /* teardown (driver is concatenated after the sliced code, so LZWCodecState is in scope) */
        if (tif.tif_data) {
            LZWCodecState *sp = (LZWCodecState *)tif.tif_data;
            if (sp->dec_codetab) free(sp->dec_codetab);
            free(tif.tif_data);
        }
    }
    return 0;
}
