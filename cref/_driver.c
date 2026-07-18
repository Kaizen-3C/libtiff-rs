
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

static tmsize_t load_hex(const char *hex) {
    tmsize_t n = 0;
    if (!hex) return 0;
    for (long i = 0; hex[2*i] && hex[2*i+1]; i++) {
        int hi = hexval((unsigned char)hex[2*i]);
        int lo = hexval((unsigned char)hex[2*i+1]);
        if (hi < 0 || lo < 0) break;
        if (n >= (tmsize_t)sizeof(inbuf)) break;
        inbuf[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

int main(void) {
    static char line[2 * (1 << 20) + 32];
    while (fgets(line, sizeof line, stdin)) {
        char *codec = strtok(line, " \t\r\n");
        if (!codec) continue;
        char c = codec[0];

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_row = 0;

        tmsize_t outbytes = 0;
        int ret = 0;

        if (c == 'P') {
            tmsize_t occ = atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t n = load_hex(strtok(NULL, " \t\r\n"));
            if (occ < 0) occ = 0;
            if (occ > (tmsize_t)sizeof(outbuf)) occ = sizeof(outbuf);
            outbytes = occ;
            tif.tif_rawdata = inbuf; tif.tif_rawdatasize = n; tif.tif_rawcp = inbuf; tif.tif_rawcc = n;
            memset(outbuf, 0, (size_t)outbytes);
            extern int PackBitsDecode(TIFF *, uint8_t *, tmsize_t, uint16_t);
            ret = PackBitsDecode(&tif, outbuf, occ, 0);
        } else if (c == 'T') {
            tmsize_t maxpixels = atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t n = load_hex(strtok(NULL, " \t\r\n"));
            if (maxpixels < 0) maxpixels = 0;
            /* maxpixels tells ThunderDecode how many bytes of outbuf it may write
               ((maxpixels+1)/2); clamp maxpixels itself (not just the buffer-size
               computation below) so the two can never disagree -- an unclamped maxpixels
               with a clamped outbuf allocation is a driver-only global-buffer-overflow
               (found by the differential fuzz target; real libtiff callers always derive
               both from the same source, so this was never reachable via a real TIFF, only
               via this driver's own inconsistent clamping). */
            if (maxpixels > 2 * (tmsize_t)sizeof(outbuf) - 1) maxpixels = 2 * (tmsize_t)sizeof(outbuf) - 1;
            outbytes = (maxpixels + 1) / 2;
            if (outbytes > (tmsize_t)sizeof(outbuf)) outbytes = sizeof(outbuf);
            tif.tif_rawdata = inbuf; tif.tif_rawdatasize = n; tif.tif_rawcp = inbuf; tif.tif_rawcc = n;
            memset(outbuf, 0, (size_t)outbytes);
            extern int ThunderDecode(TIFF *, uint8_t *, tmsize_t);
            ret = ThunderDecode(&tif, outbuf, maxpixels);
        } else if (c == 'N') {
            tmsize_t occ = atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t scan = atol(strtok(NULL, " \t\r\n") ?: "1");
            uint32_t iw = (uint32_t)atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t n = load_hex(strtok(NULL, " \t\r\n"));
            if (occ < 0) occ = 0;
            if (occ > (tmsize_t)sizeof(outbuf)) occ = sizeof(outbuf);
            if (scan <= 0) scan = 1;
            outbytes = occ;
            tif.tif_scanlinesize = scan; tif.tif_dir.td_imagewidth = iw; tif.tif_flags = 0;
            tif.tif_rawdata = inbuf; tif.tif_rawdatasize = n; tif.tif_rawcp = inbuf; tif.tif_rawcc = n;
            memset(outbuf, 0, (size_t)outbytes);
            extern int NeXTDecode(TIFF *, uint8_t *, tmsize_t, uint16_t);
            ret = NeXTDecode(&tif, outbuf, occ, 0);
        } else { /* 'L' */
            tmsize_t occ = atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t n = load_hex(strtok(NULL, " \t\r\n"));
            if (occ < 0) occ = 0;
            if (occ > (tmsize_t)sizeof(outbuf)) occ = sizeof(outbuf);
            outbytes = occ;
            tif.tif_setupdecode = LZWSetupDecode;
            if (LZWSetupDecode(&tif)) {
                tif.tif_rawdata = inbuf; tif.tif_rawdatasize = n; tif.tif_rawcp = inbuf; tif.tif_rawcc = n;
                memset(outbuf, 0, (size_t)outbytes);
                if (LZWPreDecode(&tif, 0))
                    ret = LZWDecode(&tif, outbuf, occ, 0);
            }
            if (tif.tif_data) {
                LZWCodecState *sp = (LZWCodecState *)tif.tif_data;
                if (sp->dec_codetab) free(sp->dec_codetab);
                free(tif.tif_data);
            }
        }

        printf("R %d %" PRId64 " %08lx %" PRId64 "\n", ret, (int64_t)outbytes,
               fnv32(outbuf, outbytes) & 0xffffffffUL, (int64_t)tif.tif_rawcc);
        printf(".\n");
    }
    return 0;
}
