/* In-process callable wrapper over the codec dispatcher, for differential fuzzing. Same
   op-script logic as _driver.c's per-line body — same trace grammar, same field-by-field
   formatting — just returning the trace via a caller-owned buffer (open_memstream) instead of
   printing it, and taking one already-decoded line directly instead of reading a stdin line via
   fgets. Keep in lockstep with _driver.c's per-case body — any behavioral difference here
   invalidates the differential-fuzz oracle. Matches _driver.c's empty-line semantics: a line
   with no codec tag produces no output at all. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static unsigned long fnv32(const uint8_t *p, tmsize_t n) {
    unsigned long h = 2166136261UL;
    tmsize_t i;
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h = (h * 16777619UL) & 0xffffffffUL;
    }
    return h;
}

static uint8_t fz_inbuf[1 << 20];
static uint8_t fz_outbuf[1 << 20];

static tmsize_t load_hex(const char *hex) {
    tmsize_t n = 0;
    if (!hex)
        return 0;
    for (long i = 0; hex[2 * i] && hex[2 * i + 1]; i++) {
        int hi = hexval((unsigned char)hex[2 * i]);
        int lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            break;
        if (n >= (tmsize_t)sizeof(fz_inbuf))
            break;
        fz_inbuf[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

char *run_case_c(const uint8_t *linebytes, size_t n, size_t *outlen) {
    char *buf = NULL;
    size_t bufsz = 0;
    FILE *out = open_memstream(&buf, &bufsz);
    if (!out) {
        *outlen = 0;
        return NULL;
    }

    char *mline = (char *)malloc(n + 1);
    if (!mline) {
        fclose(out);
        *outlen = bufsz;
        return buf;
    }
    memcpy(mline, linebytes, n);
    mline[n] = '\0';

    char *codec = strtok(mline, " \t\r\n");
    if (codec) {
        char c = codec[0];

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_row = 0;

        tmsize_t outbytes = 0;
        int ret = 0;

        if (c == 'P') {
            tmsize_t occ = atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t nn = load_hex(strtok(NULL, " \t\r\n"));
            if (occ < 0)
                occ = 0;
            if (occ > (tmsize_t)sizeof(fz_outbuf))
                occ = sizeof(fz_outbuf);
            outbytes = occ;
            tif.tif_rawdata = fz_inbuf;
            tif.tif_rawdatasize = nn;
            tif.tif_rawcp = fz_inbuf;
            tif.tif_rawcc = nn;
            memset(fz_outbuf, 0, (size_t)outbytes);
            extern int PackBitsDecode(TIFF *, uint8_t *, tmsize_t, uint16_t);
            ret = PackBitsDecode(&tif, fz_outbuf, occ, 0);
        } else if (c == 'T') {
            tmsize_t maxpixels = atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t nn = load_hex(strtok(NULL, " \t\r\n"));
            if (maxpixels < 0)
                maxpixels = 0;
            /* See the matching comment in _driver.c: clamp maxpixels itself so it can never
               disagree with the clamped output-buffer size below. */
            if (maxpixels > 2 * (tmsize_t)sizeof(fz_outbuf) - 1)
                maxpixels = 2 * (tmsize_t)sizeof(fz_outbuf) - 1;
            outbytes = (maxpixels + 1) / 2;
            if (outbytes > (tmsize_t)sizeof(fz_outbuf))
                outbytes = sizeof(fz_outbuf);
            tif.tif_rawdata = fz_inbuf;
            tif.tif_rawdatasize = nn;
            tif.tif_rawcp = fz_inbuf;
            tif.tif_rawcc = nn;
            memset(fz_outbuf, 0, (size_t)outbytes);
            extern int ThunderDecode(TIFF *, uint8_t *, tmsize_t);
            ret = ThunderDecode(&tif, fz_outbuf, maxpixels);
        } else if (c == 'N') {
            tmsize_t occ = atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t scan = atol(strtok(NULL, " \t\r\n") ?: "1");
            uint32_t iw = (uint32_t)atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t nn = load_hex(strtok(NULL, " \t\r\n"));
            if (occ < 0)
                occ = 0;
            if (occ > (tmsize_t)sizeof(fz_outbuf))
                occ = sizeof(fz_outbuf);
            if (scan <= 0)
                scan = 1;
            outbytes = occ;
            tif.tif_scanlinesize = scan;
            tif.tif_dir.td_imagewidth = iw;
            tif.tif_flags = 0;
            tif.tif_rawdata = fz_inbuf;
            tif.tif_rawdatasize = nn;
            tif.tif_rawcp = fz_inbuf;
            tif.tif_rawcc = nn;
            memset(fz_outbuf, 0, (size_t)outbytes);
            extern int NeXTDecode(TIFF *, uint8_t *, tmsize_t, uint16_t);
            ret = NeXTDecode(&tif, fz_outbuf, occ, 0);
        } else { /* 'L' */
            tmsize_t occ = atol(strtok(NULL, " \t\r\n") ?: "0");
            tmsize_t nn = load_hex(strtok(NULL, " \t\r\n"));
            if (occ < 0)
                occ = 0;
            if (occ > (tmsize_t)sizeof(fz_outbuf))
                occ = sizeof(fz_outbuf);
            outbytes = occ;
            tif.tif_setupdecode = LZWSetupDecode;
            if (LZWSetupDecode(&tif)) {
                tif.tif_rawdata = fz_inbuf;
                tif.tif_rawdatasize = nn;
                tif.tif_rawcp = fz_inbuf;
                tif.tif_rawcc = nn;
                memset(fz_outbuf, 0, (size_t)outbytes);
                if (LZWPreDecode(&tif, 0))
                    ret = LZWDecode(&tif, fz_outbuf, occ, 0);
            }
            if (tif.tif_data) {
                LZWCodecState *sp = (LZWCodecState *)tif.tif_data;
                if (sp->dec_codetab)
                    free(sp->dec_codetab);
                free(tif.tif_data);
            }
        }

        fprintf(out, "R %d %" PRId64 " %08lx %" PRId64 "\n", ret, (int64_t)outbytes,
                fnv32(fz_outbuf, outbytes) & 0xffffffffUL, (int64_t)tif.tif_rawcc);
        fprintf(out, ".\n");
    }

    free(mline);
    fclose(out);
    *outlen = bufsz;
    return buf;
}

void free_case_c(char *p) {
    free(p);
}
