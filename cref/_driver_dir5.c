/* Op-script driver for strip/tile geometry counts (Slice 5), for certification. One geometry per
   stdin line:
     G <rowsperstrip> <imagelength> <imagewidth> <imagedepth> <planarconfig> <samplesperpixel> \
       <tilewidth> <tilelength> <tiledepth>
   (all decimal; -1 is representable as 4294967295). Builds a reduced TIFF and prints
   G <nstrips> <ntiles>  then . */

static uint32_t TIFFNumberOfStrips(TIFF *tif);
static uint32_t TIFFNumberOfTiles(TIFF *tif);

int main(void) {
    static char line[1 << 16];
    while (fgets(line, sizeof line, stdin)) {
        unsigned long rps, il, iw, id, pc, spp, tw, tl, td;
        if (sscanf(line, "G %lu %lu %lu %lu %lu %lu %lu %lu %lu", &rps, &il, &iw, &id, &pc, &spp,
                   &tw, &tl, &td) < 9)
            continue;

        TIFF tif;
        memset(&tif, 0, sizeof tif);
        tif.tif_dir.td_rowsperstrip = (uint32_t)rps;
        tif.tif_dir.td_imagelength = (uint32_t)il;
        tif.tif_dir.td_imagewidth = (uint32_t)iw;
        tif.tif_dir.td_imagedepth = (uint32_t)id;
        tif.tif_dir.td_planarconfig = (uint16_t)pc;
        tif.tif_dir.td_samplesperpixel = (uint16_t)spp;
        tif.tif_dir.td_tilewidth = (uint32_t)tw;
        tif.tif_dir.td_tilelength = (uint32_t)tl;
        tif.tif_dir.td_tiledepth = (uint32_t)td;

        uint32_t nstrips = TIFFNumberOfStrips(&tif);
        uint32_t ntiles = TIFFNumberOfTiles(&tif);
        printf("G %" PRIu32 " %" PRIu32 "\n", nstrips, ntiles);
        printf(".\n");
    }
    return 0;
}
