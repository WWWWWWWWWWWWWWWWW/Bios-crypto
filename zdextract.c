// Converts .zd files to raw binary - either the entire file
// or specific blocks.
//
// Usage: zdextract [ blockno ..] <file.zd >file.img
//
// With no arguments, extracts the entire file, otherwise
// extracts the specified block numbers, which must be in
// ascending order.  blockno can be in decimal, octal,
// or hex, using C number syntax.

#define _LARGEFILE_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "zlib.h"

#ifdef NO_FSEEKO
#define off_t long
#define fseeko fseek
#endif

int main(int argc, char **argv)
{
    char line[LINE_MAX];
    unsigned char *buf;  // EBLOCKSIZE
    long          eblocks = -1;
    int           eblocknum;
    long          buflen;

    int           zresult;
    uLongf        zlen;
    long          zblocksize, zbufsize;
    unsigned char *zbuf;
    int           thisarg;
    int           wanted_eblock = -1;

    thisarg = 1;
    if (thisarg < argc) {
        wanted_eblock = strtol(argv[thisarg], 0, 0);
        thisarg++;
    }

    while (fgets(line, LINE_MAX, stdin) != NULL) {
        if (sscanf(line, "zblock: %x %lx", &eblocknum, &zlen) == 2) {
            if (wanted_eblock == -1 || eblocknum == wanted_eblock) {
                fprintf(stderr, "\r%.4x", eblocknum);
                fflush(stderr);
                if (fread(zbuf, 1, zlen, stdin) != zlen) {
                    fprintf(stderr, "Short read at block 0x%x\n", eblocknum);
                    exit(1);
                }
                buflen = zblocksize;
                if ((zresult = uncompress(buf, &buflen, zbuf, zlen)) != Z_OK) {
                    fprintf(stderr,
                            "Uncompress failure at block 0x%x - %d\n",
                            eblocknum, zresult);
                }
                if (buflen != zblocksize) {
                    fprintf(stderr,
                            "Uncompressed buffer bad size (%ld) at block 0x%x\n",
                            buflen, eblocknum);
                }
                if (fseeko(stdout, (off_t)eblocknum * (off_t)zblocksize,
                           SEEK_SET)) {
                    perror("fseek");
                    exit(1);
                }
                if (fwrite(buf, 1, buflen, stdout) < buflen) {
                    perror("fwrite");
                    exit(1);
                }
                if (thisarg < argc) {
                    wanted_eblock = strtol(argv[thisarg], 0, 0);
                    thisarg++;
                } else if (wanted_eblock != -1) {
                    goto out;
                }
            } else {
                fseek(stdin, zlen+1, SEEK_CUR);
            }
        }
        if (sscanf(line, "zblocks: %lx %lx", &zblocksize, &eblocks) == 2) {
            buf = malloc(zblocksize);
            /*
             * For zlib compress, the destination buffer needs to be
             * 1.001 x the src buffer size plus 12 bytes
             */
            zbufsize = ((zblocksize * 102) / 100) + 12;
            zbuf = malloc(zbufsize);
        }
    }

  out:
    fprintf(stderr, "\n");
    return 0;
}
