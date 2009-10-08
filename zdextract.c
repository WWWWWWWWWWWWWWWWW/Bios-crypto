
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "zlib.h"

int main(int argc, char **argv)
{
    char line[LINE_MAX];
    unsigned char *buf;  // EBLOCKSIZE
    long          eblocks = -1;
    int		  eblocknum;
    long          buflen;

    int           zresult;
    uLongf        zlen;
    long	  zblocksize, zbufsize;
    unsigned char *zbuf;
    int           thisarg;
    int           wanted_eblock = -1;

    thisarg = 1;
    if (thisarg < argc) { 
        wanted_eblock = strtol(argv[thisarg], 0, 0);
        thisarg++;
    }

    while (fgets(line, LINE_MAX, stdin) != NULL) {
        if (sscanf(line, "zblock: %x %x", &eblocknum, &zlen) == 2) {
            if (wanted_eblock == -1 || eblocknum == wanted_eblock) {
                fprintf(stderr, "\r%x", eblocknum);
                fflush(stderr);
                fread(zbuf, 1, zlen, stdin);
                buflen = zblocksize;
                if ((zresult = uncompress(buf, &buflen, zbuf, zlen)) != Z_OK) {
                    fprintf(stderr, "Uncompress failure at block 0x%x - %d\n", eblocknum, zresult);
                }
                if (buflen != zblocksize) {
                    fprintf(stderr, "Uncompress resulted in wrong size at block 0x%x - %d\n", eblocknum);
                }
                fwrite(buf, 1, buflen, stdout);
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
        if (sscanf(line, "zblocks: %x %x", &zblocksize, &eblocks) == 2) {
            buf = malloc(zblocksize);
            /*
             * For zlib compress, the destination buffer needs to be 1.001 x the
             * src buffer size plus 12 bytes
             */
            zbufsize = ((zblocksize * 102) / 100) + 12;
            zbuf = malloc(zbufsize);
        }
    }

  out:
    fprintf(stderr, "\n");
    return 0;
}
