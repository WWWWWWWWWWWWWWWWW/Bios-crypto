// Handle partitions

#define TFM_DESC
#include "tomcrypt.h"
#include "zlib.h"

#define DO(x) do { run_cmd((x), __LINE__, __FILE__, #x); } while (0);
void run_cmd(int res, int line, char *file, char *cmd)
{
   if (res != CRYPT_OK) {
      fprintf(stderr, "%s (%d)\n%s:%d:%s\n", error_to_string(res), res, file, line, cmd);
      if (res != CRYPT_NOP) {
         exit(EXIT_FAILURE);
      }
   }
}

#define EBLOCK_SIZE 0x20000
/*
 * For zlib compress, the destination buffer needs to be 1.001 x the
 * src buffer size plus 12 bytes
 */
#define ZBUF_EXTRA ((EBLOCK_SIZE / 999) + 12)
// #define ZBUFSIZE (EBLOCK_SIZE + ZBUF_EXTRA)
#define ZBUFSIZE (2 * EBLOCK_SIZE)

int main(int argc, char **argv)
{
    char          *fname;
    char          *hashname;
    unsigned char buf[EBLOCK_SIZE], md[MAXBLOCKSIZE], sig[512];
    unsigned long mdlen;
    FILE          *infile, *outfile;
    long          eblocks, i;
    off_t         insize;
    int		  hashid, readlen;
    int		  j;

    int		  allf;
    int           zresult;
    FILE          *zfile;
    uLongf        zlen;
    unsigned char *p;
    unsigned char zbuf[ZBUFSIZE];

    if (argc < 5) { 
        fprintf(stderr, "%s: hashname signed_file_name spec_file_name zdata_file_name\n", argv[0]);
        return EXIT_FAILURE;
    }

    LTC_ARGCHK(register_hash(&sha256_desc) != -1);
    LTC_ARGCHK(register_hash(&rmd160_desc) != -1);
    LTC_ARGCHK(register_hash(&md5_desc) != -1);
    ltc_mp = tfm_desc;

    hashname = argv[1];
    hashid = find_hash(hashname);
    LTC_ARGCHK(hashid >= 0);

    /* open filesystem image file */
    infile = fopen(argv[2], "rb");
    LTC_ARGCHK(infile != NULL);

    /* open output file */
    outfile = fopen(argv[3], "wb");
    LTC_ARGCHK(outfile != NULL);

    /* open zdata file */
    zfile = fopen(argv[4], "wb");
    LTC_ARGCHK(outfile != NULL);

    (void)fseek(infile, 0L, SEEK_END);
    insize = ftello(infile);
    (void)fseek(infile, 0L, SEEK_SET);

    eblocks = (insize + EBLOCK_SIZE - 1) / EBLOCK_SIZE;
//    LTC_ARGCHK((eblocks * EBLOCK_SIZE) == insize);

    /* Remove possible path prefix */
    fname = strrchr(argv[2], '/');
    if (fname == NULL)
        fname = argv[2];
    else
        ++fname;

    fprintf(outfile, "data: %s\n", fname);
    fprintf(outfile, "zblocks: %x %x\n", EBLOCK_SIZE, eblocks);
    fprintf(zfile,   "zblocks: %x %x\n", EBLOCK_SIZE, eblocks);

    /* make a hash of the file */
    for (i=0; i < eblocks; i++) {
        readlen = fread(buf, 1, EBLOCK_SIZE, infile);
        if (readlen != EBLOCK_SIZE && readlen && i == eblocks-1) {
            for (p = &buf[readlen]; p < &buf[EBLOCK_SIZE]; p++) {
                *p = 0xff;
            }
            readlen = EBLOCK_SIZE;
        }            
        LTC_ARGCHK(readlen == EBLOCK_SIZE);

        allf = 1;
        for (p = (unsigned char *)buf; p < &buf[EBLOCK_SIZE]; p++) {
            if (*p != 0xff) {
                allf = 0;
                break;
            }
        }

        if (!allf) {
            mdlen = sizeof(md);
            DO(hash_memory(hashid, buf, EBLOCK_SIZE, md, &mdlen));

            zlen = ZBUFSIZE;
            if ((zresult = compress(zbuf, &zlen, buf, EBLOCK_SIZE)) != Z_OK) {
                fprintf(stderr, "Compress failure at block 0x%x - %d\n", i, zresult);
            }

            fprintf(outfile, "zblock: %x %x %s ", i, zlen, hashname);
            for(j=0; j<mdlen; j++)
                fprintf(outfile,"%02x",md[j]);
            fprintf(outfile, "\n");

            fprintf(zfile, "zblock: %x %x %s ", i, zlen, hashname);
            for(j=0; j<mdlen; j++)
                fprintf(zfile,"%02x",md[j]);
            fprintf(zfile, "\n");
            fwrite(zbuf, sizeof(char), zlen, zfile);
            fprintf(zfile, "\n");
        }

    }
    fprintf(outfile, "zblocks-end:\n");
    fprintf(zfile,   "zblocks-end:\n");

    fclose(infile);
    fclose(outfile);

    return EXIT_SUCCESS;
}
