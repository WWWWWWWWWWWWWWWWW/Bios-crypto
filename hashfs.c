#define TFM_DESC
#include "tomcrypt.h"

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

int main(int argc, char **argv)
{
    char          *fname;
    char          *hashname;
    unsigned char buf[EBLOCK_SIZE], md[MAXBLOCKSIZE], sig[512];
    unsigned long mdlen;
    FILE          *infile, *outfile;
    long          eblocks, insize, i;
    int		  hashid, readlen;
    int		  j;

    if (argc < 3) { 
        fprintf(stderr, "%s: hashname signed_file_name [ output_file_name ] \n", argv[0]);
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
    if (argc == 4) {
        outfile = fopen(argv[3], "wb");
        LTC_ARGCHK(outfile != NULL);
    } else {
        outfile = stdout;
    }

    (void)fseek(infile, 0L, SEEK_END);
    insize = ftell(infile);
    (void)fseek(infile, 0L, SEEK_SET);

    eblocks = insize / EBLOCK_SIZE;
    LTC_ARGCHK((eblocks * EBLOCK_SIZE) == insize);

    /* Remove possible path prefix */
    fname = strrchr(argv[2], '/');
    if (fname == NULL)
        fname = argv[2];
    else
        ++fname;

//  fprintf(outfile, "data: %s\n", fname);
    fprintf(outfile, "erase-all\n");
    fprintf(outfile, "mark-pending: 0\n");

    /* make a hash of the file */
    for (i=0; i < eblocks; i++) {
        readlen = fread(buf, 1, EBLOCK_SIZE, infile);
        LTC_ARGCHK(readlen == EBLOCK_SIZE);
        mdlen = sizeof(md);
        DO(hash_memory(hashid, buf, EBLOCK_SIZE, md, &mdlen));

        fprintf(outfile, "eblock: %x %s ", i, hashname);
        for(j=0; j<mdlen; j++)
            fprintf(outfile,"%02x",md[j]);
        fprintf(outfile, "\n");
    }
    fprintf(outfile, "cleanmarkers\n");
    fprintf(outfile, "mark-complete: 0\n");

    fclose(infile);
    if (outfile != stdout)
        fclose(outfile);

    return EXIT_SUCCESS;
}
