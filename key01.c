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

int main(int argc, char **argv)
{
   rsa_key rsakey;
   char          fname[256];
   char          *hashname;
   unsigned char buf[4096], rsabuf[2048], md[MAXBLOCKSIZE], sig[512];
   unsigned long buflen, rsalen, mdlen, siglen;
   FILE          *infile;
   int i;

   if (argc < 2) { 
     fprintf(stderr, "Usage: %s key_file_name\n", argv[0]);
     return EXIT_FAILURE;
   }

   LTC_ARGCHK(register_hash(&sha256_desc) != -1);
   LTC_ARGCHK(register_hash(&sha512_desc) != -1);
   LTC_ARGCHK(register_hash(&rmd160_desc) != -1);
   LTC_ARGCHK(register_hash(&whirlpool_desc) != -1);
   LTC_ARGCHK(register_prng(&sprng_desc) != -1);
   ltc_mp = tfm_desc;

   /* read keyblob and import key from it */
   infile = fopen(argv[1], "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   /* now try to import the RSA key, just to validate it */
   DO(rsa_import(buf, buflen, &rsakey));

   /* open output file */
   fprintf(stdout, "key01: ");
   
   for (i = 0; i < buflen; i++)
       fprintf(stdout, "%02x", buf[i]);

   fprintf(stdout, "\n");

   rsa_free(&rsakey);

   return EXIT_SUCCESS;
}
