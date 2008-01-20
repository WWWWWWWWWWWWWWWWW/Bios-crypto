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

   if (argc < 3) { 
     fprintf(stderr, "Usage: %s hashname key_file_name [signed_file_name]\n", argv[0]);
     return EXIT_FAILURE;
   }

   LTC_ARGCHK(register_hash(&sha256_desc) != -1);
   LTC_ARGCHK(register_hash(&sha512_desc) != -1);
   LTC_ARGCHK(register_hash(&rmd160_desc) != -1);
   LTC_ARGCHK(register_hash(&whirlpool_desc) != -1);
   LTC_ARGCHK(register_prng(&sprng_desc) != -1);
   ltc_mp = tfm_desc;

   hashname = argv[1];

   /* get hashes of file */
   mdlen = sizeof(md);
   if (argc > 3) {
     DO(hash_file(find_hash(argv[1]), argv[3], md, &mdlen));
   } else {
     DO(hash_filehandle(find_hash(argv[1]), stdin, md, &mdlen));
   }

   /* read keyblob and import key from it */
   strncpy(fname, argv[2], 256);
   strncat(fname, ".private", 256);
   infile = fopen(fname, "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   /* now try to import the RSA key */
   DO(rsa_import(buf, buflen, &rsakey));

   /* now sign the hashes */
   siglen = sizeof(sig);
   DO(rsa_sign_hash(md, mdlen, sig, &siglen, NULL, find_prng("sprng"), find_hash(hashname), 8, &rsakey));

   /* open output file */
   fprintf(stdout, "sig01: %s ", hashname);
   
   /* read keyblob and import key from it */
   strncpy(fname, argv[2], 256);
   strncat(fname, ".public", 256);
   infile = fopen(fname, "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   for (i = buflen-32; i < buflen; i++)
       fprintf(stdout, "%02x", buf[i]);

   fprintf(stdout, " ");

   for (i = 0; i < siglen; i++)
       fprintf(stdout, "%02x", sig[i]);

   fprintf(stdout, "\n");

   rsa_free(&rsakey);

   return EXIT_SUCCESS;
}
