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

   if (argc < 4) { 
     fprintf(stderr, "%s: hashname key_file_name signed_file_name\n", argv[0]);
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
   DO(hash_file(find_hash(argv[1]), argv[3], md, &mdlen));

   /* read keyblob and import key from it */
   infile = fopen(argv[2], "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   /* now try to import the RSA key */
   DO(rsa_import(buf, buflen, &rsakey));

   /* now sign the hashes */
   fprintf(stderr, "Generating signature...RSA+%s\n", hashname);

   siglen = sizeof(sig);
   DO(rsa_sign_hash(md, mdlen, sig, &siglen, NULL, find_prng("sprng"), find_hash(hashname), 8, &rsakey));

   /* open output file */
   snprintf(fname, sizeof(fname), "%s.%s.sig", argv[3], hashname);
   infile = fopen(fname, "wb");
   LTC_ARGCHK(infile != NULL);
   fwrite(sig, 1, siglen, infile);
   fclose(infile);

   rsa_free(&rsakey);

   return EXIT_SUCCESS;
}
