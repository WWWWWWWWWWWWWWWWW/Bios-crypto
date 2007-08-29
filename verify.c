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
   unsigned char buf[4096], rsabuf[2048], md[MAXBLOCKSIZE];
   unsigned long buflen, rsalen, mdlen;
   char          fname[256];
   FILE          *infile;
   int           stat;
   char          *hashname;

   if (argc < 4) { 
     fprintf(stderr, "%s: hashname key_file_name signed_file_name\n", argv[0]);
     return EXIT_FAILURE;
   }

   LTC_ARGCHK(register_hash(&sha512_desc) != -1);
   LTC_ARGCHK(register_hash(&sha256_desc) != -1);
   LTC_ARGCHK(register_hash(&rmd160_desc) != -1);
   LTC_ARGCHK(register_hash(&whirlpool_desc) != -1);
   ltc_mp = tfm_desc;

   hashname = argv[1];

   /* get hashes of file */
   mdlen = sizeof(md);
   DO(hash_file(find_hash(hashname), argv[3], md, &mdlen));

   /* read keyblob and import keys from it */
   infile = fopen(argv[2], "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   /* now try to import the RSA key */
   DO(rsa_import(buf, buflen, &rsakey));

   /* open file */
   snprintf(fname, sizeof(fname), "%s.%s.sig", argv[3], hashname);
   infile = fopen(fname, "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   /* verify signature */
   fprintf(stderr, "Verifying signature RSA+%s\n", hashname);

   DO(rsa_verify_hash(buf, buflen, md, mdlen, find_hash(hashname), 8, &stat, &rsakey));
   if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); exit(EXIT_FAILURE); }   

   /* done */
   fprintf(stderr, "Signature valid\n");
 
   rsa_free(&rsakey);
 
   return EXIT_SUCCESS;
}
