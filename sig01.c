#define TFM_DESC
#define OPT_V2 "--v2"
#define OPT_FULLKEY "--fullkey"
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
   char          expiry[256];
   unsigned char buf[4096], rsabuf[2048], md[MAXBLOCKSIZE], sig[512];
   unsigned long buflen, rsalen, mdlen, siglen;
   FILE          *infile;
   int i;
   int           opt_v2      = 0;
   int           opt_fullkey = 0;
   int           argoffset   = 0;

   if (argc < 3) { 
     fprintf(stderr, "Usage: %s [--fullkey] [--v2 expiry] hashname key_file_name [signed_file_name]\n", argv[0]);
     return EXIT_FAILURE;
   }

   LTC_ARGCHK(register_hash(&sha256_desc) != -1);
   LTC_ARGCHK(register_hash(&sha512_desc) != -1);
   LTC_ARGCHK(register_hash(&rmd160_desc) != -1);
   LTC_ARGCHK(register_hash(&whirlpool_desc) != -1);
   LTC_ARGCHK(register_prng(&sprng_desc) != -1);
   ltc_mp = tfm_desc;

   for ( i=1; i < argc; i++) {
     if (strcmp(argv[i], OPT_V2)==0) {
       opt_v2 = 1;
       strncpy(expiry, argv[i+1], 256);
       i++;
       argoffset=argoffset+2;
       continue;
     }
     if (strcmp(argv[i], OPT_FULLKEY)==0) {
       opt_fullkey = 1;
       argoffset++;
       continue;
     }
     /* done! get out softly */
     i=argc;
   }

   hashname = argv[1+argoffset];

   /* get hashes of file */
   mdlen = sizeof(md);
   if ( argc - argoffset > 3) {
     DO(hash_file(find_hash(argv[1+argoffset]), argv[3+argoffset], md, &mdlen));
   } else {
     DO(hash_filehandle(find_hash(argv[1+argoffset]), stdin, md, &mdlen));
   }

   /* read keyblob and import key from it */
   strncpy(fname, argv[2+argoffset], 256);
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
   if (opt_v2==1) {
     fprintf(stdout, "sig02: %s ", hashname);
   } else {
     fprintf(stdout, "sig01: %s ", hashname);
   }

   /* read keyblob and import key from it */
   strncpy(fname, argv[2+argoffset], 256);
   strncat(fname, ".public", 256);
   infile = fopen(fname, "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   if (opt_fullkey==1) {
     i = 0;
   } else {
     i = buflen-32;
   }
   for ( ; i < buflen; i++)
       fprintf(stdout, "%02x", buf[i]);

   fprintf(stdout, " ");

   if (opt_v2==1) {
     fprintf(stdout, expiry);
     fprintf(stdout, " ");
   }

   for (i = 0; i < siglen; i++)
       fprintf(stdout, "%02x", sig[i]);

   fprintf(stdout, "\n");

   rsa_free(&rsakey);

   return EXIT_SUCCESS;
}
