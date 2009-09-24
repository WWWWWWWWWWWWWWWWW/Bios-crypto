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
   unsigned char rsabuf[2048];
   unsigned long rsalen;
   FILE          *outfile;

   if (argc != 2) { 
     fprintf(stderr, "%s: key_file_name\n", argv[0]);
     return EXIT_FAILURE;
   }

   LTC_ARGCHK(register_prng(&sprng_desc) != -1);
   ltc_mp = tfm_desc;

   /* make keys */
   fprintf(stderr, "Making 2048-bit RSA key...\n");
   DO(rsa_make_key(NULL, find_prng("sprng"), NULL, find_prng("sprng"), 2048/8, 65537, &rsakey));

   /* make the private key */
   /* export them to their own buffers */
   rsalen = sizeof(rsabuf);
   DO(rsa_export(rsabuf, &rsalen, PK_PRIVATE, &rsakey));

   /* open key.priv */
   snprintf(fname, sizeof(fname), "%s.private", argv[1]);
   outfile = fopen(fname, "wb");
   LTC_ARGCHK(outfile != NULL);
   fwrite(rsabuf, 1, rsalen, outfile);
   fclose(outfile);

   /* make the public keys */
   /* export them to their own buffers */
   rsalen = sizeof(rsabuf);
   DO(rsa_export(rsabuf, &rsalen, PK_PUBLIC, &rsakey));

   /* open key.priv */
   snprintf(fname, sizeof(fname), "%s.public", argv[1]);
   outfile = fopen(fname, "wb");
   LTC_ARGCHK(outfile != NULL);
   fwrite(rsabuf, 1, rsalen, outfile);
   fclose(outfile);

   rsa_free(&rsakey);

   return EXIT_SUCCESS;
}
