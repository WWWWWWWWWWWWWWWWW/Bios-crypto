#define TFM_DESC
#include "tomcrypt.h"

#ifdef USE_SHA512
#define SHANAME "sha512"
#define SHADESC &sha512_desc
#else
#define SHANAME "sha256"
#define SHADESC &sha256_desc
#endif

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

void setup_crypto(void)
{
   LTC_ARGCHK(register_hash(SHADESC) != -1);
   LTC_ARGCHK(register_hash(&whirlpool_desc) != -1);
   LTC_ARGCHK(register_prng(&sprng_desc) != -1);
   ltc_mp = tfm_desc;
}

void make_keys(char **argv)
{
#ifdef USE_ECC
   ecc_key ecckey;
   unsigned char eccbuf[1024];
   unsigned long ecclen;
#endif
   rsa_key rsakey;
   char          fname[256];
   unsigned char buf[4096], rsabuf[2048];
   unsigned long buflen, rsalen;
   ltc_asn1_list key[2];
   FILE          *outfile;

   /* make keys */
   fprintf(stderr, "Making 2048-bit RSA key...\n");
   DO(rsa_make_key(NULL, find_prng("sprng"), NULL, find_prng("sprng"), 2048/8, 65537, &rsakey));

#ifdef USE_ECC
   fprintf(stderr, "Making 521-bit ECC key...\n");
   DO(ecc_make_key(NULL, find_prng("sprng"), 521/8, &ecckey));
#endif

   /* make the private keys */
   /* export them to their own buffers */
   rsalen = sizeof(rsabuf);
   DO(rsa_export(rsabuf, &rsalen, PK_PRIVATE, &rsakey));
#ifdef USE_ECC
   ecclen = sizeof(eccbuf);
   DO(ecc_export(eccbuf, &ecclen, PK_PRIVATE, &ecckey));
#endif

   /* build ASN1 list */
   LTC_SET_ASN1(key, 0, LTC_ASN1_OCTET_STRING, rsabuf, rsalen);
#ifdef USE_ECC
   LTC_SET_ASN1(key, 1, LTC_ASN1_OCTET_STRING, eccbuf, ecclen);
#endif

   /* encode SEQUENCE */
   buflen = sizeof(buf);
#ifdef USE_ECC
   DO(der_encode_sequence(key, 2, buf, &buflen));
#else
   DO(der_encode_sequence(key, 1, buf, &buflen));
#endif

   /* open key.priv */
   snprintf(fname, sizeof(fname), "%s.private", argv[2]);
   outfile = fopen(fname, "wb");
   LTC_ARGCHK(outfile != NULL);
   fwrite(buf, 1, buflen, outfile);
   fclose(outfile);

   /* make the public keys */
   /* export them to their own buffers */
   rsalen = sizeof(rsabuf);
   DO(rsa_export(rsabuf, &rsalen, PK_PUBLIC, &rsakey));
#ifdef USE_ECC
   ecclen = sizeof(eccbuf);
   DO(ecc_export(eccbuf, &ecclen, PK_PUBLIC, &ecckey));
#endif

   /* build ASN1 list */
   LTC_SET_ASN1(key, 0, LTC_ASN1_OCTET_STRING, rsabuf, rsalen);
#ifdef USE_ECC
   LTC_SET_ASN1(key, 1, LTC_ASN1_OCTET_STRING, eccbuf, ecclen);
#endif

   /* encode SEQUENCE */
   buflen = sizeof(buf);
#ifdef USE_ECC
   DO(der_encode_sequence(key, 2, buf, &buflen));
#else
   DO(der_encode_sequence(key, 1, buf, &buflen));
#endif

   /* open key.priv */
   snprintf(fname, sizeof(fname), "%s.public", argv[2]);
   outfile = fopen(fname, "wb");
   LTC_ARGCHK(outfile != NULL);
   fwrite(buf, 1, buflen, outfile);
   fclose(outfile);

#ifdef USE_ECC
   ecc_free(&ecckey);
#endif
   rsa_free(&rsakey);
}

void sign_data(char **argv)
{
#ifdef USE_ECC
   ecc_key ecckey;
   unsigned char eccbuf[1024];
   unsigned long ecclen;
#endif
   rsa_key rsakey;
   char          fname[256];
   unsigned char buf[4096], rsabuf[2048], md[2][MAXBLOCKSIZE], sigs[4][512];
   unsigned long buflen, rsalen, mdlen[2], siglen[4];
   ltc_asn1_list key[2], sig[4];
   FILE          *infile;

   /* get hashes of file */
   mdlen[0] = sizeof(md[0]);
   DO(hash_file(find_hash("whirlpool"), argv[3], md[0], &mdlen[0]));
   mdlen[1] = sizeof(md[1]);
   DO(hash_file(find_hash(SHANAME), argv[3], md[1], &mdlen[1]));

   /* read keyblob and import keys from it */
   infile = fopen(argv[2], "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   /* build ASN1 list */
   LTC_SET_ASN1(key, 0, LTC_ASN1_OCTET_STRING, rsabuf, sizeof(rsabuf));
#ifdef USE_ECC
   LTC_SET_ASN1(key, 1, LTC_ASN1_OCTET_STRING, eccbuf, sizeof(eccbuf));
#endif

   /* decode ASN1 */
#ifdef USE_ECC
   DO(der_decode_sequence(buf, buflen, key, 2));
#else
   DO(der_decode_sequence(buf, buflen, key, 1));
#endif

   /* now try to import the RSA/ECC keys */
   DO(rsa_import(key[0].data, key[0].size, &rsakey));
#ifdef USE_ECC
   DO(ecc_import(key[1].data, key[1].size, &ecckey));
#endif

   /* now sign the hashes */
   fprintf(stderr, "Generating signatures...\n");
     /* RSA+whirlpool */
     siglen[0] = sizeof(sigs[0]);
     fprintf(stderr, "\tRSA+WHIRLPOOLx\n");
     DO(rsa_sign_hash(md[0], mdlen[0], sigs[0], &siglen[0], NULL, find_prng("sprng"), find_hash("whirlpool"), 8, &rsakey));
     fprintf(stderr, "buf %x len %x buf[len-1] %x\n", sigs[0], siglen[0], sigs[0][0xff]);

     /* RSA+sha */
     siglen[1] = sizeof(sigs[1]);
     fprintf(stderr, "\tRSA+" SHANAME "\n");
     DO(rsa_sign_hash(md[1], mdlen[1], sigs[1], &siglen[1], NULL, find_prng("sprng"), find_hash(SHANAME), 8, &rsakey));

     fprintf(stderr, "buf %x len %x buf[len-1] %x\n", sigs[1], siglen[1], sigs[1][siglen[1]-1]);

#ifdef USE_ECC
     /* ECC+whirlpool */
     siglen[2] = sizeof(sigs[2]);
     fprintf(stderr, "\tECC+WHIRLPOOL\n");
     DO(ecc_sign_hash(md[0], mdlen[0], sigs[2], &siglen[2], NULL, find_prng("sprng"), &ecckey));
   
     /* ECC+SHA */
     siglen[3] = sizeof(sigs[3]);
     fprintf(stderr, "\tECC+" SHANAME "\n");
     DO(ecc_sign_hash(md[1], mdlen[1], sigs[3], &siglen[3], NULL, find_prng("sprng"), &ecckey));
#endif

   /* build list */
   LTC_SET_ASN1(sig, 0, LTC_ASN1_OCTET_STRING, sigs[0], siglen[0]);
   LTC_SET_ASN1(sig, 1, LTC_ASN1_OCTET_STRING, sigs[1], siglen[1]);
#ifdef USE_ECC
   LTC_SET_ASN1(sig, 2, LTC_ASN1_OCTET_STRING, sigs[2], siglen[2]);
   LTC_SET_ASN1(sig, 3, LTC_ASN1_OCTET_STRING, sigs[3], siglen[3]);
#endif

   /* encode it */
   buflen = sizeof(buf);
#ifdef USE_ECC
   DO(der_encode_sequence(sig, 4, buf, &buflen));
#else
   DO(der_encode_sequence(sig, 2, buf, &buflen));
#endif

   /* open output file */
   snprintf(fname, sizeof(fname), "%s.sig", argv[3]);
   infile = fopen(fname, "wb");
   LTC_ARGCHK(infile != NULL);
   fwrite(buf, 1, buflen, infile);
   fclose(infile);

#ifdef USE_ECC
   ecc_free(&ecckey);
#endif
   rsa_free(&rsakey);
}

void verify_data(char **argv)
{
#ifdef USE_ECC
   ecc_key ecckey;
   unsigned char eccbuf[1024];
   unsigned long ecclen;
#endif
   rsa_key rsakey;
   char          fname[256];
   unsigned char buf[4096], rsabuf[2048], md[2][MAXBLOCKSIZE], sigs[4][512];
   unsigned long buflen, rsalen, mdlen[2], siglen[4];
   ltc_asn1_list key[2], sig[4];
   FILE          *infile;
   int           stat;

   /* get hashes of file */
   mdlen[0] = sizeof(md[0]);
   DO(hash_file(find_hash("whirlpool"), argv[3], md[0], &mdlen[0]));
   mdlen[1] = sizeof(md[1]);
   DO(hash_file(find_hash(SHANAME), argv[3], md[1], &mdlen[1]));

   /* read keyblob and import keys from it */
   infile = fopen(argv[2], "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   /* build ASN1 list */
   LTC_SET_ASN1(key, 0, LTC_ASN1_OCTET_STRING, rsabuf, sizeof(rsabuf));
#ifdef USE_ECC
   LTC_SET_ASN1(key, 1, LTC_ASN1_OCTET_STRING, eccbuf, sizeof(eccbuf));
#endif

   /* decode ASN1 */
#ifdef USE_ECC
   DO(der_decode_sequence(buf, buflen, key, 2));
#else
   DO(der_decode_sequence(buf, buflen, key, 1));
#endif

   /* now try to import the RSA/ECC keys */
   DO(rsa_import(key[0].data, key[0].size, &rsakey));
#ifdef USE_ECC
   DO(ecc_import(key[1].data, key[1].size, &ecckey));
#endif

   /* build list */
   LTC_SET_ASN1(sig, 0, LTC_ASN1_OCTET_STRING, sigs[0], sizeof(sigs[0]));
   LTC_SET_ASN1(sig, 1, LTC_ASN1_OCTET_STRING, sigs[1], sizeof(sigs[1]));
#ifdef USE_ECC
   LTC_SET_ASN1(sig, 2, LTC_ASN1_OCTET_STRING, sigs[2], sizeof(sigs[2]));
   LTC_SET_ASN1(sig, 3, LTC_ASN1_OCTET_STRING, sigs[3], sizeof(sigs[3]));
#endif

   /* open file */
   snprintf(fname, sizeof(fname), "%s.sig", argv[3]);
   infile = fopen(fname, "rb");
   LTC_ARGCHK(infile != NULL);
   buflen = fread(buf, 1, sizeof(buf), infile);
   fclose(infile);

   /* DER decode it */
#ifdef USE_ECC
   DO(der_decode_sequence(buf, buflen, sig, 4));
#else
   DO(der_decode_sequence(buf, buflen, sig, 2));
#endif

   /* verify signatures */
   fprintf(stderr, "Verifying signatures...\n");

     /* rsa+whirl */
     fprintf(stderr, "\tRSA+WHIRLPOOL\n");
     DO(rsa_verify_hash(sig[0].data, sig[0].size, md[0], mdlen[0], find_hash("whirlpool"), 8, &stat, &rsakey));
     if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); exit(EXIT_FAILURE); }   

     /* rsa+SHA */
     fprintf(stderr, "\tRSA+" SHANAME "\n");
     DO(rsa_verify_hash(sig[1].data, sig[1].size, md[1], mdlen[1], find_hash(SHANAME), 8, &stat, &rsakey));
     if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); exit(EXIT_FAILURE); }  

#ifdef USE_ECC
     /* ecc+whirl */
     fprintf(stderr, "\tECC+WHIRLPOOL\n");
     DO(ecc_verify_hash(sig[2].data, sig[2].size, md[0], mdlen[0], &stat, &ecckey));
     if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); exit(EXIT_FAILURE); }   

     /* ecc+SHA */
     fprintf(stderr, "\tECC+" SHANAME "\n");
     DO(ecc_verify_hash(sig[3].data, sig[3].size, md[1], mdlen[1], &stat, &ecckey));
     if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); exit(EXIT_FAILURE); }  
#endif
 
  /* done */
     fprintf(stderr, "Signatures valid\n");
 
#ifdef USE_ECC
   ecc_free(&ecckey);
#endif
   rsa_free(&rsakey);
}

int main(int argc, char **argv)
{
   if (argc < 3) { 
     fprintf(stderr, "%s: -makekey|-sign|-verify [options]\n", argv[0]);
     return EXIT_FAILURE;
   }

   setup_crypto();


   if (strcmp(argv[1], "-makekey") == 0) {
      make_keys(argv);
   } else if (strcmp(argv[1], "-sign") == 0) {
      if (argc < 4) { fprintf(stderr, "Not enough args for -sign\n"); return EXIT_FAILURE; }
      sign_data(argv);
   } else if (strcmp(argv[1], "-verify") == 0) {
      if (argc < 4) { fprintf(stderr, "Not enough args for -verify\n"); return EXIT_FAILURE; }
      verify_data(argv);
   } else {
      fprintf(stderr, "Unknown option [%s]\n", argv[1]);
      return EXIT_FAILURE;
   }
 
   return EXIT_SUCCESS;
}
