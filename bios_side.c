#define TFM_DESC
#include "tomcrypt.h"

#ifdef DEBUG
#define printk(...) fprintf(stderr, __VA_ARGS__);
#else
#define printk(...)
#endif

#define DO(x) do { run_cmd((x), __LINE__, __FILE__, #x); } while (0);
void run_cmd(int res, int line, char *file, char *cmd)
{
   if (res != CRYPT_OK) {
      printk( "%s (%d)\n%s:%d:%s\n", error_to_string(res), res, file, line, cmd);
      if (res != CRYPT_NOP) {
         exit(EXIT_FAILURE);
      }
   }
}


/* --- BIOS SUPPORT ROUTINES --- */
int strcmp(const char *s1, const char *s2)
{
   while (*s1 || *s2) {
      if (*s1 > *s2) return 1;
      if (*s1 < *s2) return -1;
      ++s1; ++s2;
   }
   return 0;
}

int memcmp(const void *s1, const void *s2, size_t len)
{
   unsigned char *t1, *t2;
   t1 = (unsigned char*)s1; t2 = (unsigned char*)s2;
   while (len--) {
      if (*t1 > *t2) return 1;
      if (*t1 < *t2) return -1;
      ++t1; ++t2;
   }
   return 0;
}

void *memcpy(void *dest, const void *src, size_t len)
{
   unsigned char *d, *s;
   d = dest; s = (unsigned char*)src;
   while (len--) {
     *d++ = *s++;
   }
   return dest;
}

void *memset(void *dest, int c, size_t len)
{
   unsigned char *d;
   d = dest;
   while (len--) {
     *d++ = c;
   }
   return dest;
}

/* required by ASN.1 SET type, but we're not using it ... */
void qsort(void *base, size_t nmemb, size_t size, int(*compar)(const void *, const void *))
{
}

/* --- END OF BIOS SUPPORT ROUTINES --- */


/** Verify a signature 
   @param filedata	[in] The contents of the file being verified
   @param filedatalen	[in] The length of the file in octets
   @param keydata	[in] The public key of the signer
   @param keydatalen	[in] The length of the public key
   @param sigdata	[in] The signature data
   @param sigdatalen	[in] The length of the signature data
   @return -1 on error [or invalid], 0 on success
*/
int verify_data(
   const unsigned char *filedata,
         unsigned long  filedatalen,
   const unsigned char *keydata,
         unsigned long  keydatalen,
   const unsigned char *sigdata,
         unsigned long  sigdatalen)
{
#ifdef USE_ECC
   ecc_key ecckey;
   unsigned char eccbuf[1024];
   unsigned long ecclen;
#endif
   rsa_key rsakey;
   unsigned char rsabuf[2048], md[2][MAXBLOCKSIZE], sigs[4][512];
   unsigned long rsalen, mdlen[2], siglen[4];
   ltc_asn1_list key[2], sig[4];
   int           stat;

   /* get hashes of filedata */
   mdlen[0] = sizeof(md[0]);
   DO(hash_memory(find_hash("whirlpool"), filedata, filedatalen, md[0], &mdlen[0]));
   mdlen[1] = sizeof(md[1]);
   DO(hash_memory(find_hash("sha512"), filedata, filedatalen, md[1], &mdlen[1]));

   /* build ASN1 list */
   LTC_SET_ASN1(key, 0, LTC_ASN1_OCTET_STRING, rsabuf, sizeof(rsabuf));
#ifdef USE_ECC
   LTC_SET_ASN1(key, 1, LTC_ASN1_OCTET_STRING, eccbuf, sizeof(eccbuf));
#endif

   /* decode ASN1 */
   DO(der_decode_sequence(keydata, keydatalen, key, 2));

   /* now try to import the RSA/ECC keys */
   DO(rsa_import(key[0].data, key[0].size, &rsakey));
#ifdef USE_ECC
   DO(ecc_import(key[1].data, key[1].size, &ecckey));
#endif

   /* build list */
   LTC_SET_ASN1(sig, 0, LTC_ASN1_OCTET_STRING, sigs[0], sizeof(sigs[0]));
   LTC_SET_ASN1(sig, 1, LTC_ASN1_OCTET_STRING, sigs[1], sizeof(sigs[1]));
   LTC_SET_ASN1(sig, 2, LTC_ASN1_OCTET_STRING, sigs[2], sizeof(sigs[2]));
   LTC_SET_ASN1(sig, 3, LTC_ASN1_OCTET_STRING, sigs[3], sizeof(sigs[3]));

   /* DER decode signature */
   DO(der_decode_sequence(sigdata, sigdatalen, sig, 4));

   /* verify signatures */
   printk("Verifying signatures...\n");

     /* rsa+whirl */
     printk( "\tRSA+WHIRLPOOL\n");
     DO(rsa_verify_hash(sig[0].data, sig[0].size, md[0], mdlen[0], find_hash("whirlpool"), 8, &stat, &rsakey));
     if (stat == 0) { printk( "SIGNATURE FAILED\n"); return -1; }   

     /* rsa+SHA512 */
     printk( "\tRSA+SHA512\n");
     DO(rsa_verify_hash(sig[1].data, sig[1].size, md[1], mdlen[1], find_hash("sha512"), 8, &stat, &rsakey));
     if (stat == 0) { printk( "SIGNATURE FAILED\n"); return -1; }  

#ifdef USE_ECC
     /* ecc+whirl */
     printk( "\tECC+WHIRLPOOL\n");
     DO(ecc_verify_hash(sig[2].data, sig[2].size, md[0], mdlen[0], &stat, &ecckey));
     if (stat == 0) { printk( "SIGNATURE FAILED\n"); return -1; }   

     /* ecc+SHA512 */
     printk( "\tECC+SHA512\n");
     DO(ecc_verify_hash(sig[3].data, sig[3].size, md[1], mdlen[1], &stat, &ecckey));
     if (stat == 0) { printk( "SIGNATURE FAILED\n"); return -1; }  
#endif
 
  /* done */
     printk( "Signatures valid\n");
 
#ifdef USE_ECC
   ecc_free(&ecckey);
#endif
   rsa_free(&rsakey);
   return 0;
}

#ifdef DEBUG

const unsigned char keydata[] = {
0x30, 0x82, 0x01, 0xa7, 0x04, 0x82, 0x01, 0x0e, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 
0x00, 0xeb, 0xfa, 0x7b, 0x72, 0xc5, 0x63, 0x2e, 0xb6, 0xf6, 0x8c, 0x3f, 0x0d, 0x89, 0x51, 0x79, 
0x5f, 0xbf, 0xbd, 0x08, 0x90, 0xea, 0x59, 0x7a, 0x7a, 0x58, 0x23, 0xe7, 0x82, 0xb3, 0x49, 0x45, 
0xcd, 0x87, 0x2f, 0xbb, 0xea, 0xb0, 0xd1, 0x0a, 0x7b, 0xec, 0x63, 0x0b, 0x49, 0x6d, 0xb1, 0x66, 
0x6e, 0x83, 0x4c, 0xf7, 0x4f, 0x90, 0x7a, 0xc5, 0x1c, 0x9e, 0xdc, 0xc8, 0xdd, 0x60, 0x48, 0x9d, 
0xfc, 0x2b, 0xc3, 0x53, 0xb0, 0x02, 0xeb, 0x99, 0x28, 0x07, 0x5f, 0x95, 0x44, 0x91, 0x64, 0xe8, 
0x69, 0x93, 0x9e, 0x16, 0x49, 0xa8, 0x58, 0x14, 0x01, 0xf4, 0xbb, 0xa2, 0x0a, 0x8f, 0x80, 0x77, 
0xd0, 0x86, 0x7a, 0xbb, 0x6a, 0xa4, 0xd6, 0x6c, 0x87, 0xe3, 0x01, 0xf2, 0xdf, 0x74, 0xb3, 0xb4, 
0x74, 0x3b, 0x29, 0x73, 0xd3, 0x06, 0x8e, 0x3e, 0xe6, 0xa4, 0x72, 0xd2, 0xb2, 0xbb, 0x57, 0x7e, 
0x9b, 0xa9, 0x0d, 0xe1, 0x9f, 0x21, 0x96, 0x2c, 0x58, 0xee, 0x6c, 0xc8, 0x38, 0xf4, 0x3f, 0x62, 
0x55, 0xbd, 0x03, 0x48, 0xfb, 0xf3, 0xf4, 0xf6, 0xb9, 0xde, 0x4d, 0xaf, 0x11, 0x49, 0x22, 0x38, 
0x18, 0x50, 0x0e, 0xb1, 0xc7, 0x5a, 0x48, 0x8b, 0xd3, 0x02, 0x92, 0x5c, 0xbc, 0xdb, 0x63, 0x02, 
0x2a, 0xeb, 0x85, 0x3e, 0x6a, 0x54, 0x4f, 0xf4, 0xf6, 0xec, 0xfb, 0xbb, 0xae, 0x98, 0x01, 0x2b, 
0x5b, 0xe4, 0x10, 0x83, 0x1f, 0xbe, 0xc6, 0xa0, 0x2a, 0xb0, 0xe6, 0x81, 0xb4, 0x8b, 0x72, 0x9e, 
0x96, 0x78, 0x84, 0xdc, 0x46, 0xd1, 0xa6, 0xfc, 0xa4, 0x59, 0x92, 0x57, 0x90, 0x16, 0xf7, 0x38, 
0xa9, 0x5d, 0x58, 0xe1, 0x49, 0x25, 0xce, 0x44, 0x5b, 0x06, 0x93, 0x9f, 0xe9, 0xc1, 0x96, 0x7d, 
0xef, 0x12, 0xbb, 0x55, 0xa0, 0xb0, 0xec, 0xef, 0xda, 0x0a, 0xc9, 0x6c, 0x55, 0xd2, 0x3f, 0xac, 
0xf9, 0x02, 0x03, 0x01, 0x00, 0x01, 0x04, 0x81, 0x92, 0x30, 0x81, 0x8f, 0x03, 0x02, 0x07, 0x00, 
0x02, 0x01, 0x42, 0x02, 0x42, 0x00, 0x9f, 0x19, 0x9d, 0xb9, 0x06, 0xd1, 0x09, 0x19, 0x90, 0x5d, 
0x42, 0x53, 0xaf, 0x00, 0x96, 0x8e, 0xb2, 0x93, 0xcf, 0xcd, 0x70, 0xf2, 0x41, 0xc0, 0x85, 0xd9, 
0xa4, 0xef, 0x2c, 0xaf, 0x29, 0x51, 0x56, 0x4c, 0x97, 0x27, 0x96, 0x57, 0x3b, 0x1b, 0xd8, 0x93, 
0xb8, 0x0b, 0xd7, 0xbc, 0xf2, 0xd3, 0xac, 0x91, 0x26, 0x0e, 0x3f, 0xad, 0xca, 0x4f, 0x64, 0xad, 
0x2f, 0xa3, 0x35, 0xc9, 0xfa, 0xd8, 0x29, 0x02, 0x42, 0x00, 0xc0, 0x8b, 0x73, 0xc2, 0x6d, 0xb3, 
0x3f, 0x40, 0xc2, 0x12, 0x27, 0x7a, 0xe5, 0x01, 0x2b, 0x99, 0x0d, 0x40, 0x45, 0x53, 0xb9, 0xaa, 
0x92, 0x51, 0x46, 0x80, 0x65, 0x73, 0x76, 0xba, 0xbd, 0xa0, 0x9f, 0xae, 0x9a, 0x48, 0x5b, 0xeb, 
0xea, 0x73, 0x8f, 0x11, 0x0f, 0xfc, 0xf0, 0xe2, 0xfa, 0x94, 0xbf, 0xd4, 0xd2, 0xb5, 0x1b, 0x8e, 
0x02, 0x5f, 0x66, 0xaa, 0x88, 0x74, 0xa9, 0xdb, 0x3e, 0x0a, 0xec, 
};

const unsigned char filedata[] = {
0x77, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x0a, 
};

const unsigned char sigdata[] = {
0x30, 0x82, 0x03, 0x21, 0x04, 0x82, 0x01, 0x00, 0xb0, 0x1b, 0xa5, 0x24, 0x7e, 0x5d, 0x21, 0xb7, 
0x0a, 0x30, 0xaf, 0x9f, 0x5c, 0xd1, 0x8a, 0xe8, 0x18, 0x07, 0xf2, 0xbe, 0x7d, 0xd4, 0x7c, 0xe7, 
0x3f, 0x4b, 0xdc, 0x5b, 0xcb, 0x52, 0x66, 0xc3, 0x91, 0xa3, 0x96, 0x89, 0xb6, 0x07, 0x46, 0x6e, 
0xba, 0xba, 0x8b, 0x96, 0x02, 0x75, 0x11, 0xd6, 0x80, 0x07, 0x99, 0x46, 0x13, 0x58, 0xe4, 0x59, 
0xbe, 0x82, 0x32, 0x04, 0x85, 0x31, 0x7d, 0x78, 0xe7, 0xae, 0x90, 0x3b, 0x1a, 0x0a, 0x6d, 0xe9, 
0x70, 0x7c, 0xc3, 0xa3, 0x30, 0x05, 0xbc, 0x1a, 0xa5, 0x7f, 0x0e, 0x89, 0x85, 0x6b, 0x6e, 0xe2, 
0x31, 0xdb, 0x83, 0xde, 0x85, 0x45, 0x16, 0xb3, 0x96, 0x87, 0x42, 0xf2, 0x20, 0x78, 0x3b, 0x94, 
0xe4, 0xf5, 0x91, 0x74, 0xf0, 0xd2, 0x11, 0x19, 0x6f, 0x1a, 0xf7, 0xed, 0x8f, 0xb4, 0x8a, 0xce, 
0xa9, 0xfc, 0xec, 0x64, 0x5e, 0x03, 0x85, 0xc6, 0x61, 0x16, 0xa4, 0x21, 0x66, 0x54, 0x05, 0xf4, 
0x52, 0x9c, 0x4f, 0x32, 0xb9, 0x4d, 0x0c, 0x35, 0x1c, 0x76, 0x7f, 0xf9, 0x63, 0x0f, 0x85, 0x08, 
0x9f, 0x28, 0x8e, 0x91, 0xcc, 0x69, 0xda, 0x78, 0xd1, 0x3e, 0x6b, 0x3d, 0xc1, 0x56, 0xc8, 0x83, 
0xc4, 0x3c, 0x77, 0xa3, 0x54, 0xbb, 0x9f, 0x62, 0x0f, 0x99, 0x7f, 0xd0, 0x88, 0x3c, 0x83, 0x12, 
0xb5, 0xa3, 0xd1, 0x90, 0x22, 0x8b, 0x15, 0x85, 0x6e, 0x32, 0x01, 0x9f, 0x6c, 0x7a, 0x08, 0xf4, 
0x90, 0x7d, 0x8b, 0x8c, 0xa8, 0x12, 0x6e, 0x74, 0xd3, 0xb6, 0x2e, 0x49, 0x7d, 0xc9, 0xbc, 0x51, 
0x3f, 0x11, 0xae, 0x2f, 0x50, 0x68, 0x98, 0x29, 0x12, 0x99, 0x4d, 0x31, 0x04, 0x5c, 0x91, 0x32, 
0x7e, 0x00, 0x3a, 0x09, 0x0c, 0x34, 0x0e, 0x52, 0x33, 0x7e, 0x44, 0x9c, 0xdf, 0x77, 0x41, 0x44, 
0x61, 0xf9, 0x84, 0x30, 0x09, 0xf3, 0x5f, 0xa1, 0x04, 0x82, 0x01, 0x00, 0x34, 0xca, 0xf5, 0xc0, 
0xf0, 0x1a, 0x5d, 0xa0, 0x68, 0x41, 0x9f, 0x9d, 0xa1, 0x3e, 0x85, 0x57, 0xd6, 0xe4, 0x69, 0x5b, 
0xca, 0x0c, 0xcd, 0x57, 0x34, 0x25, 0xe3, 0xde, 0x07, 0x26, 0x95, 0x99, 0x0d, 0x64, 0xa6, 0x7d, 
0x75, 0x94, 0xa8, 0xa4, 0x73, 0xdd, 0xa2, 0x70, 0x95, 0x93, 0x20, 0xd7, 0xe9, 0xa5, 0x2c, 0xed, 
0x63, 0x73, 0xd4, 0x43, 0x63, 0xee, 0x6c, 0x56, 0xdb, 0x98, 0x44, 0xa0, 0xdb, 0xe7, 0xe6, 0x3b, 
0x8c, 0x03, 0x17, 0x4e, 0xb0, 0x2e, 0xe2, 0xed, 0x2b, 0x0d, 0x93, 0xd5, 0xdc, 0x87, 0x43, 0x52, 
0xe9, 0x57, 0x24, 0x1d, 0xd7, 0xe7, 0x14, 0x12, 0xf6, 0x1a, 0xb9, 0x98, 0xee, 0x0c, 0x9e, 0xe2, 
0xa4, 0xf6, 0x89, 0xad, 0x59, 0xb2, 0xb0, 0x71, 0x2e, 0x0e, 0x20, 0xb6, 0xd0, 0xfd, 0x39, 0xe9, 
0x50, 0x45, 0x5d, 0xb7, 0x48, 0x41, 0x1f, 0x6c, 0x61, 0x8f, 0x38, 0xcc, 0xf3, 0xfa, 0xf5, 0xae, 
0xb3, 0xbd, 0xf3, 0xc7, 0xd8, 0x50, 0x1b, 0x87, 0x9a, 0x4f, 0x97, 0xe4, 0xe4, 0x5c, 0x2f, 0xe7, 
0x6a, 0xde, 0xec, 0x31, 0x3d, 0x69, 0x1f, 0xab, 0x61, 0xd4, 0x74, 0xb7, 0x3f, 0x1f, 0xea, 0x09, 
0x14, 0x80, 0xd1, 0x7b, 0x6e, 0xb9, 0x4b, 0x39, 0x67, 0xcc, 0xfc, 0x45, 0xa5, 0x11, 0x1c, 0xc5, 
0xb3, 0xd6, 0xad, 0xec, 0xbe, 0x14, 0x28, 0xd0, 0xa0, 0x7e, 0xec, 0x36, 0xdf, 0x19, 0x27, 0xb1, 
0xfa, 0x55, 0x81, 0x99, 0x92, 0x03, 0x20, 0xa7, 0xf7, 0xa5, 0x04, 0x0b, 0x4b, 0x86, 0xd7, 0xa3, 
0x77, 0xc6, 0x85, 0xae, 0x5c, 0xb8, 0x74, 0xb4, 0xfe, 0xe6, 0x5e, 0x65, 0xf9, 0x65, 0xa5, 0xe0, 
0xe7, 0x9b, 0xa7, 0x77, 0x79, 0x97, 0x2c, 0x58, 0xf3, 0x4c, 0x35, 0x43, 0x99, 0x9d, 0x39, 0x1e, 
0x78, 0x2e, 0x3b, 0x36, 0x8d, 0x4c, 0xf8, 0x6d, 0x85, 0x53, 0x9d, 0x08, 0x04, 0x81, 0x89, 0x30, 
0x81, 0x86, 0x02, 0x41, 0x1b, 0x13, 0x11, 0x27, 0xe2, 0x81, 0xd5, 0xae, 0x7b, 0xae, 0xe6, 0x4e, 
0xd5, 0x02, 0xc0, 0x25, 0x9a, 0x75, 0x30, 0x0e, 0x62, 0x9d, 0xdc, 0x8a, 0xda, 0xc7, 0xa7, 0xb8, 
0xd5, 0x94, 0x23, 0xac, 0xd7, 0x0a, 0x7c, 0x16, 0xe1, 0x6e, 0x6c, 0xbb, 0x19, 0xaf, 0xa9, 0x23, 
0x5c, 0x5f, 0xcb, 0xf6, 0xf7, 0x34, 0xdf, 0x4a, 0xd9, 0xea, 0xf1, 0xb8, 0x03, 0x68, 0xb1, 0x30, 
0x97, 0x25, 0xa6, 0x42, 0xbd, 0x02, 0x41, 0x17, 0xe9, 0x5e, 0x42, 0xe4, 0x78, 0xd6, 0xac, 0x11, 
0x9d, 0x10, 0x82, 0x70, 0xe0, 0x52, 0xf7, 0x5c, 0xac, 0x05, 0x3b, 0xb4, 0xa0, 0xb3, 0x75, 0x45, 
0x53, 0xb3, 0xd7, 0x2f, 0x0e, 0x6b, 0x96, 0x28, 0x2c, 0xf5, 0xe6, 0x05, 0xd7, 0xbb, 0x33, 0x15, 
0xe2, 0x37, 0x31, 0x4e, 0x61, 0x51, 0xf6, 0x04, 0xc7, 0x20, 0x10, 0xb4, 0xdf, 0x9b, 0xe3, 0x87, 
0x51, 0x21, 0x15, 0xd2, 0x64, 0x7b, 0xc5, 0x42, 0x04, 0x81, 0x8a, 0x30, 0x81, 0x87, 0x02, 0x42, 
0x01, 0x52, 0x58, 0xf4, 0xc0, 0x07, 0xf2, 0x97, 0x86, 0xc8, 0xf8, 0x07, 0x3c, 0x8f, 0xcc, 0x09, 
0x24, 0x1f, 0x96, 0x6b, 0xc6, 0xb8, 0x28, 0xf8, 0x16, 0xdf, 0x1f, 0xfd, 0xbf, 0xd7, 0x42, 0x2d, 
0x3f, 0xa0, 0x40, 0x84, 0xdc, 0xa7, 0x52, 0x80, 0xf5, 0xc3, 0x2e, 0x4f, 0x74, 0xf5, 0xe5, 0x24, 
0x6e, 0x7c, 0xb1, 0xbd, 0x63, 0x4b, 0xaa, 0x84, 0xb3, 0xcf, 0xd1, 0xfa, 0x45, 0xda, 0x76, 0x77, 
0x12, 0x7a, 0x02, 0x41, 0x5c, 0xd1, 0x44, 0x2d, 0x58, 0x7a, 0x4d, 0x24, 0x06, 0x30, 0xd0, 0x00, 
0xad, 0x38, 0x15, 0xea, 0x4c, 0x9e, 0xcb, 0x6c, 0xdf, 0x37, 0x87, 0x4d, 0x0b, 0x9f, 0x1e, 0xc1, 
0x40, 0x16, 0xa1, 0x45, 0x66, 0x52, 0xb0, 0x64, 0x15, 0x3a, 0xad, 0x13, 0x23, 0x11, 0x1e, 0x53, 
0xd8, 0xa4, 0xd7, 0x70, 0x32, 0x8c, 0xfb, 0x54, 0x61, 0xd1, 0x52, 0xeb, 0x0c, 0xd1, 0x8b, 0xfd, 
0x06, 0x88, 0x64, 0xcc, 0x2d, 
};

#define HEAP_SIZE 0x40000
char heap_mem[HEAP_SIZE];
int main(void)
{
   heap_start(heap_mem, HEAP_SIZE);
   register_hash(&sha512_desc);
   register_hash(&whirlpool_desc);
   ltc_mp = tfm_desc;
   
   /* you would call this with other parameters, but I'm lazy and only made one signature/keypair
    * called it multiple times to check for leaks 
    */
   if (verify_data(filedata, sizeof(filedata), keydata, sizeof(keydata), sigdata, sizeof(sigdata)) != 0) {
     printk("verify_data == -1, uh oh\n") return 0;
   }
#ifdef NOTDEF
   if (verify_data(filedata, sizeof(filedata), keydata, sizeof(keydata), sigdata, sizeof(sigdata)) != 0) {
     printk("verify_data == -1, uh oh\n") return 0;
   }
   if (verify_data(filedata, sizeof(filedata), keydata, sizeof(keydata), sigdata, sizeof(sigdata)) != 0) {
     printk("verify_data == -1, uh oh\n") return 0;
   }
   if (verify_data(filedata, sizeof(filedata), keydata, sizeof(keydata), sigdata, sizeof(sigdata)) != 0) {
     printk("verify_data == -1, uh oh\n") return 0;
   }
#endif
   check_heap();
   return 0;
}
#endif

