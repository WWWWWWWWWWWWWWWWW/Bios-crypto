#define TFM_DESC
#include "tomcrypt.h"

#define DO(x) res = (x); if (res != CRYPT_OK && res != CRYPT_NOP) { return res; }

#define HEAP_SIZE 64*1024
char heap_mem[HEAP_SIZE];

/** Verify a signature 
   @param hashes	[in] Bitmap of hashes to try
   @param filedata	[in] The contents of the file being verified
   @param filedatalen	[in] The length of the file in octets
   @param keydata	[in] The public key of the signer
   @param keydatalen	[in] The length of the public key
   @param sigdata	[in] The signature data
   @param sigdatalen	[in] The length of the signature data
   @return -1 on error [or invalid], 0 on success
*/
int verify_data(
   int   hashes,
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
   int           res;

   heap_start(heap_mem, HEAP_SIZE);
   register_hash(&sha256_desc);
   register_hash(&sha512_desc);
   register_hash(&whirlpool_desc);
   ltc_mp = tfm_desc;

   /* get hashes of filedata */
   if (hashes & 5) {
      mdlen[0] = sizeof(md[0]);
      DO(hash_memory(find_hash("whirlpool"), filedata, filedatalen, md[0], &mdlen[0]));
   }
   if (hashes & 0xa) {
      mdlen[1] = sizeof(md[1]);
      DO(hash_memory(find_hash("sha512"), filedata, filedatalen, md[1], &mdlen[1]));
   }

   /* build ASN1 list */
   if (hashes & 3) {
       LTC_SET_ASN1(key, 0, LTC_ASN1_OCTET_STRING, rsabuf, sizeof(rsabuf));
   }
#ifdef USE_ECC
   if (hashes & 0xc) {
       LTC_SET_ASN1(key, 1, LTC_ASN1_OCTET_STRING, eccbuf, sizeof(eccbuf));
   }
#endif

   /* decode ASN1 */
   DO(der_decode_sequence(keydata, keydatalen, key, 2));

   /* now try to import the RSA/ECC keys */
   if (hashes & 3) {
       DO(rsa_import(key[0].data, key[0].size, &rsakey));
   }
#ifdef USE_ECC
   if (hashes & 0xc) {
       DO(ecc_import(key[1].data, key[1].size, &ecckey));
   }
#endif

   /* build list */
   if (hashes & (1<<0)) {
       LTC_SET_ASN1(sig, 0, LTC_ASN1_OCTET_STRING, sigs[0], sizeof(sigs[0]));
   }
   if (hashes & (1<<1)) {
       LTC_SET_ASN1(sig, 1, LTC_ASN1_OCTET_STRING, sigs[1], sizeof(sigs[1]));
   }
#ifdef USE_ECC
   if (hashes & (1<<2)) {
       LTC_SET_ASN1(sig, 2, LTC_ASN1_OCTET_STRING, sigs[2], sizeof(sigs[2]));
   }
   if (hashes & (1<<3)) {
       LTC_SET_ASN1(sig, 3, LTC_ASN1_OCTET_STRING, sigs[3], sizeof(sigs[3]));
   }
#endif

   /* DER decode signature */
   DO(der_decode_sequence(sigdata, sigdatalen, sig, 4));

   /* verify signatures */

   if (hashes & (1<<0)) {
      /* rsa+whirl */
      DO(rsa_verify_hash(sig[0].data, sig[0].size, md[0], mdlen[0], find_hash("whirlpool"), 8, &stat, &rsakey));
      if (stat == 0) { return -1; }
   }

   if (hashes & (1<<1)) {
      /* rsa+SHA512 */
      DO(rsa_verify_hash(sig[1].data, sig[1].size, md[1], mdlen[1], find_hash("sha512"), 8, &stat, &rsakey));
      if (stat == 0) { return -1; }
   }

#ifdef USE_ECC
   if (hashes & (1<<2)) {
      /* ecc+whirl */
      DO(ecc_verify_hash(sig[2].data, sig[2].size, md[0], mdlen[0], &stat, &ecckey));
      if (stat == 0) { return -1; }
   }

   if (hashes & (1<<3)) {
      /* ecc+SHA512 */
      DO(ecc_verify_hash(sig[3].data, sig[3].size, md[1], mdlen[1], &stat, &ecckey));
      if (stat == 0) { return -1; }
   }
#endif

   /* done */
#ifdef USE_ECC
   ecc_free(&ecckey);
#endif
   rsa_free(&rsakey);
   return 0;
}
