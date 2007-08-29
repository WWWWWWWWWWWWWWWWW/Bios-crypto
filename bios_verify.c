#define TFM_DESC
#include "tomcrypt.h"

#define DO(x) res = (x); if (res != CRYPT_OK && res != CRYPT_NOP) { return res; }

#define HEAP_SIZE 48*1024
char heap_mem[HEAP_SIZE];

/** Verify a signature 
   @param hashname	[in] String naming the hash
   @param filedata	[in] The contents of the file being verified
   @param filedatalen	[in] The length of the file in octets
   @param keydata	[in] The public key of the signer
   @param keydatalen	[in] The length of the public key
   @param sigdata	[in] The signature data
   @param sigdatalen	[in] The length of the signature data
   @return -1 on error [or invalid], 0 on success
*/
int verify_data(
   char  *hashname,
   const unsigned char *filedata,
         unsigned long  filedatalen,
   const unsigned char *keydata,
         unsigned long  keydatalen,
   const unsigned char *sigdata,
         unsigned long  sigdatalen)
{
   rsa_key rsakey;
   unsigned char rsabuf[2048], md[MAXBLOCKSIZE];
   unsigned long rsalen, mdlen;
   int           stat;
   int           res;

   heap_start(heap_mem, HEAP_SIZE);
   register_hash(&sha256_desc);
//   register_hash(&sha512_desc);
//   register_hash(&whirlpool_desc);
   register_hash(&rmd160_desc);
   ltc_mp = tfm_desc;

   mdlen = sizeof(md);
   DO(hash_memory(find_hash(hashname), filedata, filedatalen, md, &mdlen));
   DO(rsa_import(keydata, keydatalen, &rsakey));
   DO(rsa_verify_hash(sigdata, sigdatalen, md, mdlen, find_hash(hashname), 8, &stat, &rsakey));
   rsa_free(&rsakey);
   return (stat == 0) ? -1 : 0;
}
