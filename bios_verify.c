#define TFM_DESC
#include "tomcrypt.h"
#include <stdarg.h>

#define DO(x,y) res = (x); if (res != CRYPT_OK && res != CRYPT_NOP) { return res+y; }

#define HEAP_SIZE 48*1024
char heap_mem[HEAP_SIZE];


/** Verify a signature 
   @param hashname	[in] String naming the hash
   @param keydatalen	[in] The length of the public key
   @param keydata	[in] The public key of the signer
   @param sigdatalen	[in] The length of the signature data
   @param sigdata	[in] The signature data
   @param filedatalen	[in] The length of the file in octets
   @param filedata	[in] The contents of the file being verified
   @param ...           [in] Additional len,data pairs until len is 0
   @return nonzero on error [or invalid], 0 on success
   If 
*/
int verify_data(
   char  *hashname,
         unsigned long  keydatalen,
         unsigned char *keydata,
         unsigned long  sigdatalen,
         unsigned char *sigdata,
         unsigned long  filedatalen,
   const unsigned char *filedata, ...)
{
   rsa_key rsakey;
   unsigned char rsabuf[2048], md[MAXBLOCKSIZE];
   unsigned long rsalen, mdlen;
   int           stat;
   int           res;
   va_list args;
   const unsigned char *dataptr;
   unsigned long datalen;
   hash_state hs;
   struct ltc_hash_descriptor *hd;
   int hashid;

   heap_start(heap_mem, HEAP_SIZE);

   if (strcmp(hashname,"des") == 0) {
       symmetric_key skey;
       DO(des_setup(keydata, keydatalen, 0, &skey),0x400000);
       DO(des_ecb_encrypt(filedata, sigdata, &skey),0x500000);
       return res;
   }

   register_hash(&sha256_desc);
//   register_hash(&sha512_desc);
//   register_hash(&whirlpool_desc);
   register_hash(&rmd160_desc);
   register_hash(&md4_desc);
   ltc_mp = tfm_desc;

   hashid = find_hash(hashname);
   if ((res = hash_is_valid(hashid)) != CRYPT_OK)
      return res;

   hd = &hash_descriptor[hashid];
   if ((res = hd->init(&hs)) != CRYPT_OK)
      return res;

   va_start(args, filedata);
   dataptr = filedata;
   datalen = filedatalen;

   for(;;) {
      if((res = hd->process(&hs, dataptr, datalen)) != 0)
         return res;
      if((datalen = va_arg(args, unsigned long)) == 0)
         break;
      if((dataptr = va_arg(args, unsigned char *)) == NULL)
         break;
   }
   va_end(args);

   if (keydatalen == 0) {
       res = hd->done(&hs, sigdata);
       *keydata = hd->hashsize;
       return res+0x100000;
   }

   if((res = hd->done(&hs, md)) != 0)
      return res+0x200000;

   mdlen = hd->hashsize;

   DO(rsa_import(keydata, keydatalen, &rsakey),0x300000);
   DO(rsa_verify_hash(sigdata, sigdatalen, md, mdlen, find_hash(hashname), 8, &stat, &rsakey),0x400000);
   rsa_free(&rsakey);
   return (stat == 0) ? -1 : 0;
}
