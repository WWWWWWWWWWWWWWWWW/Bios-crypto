#define TFM_DESC
#include "tomcrypt.h"

#define HEAP_SIZE 64*1024
char heap_mem[HEAP_SIZE];

/** Compute a whirlpool hash
   @param filedata	[in] The contents of the file being verified
   @param filedatalen	[in] The length of the file in octets
   @param resultdata	[in] Where to put the result
   @param resultlen	[out] Length of the result
   @return 0 on sucess, else error code
*/
int bios_hash(
   const unsigned char *hashname,
   const unsigned char *filedata,
         unsigned long  filedatalen,
         unsigned char *resultdata,
         unsigned long *resultlen
)
{
   int           res;

   heap_start(heap_mem, HEAP_SIZE);
   register_hash(&sha256_desc);
   register_hash(&sha512_desc);
   register_hash(&whirlpool_desc);

   /* get hashes of filedata */
   *resultlen = MAXBLOCKSIZE;
   res = hash_memory(find_hash(hashname), filedata, filedatalen, resultdata, resultlen);

   return res;
}
