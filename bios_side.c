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


/* --- BIOS SUPPORT ROUTINES --- */
int bios_strcmp(const char *s1, const char *s2)
{
   while (*s1 || *s2) {
      if (*s1 > *s2) return 1;
      if (*s1 < *s2) return -1;
      ++s1; ++s2;
   }
   return 0;
}

int bios_memcmp(const void *s1, const void *s2, size_t len)
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

void *bios_memcpy(void *dest, const void *src, size_t len)
{
   unsigned char *d, *s;
   d = dest; s = (unsigned char*)src;
   while (len--) {
     *d++ = *s++;
   }
   return dest;
}

void *bios_memset(void *dest, int c, size_t len)
{
   unsigned char *d;
   d = dest;
   while (len--) {
     *d++ = c;
   }
   return dest;
}

/* required by ASN.1 SET type, but we're not using it ... */
void bios_qsort(void *base, size_t nmemb, size_t size, int(*compar)(const void *, const void *))
{
}

typedef struct _heap_node {
   void       *base;
   size_t      len;
   int         free;
} heap_node;

#define NODES 64
static heap_node heap[NODES];

void bios_heap_start(void *base, size_t s)
{
   heap[0].base = base;
   heap[0].len  = s;
   heap[0].free = 1;
}

void *bios_calloc(size_t p, size_t q)
{
   int x, y;
   size_t r;

   /* find a node free that is p*q in size */
   r = p * q;
   for (x = 0; x < NODES; x++) {
      if (heap[x].base != NULL && heap[x].free == 1 && heap[x].len >= r) {
         break;
      }
   }
   /* if x == NODES we have no node */
   if (x == NODES) return NULL;

   /* now we need a node where base == NULL */   
   for (y = 0; y < NODES; y++) {
      if (x != y && heap[y].base == NULL) {
         break;
      }
   }
   /* if y == NODES we can't split a node */
   if (y == NODES) return NULL;

   /* now split node x into two parts of len-r, and r bytes, the former is free, the latter is not */
   heap[x].len  = heap[x].len - r;
   heap[y].base = heap[x].base + heap[x].len;
   heap[y].len  = r;
   heap[y].free = 0;

   return bios_memset(heap[y].base, 0, heap[y].len);
}

void *bios_malloc(size_t n)
{
   return bios_calloc(1, n);
}

void bios_free(void *p)
{
   int x, y, t;

   /* find it and mark it free */
   for (x = 0; x < NODES; x++) {
      if (heap[x].base == p) break;
   }
   if (x == NODES) {
      // SHOULD NOT GET HERE! 
      printf("invalid free...\n"); for(;;);
   }

   /* join x if possible */
   for (y = 0; y < NODES; y++) {
      if (y != x && heap[y].free == 1 && (heap[y].base + heap[y].len) == heap[x].base) {
         /* heap[y] precedes heap x, merge them */
         heap[y].len += heap[x].len;
         break;
      }
   }

   if (y != NODES) {
      /* heap[x] was merged, zero it */
      heap[x].free = 0;
      heap[x].len  = 0;
      heap[x].base = NULL;
   } else {
      /* could not merge heap[x] ... so sad */
      heap[x].free = 1;
   }

   /* defrag memory */
   do {
     t = 0;
     for (x = 0; x < NODES; x++) {
        for (y = 0; y < NODES; y++) {
            if (x != y && heap[x].base != NULL && heap[y].base != NULL && heap[x].free == 1 && heap[y].free == 1) {
              if (heap[x].base + heap[x].len == heap[y].base) {
                 /* join y to x */
                 t = 1;
                 heap[x].len += heap[y].len;
                 heap[y].len  = 0;
                 heap[y].base = NULL;
                 heap[y].free = 0;
              }
           }
      }
    }
  } while (t == 1);
}

void *bios_realloc(void *p, size_t r)
{
   void *tmp;
   tmp = bios_malloc(r);
   if (tmp == NULL) return NULL;
   XMEMCPY(tmp, p, r);
   bios_free(p);
   return tmp;
}

#ifdef DEBUG
void check_heap(void)
{
   int x;
   size_t heapleft;

   for (x = heapleft = 0; x < NODES; x++) {
      if (heap[x].base != NULL || heap[x].len != 0) {
         printf("Node %d is {%p, %z, %d}\n", x, heap[x].base, heap[x].len, heap[x].free);
      }
      if (heap[x].free) heapleft += heap[x].len;
   }
   printf("Heapleft == %z bytes\n", heapleft);
}
#endif


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
   ecc_key ecckey;
   rsa_key rsakey;
   unsigned char rsabuf[2048], eccbuf[1024], md[2][MAXBLOCKSIZE], sigs[4][512];
   unsigned long rsalen, ecclen, mdlen[2], siglen[4];
   ltc_asn1_list key[2], sig[4];
   int           stat;

   /* get hashes of filedata */
   mdlen[0] = sizeof(md[0]);
   DO(hash_memory(find_hash("whirlpool"), filedata, filedatalen, md[0], &mdlen[0]));
   mdlen[1] = sizeof(md[1]);
   DO(hash_memory(find_hash("sha512"), filedata, filedatalen, md[1], &mdlen[1]));

   /* build ASN1 list */
   LTC_SET_ASN1(key, 0, LTC_ASN1_OCTET_STRING, rsabuf, sizeof(rsabuf));
   LTC_SET_ASN1(key, 1, LTC_ASN1_OCTET_STRING, eccbuf, sizeof(eccbuf));

   /* decode ASN1 */
   DO(der_decode_sequence(keydata, keydatalen, key, 2));

   /* now try to import the RSA/ECC keys */
   DO(rsa_import(key[0].data, key[0].size, &rsakey));
   DO(ecc_import(key[1].data, key[1].size, &ecckey));

   /* build list */
   LTC_SET_ASN1(sig, 0, LTC_ASN1_OCTET_STRING, sigs[0], sizeof(sigs[0]));
   LTC_SET_ASN1(sig, 1, LTC_ASN1_OCTET_STRING, sigs[1], sizeof(sigs[1]));
   LTC_SET_ASN1(sig, 2, LTC_ASN1_OCTET_STRING, sigs[2], sizeof(sigs[2]));
   LTC_SET_ASN1(sig, 3, LTC_ASN1_OCTET_STRING, sigs[3], sizeof(sigs[3]));

   /* DER decode signature */
   DO(der_decode_sequence(sigdata, sigdatalen, sig, 4));

   /* verify signatures */
   fprintf(stderr, "Verifying signatures...\n");

     /* rsa+whirl */
     fprintf(stderr, "\tRSA+WHIRLPOOL\n");
     DO(rsa_verify_hash(sig[0].data, sig[0].size, md[0], mdlen[0], find_hash("whirlpool"), 8, &stat, &rsakey));
     if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); return -1; }   

     /* rsa+SHA512 */
     fprintf(stderr, "\tRSA+SHA512\n");
     DO(rsa_verify_hash(sig[1].data, sig[1].size, md[1], mdlen[1], find_hash("sha512"), 8, &stat, &rsakey));
     if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); return -1; }  

     /* ecc+whirl */
     fprintf(stderr, "\tECC+WHIRLPOOL\n");
     DO(ecc_verify_hash(sig[2].data, sig[2].size, md[0], mdlen[0], &stat, &ecckey));
     if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); return -1; }   

     /* ecc+SHA512 */
     fprintf(stderr, "\tECC+SHA512\n");
     DO(ecc_verify_hash(sig[3].data, sig[3].size, md[1], mdlen[1], &stat, &ecckey));
     if (stat == 0) { fprintf(stderr, "SIGNATURE FAILED\n"); return -1; }  
 
  /* done */
     fprintf(stderr, "Signatures valid\n");
 
   ecc_free(&ecckey);
   rsa_free(&rsakey);
   return 0;
}

#ifdef DEBUG
int main(void)
{
}
#endif

