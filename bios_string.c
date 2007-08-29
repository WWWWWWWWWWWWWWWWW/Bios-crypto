#include <string.h>
#include <stdlib.h>

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
