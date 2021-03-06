#include <string.h>
#include <stdlib.h>

#ifdef DEBUG
#include <stdio.h>
#define printk(...) fprintf(stderr, __VA_ARGS__);
#else
#define printk(...)
#endif

typedef struct _heap_node {
   void       *base;
   size_t      len;
   int         free;
} heap_node;

#define NODES 128
static heap_node heap[NODES];

/** Setup the memory allocator
  @param base      The base of free memory
  @param s         The size in octets (should be at least 64KB)
*/
void heap_start(void *base, size_t s)
{
   memset(heap, 0, sizeof(heap));
   heap[0].base = base;
   heap[0].len  = s;
   heap[0].free = 1;
}

void *calloc(size_t p, size_t q)
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
   if (x == NODES) { 
      return NULL;
   }

   /* now we need a node where base == NULL */   
   for (y = 0; y < NODES; y++) {
      if (x != y && heap[y].base == NULL) {
         break;
      }
   }
   /* no room to split a node, can't allocate mem */
   if (y == NODES) { 
      return NULL;
   }

   /* now split node x into two parts of len-r, and r bytes, the former is free, the latter is not */
   heap[x].len  = heap[x].len - r;
   heap[y].base = heap[x].base + heap[x].len;
   heap[y].len  = r;
   heap[y].free = 0;

   return memset(heap[y].base, 0, heap[y].len);
}

void *malloc(size_t n)
{
   return calloc(1, n);
}

void free(void *p)
{
   int x, y, t;

   /* find it and mark it free */
   for (x = 0; x < NODES; x++) {
      if (heap[x].base == p) break;
   }
   if (x == NODES) {
      for(;;);
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

   /* defrag memory (kids: don't try this at home) */
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

#ifdef NOTDEF
void *realloc(void *p, size_t r)
{
   void *tmp;
   tmp = malloc(r);
   if (tmp == NULL) return NULL;
   XMEMCPY(tmp, p, r);
   free(p);
   return tmp;
}
#endif

/* --- END OF BIOS SUPPORT ROUTINES --- */
