#include <string.h>
#include <stdlib.h>

// #define DEBUG
// #define TRACE_ALLOC

#ifdef DEBUG
#include <stdio.h>
#define printk(...) fprintf(stderr, __VA_ARGS__);
#else
#define printk(...)
#endif

void *heap_ptr;
void *heap_low;
void *heap_high;

/** Setup the memory allocator
  @param base      The base of free memory
  @param s         The size in octets (should be at least 64KB)
*/
void heap_start(void *base, size_t s)
{
   heap_low = base;
   heap_high = base + s;
   heap_ptr = heap_high;
}

void *calloc(size_t p, size_t q)
{
   size_t len;

#ifdef TRACE_ALLOC
   printk("calloc %x %x ", p, q); fflush(stderr);
#endif

   /* find a node free that is p*q in size */
   len = (((p * q) + 3) & ~3) + sizeof(int) ;

   if (heap_ptr - len < heap_low) {
#ifdef DEBUG 
   printk("Tried to allocate %lu bytes\n", len);
#endif
      return NULL;
   }

   heap_ptr -= len;
   *(int *)heap_ptr = len;

#ifdef TRACE_ALLOC
   printk("-> %x\n", heap_ptr+sizeof(int));
#endif

   return memset(heap_ptr+sizeof(int), 0, len-sizeof(int));
}

void *malloc(size_t n)
{
   return calloc(1, n);
}

void free(void *p)
{
   int x, y, t;

#ifdef TRACE_ALLOC
   printk("free %x\n", p);
#endif

   if (heap_ptr + sizeof(int) != p) {
       printk("mismatched free %x\n", p);
       return;
   }

   heap_ptr += *(int *)heap_ptr;
}

void check_heap(void)
{
    if (heap_ptr != heap_high) {
        printk("Heap not clean\n");
    }
}
