#include <tomcrypt.h>

#if 0
36527 DES: Key
36527 DES:    0xc122f931              word 0      byte 0
36527 DES:    0xc580c449              word 1      byte 4
36527 DES:    0x17bc4fe0              word 2      byte 8
36527 DES:    0xa8575468              word 3      byte 12
36527 DES:    0x1a4d91d2              word 4      byte 16
36527 DES:    0xe5d4e6b6              word 5      byte 20
36527 DES: Plain Text
36527 DES:    0x0fa07e57              word 0      byte 0
36527 DES:    0x9776f2b8              word 1      byte 4 
#endif

int main(void)
{
   unsigned char key[24], pt[8], ct[8];
   symmetric_key skey;
   int x;

   STORE32H(0xc122f931, key+0);
   STORE32H(0xc580c449, key+4);
   STORE32H(0x17bc4fe0, key+8);
   STORE32H(0xa8575468, key+12);
   STORE32H(0x1a4d91d2, key+16);
   STORE32H(0xe5d4e6b6, key+20);
   STORE32H(0x0fa07e57, pt+0);
   STORE32H(0x9776f2b8, pt+4);
   des3_setup(key, 24, 0, &skey);
   des3_ecb_encrypt(pt, ct, &skey);
   for (x = 0; x < 8; x++)  printf("%02x ", ct[x]); printf("\n");
   return 0;
}
