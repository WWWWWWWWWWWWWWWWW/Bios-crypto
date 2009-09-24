#include <tomcrypt.h>

int main(void)
{
   unsigned char key[16], data[1000], tag[16];
   int x;
   unsigned long outlen;

   for (x = 0; x <= 0x51; x++) { data[x] = x; };

#if 0
   data[16] = 0x50;
   data[17] = 0x51;
   data[18] = 0x51;
   data[19] = 0x00;
#endif

   for (x = 0; x <= 0x51; x += 4) { printf("%02X%02X %02X%02X\n", data[x+0], data[x+1], data[x+2], data[x+3]); }

   key[ 0] = 0x10;
   key[ 1] = 0xa5;
   key[ 2] = 0x6b;
   key[ 3] = 0x86;
   key[ 4] = 0x8a;
   key[ 5] = 0x64;
   key[ 6] = 0xc2;
   key[ 7] = 0x9e;
   key[ 8] = 0x0e;
   key[ 9] = 0x44;
   key[10] = 0x8e;
   key[11] = 0x44;
   key[12] = 0x77;
   key[13] = 0x25;
   key[14] = 0xe1;
   key[15] = 0xa0;

   printf("\n\n");
   for (x = 0; x < 0x10; x += 4) { printf("%02X%02X %02X%02X\n", key[x+0], key[x+1], key[x+2], key[x+3]); }

   outlen = 16;
   printf("Res: %d\n", omac_memory(register_cipher(&aes_desc), key, 16, data, 0x52, tag, &outlen));
   for (x = 0; x < 16; x++) printf("%02x ", tag[x]); printf("\n");

   return 0;
}
