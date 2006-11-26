#ifndef OLPC_CRYPTO_H_
#define OLPC_CRYPTO_H_

/* number of bytes in the RSA modulus, default 2048-bit modulus */
#define RSA_MODULUS_SIZE 256

/* bytes per ECC coordinate, ECC-256 assumed */
#define ECC_COORD_SIZE 32

/* SHA-256 a block of memory */
void sha256_memory(const unsigned char *in,
                         unsigned long  len,
                         unsigned char *dst);

int rsa_verify(const unsigned char *signature,
               const unsigned char *hash,
               const unsigned char *modulus,
                               int *result);

int ecc_verify(const unsigned char *signature,
               const unsigned char *hash,
               const unsigned char *pubkey,
                               int *result);

#endif
