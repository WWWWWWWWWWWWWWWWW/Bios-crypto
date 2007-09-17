#define TFM_DESC
#include "tomcrypt.h"

enum {
    ERR_NO_INIT = -1,
    ERR_NULL_BUF = -2,
    ERR_HASH = -3,
    ERR_KEY = -4,
    ERR_SIG = -5,
    ERR_SIG_BAD = -6,
};

static int inited = 0;
static int 
_crypt_init() {
    int st;
    if (!inited) {
	if (register_hash(&sha512_desc) == -1) return ERR_NO_INIT;
	if (register_hash(&sha256_desc) == -1) return ERR_NO_INIT;
	if (register_hash(&rmd160_desc) == -1) return ERR_NO_INIT;
	if (register_hash(&whirlpool_desc) == -1) return ERR_NO_INIT;
	ltc_mp = tfm_desc;
	inited = 1;
    }
    return 0; /* success */
}

static int
_crypt_verify(int hash_idx,
	      unsigned char *key_contents, unsigned long key_len,
	      unsigned char *sig_contents, unsigned long sig_len,
	      unsigned char *md, unsigned long mdlen) {
    rsa_key rsakey;
    int st, sig_stat;

    if (!(key_contents && sig_contents))
	return ERR_NULL_BUF;

    /* now try to import the RSA key */
    st = rsa_import(key_contents, key_len, &rsakey);
    if (st != CRYPT_OK) return ERR_KEY;

    /* verify signature */
    st = rsa_verify_hash(sig_contents, sig_len, md, mdlen, hash_idx, 8, &sig_stat, &rsakey);
    if (st != CRYPT_OK) return ERR_SIG;
    if (sig_stat == 0) return ERR_SIG_BAD;
    
    /* done */
    rsa_free(&rsakey);
    
    return 0; /* success! */
}

static int 
crypt_verify_file(char *hashname,
		  unsigned char *key_contents, unsigned long key_len,
		  unsigned char *sig_contents, unsigned long sig_len,
		  char *filename) {
    unsigned char md[MAXBLOCKSIZE];
    unsigned long mdlen;
    int hash_idx, st;

    if (!(hashname && filename))
	return ERR_NULL_BUF;

    /* initialize the hash list */
    st = _crypt_init();
    if (st != 0) return st;
    
    /* get hashes of file */
    mdlen = sizeof(md);
    hash_idx = find_hash(hashname);
    st = hash_file(hash_idx, filename, md, &mdlen);
    if (st != CRYPT_OK) return ERR_HASH;

    return _crypt_verify(hash_idx, key_contents, key_len,
			 sig_contents, sig_len, md, mdlen);
}

static int 
crypt_verify_buffer(char *hashname,
		    unsigned char *key_contents, unsigned long key_len,
		    unsigned char *sig_contents, unsigned long sig_len,
		    unsigned char *msg_contents, unsigned long msg_len) {
    unsigned char md[MAXBLOCKSIZE];
    unsigned long mdlen;
    int hash_idx, st;

    if (!(hashname && msg_contents))
	return ERR_NULL_BUF;

    /* initialize the hash list */
    st = _crypt_init();
    if (st != 0) return st;
    
    /* get hashes of buffer */
    mdlen = sizeof(md);
    hash_idx = find_hash(hashname);
    st = hash_memory(hash_idx, msg_contents, msg_len,
		     md, &mdlen);
    if (st != CRYPT_OK) return ERR_HASH;

    return _crypt_verify(hash_idx, key_contents, key_len,
			 sig_contents, sig_len, md, mdlen);
}
