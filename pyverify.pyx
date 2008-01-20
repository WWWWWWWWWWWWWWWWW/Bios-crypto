"""Python bindings to libtomcrypt hash and verification routines."""
cdef extern from "pyverify.h":
    enum:
        ERR_NO_INIT
        ERR_NULL_BUF
        ERR_HASH
        ERR_KEY
        ERR_SIG
        ERR_SIG_BAD
    int crypt_verify_file(char *hashname,
                          char *key_contents, unsigned long key_len,
                          char *sig_contents, unsigned long sig_len,
                          char *filename)
    int crypt_verify_buffer(char *hashname,
                            char *key_contents, unsigned long key_len,
                            char *sig_contents, unsigned long sig_len,
                            char *msg_contents, unsigned long msg_len)

def _check(int st):
    if st == 0: return
    msg = "Unknown problem"
    if st == ERR_NO_INIT:
        msg = "Hash initialization error"
    elif st == ERR_NULL_BUF:
        msg = "Null buffer"
    elif st == ERR_HASH:
        msg = "Error hashing file or buffer"
    elif st == ERR_KEY:
        msg = "Error loading key"
    elif st == ERR_SIG:
        msg = "Error performing signature verification"
    elif st == ERR_SIG_BAD:
        msg = "Bad signature"
    raise OSError(msg)

def verify_file(key, filename, sig):
    """Verify the given signature by the given public key on the file with
    the given name.

    Throws OSError on verification error.  Only rsa-sha256 signatures.
    """
    _check(crypt_verify_file("sha256", key, len(key), sig, len(sig), filename))

def verify_buffer(key, buffer, sig):
    """Verify the given signature by the given public key on the given buffer.

    Throws OSError on verification error.  Only rsa-sha256 signatures.
    """
    _check(crypt_verify_buffer("sha256", key, len(key), sig, len(sig),
                               buffer, len(buffer)))
