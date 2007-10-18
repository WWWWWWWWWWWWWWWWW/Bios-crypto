"""Python bindings to libtomcrypt hash and signature routines."""
from binascii import hexlify
cdef extern from "Python.h":
    object PyString_FromStringAndSize(char *, int)
cdef extern from "pysign.h":
    enum:
        ERR_NO_INIT
        ERR_NULL_BUF
        ERR_HASH
        ERR_KEY
        ERR_SIG
        ERR_SIG_BAD
    int crypt_sign_file(char *hashname,
                        char *private_key_contents,
                        unsigned long private_key_len,
                        char *sig_contents, unsigned long *sig_len_p,
                        char *filename)
    int crypt_sign_buffer(char *hashname,
                          char *private_key_contents,
                          unsigned long private_key_len,
                          char *sig_contents, unsigned long *sig_len_p,
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
        msg = "Error performing signature creation"
    elif st == ERR_SIG_BAD:
        msg = "Bad signature"
    raise OSError(msg)

def sign_file(private_key, filename, hash='sha256'):
    """Sign the file with the given name with the given private key.

    Throws OSError on signature error.  Only rsa-sha256/rsa-rmd160 signatures.
    """
    cdef char sig[4096]
    cdef unsigned long  siglen
    siglen = sizeof(sig)
    _check(crypt_sign_file(hash, private_key, len(private_key),
                           sig, &siglen, filename))
    return PyString_FromStringAndSize(sig, siglen)

def sign_buffer(private_key, buffer, hash='sha256'):
    """Sign the given buffer with the given private key.

    Throws OSError on verification error.  Only rsa-sha256/rsa-rmd160 signatures.
    """
    cdef char sig[4096]
    cdef unsigned long  siglen
    siglen = sizeof(sig)
    _check(crypt_sign_buffer(hash, private_key, len(private_key),
                             sig, &siglen, buffer, len(buffer)))
    return PyString_FromStringAndSize(sig, siglen)

def sig01(public_key, sig, hash='sha256'):
    """Return a 'sig01'-format signature, given a (binary) public key and
    signature."""
    return 'sig01: %s %s %s\n' % \
           (hash, hexlify(public_key[-32:]), hexlify(sig))
