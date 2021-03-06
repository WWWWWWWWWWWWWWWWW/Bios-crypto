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
    int _hash_buffer(char *hashname,
                     char *inbuf, unsigned long inlen,
                     char *outbuf, unsigned long *outlen)

def _check(int st):
    """Raise an appropriate `OSError` if the given libtomcrypt status code
    is not 0."""
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

    Throws `OSError` on signature error.
    Only rsa-sha256/rsa-rmd160 signatures.
    """
    cdef char sig[4096]
    cdef unsigned long  siglen
    siglen = sizeof(sig)
    _check(crypt_sign_file(hash, private_key, len(private_key),
                           sig, &siglen, filename))
    return PyString_FromStringAndSize(sig, siglen)

def sign_buffer(private_key, buffer, hash='sha256'):
    """Sign the given buffer with the given private key.

    Throws `OSError` on verification error.
    Only rsa-sha256/rsa-rmd160 signatures.
    """
    cdef char sig[4096]
    cdef unsigned long  siglen
    siglen = sizeof(sig)
    _check(crypt_sign_buffer(hash, private_key, len(private_key),
                             sig, &siglen, buffer, len(buffer)))
    return PyString_FromStringAndSize(sig, siglen)

def sig01(public_key, sig, hash='sha256'):
    """Return a 'sig01'-format signature, given a (binary) public key and
    signature.  See
    http://wiki.laptop.org/go/Firmware_Key_and_Signature_Formats#Signature
    for specification."""
    return 'sig01: %s %s %s\n' % \
           (hash, hexlify(public_key[-32:]), hexlify(sig))

def hash_buffer(buffer, hash='sha256'):
    """Hash the given buffer; return a hexadecimal string."""
    cdef char hashbuf[4096]
    cdef unsigned long hashlen
    hashlen = sizeof(hashbuf)
    _check(_hash_buffer(hash, buffer, len(buffer), hashbuf, &hashlen));
    return hexlify(PyString_FromStringAndSize(hashbuf, hashlen))
