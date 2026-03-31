/*
 * aes_shim.h — OpenSSL 1.1.1 AES API shim declarations (wolfCrypt back-end)
 *
 * All symbols listed here are implemented in shim/src/aes/aes_shim.c.
 * Include this header instead of (or alongside) <openssl/aes.h> when
 * building against the wolfCrypt shim layer.
 */

#ifndef WOLFSHIM_AES_SHIM_H
#define WOLFSHIM_AES_SHIM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------
 * Re-use the AES_KEY typedef from the OpenSSL header.  We include it
 * here so that consumers of this shim header do not need to pull in
 * the full OpenSSL tree.
 * ----------------------------------------------------------------- */
/* Guard against both OpenSSL's HEADER_AES_H and wolfSSL's WOLFSSL_AES_H_.
 * wolfssl/wolfcrypt/aes.h with OPENSSL_EXTRA pulls in wolfssl/openssl/aes.h
 * which defines "typedef WOLFSSL_AES_KEY AES_KEY".  If either header has
 * already been included we must not redefine struct aes_key_st or AES_KEY. */
#if !defined(HEADER_AES_H) && !defined(WOLFSSL_AES_H_)
# define AES_ENCRYPT  1
# define AES_DECRYPT  0
# define AES_MAXNR   14
# define AES_BLOCK_SIZE 16

struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;
#endif /* !HEADER_AES_H && !WOLFSSL_AES_H_ */

/* -----------------------------------------------------------------
 * Shim function declarations — match OpenSSL 1.1.1 signatures exactly
 * ----------------------------------------------------------------- */

const char *AES_options(void);

void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const AES_KEY *key, const int enc);

void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);

void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);

void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        unsigned char *ivec, int *num);

/* NB: the IV is _two_ blocks long */
void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);

/* NB: the IV is _four_ blocks long */
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        const AES_KEY *key2, const unsigned char *ivec,
                        const int enc);

int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
                 unsigned char *out,
                 const unsigned char *in, unsigned int inlen);

int AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
                   unsigned char *out,
                   const unsigned char *in, unsigned int inlen);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSHIM_AES_SHIM_H */
