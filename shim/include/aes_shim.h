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

/* -----------------------------------------------------------------
 * wolfshim extension: AES_KEY_new / AES_KEY_free
 *
 * These functions are NOT part of the OpenSSL 1.1.1 public API and
 * do not exist in any version of OpenSSL prior to the provider model
 * introduced in OpenSSL 3.  They are provided here because the
 * wolfshim heap-indirection pattern (see aes_ctx.h) makes the
 * absence of a _free function a practical liability: every stack-
 * allocated AES_KEY leaks ~1104 bytes of wolfCrypt context when it
 * goes out of scope without a preceding OPENSSL_cleanse() call.
 *
 * Background: OpenSSL's native AES_KEY stores the key schedule
 * inline in a 244-byte struct.  There is nothing to free; the struct
 * just goes out of scope.  wolfshim cannot store the wolfCrypt Aes
 * struct (>1104 bytes) inline without enlarging the public struct and
 * breaking the ABI, so it heap-allocates a wolfCrypt context and
 * stores only a pointer + magic sentinel in the AES_KEY buffer.  The
 * natural cleanup call (AES_KEY_free) therefore should have existed
 * in OpenSSL 1.1.1 — it just didn't, because the native
 * implementation had no heap allocation to free.
 *
 * These extensions allow callers to adopt explicit lifetime management
 * without porting to OpenSSL 3:
 *
 *   // Before: stack-allocated, leaks inner wolfCrypt context
 *   AES_KEY key;
 *   AES_set_encrypt_key(raw, 128, &key);
 *   AES_ecb_encrypt(in, out, &key, AES_ENCRYPT);
 *   OPENSSL_cleanse(&key, sizeof(key));   // required with wolfshim
 *
 *   // After: heap-allocated, no leak
 *   AES_KEY *key = AES_KEY_new();
 *   AES_set_encrypt_key(raw, 128, key);
 *   AES_ecb_encrypt(in, out, key, AES_ENCRYPT);
 *   AES_KEY_free(key);                   // frees inner + outer
 *
 * Callers that must compile against both stock OpenSSL 1.1.1 (which
 * does not define these) and this shim can guard on the macro:
 *   #ifdef WOLFSHIM_HAS_AES_KEY_FREE
 *     AES_KEY_free(key);
 *   #else
 *     OPENSSL_cleanse(key, sizeof(*key));
 *   #endif
 * ----------------------------------------------------------------- */
#define WOLFSHIM_HAS_AES_KEY_FREE 1

AES_KEY *AES_KEY_new(void);
void     AES_KEY_free(AES_KEY *key);

/* -----------------------------------------------------------------
 * wolfshim diagnostic: AES context allocation counter
 *
 * Available only when built with -DWOLFSHIM_DEBUG.
 *
 * Returns the total number of wolfCrypt Aes heap allocations made by
 * AES_set_encrypt_key / AES_set_decrypt_key since process start.
 * The counter increments on every successful key setup and never
 * decrements — it is a gross allocation count, not a net live count.
 *
 * Interpretation:
 *   At program startup:           count == 0
 *   After N key-setup calls:      count == N (expected)
 *   At steady state, still rising: callers are not calling
 *     OPENSSL_cleanse or AES_KEY_free; Aes contexts are accumulating.
 *
 * To detect leaks: snapshot the counter before and after a known
 * operation, then compare.  A delta equal to the number of key-setup
 * calls is expected.  A larger delta (or one observed after the
 * operation completes) indicates outstanding contexts.
 *
 * Not available without WOLFSHIM_DEBUG; returns 0 if called from a
 * non-debug build (the definition below is a weak stub).
 * ----------------------------------------------------------------- */
#ifdef WOLFSHIM_DEBUG
long wolfshim_aes_ctx_alloc_count(void);
#else
static inline long wolfshim_aes_ctx_alloc_count(void) { return 0; }
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSHIM_AES_SHIM_H */
