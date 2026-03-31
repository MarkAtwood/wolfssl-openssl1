/*
 * rsa_shim.h - OpenSSL 1.1.1 RSA API shims dispatching to wolfCrypt
 *
 * This header declares internal types used by rsa_shim.c.
 * It is NOT intended to be included by external consumers; those should
 * use wolfssl/openssl/rsa.h or openssl/rsa.h directly.
 *
 * Include order in rsa_shim.c:
 *   1. wolfssl/options.h
 *   2. wolfssl/wolfcrypt/settings.h
 *   3. wolfssl/openssl/rsa.h  (defines WOLFSSL_RSA, WOLFSSL_RSA_METHOD,
 *                              WOLFSSL_BIGNUM, RSA_FLAG_*, etc.)
 *   4. wolfssl/openssl/bn.h
 *   5. wolfssl/openssl/evp.h
 *   6. wolfssl/wolfcrypt/rsa.h
 *   7. THIS HEADER
 *
 * By the time this header is included, WOLFSSL_RSA_METHOD is available.
 * We extend it with the full set of function-pointer slots that the
 * OpenSSL RSA_METHOD vtable requires but that wolfSSL's minimalist
 * implementation does not carry.
 */

#ifndef WOLFSHIM_RSA_SHIM_H
#define WOLFSHIM_RSA_SHIM_H

#include <stddef.h>
#include <stdint.h>

/* wolfSSL types must already be included by the .c file before this header. */

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * RSA_PSS_PARAMS / RSA_OAEP_PARAMS
 *
 * OpenSSL ASN.1 structures declared via DECLARE_ASN1_FUNCTIONS macros.
 * wolfSSL does not define them under OPENSSL_EXTRA.  Provide minimal opaque
 * definitions here so pointer-level use (new/free) compiles.  The internal
 * ASN.1 fields are never populated; the types exist only to satisfy the ABI.
 * --------------------------------------------------------------------- */
#ifndef RSA_PSS_PARAMS_defined
# define RSA_PSS_PARAMS_defined
struct rsa_pss_params_st {
    void *hashAlgorithm;
    void *maskGenAlgorithm;
    void *saltLength;
    void *trailerField;
    void *maskHash;
};
typedef struct rsa_pss_params_st RSA_PSS_PARAMS;
#endif

#ifndef RSA_OAEP_PARAMS_defined
# define RSA_OAEP_PARAMS_defined
typedef struct rsa_oaep_params_st {
    void *hashFunc;
    void *maskGenFunc;
    void *pSourceFunc;
    void *maskHash;
} RSA_OAEP_PARAMS;
#endif

/* -------------------------------------------------------------------------
 * wolfshim_rsa_method_ext_t
 *
 * An "extended" RSA METHOD that stores the full set of function-pointer
 * slots from the OpenSSL RSA_METHOD vtable.  The embedded `base` member is
 * always the first field so that a pointer to the struct can be cast safely
 * to WOLFSSL_RSA_METHOD* (and therefore to RSA_METHOD* when that typedef
 * is active).
 *
 * Objects of this type are allocated by:
 *   - wolfshim_rsa_meth_alloc() (internal helper in rsa_shim.c)
 *   - RSA_meth_dup()
 *
 * They must NOT be freed with wolfSSL_RSA_meth_free() directly as that
 * function was not designed for this layout.  Use the RSA_meth_free()
 * macro/function which calls wolfSSL_RSA_meth_free after zeroing the ext
 * fields — or simply call free() on the pointer if the wolfSSL base struct
 * was embedded at offset 0.
 *
 * WOLFSHIM_KNOWN_GAP: wolfSSL's wolfSSL_RSA_meth_new() does NOT allocate a
 * wolfshim_rsa_method_ext_t.  Callers that invoke RSA_meth_get/set_* on
 * objects NOT created by RSA_meth_dup() risk accessing memory beyond the
 * wolfSSL allocation boundary.  Only use RSA_meth_dup() to create objects
 * that will be used with these accessors.
 * --------------------------------------------------------------------- */
/* Magic value used to identify wolfshim_rsa_method_ext_t allocations.
 * ASCII "WOLF" (0x574F4C46) stored in the magic field of every object
 * created by wolfshim_rsa_meth_alloc().  to_ext() checks this tag before
 * treating a pointer as the extended type. */
#define WOLFSHIM_RSA_METHOD_MAGIC ((uint32_t)0x574F4C46u)

typedef struct wolfshim_rsa_method_ext {
    /* Must be first — cast-compatible with WOLFSSL_RSA_METHOD*. */
    WOLFSSL_RSA_METHOD base;

    /* Type tag — set to WOLFSHIM_RSA_METHOD_MAGIC by wolfshim_rsa_meth_alloc().
     * Checked by to_ext() to verify the pointer was allocated by this shim. */
    uint32_t magic;

    /* Ownership flag for base.name.  Set to 1 when wolfshim_rsa_meth_alloc()
     * or RSA_meth_set1_name() allocates the name string.  Used by
     * RSA_meth_free() and RSA_meth_set1_name() to guard free(). */
    int name_owned;

    /* Function-pointer slots matching the OpenSSL RSA_METHOD vtable.
     * All slots are NULL in a freshly-allocated object (calloc). */
    int (*pub_enc)(int flen, const unsigned char *from,
                   unsigned char *to, WOLFSSL_RSA *rsa, int padding);
    int (*pub_dec)(int flen, const unsigned char *from,
                   unsigned char *to, WOLFSSL_RSA *rsa, int padding);
    int (*priv_enc)(int flen, const unsigned char *from,
                    unsigned char *to, WOLFSSL_RSA *rsa, int padding);
    int (*priv_dec)(int flen, const unsigned char *from,
                    unsigned char *to, WOLFSSL_RSA *rsa, int padding);
    int (*mod_exp)(WOLFSSL_BIGNUM *r0, const WOLFSSL_BIGNUM *i,
                   WOLFSSL_RSA *rsa, WOLFSSL_BN_CTX *ctx);
    int (*bn_mod_exp)(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a,
                      const WOLFSSL_BIGNUM *p, const WOLFSSL_BIGNUM *m,
                      WOLFSSL_BN_CTX *ctx, WOLFSSL_BN_MONT_CTX *m_ctx);
    int (*init)(WOLFSSL_RSA *rsa);
    int (*finish)(WOLFSSL_RSA *rsa);
    int (*sign)(int type, const unsigned char *m, unsigned int m_length,
                unsigned char *sigret, unsigned int *siglen,
                const WOLFSSL_RSA *rsa);
    int (*verify)(int dtype, const unsigned char *m, unsigned int m_length,
                  const unsigned char *sigbuf, unsigned int siglen,
                  const WOLFSSL_RSA *rsa);
    int (*keygen)(WOLFSSL_RSA *rsa, int bits, WOLFSSL_BIGNUM *e,
                  WOLFSSL_BN_GENCB *cb);
    int (*multi_prime_keygen)(WOLFSSL_RSA *rsa, int bits, int primes,
                               WOLFSSL_BIGNUM *e, WOLFSSL_BN_GENCB *cb);

    /* Application private data. */
    void *app_data;
} wolfshim_rsa_method_ext_t;

#ifdef __cplusplus
}
#endif

#endif /* WOLFSHIM_RSA_SHIM_H */
