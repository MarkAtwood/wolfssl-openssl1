/*
 * pkey_meth_shim.c - Build EVP_PKEY_METHOD objects at library init time,
 * backed by wolfSSL crypto operations.
 *
 * HEADER STRATEGY: include ONLY wolfSSL headers.  wolfSSL's OpenSSL-compat
 * layer provides the types (RSA, EC_KEY, DH, EVP_PKEY, EVP_PKEY_CTX, etc.)
 * and maps OpenSSL names to wolfSSL_ symbols via macros.
 *
 * EVP_PKEY_meth_* lives only in libcrypto's pmeth_lib.o; we forward-declare
 * those functions with opaque struct types.
 *
 * wolfSSL may have been built without HAVE_CURVE25519 / HAVE_ED25519.
 * In that case X25519/X448/Ed25519/Ed448 are registered as stub methods
 * (EVP_PKEY_CTX_new_id returns non-NULL, but actual keygen/sign fail).
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

/* wolfSSL headers first */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef HAVE_CURVE25519
# include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED25519
# include <wolfssl/wolfcrypt/ed25519.h>
#endif

/* wolfSSL OpenSSL compat layer */
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdsa.h>
#include <wolfssl/openssl/ecdh.h>
#include <wolfssl/openssl/dh.h>

/* Strip wolfSSL macro redirections for the symbols we call ourselves */
#ifdef EVP_PKEY_assign_EC_KEY
# undef EVP_PKEY_assign_EC_KEY
#endif
#ifdef EVP_PKEY_assign_DH
# undef EVP_PKEY_assign_DH
#endif
#ifdef EVP_PKEY_assign
# undef EVP_PKEY_assign
#endif
#ifdef EVP_PKEY_get0_RSA
# undef EVP_PKEY_get0_RSA
#endif
#ifdef EVP_PKEY_get0_EC_KEY
# undef EVP_PKEY_get0_EC_KEY
#endif
#ifdef EVP_PKEY_get0_DH
# undef EVP_PKEY_get0_DH
#endif
#ifdef EVP_PKEY_get0
# undef EVP_PKEY_get0
#endif
#ifdef EVP_PKEY_new
# undef EVP_PKEY_new
#endif
#ifdef EVP_PKEY_CTX_get0_pkey
# undef EVP_PKEY_CTX_get0_pkey
#endif
#ifdef EVP_PKEY_CTX_get0_peerkey
# undef EVP_PKEY_CTX_get0_peerkey
#endif
#ifdef EVP_MD_CTX_pkey_ctx
# undef EVP_MD_CTX_pkey_ctx
#endif
#ifdef EC_KEY_new_by_curve_name
# undef EC_KEY_new_by_curve_name
#endif
#ifdef EC_KEY_free
# undef EC_KEY_free
#endif
#ifdef EC_KEY_generate_key
# undef EC_KEY_generate_key
#endif
#ifdef EC_KEY_get0_public_key
# undef EC_KEY_get0_public_key
#endif
#ifdef EC_KEY_get0_group
# undef EC_KEY_get0_group
#endif
#ifdef EC_GROUP_get_degree
# undef EC_GROUP_get_degree
#endif
#ifdef ECDSA_sign
# undef ECDSA_sign
#endif
#ifdef ECDSA_verify
# undef ECDSA_verify
#endif
#ifdef ECDSA_size
# undef ECDSA_size
#endif
#ifdef ECDH_compute_key
# undef ECDH_compute_key
#endif
#ifdef DH_new
# undef DH_new
#endif
#ifdef DH_new_by_nid
# undef DH_new_by_nid
#endif
#ifdef DH_free
# undef DH_free
#endif
#ifdef DH_size
# undef DH_size
#endif
#ifdef DH_generate_key
# undef DH_generate_key
#endif
#ifdef DH_compute_key
# undef DH_compute_key
#endif
#ifdef DH_get0_key
# undef DH_get0_key
#endif
#ifdef BN_new
# undef BN_new
#endif
#ifdef BN_free
# undef BN_free
#endif
#ifdef BN_set_word
# undef BN_set_word
#endif

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "shim_rng.h"

/* =========================================================================
 * Opaque forward declarations for purely OpenSSL types
 * ========================================================================= */

/* EVP_PKEY_METHOD lives in pmeth_lib.o — opaque in our TU */
struct evp_pkey_method_st;
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;

/* WOLFSHIM_REVIEW [ABI]: EVP_PKEY_METHOD is opaque in the OpenSSL 1.1.1
 * public headers; its definition lives only in openssl/include/crypto/evp.h
 * (struct evp_pkey_method_st).  This translation unit therefore cannot
 * observe sizeof(EVP_PKEY_METHOD), so a _Static_assert on the size is not
 * possible here without including the internal header.
 *
 * Slot count validated against OpenSSL 1.1.1w
 * (openssl/include/crypto/evp.h, struct evp_pkey_method_st):
 *   - 2 int fields:  pkey_id, flags
 *   - 31 function pointer fields: init, copy, cleanup, paramgen_init,
 *     paramgen, keygen_init, keygen, sign_init, sign, verify_init, verify,
 *     verify_recover_init, verify_recover, signctx_init, signctx,
 *     verifyctx_init, verifyctx, encrypt_init, encrypt, decrypt_init,
 *     decrypt, derive_init, derive, ctrl, ctrl_str, digestsign,
 *     digestverify, check, public_check, param_check, digest_custom
 *   - Total size on LP64: 2*4 + 6 bytes padding + 31*8 = 256 bytes
 *
 * All interaction with EVP_PKEY_METHOD objects goes through the official
 * EVP_PKEY_meth_new() / EVP_PKEY_meth_set_*() accessors, which means we
 * never cast a fixed-size buffer to this type.
 *
 * What breaks if OpenSSL adds a slot: if a PKEY_METH_STUB macro that
 * allocates a fixed-size buffer and casts it to EVP_PKEY_METHOD* is ever
 * introduced, any additional slot added upstream would cause the buffer
 * allocation to be too small, resulting in reads or writes past the end of
 * the allocation (silent memory corruption / undefined behaviour).
 *
 * This slot count MUST be re-verified whenever the OpenSSL base is upgraded.
 * Any buffer-cast stub MUST include:
 *   _Static_assert(sizeof(buf) >= WOLFSHIM_EVP_PKEY_METHOD_SIZE,
 *                  "PKEY_METH_STUB buffer too small for EVP_PKEY_METHOD");
 * compiled against a build that exposes the internal header so that
 * sizeof(EVP_PKEY_METHOD) is observable. */

/* EVP_MD_CTX: wolfSSL maps this to WOLFSSL_EVP_MD_CTX */
#ifndef EVP_MD_CTX
typedef WOLFSSL_EVP_MD_CTX EVP_MD_CTX;
#endif

/* =========================================================================
 * Forward declarations of OpenSSL functions not present in wolfSSL
 * ========================================================================= */

extern EVP_PKEY_METHOD *EVP_PKEY_meth_new(int id, int flags);
extern int              EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth);

extern void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth,
    int (*keygen_init)(EVP_PKEY_CTX *ctx),
    int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));

extern void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth,
    int (*sign_init)(EVP_PKEY_CTX *ctx),
    int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                const unsigned char *tbs, size_t tbslen));

extern void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth,
    int (*verify_init)(EVP_PKEY_CTX *ctx),
    int (*verify)(EVP_PKEY_CTX *ctx,
                  const unsigned char *sig, size_t siglen,
                  const unsigned char *tbs, size_t tbslen));

extern void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth,
    int (*encrypt_init)(EVP_PKEY_CTX *ctx),
    int (*encryptfn)(EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen));

extern void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth,
    int (*decrypt_init)(EVP_PKEY_CTX *ctx),
    int (*decrypt)(EVP_PKEY_CTX *ctx,
                   unsigned char *out, size_t *outlen,
                   const unsigned char *in, size_t inlen));

extern void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth,
    int (*derive_init)(EVP_PKEY_CTX *ctx),
    int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));

extern void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth,
    int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
    int (*ctrl_str)(EVP_PKEY_CTX *ctx, const char *type, const char *value));

extern void EVP_PKEY_meth_set_digestsign(EVP_PKEY_METHOD *pmeth,
    int (*digestsign)(EVP_MD_CTX *ctx,
                      unsigned char *sig, size_t *siglen,
                      const unsigned char *tbs, size_t tbslen));

extern void EVP_PKEY_meth_set_digestverify(EVP_PKEY_METHOD *pmeth,
    int (*digestverify)(EVP_MD_CTX *ctx,
                        const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen));

/* EVP_PKEY_CTX accessors */
extern EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);
extern EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx);
extern EVP_PKEY_CTX *EVP_MD_CTX_pkey_ctx(const EVP_MD_CTX *ctx);

/* EVP_PKEY generic key accessor */
extern void *EVP_PKEY_get0(const EVP_PKEY *pkey);
extern int   EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);


/* BIGNUM */
extern BIGNUM *BN_new(void);
extern void    BN_free(BIGNUM *a);
extern int     BN_set_word(BIGNUM *a, unsigned long w);

/* EC */
extern EC_KEY *EC_KEY_new_by_curve_name(int nid);
extern void    EC_KEY_free(EC_KEY *key);
extern int     EC_KEY_generate_key(EC_KEY *key);
extern const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);
extern const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
extern int     EC_GROUP_get_degree(const EC_GROUP *group);
extern int     ECDSA_sign(int type, const unsigned char *dgst, int dgstlen,
                          unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
extern int     ECDSA_verify(int type, const unsigned char *dgst, int dgstlen,
                             const unsigned char *sig, int siglen, EC_KEY *eckey);
extern int     ECDSA_size(const EC_KEY *eckey);
extern int     ECDH_compute_key(void *out, size_t outlen,
                                const EC_POINT *pub_key, EC_KEY *ecdh,
                                void *(*KDF)(const void *in, size_t inlen,
                                             void *out, size_t *outlen));
extern int     EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
extern EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

/* DH */
extern DH    *DH_new(void);
extern DH    *DH_new_by_nid(int nid);
extern void   DH_free(DH *dh);
extern int    DH_size(const DH *dh);
extern int    DH_generate_key(DH *dh);
extern int    DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
extern void   DH_get0_key(const DH *dh, const BIGNUM **pub_key,
                          const BIGNUM **priv_key);
extern int    EVP_PKEY_assign_DH(EVP_PKEY *pkey, DH *dh);
extern DH    *EVP_PKEY_get0_DH(EVP_PKEY *pkey);

/* =========================================================================
 * Constants (define only if not already present from wolfSSL headers)
 * ========================================================================= */
#ifndef NID_rsaEncryption
# define NID_rsaEncryption 6
#endif
#ifndef NID_sha256
# define NID_sha256 672
#endif
#ifndef NID_X9_62_prime256v1
# define NID_X9_62_prime256v1 415
#endif
#ifndef NID_dhKeyAgreement
# define NID_dhKeyAgreement 28
#endif
#ifndef NID_ffdhe2048
# define NID_ffdhe2048 1126
#endif
#ifndef RSA_F4
# define RSA_F4 65537L
#endif
#ifndef RSA_PKCS1_OAEP_PADDING
# define RSA_PKCS1_OAEP_PADDING 4
#endif

/* EVP_PKEY type IDs */
#ifndef EVP_PKEY_RSA
# define EVP_PKEY_RSA     NID_rsaEncryption
#endif
#ifndef EVP_PKEY_EC
# define EVP_PKEY_EC      409
#endif
#ifndef EVP_PKEY_DH
# define EVP_PKEY_DH      NID_dhKeyAgreement
#endif
#ifndef EVP_PKEY_DHX
# define EVP_PKEY_DHX     920
#endif
#ifndef EVP_PKEY_X25519
# define EVP_PKEY_X25519  1034
#endif
#ifndef EVP_PKEY_ED25519
# define EVP_PKEY_ED25519 1087
#endif
#ifndef EVP_PKEY_X448
# define EVP_PKEY_X448    1035
#endif
#ifndef EVP_PKEY_ED448
# define EVP_PKEY_ED448   1088
#endif
#ifndef EVP_PKEY_HMAC
# define EVP_PKEY_HMAC    855
#endif
#ifndef EVP_PKEY_FLAG_SIGCTX_CUSTOM
# define EVP_PKEY_FLAG_SIGCTX_CUSTOM 4
#endif

/* =========================================================================
 * pkey_meth pointer storage — defined as "const void *" in misc_stubs.c
 * ========================================================================= */

/* pkey_rng_generate — thin wrapper around the shared per-thread RNG.
 * Delegates entirely to shim_rng_generate from shim_rng.h. */
static int pkey_rng_generate(byte *buf, word32 len)
{
    return shim_rng_generate(buf, len);
}

/* =========================================================================
 * wolfshim_pkey_meth_init — EC/DH/X25519/HMAC handled by OpenSSL built-ins
 * ========================================================================= */
void wolfshim_pkey_meth_init(void)
{
    /* crypto/ec/, crypto/dh/, crypto/hmac/ are compiled; their built-in
     * EVP_PKEY_METHODs are registered by OpenSSL's own initialisation.
     * Nothing extra needed here. */
}

/* Constructor fires at library load */
__attribute__((constructor))
static void wolfshim_pkey_meth_ctor(void)
{
    wolfshim_pkey_meth_init();
}

