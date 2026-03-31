/*
 * ec_shim.h - OpenSSL 1.1.1 EC/ECDSA/ECDH API shims dispatching to wolfCrypt
 *
 * This header declares the shim entry points that implement the OpenSSL 1.1.1
 * EC, ECDSA, and ECDH APIs using wolfSSL/wolfCrypt as the backend.
 *
 * Consumers must compile with OPENSSL_EXTRA defined so that wolfSSL's
 * OpenSSL-compatibility layer is active.
 */

#ifndef WOLFSHIM_EC_SHIM_H
#define WOLFSHIM_EC_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pull in wolfSSL OpenSSL-compat EC types: WOLFSSL_EC_KEY, WOLFSSL_EC_GROUP,
 * WOLFSSL_EC_POINT, WOLFSSL_ECDSA_SIG, WOLFSSL_EC_METHOD, WOLFSSL_EC_KEY_METHOD.
 * With OPENSSL_EXTRA these are typedef'd as EC_KEY, EC_GROUP, EC_POINT, etc.
 */
#include <stdio.h>  /* fprintf, stderr — used by WOLFSHIM_TRACE() */

#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdsa.h>
#include <wolfssl/openssl/ecdh.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/evp.h>

/*
 * The shim does not wrap every symbol with a new function name — for the
 * majority of symbols wolfSSL's compat layer provides a direct mapping via
 * preprocessor #defines (e.g. EC_KEY_new -> wolfSSL_EC_KEY_new).  Those
 * functions are exercised transparently once the wolfSSL headers are included
 * with OPENSSL_EXTRA.
 *
 * The symbols below require explicit shim wrappers because:
 *   a) wolfSSL does not implement them at all, or
 *   b) the wolfSSL compat equivalent has a different name not covered by the
 *      standard #define macros, or
 *   c) the function is stubbed with a WOLFSHIM_KNOWN_GAP (no wolfSSL equivalent) or WOLFSHIM_REVIEW (needs expert validation) comment.
 */

/*
 * WOLFSHIM_TRACE() — emit a one-line function-entry trace to stderr when
 * WOLFSHIM_DEBUG is defined at build time.  Expands to a no-op otherwise.
 * Replace every inline 5-line #ifdef WOLFSHIM_DEBUG / fprintf / #endif block
 * with a single WOLFSHIM_TRACE(); call.
 */
#ifdef WOLFSHIM_DEBUG
#  define WOLFSHIM_TRACE() \
      fprintf(stderr, "[wolfshim] ec: %s called\n", __func__)
#else
#  define WOLFSHIM_TRACE() do {} while (0)
#endif

/* ---- EC_METHOD factory stubs (wolfSSL hides EC_METHOD internals) ---------- */
const EC_METHOD *wolfshim_EC_GFp_simple_method(void);
const EC_METHOD *wolfshim_EC_GFp_mont_method(void);
const EC_METHOD *wolfshim_EC_GFp_nist_method(void);
const EC_METHOD *wolfshim_EC_GF2m_simple_method(void);

/* ---- EC_GROUP lifecycle --------------------------------------------------- */
EC_GROUP *wolfshim_EC_GROUP_new(const EC_METHOD *meth);
void      wolfshim_EC_GROUP_clear_free(EC_GROUP *group);
int       wolfshim_EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src);

/* ---- EC_GROUP curve parameters ------------------------------------------- */
int wolfshim_EC_GROUP_set_curve(EC_GROUP *group, const BIGNUM *p,
                                const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int wolfshim_EC_GROUP_get_curve(const EC_GROUP *group, BIGNUM *p,
                                BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
int wolfshim_EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p,
                                    const BIGNUM *a, const BIGNUM *b,
                                    BN_CTX *ctx);
int wolfshim_EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p,
                                    BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
int wolfshim_EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p,
                                     const BIGNUM *a, const BIGNUM *b,
                                     BN_CTX *ctx);
int wolfshim_EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p,
                                     BIGNUM *a, BIGNUM *b, BN_CTX *ctx);

/* ---- EC_GROUP new-curve constructors ------------------------------------- */
EC_GROUP *wolfshim_EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a,
                                          const BIGNUM *b, BN_CTX *ctx);
EC_GROUP *wolfshim_EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a,
                                           const BIGNUM *b, BN_CTX *ctx);

/* ---- EC_GROUP generator / order / cofactor ------------------------------- */
int              wolfshim_EC_GROUP_set_generator(EC_GROUP *group,
                                                 const EC_POINT *generator,
                                                 const BIGNUM *order,
                                                 const BIGNUM *cofactor);
const EC_POINT  *wolfshim_EC_GROUP_get0_generator(const EC_GROUP *group);
const BIGNUM    *wolfshim_EC_GROUP_get0_order(const EC_GROUP *group);
const BIGNUM    *wolfshim_EC_GROUP_get0_cofactor(const EC_GROUP *group);
int              wolfshim_EC_GROUP_get_cofactor(const EC_GROUP *group,
                                                BIGNUM *cofactor, BN_CTX *ctx);

/* ---- EC_GROUP misc ------------------------------------------------------- */
void                    wolfshim_EC_GROUP_set_curve_name(EC_GROUP *group, int nid);
int                     wolfshim_EC_GROUP_get_asn1_flag(const EC_GROUP *group);
point_conversion_form_t wolfshim_EC_GROUP_get_point_conversion_form(const EC_GROUP *group);
void                    wolfshim_EC_GROUP_set_point_conversion_form(EC_GROUP *group,
                                                                    point_conversion_form_t form);
unsigned char  *wolfshim_EC_GROUP_get0_seed(const EC_GROUP *x);
size_t          wolfshim_EC_GROUP_get_seed_len(const EC_GROUP *x);
size_t          wolfshim_EC_GROUP_set_seed(EC_GROUP *group,
                                           const unsigned char *p, size_t len);
BN_MONT_CTX    *wolfshim_EC_GROUP_get_mont_data(const EC_GROUP *group);
int             wolfshim_EC_GROUP_get_basis_type(const EC_GROUP *group);
int             wolfshim_EC_GROUP_get_trinomial_basis(const EC_GROUP *group,
                                                      unsigned int *k);
int             wolfshim_EC_GROUP_get_pentanomial_basis(const EC_GROUP *group,
                                                        unsigned int *k1,
                                                        unsigned int *k2,
                                                        unsigned int *k3);

/* ---- EC_GROUP validation / precompute ------------------------------------ */
int wolfshim_EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
int wolfshim_EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx);
int wolfshim_EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int wolfshim_EC_GROUP_have_precompute_mult(const EC_GROUP *group);

/* ---- EC_GROUP ASN.1 / parameter objects ---------------------------------- */
/* WOLFSHIM_KNOWN_GAP: ECPARAMETERS / ECPKPARAMETERS are OpenSSL-internal ASN.1
 * structures not exposed by wolfSSL.  These are declared with void* to keep
 * the shim header self-contained; callers that need the real types must include
 * the OpenSSL ec.h (build-time only, not linked). */
EC_GROUP *wolfshim_EC_GROUP_new_from_ecparameters(const void *params);
void     *wolfshim_EC_GROUP_get_ecparameters(const EC_GROUP *group,
                                             void *params);
EC_GROUP *wolfshim_EC_GROUP_new_from_ecpkparameters(const void *params);
void     *wolfshim_EC_GROUP_get_ecpkparameters(const EC_GROUP *group,
                                               void *params);

/* ---- EC_POINT extra operations ------------------------------------------- */
const EC_METHOD *wolfshim_EC_POINT_method_of(const EC_POINT *point);
int  wolfshim_EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);
int  wolfshim_EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r,
                            const EC_POINT *a, BN_CTX *ctx);
int  wolfshim_EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p,
                                              const BIGNUM *x, const BIGNUM *y,
                                              BN_CTX *ctx);
int  wolfshim_EC_POINT_get_affine_coordinates(const EC_GROUP *group,
                                              const EC_POINT *p,
                                              BIGNUM *x, BIGNUM *y,
                                              BN_CTX *ctx);
int  wolfshim_EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group,
                                                   EC_POINT *p,
                                                   const BIGNUM *x,
                                                   const BIGNUM *y,
                                                   BN_CTX *ctx);
int  wolfshim_EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
                                                   const EC_POINT *p,
                                                   BIGNUM *x, BIGNUM *y,
                                                   BN_CTX *ctx);
int  wolfshim_EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group,
                                                    EC_POINT *p,
                                                    const BIGNUM *x,
                                                    const BIGNUM *y,
                                                    BN_CTX *ctx);
int  wolfshim_EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
                                                    const EC_POINT *p,
                                                    BIGNUM *x, BIGNUM *y,
                                                    BN_CTX *ctx);
int  wolfshim_EC_POINT_set_compressed_coordinates(const EC_GROUP *group,
                                                  EC_POINT *p,
                                                  const BIGNUM *x,
                                                  int y_bit, BN_CTX *ctx);
int  wolfshim_EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group,
                                                       EC_POINT *p,
                                                       const BIGNUM *x,
                                                       int y_bit, BN_CTX *ctx);
int  wolfshim_EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group,
                                                        EC_POINT *p,
                                                        const BIGNUM *x,
                                                        int y_bit, BN_CTX *ctx);
int  wolfshim_EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                                        EC_POINT *p,
                                                        const BIGNUM *x,
                                                        const BIGNUM *y,
                                                        const BIGNUM *z,
                                                        BN_CTX *ctx);
int  wolfshim_EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                                        const EC_POINT *p,
                                                        BIGNUM *x, BIGNUM *y,
                                                        BIGNUM *z,
                                                        BN_CTX *ctx);
size_t   wolfshim_EC_POINT_point2buf(const EC_GROUP *group,
                                     const EC_POINT *point,
                                     point_conversion_form_t form,
                                     unsigned char **pbuf, BN_CTX *ctx);
EC_POINT *wolfshim_EC_POINT_bn2point(const EC_GROUP *group, const BIGNUM *bn,
                                     EC_POINT *p, BN_CTX *ctx);
int  wolfshim_EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point,
                                   BN_CTX *ctx);
int  wolfshim_EC_POINTs_make_affine(const EC_GROUP *group, size_t num,
                                    EC_POINT *points[], BN_CTX *ctx);
int  wolfshim_EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r,
                             const BIGNUM *n, size_t num,
                             const EC_POINT *p[], const BIGNUM *m[],
                             BN_CTX *ctx);

/* ---- EC_KEY extras ------------------------------------------------------- */
EC_KEY  *wolfshim_EC_KEY_copy(EC_KEY *dst, const EC_KEY *src);
ENGINE  *wolfshim_EC_KEY_get0_engine(const EC_KEY *eckey);
int      wolfshim_EC_KEY_get_flags(const EC_KEY *key);
void     wolfshim_EC_KEY_set_flags(EC_KEY *key, int flags);
void     wolfshim_EC_KEY_clear_flags(EC_KEY *key, int flags);
int      wolfshim_EC_KEY_decoded_from_explicit_params(const EC_KEY *key);
int      wolfshim_EC_KEY_can_sign(const EC_KEY *eckey);
unsigned wolfshim_EC_KEY_get_enc_flags(const EC_KEY *key);
void     wolfshim_EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);
int      wolfshim_EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg);
void    *wolfshim_EC_KEY_get_ex_data(const EC_KEY *key, int idx);
int      wolfshim_EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx);
int      wolfshim_EC_KEY_print(BIO *bp, const EC_KEY *key, int off);
int      wolfshim_EC_KEY_set_public_key_affine_coordinates(EC_KEY *key,
                                                           BIGNUM *x, BIGNUM *y);
size_t   wolfshim_EC_KEY_key2buf(const EC_KEY *key,
                                  point_conversion_form_t form,
                                  unsigned char **pbuf, BN_CTX *ctx);
int      wolfshim_EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf,
                                  size_t len, BN_CTX *ctx);
int      wolfshim_EC_KEY_oct2priv(EC_KEY *key, const unsigned char *buf,
                                   size_t len);
size_t   wolfshim_EC_KEY_priv2oct(const EC_KEY *key, unsigned char *buf,
                                   size_t len);
size_t   wolfshim_EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf);
EC_KEY  *wolfshim_EC_KEY_new_method(ENGINE *engine);
const EC_KEY_METHOD *wolfshim_EC_KEY_get_default_method(void);
void     wolfshim_EC_KEY_set_default_method(const EC_KEY_METHOD *meth);

/* ---- EC_KEY_METHOD vtable ------------------------------------------------ */
void wolfshim_EC_KEY_METHOD_set_keygen(EC_KEY_METHOD *meth,
                                       int (*keygen)(EC_KEY *key));
void wolfshim_EC_KEY_METHOD_set_compute_key(EC_KEY_METHOD *meth,
                                             int (*ckey)(unsigned char **psec,
                                                         size_t *pseclen,
                                                         const EC_POINT *pub_key,
                                                         const EC_KEY *ecdh));
void wolfshim_EC_KEY_METHOD_set_verify(EC_KEY_METHOD *meth,
                                        int (*verify)(int type,
                                                      const unsigned char *dgst,
                                                      int dgst_len,
                                                      const unsigned char *sigbuf,
                                                      int sig_len,
                                                      EC_KEY *eckey),
                                        int (*verify_sig)(const unsigned char *dgst,
                                                          int dgst_len,
                                                          const ECDSA_SIG *sig,
                                                          EC_KEY *eckey));
void wolfshim_EC_KEY_METHOD_get_init(const EC_KEY_METHOD *meth,
                                      int (**pinit)(EC_KEY *key),
                                      void (**pfinish)(EC_KEY *key),
                                      int (**pcopy)(EC_KEY *dest, const EC_KEY *src),
                                      int (**pset_group)(EC_KEY *key, const EC_GROUP *grp),
                                      int (**pset_private)(EC_KEY *key, const BIGNUM *priv_key),
                                      int (**pset_public)(EC_KEY *key, const EC_POINT *pub_key));
void wolfshim_EC_KEY_METHOD_get_keygen(const EC_KEY_METHOD *meth,
                                        int (**pkeygen)(EC_KEY *key));
void wolfshim_EC_KEY_METHOD_get_compute_key(const EC_KEY_METHOD *meth,
                                             int (**pck)(unsigned char **psec,
                                                         size_t *pseclen,
                                                         const EC_POINT *pub_key,
                                                         const EC_KEY *ecdh));
void wolfshim_EC_KEY_METHOD_get_sign(const EC_KEY_METHOD *meth,
                                      int (**psign)(int type,
                                                    const unsigned char *dgst,
                                                    int dlen,
                                                    unsigned char *sig,
                                                    unsigned int *siglen,
                                                    const BIGNUM *kinv,
                                                    const BIGNUM *r,
                                                    EC_KEY *eckey),
                                      int (**psign_setup)(EC_KEY *eckey,
                                                          BN_CTX *ctx_in,
                                                          BIGNUM **kinvp,
                                                          BIGNUM **rp),
                                      ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
                                                               int dgst_len,
                                                               const BIGNUM *in_kinv,
                                                               const BIGNUM *in_r,
                                                               EC_KEY *eckey));
void wolfshim_EC_KEY_METHOD_get_verify(const EC_KEY_METHOD *meth,
                                        int (**pverify)(int type,
                                                        const unsigned char *dgst,
                                                        int dgst_len,
                                                        const unsigned char *sigbuf,
                                                        int sig_len,
                                                        EC_KEY *eckey),
                                        int (**pverify_sig)(const unsigned char *dgst,
                                                            int dgst_len,
                                                            const ECDSA_SIG *sig,
                                                            EC_KEY *eckey));

/* ---- ECDSA extended sign operations -------------------------------------- */
const BIGNUM *wolfshim_ECDSA_SIG_get0_r(const ECDSA_SIG *sig);
const BIGNUM *wolfshim_ECDSA_SIG_get0_s(const ECDSA_SIG *sig);
ECDSA_SIG *wolfshim_ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen,
                                      const BIGNUM *kinv, const BIGNUM *rp,
                                      EC_KEY *eckey);
int wolfshim_ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx,
                               BIGNUM **kinv, BIGNUM **rp);
int wolfshim_ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen,
                            unsigned char *sig, unsigned int *siglen,
                            const BIGNUM *kinv, const BIGNUM *rp,
                            EC_KEY *eckey);

/* ---- ECDH KDF ------------------------------------------------------------ */
int wolfshim_ECDH_KDF_X9_62(unsigned char *out, size_t outlen,
                              const unsigned char *Z, size_t Zlen,
                              const unsigned char *sinfo, size_t sinfolen,
                              const EVP_MD *md);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSHIM_EC_SHIM_H */
