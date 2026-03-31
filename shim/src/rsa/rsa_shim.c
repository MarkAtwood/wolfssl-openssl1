/*
 * rsa_shim.c - OpenSSL 1.1.1 RSA API shims dispatching to wolfCrypt
 *
 * Build status
 * ------------
 * THIS FILE IS NOT COMPILED INTO libwolfshim.a.
 *
 * It has a standalone CMakeLists.txt (shim/src/rsa/CMakeLists.txt) that builds
 * a separate static library: libwolfshim_rsa.a.  That library is not currently
 * wired into the main Makefile.wolfshim build.
 *
 * In the shipping configuration, RSA_* public symbols are provided by wolfSSL's
 * own OpenSSL compatibility layer (libwolfssl.so, built with OPENSSL_EXTRA).
 * This file exists as an alternative override implementation for cases where
 * wolfSSL's built-in compat layer is insufficient.
 *
 * Build requirements:
 *   OPENSSL_EXTRA must be defined in the wolfSSL build (or via -DOPENSSL_EXTRA).
 *
 * Name-conflict strategy:
 *   wolfSSL's rsa.h (when OPENSSL_EXTRA / OPENSSL_ALL is defined) maps many
 *   OpenSSL symbol names (e.g. RSA_meth_set_pub_enc) to its own differently-
 *   typed wolfSSL_* functions via #define macros.  To implement those OpenSSL
 *   symbols with the correct signatures we #undef each conflicting macro
 *   immediately before defining the function.  No wolfshim_* prefix is used.
 *   See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 *
 * Design notes:
 *  - All shims match the OpenSSL 1.1.1 function signatures exactly.
 *  - NULL inputs are handled without crashing.
 *  - wolfCrypt negative-error returns are translated to the OpenSSL
 *    convention for each function family (NULL / 0 / -1).
 *  - Functions without a usable wolfCrypt equivalent are stubbed and
 *    tagged with WOLFSHIM_GAP[TAG] or WOLFSHIM_REVIEW [ABI].
 *    Full tag taxonomy: ARCHITECTURE.md §21.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef OPENSSL_EXTRA
# define OPENSSL_EXTRA
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

/* wolfSSL compat types: WOLFSSL_RSA, WOLFSSL_RSA_METHOD, etc. */
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>

#include "shim_rng.h"

/*
 * With OPENSSL_EXTRA/OPENSSL_ALL the wolfSSL rsa.h sets:
 *   typedef WOLFSSL_RSA        RSA;
 *   typedef WOLFSSL_RSA_METHOD RSA_METHOD;
 *   #define RSA_bits           wolfSSL_RSA_bits
 *   #define RSA_meth_set_pub_enc wolfSSL_RSA_meth_set
 *   ... etc.
 * Those typedefs and the RSA_bits / wolfSSL function mappings are fine.
 * Only the RSA_meth_set_* / RSA_meth_get_* / RSA_new_method / RSA_null_method
 * mappings cause problems because wolfSSL's implementation has different
 * parameter types (void*) compared to the proper OpenSSL signatures.
 * We will #undef those specific macros before each of our definitions.
 */

/*
 * BN_BLINDING is not exposed by wolfSSL.  Forward-declare an opaque type
 * so function signatures that return BN_BLINDING* compile without errors.
 * Callers must NEVER dereference these pointers.
 */
struct bn_blinding_st;
typedef struct bn_blinding_st BN_BLINDING;

/* RSA_PSS_PARAMS and RSA_OAEP_PARAMS are now defined in rsa_shim.h. */

/* RSA_ASN1_VERSION_* constants (defined in openssl/rsa.h, not in wolfSSL). */
#ifndef RSA_ASN1_VERSION_DEFAULT
# define RSA_ASN1_VERSION_DEFAULT 0
# define RSA_ASN1_VERSION_MULTI   1
#endif

/* Pull in the shim's internal extended RSA_METHOD type. */
#include "rsa_shim.h"

/*
 * Two-header problem: OpenSSL and wolfSSL both define struct bignum_st
 * differently.  We cannot pass an OpenSSL BIGNUM to wolfSSL APIs directly.
 * Solution: serialize to bytes using OpenSSL's BN ops, then reconstruct with
 * wolfSSL.  This is intentional.
 *
 * Root cause in detail
 * --------------------
 * wolfSSL's headers redirect BIGNUM → WOLFSSL_BIGNUM via #define, so within
 * this TU the name "BIGNUM" refers to WOLFSSL_BIGNUM (different internal
 * layout from OpenSSL's struct bignum_st).  Both headers are in scope
 * simultaneously because rsa_shim.c must include both wolfssl/openssl/rsa.h
 * (for WOLFSSL_RSA, wolfSSL_RSA_generate_key_ex, etc.) and the OpenSSL
 * public ABI (for the function signatures it is implementing).  There is no
 * way to avoid this include conflict without splitting the TU.
 *
 * Problem: RSA_generate_key_ex() receives a const BIGNUM *e from the caller.
 * That pointer came from OpenSSL's BN layer (struct bignum_st), NOT from
 * wolfSSL.  Passing it to any wolfSSL BN function — including wolfSSL_BN_*
 * aliases — is undefined behaviour because the structs are incompatible.
 *
 * Solution: undefine wolfSSL's macro redirections for BN_num_bits and
 * BN_bn2bin, then forward-declare the real OpenSSL implementations from
 * crypto/bn/bn_lib.c (which is linked into this binary because OpenSSL's
 * crypto/bn/ directory is not excluded by WOLFCRYPT_EXCLUDE).  Use those
 * OpenSSL functions to serialise the exponent to a raw byte buffer, then
 * call wolfSSL_BN_bin2bn() to reconstruct a proper WOLFSSL_BIGNUM that
 * wolfSSL_RSA_generate_key_ex() can safely consume.
 *
 * Any future function that accepts a BIGNUM* from an external caller and
 * needs to pass it to wolfSSL must apply the same serialise-and-reconstruct
 * pattern.  Do NOT cast OpenSSL BIGNUM* to WOLFSSL_BIGNUM* directly.
 */
#ifdef BN_num_bits
# undef BN_num_bits
#endif
#ifdef BN_bn2bin
# undef BN_bn2bin
#endif
/* Real OpenSSL implementations in crypto/bn/bn_lib.c. */
extern int BN_num_bits(const BIGNUM *a);
extern int BN_bn2bin(const BIGNUM *a, unsigned char *to);

/*
 * ossl_exponent_to_wolf_bn — serialize an OpenSSL BIGNUM to bytes using the
 * OpenSSL BN API, then reconstruct a WOLFSSL_BIGNUM via wolfSSL_BN_bin2bn.
 *
 * Returns a heap-allocated WOLFSSL_BIGNUM; caller must wolfSSL_BN_free() it.
 * Returns NULL on allocation failure or if e is NULL/zero.
 */
static WOLFSSL_BIGNUM *ossl_exponent_to_wolf_bn(const BIGNUM *e)
{
    int nbits, nbytes;
    unsigned char *buf;
    WOLFSSL_BIGNUM *wbn;

    if (!e) return NULL;

    nbits = BN_num_bits(e);
    if (nbits <= 0) return NULL;
    nbytes = (nbits + 7) / 8;

    buf = (unsigned char *)XMALLOC((size_t)nbytes, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!buf) return NULL;

    if (BN_bn2bin(e, buf) != nbytes) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    wbn = wolfSSL_BN_bin2bn(buf, nbytes, NULL);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return wbn; /* NULL on wolfSSL_BN_bin2bn failure */
}

/*
 * Known gaps — functionality groups not implemented in this shim:
 *
 *  - BN_BLINDING exposure: RSA_setup_blinding returns NULL; wolfSSL manages
 *    blinding internally and does not expose BN_BLINDING objects.
 *  - X9.31 operations: RSA_padding_add_X931, RSA_padding_check_X931,
 *    RSA_X931_derive_ex, and RSA_X931_generate_key_ex are all stubs.
 *  - Multi-prime RSA: RSA_generate_multi_prime_key delegates to 2-prime
 *    generation for primes==2 and returns 0 otherwise.
 *  - ASN.1 PSS/OAEP encoding: RSA_PSS_PARAMS and RSA_OAEP_PARAMS types are
 *    defined (in rsa_shim.h) for ABI compatibility but fields are never
 *    populated; no ASN.1 parse/encode path is implemented.
 *  - ENGINE dispatch: RSA_new_method / RSA_get_default_method do not
 *    integrate with an OpenSSL ENGINE subsystem.
 */

/* =========================================================================
 * Convenience debug macros
 * ======================================================================= */
#ifdef WOLFSHIM_DEBUG
# define SHIM_TRACE() \
    fprintf(stderr, "[wolfshim] rsa: %s called\n", __func__)
#else
# define SHIM_TRACE() do {} while (0)
#endif

/* =========================================================================
 * Helpers: cast RSA_METHOD* to/from extended struct.
 *
 * to_ext() / to_ext_c() verify the magic tag before returning the cast
 * pointer.  If the pointer was NOT allocated by wolfshim_rsa_meth_alloc()
 * (e.g. it came from wolfSSL_RSA_meth_new() which produces a smaller
 * WOLFSSL_RSA_METHOD), the magic field will not match and NULL is returned.
 * All RSA_meth_get/set_* callers must handle a NULL return.
 * ======================================================================= */
static wolfshim_rsa_method_ext_t *to_ext(RSA_METHOD *m)
{
    if (!m) return NULL;
    wolfshim_rsa_method_ext_t *ext = (wolfshim_rsa_method_ext_t *)m;
    /* Type-tag check: if magic doesn't match, the pointer is a native
     * WOLFSSL_RSA_METHOD (smaller than our extended struct).  Reading past
     * it would be an out-of-bounds access; return NULL to the caller.
     * Always print: this is a programming error (wrong allocator used),
     * not a transient runtime failure.  Silent no-ops here have caused
     * RSA_meth_set_* calls to appear to succeed while doing nothing. */
    if (ext->magic != WOLFSHIM_RSA_METHOD_MAGIC) {
        fprintf(stderr,
            "[wolfshim] rsa: %s: RSA_METHOD magic tag mismatch — "
            "method was not allocated by RSA_meth_new() / "
            "wolfshim_rsa_meth_alloc(); returning failure.\n"
            "  Callers that obtained this RSA_METHOD from wolfSSL_RSA_meth_new()\n"
            "  or a wolfSSL internal allocator must use RSA_meth_new() instead.\n",
            __func__);
        return NULL;
    }
    return ext;
}
static const wolfshim_rsa_method_ext_t *to_ext_c(const RSA_METHOD *m)
{
    if (!m) return NULL;
    const wolfshim_rsa_method_ext_t *ext =
        (const wolfshim_rsa_method_ext_t *)m;
    if (ext->magic != WOLFSHIM_RSA_METHOD_MAGIC) {
        fprintf(stderr,
            "[wolfshim] rsa: %s: RSA_METHOD magic tag mismatch — "
            "method was not allocated by RSA_meth_new() / "
            "wolfshim_rsa_meth_alloc(); returning failure.\n"
            "  Callers that obtained this RSA_METHOD from wolfSSL_RSA_meth_new()\n"
            "  or a wolfSSL internal allocator must use RSA_meth_new() instead.\n",
            __func__);
        return NULL;
    }
    return ext;
}

static wolfshim_rsa_method_ext_t *wolfshim_rsa_meth_alloc(const char *name,
                                                           int flags)
{
    wolfshim_rsa_method_ext_t *ext =
        (wolfshim_rsa_method_ext_t *)calloc(1, sizeof(*ext));
    if (!ext) return NULL;
    ext->magic        = WOLFSHIM_RSA_METHOD_MAGIC;
    ext->base.flags   = flags;
    ext->base.dynamic = 1;
    if (name) {
        size_t len = strlen(name);
        ext->base.name = (char *)malloc(len + 1);
        if (!ext->base.name) { free(ext); return NULL; }
        memcpy(ext->base.name, name, len + 1);
        ext->name_owned = 1;
    }
    return ext;
}

/* =========================================================================
 * RSA_blinding_off
 * RSA_FLAG_NO_BLINDING and RSA_FLAG_BLINDING are defined in wolfSSL headers
 * (not macros to functions), so these calls are fine as-is.
 * ======================================================================= */
void RSA_blinding_off(RSA *rsa)
{
    SHIM_TRACE();
    if (!rsa) return;
    wolfSSL_RSA_set_flags(rsa, RSA_FLAG_NO_BLINDING);
    wolfSSL_RSA_clear_flags(rsa, RSA_FLAG_BLINDING);
}

/* =========================================================================
 * RSA_setup_blinding
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL handles RSA blinding internally; BN_BLINDING is
 * not part of the public wolfSSL API.  Returning NULL here is the correct
 * stub behaviour — returning a fake non-NULL BN_BLINDING pointer (e.g. the
 * RSA struct aliased as BN_BLINDING*) would mislead callers and cause
 * undefined behaviour if the pointer is ever dereferenced.  RSA_blinding_off
 * and RSA_setup_blinding are both no-op stubs in this shim.
 * ======================================================================= */
BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)rsa;
    (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL handles blinding internally.  Returning NULL
     * so callers fail fast rather than operating on a dangling alias. */
    return NULL;
}

/* =========================================================================
 * RSA_check_key_ex
 * ======================================================================= */
/* wolfSSL maps RSA_check_key → wolfSSL_RSA_check_key; that is fine.
 * RSA_check_key_ex is not mapped — define directly. */
int RSA_check_key_ex(const RSA *rsa, BN_GENCB *cb)
{
    SHIM_TRACE();
    (void)cb;
    if (!rsa) return 0;
    return wolfSSL_RSA_check_key(rsa);
}

/* =========================================================================
 * RSA_generate_multi_prime_key
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not support multi-prime RSA (primes > 2).
 * ======================================================================= */
int RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes,
                                 BIGNUM *e, BN_GENCB *cb)
{
    SHIM_TRACE();
    if (!rsa) return 0;
    /* WOLFSHIM_GAP[UNSUPPORTED]: Multi-prime RSA not supported by wolfSSL.
     * For primes == 2, delegate to standard 2-prime key generation. */
    if (primes == 2) {
        /* 'e' is an OpenSSL BIGNUM; convert to WOLFSSL_BIGNUM before passing. */
        WOLFSSL_BIGNUM *wolf_e = ossl_exponent_to_wolf_bn(e);
        int ret;
        if (!wolf_e) return 0;
        ret = wolfSSL_RSA_generate_key_ex(rsa, bits, wolf_e, NULL);
        wolfSSL_BN_free(wolf_e);
        return ret;
    }
    return 0;
}

/* =========================================================================
 * RSA_get0_* individual accessors
 *
 * wolfSSL maps RSA_get0_key / RSA_get0_factors / RSA_get0_crt_params to
 * wolfSSL functions.  The individual n/e/d/p/q/dmp1/dmq1/iqmp accessors
 * are not mapped, so define them directly.
 * ======================================================================= */
const BIGNUM *RSA_get0_n(const RSA *r)
{
    SHIM_TRACE();
    if (!r) return NULL;
    return (const BIGNUM *)r->n;
}

const BIGNUM *RSA_get0_e(const RSA *r)
{
    SHIM_TRACE();
    if (!r) return NULL;
    return (const BIGNUM *)r->e;
}

const BIGNUM *RSA_get0_d(const RSA *r)
{
    SHIM_TRACE();
    if (!r) return NULL;
    return (const BIGNUM *)r->d;
}

const BIGNUM *RSA_get0_p(const RSA *r)
{
    SHIM_TRACE();
    if (!r) return NULL;
    return (const BIGNUM *)r->p;
}

const BIGNUM *RSA_get0_q(const RSA *r)
{
    SHIM_TRACE();
    if (!r) return NULL;
    return (const BIGNUM *)r->q;
}

const BIGNUM *RSA_get0_dmp1(const RSA *r)
{
    SHIM_TRACE();
    if (!r) return NULL;
    return (const BIGNUM *)r->dmp1;
}

const BIGNUM *RSA_get0_dmq1(const RSA *r)
{
    SHIM_TRACE();
    if (!r) return NULL;
    return (const BIGNUM *)r->dmq1;
}

const BIGNUM *RSA_get0_iqmp(const RSA *r)
{
    SHIM_TRACE();
    if (!r) return NULL;
    return (const BIGNUM *)r->iqmp;
}

/* =========================================================================
 * RSA_get0_pss_params
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL RSA struct has no RSA_PSS_PARAMS field.
 * ======================================================================= */
const RSA_PSS_PARAMS *RSA_get0_pss_params(const RSA *r)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL RSA struct has no RSA_PSS_PARAMS field. */
    (void)r;
    return NULL;
}

/* =========================================================================
 * RSA_get0_engine
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no ENGINE concept for RSA structs.
 * ======================================================================= */
ENGINE *RSA_get0_engine(const RSA *r)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no ENGINE concept for RSA structs. */
    (void)r;
    return NULL;
}

/* =========================================================================
 * RSA_get_version
 * ======================================================================= */
int RSA_get_version(RSA *r)
{
    SHIM_TRACE();
    (void)r;
    /* wolfSSL only supports standard 2-prime RSA. */
    return RSA_ASN1_VERSION_DEFAULT;
}

/* =========================================================================
 * Multi-prime accessors (all stubbed)
 * ======================================================================= */
int RSA_get_multi_prime_extra_count(const RSA *r)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: Multi-prime RSA not supported by wolfSSL. */
    (void)r;
    return 0;
}

int RSA_get0_multi_prime_factors(const RSA *r, const BIGNUM *primes[])
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: Multi-prime RSA not supported by wolfSSL. */
    (void)r; (void)primes;
    return 0;
}

int RSA_get0_multi_prime_crt_params(const RSA *r, const BIGNUM *exps[],
                                    const BIGNUM *coeffs[])
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: Multi-prime RSA not supported by wolfSSL. */
    (void)r; (void)exps; (void)coeffs;
    return 0;
}

int RSA_set0_multi_prime_params(RSA *r, BIGNUM *primes[], BIGNUM *exps[],
                                BIGNUM *coeffs[], int pnum)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: Multi-prime RSA not supported by wolfSSL. */
    (void)r; (void)primes; (void)exps; (void)coeffs; (void)pnum;
    return 0;
}

/* =========================================================================
 * RSA_security_bits
 *
 * NIST SP 800-57 security-strength table.
 * ======================================================================= */
int RSA_security_bits(const RSA *rsa)
{
    SHIM_TRACE();
    if (!rsa) return 0;
    int bits = wolfSSL_RSA_bits(rsa);
    if (bits <= 0)    return 0;
    if (bits < 1024)  return 0;
    if (bits < 2048)  return 80;
    if (bits < 3072)  return 112;
    if (bits < 7680)  return 128;
    if (bits < 15360) return 192;
    return 256;
}

/* =========================================================================
 * RSA_METHOD management
 *
 * wolfSSL maps several RSA_meth_set_* names to wolfSSL_RSA_meth_set (which
 * takes a void* and has a different signature).  We #undef those macros
 * before each of our definitions.
 * ======================================================================= */

RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth)
{
    SHIM_TRACE();
    if (!meth) return NULL;
    const wolfshim_rsa_method_ext_t *src = to_ext_c(meth);
    wolfshim_rsa_method_ext_t *dst =
        wolfshim_rsa_meth_alloc(meth->name, meth->flags);
    if (!dst) return NULL;
    /* Copy all extended fields at once to avoid silently missing new fields
     * added to wolfshim_rsa_method_ext_t in the future.  Then re-allocate
     * dst->base.name so dst owns its own copy of the string. */
    if (src) {
        char *saved_name = dst->base.name; /* already heap-allocated by wolfshim_rsa_meth_alloc */
        *dst = *src;
        /* Restore the separately-allocated name copy made above. */
        dst->base.name = saved_name;
        dst->name_owned = (saved_name != NULL) ? 1 : 0;
        /* magic stays WOLFSHIM_RSA_METHOD_MAGIC as set by wolfshim_rsa_meth_alloc */
        dst->magic = WOLFSHIM_RSA_METHOD_MAGIC;
    }
    return (RSA_METHOD *)dst;
}

/* =========================================================================
 * RSA_meth_free
 *
 * Frees an RSA_METHOD allocated by wolfshim_rsa_meth_alloc (which includes
 * all methods created by RSA_meth_dup).  Also handles wolfSSL-native method
 * objects by delegating to wolfSSL_RSA_meth_free.  The magic tag is checked
 * first:
 *   - If the tag matches, this is our extended struct; free name (if owned)
 *     then free the whole allocation.
 *   - If the tag does not match, the pointer was obtained from wolfSSL
 *     directly; delegate to wolfSSL_RSA_meth_free().
 * ======================================================================= */
static void wolfshim_RSA_meth_free(RSA_METHOD *meth)
{
    if (!meth) return;
    wolfshim_rsa_method_ext_t *ext = (wolfshim_rsa_method_ext_t *)meth;
    if (ext->magic == WOLFSHIM_RSA_METHOD_MAGIC) {
        if (ext->name_owned) {
            free(ext->base.name);
            ext->base.name = NULL;
        }
        free(ext);
    } else {
        /* Delegate to wolfSSL for methods not allocated by this shim.
         * wolfSSL_RSA_meth_free() is assumed to handle name ownership
         * correctly for methods allocated by wolfSSL internals; see
         * wolfSSL source (wolfssl/ssl.c) for that guarantee. */
        wolfSSL_RSA_meth_free(meth);
    }
}

/* Bare alias matching the OpenSSL 1.1.1 symbol name. */
void RSA_meth_free(RSA_METHOD *meth)
{
    wolfshim_RSA_meth_free(meth);
}

const char *RSA_meth_get0_name(const RSA_METHOD *meth)
{
    SHIM_TRACE();
    if (!meth) return NULL;
    return meth->name;
}

int RSA_meth_set1_name(RSA_METHOD *meth, const char *name)
{
    SHIM_TRACE();
    if (!meth) return 0;
    char *copy = NULL;
    if (name) {
        size_t len = strlen(name);
        copy = (char *)malloc(len + 1);
        if (!copy) return 0;
        memcpy(copy, name, len + 1);
    }
    /* Only free the previous name string if this shim allocated it.
     * Freeing a string literal (from a method not created by this shim)
     * would be undefined behaviour. */
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (ext) {
        if (ext->name_owned) {
            free(meth->name);
        }
        meth->name = copy;
        ext->name_owned = (copy != NULL) ? 1 : 0;
    } else {
        /* Cannot determine whether the existing name pointer is heap-allocated
         * (it came from wolfSSL internals); leaking it rather than risking a
         * free() of a string literal.  This is a known unavoidable leak for
         * non-extended methods. */
        meth->name = copy;
    }
    return 1;
}

int RSA_meth_get_flags(const RSA_METHOD *meth)
{
    SHIM_TRACE();
    if (!meth) return 0;
    return meth->flags;
}

int RSA_meth_set_flags(RSA_METHOD *meth, int flags)
{
    SHIM_TRACE();
    if (!meth) return 0;
    meth->flags = flags;
    return 1;
}

void *RSA_meth_get0_app_data(const RSA_METHOD *meth)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->app_data;
}

/* wolfSSL maps RSA_meth_set0_app_data → wolfSSL_RSA_meth_set (void*) which
 * clashes with our typed signature.  Undefine the macro first. */
#ifdef RSA_meth_set0_app_data
# undef RSA_meth_set0_app_data
#endif
int RSA_meth_set0_app_data(RSA_METHOD *meth, void *app_data)
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->app_data = app_data;
    return 1;
}

/* --- Function-pointer getters (not mapped by wolfSSL → no conflict) --- */

int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
    (int, const unsigned char *, unsigned char *, RSA *, int)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->pub_enc;
}

int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
    (int, const unsigned char *, unsigned char *, RSA *, int)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->pub_dec;
}

int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
    (int, const unsigned char *, unsigned char *, RSA *, int)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->priv_enc;
}

int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
    (int, const unsigned char *, unsigned char *, RSA *, int)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->priv_dec;
}

int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))
    (BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->mod_exp;
}

int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))
    (BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
     BN_CTX *, BN_MONT_CTX *)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->bn_mod_exp;
}

int (*RSA_meth_get_init(const RSA_METHOD *meth))(RSA *)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->init;
}

int (*RSA_meth_get_finish(const RSA_METHOD *meth))(RSA *)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->finish;
}

int (*RSA_meth_get_sign(const RSA_METHOD *meth))
    (int, const unsigned char *, unsigned int, unsigned char *,
     unsigned int *, const RSA *)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->sign;
}

int (*RSA_meth_get_verify(const RSA_METHOD *meth))
    (int, const unsigned char *, unsigned int, const unsigned char *,
     unsigned int, const RSA *)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->verify;
}

int (*RSA_meth_get_keygen(const RSA_METHOD *meth))
    (RSA *, int, BIGNUM *, BN_GENCB *)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->keygen;
}

int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))
    (RSA *, int, int, BIGNUM *, BN_GENCB *)
{
    SHIM_TRACE();
    const wolfshim_rsa_method_ext_t *ext = to_ext_c(meth);
    if (!ext) return NULL;
    return ext->multi_prime_keygen;
}

/* --- Function-pointer setters ---
 * wolfSSL maps several of these to wolfSSL_RSA_meth_set via #define.
 * Undefine each before our definition. */

#ifdef RSA_meth_set_pub_enc
# undef RSA_meth_set_pub_enc
#endif
int RSA_meth_set_pub_enc(RSA_METHOD *meth,
    int (*pub_enc)(int, const unsigned char *, unsigned char *, RSA *, int))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->pub_enc = pub_enc;
    return 1;
}

#ifdef RSA_meth_set_pub_dec
# undef RSA_meth_set_pub_dec
#endif
int RSA_meth_set_pub_dec(RSA_METHOD *meth,
    int (*pub_dec)(int, const unsigned char *, unsigned char *, RSA *, int))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->pub_dec = pub_dec;
    return 1;
}

#ifdef RSA_meth_set_priv_enc
# undef RSA_meth_set_priv_enc
#endif
int RSA_meth_set_priv_enc(RSA_METHOD *meth,
    int (*priv_enc)(int, const unsigned char *, unsigned char *, RSA *, int))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->priv_enc = priv_enc;
    return 1;
}

#ifdef RSA_meth_set_priv_dec
# undef RSA_meth_set_priv_dec
#endif
int RSA_meth_set_priv_dec(RSA_METHOD *meth,
    int (*priv_dec)(int, const unsigned char *, unsigned char *, RSA *, int))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->priv_dec = priv_dec;
    return 1;
}

/* wolfSSL does not define RSA_meth_set_mod_exp or RSA_meth_set_bn_mod_exp
 * as macros, so no #undef guard is needed here. */
int RSA_meth_set_mod_exp(RSA_METHOD *meth,
    int (*mod_exp)(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->mod_exp = mod_exp;
    return 1;
}

int RSA_meth_set_bn_mod_exp(RSA_METHOD *meth,
    int (*bn_mod_exp)(BIGNUM *, const BIGNUM *, const BIGNUM *,
                      const BIGNUM *, BN_CTX *, BN_MONT_CTX *))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->bn_mod_exp = bn_mod_exp;
    return 1;
}

#ifdef RSA_meth_set_init
# undef RSA_meth_set_init
#endif
int RSA_meth_set_init(RSA_METHOD *meth, int (*init)(RSA *))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->init = init;
    return 1;
}

#ifdef RSA_meth_set_finish
# undef RSA_meth_set_finish
#endif
int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish)(RSA *))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->finish = finish;
    return 1;
}

/* wolfSSL does not define RSA_meth_set_sign or RSA_meth_set_verify as
 * macros, so no #undef guard is needed here. */
int RSA_meth_set_sign(RSA_METHOD *meth,
    int (*sign)(int, const unsigned char *, unsigned int,
                unsigned char *, unsigned int *, const RSA *))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->sign = sign;
    return 1;
}

int RSA_meth_set_verify(RSA_METHOD *meth,
    int (*verify)(int, const unsigned char *, unsigned int,
                  const unsigned char *, unsigned int, const RSA *))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->verify = verify;
    return 1;
}

/* wolfSSL does not define RSA_meth_set_keygen or
 * RSA_meth_set_multi_prime_keygen as macros; no #undef guard needed. */
int RSA_meth_set_keygen(RSA_METHOD *meth,
    int (*keygen)(RSA *, int, BIGNUM *, BN_GENCB *))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->keygen = keygen;
    return 1;
}

int RSA_meth_set_multi_prime_keygen(RSA_METHOD *meth,
    int (*keygen)(RSA *, int, int, BIGNUM *, BN_GENCB *))
{
    SHIM_TRACE();
    wolfshim_rsa_method_ext_t *ext = to_ext(meth);
    if (!ext) return 0;
    ext->multi_prime_keygen = keygen;
    return 1;
}

/* =========================================================================
 * RSA_new_method
 *
 * wolfSSL maps RSA_new → wolfSSL_RSA_new; RSA_new_method is unmapped.
 * WOLFSHIM_GAP[CORRECTNESS]: ENGINE parameter is ignored.
 * ======================================================================= */
RSA *RSA_new_method(ENGINE *engine)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: ENGINE parameter is ignored — wolfSSL has no ENGINE
     * concept for RSA. */
    (void)engine;
    return wolfSSL_RSA_new();
}

/* =========================================================================
 * RSA_null_method
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no null RSA method.
 * ======================================================================= */
const RSA_METHOD *RSA_null_method(void)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no equivalent null RSA method. */
    return NULL;
}

/* =========================================================================
 * RSA_set_default_method
 *
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL has no global default RSA method setter.
 * ======================================================================= */
void RSA_set_default_method(const RSA_METHOD *meth)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL has no global default RSA method setter. */
    (void)meth;
}

/* =========================================================================
 * RSA_PKCS1_OpenSSL
 * ======================================================================= */
const RSA_METHOD *RSA_PKCS1_OpenSSL(void)
{
    SHIM_TRACE();
    return wolfSSL_RSA_get_default_method();
}

/* =========================================================================
 * RSA_PSS_PARAMS_new / RSA_PSS_PARAMS_free
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no standalone RSA_PSS_PARAMS allocator.
 * The shim allocates a zeroed block matching the struct declared in
 * openssl/rsa.h so callers can store/free it without crashing.
 * ASN.1 encode/decode of these params is not supported.
 * ======================================================================= */
RSA_PSS_PARAMS *RSA_PSS_PARAMS_new(void)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no RSA_PSS_PARAMS type.
     * Returning zeroed opaque struct; ASN.1 fields are all NULL. */
    RSA_PSS_PARAMS *p = (RSA_PSS_PARAMS *)calloc(1, sizeof(*p));
    return p;
}

void RSA_PSS_PARAMS_free(RSA_PSS_PARAMS *p)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: Internal ASN.1 fields not populated; just free. */
    free(p);
}

/* =========================================================================
 * RSA_OAEP_PARAMS_new / RSA_OAEP_PARAMS_free
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: Same situation as RSA_PSS_PARAMS.
 * ======================================================================= */
RSA_OAEP_PARAMS *RSA_OAEP_PARAMS_new(void)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no RSA_OAEP_PARAMS type.
     * Returning zeroed opaque struct; ASN.1 fields are all NULL. */
    RSA_OAEP_PARAMS *p = (RSA_OAEP_PARAMS *)calloc(1, sizeof(*p));
    return p;
}

void RSA_OAEP_PARAMS_free(RSA_OAEP_PARAMS *p)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: Internal ASN.1 fields not populated; just free. */
    free(p);
}

/* =========================================================================
 * RSA_pkey_ctx_ctrl
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no RSA_pkey_ctx_ctrl equivalent.
 * Returns -2 (EVP "command not implemented" convention).
 * ======================================================================= */
int RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd,
                      int p1, void *p2)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no RSA_pkey_ctx_ctrl equivalent.
     * Returning -2 ("command not implemented"). */
    (void)ctx; (void)optype; (void)cmd; (void)p1; (void)p2;
    return -2;
}

/* =========================================================================
 * RSA padding functions
 *
 * These call wc_RsaPad_ex / wc_RsaUnPad_ex from wolfcrypt/rsa.h.
 * ======================================================================= */

int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl)
{
    SHIM_TRACE();
    if (!to || tlen <= 0 || !f || fl <= 0) return 0;
    int ret = wc_RsaPad_ex(f, (word32)fl, to, (word32)tlen,
                           (byte)RSA_BLOCK_TYPE_1, NULL,
                           WC_RSA_PKCSV15_PAD,
                           WC_HASH_TYPE_NONE, WC_MGF1NONE,
                           NULL, 0, 0, 0, NULL);
    return (ret == 0) ? 1 : 0;
}

int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl,
                                   int rsa_len)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: rsa_len should be validated against fl to ensure the
     * padded block length matches the RSA modulus, but is not currently used;
     * wc_RsaUnPad_ex performs its own internal validation. */
    (void)rsa_len;
    if (!to || tlen <= 0 || !f || fl <= 0) return -1;
    byte *out = NULL;
    int ret = wc_RsaUnPad_ex((byte *)f, (word32)fl, &out,
                              (byte)RSA_BLOCK_TYPE_1,
                              WC_RSA_PKCSV15_PAD,
                              WC_HASH_TYPE_NONE, WC_MGF1NONE,
                              NULL, 0, 0, 0, NULL);
    if (ret < 0 || !out) return -1;
    if (ret > tlen) return -1;
    XMEMCPY(to, out, (word32)ret);
    return ret;
}

int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl)
{
    SHIM_TRACE();
    if (!to || tlen <= 0 || !f || fl <= 0) return 0;
    WC_RNG *rng = shim_get_thread_rng();
    if (!rng) return 0;
    int ret = wc_RsaPad_ex(f, (word32)fl, to, (word32)tlen,
                       (byte)RSA_BLOCK_TYPE_2, rng,
                       WC_RSA_PKCSV15_PAD,
                       WC_HASH_TYPE_NONE, WC_MGF1NONE,
                       NULL, 0, 0, 0, NULL);
    return (ret == 0) ? 1 : 0;
}

int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl,
                                   int rsa_len)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: rsa_len should be validated against fl to ensure the
     * padded block length matches the RSA modulus, but is not currently used;
     * wc_RsaUnPad_ex performs its own internal validation. */
    (void)rsa_len;
    if (!to || tlen <= 0 || !f || fl <= 0) return -1;
    byte *out = NULL;
    int ret = wc_RsaUnPad_ex((byte *)f, (word32)fl, &out,
                              (byte)RSA_BLOCK_TYPE_2,
                              WC_RSA_PKCSV15_PAD,
                              WC_HASH_TYPE_NONE, WC_MGF1NONE,
                              NULL, 0, 0, 0, NULL);
    if (ret < 0 || !out) return -1;
    if (ret > tlen) return -1;
    XMEMCPY(to, out, (word32)ret);
    return ret;
}

int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
                               const unsigned char *f, int fl,
                               const unsigned char *p, int pl)
{
    SHIM_TRACE();
    if (!to || tlen <= 0 || !f || fl <= 0) return 0;
    WC_RNG *rng = shim_get_thread_rng();
    if (!rng) return 0;
    int ret = wc_RsaPad_ex(f, (word32)fl, to, (word32)tlen,
                       (byte)RSA_BLOCK_TYPE_2, rng,
                       WC_RSA_OAEP_PAD,
                       WC_HASH_TYPE_SHA, WC_MGF1SHA1,
                       (byte *)p, (word32)pl, 0, 0, NULL);
    return (ret == 0) ? 1 : 0;
}

int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl, int rsa_len,
                                 const unsigned char *p, int pl)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: rsa_len should be validated against fl to ensure the
     * padded block length matches the RSA modulus, but is not currently used;
     * wc_RsaUnPad_ex performs its own internal validation. */
    (void)rsa_len;
    if (!to || tlen <= 0 || !f || fl <= 0) return -1;
    byte *out = NULL;
    int ret = wc_RsaUnPad_ex((byte *)f, (word32)fl, &out,
                              (byte)RSA_BLOCK_TYPE_2,
                              WC_RSA_OAEP_PAD,
                              WC_HASH_TYPE_SHA, WC_MGF1SHA1,
                              (byte *)p, (word32)pl, 0, 0, NULL);
    if (ret < 0 || !out) return -1;
    if (ret > tlen) return -1;
    XMEMCPY(to, out, (word32)ret);
    return ret;
}

int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                    const unsigned char *from, int flen,
                                    const unsigned char *param, int plen,
                                    const EVP_MD *md, const EVP_MD *mgf1md)
{
    SHIM_TRACE();
    if (!to || tlen <= 0 || !from || flen <= 0) return 0;
    /*
     * WOLFSHIM_GAP[CORRECTNESS]: EVP_MD to wc_HashType mapping may be incomplete.
     * SHA-1 is used as default when md is NULL (matching OpenSSL default).
     */
    enum wc_HashType htype =
        (md == NULL) ? WC_HASH_TYPE_SHA :
        (enum wc_HashType)wc_OidGetHash(wolfSSL_EVP_MD_type(md));
    enum wc_HashType mgfhtype =
        (mgf1md == NULL) ? htype :
        (enum wc_HashType)wc_OidGetHash(wolfSSL_EVP_MD_type(mgf1md));
    int mgf = wc_hash2mgf(mgfhtype);
    WC_RNG *rng = shim_get_thread_rng();
    if (!rng) return 0;
    int ret = wc_RsaPad_ex(from, (word32)flen, to, (word32)tlen,
                       (byte)RSA_BLOCK_TYPE_2, rng,
                       WC_RSA_OAEP_PAD,
                       htype, mgf,
                       (byte *)param, (word32)plen, 0, 0, NULL);
    return (ret == 0) ? 1 : 0;
}

int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                      const unsigned char *from, int flen,
                                      int num,
                                      const unsigned char *param, int plen,
                                      const EVP_MD *md, const EVP_MD *mgf1md)
{
    SHIM_TRACE();
    (void)num;
    if (!to || tlen <= 0 || !from || flen <= 0) return -1;
    enum wc_HashType htype =
        (md == NULL) ? WC_HASH_TYPE_SHA :
        (enum wc_HashType)wc_OidGetHash(wolfSSL_EVP_MD_type(md));
    enum wc_HashType mgfhtype =
        (mgf1md == NULL) ? htype :
        (enum wc_HashType)wc_OidGetHash(wolfSSL_EVP_MD_type(mgf1md));
    int mgf = wc_hash2mgf(mgfhtype);
    byte *out = NULL;
    int ret = wc_RsaUnPad_ex((byte *)from, (word32)flen, &out,
                              (byte)RSA_BLOCK_TYPE_2,
                              WC_RSA_OAEP_PAD,
                              htype, mgf,
                              (byte *)param, (word32)plen, 0, 0, NULL);
    if (ret < 0 || !out) return -1;
    if (ret > tlen) return -1;
    XMEMCPY(to, out, (word32)ret);
    return ret;
}

int RSA_padding_add_none(unsigned char *to, int tlen,
                         const unsigned char *f, int fl)
{
    SHIM_TRACE();
    if (!to || tlen <= 0 || !f || fl <= 0) return 0;
    if (fl > tlen) return 0;
    if (fl < tlen) {
        int diff = tlen - fl;
        XMEMSET(to, 0, (word32)diff);
        XMEMCPY(to + diff, f, (word32)fl);
    } else {
        XMEMCPY(to, f, (word32)fl);
    }
    return 1;
}

int RSA_padding_check_none(unsigned char *to, int tlen,
                           const unsigned char *f, int fl, int rsa_len)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: rsa_len should be validated against fl to ensure the
     * padded block length matches the RSA modulus, but is not currently used;
     * wc_RsaUnPad_ex performs its own internal validation. */
    (void)rsa_len;
    if (!to || tlen <= 0 || !f || fl <= 0) return -1;
    /* Per OpenSSL behavior: if the source block is larger than the output
     * buffer, a truncated copy would silently discard data — return -1 as
     * OpenSSL does rather than returning tlen as success. */
    if (fl > tlen) return -1;
    XMEMCPY(to, f, (word32)fl);
    return fl;
}

int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                           const unsigned char *f, int fl)
{
    SHIM_TRACE();
    /* SSLv23 padding differs from PKCS#1 type-2: it inserts a version-
     * marker byte sequence (0x00 0x02 ... 0x00 0x00 0x02) not present in
     * standard PKCS#1 type-2 padding.  wolfCrypt does not expose an
     * SSLv23-specific padding primitive, so we delegate to PKCS#1 type-2
     * here.  This is only correct for callers that never inspect the
     * padding format.  If the customer uses SSLv23 padding on-the-wire,
     * this needs a proper implementation or an ERR_R_UNSUPPORTED hard
     * failure. */
    return RSA_padding_add_PKCS1_type_2(to, tlen, f, fl);
}

int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                             const unsigned char *f, int fl, int rsa_len)
{
    SHIM_TRACE();
    /* SSLv23 check accepts PKCS#1 type-2 padded blocks (a superset of the
     * actual SSLv23 format), which is overly permissive but not harmful in
     * the absence of SSL 2.0 support.  SSL 2.0 is disabled in all supported
     * wolfSSL configurations. */
    return RSA_padding_check_PKCS1_type_2(to, tlen, f, fl, rsa_len);
}

/* X9.31 padding: wolfSSL has no implementation. */
int RSA_padding_add_X931(unsigned char *to, int tlen,
                         const unsigned char *f, int fl)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: X9.31 padding not supported by wolfSSL. */
    (void)to; (void)tlen; (void)f; (void)fl;
    return 0;
}

int RSA_padding_check_X931(unsigned char *to, int tlen,
                           const unsigned char *f, int fl, int rsa_len)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: X9.31 padding not supported by wolfSSL. */
    (void)to; (void)tlen; (void)f; (void)fl; (void)rsa_len;
    return -1;
}

/* =========================================================================
 * RSA_X931_hash_id
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: X9.31 hash ID mapping not defined in wolfSSL.
 * ======================================================================= */
int RSA_X931_hash_id(int nid)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: X9.31 hash IDs not defined in wolfSSL. */
    (void)nid;
    return -1;
}

/* =========================================================================
 * RSA_X931_derive_ex / RSA_X931_generate_key_ex
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: X9.31 key derivation/generation not supported by wolfSSL.
 * ======================================================================= */
int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1,
                       BIGNUM *q2, const BIGNUM *Xp1, const BIGNUM *Xp2,
                       const BIGNUM *Xp, const BIGNUM *Xq1, const BIGNUM *Xq2,
                       const BIGNUM *Xq, const BIGNUM *e, BN_GENCB *cb)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: X9.31 RSA key derivation not supported by wolfSSL. */
    (void)rsa; (void)p1; (void)p2; (void)q1; (void)q2;
    (void)Xp1; (void)Xp2; (void)Xp; (void)Xq1; (void)Xq2;
    (void)Xq; (void)e; (void)cb;
    return 0;
}

int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e,
                             BN_GENCB *cb)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: X9.31 RSA key generation not supported by wolfSSL. */
    (void)rsa; (void)bits; (void)e; (void)cb;
    return 0;
}

/* =========================================================================
 * RSA_sign_ASN1_OCTET_STRING / RSA_verify_ASN1_OCTET_STRING
 *
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no equivalent for these functions.
 * ======================================================================= */
int RSA_sign_ASN1_OCTET_STRING(int type,
                               const unsigned char *m, unsigned int m_length,
                               unsigned char *sigret, unsigned int *siglen,
                               RSA *rsa)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: No wolfSSL equivalent for RSA_sign_ASN1_OCTET_STRING.
     * Returns 0 (failure) as a stub.  No error is pushed to the OpenSSL error
     * queue because the wolfSSL shim does not wire up RSAerr().  Callers that
     * inspect ERR_get_error() after this call will see an empty error queue,
     * which may make failure diagnosis harder.  Acceptable for a stub, but
     * noted here so a future implementor knows to add RSAerr() when wiring in
     * a real implementation. */
    (void)type; (void)m; (void)m_length; (void)sigret; (void)siglen;
    (void)rsa;
    return 0;
}

int RSA_verify_ASN1_OCTET_STRING(int type, const unsigned char *m,
                                 unsigned int m_length,
                                 unsigned char *sigbuf, unsigned int siglen,
                                 RSA *rsa)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: No wolfSSL equivalent for RSA_verify_ASN1_OCTET_STRING.
     * Returns 0 (failure) as a stub.  No error is pushed to the OpenSSL error
     * queue; callers using ERR_get_error() to diagnose failures will see
     * nothing, making it impossible to distinguish "stub not implemented" from
     * "signature verification failed."  Acceptable for a stub, but a real
     * implementation must call RSAerr(RSA_F_RSA_VERIFY,
     * RSA_R_UNKNOWN_ALGORITHM_TYPE) or equivalent before returning on error. */
    (void)type; (void)m; (void)m_length; (void)sigbuf; (void)siglen;
    (void)rsa;
    return 0;
}
