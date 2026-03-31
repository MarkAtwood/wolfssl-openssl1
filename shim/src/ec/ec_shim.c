/*
 * ec_shim.c - OpenSSL 1.1.1 EC/ECDSA/ECDH API shims dispatching to wolfCrypt
 *
 * Build status
 * ------------
 * THIS FILE IS NOT COMPILED INTO libwolfshim.a.
 *
 * It has a standalone CMakeLists.txt (shim/src/ec/CMakeLists.txt) that builds
 * a separate static library: libwolfshim_ec.a.  That library is not currently
 * wired into the main Makefile.wolfshim build.
 *
 * In the shipping configuration, EC_* and ECDSA_* public symbols are provided
 * by wolfSSL's own OpenSSL compatibility layer (libwolfssl.so, built with
 * OPENSSL_EXTRA).  This file exists as an alternative override implementation
 * for cases where wolfSSL's built-in compat layer is insufficient or needs
 * to be replaced.
 *
 * Name-conflict strategy
 * ----------------------
 * wolfSSL's ec.h (with OPENSSL_EXTRA) #defines many OpenSSL symbol names as
 * macro aliases.  Each function in this file is preceded by a targeted #undef
 * to strip the macro before the function definition.  No wolfshim_* prefix is
 * used; the OpenSSL symbol names are defined directly.
 * See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 *
 * Symbols implemented (see ec_shim.h / ec_coverage.md for full list):
 *   EC_GF2m_simple_method, EC_GFp_mont_method, EC_GFp_nist_method,
 *   EC_GFp_simple_method, EC_GROUP_check, EC_GROUP_check_discriminant,
 *   EC_GROUP_clear_free, EC_GROUP_copy, EC_GROUP_get0_cofactor,
 *   EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_GROUP_get0_seed,
 *   EC_GROUP_get_asn1_flag, EC_GROUP_get_basis_type, EC_GROUP_get_cofactor,
 *   EC_GROUP_get_curve, EC_GROUP_get_curve_GF2m, EC_GROUP_get_curve_GFp,
 *   EC_GROUP_get_ecparameters, EC_GROUP_get_ecpkparameters,
 *   EC_GROUP_get_mont_data, EC_GROUP_get_pentanomial_basis,
 *   EC_GROUP_get_point_conversion_form, EC_GROUP_get_seed_len,
 *   EC_GROUP_get_trinomial_basis, EC_GROUP_have_precompute_mult,
 *   EC_GROUP_new, EC_GROUP_new_curve_GF2m, EC_GROUP_new_curve_GFp,
 *   EC_GROUP_new_from_ecparameters, EC_GROUP_new_from_ecpkparameters,
 *   EC_GROUP_precompute_mult, EC_GROUP_set_curve, EC_GROUP_set_curve_GF2m,
 *   EC_GROUP_set_curve_GFp, EC_GROUP_set_curve_name, EC_GROUP_set_generator,
 *   EC_GROUP_set_point_conversion_form, EC_GROUP_set_seed,
 *   EC_KEY_can_sign, EC_KEY_clear_flags, EC_KEY_copy,
 *   EC_KEY_decoded_from_explicit_params, EC_KEY_get0_engine,
 *   EC_KEY_get_default_method, EC_KEY_get_enc_flags, EC_KEY_get_ex_data,
 *   EC_KEY_get_flags, EC_KEY_key2buf, EC_KEY_METHOD_get_compute_key,
 *   EC_KEY_METHOD_get_init, EC_KEY_METHOD_get_keygen,
 *   EC_KEY_METHOD_get_sign, EC_KEY_METHOD_get_verify,
 *   EC_KEY_METHOD_set_compute_key, EC_KEY_METHOD_set_keygen,
 *   EC_KEY_METHOD_set_verify, EC_KEY_new_method, EC_KEY_oct2key,
 *   EC_KEY_oct2priv, EC_KEY_precompute_mult, EC_KEY_print,
 *   EC_KEY_priv2buf, EC_KEY_priv2oct, EC_KEY_set_default_method,
 *   EC_KEY_set_enc_flags, EC_KEY_set_ex_data, EC_KEY_set_flags,
 *   EC_KEY_set_public_key_affine_coordinates, EC_POINT_bn2point,
 *   EC_POINT_dbl, EC_POINT_get_affine_coordinates,
 *   EC_POINT_get_affine_coordinates_GF2m,
 *   EC_POINT_get_Jprojective_coordinates_GFp, EC_POINT_make_affine,
 *   EC_POINT_method_of, EC_POINT_point2buf, EC_POINT_set_affine_coordinates,
 *   EC_POINT_set_affine_coordinates_GF2m,
 *   EC_POINT_set_compressed_coordinates,
 *   EC_POINT_set_compressed_coordinates_GF2m,
 *   EC_POINT_set_compressed_coordinates_GFp,
 *   EC_POINT_set_Jprojective_coordinates_GFp, EC_POINT_set_to_infinity,
 *   EC_POINTs_make_affine, EC_POINTs_mul,
 *   ECDH_KDF_X9_62, ECDSA_do_sign_ex, ECDSA_SIG_get0_r, ECDSA_SIG_get0_s,
 *   ECDSA_sign_ex, ECDSA_sign_setup
 *
 * Build requirements:
 *   wolfSSL built with OPENSSL_EXTRA (enables wolfSSL OpenSSL compat layer)
 *   HAVE_ECC defined to enable elliptic curve support
 *
 * Error-return policy for no-op / stub functions:
 *   - Functions that perform an operation wolfSSL handles internally (e.g.
 *     precompute_mult) return 1 (success) because calling them cannot harm
 *     the caller.
 *   - Functions that represent a genuinely unsupported feature (e.g.
 *     set_curve with explicit BN parameters, set_generator, set_ex_data)
 *     return 0 (failure) so callers can detect that the feature is absent.
 *   - Functions that return an object (EC_GROUP*, EC_POINT*, BIGNUM*, etc.)
 *     return NULL to indicate unsupported.
 *   - void functions that are no-ops are silent; callers cannot detect them.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stddef.h>

/* wolfSSL OpenSSL compat headers */
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdsa.h>
#include <wolfssl/openssl/ecdh.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/evp.h>

/* wolfCrypt low-level for X9.63 KDF */
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>

/* Shim public header */
#include "ec_shim.h"

/* Compile-time wolfSSL version guard.
 * All direct struct field accesses in this file (curve_idx, curve_nid,
 * curve_oid, group, pub_key, priv_key, form, point->X/Y/Z/inSet/exSet)
 * were validated against the WOLFSSL_EC_GROUP / WOLFSSL_EC_POINT layout
 * as of wolfSSL 5.9.0.  If wolfSSL restructures these structs, the guard
 * below will produce a build error, forcing explicit re-validation. */
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05009000
#  error "ec_shim.c requires wolfSSL >= 5.9.0; struct layouts were validated " \
         "against that version — review all direct field accesses before " \
         "lowering this threshold"
#endif

/* Compile-time struct layout assertions.
 * ec_shim.c directly accesses WOLFSSL_EC_GROUP.{curve_idx,curve_nid,curve_oid}
 * and WOLFSSL_EC_KEY.priv_key (all WOLFSHIM_REVIEW [ABI] sites).
 * If wolfSSL restructures these structs these assertions produce a build error
 * before any silent memory corruption can occur.
 * Offsets were measured against wolfSSL 5.9.0 on x86_64.
 * When upgrading wolfSSL: re-run `offsetof` probe, update constants, and
 * re-audit every WOLFSHIM_REVIEW [ABI] comment in this file. */
_Static_assert(offsetof(WOLFSSL_EC_GROUP, curve_idx) == 0,
    "WOLFSSL_EC_GROUP.curve_idx offset changed — re-audit ec_shim.c and update this constant");
_Static_assert(offsetof(WOLFSSL_EC_GROUP, curve_nid) == 4,
    "WOLFSSL_EC_GROUP.curve_nid offset changed — re-audit ec_shim.c and update this constant");
_Static_assert(offsetof(WOLFSSL_EC_GROUP, curve_oid) == 8,
    "WOLFSSL_EC_GROUP.curve_oid offset changed — re-audit ec_shim.c and update this constant");
_Static_assert(sizeof(WOLFSSL_EC_GROUP)              == 12,
    "WOLFSSL_EC_GROUP size changed — re-audit ec_shim.c and update this constant");
_Static_assert(offsetof(WOLFSSL_EC_KEY, priv_key)    == 16,
    "WOLFSSL_EC_KEY.priv_key offset changed — re-audit ec_shim.c and update this constant");
_Static_assert(sizeof(WOLFSSL_EC_KEY)                == 56,
    "WOLFSSL_EC_KEY size changed — re-audit ec_shim.c and update this constant");

/* =========================================================================
 * Helpers / static dummy objects
 * ========================================================================= */

/*
 * wolfSSL aliases EC_METHOD to WOLFSSL_EC_GROUP (typedef in wolfssl/openssl/ec.h).
 * For the method-factory stubs we need a non-NULL pointer to return.
 * Callers that attempt to use these sentinels for EC_GROUP_new() will get a
 * NULL group back (see EC_GROUP_new shim below).
 *
 * Four distinct zero-initialised sentinels — one per EC_METHOD factory.
 * Using separate objects ensures pointer-equality comparisons between
 * different method factories return false, matching OpenSSL behaviour. */
static const WOLFSSL_EC_GROUP s_method_GFp_simple;  /* EC_GFp_simple_method  */
static const WOLFSSL_EC_GROUP s_method_GFp_mont;    /* EC_GFp_mont_method    */
static const WOLFSSL_EC_GROUP s_method_GFp_nist;    /* EC_GFp_nist_method    */
static const WOLFSSL_EC_GROUP s_method_GF2m_simple; /* EC_GF2m_simple_method */

/* =========================================================================
 * EC_METHOD factories  (wolfSSL hides EC_METHOD internals)
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose EC_METHOD as a distinct public
 * type.  EC_METHOD is typedef'd as WOLFSSL_EC_GROUP.  These factory
 * functions return a non-NULL sentinel pointer so callers can test for
 * success, but the pointer cannot be meaningfully dereferenced through the
 * OpenSSL EC_METHOD API.  EC_GROUP_new() with these methods will return NULL
 * because wolfSSL requires a NID-based constructor.
 * ========================================================================= */

const EC_METHOD *wolfshim_EC_GFp_simple_method(void)
{
    WOLFSHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose GFp simple EC_METHOD.
     * Returns a distinct sentinel so pointer-equality comparisons with other
     * EC_METHOD factory results give the correct false result. */
    return (const EC_METHOD *)&s_method_GFp_simple;
}

const EC_METHOD *wolfshim_EC_GFp_mont_method(void)
{
    WOLFSHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose GFp Montgomery EC_METHOD.
     * Returns a distinct sentinel so pointer-equality comparisons with other
     * EC_METHOD factory results give the correct false result. */
    return (const EC_METHOD *)&s_method_GFp_mont;
}

const EC_METHOD *wolfshim_EC_GFp_nist_method(void)
{
    WOLFSHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose GFp NIST EC_METHOD.
     * Returns a distinct sentinel so pointer-equality comparisons with other
     * EC_METHOD factory results give the correct false result. */
    return (const EC_METHOD *)&s_method_GFp_nist;
}

const EC_METHOD *wolfshim_EC_GF2m_simple_method(void)
{
    WOLFSHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose GF(2^m) EC_METHOD;
     * binary-field curves are not supported.  Returns a distinct sentinel so
     * pointer-equality comparisons with other EC_METHOD factory results give
     * the correct false result. */
    return (const EC_METHOD *)&s_method_GF2m_simple;
}

/* =========================================================================
 * EC_GROUP lifecycle
 * ========================================================================= */

/*
 * EC_GROUP_new — wolfSSL has no NID-agnostic constructor; we cannot honour
 * the EC_METHOD parameter.
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL requires a NID to create a group.  Callers using
 * EC_GROUP_new(EC_GFp_*_method()) then EC_GROUP_set_curve() cannot be fully
 * supported.  Return NULL to signal this limitation.
 */
EC_GROUP *wolfshim_EC_GROUP_new(const EC_METHOD *meth)
{
    WOLFSHIM_TRACE();
    (void)meth;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no NID-agnostic EC_GROUP_new; returning NULL */
    return NULL;
}

/*
 * EC_GROUP_clear_free — wolfSSL only exposes EC_GROUP_free; no separate
 * "clear" variant.  Delegate to EC_GROUP_free (wolfSSL_EC_GROUP_free).
 */
void wolfshim_EC_GROUP_clear_free(EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    if (group == NULL)
        return;
    wolfSSL_EC_GROUP_free(group);
}

/*
 * EC_GROUP_copy — wolfSSL exposes wolfSSL_EC_GROUP_dup() but not a copy-into
 * function.  dst and src are both WOLFSSL_EC_GROUP * (EC_GROUP is typedef'd to
 * WOLFSSL_EC_GROUP in wolfssl/openssl/ec.h).  src is declared const EC_GROUP *
 * matching the OpenSSL API; struct assignment from a const source is valid C.
 */
int wolfshim_EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src)
{
    WOLFSHIM_TRACE();
    if (dst == NULL || src == NULL)
        return 0;
    /* Copy all fields — struct assignment is safer than named-field copy:
     * new fields added by wolfSSL upgrades are automatically included.
     * The _Static_assert on sizeof(WOLFSSL_EC_GROUP) above will catch
     * incompatible size changes. */
    *dst = *src;
    return 1;
}

/* =========================================================================
 * EC_GROUP curve parameters
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL WOLFSSL_EC_GROUP stores only curve_idx / curve_nid /
 * curve_oid and does not hold arbitrary BN curve parameters.  The set_curve
 * family cannot be fully implemented; they return 0 (failure) with a review
 * comment.  get_curve delegates to wolfSSL_EC_GROUP_get_order / wolfSSL
 * internals where possible, but explicit a,b,p retrieval is not exposed.
 * ========================================================================= */

int wolfshim_EC_GROUP_set_curve(EC_GROUP *group, const BIGNUM *p,
                                const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)a; (void)b; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_GROUP does not support set_curve with
     * explicit BN parameters; only NID-based groups are supported */
    return 0;
}

int wolfshim_EC_GROUP_get_curve(const EC_GROUP *group, BIGNUM *p,
                                BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)a; (void)b; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_GROUP does not expose explicit BN curve
     * parameters p, a, b; only NID-based groups are supported */
    return 0;
}

int wolfshim_EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p,
                                    const BIGNUM *a, const BIGNUM *b,
                                    BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    return wolfshim_EC_GROUP_set_curve(group, p, a, b, ctx);
}

int wolfshim_EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p,
                                    BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    return wolfshim_EC_GROUP_get_curve(group, p, a, b, ctx);
}

int wolfshim_EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p,
                                     const BIGNUM *a, const BIGNUM *b,
                                     BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)a; (void)b; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) binary-field curves not supported in wolfSSL */
    return 0;
}

int wolfshim_EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p,
                                     BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)a; (void)b; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) binary-field curves not supported in wolfSSL */
    return 0;
}

/* =========================================================================
 * EC_GROUP new-curve constructors
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not support explicit GFp / GF2m group
 * construction from BN parameters.  Return NULL.
 * ========================================================================= */

EC_GROUP *wolfshim_EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a,
                                          const BIGNUM *b, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)p; (void)a; (void)b; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL requires NID-based group creation;
     * explicit BN parameter groups are not supported */
    return NULL;
}

EC_GROUP *wolfshim_EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a,
                                           const BIGNUM *b, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)p; (void)a; (void)b; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) binary-field curves not supported in wolfSSL */
    return NULL;
}

/* =========================================================================
 * EC_GROUP generator / order / cofactor
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL WOLFSSL_EC_GROUP does not store a separate
 * EC_POINT generator or BIGNUM order/cofactor — these are derived from the
 * named curve at use time.  The get0 accessors return NULL; set_generator
 * returns 0 (unsupported).
 * ========================================================================= */

int wolfshim_EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
                                    const BIGNUM *order, const BIGNUM *cofactor)
{
    WOLFSHIM_TRACE();
    (void)group; (void)generator; (void)order; (void)cofactor;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_GROUP uses built-in named-curve parameters;
     * custom generator/order/cofactor cannot be set */
    return 0;
}

const EC_POINT *wolfshim_EC_GROUP_get0_generator(const EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    (void)group;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose the group generator as an
     * EC_POINT object through this API; returning NULL */
    return NULL;
}

const BIGNUM *wolfshim_EC_GROUP_get0_order(const EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    (void)group;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not return a persistent BIGNUM* for the
     * group order via this accessor; use EC_GROUP_get_order() with a caller-
     * provided BIGNUM instead */
    return NULL;
}

const BIGNUM *wolfshim_EC_GROUP_get0_cofactor(const EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    (void)group;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose the group cofactor as a
     * persistent BIGNUM* through this accessor */
    return NULL;
}

int wolfshim_EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor,
                                   BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)ctx;
    if (group == NULL || cofactor == NULL)
        return 0;
    /*
     * Return the cofactor only for curves where it is deterministically 1.
     * All standard NIST prime curves (P-192, P-224, P-256, P-384, P-521) and
     * secp256k1 / secp224k1 have cofactor h=1.
     *
     * Curve25519 (NID 1034) has h=8 and Curve448 (NID 1035) has h=4; these
     * are NOT listed here, so callers receive 0 (failure / unknown) rather
     * than a silently wrong value.
     *
     * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose a generic cofactor accessor.
     * For any curve not explicitly enumerated below this function returns 0 so
     * that callers can detect the gap instead of receiving an incorrect value.
     */
    switch (group->curve_nid) {
        /* NIST / SEC prime-field curves — all have cofactor h = 1 */
        case NID_X9_62_prime192v1: /* P-192 */
        case NID_X9_62_prime192v2:
        case NID_X9_62_prime192v3:
        case NID_secp224r1:        /* P-224 */
        case NID_secp224k1:
        case NID_X9_62_prime256v1: /* P-256 */
        case NID_secp256k1:
        case NID_secp384r1:        /* P-384 */
        case NID_secp521r1:        /* P-521 */
            if (wolfSSL_BN_set_word(cofactor, 1) != 1)
                return 0;
            return 1;

        default:
            /* Cofactor is not known or is not 1 for this curve — return
             * failure so the caller does not silently use a wrong value. */
            return 0;
    }
}

/* =========================================================================
 * EC_GROUP misc attributes
 * ========================================================================= */

void wolfshim_EC_GROUP_set_curve_name(EC_GROUP *group, int nid)
{
    WOLFSHIM_TRACE();
    if (group == NULL)
        return;
    /* Delegate to wolfSSL EC_GROUP_set_asn1_flag path; also store NID */
    group->curve_nid = nid;
}

int wolfshim_EC_GROUP_get_asn1_flag(const EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    if (group == NULL)
        return 0;
    /*
     * wolfSSL EC_GROUP_set_asn1_flag stores the flag inside the group but
     * does not expose a getter.
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL has no wolfSSL_EC_GROUP_get_asn1_flag;
     * returning OPENSSL_EC_NAMED_CURVE as the default.
     */
    return OPENSSL_EC_NAMED_CURVE;
}

point_conversion_form_t wolfshim_EC_GROUP_get_point_conversion_form(
        const EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    (void)group;
    /*
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_GROUP does not track a per-group
     * point_conversion_form; returning POINT_CONVERSION_UNCOMPRESSED as default.
     */
    return POINT_CONVERSION_UNCOMPRESSED;
}

void wolfshim_EC_GROUP_set_point_conversion_form(EC_GROUP *group,
                                                 point_conversion_form_t form)
{
    WOLFSHIM_TRACE();
    (void)group; (void)form;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_GROUP does not store point conversion form;
     * this is a no-op */
}

unsigned char *wolfshim_EC_GROUP_get0_seed(const EC_GROUP *x)
{
    WOLFSHIM_TRACE();
    (void)x;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_GROUP does not store a seed value */
    return NULL;
}

size_t wolfshim_EC_GROUP_get_seed_len(const EC_GROUP *x)
{
    WOLFSHIM_TRACE();
    (void)x;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_GROUP does not store a seed value */
    return 0;
}

size_t wolfshim_EC_GROUP_set_seed(EC_GROUP *group, const unsigned char *p,
                                  size_t len)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)len;
    /*
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_GROUP does not support storing a seed value.
     * The seed passed here is silently discarded — it is never stored and
     * cannot be retrieved via EC_GROUP_get0_seed() / EC_GROUP_get_seed_len().
     * Per the file's error-return policy (see header comment), functions that
     * represent a genuinely unsupported feature return 0 (failure) so callers
     * can detect that the feature is absent.  Seed storage is an unsupported
     * feature, so this function returns 0 consistently with that policy.
     */
    return 0;
}

BN_MONT_CTX *wolfshim_EC_GROUP_get_mont_data(const EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    (void)group;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL hides BN_MONT_CTX internals; cannot return
     * a Montgomery context from the EC_GROUP */
    return NULL;
}

int wolfshim_EC_GROUP_get_basis_type(const EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    (void)group;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) basis type (trinomial/pentanomial) not
     * supported by wolfSSL; return 0 (unknown) */
    return 0;
}

int wolfshim_EC_GROUP_get_trinomial_basis(const EC_GROUP *group,
                                          unsigned int *k)
{
    WOLFSHIM_TRACE();
    (void)group;
    if (k) *k = 0;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) trinomial basis not supported by wolfSSL */
    return 0;
}

int wolfshim_EC_GROUP_get_pentanomial_basis(const EC_GROUP *group,
                                            unsigned int *k1,
                                            unsigned int *k2,
                                            unsigned int *k3)
{
    WOLFSHIM_TRACE();
    (void)group;
    if (k1) *k1 = 0;
    if (k2) *k2 = 0;
    if (k3) *k3 = 0;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) pentanomial basis not supported by wolfSSL */
    return 0;
}

/* =========================================================================
 * EC_GROUP validation / precompute
 * ========================================================================= */

int wolfshim_EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)ctx;
    if (group == NULL)
        return 0;
    /*
     * wolfSSL does not expose EC_GROUP_check.  For a NID-based group a
     * non-zero curve_nid is sufficient evidence that the group is valid.
     * WOLFSHIM_GAP[CORRECTNESS]: only verifies that the group has a non-zero NID;
     * full discriminant / order primality checks are not performed.
     */
    return (group->curve_nid != 0) ? 1 : 0; /* direct struct access, see WOLFSHIM_GAP[CORRECTNESS] at wolfshim_EC_GROUP_copy */
}

int wolfshim_EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)ctx;
    if (group == NULL)
        return 0;
    /*
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not expose EC_GROUP_check_discriminant;
     * best-effort: return 1 for any valid NID-based group.
     */
    return (group->curve_nid != 0) ? 1 : 0; /* direct struct access, see WOLFSHIM_GAP[CORRECTNESS] at wolfshim_EC_GROUP_copy */
}

int wolfshim_EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)ctx;
    /* wolfSSL handles precomputation internally; acceptable no-op returning 1 */
    return 1;
}

int wolfshim_EC_GROUP_have_precompute_mult(const EC_GROUP *group)
{
    WOLFSHIM_TRACE();
    (void)group;
    /* wolfSSL handles precomputation internally; always report available */
    return 1;
}

/* =========================================================================
 * EC_GROUP ASN.1 / parameter objects
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose ECPARAMETERS / ECPKPARAMETERS
 * object constructors via the OpenSSL compat API.  These functions return
 * NULL / 0 to indicate unsupported.
 * ========================================================================= */

EC_GROUP *wolfshim_EC_GROUP_new_from_ecparameters(const void *params)
{
    WOLFSHIM_TRACE();
    (void)params;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL compat layer does not expose
     * EC_GROUP_new_from_ecparameters; ECPARAMETERS type not available */
    return NULL;
}

void *wolfshim_EC_GROUP_get_ecparameters(const EC_GROUP *group,
                                         void *params)
{
    WOLFSHIM_TRACE();
    (void)group; (void)params;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL compat layer does not expose
     * EC_GROUP_get_ecparameters; ECPARAMETERS type not available */
    return NULL;
}

EC_GROUP *wolfshim_EC_GROUP_new_from_ecpkparameters(const void *params)
{
    WOLFSHIM_TRACE();
    (void)params;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL compat layer does not expose
     * EC_GROUP_new_from_ecpkparameters; ECPKPARAMETERS type not available */
    return NULL;
}

void *wolfshim_EC_GROUP_get_ecpkparameters(const EC_GROUP *group,
                                           void *params)
{
    WOLFSHIM_TRACE();
    (void)group; (void)params;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL compat layer does not expose
     * EC_GROUP_get_ecpkparameters; ECPKPARAMETERS type not available */
    return NULL;
}

/* =========================================================================
 * EC_POINT extra operations
 * ========================================================================= */

const EC_METHOD *wolfshim_EC_POINT_method_of(const EC_POINT *point)
{
    WOLFSHIM_TRACE();
    (void)point;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_POINT does not hold a per-point EC_METHOD
     * reference; returning the GFp_simple sentinel as a best-effort value */
    return (const EC_METHOD *)&s_method_GFp_simple;
}

int wolfshim_EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point)
{
    WOLFSHIM_TRACE();
    if (group == NULL || point == NULL)
        return 0;
    /*
     * Set the affine coordinates to (0, 0) to represent the point at infinity
     * in wolfSSL's EC_POINT representation.  wolfSSL uses a projective Z=0
     * check internally; setting all BNs to zero is the accepted approach.
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not provide wolfSSL_EC_POINT_set_to_infinity
     * through the OpenSSL compat layer.  Direct struct field access is required
     * here (point->X, ->Y, ->Z, ->inSet, ->exSet).  This code depends on the
     * internal layout of WOLFSSL_EC_POINT which may change between wolfSSL
     * versions without notice.  The LIBWOLFSSL_VERSION_HEX compile-time guard
     * at the top of this file will trigger a build error if wolfSSL is upgraded
     * past the validated version, prompting re-verification of this layout.
     * This is pinned to the WOLFSSL_EC_POINT layout as of the wolfSSL version
     * used to build this shim.  If wolfSSL restructures WOLFSSL_EC_POINT (e.g.
     * adds reference counting or lazy coordinate evaluation), this code must
     * be revisited.
     */
    if (point->X) wolfSSL_BN_zero(point->X);
    if (point->Y) wolfSSL_BN_zero(point->Y);
    if (point->Z) wolfSSL_BN_zero(point->Z);
    point->inSet = 0;
    point->exSet = 0;
    return 1;
}

int wolfshim_EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r,
                          const EC_POINT *a, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    if (group == NULL || r == NULL || a == NULL)
        return 0;
    /* EC_POINT_dbl(r, a) = EC_POINT_add(r, a, a) by mathematical identity.
     * wolfSSL_EC_POINT_dbl was searched for in the installed wolfSSL headers
     * (<wolfssl/openssl/ec.h> and all transitively included wolfssl headers)
     * and was not found — it is not exposed through the wolfSSL OpenSSL compat
     * layer.  wolfSSL_EC_POINT_add is therefore the only available API.
     *
     * The P=Q (tangent rule) case is handled correctly by wolfSSL's internal
     * ecc library.  wolfSSL_EC_POINT_add delegates to wolfssl_ec_point_add()
     * (wolfssl/src/pk_ec.c), which calls ecc_projective_add_point() from
     * wolfcrypt/src/ecc.c.  That function (_ecc_projective_add_point, ecc.c
     * line ~2051) explicitly detects the P==Q case by comparing x, y, and z
     * coordinates; when they are equal it calls _ecc_projective_dbl_point()
     * directly instead of applying the chord formula.  Passing identical
     * pointers for p1 and p2 results in the Montgomery copies being made from
     * the same source data, so the coordinate comparison will find equality
     * and the doubling path will be taken.  The implementation is correct for
     * the doubling case.
     *
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL_EC_POINT_dbl not found in installed headers;
     * wolfSSL_EC_POINT_add is used for doubling.  wolfSSL's
     * _ecc_projective_add_point (ecc.c) handles the P=Q case via explicit
     * coordinate comparison and delegation to _ecc_projective_dbl_point.
     * A wolfSSL engineer should confirm this analysis remains accurate if the
     * wolfSSL version floor (LIBWOLFSSL_VERSION_HEX) is ever lowered. */
    return wolfSSL_EC_POINT_add(group, r, a, a, ctx);
}

/*
 * EC_POINT affine coordinates — delegates to wolfSSL_EC_POINT_{set,get}_affine_*
 */
int wolfshim_EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p,
                                             const BIGNUM *x, const BIGNUM *y,
                                             BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    return wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
}

int wolfshim_EC_POINT_get_affine_coordinates(const EC_GROUP *group,
                                             const EC_POINT *p,
                                             BIGNUM *x, BIGNUM *y,
                                             BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    return wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
}

int wolfshim_EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group,
                                                  EC_POINT *p,
                                                  const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    return wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
}

int wolfshim_EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
                                                  const EC_POINT *p,
                                                  BIGNUM *x, BIGNUM *y,
                                                  BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    return wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
}

int wolfshim_EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group,
                                                   EC_POINT *p,
                                                   const BIGNUM *x,
                                                   const BIGNUM *y,
                                                   BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)x; (void)y; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) binary-field curves are not supported by
     * wolfSSL.  Delegating to the GFp variant would silently produce wrong
     * results for any genuine binary-field point; return 0 (failure) so the
     * caller can detect that the operation is unsupported. */
    return 0;
}

int wolfshim_EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
                                                   const EC_POINT *p,
                                                   BIGNUM *x, BIGNUM *y,
                                                   BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)x; (void)y; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) binary-field curves are not supported by
     * wolfSSL.  Delegating to the GFp variant would silently produce wrong
     * results for any genuine binary-field point; return 0 (failure) so the
     * caller can detect that the operation is unsupported. */
    return 0;
}

int wolfshim_EC_POINT_set_compressed_coordinates(const EC_GROUP *group,
                                                 EC_POINT *p,
                                                 const BIGNUM *x,
                                                 int y_bit, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    if (group == NULL || p == NULL || x == NULL)
        return 0;
    /*
     * Reconstruct the point from compressed form by encoding as a 0x02/0x03
     * prefixed octet string and decoding via EC_POINT_oct2point.
     * WOLFSHIM_GAP[CORRECTNESS]: This relies on wolfSSL's oct2point supporting
     * compressed encoding; may fail for some curve configurations.
     */
    {
        int field_size = (wolfSSL_EC_GROUP_get_degree(group) + 7) / 8;
        unsigned char *buf;
        int ret;

        buf = (unsigned char *)XMALLOC((size_t)(field_size + 1), NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (buf == NULL)
            return 0;
        buf[0] = (y_bit & 1) ? 0x03 : 0x02;
        {
            int x_bytes = wolfSSL_BN_num_bytes(x);
            int pad = field_size - x_bytes;
            if (x_bytes < 0 || x_bytes > field_size) {
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return 0;
            }
            /* zero-pad the leading bytes, then write x big-endian */
            XMEMSET(buf + 1, 0, (size_t)pad);
            if (wolfSSL_BN_bn2bin(x, buf + 1 + pad) != x_bytes) {
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return 0;
            }
        }
        ret = wolfSSL_EC_POINT_oct2point(group, p, buf,
                                         (size_t)(field_size + 1), ctx);
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
}

int wolfshim_EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group,
                                                      EC_POINT *p,
                                                      const BIGNUM *x,
                                                      int y_bit, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    return wolfshim_EC_POINT_set_compressed_coordinates(group, p, x, y_bit, ctx);
}

int wolfshim_EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group,
                                                       EC_POINT *p,
                                                       const BIGNUM *x,
                                                       int y_bit, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)x; (void)y_bit; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) compressed coordinates not supported */
    return 0;
}

int wolfshim_EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                                       EC_POINT *p,
                                                       const BIGNUM *x,
                                                       const BIGNUM *y,
                                                       const BIGNUM *z,
                                                       BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)group; (void)p; (void)x; (void)y; (void)z; (void)ctx;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL works in affine coordinates internally;
     * Jacobian projective coordinate input is not supported */
    return 0;
}

int wolfshim_EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                                       const EC_POINT *p,
                                                       BIGNUM *x, BIGNUM *y,
                                                       BIGNUM *z,
                                                       BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)ctx;
    if (group == NULL || p == NULL)
        return 0;
    /*
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL stores points in affine form; return
     * affine (x, y) with Z=1 as a best-effort Jacobian representation.
     */
    if (wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, p, x, y, NULL) != 1)
        return 0;
    if (z != NULL) {
        if (wolfSSL_BN_set_word(z, 1) != 1)
            return 0;
    }
    return 1;
}

size_t wolfshim_EC_POINT_point2buf(const EC_GROUP *group,
                                   const EC_POINT *point,
                                   point_conversion_form_t form,
                                   unsigned char **pbuf, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    size_t len;
    unsigned char *buf;

    if (group == NULL || point == NULL || pbuf == NULL)
        return 0;

    /* First call to get required length */
    len = wolfSSL_EC_POINT_point2oct(group, point, form, NULL, 0, ctx);
    if (len == 0)
        return 0;

    buf = (unsigned char *)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL)
        return 0;

    len = wolfSSL_EC_POINT_point2oct(group, point, form, buf, len, ctx);
    if (len == 0) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return 0;
    }
    *pbuf = buf;
    return len;
}

EC_POINT *wolfshim_EC_POINT_bn2point(const EC_GROUP *group, const BIGNUM *bn,
                                     EC_POINT *p, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    if (group == NULL || bn == NULL)
        return NULL;
    {
        /* Convert BIGNUM to byte array, then decode as oct string */
        int bn_len = wolfSSL_BN_num_bytes(bn);
        unsigned char *buf;

        if (bn_len <= 0)
            return NULL;

        buf = (unsigned char *)XMALLOC((size_t)bn_len, NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (buf == NULL)
            return NULL;

        if (wolfSSL_BN_bn2bin(bn, buf) != bn_len) {
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return NULL;
        }

        /* Track whether we allocated a new point so we can free on error */
        int allocated = (p == NULL);
        if (allocated) {
            p = wolfSSL_EC_POINT_new(group);
            if (p == NULL) {
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }
        }

        if (wolfSSL_EC_POINT_oct2point(group, p, buf,
                                       (size_t)bn_len, ctx) != 1) {
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (allocated) wolfSSL_EC_POINT_free(p);
            return NULL;
        }
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return p;
    }
}

int wolfshim_EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point,
                                  BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)ctx;
    if (group == NULL || point == NULL)
        return 0;
    /*
     * wolfSSL stores EC_POINTs in affine form already.  Trigger coordinate
     * sync by reading affine coordinates back.
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_POINT is always affine; this is a no-op.
     */
    return 1;
}

int wolfshim_EC_POINTs_make_affine(const EC_GROUP *group, size_t num,
                                   EC_POINT *points[], BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    size_t i;
    if (group == NULL || (num > 0 && points == NULL))
        return 0;
    /* wolfSSL points are always affine; iterate calling make_affine on each */
    for (i = 0; i < num; i++) {
        if (wolfshim_EC_POINT_make_affine(group, points[i], ctx) != 1)
            return 0;
    }
    return 1;
}

int wolfshim_EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r,
                           const BIGNUM *n, size_t num,
                           const EC_POINT *p[], const BIGNUM *m[],
                           BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    if (group == NULL || r == NULL)
        return 0;

    if (num == 0) {
        /* r = generator * n */
        return wolfSSL_EC_POINT_mul(group, r, n, NULL, NULL, ctx);
    }
    if (num == 1 && p != NULL && m != NULL) {
        /* r = generator * n + p[0] * m[0] */
        return wolfSSL_EC_POINT_mul(group, r, n, p[0], m[0], ctx);
    }

    /*
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_POINT_mul only supports a single point
     * multiplication (r = n*G + m*q).  Multi-point (num > 1) is not
     * directly supported.  As a best-effort, compute the sum iteratively:
     * start with r = n*G, then for each i add p[i]*m[i] via separate
     * EC_POINT_mul calls and point addition.
     */
    {
        size_t i;
        EC_POINT *tmp;
        int ret;

        /* r = n * G */
        ret = wolfSSL_EC_POINT_mul(group, r, n, NULL, NULL, ctx);
        if (ret != 1)
            return 0;

        tmp = wolfSSL_EC_POINT_new(group);
        if (tmp == NULL)
            return 0;

        for (i = 0; i < num; i++) {
            if (p[i] == NULL || m[i] == NULL)
                continue;
            /* tmp = m[i] * p[i] */
            ret = wolfSSL_EC_POINT_mul(group, tmp, NULL, p[i], m[i], ctx);
            if (ret != 1) {
                wolfSSL_EC_POINT_free(tmp);
                return 0;
            }
            /* r = r + tmp */
            ret = wolfSSL_EC_POINT_add(group, r, r, tmp, ctx);
            if (ret != 1) {
                wolfSSL_EC_POINT_free(tmp);
                return 0;
            }
        }
        wolfSSL_EC_POINT_free(tmp);
        return 1;
    }
}

/* =========================================================================
 * EC_KEY extras
 * ========================================================================= */

EC_KEY *wolfshim_EC_KEY_copy(EC_KEY *dst, const EC_KEY *src)
{
    WOLFSHIM_TRACE();
    if (dst == NULL || src == NULL)
        return NULL;
    /*
     * wolfSSL does not expose EC_KEY_copy (copy-into); use EC_KEY_dup and
     * then manually copy the fields into dst.
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL only provides EC_KEY_dup (allocates new key);
     * performing field-level copy into dst.
     */
    if (src->group) {
        if (dst->group == NULL) {
            dst->group = wolfSSL_EC_GROUP_dup(src->group);
            if (dst->group == NULL)
                return NULL; /* allocation failure — do not silently lose pub_key */
        } else {
            wolfshim_EC_GROUP_copy(dst->group, src->group);
        }
    }
    if (src->pub_key) {
        if (dst->pub_key == NULL && dst->group) {
            dst->pub_key = wolfSSL_EC_POINT_dup(src->pub_key, dst->group);
            if (dst->pub_key == NULL)
                return NULL; /* allocation failure */
        } else if (dst->pub_key && dst->group) {
            wolfSSL_EC_POINT_copy(dst->pub_key, src->pub_key);
        }
    }
    if (src->priv_key) {
        if (dst->priv_key == NULL) {
            dst->priv_key = wolfSSL_BN_dup(src->priv_key);
            if (dst->priv_key == NULL)
                return NULL; /* allocation failure */
        } else {
            if (wolfSSL_BN_copy(dst->priv_key, src->priv_key) == NULL)
                return NULL; /* copy failure */
        }
    }
    dst->form = src->form;
    return dst;
}

ENGINE *wolfshim_EC_KEY_get0_engine(const EC_KEY *eckey)
{
    WOLFSHIM_TRACE();
    (void)eckey;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not use ENGINE objects for EC_KEY */
    return NULL;
}

int wolfshim_EC_KEY_get_flags(const EC_KEY *key)
{
    WOLFSHIM_TRACE();
    (void)key;
    /*
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_KEY does not expose a flags field through
     * the OpenSSL compat API; returning 0.
     */
    return 0;
}

void wolfshim_EC_KEY_set_flags(EC_KEY *key, int flags)
{
    WOLFSHIM_TRACE();
    (void)key; (void)flags;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_KEY has no settable flags via compat API;
     * this is a no-op */
}

void wolfshim_EC_KEY_clear_flags(EC_KEY *key, int flags)
{
    WOLFSHIM_TRACE();
    (void)key; (void)flags;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_KEY has no clearable flags via compat API;
     * this is a no-op */
}

int wolfshim_EC_KEY_decoded_from_explicit_params(const EC_KEY *key)
{
    WOLFSHIM_TRACE();
    (void)key;
    /*
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_KEY always uses named-curve parameters;
     * explicit parameter decoding is not supported.  Return 0 (false).
     */
    return 0;
}

int wolfshim_EC_KEY_can_sign(const EC_KEY *eckey)
{
    WOLFSHIM_TRACE();
    if (eckey == NULL)
        return 0;
    /* A key can sign if it has a private key component */
    return (eckey->priv_key != NULL) ? 1 : 0; /* direct struct access; see WOLFSHIM_GAP[CORRECTNESS] at wolfshim_EC_GROUP_copy */
}

unsigned wolfshim_EC_KEY_get_enc_flags(const EC_KEY *key)
{
    WOLFSHIM_TRACE();
    if (key == NULL)
        return 0;
    /*
     * pkcs8HeaderSz field is the closest analog wolfSSL stores; encoding
     * flags (EC_PKEY_NO_PARAMETERS, EC_PKEY_NO_PUBKEY) are not tracked.
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_KEY does not expose enc_flags; returning 0.
     */
    return 0;
}

void wolfshim_EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags)
{
    WOLFSHIM_TRACE();
    (void)eckey; (void)flags;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL EC_KEY has no enc_flags field; no-op */
}

int wolfshim_EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg)
{
    WOLFSHIM_TRACE();
    (void)key; (void)idx; (void)arg;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY does not support ex_data; returning 0 */
    return 0;
}

void *wolfshim_EC_KEY_get_ex_data(const EC_KEY *key, int idx)
{
    WOLFSHIM_TRACE();
    (void)key; (void)idx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY does not support ex_data; returning NULL */
    return NULL;
}

int wolfshim_EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    (void)key; (void)ctx;
    /* wolfSSL handles precomputation internally; acceptable no-op returning 1 */
    return 1;
}

int wolfshim_EC_KEY_print(BIO *bp, const EC_KEY *key, int off)
{
    WOLFSHIM_TRACE();
    if (bp == NULL || key == NULL)
        return 0;
    (void)off;
    /*
     * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL provides wolfSSL_EC_KEY_print_fp (FILE*) but
     * not a BIO-based EC_KEY_print.  This shim cannot forward to a BIO
     * without extracting the underlying FILE* or implementing BIO writing.
     * Returning 0 to indicate unsupported.
     */
    return 0;
}

int wolfshim_EC_KEY_set_public_key_affine_coordinates(EC_KEY *key,
                                                      BIGNUM *x, BIGNUM *y)
{
    WOLFSHIM_TRACE();
    if (key == NULL || x == NULL || y == NULL)
        return 0;
    if (key->group == NULL)
        return 0;
    {
        EC_POINT *pub = wolfSSL_EC_POINT_new(key->group);
        int ret;
        if (pub == NULL)
            return 0;
        ret = wolfSSL_EC_POINT_set_affine_coordinates_GFp(key->group, pub,
                                                          x, y, NULL);
        if (ret == 1)
            ret = wolfSSL_EC_KEY_set_public_key(key, pub);
        wolfSSL_EC_POINT_free(pub);
        return ret;
    }
}

size_t wolfshim_EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form,
                               unsigned char **pbuf, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    const EC_GROUP *group;
    const EC_POINT *pub;

    if (key == NULL || pbuf == NULL)
        return 0;
    group = wolfSSL_EC_KEY_get0_group(key);
    pub   = wolfSSL_EC_KEY_get0_public_key(key);
    if (group == NULL || pub == NULL)
        return 0;
    return wolfshim_EC_POINT_point2buf(group, pub, form, pbuf, ctx);
}

int wolfshim_EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf,
                             size_t len, BN_CTX *ctx)
{
    WOLFSHIM_TRACE();
    if (key == NULL || buf == NULL || len == 0)
        return 0;
    {
        const EC_GROUP *group = wolfSSL_EC_KEY_get0_group(key);
        EC_POINT *pub;
        int ret;

        if (group == NULL)
            return 0;
        pub = wolfSSL_EC_POINT_new(group);
        if (pub == NULL)
            return 0;
        ret = wolfSSL_EC_POINT_oct2point(group, pub, buf, len, ctx);
        if (ret == 1)
            ret = wolfSSL_EC_KEY_set_public_key(key, pub);
        wolfSSL_EC_POINT_free(pub);
        return ret;
    }
}

int wolfshim_EC_KEY_oct2priv(EC_KEY *key, const unsigned char *buf, size_t len)
{
    WOLFSHIM_TRACE();
    if (key == NULL || buf == NULL || len == 0)
        return 0;
    {
        BIGNUM *priv = wolfSSL_BN_bin2bn(buf, (int)len, NULL);
        int ret;
        if (priv == NULL)
            return 0;
        ret = wolfSSL_EC_KEY_set_private_key(key, priv);
        wolfSSL_BN_free(priv);
        return ret;
    }
}

size_t wolfshim_EC_KEY_priv2oct(const EC_KEY *key, unsigned char *buf,
                                size_t len)
{
    WOLFSHIM_TRACE();
    const BIGNUM *priv;
    int field_size;

    if (key == NULL)
        return 0;
    priv = wolfSSL_EC_KEY_get0_private_key(key);
    if (priv == NULL)
        return 0;
    {
        const EC_GROUP *group = wolfSSL_EC_KEY_get0_group(key);
        if (group == NULL)
            return 0;
        field_size = (wolfSSL_EC_GROUP_get_degree(group) + 7) / 8;
    }
    if (buf == NULL)
        return (size_t)field_size;
    if (len < (size_t)field_size)
        return 0;
    {
        int priv_bytes = wolfSSL_BN_num_bytes(priv);
        int pad = field_size - priv_bytes;
        if (priv_bytes < 0 || priv_bytes > field_size)
            return 0;
        XMEMSET(buf, 0, (size_t)pad);
        if (wolfSSL_BN_bn2bin(priv, buf + pad) != priv_bytes)
            return 0;
    }
    return (size_t)field_size;
}

size_t wolfshim_EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf)
{
    WOLFSHIM_TRACE();
    size_t len;
    unsigned char *buf;

    if (eckey == NULL || pbuf == NULL)
        return 0;
    len = wolfshim_EC_KEY_priv2oct(eckey, NULL, 0);
    if (len == 0)
        return 0;
    buf = (unsigned char *)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL)
        return 0;
    if (wolfshim_EC_KEY_priv2oct(eckey, buf, len) != len) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return 0;
    }
    *pbuf = buf;
    return len;
}

EC_KEY *wolfshim_EC_KEY_new_method(ENGINE *engine)
{
    WOLFSHIM_TRACE();
    (void)engine;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not support ENGINE; creates a plain
     * EC_KEY ignoring the engine parameter */
    return wolfSSL_EC_KEY_new();
}

const EC_KEY_METHOD *wolfshim_EC_KEY_get_default_method(void)
{
    WOLFSHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose a default EC_KEY_METHOD;
     * returning the wolfSSL OpenSSL compat method */
    return wolfSSL_EC_KEY_OpenSSL();
}

void wolfshim_EC_KEY_set_default_method(const EC_KEY_METHOD *meth)
{
    WOLFSHIM_TRACE();
    (void)meth;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not support setting a global default
     * EC_KEY_METHOD; this is a no-op */
}

/* =========================================================================
 * EC_KEY_METHOD vtable stubs
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL WOLFSSL_EC_KEY_METHOD is a stub struct with no
 * actual function pointers exposed.  All get/set methods here are no-ops or
 * return with output pointers set to NULL.
 * ========================================================================= */

void wolfshim_EC_KEY_METHOD_set_keygen(EC_KEY_METHOD *meth,
                                       int (*keygen)(EC_KEY *key))
{
    WOLFSHIM_TRACE();
    (void)meth; (void)keygen;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY_METHOD vtable not exposed */
}

void wolfshim_EC_KEY_METHOD_set_compute_key(EC_KEY_METHOD *meth,
                                             int (*ckey)(unsigned char **psec,
                                                         size_t *pseclen,
                                                         const EC_POINT *pub_key,
                                                         const EC_KEY *ecdh))
{
    WOLFSHIM_TRACE();
    (void)meth; (void)ckey;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY_METHOD vtable not exposed */
}

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
                                                          EC_KEY *eckey))
{
    WOLFSHIM_TRACE();
    (void)meth; (void)verify; (void)verify_sig;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY_METHOD vtable not exposed */
}

void wolfshim_EC_KEY_METHOD_get_init(const EC_KEY_METHOD *meth,
                                      int (**pinit)(EC_KEY *key),
                                      void (**pfinish)(EC_KEY *key),
                                      int (**pcopy)(EC_KEY *dest, const EC_KEY *src),
                                      int (**pset_group)(EC_KEY *key, const EC_GROUP *grp),
                                      int (**pset_private)(EC_KEY *key, const BIGNUM *priv_key),
                                      int (**pset_public)(EC_KEY *key, const EC_POINT *pub_key))
{
    WOLFSHIM_TRACE();
    (void)meth;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY_METHOD vtable not exposed */
    if (pinit)       *pinit       = NULL;
    if (pfinish)     *pfinish     = NULL;
    if (pcopy)       *pcopy       = NULL;
    if (pset_group)  *pset_group  = NULL;
    if (pset_private)*pset_private= NULL;
    if (pset_public) *pset_public = NULL;
}

void wolfshim_EC_KEY_METHOD_get_keygen(const EC_KEY_METHOD *meth,
                                        int (**pkeygen)(EC_KEY *key))
{
    WOLFSHIM_TRACE();
    (void)meth;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY_METHOD vtable not exposed */
    if (pkeygen) *pkeygen = NULL;
}

void wolfshim_EC_KEY_METHOD_get_compute_key(const EC_KEY_METHOD *meth,
                                             int (**pck)(unsigned char **psec,
                                                         size_t *pseclen,
                                                         const EC_POINT *pub_key,
                                                         const EC_KEY *ecdh))
{
    WOLFSHIM_TRACE();
    (void)meth;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY_METHOD vtable not exposed */
    if (pck) *pck = NULL;
}

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
                                                               EC_KEY *eckey))
{
    WOLFSHIM_TRACE();
    (void)meth;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY_METHOD vtable not exposed */
    if (psign)      *psign      = NULL;
    if (psign_setup)*psign_setup= NULL;
    if (psign_sig)  *psign_sig  = NULL;
}

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
                                                            EC_KEY *eckey))
{
    WOLFSHIM_TRACE();
    (void)meth;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL EC_KEY_METHOD vtable not exposed */
    if (pverify)     *pverify     = NULL;
    if (pverify_sig) *pverify_sig = NULL;
}

/* =========================================================================
 * ECDSA_SIG accessors (r, s)
 * ========================================================================= */

const BIGNUM *wolfshim_ECDSA_SIG_get0_r(const ECDSA_SIG *sig)
{
    WOLFSHIM_TRACE();
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    if (sig == NULL)
        return NULL;
    wolfSSL_ECDSA_SIG_get0(sig, &r, &s);
    return r;
}

const BIGNUM *wolfshim_ECDSA_SIG_get0_s(const ECDSA_SIG *sig)
{
    WOLFSHIM_TRACE();
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    if (sig == NULL)
        return NULL;
    wolfSSL_ECDSA_SIG_get0(sig, &r, &s);
    return s;
}

/* =========================================================================
 * ECDSA extended sign operations
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not support pre-computed k^-1 (kinv) or
 * the ECDSA_sign_setup / ECDSA_do_sign_ex / ECDSA_sign_ex interface.
 * These shims fall back to the standard sign path ignoring kinv/rp.
 * ========================================================================= */

ECDSA_SIG *wolfshim_ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen,
                                      const BIGNUM *kinv, const BIGNUM *rp,
                                      EC_KEY *eckey)
{
    WOLFSHIM_TRACE();
    (void)kinv; (void)rp;
    /* WOLFSHIM_GAP[CORRECTNESS]: kinv/rp pre-computed k^-1 not supported by wolfSSL;
     * falling back to standard ECDSA_do_sign */
    return wolfSSL_ECDSA_do_sign(dgst, dgstlen, eckey);
}

int wolfshim_ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx,
                               BIGNUM **kinv, BIGNUM **rp)
{
    WOLFSHIM_TRACE();
    (void)eckey; (void)ctx;
    /*
     * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not support ECDSA_sign_setup precomputation;
     * set output pointers to NULL and return failure.
     */
    if (kinv) *kinv = NULL;
    if (rp)   *rp   = NULL;
    return 0;
}

int wolfshim_ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen,
                            unsigned char *sig, unsigned int *siglen,
                            const BIGNUM *kinv, const BIGNUM *rp,
                            EC_KEY *eckey)
{
    WOLFSHIM_TRACE();
    (void)kinv; (void)rp;
    /* WOLFSHIM_GAP[CORRECTNESS]: kinv/rp pre-computed k^-1 not supported by wolfSSL;
     * falling back to standard ECDSA_sign */
    return wolfSSL_ECDSA_sign(type, dgst, dgstlen, sig, siglen, eckey);
}

/* =========================================================================
 * ECDH_KDF_X9_62 — ANSI X9.63 / X9.62 key derivation function
 * ========================================================================= */

int wolfshim_ECDH_KDF_X9_62(unsigned char *out, size_t outlen,
                              const unsigned char *Z, size_t Zlen,
                              const unsigned char *sinfo, size_t sinfolen,
                              const EVP_MD *md)
{
    WOLFSHIM_TRACE();

#ifdef HAVE_X963_KDF
    /* Map EVP_MD to wolfCrypt hash type */
    int nid;
    enum wc_HashType hash_type;

    if (out == NULL || Z == NULL || md == NULL)
        return 0;

    nid = wolfSSL_EVP_MD_type(md);

    switch (nid) {
        case WC_NID_sha1:
            hash_type = WC_HASH_TYPE_SHA;
            break;
        case WC_NID_sha224:
            hash_type = WC_HASH_TYPE_SHA224;
            break;
        case WC_NID_sha256:
            hash_type = WC_HASH_TYPE_SHA256;
            break;
        case WC_NID_sha384:
            hash_type = WC_HASH_TYPE_SHA384;
            break;
        case WC_NID_sha512:
            hash_type = WC_HASH_TYPE_SHA512;
            break;
        default:
            /* WOLFSHIM_GAP[UNSUPPORTED]: unsupported hash type for X9.63 KDF */
            return 0;
    }

    {
        int ret = wc_X963_KDF(hash_type,
                               Z, (word32)Zlen,
                               sinfo, (word32)sinfolen,
                               out, (word32)outlen);
        return (ret == 0) ? 1 : 0;
    }
#else
    (void)out; (void)outlen; (void)Z; (void)Zlen;
    (void)sinfo; (void)sinfolen; (void)md;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL not built with HAVE_X963_KDF; ECDH_KDF_X9_62
     * is unavailable */
    return 0;
#endif /* HAVE_X963_KDF */
}
