/*
 * evp_wolf_bridge.c — wolfSSL-side EVP digest bridge (wolfSSL headers only)
 *
 * This file is compiled with ONLY wolfSSL headers (no OpenSSL headers).
 * It provides a C bridge layer that EVP_MD callbacks can call to
 * init/update/final/cleanup digest operations using wolfSSL's EVP layer.
 *
 * Algorithm IDs defined in evp_wolf_bridge.h.
 */

#include <stddef.h>
#include <string.h>

/* wolfSSL headers only */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

/* Hard requirements: these algorithms underpin TLS and certificate handling */
#ifdef NO_SHA
# error "wolfSSL must be built with SHA-1 support to use evp_wolf_bridge.c"
#endif
#ifdef NO_SHA256
# error "wolfSSL must be built with SHA-256 support to use evp_wolf_bridge.c"
#endif
#ifdef NO_MD5
# error "wolfSSL must be built with MD5 support to use evp_wolf_bridge.c"
#endif

#include <wolfssl/openssl/evp.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>

/* ERR_put_error + ERR_R_* constants via wolfSSL compat header */
#include <wolfssl/openssl/err.h>
/* ERR_LIB_EVP is defined in wolfssl/openssl/ssl.h, pulled transitively by
 * evp.h on most wolfSSL builds.  Guard with a fallback in case it is not. */
#ifndef ERR_LIB_EVP
# define ERR_LIB_EVP 6
#endif

#include <evp_wolf_bridge.h>

/*
 * Returns the size in bytes needed to store a WOLFSSL_EVP_MD_CTX.
 * The caller (OpenSSL side) uses this as ctx_size in the EVP_MD struct.
 * We store one pointer (to a heap-allocated context) so the actual
 * storage needed in md_data is sizeof(void*).
 */
size_t wolf_md_ptr_size(void)
{
    return sizeof(WOLFSSL_EVP_MD_CTX *);
}

/*
 * Translate our algo_id to the wolfSSL EVP_MD string.
 */
static const WOLFSSL_EVP_MD *algo_to_wssl_md(int algo_id)
{
    switch (algo_id) {
    case WOLF_MD_SHA1:       return wolfSSL_EVP_sha1();
    case WOLF_MD_SHA224:     return wolfSSL_EVP_sha224();
    case WOLF_MD_SHA256:     return wolfSSL_EVP_sha256();
    case WOLF_MD_SHA384:     return wolfSSL_EVP_sha384();
    case WOLF_MD_SHA512:     return wolfSSL_EVP_sha512();
    case WOLF_MD_SHA512_224: return wolfSSL_EVP_sha512_224();
    case WOLF_MD_SHA512_256: return wolfSSL_EVP_sha512_256();
    case WOLF_MD_MD4:        return wolfSSL_EVP_md4();
    case WOLF_MD_MD5:        return wolfSSL_EVP_md5();
    case WOLF_MD_RMD160:     return wolfSSL_EVP_ripemd160();
    case WOLF_MD_SHA3_224:   return wolfSSL_EVP_sha3_224();
    case WOLF_MD_SHA3_256:   return wolfSSL_EVP_sha3_256();
    case WOLF_MD_SHA3_384:   return wolfSSL_EVP_sha3_384();
    case WOLF_MD_SHA3_512:   return wolfSSL_EVP_sha3_512();
    case WOLF_MD_SHAKE128:
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NO_SHAKE128)
        return wolfSSL_EVP_shake128();
#else
        return NULL;
#endif
    case WOLF_MD_SHAKE256:
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NO_SHAKE256)
        return wolfSSL_EVP_shake256();
#else
        return NULL;
#endif
    case WOLF_MD_MDC2:       return wolfSSL_EVP_mdc2();
    default:                 return NULL;
    }
}

/*
 * wolf_md_init: initialise the wolfSSL digest context stored at *pctx.
 * md_data_ptr points to sizeof(void*) bytes of storage in OpenSSL's
 * EVP_MD_CTX md_data area; we store a heap-allocated WOLFSSL_EVP_MD_CTX
 * pointer there.
 */
int wolf_md_init(void *md_data_ptr, int algo_id)
{
    WOLFSSL_EVP_MD_CTX **pp = (WOLFSSL_EVP_MD_CTX **)md_data_ptr; /* pp = pointer to the heap-allocated wolfSSL context slot */
    WOLFSSL_EVP_MD_CTX *wctx;
    const WOLFSSL_EVP_MD *wmd;

    if (!pp)
        return 0;

    wmd = algo_to_wssl_md(algo_id);
    if (!wmd)
        return 0;

    /* Allocate if not present.
     * Use wolfSSL_EVP_MD_CTX_new() so the runtime wolfSSL library allocates
     * the correct size internally — avoids an ABI mismatch if the installed
     * wolfSSL library's actual struct is larger than sizeof() as seen by the
     * shim's compile-time headers. */
    if (*pp == NULL) {
        wctx = wolfSSL_EVP_MD_CTX_new();
        if (!wctx)
            return 0;
        *pp = wctx;
    } else {
        wctx = *pp;
    }

    return wolfSSL_EVP_DigestInit_ex(wctx, wmd, NULL);
}

/*
 * wolf_md_update: pass data to the digest.
 */
int wolf_md_update(void *md_data_ptr, const void *data, size_t count)
{
    WOLFSSL_EVP_MD_CTX *wctx;
    WOLFSSL_EVP_MD_CTX **pp = (WOLFSSL_EVP_MD_CTX **)md_data_ptr;
    if (!pp || !*pp)
        return 0;
    /* Guard against size_t -> word32 truncation.  EVP_DigestUpdate callers
     * streaming >4 GB in a single call get a clean error rather than a
     * silent truncation to the wrong byte count. */
    if (count > (word32)-1) {
        ERR_put_error(ERR_LIB_EVP, 0, ERR_R_PASSED_INVALID_ARGUMENT,
                      __FILE__, __LINE__);
        return 0;
    }
    wctx = *pp;
    return wolfSSL_EVP_DigestUpdate(wctx, data, (unsigned int)count);
}

/*
 * wolf_md_final: finalise the digest and write output.
 */
int wolf_md_final(void *md_data_ptr, unsigned char *out)
{
    unsigned int len = 0;
    WOLFSSL_EVP_MD_CTX *wctx;
    WOLFSSL_EVP_MD_CTX **pp = (WOLFSSL_EVP_MD_CTX **)md_data_ptr;
    if (!pp || !*pp)
        return 0;
    wctx = *pp;
    return wolfSSL_EVP_DigestFinal_ex(wctx, out, &len);
}

/*
 * wolf_md_final_xof: produce variable-length XOF output (SHAKE128/256).
 */
int wolf_md_final_xof(void *md_data_ptr, unsigned char *out, size_t len)
{
    WOLFSSL_EVP_MD_CTX **pp = (WOLFSSL_EVP_MD_CTX **)md_data_ptr;
    if (!pp || !*pp)
        return 0;
    return wolfSSL_EVP_DigestFinalXOF(*pp, out, len) == 1 ? 1 : 0;
}

/*
 * wolf_md_copy: copy the wolfSSL context from src to dst.
 */
int wolf_md_copy(void *dst_md_data_ptr, const void *src_md_data_ptr)
{
    WOLFSSL_EVP_MD_CTX **dst_pp = (WOLFSSL_EVP_MD_CTX **)dst_md_data_ptr;
    WOLFSSL_EVP_MD_CTX * const *src_pp =
        (WOLFSSL_EVP_MD_CTX * const *)src_md_data_ptr;
    WOLFSSL_EVP_MD_CTX *dst_wctx;

    /*
     * md_data may be NULL when the EVP_MD_CTX was set up with
     * EVP_MD_CTX_FLAG_NO_INIT (used by the HMAC pkey method).  In that
     * case there is no wolfSSL context to copy — return success.
     */
    if (!dst_pp || !src_pp)
        return 1;

    /* source wolfSSL context not yet allocated — nothing to copy */
    if (!*src_pp) {
        /* Free any existing destination context before clearing the pointer. */
        if (*dst_pp) {
            wolfSSL_EVP_MD_CTX_free(*dst_pp);
            *dst_pp = NULL;
        }
        return 1;
    }

    /* Optimisation: if the destination context is already allocated, copy
     * directly into it to avoid a malloc+free pair on the hot TLS PRF path. */
    if (*dst_pp) {
        return wolfSSL_EVP_MD_CTX_copy_ex(*dst_pp, *src_pp);
    }

    /* No existing destination — allocate via wolfSSL_EVP_MD_CTX_new() to get
     * the correct runtime size, then copy with wolfSSL_EVP_MD_CTX_copy_ex(). */
    dst_wctx = wolfSSL_EVP_MD_CTX_new();
    if (!dst_wctx)
        return 0;
    if (!wolfSSL_EVP_MD_CTX_copy_ex(dst_wctx, *src_pp)) {
        wolfSSL_EVP_MD_CTX_free(dst_wctx);
        return 0;
    }
    *dst_pp = dst_wctx;
    return 1;
}

/*
 * wolf_md_cleanup: free the wolfSSL context stored at md_data_ptr.
 */
int wolf_md_cleanup(void *md_data_ptr)
{
    WOLFSSL_EVP_MD_CTX **pp = (WOLFSSL_EVP_MD_CTX **)md_data_ptr;
    if (pp && *pp) {
        /* wolfSSL_EVP_MD_CTX_free does cleanup + free with the correct size */
        wolfSSL_EVP_MD_CTX_free(*pp);
        *pp = NULL;
    }
    return 1;
}

/* =========================================================================
 * Native RIPEMD-160 via wolfCrypt wc_* API
 *
 * wolfSSL_EVP_ripemd160() is a stub returning NULL, so we bypass the EVP
 * layer and call the wolfCrypt primitives directly.
 * md_data_ptr stores one RipeMd * (heap-allocated) in the pointer slot of
 * the caller's EVP_MD_CTX md_data area.
 *
 * Lifecycle differs from the other EVP digest paths (wolf_md_init/final):
 *
 *   wolf_md_init    — reuses an existing WOLFSSL_EVP_MD_CTX if *pp != NULL,
 *                     avoiding a malloc+free pair on the Init→Final→Init
 *                     hot path (e.g. TLS record hashing).
 *
 *   wolf_rmd160_init — always allocates fresh; wolf_rmd160_final frees.
 *                     No reuse across Final→Init cycles.
 *
 * Why no reuse here: RIPEMD-160 is not on any TLS hot path (it appears only
 * in legacy certificate signatures and a handful of CMS operations).  The
 * malloc+free overhead is not measurable in practice.  Implementing reuse
 * would require checking *pp != NULL and calling wc_InitRipeMd(*pp) in
 * place — technically straightforward, but adds code for no observable
 * benefit at current usage rates.  If profiling ever shows RIPEMD-160
 * Init→Final→Init in a hot loop, add the reuse check here mirroring
 * wolf_md_init (lines 107-117 above).
 * ========================================================================= */
#include <wolfssl/wolfcrypt/ripemd.h>

int wolf_rmd160_init(void *md_data_ptr)
{
    RipeMd **pp = (RipeMd **)md_data_ptr;
    /* Always allocates fresh — no reuse across Final→Init. See block comment. */
    RipeMd *ctx = (RipeMd *)XMALLOC(sizeof(RipeMd), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return 0;
    if (wc_InitRipeMd(ctx) != 0) { XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER); return 0; }
    *pp = ctx;
    return 1;
}

int wolf_rmd160_update(void *md_data_ptr, const void *data, size_t count)
{
    RipeMd **pp = (RipeMd **)md_data_ptr;
    if (!pp || !*pp) return 0;
    /* Guard against size_t -> word32 truncation.  See wolf_md_update comment. */
    if (count > (word32)-1) {
        ERR_put_error(ERR_LIB_EVP, 0, ERR_R_PASSED_INVALID_ARGUMENT,
                      __FILE__, __LINE__);
        return 0;
    }
    return wc_RipeMdUpdate(*pp, (const byte *)data, (word32)count) == 0 ? 1 : 0;
}

int wolf_rmd160_final(void *md_data_ptr, unsigned char *out)
{
    RipeMd **pp = (RipeMd **)md_data_ptr;
    if (!pp || !*pp) return 0;
    int rc = (wc_RipeMdFinal(*pp, (byte *)out) == 0) ? 1 : 0;
    /* Free immediately rather than keeping the allocation for Init reuse.
     * See block comment above wolf_rmd160_init for rationale. */
    XFREE(*pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    *pp = NULL;
    return rc;
}

int wolf_rmd160_copy(void *dst_md_data_ptr, const void *src_md_data_ptr)
{
    RipeMd **dst = (RipeMd **)dst_md_data_ptr;
    RipeMd * const *src = (RipeMd * const *)src_md_data_ptr;
    if (!dst || !src || !*src) return 0;
    RipeMd *ctx = (RipeMd *)XMALLOC(sizeof(RipeMd), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return 0;
    *ctx = **src;
    /* Free any pre-existing destination context before overwriting. */
    if (*dst)
        XFREE(*dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    *dst = ctx;
    return 1;
}

int wolf_rmd160_cleanup(void *md_data_ptr)
{
    RipeMd **pp = (RipeMd **)md_data_ptr;
    if (pp && *pp) { XFREE(*pp, NULL, DYNAMIC_TYPE_TMP_BUFFER); *pp = NULL; }
    return 1;
}

/* =========================================================================
 * MD5+SHA1 combined digest — used for TLS 1.0/1.1 client certificate auth.
 * Output: MD5(data) || SHA1(data) — 36 bytes total.
 * md_data stores struct md5_sha1_ctx directly (no heap pointer indirection).
 * ========================================================================= */

struct md5_sha1_ctx {
    wc_Md5 md5;
    wc_Sha sha1;
};

size_t wolf_md5sha1_ctx_size(void)
{
    return sizeof(struct md5_sha1_ctx);
}

int wolf_md5sha1_init(void *md_data)
{
    struct md5_sha1_ctx *ctx = (struct md5_sha1_ctx *)md_data;
    return (wc_InitMd5(&ctx->md5) == 0 && wc_InitSha(&ctx->sha1) == 0) ? 1 : 0;
}

int wolf_md5sha1_update(void *md_data, const void *data, size_t len)
{
    struct md5_sha1_ctx *ctx = (struct md5_sha1_ctx *)md_data;
    /* Guard against size_t -> word32 truncation.  See wolf_md_update comment. */
    if (len > (word32)-1) {
        ERR_put_error(ERR_LIB_EVP, 0, ERR_R_PASSED_INVALID_ARGUMENT,
                      __FILE__, __LINE__);
        return 0;
    }
    return (wc_Md5Update(&ctx->md5, (const byte *)data, (word32)len) == 0 &&
            wc_ShaUpdate(&ctx->sha1, (const byte *)data, (word32)len) == 0) ? 1 : 0;
}

int wolf_md5sha1_final(void *md_data, unsigned char *out)
{
    struct md5_sha1_ctx *ctx = (struct md5_sha1_ctx *)md_data;
    return (wc_Md5Final(&ctx->md5, out) == 0 &&
            wc_ShaFinal(&ctx->sha1, out + 16) == 0) ? 1 : 0;
}

int wolf_md5sha1_copy(void *dst, const void *src)
{
    *(struct md5_sha1_ctx *)dst = *(const struct md5_sha1_ctx *)src;
    return 1;
}

int wolf_md5sha1_cleanup(void *md_data)
{
    struct md5_sha1_ctx *ctx = (struct md5_sha1_ctx *)md_data;
    wc_Md5Free(&ctx->md5);
    wc_ShaFree(&ctx->sha1);
    return 1;
}
