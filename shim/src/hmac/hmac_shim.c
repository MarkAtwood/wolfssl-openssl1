/*
 * hmac_shim.c - OpenSSL 1.1.1 HMAC API shims dispatching to wolfCrypt
 *
 * Symbols implemented:
 *   HMAC_CTX_reset
 *   HMAC_CTX_set_flags
 *
 * Build requirements:
 *   - wolfSSL built with OPENSSL_EXTRA (enables WOLFSSL_HMAC_CTX and the
 *     wolfSSL_HMAC_* compatibility functions)
 *   - Include paths must resolve both wolfssl/ and wolfssl/wolfssl/
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WOLFSHIM_DEBUG
#include <stdio.h>
#endif

/*
 * Pull in the wolfSSL OpenSSL-compat HMAC types and function declarations.
 * This defines WOLFSSL_HMAC_CTX, wolfSSL_HMAC_CTX_cleanup(), and
 * wolfSSL_HMAC_CTX_Init().
 */
#include <wolfssl/openssl/hmac.h>

/*
 * The shim's own header.  It uses HMAC_CTX which is typedef'd above via
 * wolfSSL's compat header, so include it after the wolfSSL header.
 */
#include "hmac_shim.h"

/* -------------------------------------------------------------------------
 * HMAC_CTX_reset
 * -------------------------------------------------------------------------
 * OpenSSL 1.1.1 signature:
 *   int HMAC_CTX_reset(HMAC_CTX *ctx);
 *
 * Semantics: release any resources held by ctx and return it to the same
 * state as a freshly allocated context.  Returns 1 on success.
 *
 * wolfSSL mapping:
 *   wolfSSL_HMAC_CTX_cleanup(ctx) frees wc_HmacFree internal state.
 *   wolfSSL_HMAC_CTX_Init(ctx)    zeroes the struct, ready for reuse.
 *   Both return void/1 respectively; combined they match the OpenSSL reset.
 * ------------------------------------------------------------------------- */
int HMAC_CTX_reset(HMAC_CTX *ctx)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] hmac: %s called\n", __func__);
#endif

    if (ctx == NULL) {
        return 0;
    }

    /* Release any wc_HmacFree() resources held inside the context. */
    wolfSSL_HMAC_CTX_cleanup(ctx);

    /* Re-zero the struct so the context is ready to be reused.
     * wolfSSL_HMAC_CTX_Init() returns int but is infallible for non-NULL ctx:
     * it returns 1 unconditionally when ctx != NULL (see wolfSSL ssl_crypto.c).
     * The NULL case has already been handled above, so no return-value check
     * is required here.  If a future wolfSSL version makes Init fallible,
     * this site must be revisited. */
    wolfSSL_HMAC_CTX_Init(ctx);

    return 1;
}

/* -------------------------------------------------------------------------
 * HMAC_CTX_set_flags
 * -------------------------------------------------------------------------
 * OpenSSL 1.1.1 signature:
 *   void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);
 *
 * Semantics: propagate EVP-level flags (e.g. EVP_MD_CTX_FLAG_NO_INIT) into
 * the underlying EVP_MD_CTX objects that an OpenSSL HMAC_CTX contains.
 *
 * wolfSSL mapping:
 *   WOLFSSL_HMAC_CTX (defined in wolfssl/openssl/compat_types.h) contains:
 *     Hmac    hmac;
 *     int     type;
 *     word32  save_ipad[...];
 *     word32  save_opad[...];
 *   There is no flags field and no wolfSSL API to set EVP flags on an
 *   HMAC_CTX.  The function is therefore a documented no-op stub.
 *
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not expose an EVP flags mechanism on
 *   HMAC_CTX.  Callers that rely on specific flag semantics (e.g.
 *   EVP_MD_CTX_FLAG_NO_INIT used by some TLS PRF implementations) will not
 *   get the intended behaviour.  Revisit if wolfSSL gains a flags field in
 *   WOLFSSL_HMAC_CTX or an equivalent API.
 * ------------------------------------------------------------------------- */
void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] hmac: %s called\n", __func__);
#endif

    (void)ctx;
    (void)flags;
}
