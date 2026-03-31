/*
 * hmac_shim.h - OpenSSL 1.1.1 HMAC API shims dispatching to wolfCrypt
 *
 * Symbols covered:
 *   HMAC_CTX_reset
 *   HMAC_CTX_set_flags
 */

#ifndef WOLFSHIM_HMAC_SHIM_H
#define WOLFSHIM_HMAC_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Include-order requirement: wolfssl/openssl/hmac.h (or openssl/hmac.h) MUST
 * be included before this header so that HMAC_CTX (typedef'd from
 * WOLFSSL_HMAC_CTX) is already defined when the prototypes below are parsed.
 *
 * Enforcement: if neither wolfSSL's nor OpenSSL's hmac.h has been included
 * the HMAC_CTX type will be unknown and the compiler will emit a confusing
 * "unknown type name" error on the prototypes below.  Include one of:
 *   #include <wolfssl/openssl/hmac.h>
 *   #include <openssl/hmac.h>
 * before this header.
 */
#if !defined(WOLFSSL_HMAC_H_) && !defined(HEADER_HMAC_H)
#error "Include wolfssl/openssl/hmac.h (or openssl/hmac.h) before hmac_shim.h"
#endif

/*
 * HMAC_CTX_reset - clear and reinitialise an existing HMAC context.
 *
 * OpenSSL 1.1.1 signature:
 *   int HMAC_CTX_reset(HMAC_CTX *ctx);
 *
 * Returns 1 on success; returns 0 if ctx is NULL (defensive extension —
 * OpenSSL does not define NULL behaviour for this function).
 */
int HMAC_CTX_reset(HMAC_CTX *ctx);

/*
 * HMAC_CTX_set_flags - set flags on an HMAC context.
 *
 * OpenSSL 1.1.1 signature:
 *   void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);
 *
 * wolfSSL HMAC_CTX has no flags field; this is a documented stub.
 */
void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSHIM_HMAC_SHIM_H */
