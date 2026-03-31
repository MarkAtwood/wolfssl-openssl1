/*
 * wolfshim_compat.h - Type compatibility bridge for wolfCrypt shim layer
 *
 * Provides typedefs that bridge OpenSSL ABI types not present in wolfSSL's
 * compatibility headers. This header must be included AFTER wolfssl headers.
 */

#ifndef WOLFSHIM_COMPAT_H
#define WOLFSHIM_COMPAT_H

/* BN_BLINDING: OpenSSL internal type not exported by wolfSSL.
 * The shim layer implements stub functions under this name. */
#ifndef BN_BLINDING
typedef struct bn_blinding_st BN_BLINDING;
struct bn_blinding_st { int _dummy; };
#endif

/* BN_RECP_CTX: OpenSSL reciprocal context, not in wolfSSL. */
#ifndef BN_RECP_CTX
typedef struct bn_recp_ctx_st BN_RECP_CTX;
struct bn_recp_ctx_st { int _dummy; };
#endif

/* AES_KEY: OpenSSL AES key structure.
 * wolfSSL defines WOLFSSL_AES_KEY and then typedef's AES_KEY in openssl/aes.h
 * but only when OPENSSL_EXTRA is set correctly. Provide it here as fallback. */
#ifndef WOLFSSL_AES_KEY
#include <wolfssl/openssl/aes.h>
#endif

#endif /* WOLFSHIM_COMPAT_H */
