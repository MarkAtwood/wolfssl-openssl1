/*
 * wolfshim_preinclude.h - Pre-include header for wolfCrypt shim compilation
 *
 * This header pulls in wolfSSL compat types then undefs macros that would
 * hijack the shim's own function definitions. Must be -include'd before
 * the shim .c source file.
 */

#ifndef WOLFSHIM_PREINCLUDE_H
#define WOLFSHIM_PREINCLUDE_H

/* wolfSSL options must come first */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

/* Provide a concrete definition for WOLFSSL_BN_GENCB before wolfSSL headers
 * forward-declare it as incomplete. This makes sizeof(BN_GENCB) work in
 * bn_shim.c without requiring the full wolfSSL internal struct layout. */
struct WOLFSSL_BN_GENCB { int _pad; };

/* wolfSSL OpenSSL compat headers for types (AES_KEY, BIGNUM, etc.) */
#include <wolfssl/openssl/aes.h>

/* Undefine wolfSSL macro aliases that would hijack the shim's function defs */
#undef AES_cbc_encrypt
#undef AES_ecb_encrypt
#undef AES_cfb128_encrypt
#undef AES_set_encrypt_key
#undef AES_set_decrypt_key
#undef AES_wrap_key
#undef AES_unwrap_key
#undef AES_encrypt
#undef AES_decrypt
/* AES direction constant mapping:
 * OpenSSL: AES_ENCRYPT=1, AES_DECRYPT=0
 * wolfCrypt: AES_ENCRYPTION=0, AES_DECRYPTION=1
 * These are INVERTED. Every direction check in this shim must use
 * the OpenSSL constants and explicitly map to wolfCrypt constants.
 * The correct mapping is: wolfCrypt_enc = (openssl_enc == AES_DECRYPT ? 0 : 1)
 * i.e. NOT a direct assignment.
 *
 * wolfSSL remaps AES_ENCRYPT/AES_DECRYPT to its own enum values via macros;
 * undef and restore the OpenSSL integer constants so all shim code that
 * tests (enc == AES_ENCRYPT) works correctly regardless of include order. */
#undef AES_ENCRYPT
#undef AES_DECRYPT
#define AES_ENCRYPT 1
#define AES_DECRYPT 0

/* BN_BLINDING / BN_RECP_CTX: not defined in wolfSSL; provide opaque stubs.
 * Use the same struct tag name as OpenSSL so forward declarations in shim
 * source files (typedef struct bn_blinding_st BN_BLINDING) also work. */
#ifndef BN_BLINDING_DEFINED
#define BN_BLINDING_DEFINED
struct bn_blinding_st { int _pad; };
typedef struct bn_blinding_st BN_BLINDING;
#endif

#ifndef BN_RECP_CTX_DEFINED
#define BN_RECP_CTX_DEFINED
struct bn_recp_ctx_st { int _pad; };
typedef struct bn_recp_ctx_st BN_RECP_CTX;
#endif

#endif /* WOLFSHIM_PREINCLUDE_H */
