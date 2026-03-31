/*
 * misc_stubs.c — Stub implementations for symbols not covered by other shims.
 *
 * Covers:
 *   - SHA internal assembly-ABI functions (sha1_block_data_order, etc.)
 *   - SHA Transform functions (SHA1_Transform, SHA256_Transform, SHA512_Transform)
 *   - SHA3 (absorb/squeeze) — stub
 *   - vpaes_* (vector AES, dispatch to standard AES)
 *   - Legacy ciphers: ARIA, BF, Camellia, CAST, RC2, SEED, WHIRLPOOL,
 *                     MDC2, RIPEMD160, ChaCha20, xor128, rc4_md5
 *   - DES extras (cfb/ofb/xcbc/ecb3 variants)
 *   - DSA/DH/EC/RSA data object stubs (pkey_meth pointers, ASN1_IT)
 *   - ERR_load_* stubs
 *   - Internal cleanup stubs
 *   - Poly1305 stubs
 *   - EVP_sm3, DH_check_params, EC_KEY_can_sign, etc.
 *   - d2i/i2d DSA private/public key
 *
 * IMPORTANT: Do NOT include any real OpenSSL headers here.
 * Including <openssl/err.h> pulls in <openssl/stack.h> which defines
 * OPENSSL_STACK, conflicting with WOLFSSL_STACK from wolfSSL headers.
 * Instead we forward-declare ERR_put_error and define constants manually.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WOLFSHIM_DEBUG
# define WOLFSHIM_LOG(name) fprintf(stderr, "[wolfshim] stubs: %s called\n", name)
#else
# define WOLFSHIM_LOG(name) ((void)0)
#endif

/* wolfSSL options must come first to enable all configured features
 * (WOLFSSL_SHA224, WOLFSSL_SHA384, WOLFSSL_SHA512, OPENSSL_EXTRA, etc.) */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/aes.h>

/*
 * Undef wolfSSL's macro redirections so our function definitions below are
 * not preprocessor-renamed to wolfSSL_* (which would cause type conflicts).
 */
#ifdef SHA1_Transform
# undef SHA1_Transform
#endif
#ifdef SHA256_Transform
# undef SHA256_Transform
#endif
#ifdef SHA512_Transform
# undef SHA512_Transform
#endif
#ifdef EVP_sm3
# undef EVP_sm3
#endif
#ifdef AES_encrypt
# undef AES_encrypt
#endif
#ifdef AES_decrypt
# undef AES_decrypt
#endif
#ifdef AES_cbc_encrypt
# undef AES_cbc_encrypt
#endif
#ifdef AES_set_encrypt_key
# undef AES_set_encrypt_key
#endif
#ifdef AES_set_decrypt_key
# undef AES_set_decrypt_key
#endif

/*
 * Forward declarations for the shim AES entry-points defined in aliases.c.
 * After the undefs above, wolfssl/openssl/aes.h no longer provides prototypes
 * via macro redirection, so we declare the symbols explicitly.  These must
 * match the aliases.c signatures exactly.
 */
/* Use the AES_KEY type that was pulled in via wolfssl/openssl/aes.h */
int  AES_set_encrypt_key(const unsigned char *key, int bits, AES_KEY *schedule);
int  AES_set_decrypt_key(const unsigned char *key, int bits, AES_KEY *schedule);
void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);

/*
 * Forward-declare ERR_put_error and define the constants we need,
 * so we can report errors without including <openssl/err.h>.
 */
#ifndef ERR_LIB_EVP
# define ERR_LIB_EVP 6
#endif
#ifndef ERR_R_FATAL
# define ERR_R_FATAL 64
#endif
#ifndef ERR_R_DISABLED
# define ERR_R_DISABLED (5 | ERR_R_FATAL)
#endif

extern void ERR_put_error(int lib, int func, int reason,
                          const char *file, int line);

/* =========================================================================
 * SHA Transform functions — dispatch to wolfSSL
 *
 * OpenSSL declares these as void; wolfSSL_SHA*_Transform returns int.
 * We provide the void wrappers (macros were undeffed above).
 * ========================================================================= */

void SHA1_Transform(WOLFSSL_SHA_CTX *c, const unsigned char *data)
{
    /* sha_shim.c stores a WOLFSSL_SHA_CTX * heap pointer in the first
     * sizeof(void*) bytes of the caller's (OpenSSL-sized) SHA_CTX.
     * Dereference before forwarding so we pass the real wolfSSL context,
     * not the pointer-wrapper struct. */
    WOLFSSL_SHA_CTX **pp = (WOLFSSL_SHA_CTX **)(void *)c;
    WOLFSHIM_LOG("SHA1_Transform");
    if (!pp || !*pp) return;
    (void)wolfSSL_SHA1_Transform(*pp, data);
}

void SHA256_Transform(WOLFSSL_SHA256_CTX *c, const unsigned char *data)
{
    /* Same heap-pointer indirection as SHA1_Transform — see comment above. */
    WOLFSSL_SHA256_CTX **pp = (WOLFSSL_SHA256_CTX **)(void *)c;
    WOLFSHIM_LOG("SHA256_Transform");
    if (!pp || !*pp) return;
    (void)wolfSSL_SHA256_Transform(*pp, data);
}

void SHA512_Transform(WOLFSSL_SHA512_CTX *c, const unsigned char *data)
{
    /* Same heap-pointer indirection as SHA1_Transform — see comment above.
     * SHA384_Transform uses the same wolfSSL context type as SHA512. */
    WOLFSSL_SHA512_CTX **pp = (WOLFSSL_SHA512_CTX **)(void *)c;
    WOLFSHIM_LOG("SHA512_Transform");
    if (!pp || !*pp) return;
    (void)wolfSSL_SHA512_Transform(*pp, data);
}

/* =========================================================================
 * SHA internal assembly-ABI stubs
 * ========================================================================= */

void sha1_block_data_order(void *ctx, const void *inp, size_t blocks)
{
    /* WOLFSHIM_GAP[UNSUPPORTED]: This internal OpenSSL SHA-1 block-compression entry
     * point should never be reached — sha_shim.c routes all SHA-1 operations
     * through wolfSSL_SHA1_* and does not expose the raw block function.
     * If this is reached, the hash output will be wrong (the block was not
     * processed).  Push an error so callers checking ERR_get_error() can
     * detect the failure; do not abort() since that kills the whole process. */
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx; (void)inp; (void)blocks;
}

void sha256_block_data_order(void *ctx, const void *inp, size_t blocks)
{
    /* See sha1_block_data_order comment above — same reasoning applies. */
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx; (void)inp; (void)blocks;
}

void sha1_multi_block(void *ctx, const void *inp, int num)
{
    /* WOLFSHIM_GAP[UNSUPPORTED]: sha1_multi_block is the multi-buffer SHA-1
     * acceleration entry point.  If called, the blocks are not processed and
     * the hash output will be wrong.  Push an error so callers checking
     * ERR_get_error() can detect the failure; do not abort() since that kills
     * the whole process. */
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    WOLFSHIM_LOG("sha1_multi_block");
    (void)ctx; (void)inp; (void)num;
}

void sha256_multi_block(void *ctx, const void *inp, int num)
{
    /* WOLFSHIM_GAP[UNSUPPORTED]: sha256_multi_block is the multi-buffer SHA-256
     * acceleration entry point.  If called, the blocks are not processed and
     * the hash output will be wrong.  Push an error so callers checking
     * ERR_get_error() can detect the failure; do not abort() since that kills
     * the whole process. */
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    WOLFSHIM_LOG("sha256_multi_block");
    (void)ctx; (void)inp; (void)num;
}

/* WOLFSHIM_GAP[UNSUPPORTED]: SHA-512/224 and SHA-512/256 truncated variants are
 * not exposed in wolfCrypt's OpenSSL-compat layer.  These functions return 0
 * which, in OpenSSL convention for SHA*_Init functions, means failure.
 * The EVP layer (m_sha1.c) propagates the 0 upward as an init error.
 * Safe to stub: these are rarely-used truncation variants; any caller that
 * checks the return value will get a detectable error. */
int sha512_224_init(void *ctx)
{
    WOLFSHIM_LOG("sha512_224_init");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx;
    return 0;
}

int sha512_256_init(void *ctx)
{
    WOLFSHIM_LOG("sha512_256_init");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx;
    return 0;
}

size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len, size_t r)
{
    /* WOLFSHIM_GAP[UNSUPPORTED]: SHA3_absorb is the raw Keccak absorb permutation used
     * by OpenSSL's SHA-3 assembly path.  The wolfshim SHA-3 path goes through
     * wolfSSL_EVP_sha3_* and never calls this function.  Push an error rather
     * than aborting the process. */
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)A; (void)inp; (void)r;
    /* Return len to signal that 0 bytes were consumed (all len bytes remain
     * unprocessed).  OpenSSL's SHA3_absorb contract: return value = number of
     * bytes remaining after processing complete r-byte blocks.  Returning len
     * means "no complete blocks processed; entire input still pending."
     * This is correct for a stub that cannot do any real work. */
    return len;
}

void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r)
{
    /* WOLFSHIM_GAP[UNSUPPORTED]: SHA3_squeeze is the raw Keccak squeeze permutation.
     * Zero the output buffer so callers do not get uninitialized data, then
     * push an error.  The wolfshim SHA-3 path never reaches this function. */
    if (out && len > 0)
        memset(out, 0, len);
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)A; (void)r;
}

/* =========================================================================
 * vpaes_* stubs — vector-permutation AES, dispatch to standard AES
 *
 * OpenSSL defines "vpaes" (vector-permutation AES) as an alternative software
 * implementation using SSSE3 shuffle instructions.  In this shim the vpaes
 * distinction is meaningless: wolfCrypt handles both software and hardware AES
 * internally and selects the best path at runtime.
 *
 * IMPORTANT: vpaes_set_encrypt_key / vpaes_set_decrypt_key MUST delegate to
 * the shim's AES_set_encrypt_key / AES_set_decrypt_key (defined in aliases.c),
 * NOT to wolfSSL_AES_set_encrypt_key.  The wolfSSL compat-layer call does NOT
 * go through aes_ctx_alloc() and therefore does NOT write the WOLFSHIM_AES_CTX_MAGIC
 * sentinel into the AES_KEY buffer.  Any subsequent call to aes_ctx_get() on such
 * a key returns NULL, causing vpaes_encrypt / AES_encrypt to silently no-op or
 * crash.  By forwarding to the shim's own AES_set_encrypt_key the key is
 * initialised with a heap-allocated Aes* and the correct sentinel, which every
 * downstream operation in this shim expects.
 *
 * vpaes_encrypt / vpaes_decrypt / vpaes_cbc_encrypt delegate to the same
 * shim entry-points for the same reason: they call aes_ctx_get() internally.
 * ========================================================================= */

/* vpaes_set_encrypt_key delegates to AES_set_encrypt_key — wolfCrypt handles
 * both software and hardware AES; the vpaes distinction is meaningless in this shim */
int vpaes_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key)
{
    WOLFSHIM_LOG("vpaes_set_encrypt_key");
    return AES_set_encrypt_key(userKey, bits, key);
}

/* vpaes_set_decrypt_key delegates to AES_set_decrypt_key — same rationale */
int vpaes_set_decrypt_key(const unsigned char *userKey, int bits, AES_KEY *key)
{
    WOLFSHIM_LOG("vpaes_set_decrypt_key");
    return AES_set_decrypt_key(userKey, bits, key);
}

void vpaes_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
    WOLFSHIM_LOG("vpaes_encrypt");
    AES_encrypt(in, out, key);
}

void vpaes_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
    WOLFSHIM_LOG("vpaes_decrypt");
    AES_decrypt(in, out, key);
}

void vpaes_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const AES_KEY *key,
                       unsigned char *ivec, int enc)
{
    WOLFSHIM_LOG("vpaes_cbc_encrypt");
    AES_cbc_encrypt(in, out, length, key, ivec, enc);
}

/* =========================================================================
 * Legacy cipher stubs — not available in wolfCrypt, return error
 *
 * BF/CAST5/RC2/SEED/Camellia/ARIA abort() stubs live in
 * legacy_stubs/legacy_cipher_stubs.c.  Only ciphers with no abort()
 * replacement (MDC2, RIPEMD-160, SM4, rc4_md5_enc) remain here.
 * ========================================================================= */

/* MDC2 */
/* WOLFSHIM_GAP[UNSUPPORTED]: MDC2 (Message Digest Cipher 2) is not available in
 * wolfCrypt.  Init/Update/Final return 0 (failure in OpenSSL convention),
 * so the EVP layer propagates the error upward.  ERR_put_error is called
 * for diagnostics.  Safe to stub: MDC2 is a legacy, patent-encumbered
 * digest not used in any modern TLS ciphersuites. */
int MDC2_Init(void *ctx)
{
    WOLFSHIM_LOG("MDC2_Init");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx;
    return 0;
}
int MDC2_Update(void *ctx, const unsigned char *data, size_t len)
{
    WOLFSHIM_LOG("MDC2_Update");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx; (void)data; (void)len;
    return 0;
}
int MDC2_Final(unsigned char *md, void *ctx)
{
    WOLFSHIM_LOG("MDC2_Final");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)md; (void)ctx;
    return 0;
}

/* rc4_md5_enc */
void rc4_md5_enc(void *key, const void *inp, void *out, void *ctx, size_t blocks)
{
    WOLFSHIM_LOG("rc4_md5_enc");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)key; (void)inp; (void)out; (void)ctx; (void)blocks;
}

/* RIPEMD160 */
/* WOLFSHIM_GAP[UNSUPPORTED]: RIPEMD-160 is not available in wolfCrypt (absent in
 * default FIPS/embedded builds).  Init/Update/Final return 0 (failure),
 * and ERR_put_error is called so callers can detect the error.
 * Safe to stub: RIPEMD-160 is not used in TLS 1.2+ and is disabled in
 * most modern security policies. */
int RIPEMD160_Init(void *ctx)
{
    WOLFSHIM_LOG("RIPEMD160_Init");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx;
    return 0;
}
int RIPEMD160_Update(void *ctx, const void *data, size_t len)
{
    WOLFSHIM_LOG("RIPEMD160_Update");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx; (void)data; (void)len;
    return 0;
}
int RIPEMD160_Final(unsigned char *md, void *ctx)
{
    WOLFSHIM_LOG("RIPEMD160_Final");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)md; (void)ctx;
    return 0;
}

/* SM4 */
void SM4_set_key(const unsigned char *key, void *ks)
{
    WOLFSHIM_LOG("SM4_set_key");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)key; (void)ks;
}
void SM4_encrypt(const unsigned char *in, unsigned char *out, const void *ks)
{
    WOLFSHIM_LOG("SM4_encrypt");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)in; (void)out; (void)ks;
}
void SM4_decrypt(const unsigned char *in, unsigned char *out, const void *ks)
{
    WOLFSHIM_LOG("SM4_decrypt");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)in; (void)out; (void)ks;
}

/* WHIRLPOOL */
/* WOLFSHIM_GAP[UNSUPPORTED]: WHIRLPOOL is not available in wolfCrypt.
 * WHIRLPOOL_Init/Update/Final return 0 (failure in OpenSSL convention),
 * which correctly signals to the EVP layer that the operation failed.
 * ERR_put_error is called so the caller can detect the error via ERR_get_error().
 * Safe to stub: WHIRLPOOL is a legacy, non-FIPS digest not used by TLS. */
int WHIRLPOOL_Init(void *ctx)
{
    WOLFSHIM_LOG("WHIRLPOOL_Init");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx;
    return 0;
}
int WHIRLPOOL_Update(void *ctx, const void *inp, size_t bytes)
{
    WOLFSHIM_LOG("WHIRLPOOL_Update");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ctx; (void)inp; (void)bytes;
    return 0;
}
int WHIRLPOOL_Final(unsigned char *md, void *ctx)
{
    WOLFSHIM_LOG("WHIRLPOOL_Final");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)md; (void)ctx;
    return 0;
}

/*
 * EVP_PKEY_METHOD stubs for algorithms excluded in WOLFCRYPT_EXCLUDE mode.
 *
 * These are needed because pmeth_lib.c references them in standard_methods[].
 * The standard_methods[] array must stay sorted by pkey_id for binary search.
 *
 * CRITICAL: the first field of EVP_PKEY_METHOD is `int pkey_id`.  A NULL/zero
 * stub would break the binary search for IDs 1034-1062 (X25519/HKDF/etc.).
 * Each stub must have the correct pkey_id so the sorted order is preserved.
 *
 * Layout: int pkey_id (4) + int flags (4) + 31 function pointers (248) = 256 B
 * NID values: NID_poly1305 = 1061, NID_siphash = 1062, NID_sm2 = 1172
 */
#define PKEY_METH_STUB(name, nid)  \
    struct { int pkey_id; int flags; void *fns[31]; } name = { .pkey_id = (nid) }

PKEY_METH_STUB(sm2_pkey_meth,      1172);

/*
 * EVP_PKEY_ASN1_METHOD stubs for algorithms excluded in WOLFCRYPT_EXCLUDE mode.
 *
 * ameth_lib.c uses OBJ_bsearch on standard_methods[] keyed by pkey_id.
 * A zeroed stub has pkey_id=0, breaking the sorted order for X25519/ED25519.
 *
 * Layout (x86-64): int pkey_id (4) + int pkey_base_id (4) +
 *   unsigned long pkey_flags (8) + char *pem_str (8) + char *info (8) +
 *   31 function pointers (248) = 280 bytes.
 *
 * NID values: NID_poly1305 = 1061, NID_siphash = 1062
 * pem_str = NULL (zero) → skipped by EVP_PKEY_asn1_find_str() NULL guard.
 */
#define ASN1_METH_STUB(name, nid)                                          \
    struct {                                                                \
        int pkey_id; int pkey_base_id; unsigned long pkey_flags;           \
        void *pem_str; void *info;                                         \
        void *fns[31];                                                     \
    } name = { .pkey_id = (nid), .pkey_base_id = (nid) }



/* =========================================================================
 * ERR_load_* stubs
 * ========================================================================= */

/* WOLFSHIM_GAP[UNSUPPORTED]: ERR_load_RAND_strings is an OpenSSL internal
 * function that registers RAND error strings into the error table.
 * wolfSSL manages its own error strings; calling this is a no-op.
 * Returning 1 (success) is safe: callers treat non-1 as a non-fatal
 * informational failure, and missing error strings do not affect security. */
int ERR_load_RAND_strings(void) { return 1; }


/* =========================================================================
 * EVP_sm3 stub
 * EVP_sm3 macro was undeffed above; return NULL as const WOLFSSL_EVP_MD*
 * ========================================================================= */

const WOLFSSL_EVP_MD *EVP_sm3(void)
{
    WOLFSHIM_LOG("EVP_sm3");
    return NULL;
}

/* =========================================================================
 * Internal RAND cleanup stubs
 * ========================================================================= */

void rand_cleanup_int(void)      { WOLFSHIM_LOG("rand_cleanup_int"); }
void rand_drbg_cleanup_int(void) { WOLFSHIM_LOG("rand_drbg_cleanup_int"); }
void drbg_delete_thread_state(void) { WOLFSHIM_LOG("drbg_delete_thread_state"); }


/* =========================================================================
 * App-level stubs — symbols needed by apps/openssl binary but not in wolfSSL
 * Undef wolfSSL macros that would conflict with our function definitions.
 * ========================================================================= */

/* Undef DH macros that expand to wolfSSL functions or BN expressions */
#ifdef DH_bits
# undef DH_bits
#endif
#ifdef DH_generate_parameters_ex
# undef DH_generate_parameters_ex
#endif
#ifdef DH_get_length
# undef DH_get_length
#endif
#ifdef DHparams_print
# undef DHparams_print
#endif

/* Undef EC macros that expand to no-ops or wolfSSL functions */
#ifdef EC_GROUP_set_point_conversion_form
# undef EC_GROUP_set_point_conversion_form
#endif
#ifdef EC_GROUP_get_point_conversion_form
# undef EC_GROUP_get_point_conversion_form
#endif
#ifdef EC_GROUP_set_seed
# undef EC_GROUP_set_seed
#endif
#ifdef EC_GROUP_check
# undef EC_GROUP_check
#endif
#ifdef EC_GROUP_get0_generator
# undef EC_GROUP_get0_generator
#endif
#ifdef EC_GROUP_get_cofactor
# undef EC_GROUP_get_cofactor
#endif
#ifdef EC_GROUP_get_curve
# undef EC_GROUP_get_curve
#endif
#ifdef ECPKParameters_print
# undef ECPKParameters_print
#endif
#ifdef EC_KEY_set_enc_flags
# undef EC_KEY_set_enc_flags
#endif
#ifdef EC_KEY_precompute_mult
# undef EC_KEY_precompute_mult
#endif
#ifdef EC_KEY_print
# undef EC_KEY_print
#endif

/* Undef DSA macros */
#ifdef DSA_print
# undef DSA_print
#endif
#ifdef DSA_sign
# undef DSA_sign
#endif
#ifdef DSA_verify
# undef DSA_verify
#endif
#ifdef DSAparams_dup
# undef DSAparams_dup
#endif
#ifdef DSAparams_print
# undef DSAparams_print
#endif

/* BF (Blowfish) block encrypt/decrypt (operate on 32-bit word pairs) */
void BF_encrypt(unsigned long *data, const void *key)
{
    WOLFSHIM_LOG("BF_encrypt");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)data; (void)key;
}
void BF_decrypt(unsigned long *data, const void *key)
{
    WOLFSHIM_LOG("BF_decrypt");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)data; (void)key;
}

/* BF_options: informational query, not a crypto operation — soft stub is fine */
const char *BF_options(void) { return "blowfish(disabled)"; }

/* DES options */
const char *DES_options(void) { return "des(wolfcrypt)"; }



/* RC4_options, RC4_set_key, and RC4 are in rc4/rc4_shim.c (wolfCrypt-backed) */

/* WHIRLPOOL single-call */
/* WOLFSHIM_GAP[UNSUPPORTED]: WHIRLPOOL one-shot is not available in wolfCrypt.
 * Returning a zeroed md buffer is unsafe (caller could trust it as a real
 * digest), but returning NULL would also be unsafe if the caller does not
 * check for NULL.  We signal failure via ERR_put_error and return NULL so
 * that any NULL-checking caller detects the error immediately.  The md
 * buffer is intentionally NOT zeroed so accidental use of the output is
 * detectable as garbage rather than a plausible-looking all-zero digest. */
unsigned char *WHIRLPOOL(const void *data, size_t n, unsigned char *md)
{
    WOLFSHIM_LOG("WHIRLPOOL");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)data; (void)n; (void)md;
    return NULL;
}

/* DES aliases now live in aliases.c; MODE files now live in OpenSSL's DES directory.
 * This section intentionally left empty. */

/* =========================================================================
 * EC_POINT plain-name wrappers needed by test/ecdsatest/ectest
 * ========================================================================= */

#include <wolfssl/openssl/ec.h>

/* =========================================================================
 * EC_GROUP and EC_POINT wrappers — wolfSSL-backed (undef + forward)
 * ========================================================================= */

#ifdef EC_GROUP_cmp
# undef EC_GROUP_cmp
#endif
#ifdef EC_GROUP_dup
# undef EC_GROUP_dup
#endif
#ifdef EC_GROUP_get_degree
# undef EC_GROUP_get_degree
#endif
#ifdef EC_GROUP_order_bits
# undef EC_GROUP_order_bits
#endif
#ifdef EC_POINT_new
# undef EC_POINT_new
#endif
#ifdef EC_POINT_add
# undef EC_POINT_add
#endif
#ifdef EC_POINT_invert
# undef EC_POINT_invert
#endif
#ifdef EC_POINT_cmp
# undef EC_POINT_cmp
#endif
#ifdef EC_POINT_copy
# undef EC_POINT_copy
#endif
#ifdef EC_POINT_is_at_infinity
# undef EC_POINT_is_at_infinity
#endif
#ifdef EC_POINT_point2oct
# undef EC_POINT_point2oct
#endif
#ifdef EC_POINT_oct2point
# undef EC_POINT_oct2point
#endif
#ifdef EC_POINT_is_on_curve
# undef EC_POINT_is_on_curve
#endif
#ifdef EC_POINT_point2hex
# undef EC_POINT_point2hex
#endif
#ifdef EC_POINT_hex2point
# undef EC_POINT_hex2point
#endif
#ifdef EC_POINT_set_affine_coordinates
# undef EC_POINT_set_affine_coordinates
#endif
#ifdef EC_POINT_set_affine_coordinates_GFp
# undef EC_POINT_set_affine_coordinates_GFp
#endif


/* =========================================================================
 * HMAC_CTX plain-name wrappers needed by test/hmactest
 * ========================================================================= */

#include <wolfssl/openssl/hmac.h>

/* DES_quad_cksum now provided by crypto/des/qud_cksm.o */
