/*
 * sha_ctx.h — SHA heap-pointer sentinel helpers (wolfCrypt back-end)
 *
 * SHA_CTX MEMORY MODEL
 * --------------------
 * wolfSSL's SHA context structs are larger than OpenSSL's equivalents, so the
 * shim heap-allocates a wolfSSL context for each OpenSSL SHA_CTX and stores
 * the pointer in the first pointer-slot of the caller's buffer.
 *
 * Buffer layout (SHA_CTX / SHA256_CTX / SHA512_CTX — all three):
 *   [0 .. sizeof(void*)-1]              : WOLFSSL_SHA*_CTX* (heap-allocated)
 *   [sizeof(void*) .. 2*sizeof(void*)-1]: WOLFSHIM_SHA*_CTX_MAGIC sentinel
 *
 * The sentinel serves two purposes:
 *   1. Guards SHA*_Init's reuse path against non-NULL garbage in an
 *      uninitialised SHA_CTX (a non-zero first slot without the sentinel
 *      triggers a fresh malloc rather than a use-after-free crash).
 *   2. Lets OPENSSL_cleanse identify and free the heap context when a caller
 *      zeroes the SHA_CTX on abandonment — the same destructor-hook pattern
 *      used by aes_ctx.h for AES_KEY.
 *
 * LIFECYCLE
 * ---------
 *   SHA*_Init   — if pointer slot is NULL or sentinel is absent: malloc fresh
 *                 allocation and set sentinel.  If both are valid: wolfSSL
 *                 reinitialises the existing allocation in-place (no malloc).
 *
 *   SHA*_Final  — delivers the digest, explicit_bzero's the wolfSSL context,
 *                 and RE-SETS the sentinel.  Does NOT free.  The allocation
 *                 stays alive so the next SHA*_Init can reuse it without a
 *                 malloc — important on the TLS record-hash hot path.
 *
 *   OPENSSL_cleanse(ctx, len) — if the sentinel matches, zeros and frees the
 *                 heap wolfSSL context, then clears both pointer slots.
 *                 Callers that wipe the SHA_CTX before abandonment (the
 *                 common pattern in OpenSSL's own crypto/) pay no leak.
 *
 * ARCHITECTURAL LEAK
 * ------------------
 * A stack-allocated SHA_CTX that goes out of scope without a preceding
 * OPENSSL_cleanse call cannot be intercepted.  The wolfSSL heap allocation
 * leaks.  This is the same constraint as for AES_KEY — see wolfshim.supp for
 * the Valgrind suppression.
 *
 * PERFORMANCE NOTE
 * ----------------
 * SHA*_Init does a malloc on first use (reuses the allocation on subsequent
 * Init calls after Final, which is the common TLS record-hash pattern).
 * The per-connection malloc is an inherent cost of the OpenSSL 1.1.1 ABI.
 * If this overhead is unacceptable, see the PERFORMANCE REGRESSION WARNING in
 * aes_ctx.h — the same analysis applies here, and the same remediation
 * (OpenSSL 3 + wolfProvider) is the correct path forward.
 *
 * SENTINEL ASSIGNMENT
 * -------------------
 * Three sentinels — one per OpenSSL CTX type.  SHA224 shares SHA256_CTX;
 * SHA384 shares SHA512_CTX.  Both pairs use the same sentinel because free()
 * needs only the raw pointer, not the variant.  All values differ from
 * WOLFSHIM_AES_CTX_MAGIC (0x574F4C4657534844).
 *
 */

#ifndef WOLFSHIM_SHA_CTX_H
#define WOLFSHIM_SHA_CTX_H

#include <stdint.h>
#include <stdlib.h>   /* free() */
#include <string.h>   /* memcpy, memset */
#include <strings.h>  /* explicit_bzero */

/* wolfSSL SHA context types (WOLFSSL_SHA_CTX, WOLFSSL_SHA256_CTX, etc.)
 * options.h must precede settings.h so the build-time configuration is
 * loaded before any wolfCrypt struct definitions are parsed. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/sha.h>

/*
 * Magic sentinels.  On 64-bit: 8-byte values encoding the variant name.
 * On 32-bit: 4-byte values (upper 32 bits are dropped by the cast).
 *   WSH1CONT = "WSH1" + "CONT" — SHA-1 context
 *   WSH2CONT = "WSH2" + "CONT" — SHA-224 / SHA-256 context
 *   WSH5CONT = "WSH5" + "CONT" — SHA-384 / SHA-512 context
 */
#if UINTPTR_MAX > 0xFFFFFFFFU
# define WOLFSHIM_SHA1_CTX_MAGIC   ((void *)(uintptr_t)0x57534831434F4E54ULL)
# define WOLFSHIM_SHA256_CTX_MAGIC ((void *)(uintptr_t)0x57534832434F4E54ULL)
# define WOLFSHIM_SHA512_CTX_MAGIC ((void *)(uintptr_t)0x57534835434F4E54ULL)
#else
# define WOLFSHIM_SHA1_CTX_MAGIC   ((void *)(uintptr_t)0x57534831UL)
# define WOLFSHIM_SHA256_CTX_MAGIC ((void *)(uintptr_t)0x57534832UL)
# define WOLFSHIM_SHA512_CTX_MAGIC ((void *)(uintptr_t)0x57534835UL)
#endif

/* -----------------------------------------------------------------------
 * Shared: read / write the sentinel slot at offset sizeof(void*).
 * All access via memcpy to avoid alignment assumptions.
 *
 * Buffer slot layout (callers name the pointer-to-slot-0 "pp"):
 *   slot 0  [0 .. sizeof(void*)-1]     : WOLFSSL_SHA*_CTX* (heap-allocated)
 *   slot 1  [sizeof(void*) .. 2*-1]    : magic sentinel (variant ID)
 * ----------------------------------------------------------------------- */

static inline void *sha_ctx_read_sentinel(const void *ctx)
{
    void *magic = NULL;
    memcpy(&magic, (const char *)ctx + sizeof(void *), sizeof(void *));
    return magic;
}

static inline void sha_ctx_write_sentinel(void *ctx, void *magic)
{
    memcpy((char *)ctx + sizeof(void *), &magic, sizeof(void *));
}

/* -----------------------------------------------------------------------
 * SHA-1  (OpenSSL: SHA_CTX, wolfSSL: WOLFSSL_SHA_CTX)
 * ----------------------------------------------------------------------- */

static inline int sha1_ctx_has_sentinel(const void *ctx)
{
    return sha_ctx_read_sentinel(ctx) == WOLFSHIM_SHA1_CTX_MAGIC;
}

static inline void sha1_ctx_set_sentinel(void *ctx)
{
    void *magic = WOLFSHIM_SHA1_CTX_MAGIC;
    sha_ctx_write_sentinel(ctx, magic);
}

/* -----------------------------------------------------------------------
 * SHA-224 / SHA-256  (OpenSSL: SHA256_CTX)
 * wolfSSL: WOLFSSL_SHA224_CTX and WOLFSSL_SHA256_CTX have equal sizeof
 * (both wrap wc_Sha256).  Both use WOLFSHIM_SHA256_CTX_MAGIC.
 * ----------------------------------------------------------------------- */

static inline int sha256_ctx_has_sentinel(const void *ctx)
{
    return sha_ctx_read_sentinel(ctx) == WOLFSHIM_SHA256_CTX_MAGIC;
}

static inline void sha256_ctx_set_sentinel(void *ctx)
{
    void *magic = WOLFSHIM_SHA256_CTX_MAGIC;
    sha_ctx_write_sentinel(ctx, magic);
}

/* -----------------------------------------------------------------------
 * SHA-384 / SHA-512  (OpenSSL: SHA512_CTX)
 * wolfSSL: WOLFSSL_SHA384_CTX and WOLFSSL_SHA512_CTX have equal sizeof
 * (both wrap wc_Sha512).  Both use WOLFSHIM_SHA512_CTX_MAGIC.
 * ----------------------------------------------------------------------- */

static inline int sha512_ctx_has_sentinel(const void *ctx)
{
    return sha_ctx_read_sentinel(ctx) == WOLFSHIM_SHA512_CTX_MAGIC;
}

static inline void sha512_ctx_set_sentinel(void *ctx)
{
    void *magic = WOLFSHIM_SHA512_CTX_MAGIC;
    sha_ctx_write_sentinel(ctx, magic);
}

/* -----------------------------------------------------------------------
 * Generic free: zero and free the heap context stored in ctx.
 * Checks expected_magic before touching anything; clears both pointer
 * slots after freeing.  ctx_size is the sizeof the wolfSSL context type
 * (passed by the caller who knows the variant).
 *
 * Called by sha_ctx_free_any with the appropriate magic/size per variant.
 * Not called directly from sha_shim.c — Init/Final never free the heap
 * context (they keep it alive for reuse; see ARCHITECTURE.md §2).
 * ----------------------------------------------------------------------- */
static inline void sha_ctx_free_sentinel(void *ctx, void *expected_magic,
                                         size_t ctx_size)
{
    void *p = NULL;
    if (sha_ctx_read_sentinel(ctx) != expected_magic)
        return;
    memcpy(&p, ctx, sizeof(void *));
    if (p) { explicit_bzero(p, ctx_size); free(p); }
    memset(ctx, 0, 2 * sizeof(void *));
}

/* -----------------------------------------------------------------------
 * Generic: try all three SHA sentinels.
 * Called by OPENSSL_cleanse to handle any SHA_CTX variant in one call.
 * ----------------------------------------------------------------------- */

static inline void sha_ctx_free_any(void *ctx)
{
    void *magic = sha_ctx_read_sentinel(ctx);
    if      (magic == WOLFSHIM_SHA1_CTX_MAGIC)
        sha_ctx_free_sentinel(ctx, WOLFSHIM_SHA1_CTX_MAGIC,   sizeof(WOLFSSL_SHA_CTX));
    else if (magic == WOLFSHIM_SHA256_CTX_MAGIC)
        /* sizeof(WOLFSSL_SHA224_CTX) == sizeof(WOLFSSL_SHA256_CTX) per wolfSSL */
        sha_ctx_free_sentinel(ctx, WOLFSHIM_SHA256_CTX_MAGIC, sizeof(WOLFSSL_SHA256_CTX));
    else if (magic == WOLFSHIM_SHA512_CTX_MAGIC)
        /* sizeof(WOLFSSL_SHA384_CTX) == sizeof(WOLFSSL_SHA512_CTX) per wolfSSL */
        sha_ctx_free_sentinel(ctx, WOLFSHIM_SHA512_CTX_MAGIC, sizeof(WOLFSSL_SHA512_CTX));
}

#endif /* WOLFSHIM_SHA_CTX_H */
