/*
 * sha_shim.h — wolfshim SHA API declarations including wolfshim extensions
 *
 * The standard SHA Init/Update/Final/one-shot symbols are declared through
 * <openssl/sha.h>.  This header adds only
 * the wolfshim extension functions that are NOT part of the OpenSSL 1.1.1 API.
 *
 * wolfshim extensions: SHA_CTX_new / SHA_CTX_free
 *                      SHA256_CTX_new / SHA256_CTX_free
 *                      SHA512_CTX_new / SHA512_CTX_free
 *
 * Background
 * ----------
 * OpenSSL 1.1.1's SHA_CTX / SHA256_CTX / SHA512_CTX are plain fixed-size
 * structs (96 / 112 / 216 bytes respectively).  OpenSSL's native implementation
 * stores all hash state inline, so the struct can be stack-allocated and
 * simply goes out of scope — there is nothing to free.
 *
 * wolfSSL's SHA context structs are larger (≥112 / ≥128 / ≥288 bytes).
 * The shim cannot store them inline without overflowing the public struct and
 * corrupting adjacent stack variables.  Instead the shim heap-allocates the
 * wolfSSL context and stores a pointer + magic sentinel in the first two
 * pointer-slots of the caller's buffer.
 *
 * Consequence: a stack-allocated SHA_CTX that goes out of scope without a
 * preceding OPENSSL_cleanse() call leaks the inner wolfSSL context — 112–288
 * bytes per context depending on the variant.  At 1000 TLS connections/second
 * this is approximately 1–3 MB/s of hash-state-containing heap.
 *
 * These extensions provide a _new/_free pair so callers can adopt explicit
 * lifetime management without porting to OpenSSL 3:
 *
 *   // Before: stack-allocated, leaks inner wolfSSL context
 *   SHA_CTX ctx;
 *   SHA1_Init(&ctx);
 *   SHA1_Update(&ctx, data, len);
 *   SHA1_Final(digest, &ctx);
 *   OPENSSL_cleanse(&ctx, sizeof(ctx));   // required with wolfshim
 *
 *   // After: heap-allocated, no leak, familiar _new/_free pattern
 *   SHA_CTX *ctx = SHA_CTX_new();
 *   SHA1_Init(ctx);
 *   SHA1_Update(ctx, data, len);
 *   SHA1_Final(digest, ctx);
 *   SHA_CTX_free(ctx);                   // frees inner wolfSSL context + outer
 *
 * Compile-time guard for code that must compile against both stock
 * OpenSSL 1.1.1 (which does not define these) and this shim:
 *   #ifdef WOLFSHIM_HAS_SHA_CTX_FREE
 *     SHA_CTX_free(ctx);
 *   #else
 *     OPENSSL_cleanse(ctx, sizeof(*ctx));
 *   #endif
 *
 */

#ifndef WOLFSHIM_SHA_SHIM_H
#define WOLFSHIM_SHA_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SHA_CTX / SHA256_CTX / SHA512_CTX type definitions.
 *
 * sha_shim.h is a public consumer header — it must not drag in wolfSSL
 * internals.  Include only the OpenSSL-compat SHA header, which is the
 * same header that stock OpenSSL 1.1.1 callers already include.
 *
 * Guard against double-inclusion: wolfSSL's openssl/sha.h sets
 * WOLFSSL_SHA_H_ (openssl/sha.h sets HEADER_SHA_H in stock OpenSSL).
 * Either guard means the types are already defined.
 */
#if !defined(WOLFSSL_SHA_H_) && !defined(HEADER_SHA_H)
# include <openssl/sha.h>
#endif

/*
 * Feature guard: callers that need to conditionally enable these extensions
 * when building against wolfshim vs. stock OpenSSL 1.1.1 can test this macro.
 */
#define WOLFSHIM_HAS_SHA_CTX_FREE 1

/* -----------------------------------------------------------------
 * wolfshim diagnostic: SHA context allocation counter
 *
 * Available only when built with -DWOLFSHIM_DEBUG.
 *
 * Returns the total number of wolfSSL SHA context heap allocations
 * made by SHA1_Init / SHA224_Init / SHA256_Init / SHA384_Init /
 * SHA512_Init since process start.  The counter increments on every
 * fresh malloc (the reuse path after SHA*_Final does not increment)
 * and never decrements.
 *
 * Interpretation mirrors wolfshim_aes_ctx_alloc_count():
 *   At startup:                    count == 0
 *   After N distinct Init calls:   count == N (expected)
 *   Still rising at steady state:  SHA_CTX objects are being
 *     abandoned without SHA*_CTX_free or OPENSSL_cleanse; wolfSSL
 *     contexts are accumulating on the heap.
 *
 * In non-debug builds returns 0.
 * ----------------------------------------------------------------- */
#ifdef WOLFSHIM_DEBUG
long wolfshim_sha_ctx_alloc_count(void);
#else
static inline long wolfshim_sha_ctx_alloc_count(void) { return 0; }
#endif

/* -----------------------------------------------------------------
 * SHA-1  (OpenSSL type: SHA_CTX)
 * ----------------------------------------------------------------- */

/*
 * SHA_CTX_new — allocate and zero a heap SHA_CTX.
 *
 * The inner wolfSSL SHA-1 context is allocated lazily on the first
 * SHA1_Init() call.  Returns NULL on allocation failure.
 */
SHA_CTX *SHA_CTX_new(void);

/*
 * SHA_CTX_free — free the inner wolfSSL SHA-1 context (zeroing it first)
 * and then free the outer SHA_CTX struct.
 *
 * Safe to call with NULL (no-op).  Must not be called on a stack-allocated
 * SHA_CTX — for those, call OPENSSL_cleanse(&ctx, sizeof(ctx)) instead.
 */
void SHA_CTX_free(SHA_CTX *ctx);

/* -----------------------------------------------------------------
 * SHA-224 / SHA-256  (OpenSSL type: SHA256_CTX)
 *
 * SHA-224 and SHA-256 share the same OpenSSL struct (SHA256_CTX) and the
 * same wolfSSL context type.  One _new/_free pair covers both variants.
 * ----------------------------------------------------------------- */

SHA256_CTX *SHA256_CTX_new(void);
void        SHA256_CTX_free(SHA256_CTX *ctx);

/* -----------------------------------------------------------------
 * SHA-384 / SHA-512  (OpenSSL type: SHA512_CTX)
 *
 * SHA-384 and SHA-512 share the same OpenSSL struct (SHA512_CTX) and the
 * same wolfSSL context type.  One _new/_free pair covers both variants.
 * ----------------------------------------------------------------- */

SHA512_CTX *SHA512_CTX_new(void);
void        SHA512_CTX_free(SHA512_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSHIM_SHA_SHIM_H */
