/*
 * sha_shim.c — OpenSSL 1.1.1 SHA API shim (wolfCrypt back-end)
 *
 * Heap-pointer layout
 * -------------------
 * wolfSSL's SHA context structs are LARGER than OpenSSL's:
 *   WOLFSSL_SHA_CTX    (≥112 B) > SHA_CTX    (96 B)  — at least 16 B overflow
 *   WOLFSSL_SHA256_CTX (≥128 B) > SHA256_CTX (112 B) — at least 16 B overflow
 *   WOLFSSL_SHA512_CTX (≥288 B) > SHA512_CTX (216 B) — at least 72 B overflow
 *
 * Writing a wolfSSL context directly into the OpenSSL struct causes a stack
 * buffer overflow when the CTX is stack-allocated, corrupting adjacent
 * variables (manifests as the RC4 bulk-cipher test failure).
 *
 * Fix: store only a void * (8 bytes) in the first sizeof(void *) bytes of the
 * OpenSSL CTX.  The pointer references a heap-allocated wolfSSL CTX.
 *
 *   Init   — if pointer+sentinel are both valid: wolfSSL reinitialises the
 *             existing allocation in-place (no malloc — the hot-path case
 *             after a preceding Final).  Otherwise: malloc fresh allocation,
 *             set the sentinel, call wolfSSL_SHA*_Init.
 *   Update — dereference the stored pointer.
 *   Final  — deliver the digest, explicit_bzero the wolfSSL context (wipes
 *             intermediate hash state / key material), re-set the sentinel.
 *             Does NOT free — the allocation stays alive for the next Init
 *             to reuse without a malloc.
 *
 * Lifetime management
 * -------------------
 * The sentinel in the second pointer-slot marks the buffer as wolfshim-managed.
 * OPENSSL_cleanse(ctx, len) checks for the sentinel and, if found, frees the
 * heap allocation before zeroing the buffer — the same pattern used by
 * aes_ctx.h for AES_KEY.  Callers that wipe the SHA_CTX before abandonment
 * pay no leak.  Stack-allocated SHA_CTX objects that go out of scope without
 * OPENSSL_cleanse cause an architectural leak of one wolfSSL context per
 * SHA_CTX — Valgrind will report these as real leaks; fix the caller.
 *
 * One-shot functions (SHA1, SHA224, …) work directly with heap-allocated
 * wolfSSL contexts and never touch a caller-supplied SHA_CTX, so they do
 * not suffer from the size mismatch at all.
 *
 * Contract for callers: a SHA_CTX must have its first sizeof(void *) bytes
 * zeroed before the first SHA*_Init call.  This is satisfied by:
 *   • stack declarations that are value-initialised: SHA_CTX c = {0};
 *   • heap allocations via calloc / OPENSSL_zalloc
 *   • the common pattern:  SHA_CTX c; SHA1_Init(&c);  — on first call the
 *     pointer slot is NULL (no sentinel) and a fresh allocation is made.
 *     The Init→Update→Final→Init cycle reuses the allocation in-place.
 *     Garbage in the pointer slot without the sentinel is treated as "not
 *     initialised" and triggers a fresh malloc rather than a crash.
 *
 * wolfshim extensions (not in OpenSSL 1.1.1, see sha_shim.h and RELEASE-NOTES.md):
 *   SHA_CTX_new / SHA_CTX_free
 *   SHA256_CTX_new / SHA256_CTX_free
 *   SHA512_CTX_new / SHA512_CTX_free
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* explicit_bzero */
#include <pthread.h>

#ifdef WOLFSHIM_DEBUG
# include <stdio.h>
# include <stdatomic.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_SHA
# error "wolfSSL must be built with SHA-1 support to use sha_shim.c"
#endif
#ifdef NO_SHA256
# error "wolfSSL must be built with SHA-256 support to use sha_shim.c"
#endif
#ifndef WOLFSSL_SHA384
# error "wolfSSL must be built with SHA-384 support (--enable-sha384) to use sha_shim.c"
#endif
#ifndef WOLFSSL_SHA512
# error "wolfSSL must be built with SHA-512 support (--enable-sha512) to use sha_shim.c"
#endif

/* wolfcrypt digest-size constants */
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

/*
 * wolfSSL openssl-compat sha.h gives us:
 *   typedef WOLFSSL_SHA_CTX    SHA_CTX;
 *   typedef WOLFSSL_SHA256_CTX SHA256_CTX;
 *   typedef WOLFSSL_SHA384_CTX SHA384_CTX;  (alias of SHA512_CTX in OpenSSL)
 *   typedef WOLFSSL_SHA512_CTX SHA512_CTX;
 * and macros like #define SHA1_Init wolfSSL_SHA1_Init.
 * We need the wolfSSL_* function prototypes and WOLFSSL_*_CTX types,
 * so we include this header.  The function-name macros are undef'd below.
 */
#include <wolfssl/openssl/sha.h>

/* SHA heap-pointer sentinel helpers (self-contained; includes wolfssl/openssl/sha.h internally). */
#include "sha_ctx.h"
/* wolfshim extension declarations (SHA_CTX_new/free etc.) */
#include "sha_shim.h"

#undef SHA1_Init
#undef SHA1_Update
#undef SHA1_Final
#undef SHA1_Transform
#undef SHA224_Init
#undef SHA224_Update
#undef SHA224_Final
#undef SHA256_Init
#undef SHA256_Update
#undef SHA256_Final
#undef SHA256_Transform
#undef SHA384_Init
#undef SHA384_Update
#undef SHA384_Final
#undef SHA512_Init
#undef SHA512_Update
#undef SHA512_Final
#undef SHA512_Transform

#ifdef SHA
# undef SHA
#endif
#ifdef SHA224
# undef SHA224
#endif
#ifdef SHA256
# undef SHA256
#endif
#ifdef SHA384
# undef SHA384
#endif
#ifdef SHA512
# undef SHA512
#endif

/* =========================================================================
 * Internal helpers — access the heap pointer stored in the first 8 bytes
 * of the caller's (OpenSSL-sized) context structure.
 *
 * The wolfSSL context pointer is embedded in bytes [0, sizeof(void*)) of the
 * caller's OpenSSL struct.  These helpers retrieve that pointer.  Each
 * function is named for what it MEANS (the embedded wolfSSL context handle),
 * not for the byte-level mechanics of reading it.
 * ========================================================================= */

static inline WOLFSSL_SHA_CTX **sha1_wolf_ctx(SHA_CTX *c)
{
    return (WOLFSSL_SHA_CTX **)(void *)c;
}

static inline WOLFSSL_SHA256_CTX **sha256_wolf_ctx(SHA256_CTX *c)
{
    return (WOLFSSL_SHA256_CTX **)(void *)c;
}

static inline WOLFSSL_SHA224_CTX **sha224_wolf_ctx(SHA256_CTX *c)
{
    return (WOLFSSL_SHA224_CTX **)(void *)c;
}

static inline WOLFSSL_SHA512_CTX **sha512_wolf_ctx(SHA512_CTX *c)
{
    return (WOLFSSL_SHA512_CTX **)(void *)c;
}

static inline WOLFSSL_SHA384_CTX **sha384_wolf_ctx(SHA512_CTX *c)
{
    return (WOLFSSL_SHA384_CTX **)(void *)c;
}

/* No module-level mutex is needed for the one-shot SHA*() static_buf path.
 * Each per-function static output buffer is declared __thread (C11/GCC/Clang
 * thread-local storage), so every thread has its own independent copy.
 * Two concurrent calls from *different* threads therefore write to distinct
 * memory and can never corrupt each other.  The residual contract (unchanged
 * from OpenSSL 1.1.x) is: a caller that retains the returned pointer must
 * not call the same SHA*() function again from the *same* thread before it
 * is done reading — a same-thread re-entry would overwrite its own buffer.
 * Callers that need a stable output across multiple threads must supply a
 * non-NULL md argument. */

#ifdef WOLFSHIM_DEBUG
/* Allocation counter — diagnostic only.
 * Counts the total number of wolfSSL SHA context heap allocations made by
 * SHA*_Init across all SHA variants since process start.  Increments on
 * every fresh malloc; does not decrement (frees happen via OPENSSL_cleanse
 * which runs in a different TU).  A rapidly growing value indicates the
 * sentinel/reuse path is not firing — i.e. Init→Final→Init is paying a
 * malloc each cycle instead of reusing the existing allocation.
 * Declared _Atomic so concurrent Init calls do not produce torn reads.
 * Call wolfshim_sha_ctx_alloc_count() to read it. */
static _Atomic long s_sha_alloc_count = 0;
long wolfshim_sha_ctx_alloc_count(void) { return s_sha_alloc_count; }
#endif

/* =========================================================================
 * SHA-1
 * ========================================================================= */

int SHA1_Init(SHA_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA_CTX **pp = sha1_wolf_ctx(c); /* pp = pointer to the heap-allocated wolfSSL context slot */
    /* Reuse if the sentinel confirms this is a live wolfshim allocation.
     * The sentinel check prevents a non-NULL garbage value in an
     * uninitialised SHA_CTX from being misread as a valid pointer. */
    if (*pp && sha1_ctx_has_sentinel(c)) {
        if (wolfSSL_SHA1_Init(*pp))
            return 1;
        /* reinit failed — fall through to fresh malloc */
    }
    *pp = (WOLFSSL_SHA_CTX *)malloc(sizeof(WOLFSSL_SHA_CTX));
    if (!*pp) return 0;
#ifdef WOLFSHIM_DEBUG
    atomic_fetch_add(&s_sha_alloc_count, 1);
#endif
    sha1_ctx_set_sentinel(c);
    return wolfSSL_SHA1_Init(*pp) ? 1 : 0;
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called len=%zu\n", __func__, len);
#endif
    WOLFSSL_SHA_CTX **pp = sha1_wolf_ctx(c);
    if (!c || !*pp) return 0;
    return wolfSSL_SHA1_Update(*pp, data, (unsigned long)len);
}

int SHA1_Final(unsigned char *md, SHA_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA_CTX **pp = sha1_wolf_ctx(c);
    if (!pp || !*pp) return 0;
    int rc = wolfSSL_SHA1_Final(md, *pp);
    /* Zero the wolfSSL context to wipe intermediate hash state (which may
     * be derived from key material in HMAC inner/outer hashing).
     * We keep the allocation alive — the sentinel stays set — so the next
     * SHA1_Init can reinitialise the existing buffer in-place without a
     * malloc.  OPENSSL_cleanse(c, sizeof(*c)) will free it on abandonment.
     * Stack-allocated SHA_CTX objects abandoned without OPENSSL_cleanse
     * cause a leak; Valgrind will report it. Fix the caller. */
    explicit_bzero(*pp, sizeof(WOLFSSL_SHA_CTX));
    sha1_ctx_set_sentinel(c);  /* sentinel survives Final; Init will reuse */
    return rc;
}

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called n=%zu\n", __func__, n);
#endif
    /* Thread-safety note: static_buf is __thread (thread-local), so each
     * thread has its own copy — concurrent calls from different threads never
     * race.  The returned pointer is only valid until the same thread calls
     * SHA1() again; callers that need a stable buffer must pass non-NULL md. */
    static __thread unsigned char static_buf[WC_SHA_DIGEST_SIZE];
    unsigned char *out = md ? md : static_buf;
    WOLFSSL_SHA_CTX *wctx;
    int ok = 0;
    wctx = (WOLFSSL_SHA_CTX *)malloc(sizeof(WOLFSSL_SHA_CTX));
    if (wctx) {
        ok = wolfSSL_SHA1_Init(wctx)
          && wolfSSL_SHA1_Update(wctx, d, (unsigned long)n)
          && wolfSSL_SHA1_Final(out, wctx);
        explicit_bzero(wctx, sizeof(*wctx)); /* wipe hash state before free */
        free(wctx);
    }
    return ok ? out : NULL;
}

/* =========================================================================
 * SHA-224
 * OpenSSL uses SHA256_CTX for SHA224.  wolfSSL uses a separate
 * WOLFSSL_SHA224_CTX, but internally both wrap the same wc_Sha256 state
 * so the sizeof values are identical and the cast is safe.
 * ========================================================================= */

int SHA224_Init(SHA256_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA224_CTX **pp = sha224_wolf_ctx(c);
    if (*pp && sha256_ctx_has_sentinel(c)) {
        if (wolfSSL_SHA224_Init(*pp))
            return 1;
        /* reinit failed — fall through to fresh malloc */
    }
    *pp = (WOLFSSL_SHA224_CTX *)malloc(sizeof(WOLFSSL_SHA224_CTX));
    if (!*pp) return 0;
#ifdef WOLFSHIM_DEBUG
    atomic_fetch_add(&s_sha_alloc_count, 1);
#endif
    sha256_ctx_set_sentinel(c);
    return wolfSSL_SHA224_Init(*pp) ? 1 : 0;
}

int SHA224_Update(SHA256_CTX *c, const void *data, size_t len)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called len=%zu\n", __func__, len);
#endif
    WOLFSSL_SHA224_CTX **pp = sha224_wolf_ctx(c);
    if (!c || !*pp) return 0;
    return wolfSSL_SHA224_Update(*pp, data, (unsigned long)len);
}

int SHA224_Final(unsigned char *md, SHA256_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA224_CTX **pp = sha224_wolf_ctx(c);
    if (!pp || !*pp) return 0;
    int rc = wolfSSL_SHA224_Final(md, *pp);
    explicit_bzero(*pp, sizeof(WOLFSSL_SHA224_CTX));
    sha256_ctx_set_sentinel(c);
    return rc;
}

unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called n=%zu\n", __func__, n);
#endif
    /* Thread-safety note: static_buf is __thread (thread-local), so each
     * thread has its own copy — concurrent calls from different threads never
     * race.  The returned pointer is only valid until the same thread calls
     * SHA224() again; callers that need a stable buffer must pass non-NULL md. */
    static __thread unsigned char static_buf[WC_SHA224_DIGEST_SIZE];
    unsigned char *out = md ? md : static_buf;
    WOLFSSL_SHA224_CTX *wctx;
    int ok = 0;
    wctx = (WOLFSSL_SHA224_CTX *)malloc(sizeof(WOLFSSL_SHA224_CTX));
    if (wctx) {
        ok = wolfSSL_SHA224_Init(wctx)
          && wolfSSL_SHA224_Update(wctx, d, (unsigned long)n)
          && wolfSSL_SHA224_Final(out, wctx);
        explicit_bzero(wctx, sizeof(*wctx)); /* wipe hash state before free */
        free(wctx);
    }
    return ok ? out : NULL;
}

/* =========================================================================
 * SHA-256
 * ========================================================================= */

int SHA256_Init(SHA256_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA256_CTX **pp = sha256_wolf_ctx(c);
    if (*pp && sha256_ctx_has_sentinel(c)) {
        if (wolfSSL_SHA256_Init(*pp))
            return 1;
        /* reinit failed — fall through to fresh malloc */
    }
    *pp = (WOLFSSL_SHA256_CTX *)malloc(sizeof(WOLFSSL_SHA256_CTX));
    if (!*pp) return 0;
#ifdef WOLFSHIM_DEBUG
    atomic_fetch_add(&s_sha_alloc_count, 1);
#endif
    sha256_ctx_set_sentinel(c);
    return wolfSSL_SHA256_Init(*pp) ? 1 : 0;
}

int SHA256_Update(SHA256_CTX *c, const void *data, size_t len)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called len=%zu\n", __func__, len);
#endif
    WOLFSSL_SHA256_CTX **pp = sha256_wolf_ctx(c);
    if (!c || !*pp) return 0;
    return wolfSSL_SHA256_Update(*pp, data, (unsigned long)len);
}

int SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA256_CTX **pp = sha256_wolf_ctx(c);
    if (!pp || !*pp) return 0;
    int rc = wolfSSL_SHA256_Final(md, *pp);
    explicit_bzero(*pp, sizeof(WOLFSSL_SHA256_CTX));
    sha256_ctx_set_sentinel(c);
    return rc;
}

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called n=%zu\n", __func__, n);
#endif
    /* Thread-safety note: static_buf is __thread (thread-local), so each
     * thread has its own copy — concurrent calls from different threads never
     * race.  The returned pointer is only valid until the same thread calls
     * SHA256() again; callers that need a stable buffer must pass non-NULL md. */
    static __thread unsigned char static_buf[WC_SHA256_DIGEST_SIZE];
    unsigned char *out = md ? md : static_buf;
    WOLFSSL_SHA256_CTX *wctx;
    int ok = 0;
    wctx = (WOLFSSL_SHA256_CTX *)malloc(sizeof(WOLFSSL_SHA256_CTX));
    if (wctx) {
        ok = wolfSSL_SHA256_Init(wctx)
          && wolfSSL_SHA256_Update(wctx, d, (unsigned long)n)
          && wolfSSL_SHA256_Final(out, wctx);
        explicit_bzero(wctx, sizeof(*wctx)); /* wipe hash state before free */
        free(wctx);
    }
    return ok ? out : NULL;
}

/* =========================================================================
 * SHA-384
 * OpenSSL uses SHA512_CTX for SHA384.  wolfSSL uses WOLFSSL_SHA384_CTX,
 * which internally wraps the same wc_Sha512 state — sizeof values match.
 * ========================================================================= */

int SHA384_Init(SHA512_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA384_CTX **pp = sha384_wolf_ctx(c);
    if (*pp && sha512_ctx_has_sentinel(c)) {
        if (wolfSSL_SHA384_Init(*pp))
            return 1;
        /* reinit failed — fall through to fresh malloc */
    }
    *pp = (WOLFSSL_SHA384_CTX *)malloc(sizeof(WOLFSSL_SHA384_CTX));
    if (!*pp) return 0;
#ifdef WOLFSHIM_DEBUG
    atomic_fetch_add(&s_sha_alloc_count, 1);
#endif
    sha512_ctx_set_sentinel(c);
    return wolfSSL_SHA384_Init(*pp) ? 1 : 0;
}

int SHA384_Update(SHA512_CTX *c, const void *data, size_t len)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called len=%zu\n", __func__, len);
#endif
    WOLFSSL_SHA384_CTX **pp = sha384_wolf_ctx(c);
    if (!c || !*pp) return 0;
    return wolfSSL_SHA384_Update(*pp, data, (unsigned long)len);
}

int SHA384_Final(unsigned char *md, SHA512_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA384_CTX **pp = sha384_wolf_ctx(c);
    if (!pp || !*pp) return 0;
    int rc = wolfSSL_SHA384_Final(md, *pp);
    explicit_bzero(*pp, sizeof(WOLFSSL_SHA384_CTX));
    sha512_ctx_set_sentinel(c);
    return rc;
}

unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called n=%zu\n", __func__, n);
#endif
    /* Thread-safety note: static_buf is __thread (thread-local), so each
     * thread has its own copy — concurrent calls from different threads never
     * race.  The returned pointer is only valid until the same thread calls
     * SHA384() again; callers that need a stable buffer must pass non-NULL md. */
    static __thread unsigned char static_buf[WC_SHA384_DIGEST_SIZE];
    unsigned char *out = md ? md : static_buf;
    WOLFSSL_SHA384_CTX *wctx;
    int ok = 0;
    wctx = (WOLFSSL_SHA384_CTX *)malloc(sizeof(WOLFSSL_SHA384_CTX));
    if (wctx) {
        ok = wolfSSL_SHA384_Init(wctx)
          && wolfSSL_SHA384_Update(wctx, d, (unsigned long)n)
          && wolfSSL_SHA384_Final(out, wctx);
        explicit_bzero(wctx, sizeof(*wctx)); /* wipe hash state before free */
        free(wctx);
    }
    return ok ? out : NULL;
}

/* =========================================================================
 * SHA-512
 * ========================================================================= */

int SHA512_Init(SHA512_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA512_CTX **pp = sha512_wolf_ctx(c);
    if (*pp && sha512_ctx_has_sentinel(c)) {
        if (wolfSSL_SHA512_Init(*pp))
            return 1;
        /* reinit failed — fall through to fresh malloc */
    }
    *pp = (WOLFSSL_SHA512_CTX *)malloc(sizeof(WOLFSSL_SHA512_CTX));
    if (!*pp) return 0;
#ifdef WOLFSHIM_DEBUG
    atomic_fetch_add(&s_sha_alloc_count, 1);
#endif
    sha512_ctx_set_sentinel(c);
    return wolfSSL_SHA512_Init(*pp) ? 1 : 0;
}

int SHA512_Update(SHA512_CTX *c, const void *data, size_t len)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called len=%zu\n", __func__, len);
#endif
    WOLFSSL_SHA512_CTX **pp = sha512_wolf_ctx(c);
    if (!c || !*pp) return 0;
    return wolfSSL_SHA512_Update(*pp, data, (unsigned long)len);
}

int SHA512_Final(unsigned char *md, SHA512_CTX *c)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called\n", __func__);
#endif
    WOLFSSL_SHA512_CTX **pp = sha512_wolf_ctx(c);
    if (!pp || !*pp) return 0;
    int rc = wolfSSL_SHA512_Final(md, *pp);
    explicit_bzero(*pp, sizeof(WOLFSSL_SHA512_CTX));
    sha512_ctx_set_sentinel(c);
    return rc;
}

unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] sha: %s called n=%zu\n", __func__, n);
#endif
    /* Thread-safety note: static_buf is __thread (thread-local), so each
     * thread has its own copy — concurrent calls from different threads never
     * race.  The returned pointer is only valid until the same thread calls
     * SHA512() again; callers that need a stable buffer must pass non-NULL md. */
    static __thread unsigned char static_buf[WC_SHA512_DIGEST_SIZE];
    unsigned char *out = md ? md : static_buf;
    WOLFSSL_SHA512_CTX *wctx;
    int ok = 0;
    wctx = (WOLFSSL_SHA512_CTX *)malloc(sizeof(WOLFSSL_SHA512_CTX));
    if (wctx) {
        ok = wolfSSL_SHA512_Init(wctx)
          && wolfSSL_SHA512_Update(wctx, d, (unsigned long)n)
          && wolfSSL_SHA512_Final(out, wctx);
        explicit_bzero(wctx, sizeof(*wctx)); /* wipe hash state before free */
        free(wctx);
    }
    return ok ? out : NULL;
}

/* =========================================================================
 * wolfshim extensions: SHA_CTX_new / SHA_CTX_free (and SHA256 / SHA512)
 *
 * These functions are NOT part of the OpenSSL 1.1.1 public API.
 * See sha_shim.h and shim/RELEASE-NOTES.md §"wolfshim extensions" for the
 * full rationale.
 *
 * _new:  allocate and zero a heap outer struct (sizeof SHA_CTX /
 *        SHA256_CTX / SHA512_CTX).  The inner wolfSSL context is allocated
 *        lazily on the first SHA*_Init call — same path as stack-allocated
 *        contexts.  Returns NULL on allocation failure.
 *
 * _free: if the inner wolfSSL context pointer is live (sentinel valid),
 *        zero and free the inner context first, then free the outer struct.
 *        Safe to call with NULL.  Must NOT be called on a stack-allocated
 *        SHA_CTX — use OPENSSL_cleanse(&ctx, sizeof(ctx)) for those.
 * ========================================================================= */

/* -------------------------------------------------------------------------
 * SHA-1  (OpenSSL type: SHA_CTX)
 * ------------------------------------------------------------------------- */
SHA_CTX *SHA_CTX_new(void)
{
    return (SHA_CTX *)calloc(1, sizeof(SHA_CTX));
}

void SHA_CTX_free(SHA_CTX *ctx)
{
    if (!ctx)
        return;
    sha_ctx_free_sentinel(ctx, WOLFSHIM_SHA1_CTX_MAGIC, sizeof(WOLFSSL_SHA_CTX));
    free(ctx);
}

/* -------------------------------------------------------------------------
 * SHA-224 / SHA-256  (OpenSSL type: SHA256_CTX)
 *
 * SHA-224 and SHA-256 share the same struct type in both OpenSSL and wolfSSL.
 * One _new/_free pair serves both variants.
 * ------------------------------------------------------------------------- */
SHA256_CTX *SHA256_CTX_new(void)
{
    return (SHA256_CTX *)calloc(1, sizeof(SHA256_CTX));
}

void SHA256_CTX_free(SHA256_CTX *ctx)
{
    if (!ctx)
        return;
    sha_ctx_free_sentinel(ctx, WOLFSHIM_SHA256_CTX_MAGIC, sizeof(WOLFSSL_SHA256_CTX));
    free(ctx);
}

/* -------------------------------------------------------------------------
 * SHA-384 / SHA-512  (OpenSSL type: SHA512_CTX)
 *
 * SHA-384 and SHA-512 share the same struct type in both OpenSSL and wolfSSL.
 * One _new/_free pair serves both variants.
 * ------------------------------------------------------------------------- */
SHA512_CTX *SHA512_CTX_new(void)
{
    return (SHA512_CTX *)calloc(1, sizeof(SHA512_CTX));
}

void SHA512_CTX_free(SHA512_CTX *ctx)
{
    if (!ctx)
        return;
    sha_ctx_free_sentinel(ctx, WOLFSHIM_SHA512_CTX_MAGIC, sizeof(WOLFSSL_SHA512_CTX));
    free(ctx);
}
