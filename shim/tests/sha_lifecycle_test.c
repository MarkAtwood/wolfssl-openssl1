/*
 * sha_lifecycle_test.c — Unit tests for SHA*_CTX_new / SHA*_CTX_free
 * wolfshim lifecycle extensions and digest correctness.
 *
 * Include strategy
 * ----------------
 * Tests include the stock OpenSSL 1.1.1 SHA header (<openssl/sha.h>).
 * OpenSSL's header declares SHA1_Init / SHA1_Update / SHA1_Final etc. as
 * plain C prototypes with no macro aliasing, so calls resolve directly to
 * the wolfshim ELF symbols at link time.  This is the same header a
 * wolfshim consumer would include.
 *
 * sha_shim.h sees HEADER_SHA_H set (by <openssl/sha.h>) and skips its own
 * openssl/sha.h include; it adds only the wolfshim extension declarations
 * (SHA*_CTX_new / SHA*_CTX_free and the alloc counter).
 *
 * wolfshim heap-indirection recap
 * --------------------------------
 * SHA_CTX / SHA256_CTX / SHA512_CTX in OpenSSL 1.1.1 are plain fixed-size
 * structs (96 / 112 / 216 bytes).  wolfSSL's SHA context structs are larger,
 * so the shim heap-allocates the wolfSSL context and stores only a pointer +
 * magic sentinel in the caller's buffer.
 *
 *   SHA*_Init   — if pointer slot is NULL or sentinel absent: malloc inner,
 *                 set sentinel.  If both present: reinit in-place (no malloc).
 *   SHA*_Final  — deliver digest, bzero the inner context, re-set sentinel.
 *                 Does NOT free — keeps allocation alive for Init reuse.
 *   SHA*_CTX_free — free the inner wolfSSL context then the outer struct.
 *
 * Known-answer test vectors (empty-string digests, RFC / NIST)
 * ------------------------------------------------------------
 *   SHA-1("")   = da39a3ee5e6b4b0d3255bfef95601890afd80709
 *   SHA-224("") = d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
 *   SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 *   SHA-384("") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da
 *                 274edebfe76f65fbd51ad2f14898b95b
 *   SHA-512("") = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
 *                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>  /* SHA_CTX, SHA1_Init/Update/Final, digest lengths */
#include "sha_shim.h"     /* SHA*_CTX_new/free, wolfshim_sha_ctx_alloc_count */

/* -------------------------------------------------------------------------
 * Minimal test framework (matches rand_shim_test.c)
 * ------------------------------------------------------------------------- */

static int tests_run = 0, tests_passed = 0;

#define EXPECT(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
    } else { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
    } \
} while (0)

/* =========================================================================
 * SHA-1  (OpenSSL type: SHA_CTX)
 * ========================================================================= */

static void test_sha1_ctx_new_returns_nonnull(void)
{
    SHA_CTX *ctx = SHA_CTX_new();
    EXPECT(ctx != NULL, "SHA_CTX_new() should return non-NULL");
    SHA_CTX_free(ctx);
}

static void test_sha1_ctx_free_null(void)
{
    SHA_CTX_free(NULL);   /* must not crash */
    EXPECT(1, "SHA_CTX_free(NULL) should not crash");
}

static void test_sha1_ctx_free_without_init(void)
{
    /* SHA_CTX_new then free without any SHA1_Init.  The inner wolfSSL context
     * is never allocated (no sentinel written), so sha_ctx_free_sentinel is a
     * no-op for the inner allocation; only the outer calloc'd struct is freed. */
    SHA_CTX *ctx = SHA_CTX_new();
    EXPECT(ctx != NULL, "SHA_CTX_new() for free-without-init test");
    SHA_CTX_free(ctx);
    EXPECT(1, "SHA_CTX_free without prior SHA1_Init should not crash");
}

static void test_sha1_empty_digest(void)
{
    static const unsigned char expected[SHA_DIGEST_LENGTH] = {
        0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,
        0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,
        0xaf,0xd8,0x07,0x09
    };
    unsigned char md[SHA_DIGEST_LENGTH];

    SHA_CTX *ctx = SHA_CTX_new();
    EXPECT(ctx != NULL, "SHA_CTX_new() for SHA-1 digest test");
    EXPECT(SHA1_Init(ctx)   == 1, "SHA1_Init should return 1");
    EXPECT(SHA1_Final(md, ctx) == 1, "SHA1_Final should return 1");
    EXPECT(memcmp(md, expected, SHA_DIGEST_LENGTH) == 0,
           "SHA-1 of empty string matches known-answer vector");
    SHA_CTX_free(ctx);
}

static void test_sha1_ctx_reuse(void)
{
    /* Init → Final → Init → Final: the second Init should reuse the heap
     * allocation made by the first Init (no new malloc on the second call).
     * Both cycles must produce the same digest of the same input. */
    static const unsigned char data[] = "wolfshim reuse test";
    unsigned char md1[SHA_DIGEST_LENGTH], md2[SHA_DIGEST_LENGTH];

    SHA_CTX *ctx = SHA_CTX_new();
    EXPECT(ctx != NULL, "SHA_CTX_new() for reuse test");

    EXPECT(SHA1_Init(ctx) == 1, "SHA1_Init (first cycle)");
    EXPECT(SHA1_Update(ctx, data, sizeof(data) - 1) == 1,
           "SHA1_Update (first cycle)");
    EXPECT(SHA1_Final(md1, ctx) == 1, "SHA1_Final (first cycle)");

    /* Second cycle — should reuse the existing inner allocation */
    EXPECT(SHA1_Init(ctx) == 1, "SHA1_Init (second cycle, reuse path)");
    EXPECT(SHA1_Update(ctx, data, sizeof(data) - 1) == 1,
           "SHA1_Update (second cycle)");
    EXPECT(SHA1_Final(md2, ctx) == 1, "SHA1_Final (second cycle)");

    EXPECT(memcmp(md1, md2, SHA_DIGEST_LENGTH) == 0,
           "SHA-1 reuse path should produce identical digests");
    SHA_CTX_free(ctx);
}

/* =========================================================================
 * SHA-224 / SHA-256  (OpenSSL type: SHA256_CTX)
 *
 * SHA-224 and SHA-256 share SHA256_CTX; one _new/_free pair covers both.
 * ========================================================================= */

static void test_sha256_ctx_new_returns_nonnull(void)
{
    SHA256_CTX *ctx = SHA256_CTX_new();
    EXPECT(ctx != NULL, "SHA256_CTX_new() should return non-NULL");
    SHA256_CTX_free(ctx);
}

static void test_sha256_ctx_free_null(void)
{
    SHA256_CTX_free(NULL);
    EXPECT(1, "SHA256_CTX_free(NULL) should not crash");
}

static void test_sha256_ctx_free_without_init(void)
{
    SHA256_CTX *ctx = SHA256_CTX_new();
    EXPECT(ctx != NULL, "SHA256_CTX_new() for free-without-init test");
    SHA256_CTX_free(ctx);
    EXPECT(1, "SHA256_CTX_free without prior SHA256_Init should not crash");
}

static void test_sha224_empty_digest(void)
{
    /* SHA-224 uses SHA256_CTX — exercises the SHA256_CTX new/free pair with
     * the SHA-224 variant of the underlying wolfSSL context. */
    static const unsigned char expected[SHA224_DIGEST_LENGTH] = {
        0xd1,0x4a,0x02,0x8c,0x2a,0x3a,0x2b,0xc9,
        0x47,0x61,0x02,0xbb,0x28,0x82,0x34,0xc4,
        0x15,0xa2,0xb0,0x1f,0x82,0x8e,0xa6,0x2a,
        0xc5,0xb3,0xe4,0x2f
    };
    unsigned char md[SHA224_DIGEST_LENGTH];

    SHA256_CTX *ctx = SHA256_CTX_new();
    EXPECT(ctx != NULL, "SHA256_CTX_new() for SHA-224 digest test");
    EXPECT(SHA224_Init(ctx)      == 1, "SHA224_Init should return 1");
    EXPECT(SHA224_Final(md, ctx) == 1, "SHA224_Final should return 1");
    EXPECT(memcmp(md, expected, SHA224_DIGEST_LENGTH) == 0,
           "SHA-224 of empty string matches known-answer vector");
    SHA256_CTX_free(ctx);
}

static void test_sha256_empty_digest(void)
{
    static const unsigned char expected[SHA256_DIGEST_LENGTH] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    unsigned char md[SHA256_DIGEST_LENGTH];

    SHA256_CTX *ctx = SHA256_CTX_new();
    EXPECT(ctx != NULL, "SHA256_CTX_new() for SHA-256 digest test");
    EXPECT(SHA256_Init(ctx)      == 1, "SHA256_Init should return 1");
    EXPECT(SHA256_Final(md, ctx) == 1, "SHA256_Final should return 1");
    EXPECT(memcmp(md, expected, SHA256_DIGEST_LENGTH) == 0,
           "SHA-256 of empty string matches known-answer vector");
    SHA256_CTX_free(ctx);
}

static void test_sha256_ctx_reuse(void)
{
    static const unsigned char data[] = "wolfshim reuse test";
    unsigned char md1[SHA256_DIGEST_LENGTH], md2[SHA256_DIGEST_LENGTH];

    SHA256_CTX *ctx = SHA256_CTX_new();
    EXPECT(ctx != NULL, "SHA256_CTX_new() for reuse test");

    EXPECT(SHA256_Init(ctx) == 1, "SHA256_Init (first cycle)");
    EXPECT(SHA256_Update(ctx, data, sizeof(data) - 1) == 1,
           "SHA256_Update (first cycle)");
    EXPECT(SHA256_Final(md1, ctx) == 1, "SHA256_Final (first cycle)");

    EXPECT(SHA256_Init(ctx) == 1, "SHA256_Init (second cycle, reuse path)");
    EXPECT(SHA256_Update(ctx, data, sizeof(data) - 1) == 1,
           "SHA256_Update (second cycle)");
    EXPECT(SHA256_Final(md2, ctx) == 1, "SHA256_Final (second cycle)");

    EXPECT(memcmp(md1, md2, SHA256_DIGEST_LENGTH) == 0,
           "SHA-256 reuse path should produce identical digests");
    SHA256_CTX_free(ctx);
}

/* =========================================================================
 * SHA-384 / SHA-512  (OpenSSL type: SHA512_CTX)
 *
 * SHA-384 and SHA-512 share SHA512_CTX; one _new/_free pair covers both.
 * ========================================================================= */

static void test_sha512_ctx_new_returns_nonnull(void)
{
    SHA512_CTX *ctx = SHA512_CTX_new();
    EXPECT(ctx != NULL, "SHA512_CTX_new() should return non-NULL");
    SHA512_CTX_free(ctx);
}

static void test_sha512_ctx_free_null(void)
{
    SHA512_CTX_free(NULL);
    EXPECT(1, "SHA512_CTX_free(NULL) should not crash");
}

static void test_sha512_ctx_free_without_init(void)
{
    SHA512_CTX *ctx = SHA512_CTX_new();
    EXPECT(ctx != NULL, "SHA512_CTX_new() for free-without-init test");
    SHA512_CTX_free(ctx);
    EXPECT(1, "SHA512_CTX_free without prior SHA512_Init should not crash");
}

static void test_sha384_empty_digest(void)
{
    /* SHA-384 uses SHA512_CTX — exercises the SHA512_CTX new/free pair with
     * the SHA-384 variant of the underlying wolfSSL context. */
    static const unsigned char expected[SHA384_DIGEST_LENGTH] = {
        0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,
        0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,
        0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,
        0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,
        0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,
        0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b
    };
    unsigned char md[SHA384_DIGEST_LENGTH];

    SHA512_CTX *ctx = SHA512_CTX_new();
    EXPECT(ctx != NULL, "SHA512_CTX_new() for SHA-384 digest test");
    EXPECT(SHA384_Init(ctx)      == 1, "SHA384_Init should return 1");
    EXPECT(SHA384_Final(md, ctx) == 1, "SHA384_Final should return 1");
    EXPECT(memcmp(md, expected, SHA384_DIGEST_LENGTH) == 0,
           "SHA-384 of empty string matches known-answer vector");
    SHA512_CTX_free(ctx);
}

static void test_sha512_empty_digest(void)
{
    static const unsigned char expected[SHA512_DIGEST_LENGTH] = {
        0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,
        0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
        0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,
        0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
        0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,
        0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
        0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,
        0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e
    };
    unsigned char md[SHA512_DIGEST_LENGTH];

    SHA512_CTX *ctx = SHA512_CTX_new();
    EXPECT(ctx != NULL, "SHA512_CTX_new() for SHA-512 digest test");
    EXPECT(SHA512_Init(ctx)      == 1, "SHA512_Init should return 1");
    EXPECT(SHA512_Final(md, ctx) == 1, "SHA512_Final should return 1");
    EXPECT(memcmp(md, expected, SHA512_DIGEST_LENGTH) == 0,
           "SHA-512 of empty string matches known-answer vector");
    SHA512_CTX_free(ctx);
}

static void test_sha512_ctx_reuse(void)
{
    static const unsigned char data[] = "wolfshim reuse test";
    unsigned char md1[SHA512_DIGEST_LENGTH], md2[SHA512_DIGEST_LENGTH];

    SHA512_CTX *ctx = SHA512_CTX_new();
    EXPECT(ctx != NULL, "SHA512_CTX_new() for reuse test");

    EXPECT(SHA512_Init(ctx) == 1, "SHA512_Init (first cycle)");
    EXPECT(SHA512_Update(ctx, data, sizeof(data) - 1) == 1,
           "SHA512_Update (first cycle)");
    EXPECT(SHA512_Final(md1, ctx) == 1, "SHA512_Final (first cycle)");

    EXPECT(SHA512_Init(ctx) == 1, "SHA512_Init (second cycle, reuse path)");
    EXPECT(SHA512_Update(ctx, data, sizeof(data) - 1) == 1,
           "SHA512_Update (second cycle)");
    EXPECT(SHA512_Final(md2, ctx) == 1, "SHA512_Final (second cycle)");

    EXPECT(memcmp(md1, md2, SHA512_DIGEST_LENGTH) == 0,
           "SHA-512 reuse path should produce identical digests");
    SHA512_CTX_free(ctx);
}

/* =========================================================================
 * Allocation counter (WOLFSHIM_DEBUG builds only)
 *
 * wolfshim_sha_ctx_alloc_count() counts wolfSSL SHA context heap allocations
 * across all five SHA variants since process start.  It increments only on a
 * fresh malloc — the Init→Final→Init reuse path does NOT increment.
 * ========================================================================= */

#ifdef WOLFSHIM_DEBUG
static void test_sha_alloc_count_increments_on_first_init(void)
{
    long before = wolfshim_sha_ctx_alloc_count();

    SHA_CTX *ctx = SHA_CTX_new();
    EXPECT(ctx != NULL, "SHA_CTX_new() for alloc_count test");
    SHA1_Init(ctx);

    EXPECT(wolfshim_sha_ctx_alloc_count() == before + 1,
           "alloc_count should increment by 1 on first SHA1_Init");
    SHA_CTX_free(ctx);
}

static void test_sha_alloc_count_no_increment_on_reuse(void)
{
    /* After SHA*_Final the sentinel is re-set, so the next SHA*_Init reuses
     * the existing inner allocation without a new malloc.  The counter must
     * not increment on the reuse path. */
    SHA_CTX *ctx = SHA_CTX_new();
    EXPECT(ctx != NULL, "SHA_CTX_new() for reuse alloc_count test");

    SHA1_Init(ctx);
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA1_Final(md, ctx);

    long after_first = wolfshim_sha_ctx_alloc_count();

    /* Second Init — should reuse, not allocate */
    SHA1_Init(ctx);
    SHA1_Final(md, ctx);

    EXPECT(wolfshim_sha_ctx_alloc_count() == after_first,
           "alloc_count should NOT increment on SHA1_Init reuse path");
    SHA_CTX_free(ctx);
}

static void test_sha256_alloc_count_increments(void)
{
    long before = wolfshim_sha_ctx_alloc_count();

    SHA256_CTX *ctx = SHA256_CTX_new();
    EXPECT(ctx != NULL, "SHA256_CTX_new() for alloc_count test");
    SHA256_Init(ctx);

    EXPECT(wolfshim_sha_ctx_alloc_count() == before + 1,
           "alloc_count should increment by 1 on first SHA256_Init");
    SHA256_CTX_free(ctx);
}

static void test_sha512_alloc_count_increments(void)
{
    long before = wolfshim_sha_ctx_alloc_count();

    SHA512_CTX *ctx = SHA512_CTX_new();
    EXPECT(ctx != NULL, "SHA512_CTX_new() for alloc_count test");
    SHA512_Init(ctx);

    EXPECT(wolfshim_sha_ctx_alloc_count() == before + 1,
           "alloc_count should increment by 1 on first SHA512_Init");
    SHA512_CTX_free(ctx);
}
#endif /* WOLFSHIM_DEBUG */

/* =========================================================================
 * main
 * ========================================================================= */

int main(void)
{
    /* SHA-1  (SHA_CTX) */
    test_sha1_ctx_new_returns_nonnull();
    test_sha1_ctx_free_null();
    test_sha1_ctx_free_without_init();
    test_sha1_empty_digest();
    test_sha1_ctx_reuse();

    /* SHA-224 / SHA-256  (SHA256_CTX) */
    test_sha256_ctx_new_returns_nonnull();
    test_sha256_ctx_free_null();
    test_sha256_ctx_free_without_init();
    test_sha224_empty_digest();
    test_sha256_empty_digest();
    test_sha256_ctx_reuse();

    /* SHA-384 / SHA-512  (SHA512_CTX) */
    test_sha512_ctx_new_returns_nonnull();
    test_sha512_ctx_free_null();
    test_sha512_ctx_free_without_init();
    test_sha384_empty_digest();
    test_sha512_empty_digest();
    test_sha512_ctx_reuse();

#ifdef WOLFSHIM_DEBUG
    /* Allocation counter */
    test_sha_alloc_count_increments_on_first_init();
    test_sha_alloc_count_no_increment_on_reuse();
    test_sha256_alloc_count_increments();
    test_sha512_alloc_count_increments();
#endif

    printf("%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
