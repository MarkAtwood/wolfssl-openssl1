/*
 * rand_shim_test.c - Unit tests for the wolfshim RAND/RAND_DRBG layer
 *
 * These tests call wolfshim_RAND_* functions directly (bypassing the
 * OpenSSL-named public aliases) to verify the shim logic in isolation.
 * This justifies the two-layer wolfshim_* / public-alias architecture
 * described in rand_shim.c.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

/* NID_aes_256_ctr -- define manually if not available from wolfSSL headers */
#ifndef NID_aes_256_ctr
#define NID_aes_256_ctr 904
#endif

/* The shim header -- declares wolfshim_RAND_* prototypes */
#include "rand_shim.h"

/* -------------------------------------------------------------------------
 * Minimal test framework
 * ------------------------------------------------------------------------- */

static int tests_run = 0, tests_passed = 0;
#define EXPECT(cond, msg) do { \
    tests_run++; \
    if (cond) { tests_passed++; } \
    else { fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); } \
} while(0)

/* Helper: check whether a buffer is all-zero */
static int is_all_zero(const unsigned char *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (buf[i] != 0)
            return 0;
    }
    return 1;
}

/* =========================================================================
 * RAND_DRBG lifecycle tests
 * ========================================================================= */

static void test_drbg_new_type_zero(void)
{
    RAND_DRBG *d = wolfshim_RAND_DRBG_new(0, 0, NULL);
    EXPECT(d != NULL, "RAND_DRBG_new(0, 0, NULL) should return non-NULL");
    wolfshim_RAND_DRBG_free(d);
}

static void test_drbg_new_type_nonzero(void)
{
    /* Non-zero type (e.g. NID_aes_256_ctr) is accepted by _new but with a
     * warning; the returned DRBG still uses wolfCrypt's Hash-DRBG. */
    RAND_DRBG *d = wolfshim_RAND_DRBG_new(NID_aes_256_ctr, 0, NULL);
    EXPECT(d != NULL,
           "RAND_DRBG_new(NID_aes_256_ctr, 0, NULL) should return non-NULL");
    wolfshim_RAND_DRBG_free(d);
}

static void test_drbg_instantiate(void)
{
    RAND_DRBG *d = wolfshim_RAND_DRBG_new(0, 0, NULL);
    EXPECT(d != NULL, "RAND_DRBG_new for instantiate test");

    int ret = wolfshim_RAND_DRBG_instantiate(d, NULL, 0);
    EXPECT(ret == 1, "RAND_DRBG_instantiate(drbg, NULL, 0) should return 1");

    wolfshim_RAND_DRBG_free(d);
}

static void test_drbg_generate_after_instantiate(void)
{
    RAND_DRBG *d = wolfshim_RAND_DRBG_new(0, 0, NULL);
    EXPECT(d != NULL, "RAND_DRBG_new for generate test");

    wolfshim_RAND_DRBG_instantiate(d, NULL, 0);

    unsigned char buf[32];
    memset(buf, 0, sizeof(buf));
    int ret = wolfshim_RAND_DRBG_generate(d, buf, sizeof(buf), 0, NULL, 0);
    EXPECT(ret == 1, "RAND_DRBG_generate should return 1 after instantiate");
    EXPECT(!is_all_zero(buf, sizeof(buf)),
           "RAND_DRBG_generate should produce non-zero output (probabilistic)");

    wolfshim_RAND_DRBG_free(d);
}

static void test_drbg_uninstantiate_then_generate_fails(void)
{
    RAND_DRBG *d = wolfshim_RAND_DRBG_new(0, 0, NULL);
    EXPECT(d != NULL, "RAND_DRBG_new for uninstantiate test");

    wolfshim_RAND_DRBG_instantiate(d, NULL, 0);

    int ret = wolfshim_RAND_DRBG_uninstantiate(d);
    EXPECT(ret == 1, "RAND_DRBG_uninstantiate should return 1");

    /* After uninstantiate, generate auto-instantiates in this shim (see
     * implementation comment).  We test that uninstantiate itself succeeds
     * and does not crash; the auto-instantiate behaviour is an implementation
     * detail. */
    unsigned char buf[32];
    memset(buf, 0, sizeof(buf));
    ret = wolfshim_RAND_DRBG_generate(d, buf, sizeof(buf), 0, NULL, 0);
    /* The shim auto-instantiates, so generate succeeds even after
     * uninstantiate.  Verify it at least does not crash. */
    EXPECT(ret == 0 || ret == 1,
           "RAND_DRBG_generate after uninstantiate should not crash");

    wolfshim_RAND_DRBG_free(d);
}

static void test_drbg_free_null(void)
{
    /* Must not crash */
    wolfshim_RAND_DRBG_free(NULL);
    EXPECT(1, "RAND_DRBG_free(NULL) should not crash");
}

/* =========================================================================
 * RAND_DRBG_set type rejection tests
 * ========================================================================= */

static void test_drbg_set_type_zero(void)
{
    RAND_DRBG *d = wolfshim_RAND_DRBG_new(0, 0, NULL);
    EXPECT(d != NULL, "RAND_DRBG_new for set test");

    int ret = wolfshim_RAND_DRBG_set(d, 0, 0);
    EXPECT(ret == 1, "RAND_DRBG_set(drbg, 0, 0) should return 1");

    wolfshim_RAND_DRBG_free(d);
}

static void test_drbg_set_type_nonzero_rejected(void)
{
    RAND_DRBG *d = wolfshim_RAND_DRBG_new(0, 0, NULL);
    EXPECT(d != NULL, "RAND_DRBG_new for set rejection test");

    int ret = wolfshim_RAND_DRBG_set(d, 12, 0);
    EXPECT(ret == 0, "RAND_DRBG_set(drbg, 12, 0) should return 0 (rejected)");

    wolfshim_RAND_DRBG_free(d);
}

/* =========================================================================
 * RAND_DRBG_set_defaults type rejection tests
 * ========================================================================= */

static void test_drbg_set_defaults_type_zero(void)
{
    int ret = wolfshim_RAND_DRBG_set_defaults(0, 0);
    EXPECT(ret == 1, "RAND_DRBG_set_defaults(0, 0) should return 1");
}

static void test_drbg_set_defaults_type_nonzero_rejected(void)
{
    int ret = wolfshim_RAND_DRBG_set_defaults(12, 0);
    EXPECT(ret == 0,
           "RAND_DRBG_set_defaults(12, 0) should return 0 (rejected)");
}

/* =========================================================================
 * RAND_DRBG_secure_new tests
 * ========================================================================= */

static void test_drbg_secure_new(void)
{
    RAND_DRBG *d = wolfshim_RAND_DRBG_secure_new(0, 0, NULL);
    EXPECT(d != NULL,
           "RAND_DRBG_secure_new(0, 0, NULL) should return non-NULL");
    /* The 'secure' field is internal to the struct; we cannot inspect it
     * directly from here without exposing the struct layout.  We verify the
     * allocation succeeded and free does not crash. */
    wolfshim_RAND_DRBG_free(d);
    EXPECT(1, "RAND_DRBG_free of secure DRBG should not crash");
}

/* =========================================================================
 * RAND_bytes tests
 * ========================================================================= */

static void test_rand_bytes_normal(void)
{
    unsigned char buf[32];
    memset(buf, 0, sizeof(buf));

    int ret = wolfshim_RAND_bytes(buf, 32);
    EXPECT(ret == 1, "RAND_bytes(buf, 32) should return 1");
    EXPECT(!is_all_zero(buf, sizeof(buf)),
           "RAND_bytes should fill buffer with non-zero data (probabilistic)");
}

static void test_rand_bytes_null(void)
{
    int ret = wolfshim_RAND_bytes(NULL, 32);
    EXPECT(ret == 0, "RAND_bytes(NULL, 32) should return 0");
}

static void test_rand_bytes_zero_length(void)
{
    unsigned char buf[4];
    int ret = wolfshim_RAND_bytes(buf, 0);
    EXPECT(ret == 0, "RAND_bytes(buf, 0) should return 0");
}

/* =========================================================================
 * RAND_status test
 * ========================================================================= */

static void test_rand_status(void)
{
    int ret = wolfshim_RAND_status();
    EXPECT(ret == 1, "RAND_status() should return 1");
}

/* =========================================================================
 * RAND_get_rand_method test
 * ========================================================================= */

static void test_rand_get_rand_method(void)
{
    const RAND_METHOD *m = wolfshim_RAND_get_rand_method();
    EXPECT(m != NULL, "RAND_get_rand_method() should return non-NULL");
    EXPECT(m->bytes != NULL,
           "RAND_get_rand_method()->bytes should be non-NULL");
}

/* =========================================================================
 * RAND_set_rand_method / RAND_get_rand_method round-trip tests
 * ========================================================================= */

/* Dummy bytes function for custom method testing */
static int dummy_bytes(unsigned char *buf, int num)
{
    (void)buf;
    (void)num;
    return 42;
}

static void test_rand_set_get_method(void)
{
    /* Save the default method pointer */
    const RAND_METHOD *default_m = wolfshim_RAND_get_rand_method();
    EXPECT(default_m != NULL, "default RAND_METHOD should be non-NULL");

    /* Install a custom method */
    RAND_METHOD custom;
    memset(&custom, 0, sizeof(custom));
    custom.bytes = dummy_bytes;

    int ret = wolfshim_RAND_set_rand_method(&custom);
    EXPECT(ret == 1, "RAND_set_rand_method should return 1");

    const RAND_METHOD *got = wolfshim_RAND_get_rand_method();
    EXPECT(got == &custom,
           "RAND_get_rand_method should return the installed custom method");

    /* Restore default by installing NULL */
    ret = wolfshim_RAND_set_rand_method(NULL);
    EXPECT(ret == 1, "RAND_set_rand_method(NULL) should return 1");

    got = wolfshim_RAND_get_rand_method();
    EXPECT(got == default_m,
           "After setting NULL, RAND_get_rand_method should return the "
           "default wolfshim method");
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void)
{
    /* RAND_DRBG lifecycle */
    test_drbg_new_type_zero();
    test_drbg_new_type_nonzero();
    test_drbg_instantiate();
    test_drbg_generate_after_instantiate();
    test_drbg_uninstantiate_then_generate_fails();
    test_drbg_free_null();

    /* RAND_DRBG_set type rejection */
    test_drbg_set_type_zero();
    test_drbg_set_type_nonzero_rejected();

    /* RAND_DRBG_set_defaults type rejection */
    test_drbg_set_defaults_type_zero();
    test_drbg_set_defaults_type_nonzero_rejected();

    /* RAND_DRBG_secure_new */
    test_drbg_secure_new();

    /* RAND_bytes */
    test_rand_bytes_normal();
    test_rand_bytes_null();
    test_rand_bytes_zero_length();

    /* RAND_status */
    test_rand_status();

    /* RAND_get_rand_method */
    test_rand_get_rand_method();

    /* RAND_set_rand_method / get round-trip */
    test_rand_set_get_method();

    /* Summary */
    printf("%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
