/*
 * aes_lifecycle_test.c — Unit tests for AES_KEY_new / AES_KEY_free wolfshim
 * lifecycle extensions.
 *
 * Include strategy
 * ----------------
 * Tests include the stock OpenSSL 1.1.1 AES header (<openssl/aes.h>) rather
 * than wolfSSL's compat header.  OpenSSL's header declares AES_set_encrypt_key,
 * AES_ecb_encrypt, etc. as plain C prototypes with no macro aliasing, so every
 * call resolves directly to the wolfshim ELF symbol at link time.  This is the
 * same header a wolfshim consumer would include.
 *
 * wolfshim extensions (AES_KEY_new / AES_KEY_free / alloc counter) come from
 * aes_shim.h, which skips its standard-function declarations when HEADER_AES_H
 * is already set by <openssl/aes.h>.
 *
 * AES-128 ECB test vector
 * -----------------------
 * Key:        000102030405060708090a0b0c0d0e0f
 * Plaintext:  00112233445566778899aabbccddeeff
 * Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
 * Source: NIST FIPS 197 Appendix B
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>  /* AES_KEY, AES_set_encrypt_key, AES_ecb_encrypt, … */
#include "aes_shim.h"     /* AES_KEY_new, AES_KEY_free, wolfshim_aes_ctx_alloc_count */

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
 * AES_KEY_new
 * ========================================================================= */

static void test_aes_key_new_returns_nonnull(void)
{
    AES_KEY *k = AES_KEY_new();
    EXPECT(k != NULL, "AES_KEY_new() should return non-NULL");
    AES_KEY_free(k);
}

static void test_aes_key_new_is_zeroed(void)
{
    AES_KEY *k = AES_KEY_new();
    EXPECT(k != NULL, "AES_KEY_new() for zeroed-check");

    /* calloc guarantees zero-fill.  Verify the two pointer-slots that the
     * sentinel system uses are zero before any AES_set_*_key call. */
    unsigned char slots[2 * sizeof(void *)];
    memcpy(slots, k, sizeof(slots));
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(slots); i++) {
        if (slots[i] != 0) { all_zero = 0; break; }
    }
    EXPECT(all_zero, "AES_KEY_new() pointer slots should be zero-filled");
    AES_KEY_free(k);
}

/* =========================================================================
 * AES_KEY_free edge cases
 * ========================================================================= */

static void test_aes_key_free_null(void)
{
    AES_KEY_free(NULL);     /* must not crash */
    EXPECT(1, "AES_KEY_free(NULL) should not crash");
}

static void test_aes_key_free_without_set_key(void)
{
    /* AES_KEY_new followed immediately by AES_KEY_free, with no
     * AES_set_*_key call.  The inner wolfCrypt Aes context is never
     * allocated (no sentinel written), so aes_ctx_free is a no-op for the
     * inner allocation; only the outer calloc'd struct is freed. */
    AES_KEY *k = AES_KEY_new();
    EXPECT(k != NULL, "AES_KEY_new() for free-without-set test");
    AES_KEY_free(k);
    EXPECT(1, "AES_KEY_free without prior AES_set_*_key should not crash");
}

/* =========================================================================
 * AES_KEY_new + AES_set_*_key + AES_KEY_free lifecycle
 * ========================================================================= */

static void test_aes_key_set_encrypt_free(void)
{
    static const unsigned char raw[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    AES_KEY *k = AES_KEY_new();
    EXPECT(k != NULL, "AES_KEY_new() for set_encrypt test");
    EXPECT(AES_set_encrypt_key(raw, 128, k) == 0,
           "AES_set_encrypt_key should return 0 on success");
    AES_KEY_free(k);
    EXPECT(1, "AES_KEY_free after set_encrypt_key should not crash");
}

static void test_aes_key_set_decrypt_free(void)
{
    static const unsigned char raw[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    AES_KEY *k = AES_KEY_new();
    EXPECT(k != NULL, "AES_KEY_new() for set_decrypt test");
    EXPECT(AES_set_decrypt_key(raw, 128, k) == 0,
           "AES_set_decrypt_key should return 0 on success");
    AES_KEY_free(k);
    EXPECT(1, "AES_KEY_free after set_decrypt_key should not crash");
}

/* =========================================================================
 * AES-128 ECB encrypt + decrypt round-trip  (NIST FIPS 197 Appendix B)
 * ========================================================================= */

static void test_aes_key_ecb_roundtrip(void)
{
    static const unsigned char key128[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const unsigned char plaintext[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const unsigned char expected_ct[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    unsigned char ct[16], pt2[16];
    memset(ct,  0, sizeof(ct));
    memset(pt2, 0, sizeof(pt2));

    /* Encrypt */
    AES_KEY *enc = AES_KEY_new();
    EXPECT(enc != NULL, "AES_KEY_new() for ECB encrypt");
    EXPECT(AES_set_encrypt_key(key128, 128, enc) == 0,
           "AES_set_encrypt_key for ECB round-trip");
    AES_ecb_encrypt(plaintext, ct, enc, AES_ENCRYPT);
    EXPECT(memcmp(ct, expected_ct, 16) == 0,
           "AES-128 ECB ciphertext matches NIST FIPS 197 Appendix B vector");
    AES_KEY_free(enc);

    /* Decrypt */
    AES_KEY *dec = AES_KEY_new();
    EXPECT(dec != NULL, "AES_KEY_new() for ECB decrypt");
    EXPECT(AES_set_decrypt_key(key128, 128, dec) == 0,
           "AES_set_decrypt_key for ECB round-trip");
    AES_ecb_encrypt(ct, pt2, dec, AES_DECRYPT);
    EXPECT(memcmp(pt2, plaintext, 16) == 0,
           "AES-128 ECB decrypted plaintext matches original");
    AES_KEY_free(dec);
}

/* =========================================================================
 * Allocation counter (WOLFSHIM_DEBUG builds only)
 *
 * wolfshim_aes_ctx_alloc_count() counts wolfCrypt Aes heap allocations
 * made by AES_set_encrypt_key / AES_set_decrypt_key.  It increments on
 * every successful key setup and never decrements.
 * ========================================================================= */

#ifdef WOLFSHIM_DEBUG
static void test_aes_alloc_count_set_encrypt(void)
{
    static const unsigned char raw[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    long before = wolfshim_aes_ctx_alloc_count();

    AES_KEY *k = AES_KEY_new();
    EXPECT(k != NULL, "AES_KEY_new() for alloc_count test");
    AES_set_encrypt_key(raw, 128, k);

    EXPECT(wolfshim_aes_ctx_alloc_count() == before + 1,
           "alloc_count should increment by 1 after AES_set_encrypt_key");
    AES_KEY_free(k);
}

static void test_aes_alloc_count_set_decrypt(void)
{
    static const unsigned char raw[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    long before = wolfshim_aes_ctx_alloc_count();

    AES_KEY *k = AES_KEY_new();
    EXPECT(k != NULL, "AES_KEY_new() for alloc_count decrypt test");
    AES_set_decrypt_key(raw, 128, k);

    EXPECT(wolfshim_aes_ctx_alloc_count() == before + 1,
           "alloc_count should increment by 1 after AES_set_decrypt_key");
    AES_KEY_free(k);
}
#endif /* WOLFSHIM_DEBUG */

/* =========================================================================
 * main
 * ========================================================================= */

int main(void)
{
    /* AES_KEY_new */
    test_aes_key_new_returns_nonnull();
    test_aes_key_new_is_zeroed();

    /* AES_KEY_free edge cases */
    test_aes_key_free_null();
    test_aes_key_free_without_set_key();

    /* Full lifecycle */
    test_aes_key_set_encrypt_free();
    test_aes_key_set_decrypt_free();

    /* Correctness: NIST FIPS 197 ECB round-trip */
    test_aes_key_ecb_roundtrip();

#ifdef WOLFSHIM_DEBUG
    /* Allocation counter */
    test_aes_alloc_count_set_encrypt();
    test_aes_alloc_count_set_decrypt();
#endif

    printf("%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
