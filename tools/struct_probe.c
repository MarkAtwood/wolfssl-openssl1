/*
 * struct_probe.c — Print sizeof/offsetof values for wolfSSL structs
 *                  used by the shim layer.
 *
 * Referenced by CONTRIBUTING.md (wolfSSL upgrade checklist, step 1).
 * After a wolfSSL upgrade, compile and run this tool and compare the
 * output against the _Static_assert constants in:
 *   shim/src/aes/aes_shim.c
 *   shim/src/ec/ec_shim.c
 *
 * Compile (option A — using wolfssl-config):
 *   gcc -o tools/struct_probe tools/struct_probe.c \
 *       -I wolfssl/src -I wolfssl/wolfssl \
 *       $(wolfssl/src/wolfssl-config --cflags)
 *
 * Compile (option B — manual flags):
 *   cd wolfssl && gcc -o ../tools/struct_probe_bin \
 *       ../tools/struct_probe.c \
 *       -I . -I wolfssl -DOPENSSL_EXTRA -DHAVE_ECC \
 *       -DWOLFSSL_AES_CFB -DWOLFSSL_AES_OFB
 *
 * Exit status:
 *   0  All probed values match expected constants.
 *   1  One or more values differ — update the _Static_assert constants.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/openssl/ec.h>
#include <stddef.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Expected values — must match the _Static_assert constants in the shim.
 * Update these after verifying a new wolfSSL release.
 * ----------------------------------------------------------------------- */

/* From shim/src/aes/aes_shim.c */
#define EXPECTED_AES_REG_OFFSET   256
#define EXPECTED_AES_LEFT_OFFSET  864

/* From shim/src/ec/ec_shim.c */
#define EXPECTED_EC_GROUP_SIZE           12
#define EXPECTED_EC_GROUP_CURVE_IDX       0
#define EXPECTED_EC_GROUP_CURVE_NID       4
#define EXPECTED_EC_GROUP_CURVE_OID       8
#define EXPECTED_EC_KEY_SIZE             56
#define EXPECTED_EC_KEY_PRIV_KEY         16

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static int g_failures = 0;

static void check(const char *label, size_t actual, size_t expected)
{
    if (actual == expected) {
        printf("  %-40s = %-6zu [expected: %-6zu]  OK\n",
               label, actual, expected);
    } else {
        printf("  %-40s = %-6zu [expected: %-6zu]  *** CHANGED ***\n",
               label, actual, expected);
        g_failures++;
    }
}

/* Print a value that has no expected constant (informational only). */
static void info(const char *label, size_t value)
{
    printf("  %-40s = %zu\n", label, value);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("=== Aes struct (expected: reg=%d, left=%d) ===\n",
           EXPECTED_AES_REG_OFFSET, EXPECTED_AES_LEFT_OFFSET);

    /* sizeof(Aes) — no _Static_assert for this yet, informational only */
    info("sizeof(Aes)", sizeof(Aes));

    check("offsetof(Aes, reg)",
          offsetof(Aes, reg), EXPECTED_AES_REG_OFFSET);

#if defined(WOLFSSL_AES_CFB) || defined(WOLFSSL_AES_OFB) || \
    defined(WOLFSSL_AES_XTS) || defined(WOLFSSL_AES_CTS)
    check("offsetof(Aes, left)",
          offsetof(Aes, left), EXPECTED_AES_LEFT_OFFSET);
#else
    printf("  %-40s   (field not present — streaming modes disabled)\n",
           "offsetof(Aes, left)");
#endif

    printf("\n");

    printf("=== WOLFSSL_EC_GROUP struct (expected: sizeof=%d, "
           "curve_idx=%d, curve_nid=%d, curve_oid=%d) ===\n",
           EXPECTED_EC_GROUP_SIZE,
           EXPECTED_EC_GROUP_CURVE_IDX,
           EXPECTED_EC_GROUP_CURVE_NID,
           EXPECTED_EC_GROUP_CURVE_OID);

    check("sizeof(WOLFSSL_EC_GROUP)",
          sizeof(WOLFSSL_EC_GROUP), EXPECTED_EC_GROUP_SIZE);
    check("offsetof(WOLFSSL_EC_GROUP, curve_idx)",
          offsetof(WOLFSSL_EC_GROUP, curve_idx), EXPECTED_EC_GROUP_CURVE_IDX);
    check("offsetof(WOLFSSL_EC_GROUP, curve_nid)",
          offsetof(WOLFSSL_EC_GROUP, curve_nid), EXPECTED_EC_GROUP_CURVE_NID);
    check("offsetof(WOLFSSL_EC_GROUP, curve_oid)",
          offsetof(WOLFSSL_EC_GROUP, curve_oid), EXPECTED_EC_GROUP_CURVE_OID);

    printf("\n");

    printf("=== WOLFSSL_EC_KEY struct (expected: sizeof=%d, "
           "priv_key=%d) ===\n",
           EXPECTED_EC_KEY_SIZE,
           EXPECTED_EC_KEY_PRIV_KEY);

    check("sizeof(WOLFSSL_EC_KEY)",
          sizeof(WOLFSSL_EC_KEY), EXPECTED_EC_KEY_SIZE);
    check("offsetof(WOLFSSL_EC_KEY, priv_key)",
          offsetof(WOLFSSL_EC_KEY, priv_key), EXPECTED_EC_KEY_PRIV_KEY);

    printf("\n");

    if (g_failures == 0) {
        printf("All values match expected constants.\n");
    } else {
        printf("%d value(s) CHANGED — update _Static_assert constants in "
               "shim/src/aes/aes_shim.c and/or shim/src/ec/ec_shim.c.\n",
               g_failures);
    }

    return g_failures == 0 ? 0 : 1;
}
