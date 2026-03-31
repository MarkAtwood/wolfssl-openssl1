/*
 * wolfshim_abi_check.c — Runtime ABI sanity check for wolfSSL struct layout
 *
 * Runs at shared-library load time via __attribute__((constructor)), before
 * main() and before any application crypto call.  If the installed
 * libwolfssl.so was built with different flags than the headers the shim
 * was compiled against, struct field offsets can shift, causing silent heap
 * corruption.  This constructor catches the mismatch early and aborts with
 * a diagnostic message rather than letting the process continue.
 *
 * Three layers of detection:
 *
 *   Layer 1 — Version check.
 *     Compares LIBWOLFSSL_VERSION_HEX (compile-time constant baked into the
 *     wolfSSL headers) against wolfSSL_lib_version_hex() (the value reported
 *     by the runtime libwolfssl.so).  Catches the common case of deploying a
 *     different wolfSSL version than the shim was compiled against.
 *
 *   Layer 2 — Aes struct size canary probe.
 *     Allocates sizeof(Aes) + CANARY_LEN bytes, fills the trailing suffix
 *     with a known byte pattern, calls wc_AesInit() into the leading portion,
 *     then verifies the canary is undisturbed.  If the runtime wolfSSL thinks
 *     sizeof(Aes) is larger than the compile-time value, wc_AesInit() writes
 *     past the boundary and corrupts the canary.  This catches the "wolfSSL
 *     built with extra features that grew the Aes struct" case — the most
 *     dangerous variant because it causes silent heap overflows in
 *     AES_set_encrypt_key / AES_set_decrypt_key.
 *
 *   Layer 3 — Field offset probes (EC_GROUP.curve_nid, BIGNUM.neg).
 *     Creates real wolfSSL objects through the public API, reads a known
 *     field both via the public accessor function and via direct struct cast
 *     at the compile-time offsetof(), and verifies both values agree.  A
 *     discrepancy means the field moved — the WOLFSHIM_REVIEW [ABI] sites
 *     in ec_shim.c and bn_shim.c are reading wrong bytes.
 *
 * Aes.reg / Aes.left are not independently probed here: they are internal
 * fields with no public accessor to compare against.  The version guard and
 * canary probe together cover the realistic failure modes for those fields.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>

/* ── canary helpers ───────────────────────────────────────────────────────── */

#define CANARY_LEN  64
#define CANARY_BYTE 0xA5u

static void canary_fill(unsigned char *p)
{
    int i;
    for (i = 0; i < CANARY_LEN; i++)
        p[i] = (unsigned char)(CANARY_BYTE ^ (unsigned char)i);
}

static int canary_intact(const unsigned char *p)
{
    int i;
    for (i = 0; i < CANARY_LEN; i++)
        if (p[i] != (unsigned char)(CANARY_BYTE ^ (unsigned char)i))
            return 0;
    return 1;
}

/* ── layer 1: version ─────────────────────────────────────────────────────── */

static void check_version(void)
{
    unsigned long compiled = (unsigned long)LIBWOLFSSL_VERSION_HEX;
    unsigned long runtime  = (unsigned long)wolfSSL_lib_version_hex();

    if (runtime == compiled)
        return;

    fprintf(stderr,
        "[wolfshim] FATAL: wolfSSL version mismatch.\n"
        "  Compiled against: 0x%08lX  (%s)\n"
        "  Runtime library:  0x%08lX  (%s)\n"
        "\n"
        "  The shim accesses wolfSSL internal struct fields directly\n"
        "  (Aes.reg, Aes.left, WOLFSSL_EC_GROUP.curve_nid, WOLFSSL_BIGNUM.neg).\n"
        "  Running a mismatched wolfSSL causes silent heap corruption.\n"
        "\n"
        "  Fix: rebuild the shim and OpenSSL against the installed wolfSSL\n"
        "  (recompile shim/src/ and the OpenSSL tree against the new headers).\n",
        compiled, LIBWOLFSSL_VERSION_STRING,
        runtime, wolfSSL_lib_version());
    abort();
}

/* ── layer 2: Aes struct size canary ─────────────────────────────────────── */

static void check_aes_struct_size(void)
{
    unsigned char *buf;
    size_t alloc = sizeof(Aes) + CANARY_LEN;

    buf = (unsigned char *)calloc(1, alloc);
    if (!buf)
        return;  /* allocation failure — skip probe rather than false-positive */

    canary_fill(buf + sizeof(Aes));
    wc_AesInit((Aes *)buf, NULL, INVALID_DEVID);

    if (!canary_intact(buf + sizeof(Aes))) {
        fprintf(stderr,
            "[wolfshim] FATAL: Aes struct size mismatch.\n"
            "  sizeof(Aes) at compile time: %zu bytes\n"
            "  Runtime wc_AesInit() wrote past that boundary (canary overwritten).\n"
            "  Cause: wolfSSL deployed with different ./configure flags than\n"
            "  the wolfSSL headers the shim was compiled against.\n"
            "\n"
            "  Fix: rebuild the shim and OpenSSL against the deployed wolfSSL\n"
            "  (recompile shim/src/ and the OpenSSL tree against the new headers).\n",
            sizeof(Aes));
        wc_AesFree((Aes *)buf);
        free(buf);
        abort();
    }

    wc_AesFree((Aes *)buf);
    free(buf);
}

/* ── layer 3a: WOLFSSL_EC_GROUP.curve_nid field offset ───────────────────── */

static void check_ec_group_field(void)
{
    WOLFSSL_EC_GROUP *grp;
    int via_api;
    int via_cast;

    grp = wolfSSL_EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!grp)
        return;  /* EC not compiled into this wolfSSL build — skip */

    via_api  = wolfSSL_EC_GROUP_get_curve_name(grp);
    via_cast = ((WOLFSSL_EC_GROUP *)grp)->curve_nid;

    wolfSSL_EC_GROUP_free(grp);

    if (via_api != NID_X9_62_prime256v1 || via_cast != via_api) {
        fprintf(stderr,
            "[wolfshim] FATAL: WOLFSSL_EC_GROUP.curve_nid field offset mismatch.\n"
            "  Expected NID_X9_62_prime256v1 (%d) from both paths.\n"
            "  wolfSSL_EC_GROUP_get_curve_name() returned: %d\n"
            "  Direct struct cast at compile-time offsetof(curve_nid): %d\n"
            "\n"
            "  The WOLFSHIM_REVIEW [ABI] sites in ec_shim.c are reading wrong\n"
            "  bytes.  Audit ec_shim.c against the new wolfSSL struct layout,\n"
            "  then rebuild the shim against the new headers:\n"
            "    grep -n 'WOLFSHIM_REVIEW.*ABI' shim/src/ec/ec_shim.c\n",
            NID_X9_62_prime256v1, via_api, via_cast);
        abort();
    }
}

/* ── layer 3b: WOLFSSL_BIGNUM.neg field offset ───────────────────────────── */

static void check_bn_neg_field(void)
{
    WOLFSSL_BIGNUM *bn;
    int via_api;
    int via_cast;

    bn = wolfSSL_BN_new();
    if (!bn)
        return;

    wolfSSL_BN_set_word(bn, 42);  /* positive value — neg must be 0 */

    via_api  = wolfSSL_BN_is_negative(bn);
    via_cast = ((WOLFSSL_BIGNUM *)bn)->neg;

    wolfSSL_BN_free(bn);

    if (via_api != 0 || via_cast != 0) {
        fprintf(stderr,
            "[wolfshim] FATAL: WOLFSSL_BIGNUM.neg field offset mismatch.\n"
            "  Created a positive BIGNUM (value=42); neg must be 0 via both paths.\n"
            "  wolfSSL_BN_is_negative() returned: %d  (expected 0)\n"
            "  Direct struct cast at compile-time offsetof(neg): %d  (expected 0)\n"
            "\n"
            "  The WOLFSHIM_REVIEW [ABI] sites in bn_shim.c are reading wrong\n"
            "  bytes.  Audit bn_shim.c against the new wolfSSL struct layout,\n"
            "  then rebuild the shim against the new headers:\n"
            "    grep -n 'WOLFSHIM_REVIEW.*ABI' shim/src/bn/bn_shim.c\n",
            via_api, via_cast);
        abort();
    }
}

/* ── constructor ──────────────────────────────────────────────────────────── */

__attribute__((constructor))
static void wolfshim_abi_check(void)
{
    check_version();
    check_aes_struct_size();
    check_ec_group_field();
    check_bn_neg_field();
}
