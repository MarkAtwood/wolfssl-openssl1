/*
 * des_shim.c — wolfCrypt DES bridge
 *
 * Provides DES_encrypt1, DES_encrypt2, DES_encrypt3, DES_decrypt3,
 * DES_ecb_encrypt, and DES_crypt backed by wolfCrypt.
 *
 * Key layout: wolfSSL DES_set_key functions store the raw 8-byte DES key
 * in the FIRST 8 BYTES of whatever structure pointer is passed as the
 * DES_key_schedule.  Our bridge reads those 8 bytes as the raw key.
 *
 * wolfCrypt: DES_ENCRYPTION=0 (encrypt), DES_DECRYPTION=1 (decrypt).
 * OpenSSL:   DES_ENCRYPT=1,              DES_DECRYPT=0.
 * The mapping is done below with explicit integer comparisons.
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#include <stddef.h>
#include <string.h>

/* wolfSSL wolfCrypt DES headers only */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_DES3
# error "wolfSSL must be built with DES3 support (--enable-des3) to use des_shim.c"
#endif

/* Compile-time wolfSSL version guard.
 * des_shim.c reads the first 8 bytes of DES_key_schedule as the raw DES key.
 * This layout was validated against wolfSSL 5.9.0.  If wolfSSL restructures
 * DES_key_schedule, this guard produces a build error forcing re-validation. */
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05009000
#  error "des_shim.c accesses wolfSSL DES_key_schedule internal layout " \
         "validated against wolfSSL 5.9.0 — re-audit all WOLFSHIM_REVIEW [ABI] " \
         "sites before lowering this threshold"
#endif

#include <wolfssl/wolfcrypt/des3.h>

/* Pull in DES_key_schedule typedef for the _Static_assert below, then
 * immediately #undef the function-name macros that would collide with
 * the replacement symbols this file defines. */
#include <wolfssl/openssl/des.h>
#undef DES_ecb_encrypt
#undef DES_cbc_encrypt
#undef DES_ncbc_encrypt
#undef DES_ede3_cbc_encrypt

/* Compile-time struct layout assertion.
 * wolfSSL's DES_key_schedule is typedef'd to WOLFSSL_DES_cblock, which is a
 * raw 8-byte array (byte[8]).  Because it IS the key bytes — not a wrapper
 * struct with a header field — the key is at offset 0 by definition.
 *
 * We assert sizeof == 8 (not >= 8) to catch any wolfSSL change that wraps the
 * raw bytes in a struct (which could move the key away from offset 0 while
 * keeping the total size >= 8).  An exact-size assertion is the minimum check
 * that rules out a struct header being prepended. */
_Static_assert(sizeof(DES_key_schedule) == 8,
    "DES_key_schedule is not exactly 8 bytes — it may no longer be a raw "
    "key array; re-audit des_shim.c to verify the raw key is still at offset 0");

/*
 * deslong_to_bytes() and bytes_to_deslong() extract bytes from DES_LONG
 * (unsigned int) using explicit shift-by-8 operations, which is only correct
 * on a little-endian architecture.  Guard against building on big-endian targets
 * where the output would be silently wrong.
 *
 * If you need big-endian support: replace the shift-based extraction with
 * portable byte-at-a-time reads (e.g., GETCHAR from a byte*) and remove
 * this guard.
 */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#  error "des_shim.c assumes little-endian byte order in deslong_to_bytes / " \
         "bytes_to_deslong — re-implement those helpers portably before " \
         "building on a big-endian target"
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/*
 * OpenSSL DES_LONG = unsigned int on all supported platforms.
 * We define it locally to avoid pulling in conflicting OpenSSL headers.
 */
typedef unsigned int DES_LONG;

/* OpenSSL enc direction constants (opposite of wolfCrypt enum) */
#define WOLF_DES_OPENSSL_ENCRYPT 1
#define WOLF_DES_OPENSSL_DECRYPT 0

/* ── helpers ──────────────────────────────────────────────────────────────── */

/* Convert DES_LONG[2] (little-endian, OpenSSL convention) → 8 raw bytes */
static void deslong_to_bytes(const DES_LONG *data, byte *out)
{
    out[0] = (byte)(data[0]      );
    out[1] = (byte)(data[0] >>  8);
    out[2] = (byte)(data[0] >> 16);
    out[3] = (byte)(data[0] >> 24);
    out[4] = (byte)(data[1]      );
    out[5] = (byte)(data[1] >>  8);
    out[6] = (byte)(data[1] >> 16);
    out[7] = (byte)(data[1] >> 24);
}

/* Convert 8 raw bytes → DES_LONG[2] (little-endian) */
static void bytes_to_deslong(const byte *in, DES_LONG *data)
{
    data[0] = (DES_LONG)in[0]
            | ((DES_LONG)in[1] <<  8)
            | ((DES_LONG)in[2] << 16)
            | ((DES_LONG)in[3] << 24);
    data[1] = (DES_LONG)in[4]
            | ((DES_LONG)in[5] <<  8)
            | ((DES_LONG)in[6] << 16)
            | ((DES_LONG)in[7] << 24);
}

/* ── DES_encrypt1 ─────────────────────────────────────────────────────────── */

/*
 * Full DES block cipher (IP + rounds + FP) via wolfCrypt single-DES.
 * ks points to OpenSSL's DES_key_schedule (128 bytes), but wolfSSL's
 * set_key wrote only the raw 8-byte key into its first 8 bytes.
 */
void DES_encrypt1(DES_LONG *data, void *ks, int enc)
{
    byte key[8], in[8], out[8];
    static const byte zero_iv[8] = {0};
    Des des;

    /*
     * WOLFSHIM_REVIEW [ABI]: reads the first 8 bytes of DES_key_schedule as the
     * raw DES key.  wolfSSL's DES_set_key_unchecked() (and _checked()) store the
     * raw 8-byte key at offset 0 of the passed DES_key_schedule buffer.
     * Validated against wolfSSL 5.9.0.  If wolfSSL changes this layout, the
     * _Static_assert above and the version guard will need updating.
     */
    memcpy(key, (const byte *)ks, 8);
    deslong_to_bytes(data, in);

    if (enc == WOLF_DES_OPENSSL_ENCRYPT) {
        if (wc_Des_SetKey(&des, key, zero_iv, DES_ENCRYPTION) != 0) {
            data[0] = 0; data[1] = 0;
            return;
        }
        if (wc_Des_CbcEncrypt(&des, out, in, 8) != 0) {
            data[0] = 0; data[1] = 0;
            return;
        }
    } else {
        if (wc_Des_SetKey(&des, key, zero_iv, DES_DECRYPTION) != 0) {
            data[0] = 0; data[1] = 0;
            return;
        }
        if (wc_Des_CbcDecrypt(&des, out, in, 8) != 0) {
            data[0] = 0; data[1] = 0;
            return;
        }
    }

    bytes_to_deslong(out, data);
}

/* ── DES_encrypt2 ─────────────────────────────────────────────────────────── */

/*
 * DES_encrypt2 exists here only to satisfy the linker.  Do not call it.
 *
 * In OpenSSL, DES_encrypt2 is a "middle-round" primitive that omits the
 * Initial Permutation (IP) and Final Permutation (FP).  It exists so that
 * DES_encrypt3/DES_decrypt3 can chain three DES passes without paying for
 * redundant IP/FP at the boundaries.
 *
 * wolfCrypt has no equivalent no-IP/FP primitive.  There is no wolfCrypt API
 * that this function can map to correctly.  Calling it will produce wrong
 * ciphertext — not an error, not a crash, just wrong output.
 *
 * This shim's DES_encrypt3 and DES_decrypt3 do NOT call DES_encrypt2; they
 * bypass it entirely by using wc_Des3 directly.  There is therefore no
 * internal path through which DES_encrypt2 can be reached and produce correct
 * output.  Any caller reaching this function is always wrong.
 *
 * The abort() below makes that explicit: if anything calls DES_encrypt2, it
 * gets a hard stop with a diagnostic rather than silently wrong ciphertext.
 * abort() is used instead of assert() because assert() is suppressed by
 * NDEBUG and this invariant must hold in production builds.
 */
#include <stdio.h>
#include <stdlib.h>
void DES_encrypt2(DES_LONG *data, void *ks, int enc)
{
    (void)data; (void)ks; (void)enc;
    fprintf(stderr,
        "[wolfshim] DES_encrypt2 called directly — this function produces "
        "wrong ciphertext in the wolfCrypt shim and must not be used.\n"
        "wolfCrypt has no no-IP/FP DES primitive; the wolfshim 3DES path "
        "(DES_encrypt3/DES_decrypt3) uses wc_Des3 directly and never reaches "
        "this function.\n");
    abort();
}

/* ── DES_encrypt3 / DES_decrypt3 ─────────────────────────────────────────── */

/*
 * 3DES EDE encrypt: E(ks1) → D(ks2) → E(ks3).
 * Uses wolfCrypt wc_Des3 with the three raw keys concatenated.
 */
void DES_encrypt3(DES_LONG *data, void *ks1, void *ks2, void *ks3)
{
    byte in[8], out[8];
    static const byte zero_iv[8] = {0};
    byte key24[24];
    Des3 des3;

    /*
     * WOLFSHIM_REVIEW [ABI]: reads the first 8 bytes of DES_key_schedule as the
     * raw DES key.  wolfSSL's DES_set_key_unchecked() (and _checked()) store the
     * raw 8-byte key at offset 0 of the passed DES_key_schedule buffer.
     * Validated against wolfSSL 5.9.0.  If wolfSSL changes this layout, the
     * _Static_assert above and the version guard will need updating.
     */
    memcpy(key24,      (const byte *)ks1, 8);
    memcpy(key24 + 8,  (const byte *)ks2, 8);
    memcpy(key24 + 16, (const byte *)ks3, 8);

    deslong_to_bytes(data, in);

    wc_Des3Init(&des3, NULL, INVALID_DEVID);
    if (wc_Des3_SetKey(&des3, key24, zero_iv, DES_ENCRYPTION) != 0) {
        wc_Des3Free(&des3);
        data[0] = 0; data[1] = 0;
        return;
    }
    if (wc_Des3_CbcEncrypt(&des3, out, in, 8) != 0) {
        wc_Des3Free(&des3);
        data[0] = 0; data[1] = 0;
        return;
    }
    wc_Des3Free(&des3);

    bytes_to_deslong(out, data);
}

/*
 * 3DES EDE decrypt: D(ks3) → E(ks2) → D(ks1).
 */
void DES_decrypt3(DES_LONG *data, void *ks1, void *ks2, void *ks3)
{
    byte in[8], out[8];
    static const byte zero_iv[8] = {0};
    byte key24[24];
    Des3 des3;

    /*
     * WOLFSHIM_REVIEW [ABI]: reads the first 8 bytes of DES_key_schedule as the
     * raw DES key.  wolfSSL's DES_set_key_unchecked() (and _checked()) store the
     * raw 8-byte key at offset 0 of the passed DES_key_schedule buffer.
     * Validated against wolfSSL 5.9.0.  If wolfSSL changes this layout, the
     * _Static_assert above and the version guard will need updating.
     */
    memcpy(key24,      (const byte *)ks1, 8);
    memcpy(key24 + 8,  (const byte *)ks2, 8);
    memcpy(key24 + 16, (const byte *)ks3, 8);

    deslong_to_bytes(data, in);

    wc_Des3Init(&des3, NULL, INVALID_DEVID);
    if (wc_Des3_SetKey(&des3, key24, zero_iv, DES_DECRYPTION) != 0) {
        wc_Des3Free(&des3);
        data[0] = 0; data[1] = 0;
        return;
    }
    if (wc_Des3_CbcDecrypt(&des3, out, in, 8) != 0) {
        wc_Des3Free(&des3);
        data[0] = 0; data[1] = 0;
        return;
    }
    wc_Des3Free(&des3);

    bytes_to_deslong(out, data);
}

/* ── DES_ecb_encrypt ─────────────────────────────────────────────────────── */

/*
 * ECB single-block DES via CBC with a zero IV (one block ⇒ IV has no
 * effect on the result).
 * input/output: pointers to 8-byte DES blocks.
 * ks: pointer to a DES_key_schedule whose first 8 bytes hold the raw key.
 */
void DES_ecb_encrypt(const unsigned char *input, unsigned char *output,
                     void *ks, int enc)
{
    byte key[8];
    static const byte zero_iv[8] = {0};
    Des des;

    /*
     * WOLFSHIM_REVIEW [ABI]: reads the first 8 bytes of DES_key_schedule as the
     * raw DES key.  wolfSSL's DES_set_key_unchecked() (and _checked()) store the
     * raw 8-byte key at offset 0 of the passed DES_key_schedule buffer.
     * Validated against wolfSSL 5.9.0.  If wolfSSL changes this layout, the
     * _Static_assert above and the version guard will need updating.
     */
    memcpy(key, (const byte *)ks, 8);

    if (enc == WOLF_DES_OPENSSL_ENCRYPT) {
        if (wc_Des_SetKey(&des, key, zero_iv, DES_ENCRYPTION) != 0) {
            memset(output, 0, 8);
            return;
        }
        if (wc_Des_CbcEncrypt(&des, output, input, 8) != 0) {
            memset(output, 0, 8);
            return;
        }
    } else {
        if (wc_Des_SetKey(&des, key, zero_iv, DES_DECRYPTION) != 0) {
            memset(output, 0, 8);
            return;
        }
        if (wc_Des_CbcDecrypt(&des, output, input, 8) != 0) {
            memset(output, 0, 8);
            return;
        }
    }
}

/* ── DES_crypt ───────────────────────────────────────────────────────────── */

/*
 * Unix crypt(3) DES wrapper.  Returns NULL for:
 *  - salt shorter than 2 characters
 *  - any salt character outside [a-zA-Z0-9./]
 */
#define _GNU_SOURCE
#include <crypt.h>

static int des_crypt_valid_salt_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '/';
}

char *DES_crypt(const char *buf, const char *salt)
{
    struct crypt_data cd = {0};

    if (!salt || !salt[0] || !salt[1])
        return NULL;
    if (!des_crypt_valid_salt_char((unsigned char)salt[0]) ||
        !des_crypt_valid_salt_char((unsigned char)salt[1]))
        return NULL;
    return crypt_r(buf, salt, &cd);
}
