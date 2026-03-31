/*
 * aes_shim.c — OpenSSL 1.1.1 AES API shim (wolfCrypt back-end)
 *
 * Implements the following OpenSSL symbols by dispatching to wolfCrypt:
 *   AES_bi_ige_encrypt
 *   AES_cfb1_encrypt
 *   AES_cfb8_encrypt
 *   AES_ecb_encrypt
 *   AES_ige_encrypt
 *   AES_ofb128_encrypt
 *   AES_options
 *   AES_unwrap_key
 *   AES_wrap_key
 *
 * Build-time feature gates used:
 *   HAVE_AES_ECB        — wc_AesEcbEncrypt / wc_AesEcbDecrypt
 *   WOLFSSL_AES_CFB     — wc_AesCfb1*, wc_AesCfb8*
 *   WOLFSSL_AES_OFB     — wc_AesOfbEncrypt / wc_AesOfbDecrypt
 *   HAVE_AES_KEYWRAP    — wc_AesKeyWrap_ex / wc_AesKeyUnWrap_ex
 *   WOLFSSL_AES_DIRECT  — wc_AesEncryptDirect (used as ECB fallback)
 *
 * wolfshim extensions (not in OpenSSL 1.1.1, see aes_shim.h and RELEASE-NOTES.md):
 *   AES_KEY_new / AES_KEY_free
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#include <stddef.h>
#include <stdlib.h>  /* abort() */
#include <string.h>
#include <strings.h>  /* explicit_bzero */

#include <stdio.h>  /* always needed for abort-path fprintf */
#ifdef WOLFSHIM_DEBUG
# include <stdatomic.h>
#endif

/* wolfCrypt headers — options.h must come first to load the build-time
 * configuration (#defines from ./configure) before any wolfCrypt struct
 * definitions are parsed.  Without it the Aes struct layout is the
 * unconfigured default, which differs from the production layout. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_AES
# error "wolfSSL must be built with AES support (no --disable-aes) to use aes_shim.c"
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>

/* wolfssl/openssl/err.h defines ERR_R_DISABLED but not ERR_LIB_EVP or
 * ERR_put_error; wolfssl/openssl/ssl.h has those but is heavyweight.
 * Use the same explicit approach as misc_stubs.c. */
#ifndef ERR_LIB_EVP
# define ERR_LIB_EVP 6
#endif
#ifndef ERR_R_FATAL
# define ERR_R_FATAL 64
#endif
#ifdef ERR_R_DISABLED
# undef ERR_R_DISABLED  /* wolfssl/wolfcrypt/error-crypt.h defines this as NOT_COMPILED_IN (-174); */
#endif                   /* we want the OpenSSL-compatible value for the error queue */
# define ERR_R_DISABLED (5 | ERR_R_FATAL)
extern void ERR_put_error(int lib, int func, int reason,
                          const char *file, int line);

/* shim AES_KEY typedef and declarations */
#include "aes_shim.h"

/* Internal helper: heap-allocated Aes* stored in the AES_KEY buffer.
 * This avoids storing Aes inline, which would require enlarging the public
 * struct aes_key_st and breaking the ABI. */
#include "aes_ctx.h"

/* Compile-time wolfSSL version guard.
 * aes_shim.c directly accesses wolfCrypt Aes struct fields (reg, left)
 * for streaming CFB/OFB mode IV state.  These were validated against
 * wolfSSL 5.9.0.  If wolfSSL restructures Aes, this guard produces a
 * build error forcing re-validation. */
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05009000
#  error "aes_shim.c requires wolfSSL >= 5.9.0; direct Aes struct field " \
         "accesses (reg, left) were validated against that version -- " \
         "review all such accesses before lowering this threshold"
#endif

/* Compile-time struct layout assertions.
 * aes_shim.c directly accesses Aes.reg and Aes.left (WOLFSHIM_REVIEW [ABI]
 * sites).  If wolfSSL restructures the Aes struct these assertions produce a
 * build error before any silent memory corruption can occur.
 * Offsets were measured against wolfSSL 5.9.0 on x86_64 with --enable-aescfb
 * --enable-aesofb --enable-aesctr in the wolfSSL build.
 * When upgrading wolfSSL: re-run the offsetof probe in the project root,
 * update the constants below, and re-audit every WOLFSHIM_REVIEW [ABI]
 * comment in this file. */
_Static_assert(offsetof(Aes, reg) == 256,
    "Aes.reg offset changed — re-audit aes_shim.c WOLFSHIM_REVIEW [ABI] sites and update this constant");
/* Aes.left exists only when streaming CFB/OFB/XTS/CTS is enabled */
#if defined(WOLFSSL_AES_CFB) || defined(WOLFSSL_AES_OFB) || \
    defined(WOLFSSL_AES_XTS) || defined(WOLFSSL_AES_CTS)
_Static_assert(offsetof(Aes, left) == 864,
    "Aes.left offset changed — re-audit aes_shim.c WOLFSHIM_REVIEW [ABI] sites and update this constant");
#endif

/* AES direction constants: OpenSSL and wolfCrypt use INVERTED values.
 * Canonical explanation lives in shim/include/wolfshim_preinclude.h —
 * see the "AES direction constant mapping" comment block there.
 * Short summary: OpenSSL AES_ENCRYPT=1/AES_DECRYPT=0; wolfCrypt is opposite.
 * Always test against the OpenSSL constants; never pass enc directly to wc_*. */
#ifndef AES_ENCRYPT
# define AES_ENCRYPT 1
#endif
#ifndef AES_DECRYPT
# define AES_DECRYPT 0
#endif

#define AES_BLOCK_SIZE 16

/*
 * The OpenSSL AES_KEY struct (struct aes_key_st, 244 bytes) is smaller than
 * wolfCrypt's Aes (~1104 bytes).  Rather than storing Aes inline (which would
 * require enlarging the public struct and breaking the ABI), we store a
 * heap-allocated Aes* in the first two pointer-slots of the AES_KEY buffer.
 * All functions retrieve the context via aes_ctx_get().
 */

/* -----------------------------------------------------------------------
 * AES_options
 * Returns a static string advertising AES support level.
 * ----------------------------------------------------------------------- */
const char *AES_options(void)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    /* wolfCrypt supports full AES (128/192/256, multiple modes). */
    return "aes(full)";
}

/* -----------------------------------------------------------------------
 * AES_ecb_encrypt
 * Encrypt or decrypt a single 16-byte block using AES-ECB.
 * ----------------------------------------------------------------------- */
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const AES_KEY *key, const int enc)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    if (in == NULL || out == NULL || key == NULL)
        return;

#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
    {
        Aes *aes = aes_ctx_get((const void *)key);
        if (!aes) {
            fprintf(stderr,
                "[wolfshim] FATAL: AES_ecb_encrypt called with uninitialised or "
                "AES_KEY has no wolfshim sentinel (aes_ctx_get returned NULL).\n"
                "  Either AES_set_encrypt_key/AES_set_decrypt_key was not called,\n"
                "  or the AES_KEY buffer was zeroed after initialization (e.g. with\n"
                "  memset/bzero instead of OPENSSL_cleanse) — in that case the\n"
                "  wolfCrypt heap context has leaked and key material may remain\n"
                "  on the heap.  Use OPENSSL_cleanse() to wipe keys.\n"
                "  Aborting: proceeding would produce silent wrong ciphertext.\n");
            abort();
        }
# if defined(HAVE_AES_ECB)
        if (enc == AES_ENCRYPT) {
            wc_AesEcbEncrypt(aes, out, in, AES_BLOCK_SIZE);
        } else {
#  ifdef HAVE_AES_DECRYPT
            wc_AesEcbDecrypt(aes, out, in, AES_BLOCK_SIZE);
#  else
            /* WOLFSHIM_GAP[UNSUPPORTED]: HAVE_AES_DECRYPT not set.
             * Abort rather than zero the output buffer.  Zeroing would be a
             * confidentiality failure: the caller gets a success-shaped result
             * (function returned, buffer filled) but the bytes are meaningless
             * — silent wrong ciphertext with no visible error signal.  An abort
             * is immediately visible in any test or crash reporting system. */
            fprintf(stderr,
                "[wolfshim] FATAL: AES_ecb_encrypt (decrypt path) called but "
                "HAVE_AES_DECRYPT is not set in this wolfSSL build.\n"
                "  Aborting rather than returning zeroed output: zeroed output\n"
                "  would be silent wrong ciphertext — a confidentiality failure\n"
                "  where the caller sees no error but receives meaningless bytes.\n"
                "  Fix: rebuild wolfSSL without --disable-aes-decrypt.\n");
            abort();
#  endif
        }
# else /* WOLFSSL_AES_DIRECT fallback */
        /* Fallback: use direct single-block encrypt/decrypt. */
        if (enc == AES_ENCRYPT) {
            wc_AesEncryptDirect(aes, out, in);
        } else {
            wc_AesDecryptDirect(aes, out, in);
        }
# endif
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: Neither HAVE_AES_ECB nor WOLFSSL_AES_DIRECT is
     * enabled.  Abort rather than zero the output buffer.  Zeroing would be a
     * confidentiality failure: the caller gets a success-shaped result
     * (function returned, buffer filled) but the bytes are meaningless
     * — silent wrong ciphertext with no visible error signal.  An abort
     * is immediately visible in any test or crash reporting system. */
    (void)key; (void)enc;
    fprintf(stderr,
        "[wolfshim] FATAL: AES_ecb_encrypt called but neither HAVE_AES_ECB nor "
        "WOLFSSL_AES_DIRECT is set in this wolfSSL build.\n"
        "  Aborting rather than returning zeroed output: zeroed output\n"
        "  would be silent wrong ciphertext — a confidentiality failure\n"
        "  where the caller sees no error but receives meaningless bytes.\n"
        "  Fix: rebuild wolfSSL with --enable-aesecb or CFLAGS=-DWOLFSSL_AES_DIRECT.\n");
    abort();
#endif
}

/* -----------------------------------------------------------------------
 * AES_cfb1_encrypt
 * Encrypt/decrypt using 1-bit CFB mode.
 * length is the number of *bits* to process.
 * ----------------------------------------------------------------------- */
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    if (in == NULL || out == NULL || key == NULL || ivec == NULL)
        return;

#ifdef WOLFSSL_AES_CFB
    {
        /*
         * WOLFSHIM_GAP[CORRECTNESS]: aes->reg and aes->left are internal wolfCrypt Aes
         * struct fields.  wolfSSL does not expose a public API to read/write
         * per-call IV state for streaming CFB/OFB modes, so direct field
         * access is necessary here.  This is intentional; revisit if wolfCrypt
         * adds wc_AesGetIV() or equivalent.
         */
        Aes *aes = aes_ctx_get((const void *)key);
        if (!aes) {
            fprintf(stderr,
                "[wolfshim] FATAL: AES_cfb1_encrypt called with uninitialised or "
                "AES_KEY has no wolfshim sentinel (aes_ctx_get returned NULL).\n"
                "  Either AES_set_encrypt_key/AES_set_decrypt_key was not called,\n"
                "  or the AES_KEY buffer was zeroed after initialization (e.g. with\n"
                "  memset/bzero instead of OPENSSL_cleanse) — in that case the\n"
                "  wolfCrypt heap context has leaked and key material may remain\n"
                "  on the heap.  Use OPENSSL_cleanse() to wipe keys.\n"
                "  Aborting: proceeding would produce silent wrong ciphertext.\n");
            abort();
        }
        XMEMCPY(aes->reg, ivec, AES_BLOCK_SIZE);

        /* Guard against size_t -> word32 truncation.
         * Abort rather than zero the output buffer.  Zeroing would be a
         * confidentiality failure: the caller gets a success-shaped result
         * (function returned, buffer filled) but the bytes are meaningless
         * — silent wrong ciphertext with no visible error signal.  An abort
         * is immediately visible in any test or crash reporting system. */
        if (length > (word32)-1) {
            fprintf(stderr,
                "[wolfshim] FATAL: AES_cfb1_encrypt: length %zu exceeds word32 max "
                "— cannot pass to wc_AesCfb1Encrypt/Decrypt.\n"
                "  Aborting rather than returning zeroed output: zeroed output\n"
                "  would be silent wrong ciphertext — a confidentiality failure\n"
                "  where the caller sees no error but receives meaningless bytes.\n",
                length);
            abort();
        }
        /* length is in bits for CFB1 */
        if (enc == AES_ENCRYPT) {
            wc_AesCfb1Encrypt(aes, out, in, (word32)length);
        } else {
# ifdef HAVE_AES_DECRYPT
            wc_AesCfb1Decrypt(aes, out, in, (word32)length);
# else
            /* WOLFSHIM_GAP[UNSUPPORTED]: HAVE_AES_DECRYPT not set.
             * Abort rather than zero the output buffer.  Zeroing would be a
             * confidentiality failure: the caller gets a success-shaped result
             * (function returned, buffer filled) but the bytes are meaningless
             * — silent wrong ciphertext with no visible error signal.  An abort
             * is immediately visible in any test or crash reporting system. */
            fprintf(stderr,
                "[wolfshim] FATAL: AES_cfb1_encrypt (decrypt path) called but "
                "HAVE_AES_DECRYPT is not set in this wolfSSL build.\n"
                "  Aborting rather than returning zeroed output: zeroed output\n"
                "  would be silent wrong ciphertext — a confidentiality failure\n"
                "  where the caller sees no error but receives meaningless bytes.\n"
                "  Fix: rebuild wolfSSL without --disable-aes-decrypt.\n");
            abort();
# endif
        }
        XMEMCPY(ivec, (byte *)(aes->reg), AES_BLOCK_SIZE);
        if (num != NULL)
            /* wolfSSL AES-CFB exposes no public API to read partial-block
             * state after a wc_AesCfb1Encrypt/Decrypt call.  We derive it
             * from the internal aes->left field (bytes remaining in the
             * current keystream block) to match OpenSSL's streaming
             * semantics: *num is the byte offset within the 16-byte IV
             * block at which the next call should resume.  This is why
             * aes->left is accessed directly (WOLFSHIM_REVIEW [ABI] above).
             * Do NOT remove this update — callers that split plaintext
             * across multiple calls rely on *num being correct. */
            *num = (AES_BLOCK_SIZE - (int)aes->left) % AES_BLOCK_SIZE;
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: WOLFSSL_AES_CFB not enabled.
     * Abort rather than zero the output buffer.  Zeroing would be a
     * confidentiality failure: the caller gets a success-shaped result
     * (function returned, buffer filled) but the bytes are meaningless
     * — silent wrong ciphertext with no visible error signal.  An abort
     * is immediately visible in any test or crash reporting system. */
    (void)length; (void)key; (void)ivec; (void)num; (void)enc;
    fprintf(stderr,
        "[wolfshim] FATAL: AES_cfb1_encrypt called but WOLFSSL_AES_CFB is not "
        "set in this wolfSSL build.\n"
        "  Aborting rather than returning zeroed output: zeroed output\n"
        "  would be silent wrong ciphertext — a confidentiality failure\n"
        "  where the caller sees no error but receives meaningless bytes.\n"
        "  Fix: rebuild wolfSSL with --enable-aescfb.\n");
    abort();
#endif
}

/* -----------------------------------------------------------------------
 * AES_cfb8_encrypt
 * Encrypt/decrypt using 8-bit CFB mode.
 * length is the number of *bytes* to process.
 * ----------------------------------------------------------------------- */
void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    if (in == NULL || out == NULL || key == NULL || ivec == NULL)
        return;

#ifdef WOLFSSL_AES_CFB
    {
        /*
         * WOLFSHIM_GAP[CORRECTNESS]: aes->reg and aes->left are internal wolfCrypt Aes
         * struct fields.  wolfSSL does not expose a public API to read/write
         * per-call IV state for streaming CFB/OFB modes, so direct field
         * access is necessary here.  This is intentional; revisit if wolfCrypt
         * adds wc_AesGetIV() or equivalent.
         */
        Aes *aes = aes_ctx_get((const void *)key);
        if (!aes) {
            fprintf(stderr,
                "[wolfshim] FATAL: AES_cfb8_encrypt called with uninitialised or "
                "AES_KEY has no wolfshim sentinel (aes_ctx_get returned NULL).\n"
                "  Either AES_set_encrypt_key/AES_set_decrypt_key was not called,\n"
                "  or the AES_KEY buffer was zeroed after initialization (e.g. with\n"
                "  memset/bzero instead of OPENSSL_cleanse) — in that case the\n"
                "  wolfCrypt heap context has leaked and key material may remain\n"
                "  on the heap.  Use OPENSSL_cleanse() to wipe keys.\n"
                "  Aborting: proceeding would produce silent wrong ciphertext.\n");
            abort();
        }
        XMEMCPY(aes->reg, ivec, AES_BLOCK_SIZE);

        /* Guard against size_t -> word32 truncation.
         * Abort rather than zero the output buffer.  Zeroing would be a
         * confidentiality failure: the caller gets a success-shaped result
         * (function returned, buffer filled) but the bytes are meaningless
         * — silent wrong ciphertext with no visible error signal.  An abort
         * is immediately visible in any test or crash reporting system. */
        if (length > (word32)-1) {
            fprintf(stderr,
                "[wolfshim] FATAL: AES_cfb8_encrypt: length %zu exceeds word32 max "
                "— cannot pass to wc_AesCfb8Encrypt/Decrypt.\n"
                "  Aborting rather than returning zeroed output: zeroed output\n"
                "  would be silent wrong ciphertext — a confidentiality failure\n"
                "  where the caller sees no error but receives meaningless bytes.\n",
                length);
            abort();
        }
        if (enc == AES_ENCRYPT) {
            wc_AesCfb8Encrypt(aes, out, in, (word32)length);
        } else {
# ifdef HAVE_AES_DECRYPT
            wc_AesCfb8Decrypt(aes, out, in, (word32)length);
# else
            /* WOLFSHIM_GAP[UNSUPPORTED]: HAVE_AES_DECRYPT not set.
             * Abort rather than zero the output buffer.  Zeroing would be a
             * confidentiality failure: the caller gets a success-shaped result
             * (function returned, buffer filled) but the bytes are meaningless
             * — silent wrong ciphertext with no visible error signal.  An abort
             * is immediately visible in any test or crash reporting system. */
            fprintf(stderr,
                "[wolfshim] FATAL: AES_cfb8_encrypt (decrypt path) called but "
                "HAVE_AES_DECRYPT is not set in this wolfSSL build.\n"
                "  Aborting rather than returning zeroed output: zeroed output\n"
                "  would be silent wrong ciphertext — a confidentiality failure\n"
                "  where the caller sees no error but receives meaningless bytes.\n"
                "  Fix: rebuild wolfSSL without --disable-aes-decrypt.\n");
            abort();
# endif
        }
        XMEMCPY(ivec, (byte *)(aes->reg), AES_BLOCK_SIZE);
        if (num != NULL)
            /* wolfSSL AES-CFB exposes no public API to read partial-block
             * state after a wc_AesCfb8Encrypt/Decrypt call.  We derive it
             * from the internal aes->left field to match OpenSSL's streaming
             * semantics: *num is the byte offset within the 16-byte IV block
             * at which the next call should resume.  Do NOT remove this
             * update — callers that split plaintext across multiple calls
             * rely on *num being correct. */
            *num = (AES_BLOCK_SIZE - (int)aes->left) % AES_BLOCK_SIZE;
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: WOLFSSL_AES_CFB not enabled.
     * Abort rather than zero the output buffer.  Zeroing would be a
     * confidentiality failure: the caller gets a success-shaped result
     * (function returned, buffer filled) but the bytes are meaningless
     * — silent wrong ciphertext with no visible error signal.  An abort
     * is immediately visible in any test or crash reporting system. */
    (void)length; (void)key; (void)ivec; (void)num; (void)enc;
    fprintf(stderr,
        "[wolfshim] FATAL: AES_cfb8_encrypt called but WOLFSSL_AES_CFB is not "
        "set in this wolfSSL build.\n"
        "  Aborting rather than returning zeroed output: zeroed output\n"
        "  would be silent wrong ciphertext — a confidentiality failure\n"
        "  where the caller sees no error but receives meaningless bytes.\n"
        "  Fix: rebuild wolfSSL with --enable-aescfb.\n");
    abort();
#endif
}

/* -----------------------------------------------------------------------
 * AES_ofb128_encrypt
 * Encrypt/decrypt using OFB (Output Feedback) 128-bit mode.
 * Note: OFB is symmetric — the same function encrypts and decrypts.
 * ----------------------------------------------------------------------- */
void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        unsigned char *ivec, int *num)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    if (in == NULL || out == NULL || key == NULL || ivec == NULL)
        return;

#ifdef WOLFSSL_AES_OFB
    {
        /*
         * WOLFSHIM_GAP[CORRECTNESS]: aes->reg and aes->left are internal wolfCrypt Aes
         * struct fields.  wolfSSL does not expose a public API to read/write
         * per-call IV state for streaming CFB/OFB modes, so direct field
         * access is necessary here.  This is intentional; revisit if wolfCrypt
         * adds wc_AesGetIV() or equivalent.
         */
        Aes *aes = aes_ctx_get((const void *)key);
        if (!aes) {
            fprintf(stderr,
                "[wolfshim] FATAL: AES_ofb128_encrypt called with uninitialised or "
                "AES_KEY has no wolfshim sentinel (aes_ctx_get returned NULL).\n"
                "  Either AES_set_encrypt_key/AES_set_decrypt_key was not called,\n"
                "  or the AES_KEY buffer was zeroed after initialization (e.g. with\n"
                "  memset/bzero instead of OPENSSL_cleanse) — in that case the\n"
                "  wolfCrypt heap context has leaked and key material may remain\n"
                "  on the heap.  Use OPENSSL_cleanse() to wipe keys.\n"
                "  Aborting: proceeding would produce silent wrong ciphertext.\n");
            abort();
        }
        XMEMCPY(aes->reg, ivec, AES_BLOCK_SIZE);
        /* Guard against size_t -> word32 truncation.
         * Abort rather than zero the output buffer — same policy as CFB. */
        if (length > (word32)-1) {
            fprintf(stderr,
                "[wolfshim] FATAL: AES_ofb128_encrypt: length %zu exceeds word32 max "
                "— cannot pass to wc_AesOfbEncrypt.\n"
                "  Aborting rather than returning zeroed output: zeroed output\n"
                "  would be silent wrong ciphertext — a confidentiality failure\n"
                "  where the caller sees no error but receives meaningless bytes.\n",
                length);
            abort();
        }
        /* OFB encrypt and decrypt are identical operations */
        wc_AesOfbEncrypt(aes, out, in, (word32)length);
        XMEMCPY(ivec, (byte *)(aes->reg), AES_BLOCK_SIZE);
        if (num != NULL)
            /* wolfSSL AES-OFB exposes no public API to read partial-block
             * state after wc_AesOfbEncrypt.  We derive *num from aes->left
             * for the same reason as the CFB variants above: OpenSSL's
             * streaming semantics require *num to carry the byte offset
             * within the current keystream block across calls.  Do NOT
             * remove this update. */
            *num = (AES_BLOCK_SIZE - (int)aes->left) % AES_BLOCK_SIZE;
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: WOLFSSL_AES_OFB not enabled.
     * Abort rather than zero the output buffer.  Zeroing would be a
     * confidentiality failure: the caller gets a success-shaped result
     * (function returned, buffer filled) but the bytes are meaningless
     * — silent wrong ciphertext with no visible error signal.  An abort
     * is immediately visible in any test or crash reporting system. */
    (void)length; (void)key; (void)ivec; (void)num;
    fprintf(stderr,
        "[wolfshim] FATAL: AES_ofb128_encrypt called but WOLFSSL_AES_OFB is not "
        "set in this wolfSSL build.\n"
        "  Aborting rather than returning zeroed output: zeroed output\n"
        "  would be silent wrong ciphertext — a confidentiality failure\n"
        "  where the caller sees no error but receives meaningless bytes.\n"
        "  Fix: rebuild wolfSSL with --enable-aesofb.\n");
    abort();
#endif
}

/* -----------------------------------------------------------------------
 * AES_ige_encrypt
 * Infinite Garble Extension (IGE) mode.
 * IV is _two_ blocks (32 bytes): first block is IV for forward direction,
 * second block is the IV for the feedback path.
 *
 * wolfCrypt does not implement IGE natively.  The algorithm is implemented
 * here manually using the AES direct (single-block) primitive.
 *
 * WOLFSHIM_GAP[CORRECTNESS]: This is a hand-rolled IGE implementation using
 * wc_AesEncryptDirect / wc_AesDecryptDirect.  It requires WOLFSSL_AES_DIRECT
 * to be enabled.  If that flag is absent the function is a no-op stub.
 * ----------------------------------------------------------------------- */
void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    if (in == NULL || out == NULL || key == NULL || ivec == NULL)
        return;
    if (length == 0 || (length % AES_BLOCK_SIZE) != 0)
        return;

#ifdef WOLFSSL_AES_DIRECT
    {
        /*
         * Copy the Aes context into a local variable so the loop below can
         * mutate IV state without disturbing the caller's stored key.
         */
        Aes *aes_ptr = aes_ctx_get((const void *)key);
        if (!aes_ptr) {
            fprintf(stderr,
                "[wolfshim] FATAL: AES_ige_encrypt called with uninitialised or "
                "AES_KEY has no wolfshim sentinel (aes_ctx_get returned NULL).\n"
                "  Either AES_set_encrypt_key/AES_set_decrypt_key was not called,\n"
                "  or the AES_KEY buffer was zeroed after initialization (e.g. with\n"
                "  memset/bzero instead of OPENSSL_cleanse) — in that case the\n"
                "  wolfCrypt heap context has leaked and key material may remain\n"
                "  on the heap.  Use OPENSSL_cleanse() to wipe keys.\n"
                "  Aborting: proceeding would produce silent wrong ciphertext.\n");
            abort();
        }
        Aes aes_local;
        XMEMCPY(&aes_local, aes_ptr, sizeof(Aes));
        Aes *aes = &aes_local;
        const unsigned char *iv1 = ivec;                  /* forward IV */
        const unsigned char *iv2 = ivec + AES_BLOCK_SIZE; /* feedback IV */
        unsigned char tmp[AES_BLOCK_SIZE];
        unsigned char prev_out[AES_BLOCK_SIZE];
        unsigned char cur_iv1[AES_BLOCK_SIZE];
        unsigned char cur_iv2[AES_BLOCK_SIZE];
        size_t i, j;

        memcpy(cur_iv1, iv1, AES_BLOCK_SIZE);
        memcpy(cur_iv2, iv2, AES_BLOCK_SIZE);

        if (enc == AES_ENCRYPT) {
            for (j = 0; j < length; j += AES_BLOCK_SIZE) {
                /* tmp = in_block XOR iv1 */
                for (i = 0; i < AES_BLOCK_SIZE; i++)
                    tmp[i] = in[j + i] ^ cur_iv1[i];
                /* out_block = AES_enc(tmp) XOR iv2 */
                wc_AesEncryptDirect(aes, prev_out, tmp);
                for (i = 0; i < AES_BLOCK_SIZE; i++)
                    out[j + i] = prev_out[i] ^ cur_iv2[i];
                /* update IVs */
                memcpy(cur_iv1, out + j,  AES_BLOCK_SIZE); /* next iv1 = out */
                memcpy(cur_iv2, in  + j,  AES_BLOCK_SIZE); /* next iv2 = in  */
            }
            /* Write updated IVs back */
            memcpy(ivec,                  cur_iv1, AES_BLOCK_SIZE);
            memcpy(ivec + AES_BLOCK_SIZE, cur_iv2, AES_BLOCK_SIZE);
        } else {

            for (j = 0; j < length; j += AES_BLOCK_SIZE) {
                /* tmp = in_block XOR iv2 */
                for (i = 0; i < AES_BLOCK_SIZE; i++)
                    tmp[i] = in[j + i] ^ cur_iv2[i];
                /* out_block = AES_dec(tmp) XOR iv1 */
                wc_AesDecryptDirect(aes, prev_out, tmp);
                for (i = 0; i < AES_BLOCK_SIZE; i++)
                    out[j + i] = prev_out[i] ^ cur_iv1[i];
                /* update IVs */
                memcpy(cur_iv1, in  + j, AES_BLOCK_SIZE); /* next iv1 = in  */
                memcpy(cur_iv2, out + j, AES_BLOCK_SIZE); /* next iv2 = out */
            }
            memcpy(ivec,                  cur_iv1, AES_BLOCK_SIZE);
            memcpy(ivec + AES_BLOCK_SIZE, cur_iv2, AES_BLOCK_SIZE);
        }
        /* Scrub temporaries — explicit_bzero prevents the compiler from
         * eliding these as dead stores before the variables go out of scope. */
        explicit_bzero(tmp,      AES_BLOCK_SIZE);
        explicit_bzero(prev_out, AES_BLOCK_SIZE);
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: WOLFSSL_AES_DIRECT not enabled.
     * Abort rather than zero the output buffer.  Zeroing would be a
     * confidentiality failure: the caller gets a success-shaped result
     * (function returned, buffer filled) but the bytes are meaningless
     * — silent wrong ciphertext with no visible error signal.  An abort
     * is immediately visible in any test or crash reporting system. */
    (void)enc;
    fprintf(stderr,
        "[wolfshim] FATAL: AES_ige_encrypt called but WOLFSSL_AES_DIRECT is not "
        "set in this wolfSSL build.\n"
        "  Aborting rather than returning zeroed output: zeroed output\n"
        "  would be silent wrong ciphertext — a confidentiality failure\n"
        "  where the caller sees no error but receives meaningless bytes.\n"
        "  Fix: rebuild wolfSSL with CFLAGS=-DWOLFSSL_AES_DIRECT.\n");
    abort();
#endif
}

/* -----------------------------------------------------------------------
 * AES_bi_ige_encrypt
 * Bi-directional Infinite Garble Extension mode.
 * IV is _four_ blocks (64 bytes).
 * Uses two AES keys: key (forward) and key2 (backward).
 *
 * WOLFSHIM_GAP[CORRECTNESS]: Bi-directional IGE is very rarely used and is not
 * implemented in wolfCrypt.  This implementation performs two IGE passes
 * (forward then backward for encrypt, backward then forward for decrypt)
 * using the hand-rolled IGE logic above via the AES_DIRECT primitive.
 * If WOLFSSL_AES_DIRECT is absent the function is a no-op stub.
 * ----------------------------------------------------------------------- */
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        const AES_KEY *key2, const unsigned char *ivec,
                        const int enc)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    if (in == NULL || out == NULL || key == NULL || key2 == NULL || ivec == NULL)
        return;
    if (length == 0 || (length % AES_BLOCK_SIZE) != 0)
        return;

#ifdef WOLFSSL_AES_DIRECT
    {
        /*
         * Bi-IGE: encrypt = IGE_enc(key, iv[0..1], IGE_enc(key2, iv[2..3], in))
         *         decrypt = IGE_dec(key2, iv[2..3], IGE_dec(key, iv[0..1], in))
         *
         * We use a temporary buffer for the intermediate pass.
         * iv[0] and iv[1] are used by key, iv[2] and iv[3] by key2.
         */
        unsigned char *tmp = (unsigned char *)XMALLOC(length, NULL,
                                                      DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL)
            return;

        if (enc == AES_ENCRYPT) {
            /* First pass: IGE with key2 using iv[2..3] */
            unsigned char iv_copy1[AES_BLOCK_SIZE * 2];
            unsigned char iv_copy2[AES_BLOCK_SIZE * 2];
            memcpy(iv_copy1, ivec + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE * 2);
            memcpy(iv_copy2, ivec,                       AES_BLOCK_SIZE * 2);

            AES_ige_encrypt(in, tmp, length, key2, iv_copy1, AES_ENCRYPT);
            /* Second pass: IGE with key using iv[0..1] */
            AES_ige_encrypt(tmp, out, length, key, iv_copy2, AES_ENCRYPT);
        } else {
            unsigned char iv_copy1[AES_BLOCK_SIZE * 2];
            unsigned char iv_copy2[AES_BLOCK_SIZE * 2];
            memcpy(iv_copy1, ivec,                       AES_BLOCK_SIZE * 2);
            memcpy(iv_copy2, ivec + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE * 2);

            AES_ige_encrypt(in,  tmp, length, key,  iv_copy1, AES_DECRYPT);
            AES_ige_encrypt(tmp, out, length, key2, iv_copy2, AES_DECRYPT);
        }

        explicit_bzero(tmp, length);
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: WOLFSSL_AES_DIRECT not enabled.
     * Abort rather than zero the output buffer.  Zeroing would be a
     * confidentiality failure: the caller gets a success-shaped result
     * (function returned, buffer filled) but the bytes are meaningless
     * — silent wrong ciphertext with no visible error signal.  An abort
     * is immediately visible in any test or crash reporting system. */
    (void)enc;
    fprintf(stderr,
        "[wolfshim] FATAL: AES_bi_ige_encrypt called but WOLFSSL_AES_DIRECT is not "
        "set in this wolfSSL build.\n"
        "  Aborting rather than returning zeroed output: zeroed output\n"
        "  would be silent wrong ciphertext — a confidentiality failure\n"
        "  where the caller sees no error but receives meaningless bytes.\n"
        "  Fix: rebuild wolfSSL with CFLAGS=-DWOLFSSL_AES_DIRECT.\n");
    abort();
#endif
}

/* -----------------------------------------------------------------------
 * AES_wrap_key
 * RFC 3394 AES key wrap.
 * Returns the number of bytes written to out (inlen + 8) on success,
 * or -1 on error (matching OpenSSL behaviour).
 * ----------------------------------------------------------------------- */
int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
                 unsigned char *out,
                 const unsigned char *in, unsigned int inlen)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    if (key == NULL || out == NULL || in == NULL)
        return -1;

#if defined(HAVE_AES_KEYWRAP) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    {
        int ret;
        unsigned int outSz = inlen + 8; /* RFC 3394: output is input + 8 bytes */
        Aes *aes = aes_ctx_get((const void *)key);
        if (!aes) return -1;

        ret = wc_AesKeyWrap_ex(aes,
                               in,  (word32)inlen,
                               out, (word32)outSz,
                               iv);
        return (ret > 0) ? ret : -1;
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: HAVE_AES_KEYWRAP is not enabled (or FIPS/SELFTEST is
     * active and the _ex variant is unavailable).  We only have the expanded
     * key schedule, not the raw key bytes that wc_AesKeyWrap requires.
     * Callers using ERR_get_error() will see ERR_R_DISABLED. */
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] KNOWN_GAP %s: HAVE_AES_KEYWRAP not set (or FIPS/SELFTEST active), key wrap unavailable\n", __func__);
#endif
    (void)key;
    (void)iv;
    (void)inlen;
    return -1;
#endif
}

/* -----------------------------------------------------------------------
 * AES context allocation counter — diagnostic only (WOLFSHIM_DEBUG builds).
 *
 * Defined here because aes_shim.c owns the AES_KEY_new / AES_KEY_free
 * extensions and is the canonical home for AES heap lifecycle logic.
 * aliases.c (which contains AES_set_encrypt_key / AES_set_decrypt_key) calls
 * wolfshim_aes_alloc_count_inc() — a thin non-static helper — so the counter
 * stays in one TU while the increment can happen across TU boundaries.
 *
 * wolfshim_aes_ctx_alloc_count() is declared in aes_shim.h.
 * ----------------------------------------------------------------------- */
#ifdef WOLFSHIM_DEBUG
static _Atomic long s_aes_alloc_count = 0;
long wolfshim_aes_ctx_alloc_count(void) { return s_aes_alloc_count; }
void wolfshim_aes_alloc_count_inc(void) { atomic_fetch_add(&s_aes_alloc_count, 1); }
#endif

/* -----------------------------------------------------------------------
 * AES_KEY_new / AES_KEY_free — wolfshim extensions (not in OpenSSL 1.1.1)
 *
 * See aes_shim.h §"wolfshim extension: AES_KEY_new / AES_KEY_free" and
 * shim/RELEASE-NOTES.md §"wolfshim extensions" for full rationale.
 *
 * AES_KEY_new  — allocate and zero a heap AES_KEY; the inner wolfCrypt Aes
 *                context is allocated lazily on the first AES_set_*_key call.
 * AES_KEY_free — call aes_ctx_free (frees + zeros the inner wolfCrypt Aes,
 *                clears both pointer slots), then free the outer struct.
 *                Safe to call with NULL (no-op).
 * ----------------------------------------------------------------------- */
AES_KEY *AES_KEY_new(void)
{
    /* calloc rather than XMALLOC: the outer AES_KEY struct is a public OpenSSL
     * concept, not a wolfCrypt internal.  Using libc calloc keeps it out of the
     * wolfCrypt allocator, consistent with SHA*_CTX_new and with how OpenSSL
     * itself allocates public structs.  The inner wolfCrypt Aes context (alloc'd
     * later by AES_set_*_key via aes_ctx_alloc) correctly uses XMALLOC. */
    return (AES_KEY *)calloc(1, sizeof(AES_KEY));
}

void AES_KEY_free(AES_KEY *key)
{
    if (!key)
        return;
    aes_ctx_free(key);  /* frees inner wolfCrypt Aes and zeros both pointer slots */
    free(key);          /* frees outer AES_KEY struct (paired with calloc in AES_KEY_new) */
}

/* -----------------------------------------------------------------------
 * AES_unwrap_key
 * RFC 3394 AES key unwrap.
 * Returns the number of bytes written to out (inlen - 8) on success,
 * or -1 on error.
 * ----------------------------------------------------------------------- */
int AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
                   unsigned char *out,
                   const unsigned char *in, unsigned int inlen)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] aes: %s called\n", __func__);
#endif
    if (key == NULL || out == NULL || in == NULL)
        return -1;
    if (inlen < 16)
        return -1;

#if defined(HAVE_AES_KEYWRAP) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    {
        int ret;
        unsigned int outSz = inlen - 8;
        Aes *aes = aes_ctx_get((const void *)key);
        if (!aes) return -1;

        ret = wc_AesKeyUnWrap_ex(aes,
                                 in,  (word32)inlen,
                                 out, (word32)outSz,
                                 iv);
        return (ret > 0) ? ret : -1;
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: HAVE_AES_KEYWRAP is not enabled (or FIPS/SELFTEST is
     * active).  Cannot unwrap without the raw key bytes.
     * Callers using ERR_get_error() will see ERR_R_DISABLED. */
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] KNOWN_GAP %s: HAVE_AES_KEYWRAP not set (or FIPS/SELFTEST active), key unwrap unavailable\n", __func__);
#endif
    (void)key;
    (void)iv;
    (void)inlen;
    return -1;
#endif
}
