/*
 * aliases.c — Thin wrapper functions creating ELF symbols for OpenSSL names
 *
 * wolfSSL exports wolfSSL_FOO but callers reference FOO.  wolfSSL's preprocessor
 * macros (#define FOO wolfSSL_FOO) work at compile time but do NOT create ELF
 * symbols.  This file provides real function bodies for each alias so the
 * linker can resolve them.
 *
 * Strategy:
 *   1. Include wolfSSL headers WITHOUT OPENSSL_COEXIST to get the full typedef
 *      definitions (AES_KEY, DH, DSA, EC_KEY, etc.) and wolfSSL_* prototypes.
 *   2. After all headers are included, undef the specific macros that would
 *      rename our function definitions (e.g. #define AES_cbc_encrypt wolfSSL_...).
 *   3. Define thin wrapper functions that call wolfSSL_*.
 *
 * This file is manually maintained.  There is no generator to re-run.
 * (Historical note: thin DES/MD5/RC4/RAND stubs were scaffolded by a
 * one-shot script on 2026-03-27; all non-trivial logic was written by hand
 * and the script no longer applies.)
 *
 * When adding a new wolfSSL macro alias: add the #undef in the block below,
 * write the wrapper function, and update DEV_HISTORY.md §aliases.
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>   /* abort() */
#include <string.h>
#include <strings.h>  /* explicit_bzero */
#include <limits.h>

#ifdef WOLFSHIM_DEBUG
# define WOLFSHIM_LOG(name) fprintf(stderr, "[wolfshim] alias: %s called\n", name)
#else
# define WOLFSHIM_LOG(name) ((void)0)
#endif

/* wolfSSL options must come first to enable all configured features
 * (OPENSSL_EXTRA, WOLFSSL_SHA224, WOLFSSL_SHA384, WOLFSSL_SHA512, etc.) */
#include <wolfssl/options.h>
/* Pull in wolfSSL settings (defines OPENSSL_EXTRA, etc.) */
#include <wolfssl/wolfcrypt/settings.h>

/* Include ALL wolfSSL OpenSSL-compat headers WITHOUT OPENSSL_COEXIST.
 * This gives us the typedef aliases (AES_KEY, DH, DSA, EC_KEY, etc.)
 * AND the #define macros (AES_cbc_encrypt -> wolfSSL_AES_cbc_encrypt).
 * We will undef the macros we need to shadow right before each function. */
#include <wolfssl/openssl/aes.h>
/* wolfCrypt native AES API — used directly to avoid wolfSSL compat layer bugs */
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/types.h>
/* Internal helper: heap-allocated Aes* pointer stored in the AES_KEY buffer */
#include "aes_ctx.h"
/* wolfshim AES extension declarations (AES_KEY_new/free, alloc counter).
 * Must follow wolfssl/openssl/aes.h so WOLFSSL_AES_H_ is set before
 * aes_shim.h's AES_KEY typedef guard fires — otherwise the two typedefs
 * for AES_KEY conflict.  Provides wolfshim_aes_alloc_count_inc() prototype
 * under WOLFSHIM_DEBUG so the compiler catches signature drift vs. aes_shim.c. */
#include "aes_shim.h"
/* Internal helper: heap-allocated wolfSSL SHA context stored in SHA_CTX buffers.
 * Must follow wolfssl/openssl/aes.h (which pulls in sha.h transitively via
 * wolfssl/openssl/hmac.h / ssl.h) so WOLFSSL_SHA*_CTX types are defined. */
#include <wolfssl/openssl/sha.h>
#include "sha_ctx.h"
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/openssl/des.h>
#include <wolfssl/openssl/dh.h>
#include <wolfssl/openssl/dsa.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdsa.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/openssl/md5.h>
#include <wolfssl/openssl/rc4.h>
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/openssl/asn1.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/ecdh.h>
/* wolfSSL OpenSSL SSL compat header — provides ERR_put_error and ERR_LIB_EVP
 * (defined in ssl.h as wolfSSL_ERR_put_error / WOLFSSL_ERR_LIB_EVP).
 * Not pulled in transitively by evp.h or aes.h, so included explicitly. */
#include <wolfssl/openssl/ssl.h>

/*
 * Now undef all the macros that wolfSSL defined to redirect function calls.
 * This allows us to define our own function with the OpenSSL name that calls
 * wolfSSL_* — without the macro redirecting our definition itself.
 */

/* AES */
#undef AES_set_encrypt_key
#undef AES_set_decrypt_key
#undef AES_cbc_encrypt
#undef AES_encrypt
#undef AES_decrypt
#undef AES_ecb_encrypt
#undef AES_cfb128_encrypt
#undef AES_wrap_key
#undef AES_unwrap_key

/* DES */
#undef DES_set_odd_parity
#undef DES_set_key_unchecked
#undef DES_ncbc_encrypt
#undef DES_ede3_cbc_encrypt
#undef DES_set_key
#undef DES_set_key_checked
#undef DES_key_sched
#undef DES_cbc_cksum
#undef DES_cbc_encrypt

/* MD5 */
#undef MD5_Init
#undef MD5_Update
#undef MD5_Final
#undef MD5_Transform
#undef MD5

/* RC4 */
#undef RC4_set_key
#undef RC4

/* RAND */
#undef RAND_load_file
#undef RAND_write_file

/* Memory utilities */
#undef OPENSSL_cleanse

/* ==========================================================================
 * AES aliases
 * ========================================================================== */

/* Aes.reg is accessed directly in AES_cbc_encrypt to copy back the updated IV.
 * This offset was validated against wolfSSL 5.9.0.  If the Aes struct changes,
 * the version guard in aes_shim.c will fire — but aliases.c is compiled
 * separately, so it needs its own guard. */
_Static_assert(offsetof(Aes, reg) == 256,
    "Aes.reg offset changed — re-audit aliases.c AES_cbc_encrypt iv-update "
    "(XMEMCPY(ivec, (byte *)aes->reg, WC_AES_BLOCK_SIZE)) and update constant");

/*
 * AES direction constants: OpenSSL and wolfCrypt use INVERTED values.
 * Canonical explanation lives in shim/include/wolfshim_preinclude.h —
 * see the "AES direction constant mapping" comment block there.
 * Short summary: OpenSSL AES_ENCRYPT=1/AES_DECRYPT=0; wolfCrypt is opposite.
 * Always test against the OpenSSL constants; never pass enc directly to wc_*.
 */
#undef AES_ENCRYPT
#undef AES_DECRYPT
#define AES_ENCRYPT 1
#define AES_DECRYPT 0

/*
 * AES aliases use wolfCrypt native API directly (wc_AesInit / wc_AesSetKey /
 * wc_AesCbcEncrypt etc.) rather than the wolfSSL OpenSSL-compat layer.
 *
 * Reason: wolfSSL_AES_set_encrypt_key() calls wolfssl_aes_set_key() which
 * does XMEMSET(aes, 0, sizeof(WOLFSSL_AES_KEY)) — that only zeros the
 * header-visible 896 bytes.  The runtime Aes struct (inside the wolfSSL
 * shared library) may be larger (AES_CTR / CFB / GCM overhead).  Calling
 * wc_AesInit() directly lets wolfCrypt zero sizeof(Aes) as it knows it,
 * producing a correctly initialised context and correct ciphertext.
 *
 * Context storage: a heap-allocated Aes* is stored in the first two
 * pointer-slots of the AES_KEY buffer via aes_ctx_alloc().  The caller's
 * struct aes_key_st (244 bytes) is large enough to hold two pointers (16 bytes).
 */

/*
 * WOLFSHIM_GAP[SECURITY:MITIGATED]: AES_KEY.rounds is not set by this shim.
 *
 * OpenSSL stores the expanded AES round-key schedule in AES_KEY.rd_key[] and
 * the round count in AES_KEY.rounds (at byte offset 240).  This shim instead
 * stores a heap-allocated wolfCrypt Aes* in rd_key[0..1] with a magic sentinel
 * in rd_key[2..3] and leaves rounds = 0.  All subsequent operations (AES_encrypt,
 * AES_cbc_encrypt, etc.) retrieve the wolfCrypt context via aes_ctx_get() and
 * never read rd_key[] or rounds directly.
 *
 * However, OpenSSL's e_aes.c can reach two assembly fast-paths that bypass the
 * shim functions and read the key schedule directly:
 *
 *   BSAES (bit-sliced AES) — enabled when BSAES_CAPABLE is true.
 *   On x86_64: BSAES_CAPABLE = OPENSSL_ia32cap_P[1] & (1<<9) (SSE4.1 flag),
 *   which is true on CPUs that have SSE4.1 but NOT AES-NI (pre-Westmere, ~2009).
 *   When BSAES_CAPABLE is true and AESNI_CAPABLE is false, aes_init_key() calls
 *   our AES_set_encrypt_key (wolfCrypt, no real schedule) and then sets
 *   dat->stream.ctr = bsaes_ctr32_encrypt_blocks (assembly that reads rd_key[]).
 *   This would produce wrong output silently.
 *
 *   Decision: no mitigation was applied.  WOLFSSL_AES_KEY (the wolfSSL
 *   OpenSSL-compat struct) exposes no `rounds` field, so writing the correct
 *   round count (6 + bits/32) into that field is not possible without casting
 *   to a raw byte offset — which is fragile and undocumented.  Instead, the
 *   shim relies on the BSAES path being excluded from the build entirely:
 *   the patched openssl/crypto/aes/aes_core.c uses WOLFCRYPT_EXCLUDE=1, which
 *   disables the BSAES capability check at compile time so bsaes_ctr32_encrypt_blocks
 *   is never registered.  If that guard were ever removed, BSAES would silently
 *   corrupt data; this comment serves as the audit trail for that decision.
 *
 * Safe paths (unaffected):
 *   - AESNI_CAPABLE (modern CPUs): aesni_init_key() calls aesni_set_encrypt_key
 *     assembly directly; our shim is never in the EVP path.
 *   - Software fallback (no capability): aes_init_key() calls our shim for both
 *     init and cipher ops (AES_encrypt, AES_cbc_encrypt); rounds is not read.
 */
#ifndef WOLFCRYPT_EXCLUDE
#error "aliases.c requires WOLFCRYPT_EXCLUDE — BSAES will produce silent wrong " \
       "ciphertext if bsaes_ctr32_encrypt_blocks is registered. Set " \
       "WOLFCRYPT_EXCLUDE=1 in the build or patch openssl/crypto/aes/aes_core.c."
#endif

int AES_set_encrypt_key(const unsigned char *key, int bits, AES_KEY *schedule)
{
    Aes *aes;
    WOLFSHIM_LOG("AES_set_encrypt_key");
    aes = aes_ctx_alloc((void *)schedule);
    if (!aes) return -1;
    if (wc_AesInit(aes, NULL, INVALID_DEVID) != 0) {
        /* Free the allocated Aes before returning so the caller's schedule
         * is left clean (no dangling pointer, magic sentinel zeroed).
         * Without this, aes_ctx_get(schedule) would return a pointer to an
         * uninitialised Aes struct — any subsequent encrypt call would run
         * AES with garbage key material and no error. */
        aes_ctx_free(schedule);
        return -1;
    }
    /* AES_ENCRYPTION = 0 in wolfcrypt/aes.h */
    if (wc_AesSetKey(aes, key, (word32)(bits / 8), NULL, AES_ENCRYPTION) != 0) {
        /* wc_AesInit succeeded so the Aes is properly initialised but holds
         * no key.  Free it so the schedule cannot be used with a null key. */
        aes_ctx_free(schedule);
        return -2;
    }
    /* WOLFSHIM_GAP[SECURITY:MITIGATED]: The original intent was to write 6 + bits/32 into
     * schedule->rounds so that any BSAES assembly path reading that field
     * would see a plausible round count rather than 0.  However,
     * WOLFSSL_AES_KEY has no `rounds` field, so the write is impossible.
     * This is not a regression: under WOLFCRYPT_EXCLUDE=1 the BSAES
     * assembly is excluded from the build entirely; the EVP AES path goes
     * through wolfCrypt directly and never reads schedule->rounds. */

#ifdef WOLFSHIM_DEBUG
    wolfshim_aes_alloc_count_inc();  /* key setup succeeded; track allocation */
#endif
    return 0;
}

int AES_set_decrypt_key(const unsigned char *key, int bits, AES_KEY *schedule)
{
    Aes *aes;
    WOLFSHIM_LOG("AES_set_decrypt_key");
    aes = aes_ctx_alloc((void *)schedule);
    if (!aes) return -1;
    if (wc_AesInit(aes, NULL, INVALID_DEVID) != 0) {
        aes_ctx_free(schedule);  /* see AES_set_encrypt_key comment above */
        return -1;
    }
    /* AES_DECRYPTION = 1 in wolfcrypt/aes.h */
    if (wc_AesSetKey(aes, key, (word32)(bits / 8), NULL, AES_DECRYPTION) != 0) {
        aes_ctx_free(schedule);  /* see AES_set_encrypt_key comment above */
        return -2;
    }
    /* See AES_set_encrypt_key comment above re: schedule->rounds. */

#ifdef WOLFSHIM_DEBUG
    wolfshim_aes_alloc_count_inc();  /* key setup succeeded; track allocation */
#endif
    return 0;
}

void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc)
{
    Aes *aes;
    int ret;
    WOLFSHIM_LOG("AES_cbc_encrypt");
    aes = aes_ctx_get((const void *)key);
    if (!aes) {
        if (aes_ctx_appears_zeroed(key))
            fprintf(stderr, "[wolfshim] FATAL: AES_cbc_encrypt: AES_KEY was zeroed "
                    "after initialization — wolfCrypt heap context leaked.\n"
                    "  Use OPENSSL_cleanse() to wipe keys, not memset/bzero.\n");
        else
            fprintf(stderr, "[wolfshim] FATAL: AES_cbc_encrypt: AES_KEY has no "
                    "wolfshim sentinel — AES_set_encrypt_key() was not called.\n");
        abort();
    }
    if (!ivec || length == 0) return;
    /* Guard against size_t → word32 truncation */
    if (length > (size_t)UINT32_MAX) {
        explicit_bzero(out, length);
#ifdef WOLFSHIM_DEBUG
        fprintf(stderr, "[wolfshim] AES_cbc_encrypt: length overflow (size_t truncation)\n");
#endif
        ERR_put_error(ERR_LIB_EVP, 0, EVP_R_BAD_DECRYPT, __FILE__, __LINE__);
        return;
    }
    wc_AesSetIV(aes, ivec);
    /* AES_ENCRYPT=1 (openssl/aes.h) vs AES_ENCRYPTION=0 (wolfcrypt/aes.h) */
    if (enc == AES_ENCRYPT) {
        ret = wc_AesCbcEncrypt(aes, out, in, (word32)length);
    } else {
        ret = wc_AesCbcDecrypt(aes, out, in, (word32)length);
    }
    if (ret != 0) {
        explicit_bzero(out, length);
#ifdef WOLFSHIM_DEBUG
        fprintf(stderr, "[wolfshim] AES_cbc_encrypt: wolfCrypt error %d\n", ret);
#endif
        ERR_put_error(ERR_LIB_EVP, 0, EVP_R_BAD_DECRYPT, __FILE__, __LINE__);
        return;
    }
    /* OpenSSL contract: AES_cbc_encrypt must write the last ciphertext block
     * back to ivec so that a caller streaming CBC across multiple calls can
     * pass the same ivec pointer on the next call.  wc_AesCbcEncrypt does NOT
     * do this — it updates ivec internally but never writes back through the
     * caller-supplied pointer.  The last ciphertext block (= the next IV) is
     * left in aes->reg after the call.  We read it directly from there.
     * WOLFSHIM_REVIEW [ABI]: this is a direct field access; the _Static_assert
     * above guards the offset.  For decrypt, aes->reg holds the last input
     * ciphertext block (the correct next-IV), so the same copy is correct for
     * both directions. */
    XMEMCPY(ivec, (byte *)aes->reg, WC_AES_BLOCK_SIZE);
}

void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key)
{
    Aes *aes;
    WOLFSHIM_LOG("AES_encrypt");
    aes = aes_ctx_get((const void *)key);
    if (!aes) {
        if (aes_ctx_appears_zeroed(key))
            fprintf(stderr, "[wolfshim] FATAL: AES_encrypt: AES_KEY was zeroed "
                    "after initialization — wolfCrypt heap context leaked.\n"
                    "  Use OPENSSL_cleanse() to wipe keys, not memset/bzero.\n");
        else
            fprintf(stderr, "[wolfshim] FATAL: AES_encrypt: AES_KEY has no "
                    "wolfshim sentinel — AES_set_encrypt_key() was not called.\n");
        abort();
    }
    wc_AesEncryptDirect(aes, out, in);
}

void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key)
{
    Aes *aes;
    WOLFSHIM_LOG("AES_decrypt");
    aes = aes_ctx_get((const void *)key);
    if (!aes) {
        if (aes_ctx_appears_zeroed(key))
            fprintf(stderr, "[wolfshim] FATAL: AES_decrypt: AES_KEY was zeroed "
                    "after initialization — wolfCrypt heap context leaked.\n"
                    "  Use OPENSSL_cleanse() to wipe keys, not memset/bzero.\n");
        else
            fprintf(stderr, "[wolfshim] FATAL: AES_decrypt: AES_KEY has no "
                    "wolfshim sentinel — AES_set_decrypt_key() was not called.\n");
        abort();
    }
    wc_AesDecryptDirect(aes, out, in);
}

/* ==========================================================================
 * DES aliases
 * ========================================================================== */

void DES_set_odd_parity(DES_cblock *key)
{
    WOLFSHIM_LOG("DES_set_odd_parity");
    wolfSSL_DES_set_odd_parity(key);
}

int DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule)
{
    WOLFSHIM_LOG("DES_set_key_unchecked");
    /* wolfSSL returns void; OpenSSL spec returns 0 on success */
    wolfSSL_DES_set_key_unchecked(key, schedule);
    return 0;
}

int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule)
{
    WOLFSHIM_LOG("DES_set_key");
    return wolfSSL_DES_set_key(key, schedule);
}

int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule)
{
    WOLFSHIM_LOG("DES_set_key_checked");
    return wolfSSL_DES_set_key_checked(key, schedule);
}

int DES_key_sched(const_DES_cblock *key, DES_key_schedule *schedule)
{
    WOLFSHIM_LOG("DES_key_sched");
    return wolfSSL_DES_key_sched(key, schedule);
}

DES_LONG DES_cbc_cksum(const unsigned char *input, DES_cblock *output,
                       long length, DES_key_schedule *schedule,
                       const_DES_cblock *ivec)
{
    WOLFSHIM_LOG("DES_cbc_cksum");
    return wolfSSL_DES_cbc_cksum(input, output, length, schedule, ivec);
}

void DES_cbc_encrypt(const unsigned char *input, unsigned char *output,
                     long length, DES_key_schedule *schedule,
                     DES_cblock *ivec, int enc)
{
    WOLFSHIM_LOG("DES_cbc_encrypt");
    wolfSSL_DES_cbc_encrypt(input, output, length, schedule, ivec, enc);
}

void DES_ncbc_encrypt(const unsigned char *input, unsigned char *output,
                      long length, DES_key_schedule *schedule,
                      DES_cblock *ivec, int enc)
{
    WOLFSHIM_LOG("DES_ncbc_encrypt");
    wolfSSL_DES_ncbc_encrypt(input, output, length, schedule, ivec, enc);
}

void DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output,
                           long length,
                           DES_key_schedule *ks1, DES_key_schedule *ks2,
                           DES_key_schedule *ks3, DES_cblock *ivec, int enc)
{
    WOLFSHIM_LOG("DES_ede3_cbc_encrypt");
    wolfSSL_DES_ede3_cbc_encrypt(input, output, length, ks1, ks2, ks3, ivec, enc);
}

/* ==========================================================================
 * MD5 aliases
 * ========================================================================== */

int MD5_Init(MD5_CTX *ctx)
{
    WOLFSHIM_LOG("MD5_Init");
    return wolfSSL_MD5_Init(ctx);
}

int MD5_Update(MD5_CTX *ctx, const void *data, size_t len)
{
    WOLFSHIM_LOG("MD5_Update");
    return wolfSSL_MD5_Update(ctx, data, len);
}

int MD5_Final(unsigned char *md, MD5_CTX *ctx)
{
    WOLFSHIM_LOG("MD5_Final");
    return wolfSSL_MD5_Final(md, ctx);
}

void MD5_Transform(MD5_CTX *ctx, const unsigned char *b)
{
    WOLFSHIM_LOG("MD5_Transform");
    wolfSSL_MD5_Transform(ctx, b);
}

unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md)
{
    WOLFSHIM_LOG("MD5");
    return wolfSSL_MD5(d, n, md);
}

/* ==========================================================================
 * RC4 aliases
 * ========================================================================== */

void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data)
{
    WOLFSHIM_LOG("RC4_set_key");
    wolfSSL_RC4_set_key(key, len, data);
}

void RC4(RC4_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata)
{
    WOLFSHIM_LOG("RC4");
    wolfSSL_RC4(key, len, indata, outdata);
}

/* ==========================================================================
 * RAND aliases
 * ========================================================================== */

int RAND_load_file(const char *fname, long max_bytes)
{
    WOLFSHIM_LOG("RAND_load_file");
    return wolfSSL_RAND_load_file(fname, max_bytes);
}

int RAND_write_file(const char *fname)
{
    WOLFSHIM_LOG("RAND_write_file");
    return wolfSSL_RAND_write_file(fname);
}

/* ==========================================================================
 * Memory utilities
 * ========================================================================== */

/*
 * OPENSSL_cleanse — secure memory wipe with wolfshim destructor hooks.
 *
 * Why this shim exists
 * --------------------
 * Vanilla OpenSSL's AES_KEY and SHA_CTX are plain structs; all state is inline.
 * Zeroing them with OPENSSL_cleanse destroys everything.
 *
 * This shim cannot store wolfCrypt's Aes or SHA contexts inline — they are far
 * larger than the corresponding OpenSSL structs.  Instead, each heap-allocates
 * a wolfCrypt context and stores the pointer (plus a magic sentinel) in the
 * first two pointer-slots of the caller's buffer:
 *   - AES_KEY → aes_ctx.h (sentinel 0x574F4C4657534844 "WOLFWSHD")
 *   - SHA_CTX → sha_ctx.h (sentinel 0x57534831434F4E54 "WSH1CONT")
 *   - SHA256_CTX → sha_ctx.h (sentinel 0x57534832434F4E54 "WSH2CONT")
 *   - SHA512_CTX → sha_ctx.h (sentinel 0x57534835434F4E54 "WSH5CONT")
 *
 * A plain memset/explicit_bzero of any of these buffers would zero the pointer
 * slot — making the heap allocation unreachable — without freeing or zeroing
 * the heap block.  Key material and hash state would leak.
 *
 * OpenSSL calls OPENSSL_cleanse on AES_KEY in two situations:
 *
 *   1. Stack-allocated AES_KEY in caller code (e.g. crypto/cms/cms_env.c):
 *        AES_KEY actx;
 *        AES_set_encrypt_key(..., &actx);
 *        AES_wrap_key(&actx, ...);
 *        OPENSSL_cleanse(&actx, sizeof(actx));   <-- "I'm done, wipe it"
 *
 *   2. EVP_CIPHER_CTX_free / EVP_CIPHER_CTX_reset path (crypto/evp/evp_enc.c):
 *        OPENSSL_cleanse(c->cipher_data, c->cipher->ctx_size);
 *      cipher_data points to an EVP_AES_KEY which embeds an AES_KEY at offset 0.
 *      The BLOCK_CIPHER_generic macro registers NULL as the cleanup callback for
 *      CBC/ECB/CFB/OFB/CTR modes — OPENSSL_cleanse is the only teardown they get.
 *
 * SHA_CTX is also cleansed by well-written callers:
 *   SHA_CTX ctx; SHA1_Init(&ctx); ... SHA1_Final(md, &ctx);
 *   OPENSSL_cleanse(&ctx, sizeof(ctx));   <-- frees the heap wolfSSL context
 * SHA*_Final keeps the allocation alive (for Init reuse) and sets the sentinel;
 * OPENSSL_cleanse is therefore the normal free path for stack-allocated SHA_CTX.
 *
 * The fix
 * -------
 * Before zeroing the buffer, check whether it contains a wolfshim sentinel at
 * offset sizeof(void*).  If so, zero and free the heap context first.
 * Then explicit_bzero() wipes the rest of the buffer as normal.
 *
 * The len >= 2*sizeof(void*) guard is required because the sentinel read covers
 * 2*sizeof(void*) bytes.  Any buffer smaller than that cannot hold a sentinel.
 * For all other buffers, the sentinel check returns a no-op.
 *
 * False-positive risk: each sentinel is a distinct 64-bit value unlikely to
 * collide with non-wolfshim data.  All four values are checked in sequence;
 * at most one will match.
 */
void OPENSSL_cleanse(void *ptr, size_t len)
{
    WOLFSHIM_LOG("OPENSSL_cleanse");
    if (len >= 2 * sizeof(void *)) {
        aes_ctx_free(ptr);      /* no-op unless wolfshim AES sentinel matches */
        sha_ctx_free_any(ptr);  /* no-op unless wolfshim SHA sentinel matches */
    }
    explicit_bzero(ptr, len);
}

