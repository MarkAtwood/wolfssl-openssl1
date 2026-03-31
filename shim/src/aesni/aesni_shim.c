/*
 * aesni_shim.c — Stubs for OpenSSL's aesni_* assembly-ABI symbols
 *
 * OpenSSL's crypto/aes/ and crypto/modes/ objects reference assembly symbols
 * that are normally satisfied by aesni-x86_64.s (hardware AES-NI intrinsics).
 * When building with wolfCrypt these assembly files are not linked.
 *
 * This shim provides:
 *   - Core path functions (aesni_set_encrypt_key, aesni_cbc_encrypt, etc.)
 *     dispatch to the wolfSSL AES wrappers from aliases.c.
 *   - SHA-combined functions (aesni_cbc_sha1_enc, aesni_cbc_sha256_enc,
 *     aesni_multi_cbc_encrypt) are stubbed — they are pipeline-optimisation
 *     variants that combine AES-CBC with SHA in one pass.  The OpenSSL code
 *     falls back to separate AES + SHA paths when these are unavailable.
 *   - Exotic variants (aesni_xts_*, aesni_ocb_*, aesni_ccm64_*) are stubbed
 *     with ERR_put_error since they require AES-NI hardware instructions that
 *     wolfCrypt does not expose through the AES_KEY ABI.
 *
 * All stubs log via WOLFSHIM_DEBUG when compiled with -DWOLFSHIM_DEBUG.
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef WOLFSHIM_DEBUG
# include <stdio.h>
# define WOLFSHIM_LOG(name) fprintf(stderr, "[wolfshim] aesni: %s called\n", name)
#else
# define WOLFSHIM_LOG(name) ((void)0)
#endif

/* wolfSSL options must come first to enable all configured features */
#include <wolfssl/options.h>
/* Pull in wolfSSL settings and AES API */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/*
 * Pull in OpenSSL type definitions needed for AES_KEY, SHA_CTX, etc.
 * Use the wolfSSL openssl-compat headers.
 */
#include <wolfssl/openssl/aes.h>
/* We need the raw AES_KEY typedef — undef macros that redirect to wolfSSL */
#undef AES_set_encrypt_key
#undef AES_set_decrypt_key
#undef AES_cbc_encrypt
#undef AES_encrypt
#undef AES_decrypt

/* OpenSSL error reporting — use wolfSSL compat header to avoid type conflicts */
#include <wolfssl/openssl/err.h>

/* -----------------------------------------------------------------------
 * Forward declarations of the alias functions we'll call for dispatch.
 * These are defined in aliases.c, which in turn calls wolfSSL_AES_*.
 * ----------------------------------------------------------------------- */
extern int  AES_set_encrypt_key(const unsigned char *key, int bits, AES_KEY *schedule);
extern int  AES_set_decrypt_key(const unsigned char *key, int bits, AES_KEY *schedule);
extern void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t length, const AES_KEY *key,
                            unsigned char *ivec, const int enc);
extern void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
extern void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

/* =========================================================================
 * Core AES-NI dispatch functions
 * These map aesni_* -> AES_* (wolfSSL-backed, software AES path)
 * ========================================================================= */

int aesni_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key)
{
    WOLFSHIM_LOG("aesni_set_encrypt_key");
    return AES_set_encrypt_key(userKey, bits, key);
}

int aesni_set_decrypt_key(const unsigned char *userKey, int bits, AES_KEY *key)
{
    WOLFSHIM_LOG("aesni_set_decrypt_key");
    return AES_set_decrypt_key(userKey, bits, key);
}

void aesni_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
    WOLFSHIM_LOG("aesni_encrypt");
    AES_encrypt(in, out, key);
}

void aesni_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
    WOLFSHIM_LOG("aesni_decrypt");
    AES_decrypt(in, out, key);
}

void aesni_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const AES_KEY *key,
                       unsigned char *ivec, int enc)
{
    WOLFSHIM_LOG("aesni_cbc_encrypt");
    AES_cbc_encrypt(in, out, length, key, ivec, enc);
}

void aesni_ecb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const AES_KEY *key, int enc)
{
    WOLFSHIM_LOG("aesni_ecb_encrypt");
    /* ECB: encrypt each 16-byte block independently */
    size_t i;
    if (enc) {
        for (i = 0; i + 16 <= length; i += 16)
            AES_encrypt(in + i, out + i, key);
    } else {
        for (i = 0; i + 16 <= length; i += 16)
            AES_decrypt(in + i, out + i, key);
    }
}

void aesni_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t blocks, const void *key,
                                const unsigned char *ivec)
{
    WOLFSHIM_LOG("aesni_ctr32_encrypt_blocks");
    /*
     * CTR mode: XOR each block with AES(key, counter).
     * The counter is the IV with a 32-bit big-endian increment on bytes 12-15.
     */
    unsigned char ctr_block[16];
    unsigned char keystream[16];
    size_t i;
    uint32_t ctr;

    memcpy(ctr_block, ivec, 16);
    /* Extract 32-bit counter from last 4 bytes (big-endian) */
    ctr = ((uint32_t)ivec[12] << 24) | ((uint32_t)ivec[13] << 16) |
          ((uint32_t)ivec[14] <<  8) |  (uint32_t)ivec[15];

    for (i = 0; i < blocks; i++) {
        /* Encrypt counter block */
        AES_encrypt(ctr_block, keystream, (const AES_KEY *)key);
        /* XOR with input */
        size_t j;
        for (j = 0; j < 16; j++)
            out[i * 16 + j] = in[i * 16 + j] ^ keystream[j];
        /* Increment counter (32-bit, big-endian, wraps) */
        ctr++;
        ctr_block[12] = (ctr >> 24) & 0xFF;
        ctr_block[13] = (ctr >> 16) & 0xFF;
        ctr_block[14] = (ctr >>  8) & 0xFF;
        ctr_block[15] =  ctr        & 0xFF;
    }
}

/* =========================================================================
 * SHA-combined pipeline stubs
 * These combine AES-CBC + SHA in one hardware pass.  We stub them so the
 * caller falls back to the separate AES + SHA paths.  Returning 0 (failure)
 * signals OpenSSL to use the non-optimised path.
 * ========================================================================= */

void aesni_cbc_sha1_enc(const void *inp, void *out, size_t blocks,
                        const void *key, unsigned char iv[16],
                        void *ctx, const void *in0)
{
    WOLFSHIM_LOG("aesni_cbc_sha1_enc");
    /*
     * OpenSSL probes this with (NULL, NULL, 0, NULL, NULL, NULL, NULL) at
     * library init time (EVP_aes_128_cbc_hmac_sha1) to test AES-NI+SHA1
     * pipelining support.  Returning without doing anything causes OpenSSL
     * to use separate AES-CBC + SHA1 paths, which is correct here.
     */
    (void)inp; (void)out; (void)blocks; (void)key; (void)iv; (void)ctx; (void)in0;
}

int aesni_cbc_sha256_enc(const void *inp, void *out, size_t blocks,
                         const void *key, unsigned char iv[16],
                         void *ctx, const void *in0)
{
    WOLFSHIM_LOG("aesni_cbc_sha256_enc");
    /*
     * OpenSSL probes this with (NULL, NULL, 0, NULL, NULL, NULL, NULL) at
     * library init time (EVP_aes_128_cbc_hmac_sha256) to test AES-NI+SHA256
     * pipelining support.  Returning 0 signals "not available", causing
     * OpenSSL to fall back to separate AES-CBC + SHA256 paths.
     */
    (void)inp; (void)out; (void)blocks; (void)key; (void)iv; (void)ctx; (void)in0;
    return 0;
}

void aesni_multi_cbc_encrypt(void *ciph_descs, void *key, int num)
{
    WOLFSHIM_LOG("aesni_multi_cbc_encrypt");
    /*
     * This function should be unreachable: aesni_cbc_sha256_enc returns 0
     * (capability-probe failure) which causes OpenSSL to disable the TLS
     * multi-block fast path before ever calling this function.
     *
     * If this is reached, it means the multi-block path was enabled by some
     * other route.  We cannot safely zero the output buffers because
     * ciph_descs is an opaque pointer to OpenSSL-internal multi-block
     * descriptor structs whose layout requires internal OpenSSL headers.
     * Push an error so that any caller checking ERR_get_error() can detect
     * that encryption did not occur.  Output buffers are left as-is.
     */
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)ciph_descs;
    (void)key;
    (void)num;
}

/* =========================================================================
 * XTS stubs — require hardware AES-NI for correct behaviour
 * ========================================================================= */

void aesni_xts_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length,
                       const AES_KEY *key1, const AES_KEY *key2,
                       const unsigned char iv[16])
{
    WOLFSHIM_LOG("aesni_xts_encrypt");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)in; (void)out; (void)length;
    (void)key1; (void)key2; (void)iv;
}

void aesni_xts_decrypt(const unsigned char *in, unsigned char *out,
                       size_t length,
                       const AES_KEY *key1, const AES_KEY *key2,
                       const unsigned char iv[16])
{
    WOLFSHIM_LOG("aesni_xts_decrypt");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)in; (void)out; (void)length;
    (void)key1; (void)key2; (void)iv;
}

/* =========================================================================
 * OCB stubs — require hardware AES-NI
 * ========================================================================= */

void aesni_ocb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       size_t start_block_num,
                       unsigned char offset_i[16],
                       const unsigned char L_[][16],
                       unsigned char checksum[16])
{
    WOLFSHIM_LOG("aesni_ocb_encrypt");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)in; (void)out; (void)blocks; (void)key;
    (void)start_block_num; (void)offset_i; (void)L_; (void)checksum;
}

void aesni_ocb_decrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       size_t start_block_num,
                       unsigned char offset_i[16],
                       const unsigned char L_[][16],
                       unsigned char checksum[16])
{
    WOLFSHIM_LOG("aesni_ocb_decrypt");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)in; (void)out; (void)blocks; (void)key;
    (void)start_block_num; (void)offset_i; (void)L_; (void)checksum;
}

/* =========================================================================
 * CCM64 stubs — require hardware AES-NI
 * ========================================================================= */

void aesni_ccm64_encrypt_blocks(const unsigned char *in,
                                unsigned char *out,
                                size_t blocks,
                                const void *key,
                                const unsigned char ivec[16],
                                unsigned char cmac[16])
{
    WOLFSHIM_LOG("aesni_ccm64_encrypt_blocks");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)in; (void)out; (void)blocks; (void)key;
    (void)ivec; (void)cmac;
}

void aesni_ccm64_decrypt_blocks(const unsigned char *in,
                                unsigned char *out,
                                size_t blocks,
                                const void *key,
                                const unsigned char ivec[16],
                                unsigned char cmac[16])
{
    WOLFSHIM_LOG("aesni_ccm64_decrypt_blocks");
    ERR_put_error(ERR_LIB_EVP, 0, ERR_R_DISABLED, __FILE__, __LINE__);
    (void)in; (void)out; (void)blocks; (void)key;
    (void)ivec; (void)cmac;
}
