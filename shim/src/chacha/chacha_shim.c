/*
 * chacha_shim.c — ChaCha20 and Poly1305 bridge to wolfCrypt
 *
 * Replaces the following OpenSSL objects in the libcrypto link:
 *   crypto/chacha/chacha-x86_64.o    — ChaCha20_ctr32
 *   crypto/poly1305/poly1305.o       — Poly1305_ctx_size / _Init / _Update / _Final
 *   crypto/poly1305/poly1305-x86_64.o — xor128_encrypt_n_pad / xor128_decrypt_n_pad
 *
 * OpenSSL's e_chacha20_poly1305.o links against these symbols.  Providing
 * wolfCrypt-backed implementations here gives a pure wolfCrypt ChaCha20-Poly1305
 * AEAD path; no OpenSSL crypto code is needed.
 *
 * Notes on ChaCha20_ctr32:
 *   counter[0]   = initial block counter (little-endian uint32)
 *   counter[1..3] = 96-bit nonce (three uint32s)
 * wc_Chacha_SetIV(ctx, iv12, initial_ctr) matches this layout exactly.
 *
 * Notes on Poly1305_ctx_size:
 *   Called at runtime by e_chacha20_poly1305.c to size the heap allocation
 *   (sizeof(EVP_CHACHA_AEAD_CTX) + Poly1305_ctx_size()).  Returning
 *   sizeof(wolfCrypt Poly1305) ensures the right amount is allocated and that
 *   Poly1305_Init/Update/Final can treat the memory as a wolfCrypt Poly1305.
 *
 * Notes on xor128_encrypt_n_pad / xor128_decrypt_n_pad:
 *   Used in the TLS-record fast-path in e_chacha20_poly1305.c.
 *   Semantics: XOR len bytes of inp with the keystream buffer at otp, writing
 *   result to out.  For encrypt: otp is overwritten with ciphertext (for
 *   subsequent Poly1305 update).  For decrypt: otp is overwritten with the
 *   original ciphertext.  Both pad otp to the next 16-byte boundary with
 *   zero bytes.  Return value: pointer just past the padded region of otp.
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#include <stddef.h>
#include <string.h>
#include <strings.h>  /* explicit_bzero */

/* wolfSSL headers — provides ChaCha and Poly1305 types and APIs */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#ifndef HAVE_CHACHA
# error "wolfSSL must be built with ChaCha20 support (--enable-chacha) to use chacha_shim.c"
#endif
#ifndef HAVE_POLY1305
# error "wolfSSL must be built with Poly1305 support (--enable-poly1305) to use chacha_shim.c"
#endif

#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/poly1305.h>

#ifdef WOLFSHIM_DEBUG
# include <stdio.h>
# define WOLFSHIM_LOG(name) fprintf(stderr, "[wolfshim] chacha: %s\n", name)
#else
# define WOLFSHIM_LOG(name) ((void)0)
#endif

/* -------------------------------------------------------------------------
 * ChaCha20_ctr32 — core ChaCha20 keystream XOR used by e_chacha20_poly1305
 * ------------------------------------------------------------------------- */

void ChaCha20_ctr32(unsigned char *out, const unsigned char *inp, size_t len,
                    const unsigned int key[8], const unsigned int counter[4])
{
    ChaCha ctx;
    int ret;
    WOLFSHIM_LOG("ChaCha20_ctr32");
    /* key[0..7] = 32-byte key */
    ret = wc_Chacha_SetKey(&ctx, (const byte *)key, 32);
    if (ret != 0) {
        memset(out, 0, len);
        explicit_bzero(&ctx, sizeof(ctx));
        return;
    }
    /* counter[0] = block counter; counter[1..3] = 96-bit nonce */
    ret = wc_Chacha_SetIV(&ctx, (const byte *)&counter[1], counter[0]);
    if (ret != 0) {
        memset(out, 0, len);
        explicit_bzero(&ctx, sizeof(ctx));
        return;
    }
    /* Defense-in-depth: TLS record sizes are bounded at 16 KB, so len
     * exceeding word32 is unreachable in normal operation, but silently
     * truncating a size_t to word32 would process the wrong byte count. */
    if (len > (size_t)(word32)-1) {
        memset(out, 0, len);
        explicit_bzero(&ctx, sizeof(ctx));
        return;
    }
    ret = wc_Chacha_Process(&ctx, out, inp, (word32)len);
    if (ret != 0) {
        memset(out, 0, len);
    }
    explicit_bzero(&ctx, sizeof(ctx));
}

/* -------------------------------------------------------------------------
 * Poly1305 — public API backed by wolfCrypt
 * The ctx pointer points to a heap region sized by Poly1305_ctx_size().
 * e_chacha20_poly1305.c allocates sizeof(EVP_CHACHA_AEAD_CTX)+Poly1305_ctx_size()
 * and places the Poly1305 context at (EVP_CHACHA_AEAD_CTX *)(actx + 1).
 * ------------------------------------------------------------------------- */

size_t Poly1305_ctx_size(void)
{
    return sizeof(Poly1305);
}

void Poly1305_Init(void *ctx, const unsigned char key[32])
{
    WOLFSHIM_LOG("Poly1305_Init");
    wc_Poly1305SetKey((Poly1305 *)ctx, key, 32);
}

void Poly1305_Update(void *ctx, const unsigned char *inp, size_t len)
{
    WOLFSHIM_LOG("Poly1305_Update");
    /* Defense-in-depth: TLS record sizes are bounded at 16 KB so this guard
     * is unreachable in normal operation, but silently truncating would
     * produce a wrong MAC over a different byte count than intended. */
    if (len > (size_t)(word32)-1) {
        return;
    }
    wc_Poly1305Update((Poly1305 *)ctx, inp, (word32)len);
}

void Poly1305_Final(void *ctx, unsigned char mac[16])
{
    WOLFSHIM_LOG("Poly1305_Final");
    wc_Poly1305Final((Poly1305 *)ctx, mac);
}

/* -------------------------------------------------------------------------
 * xor128_encrypt_n_pad
 *
 * XOR len bytes of inp (plaintext) with the keystream at otp, writing
 * ciphertext to both out and otp.  Zero-pad otp from len up to the next
 * 16-byte boundary.  Return pointer to the first byte past the padded region
 * of otp (used by the caller to track Poly1305 input length).
 * ------------------------------------------------------------------------- */

void *xor128_encrypt_n_pad(void *out, const void *inp, void *otp, size_t len)
{
    unsigned char       *o = (unsigned char *)out;
    const unsigned char *i = (const unsigned char *)inp;
    unsigned char       *k = (unsigned char *)otp;
    size_t n;

    for (n = 0; n < len; n++)
        k[n] = o[n] = i[n] ^ k[n];   /* encrypt; put ciphertext in otp */

    /* zero-pad to 16-byte boundary for Poly1305 */
    while (n & 15)
        k[n++] = 0;

    return k + n;
}

/* -------------------------------------------------------------------------
 * xor128_decrypt_n_pad
 *
 * XOR len bytes of inp (ciphertext) with the keystream at otp, writing
 * plaintext to out.  Store the original ciphertext into otp (Poly1305
 * authenticates the ciphertext).  Zero-pad otp from len up to the next
 * 16-byte boundary.  Return pointer past the padded region.
 * ------------------------------------------------------------------------- */

void *xor128_decrypt_n_pad(void *out, const void *inp, void *otp, size_t len)
{
    unsigned char       *o = (unsigned char *)out;
    const unsigned char *i = (const unsigned char *)inp;
    unsigned char       *k = (unsigned char *)otp;
    size_t n;

    for (n = 0; n < len; n++) {
        unsigned char c = i[n];
        o[n] = k[n] ^ c;   /* decrypt */
        k[n] = c;           /* ciphertext in otp for Poly1305 */
    }

    /* zero-pad to 16-byte boundary */
    while (n & 15)
        k[n++] = 0;

    return k + n;
}
