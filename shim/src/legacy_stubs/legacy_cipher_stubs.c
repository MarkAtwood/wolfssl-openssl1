/*
 * legacy_cipher_stubs.c — abort() stubs for legacy ciphers absent from wolfSSL
 *
 * The following ciphers are not implemented in wolfSSL's OpenSSL compatibility
 * layer and are excluded from the WOLFCRYPT_EXCLUDE link:
 *
 *   Blowfish  (BF_*)        — no wolfSSL equivalent
 *   CAST5     (CAST_*)      — no wolfSSL equivalent
 *   RC2       (RC2_*)       — wolfSSL has WOLFSSL_STUB that returns NULL
 *   SEED      (SEED_*)      — no wolfSSL equivalent
 *   Camellia  (Camellia_*)  — wolfSSL has internal support but no EVP compat
 *   ARIA      (aria_*)      — wolfSSL only has ARIA-GCM, not the raw cipher
 *
 * OpenSSL's EVP wrappers (e_bf.o, e_cast.o, e_rc2.o, e_seed.o, e_camellia.o,
 * e_aria.o) ARE still linked — they provide the EVP_bf_cbc() etc. accessor
 * functions that return valid-looking EVP_CIPHER pointers.  The problem is
 * that those cipher structs reference these primitive functions as callbacks.
 * Without stubs they resolve to NULL/undefined PLT entries, so the first
 * EVP_EncryptInit_ex() or EVP_EncryptUpdate() call segfaults inside the EVP
 * dispatch with no useful diagnostic.
 *
 * These stubs replace the segfault with an immediate abort() and a message
 * identifying the unsupported cipher.  abort() is preferable to returning a
 * failure code because:
 *
 *   1. Many EVP callers do not check intermediate return values; a 0 return
 *      from EVP_EncryptUpdate() would be silently ignored, producing plaintext
 *      output that the caller treats as ciphertext.
 *   2. A crash at the exact call site with a diagnostic is faster to triage
 *      than a segfault three stack frames deeper in EVP dispatch.
 *   3. These ciphers provide no security value in a modern deployment; the
 *      correct fix is to remove the cipher from the application, not to
 *      silently pass through plaintext.
 *
 * Each stub prints the cipher name and the missing symbol so the caller can
 * identify which cipher triggered the abort.
 */

#include <stdio.h>
#include <stdlib.h>

/* ── abort helper ──────────────────────────────────────────────────────────── */

static void __attribute__((noreturn))
wolfshim_unsupported_cipher(const char *cipher, const char *symbol)
{
    fprintf(stderr,
        "[wolfshim] FATAL: unsupported legacy cipher '%s' — symbol '%s' called.\n"
        "  This cipher is absent from wolfSSL and was excluded from the build.\n"
        "  EVP_EncryptInit_ex / EVP_DecryptInit_ex was called with a cipher\n"
        "  (e.g. EVP_bf_cbc(), EVP_cast5_cbc(), EVP_rc2_cbc(),\n"
        "   EVP_seed(), EVP_camellia_128_cbc(), EVP_aria_*()) that has no wolfCrypt backend.\n"
        "\n"
        "  Fix: remove use of this cipher from the application, or build a\n"
        "  wolfSSL version that includes the required primitive\n"
        "  (third-party patches for Blowfish/CAST/RC2/SEED/Camellia/ARIA).\n",
        cipher, symbol);
    abort();
}

/* ── Blowfish ──────────────────────────────────────────────────────────────── */

void BF_set_key(void *key, int len, const unsigned char *data)
    { (void)key; (void)len; (void)data; wolfshim_unsupported_cipher("Blowfish", "BF_set_key"); }

void BF_ecb_encrypt(const unsigned char *in, unsigned char *out, void *key, int enc)
    { (void)in; (void)out; (void)key; (void)enc; wolfshim_unsupported_cipher("Blowfish", "BF_ecb_encrypt"); }

void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
                    void *schedule, unsigned char *ivec, int enc)
    { (void)in; (void)out; (void)length; (void)schedule; (void)ivec; (void)enc;
      wolfshim_unsupported_cipher("Blowfish", "BF_cbc_encrypt"); }

void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length,
                      void *schedule, unsigned char *ivec, int *num, int enc)
    { (void)in; (void)out; (void)length; (void)schedule; (void)ivec; (void)num; (void)enc;
      wolfshim_unsupported_cipher("Blowfish", "BF_cfb64_encrypt"); }

void BF_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length,
                      void *schedule, unsigned char *ivec, int *num)
    { (void)in; (void)out; (void)length; (void)schedule; (void)ivec; (void)num;
      wolfshim_unsupported_cipher("Blowfish", "BF_ofb64_encrypt"); }

/* ── CAST5 ─────────────────────────────────────────────────────────────────── */

void CAST_set_key(void *key, int nkey, const unsigned char *data)
    { (void)key; (void)nkey; (void)data; wolfshim_unsupported_cipher("CAST5", "CAST_set_key"); }

void CAST_ecb_encrypt(const unsigned char *in, unsigned char *out, void *key, int enc)
    { (void)in; (void)out; (void)key; (void)enc; wolfshim_unsupported_cipher("CAST5", "CAST_ecb_encrypt"); }

void CAST_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
                      void *ks, unsigned char *iv, int enc)
    { (void)in; (void)out; (void)length; (void)ks; (void)iv; (void)enc;
      wolfshim_unsupported_cipher("CAST5", "CAST_cbc_encrypt"); }

void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length,
                        void *ks, unsigned char *iv, int *num, int enc)
    { (void)in; (void)out; (void)length; (void)ks; (void)iv; (void)num; (void)enc;
      wolfshim_unsupported_cipher("CAST5", "CAST_cfb64_encrypt"); }

void CAST_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length,
                        void *ks, unsigned char *iv, int *num)
    { (void)in; (void)out; (void)length; (void)ks; (void)iv; (void)num;
      wolfshim_unsupported_cipher("CAST5", "CAST_ofb64_encrypt"); }

/* ── RC2 ───────────────────────────────────────────────────────────────────── */

void RC2_set_key(void *key, int len, const unsigned char *data, int bits)
    { (void)key; (void)len; (void)data; (void)bits; wolfshim_unsupported_cipher("RC2", "RC2_set_key"); }

void RC2_ecb_encrypt(const unsigned char *in, unsigned char *out, void *key, int enc)
    { (void)in; (void)out; (void)key; (void)enc; wolfshim_unsupported_cipher("RC2", "RC2_ecb_encrypt"); }

void RC2_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
                     void *ks, unsigned char *iv, int enc)
    { (void)in; (void)out; (void)length; (void)ks; (void)iv; (void)enc;
      wolfshim_unsupported_cipher("RC2", "RC2_cbc_encrypt"); }

void RC2_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length,
                       void *schedule, unsigned char *ivec, int *num, int enc)
    { (void)in; (void)out; (void)length; (void)schedule; (void)ivec; (void)num; (void)enc;
      wolfshim_unsupported_cipher("RC2", "RC2_cfb64_encrypt"); }

void RC2_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length,
                       void *schedule, unsigned char *ivec, int *num)
    { (void)in; (void)out; (void)length; (void)schedule; (void)ivec; (void)num;
      wolfshim_unsupported_cipher("RC2", "RC2_ofb64_encrypt"); }

/* ── SEED ──────────────────────────────────────────────────────────────────── */

void SEED_set_key(const unsigned char *rawkey, void *ks)
    { (void)rawkey; (void)ks; wolfshim_unsupported_cipher("SEED", "SEED_set_key"); }

void SEED_ecb_encrypt(const unsigned char *in, unsigned char *out, void *ks, int enc)
    { (void)in; (void)out; (void)ks; (void)enc; wolfshim_unsupported_cipher("SEED", "SEED_ecb_encrypt"); }

void SEED_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                      void *ks, unsigned char *iv, int enc)
    { (void)in; (void)out; (void)len; (void)ks; (void)iv; (void)enc;
      wolfshim_unsupported_cipher("SEED", "SEED_cbc_encrypt"); }

void SEED_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                         void *ks, unsigned char *iv, int *num, int enc)
    { (void)in; (void)out; (void)len; (void)ks; (void)iv; (void)num; (void)enc;
      wolfshim_unsupported_cipher("SEED", "SEED_cfb128_encrypt"); }

void SEED_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                         void *ks, unsigned char *iv, int *num)
    { (void)in; (void)out; (void)len; (void)ks; (void)iv; (void)num;
      wolfshim_unsupported_cipher("SEED", "SEED_ofb128_encrypt"); }

/* ── Camellia ──────────────────────────────────────────────────────────────── */

int Camellia_set_key(const unsigned char *userKey, int bits, void *key)
    { (void)userKey; (void)bits; (void)key; wolfshim_unsupported_cipher("Camellia", "Camellia_set_key"); }

void Camellia_encrypt(const unsigned char *in, unsigned char *out, const void *key)
    { (void)in; (void)out; (void)key; wolfshim_unsupported_cipher("Camellia", "Camellia_encrypt"); }

void Camellia_decrypt(const unsigned char *in, unsigned char *out, const void *key)
    { (void)in; (void)out; (void)key; wolfshim_unsupported_cipher("Camellia", "Camellia_decrypt"); }

void Camellia_cbc_encrypt(const unsigned char *in, unsigned char *out,
                          size_t length, const void *key,
                          unsigned char *ivec, int enc)
    { (void)in; (void)out; (void)length; (void)key; (void)ivec; (void)enc;
      wolfshim_unsupported_cipher("Camellia", "Camellia_cbc_encrypt"); }

/* ── ARIA ──────────────────────────────────────────────────────────────────── */

int aria_set_encrypt_key(const unsigned char *userKey, int bits, void *key)
    { (void)userKey; (void)bits; (void)key; wolfshim_unsupported_cipher("ARIA", "aria_set_encrypt_key"); }

int aria_set_decrypt_key(const unsigned char *userKey, int bits, void *key)
    { (void)userKey; (void)bits; (void)key; wolfshim_unsupported_cipher("ARIA", "aria_set_decrypt_key"); }

void aria_encrypt(const unsigned char *in, unsigned char *out, const void *key)
    { (void)in; (void)out; (void)key; wolfshim_unsupported_cipher("ARIA", "aria_encrypt"); }

/* RC4 is implemented via rc4/rc4_shim.c (wolfCrypt Arc4, --enable-arc4). */
