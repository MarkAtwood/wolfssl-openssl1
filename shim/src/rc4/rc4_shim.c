/*
 * rc4_shim.c — RC4 (ARC4) bridge to wolfCrypt
 *
 * Replaces the following OpenSSL object in the libcrypto link:
 *   crypto/rc4/rc4-x86_64.o   — RC4 / RC4_set_key / RC4_options
 *
 * OpenSSL's e_rc4.o links against RC4_set_key and RC4.  This shim provides
 * those symbols backed by wolfSSL's wc_Arc4* API.  wolfSSL must be built
 * with --enable-arc4 (already set in build.sh).
 *
 * Struct size note:
 *   OpenSSL's RC4_KEY = { RC4_INT x, y; RC4_INT data[256]; }
 *   With RC4_INT = unsigned int (x86-64), sizeof(RC4_KEY) ≈ 1032 bytes.
 *   wolfSSL's Arc4 ≈ 268 bytes (byte x, y; byte state[256]; void *heap).
 *   e_rc4.o allocates sizeof(EVP_RC4_KEY) = sizeof(RC4_KEY) ≈ 1032 bytes in
 *   the EVP cipher context — always larger than sizeof(Arc4) — so casting is
 *   safe; wolfSSL only touches the first ~268 bytes of the buffer.
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#ifndef NO_RC4
# include <wolfssl/wolfcrypt/arc4.h>
#else
# error "wolfSSL must be built with RC4/ARC4 support (--enable-arc4) to use rc4_shim.c"
#endif

/* ── RC4_set_key ────────────────────────────────────────────────────────────
 *
 * OpenSSL signature:
 *   void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
 *
 * The caller (e_rc4.o) passes a buffer of sizeof(RC4_KEY) ≈ 1032 bytes.
 * We initialise and key wolfSSL's Arc4 struct in that buffer.
 */
void RC4_set_key(void *key, int len, const unsigned char *data)
{
    Arc4 *arc4 = (Arc4 *)key;
    wc_Arc4Init(arc4, NULL, INVALID_DEVID);
    wc_Arc4SetKey(arc4, data, (word32)(len < 0 ? 0 : (unsigned)len));
}

/* ── RC4 ────────────────────────────────────────────────────────────────────
 *
 * OpenSSL signature:
 *   void RC4(RC4_KEY *key, size_t len,
 *            const unsigned char *indata, unsigned char *outdata);
 */
void RC4(void *key, size_t len, const unsigned char *indata,
         unsigned char *outdata)
{
    Arc4 *arc4 = (Arc4 *)key;
    /* RC4 is a stream cipher; practical inputs are bounded well within word32
     * range (TLS record max 16 KiB).  Abort rather than zero outdata: zeroed
     * output would be silent wrong ciphertext — a confidentiality failure
     * where the caller sees no error but receives meaningless bytes. */
    if (len > (size_t)(word32)-1) {
        fprintf(stderr,
            "[wolfshim] FATAL: RC4() input length %zu exceeds word32 range.\n"
            "  Aborting rather than producing zeroed (wrong) ciphertext.\n",
            len);
        abort();
    }
    wc_Arc4Process(arc4, outdata, indata, (word32)len);
}

/* ── RC4_options ────────────────────────────────────────────────────────────
 *
 * OpenSSL signature:
 *   const char *RC4_options(void);
 *
 * Returns a string describing the RC4 implementation variant.  wolfCrypt's
 * Arc4 uses a byte-oriented state array (byte state[256]), which corresponds
 * to OpenSSL's RC4_CHAR build variant.
 */
const char *RC4_options(void) { return "rc4(char)"; }
