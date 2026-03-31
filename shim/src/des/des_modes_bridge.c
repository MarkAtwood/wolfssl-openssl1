/*
 * des_modes_bridge.c — wolfCrypt-backed DES mode implementations
 *
 * Replaces OpenSSL's mode object files (cfb64ede.c, cfb64enc.c, cfb_enc.c,
 * ecb3_enc.c, ofb64ede.c, ofb64enc.c, ofb_enc.c, pcbc_enc.c, qud_cksm.c,
 * str2key.c, xcbc_enc.c) so that no OpenSSL crypto code is linked.
 *
 * All block cipher operations use wolfCrypt wc_Des_CbcEncrypt/Decrypt (with
 * a zero IV for a single block — equivalent to ECB) and wc_Des3_Cbc*.
 *
 * Compiled with wolfSSL headers only; no OpenSSL headers are included.
 */

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* wolfSSL headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_DES3
# error "wolfSSL must be built with DES3 support (--enable-des3) to use des_modes_bridge.c"
#endif

#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/openssl/des.h>

/* ── single-block DES block-cipher helpers ─────────────────────────────────
 * CBC with a zero IV for a single 8-byte block is identical to ECB:
 *   encrypt(in) = CBC_k(in ⊕ 0) = ECB_k(in)                              */

static const byte null_iv[8] = {0};

static void des_ecb_enc(const byte *key, byte *out, const byte *in)
{
    Des des;
    wc_Des_SetKey(&des, key, null_iv, DES_ENCRYPTION);
    wc_Des_CbcEncrypt(&des, out, in, 8);
}

static void des_ecb_dec(const byte *key, byte *out, const byte *in)
{
    Des des;
    wc_Des_SetKey(&des, key, null_iv, DES_DECRYPTION);
    wc_Des_CbcDecrypt(&des, out, in, 8);
}

static void des3_ecb_enc(const byte *k1, const byte *k2, const byte *k3,
                          byte *out, const byte *in)
{
    Des3 des3;
    byte key24[24];
    memcpy(key24,      k1, 8);
    memcpy(key24 + 8,  k2, 8);
    memcpy(key24 + 16, k3, 8);
    wc_Des3Init(&des3, NULL, INVALID_DEVID);
    wc_Des3_SetKey(&des3, key24, null_iv, DES_ENCRYPTION);
    wc_Des3_CbcEncrypt(&des3, out, in, 8);
    wc_Des3Free(&des3);
}

static void des3_ecb_dec(const byte *k1, const byte *k2, const byte *k3,
                          byte *out, const byte *in)
{
    Des3 des3;
    byte key24[24];
    memcpy(key24,      k1, 8);
    memcpy(key24 + 8,  k2, 8);
    memcpy(key24 + 16, k3, 8);
    wc_Des3Init(&des3, NULL, INVALID_DEVID);
    wc_Des3_SetKey(&des3, key24, null_iv, DES_DECRYPTION);
    wc_Des3_CbcDecrypt(&des3, out, in, 8);
    wc_Des3Free(&des3);
}

/* ── shift-register update (CFB/OFB) ──────────────────────────────────────
 * Shift iv[0..7] left by numbits, fill the rightmost bits from feedback.
 * For byte-aligned numbits this is a simple memmove + append.
 * For non-byte-aligned we replicate the bit-shift logic from cfb_enc.c
 * (which operates on raw byte arrays using the same LE convention).       */

static void iv_shift_left(byte *iv, const byte *feedback, int numbits)
{
    int full = numbits / 8;        /* whole bytes to discard on the left  */
    int extra = numbits % 8;       /* remaining bits                       */
    int n_bytes = (numbits + 7) / 8;
    int i;

    if (extra == 0) {
        memmove(iv, iv + full, 8 - full);
        memcpy(iv + 8 - full, feedback, full);
    } else {
        /* Build a 16-byte window: [iv | feedback], then extract 8 bytes  */
        byte tmp[17];
        memcpy(tmp, iv, 8);
        memcpy(tmp + 8, feedback, n_bytes);
        tmp[8 + n_bytes] = 0;
        /* Byte-level shift */
        memmove(tmp, tmp + full, 9);
        /* Bit-level shift for the fractional part */
        for (i = 0; i < 8; i++)
            tmp[i] = (byte)((tmp[i] << extra) | (tmp[i + 1] >> (8 - extra)));
        memcpy(iv, tmp, 8);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_cfb64_encrypt — CFB-64, single DES, byte-stream interface
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, DES_key_schedule *schedule,
                       DES_cblock *ivec, int *num, int enc)
{
    const byte *key = (const byte *)schedule;
    byte *iv = (byte *)(*ivec);
    byte ks[8];
    int n = *num;
    long l = length;
    byte c, cc;

    if (enc) {
        while (l--) {
            if (n == 0) {
                des_ecb_enc(key, ks, iv);
                memcpy(iv, ks, 8);
            }
            c = *(in++) ^ iv[n];
            *(out++) = c;
            iv[n] = c;
            n = (n + 1) & 0x07;
        }
    } else {
        while (l--) {
            if (n == 0) {
                des_ecb_enc(key, ks, iv);
                memcpy(iv, ks, 8);
            }
            cc    = *(in++);
            c     = iv[n];
            iv[n] = cc;
            *(out++) = c ^ cc;
            n = (n + 1) & 0x07;
        }
    }
    *num = n;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_cfb_encrypt — CFB-r, single DES, arbitrary bit-width
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_cfb_encrypt(const unsigned char *in, unsigned char *out,
                     int numbits, long length,
                     DES_key_schedule *schedule,
                     DES_cblock *ivec, int enc)
{
    const byte *key = (const byte *)schedule;
    byte iv[8], ks[8], ct[8];
    int n_bytes, i;
    long l = length;

    if (numbits <= 0 || numbits > 64) return;
    n_bytes = (numbits + 7) / 8;
    memcpy(iv, *ivec, 8);

    while (l >= (long)n_bytes) {
        des_ecb_enc(key, ks, iv);

        for (i = 0; i < n_bytes; i++) {
            if (enc) {
                ct[i]  = in[i] ^ ks[i];
                out[i] = ct[i];
            } else {
                ct[i]  = in[i];           /* ciphertext = input when decrypting */
                out[i] = in[i] ^ ks[i];
            }
        }
        in  += n_bytes;
        out += n_bytes;
        l   -= n_bytes;

        iv_shift_left(iv, ct, numbits);
    }
    memcpy(*ivec, iv, 8);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_ofb64_encrypt — OFB-64, single DES, byte-stream interface
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_ofb64_encrypt(register const unsigned char *in,
                       register unsigned char *out, long length,
                       DES_key_schedule *schedule,
                       DES_cblock *ivec, int *num)
{
    const byte *key = (const byte *)schedule;
    byte *iv = (byte *)(*ivec);
    byte ks[8];
    int n = *num;
    long l = length;

    while (l--) {
        if (n == 0) {
            des_ecb_enc(key, ks, iv);
            memcpy(iv, ks, 8);
        }
        *(out++) = *(in++) ^ iv[n];
        n = (n + 1) & 0x07;
    }
    *num = n;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_ofb_encrypt — OFB-r, single DES, arbitrary bit-width
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_ofb_encrypt(const unsigned char *in, unsigned char *out,
                     int numbits, long length,
                     DES_key_schedule *schedule,
                     DES_cblock *ivec)
{
    const byte *key = (const byte *)schedule;
    byte iv[8], ks[8];
    int n_bytes, i;
    long l = length;

    if (numbits <= 0 || numbits > 64) return;
    n_bytes = (numbits + 7) / 8;
    memcpy(iv, *ivec, 8);

    while (l >= (long)n_bytes) {
        des_ecb_enc(key, ks, iv);

        for (i = 0; i < n_bytes; i++)
            out[i] = in[i] ^ ks[i];
        in  += n_bytes;
        out += n_bytes;
        l   -= n_bytes;

        iv_shift_left(iv, ks, numbits);  /* OFB: feedback = keystream output */
    }
    memcpy(*ivec, iv, 8);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_ede3_cfb64_encrypt — CFB-64, 3DES-EDE, byte-stream interface
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_ede3_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                             long length, DES_key_schedule *ks1,
                             DES_key_schedule *ks2, DES_key_schedule *ks3,
                             DES_cblock *ivec, int *num, int enc)
{
    const byte *k1 = (const byte *)ks1;
    const byte *k2 = (const byte *)ks2;
    const byte *k3 = (const byte *)ks3;
    byte *iv = (byte *)(*ivec);
    byte ks[8];
    int n = *num;
    long l = length;
    byte c, cc;

    if (enc) {
        while (l--) {
            if (n == 0) {
                des3_ecb_enc(k1, k2, k3, ks, iv);
                memcpy(iv, ks, 8);
            }
            c     = *(in++) ^ iv[n];
            *(out++) = c;
            iv[n] = c;
            n = (n + 1) & 0x07;
        }
    } else {
        while (l--) {
            if (n == 0) {
                des3_ecb_enc(k1, k2, k3, ks, iv);
                memcpy(iv, ks, 8);
            }
            cc    = *(in++);
            c     = iv[n];
            iv[n] = cc;
            *(out++) = c ^ cc;
            n = (n + 1) & 0x07;
        }
    }
    *num = n;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_ede3_cfb_encrypt — CFB-r, 3DES-EDE, arbitrary bit-width
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_ede3_cfb_encrypt(const unsigned char *in, unsigned char *out,
                           int numbits, long length,
                           DES_key_schedule *ks1, DES_key_schedule *ks2,
                           DES_key_schedule *ks3,
                           DES_cblock *ivec, int enc)
{
    const byte *k1 = (const byte *)ks1;
    const byte *k2 = (const byte *)ks2;
    const byte *k3 = (const byte *)ks3;
    byte iv[8], ks[8], ct[8];
    int n_bytes, i;
    long l = length;

    if (numbits <= 0 || numbits > 64) return;
    n_bytes = (numbits + 7) / 8;
    memcpy(iv, *ivec, 8);

    while (l >= (long)n_bytes) {
        des3_ecb_enc(k1, k2, k3, ks, iv);

        for (i = 0; i < n_bytes; i++) {
            if (enc) {
                ct[i]  = in[i] ^ ks[i];
                out[i] = ct[i];
            } else {
                ct[i]  = in[i];
                out[i] = in[i] ^ ks[i];
            }
        }
        in  += n_bytes;
        out += n_bytes;
        l   -= n_bytes;

        iv_shift_left(iv, ct, numbits);
    }
    memcpy(*ivec, iv, 8);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_ede3_ofb64_encrypt — OFB-64, 3DES-EDE, byte-stream interface
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_ede3_ofb64_encrypt(register const unsigned char *in,
                             register unsigned char *out, long length,
                             DES_key_schedule *k1, DES_key_schedule *k2,
                             DES_key_schedule *k3,
                             DES_cblock *ivec, int *num)
{
    const byte *ks1 = (const byte *)k1;
    const byte *ks2 = (const byte *)k2;
    const byte *ks3 = (const byte *)k3;
    byte *iv = (byte *)(*ivec);
    byte ks[8];
    int n = *num;
    long l = length;

    while (l--) {
        if (n == 0) {
            des3_ecb_enc(ks1, ks2, ks3, ks, iv);
            memcpy(iv, ks, 8);
        }
        *(out++) = *(in++) ^ iv[n];
        n = (n + 1) & 0x07;
    }
    *num = n;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_ecb3_encrypt — 3DES-EDE ECB, single 8-byte block
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output,
                      DES_key_schedule *ks1, DES_key_schedule *ks2,
                      DES_key_schedule *ks3, int enc)
{
    const byte *k1 = (const byte *)ks1;
    const byte *k2 = (const byte *)ks2;
    const byte *k3 = (const byte *)ks3;

    if (enc)
        des3_ecb_enc(k1, k2, k3, (byte *)(*output), (const byte *)(*input));
    else
        des3_ecb_dec(k1, k2, k3, (byte *)(*output), (const byte *)(*input));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_pcbc_encrypt — PCBC (Propagating CBC), single DES
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_pcbc_encrypt(const unsigned char *input, unsigned char *output,
                      long length, DES_key_schedule *schedule,
                      DES_cblock *ivec, int enc)
{
    const byte *key = (const byte *)schedule;
    byte xr[8], block_in[8], block_out[8];
    long l = length;
    int i, n;

    memcpy(xr, *ivec, 8);

    if (enc) {
        for (; l > 0; l -= 8) {
            n = (l >= 8) ? 8 : (int)l;
            /* Zero-pad partial input */
            memset(block_in, 0, 8);
            memcpy(block_in, input, n);
            /* XOR with accumulated state */
            for (i = 0; i < 8; i++) block_in[i] ^= xr[i];
            des_ecb_enc(key, block_out, block_in);
            /* new state = plaintext ^ ciphertext */
            for (i = 0; i < 8; i++)
                xr[i] = ((i < n) ? input[i] : (byte)0) ^ block_out[i];
            /* Output is always a full 8-byte block */
            memcpy(output, block_out, 8);
            input  += n;
            output += 8;
        }
    } else {
        for (; l > 0; l -= 8) {
            n = (l >= 8) ? 8 : (int)l;
            /* Decrypt always reads 8 bytes of cipher */
            des_ecb_dec(key, block_out, input);
            for (i = 0; i < 8; i++) block_out[i] ^= xr[i];
            /* new state = plaintext ^ ciphertext */
            for (i = 0; i < 8; i++) xr[i] = block_out[i] ^ input[i];
            /* Output n bytes (partial for last block) */
            memcpy(output, block_out, n);
            input  += 8;
            output += n;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_xcbc_encrypt — DESX / XCBC-MAC, single DES
 *
 * XCBC:  ciphertext = E_k( plaintext ^ prev_output ^ inW ) ^ outW
 * IV update: prev_output = ciphertext  (before outW is removed)
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_xcbc_encrypt(const unsigned char *in, unsigned char *out,
                      long length, DES_key_schedule *schedule,
                      DES_cblock *ivec,
                      const_DES_cblock *inw, const_DES_cblock *outw,
                      int enc)
{
    const byte *key  = (const byte *)schedule;
    const byte *inW  = (const byte *)(*inw);
    const byte *outW = (const byte *)(*outw);
    byte xr[8], block_in[8], block_out[8];
    long l = length;
    int i, n;

    memcpy(xr, *ivec, 8);

    if (enc) {
        for (; l > 0; l -= n) {
            n = (l >= 8) ? 8 : (int)l;
            /* block_in = (zero-padded input) ^ prev_output ^ inW */
            for (i = 0; i < n; i++) block_in[i] = in[i] ^ xr[i] ^ inW[i];
            for (i = n; i < 8; i++) block_in[i] =          xr[i] ^ inW[i];
            des_ecb_enc(key, block_out, block_in);
            /* ciphertext = encrypted ^ outW; xr = ciphertext */
            for (i = 0; i < 8; i++) xr[i] = block_out[i] ^ outW[i];
            memcpy(out, xr, 8);   /* always output 8 bytes */
            in  += n;
            out += 8;
        }
    } else {
        for (; l > 0; l -= n) {
            byte cipher[8];
            n = (l >= 8) ? 8 : (int)l;
            memcpy(cipher, in, 8);
            /* undo output whitening */
            for (i = 0; i < 8; i++) block_in[i] = cipher[i] ^ outW[i];
            des_ecb_dec(key, block_out, block_in);
            /* plaintext = decrypted ^ prev_output ^ inW */
            for (i = 0; i < 8; i++) block_out[i] ^= xr[i] ^ inW[i];
            memcpy(out, block_out, n);
            /* xr = raw ciphertext (before outW removal) */
            memcpy(xr, cipher, 8);
            in  += 8;
            out += n;
        }
    }
    memcpy(*ivec, xr, 8);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_quad_cksum — DES-based quadratic checksum
 *
 * Pure arithmetic, no DES block cipher calls.
 * Ported directly from OpenSSL qud_cksm.c.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define Q_B0(a) ((DES_LONG)(a))
#define Q_B1(a) ((DES_LONG)(a) <<  8)
#define Q_B2(a) ((DES_LONG)(a) << 16)
#define Q_B3(a) ((DES_LONG)(a) << 24)

#define NOISE ((DES_LONG)83653421L)

DES_LONG DES_quad_cksum(const unsigned char *input, DES_cblock output[],
                         long length, int out_count, DES_cblock *seed)
{
    DES_LONG z0, z1, t0, t1;
    int i;
    long l;
    const unsigned char *cp;
    DES_LONG *lp;

    if (out_count < 1) out_count = 1;
    lp = (DES_LONG *)&(output[0])[0];

    z0 = Q_B0((*seed)[0]) | Q_B1((*seed)[1]) |
         Q_B2((*seed)[2]) | Q_B3((*seed)[3]);
    z1 = Q_B0((*seed)[4]) | Q_B1((*seed)[5]) |
         Q_B2((*seed)[6]) | Q_B3((*seed)[7]);

    for (i = 0; i < 4 && i < out_count; i++) {
        cp = input;
        l  = length;
        while (l > 0) {
            if (l > 1) {
                t0  = (DES_LONG)(*cp++);
                t0 |= Q_B1(*cp++);
                l--;
            } else {
                t0 = (DES_LONG)(*cp++);
            }
            l--;
            t0  += z0;
            t0  &= 0xffffffffL;
            t1   = z1;
            z0   = (((t0 * t0) & 0xffffffffL) +
                    ((t1 * t1) & 0xffffffffL)) & 0xffffffffL;
            z0  %= 0x7fffffffL;
            z1   = ((t0 * ((t1 + NOISE) & 0xffffffffL)) & 0xffffffffL) %
                    0x7fffffffL;
        }
        if (lp != NULL) {
            *lp++ = z0;
            *lp++ = z1;
        }
    }
    return z0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DES_string_to_key / DES_string_to_2keys
 *
 * Implemented using wolfSSL's DES_cbc_cksum, DES_set_odd_parity,
 * DES_set_key_unchecked.
 * ═══════════════════════════════════════════════════════════════════════════ */

void DES_string_to_key(const char *str, DES_cblock *key)
{
    DES_key_schedule ks;
    int i, length;

    memset(key, 0, 8);
    length = (int)strlen(str);
    for (i = 0; i < length; i++) {
        unsigned char j = (unsigned char)str[i];
        if ((i % 16) < 8) {
            (*key)[i % 8] ^= (j << 1);
        } else {
            j = ((j << 4) & 0xf0) | ((j >> 4) & 0x0f);
            j = ((j << 2) & 0xcc) | ((j >> 2) & 0x33);
            j = ((j << 1) & 0xaa) | ((j >> 1) & 0x55);
            (*key)[7 - (i % 8)] ^= j;
        }
    }
    DES_set_odd_parity(key);
    DES_set_key_unchecked(key, &ks);
    DES_cbc_cksum((const unsigned char *)str, key, length, &ks, key);
    memset(&ks, 0, sizeof(ks));
    DES_set_odd_parity(key);
}

void DES_string_to_2keys(const char *str, DES_cblock *key1, DES_cblock *key2)
{
    DES_key_schedule ks;
    int i, length;

    memset(key1, 0, 8);
    memset(key2, 0, 8);
    length = (int)strlen(str);
    for (i = 0; i < length; i++) {
        unsigned char j = (unsigned char)str[i];
        if ((i % 32) < 16) {
            if ((i % 16) < 8)
                (*key1)[i % 8] ^= (j << 1);
            else
                (*key2)[i % 8] ^= (j << 1);
        } else {
            j = ((j << 4) & 0xf0) | ((j >> 4) & 0x0f);
            j = ((j << 2) & 0xcc) | ((j >> 2) & 0x33);
            j = ((j << 1) & 0xaa) | ((j >> 1) & 0x55);
            if ((i % 16) < 8)
                (*key1)[7 - (i % 8)] ^= j;
            else
                (*key2)[7 - (i % 8)] ^= j;
        }
    }
    if (length <= 8)
        memcpy(key2, key1, 8);
    DES_set_odd_parity(key1);
    DES_set_odd_parity(key2);
    DES_set_key_unchecked(key1, &ks);
    DES_cbc_cksum((const unsigned char *)str, key1, length, &ks, key1);
    DES_set_key_unchecked(key2, &ks);
    DES_cbc_cksum((const unsigned char *)str, key2, length, &ks, key2);
    memset(&ks, 0, sizeof(ks));
    DES_set_odd_parity(key1);
    DES_set_odd_parity(key2);
}
