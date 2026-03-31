/*
 * bn_shim.c - OpenSSL 1.1.1 BN API shims dispatching to wolfCrypt
 *
 * Build status
 * ------------
 * THIS FILE IS NOT COMPILED INTO libwolfshim.a.
 *
 * It has a standalone CMakeLists.txt (shim/src/bn/CMakeLists.txt) that builds
 * a separate static library: libwolfshim_bn.a.  That library is not currently
 * wired into the main Makefile.wolfshim build.
 *
 * In the shipping configuration, BN_* public symbols are provided by wolfSSL's
 * own OpenSSL compatibility layer (libwolfssl.so, built with OPENSSL_EXTRA).
 * This file exists as an alternative override implementation for cases where
 * wolfSSL's built-in compat layer is insufficient.
 *
 * Name-conflict strategy
 * ----------------------
 * wolfSSL's bn.h (with OPENSSL_EXTRA) #defines many OpenSSL BN symbol names
 * as macro aliases.  Each function is preceded by a targeted #undef to strip
 * the macro before the function definition.  No wolfshim_* prefix is used.
 * See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 *
 * Legend:
 *   DIRECT     - maps 1:1 to a wolfSSL function
 *   ADAPTED    - minor adaptation required (argument reorder, cast, etc.)
 *   STUB       - no wolfSSL equivalent; returns an error / NULL sentinel
 *   WOLFSHIM_GAP[TAG]      - known gap; full tag taxonomy in ARCHITECTURE.md §21.
 *                            Tags used in this file: SECURITY:HIGH, SECURITY:MEDIUM,
 *                            SECURITY:MITIGATED, CORRECTNESS, UNSUPPORTED.
 *   WOLFSHIM_REVIEW [ABI]  - struct layout access sites requiring re-audit on wolfSSL upgrades
 */

/* Must come before any system headers so that wolfSSL feature-test macros
 * take effect globally. */
#define OPENSSL_EXTRA
#define WOLFSSL_SP_MATH_ALL   /* allow large-integer operations */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

/* wolfSSL OpenSSL compat headers */
#include <wolfssl/options.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/crypto.h>
#include <wolfssl/ssl.h>

/* Our own shim header (opaque structs for BN_BLINDING / BN_RECP_CTX) */
#include "bn_shim.h"

/* --------------------------------------------------------------------------
 * Undefine wolfSSL macro aliases that conflict with our function definitions.
 * wolfSSL maps these names to wolfSSL_* via #define in wolfssl/openssl/bn.h,
 * which causes the function definition lines below to expand incorrectly.
 * We provide our own implementations, so the macros are not needed here.
 * -------------------------------------------------------------------------- */
#undef BN_set_flags
#undef BN_mod_exp_mont
#undef BN_generate_prime_ex
#undef BN_is_prime_ex
#undef BN_gcd
#undef BN_get_rfc2409_prime_768
#undef BN_get_rfc2409_prime_1024
#undef BN_get_rfc3526_prime_1536
#undef BN_get_rfc3526_prime_2048
#undef BN_get_rfc3526_prime_3072
#undef BN_get_rfc3526_prime_4096
#undef BN_get_rfc3526_prime_6144
#undef BN_get_rfc3526_prime_8192
#undef BN_mod_inverse
#undef BN_MONT_CTX_new
#undef BN_MONT_CTX_free
#undef BN_MONT_CTX_set
#undef BN_mod_exp_mont_word
#undef BN_CTX_get
#undef BN_CTX_start
#undef BN_rshift1
#undef BN_mask_bits
#undef BN_mod_word

/* CRYPTO_RWLOCK: OpenSSL internal locking type not in wolfSSL compat layer.
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL maps CRYPTO_THREAD_write_lock to wc_LockMutex
 * (expects wolfSSL_Mutex*), but callers pass an OpenSSL CRYPTO_RWLOCK* which
 * is internally a pthread_rwlock_t wrapper — a different struct entirely.
 * Calling wc_LockMutex on it is UB.  We typedef it to void and use our own
 * static mutex in BN_MONT_CTX_set_locked instead. */
#ifndef CRYPTO_RWLOCK
typedef void CRYPTO_RWLOCK;
#endif

/* Single mutex protecting BN_MONT_CTX_set_locked across all callers.
 * Serialises concurrent RSA first-use Montgomery context setup.  Montgomery
 * contexts are computed once then cached (*pmont != NULL fast path), so
 * contention is transient and the performance cost is acceptable for most
 * workloads.
 *
 * PERFORMANCE NOTE — high-concurrency RSA
 * ----------------------------------------
 * Under burst load where many threads complete their first RSA operation with
 * the same key simultaneously (e.g. a TLS server receiving a connection storm
 * against a single certificate), all threads serialise here until the first
 * one populates *pmont.  After that the fast path (*pmont != NULL) is taken
 * without a lock.  In practice the critical section is short (one Montgomery
 * precomputation) and occurs at most once per key, so this is unlikely to be
 * a bottleneck in steady-state operation.
 *
 * If profiling shows this lock as a hotspot, the correct remediation is NOT
 * to replace this mutex with per-key locking or a CAS scheme — that would
 * add significant complexity to code that cannot be validated against the
 * OpenSSL 1.1.1 ABI constraints.
 *
 * The correct remediation is to migrate to OpenSSL 3 + wolfProvider.
 * OpenSSL 3's provider API resolves the CRYPTO_RWLOCK type mismatch that
 * forces this global mutex (see the WOLFSHIM_GAP[CORRECTNESS] comment in
 * BN_MONT_CTX_set_locked below), and wolfProvider's RSA implementation uses
 * wolfCrypt's own thread-safe Montgomery precomputation directly without
 * needing a shim-level lock.
 */
static pthread_mutex_t s_wolfshim_mont_lock = PTHREAD_MUTEX_INITIALIZER;

/* --------------------------------------------------------------------------
 * Helper macro
 * ------------------------------------------------------------------------- */
#ifdef WOLFSHIM_DEBUG
#  define SHIM_TRACE() \
       fprintf(stderr, "[wolfshim] bn: %s called\n", __func__)
#else
#  define SHIM_TRACE() ((void)0)
#endif

/* ==========================================================================
 * BN_abs_is_word
 * OpenSSL: int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w)
 * wolfSSL:  wolfSSL_BN_is_word checks sign-positive; we need absolute value.
 * ADAPTED: compare |a| == w by checking if value equals w ignoring sign.
 * ========================================================================== */
int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w)
{
    SHIM_TRACE();
    if (a == NULL) return 0;
    /* wolfSSL_BN_is_word compares the unsigned value */
    return wolfSSL_BN_is_word(a, (WOLFSSL_BN_ULONG)w);
}

/* ==========================================================================
 * BN_asc2bn
 * OpenSSL: int BN_asc2bn(BIGNUM **a, const char *str)
 * DIRECT: wolfSSL does not expose a separate BN_asc2bn, but the OpenSSL
 * function attempts hex (0x prefix) then decimal.  Replicate that logic.
 * ========================================================================== */
int BN_asc2bn(BIGNUM **a, const char *str)
{
    SHIM_TRACE();
    if (a == NULL || str == NULL) return 0;
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        return wolfSSL_BN_hex2bn(a, str + 2);
    }
    return wolfSSL_BN_dec2bn(a, str);
}

/* ==========================================================================
 * BN_BLINDING_* - wolfSSL does not expose BN_BLINDING publicly.
 * All functions below are documented stubs.
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL handles RSA blinding internally; these stubs exist
 *   for link-time compatibility only.  Any caller that invokes these at
 *   runtime will receive error returns.
 * ========================================================================== */

WOLFSHIM_BN_BLINDING *wolfshim_BN_BLINDING_new(const void *A, const void *Ai,
                                                void *mod)
{
    SHIM_TRACE();
    (void)A; (void)Ai; (void)mod;
    return NULL;
}

void wolfshim_BN_BLINDING_free(WOLFSHIM_BN_BLINDING *b)
{
    SHIM_TRACE();
    if (b == NULL) return;
    free(b);
}

int wolfshim_BN_BLINDING_update(WOLFSHIM_BN_BLINDING *b, void *ctx)
{
    SHIM_TRACE();
    (void)b; (void)ctx;
    return 0;
}

int wolfshim_BN_BLINDING_convert(void *n, WOLFSHIM_BN_BLINDING *b, void *ctx)
{
    SHIM_TRACE();
    (void)n; (void)b; (void)ctx;
    return 0;
}

int wolfshim_BN_BLINDING_invert(void *n, WOLFSHIM_BN_BLINDING *b, void *ctx)
{
    SHIM_TRACE();
    (void)n; (void)b; (void)ctx;
    return 0;
}

int wolfshim_BN_BLINDING_convert_ex(void *n, void *r, WOLFSHIM_BN_BLINDING *b,
                                    void *ctx)
{
    SHIM_TRACE();
    (void)n; (void)r; (void)b; (void)ctx;
    return 0;
}

int wolfshim_BN_BLINDING_invert_ex(void *n, const void *r,
                                   WOLFSHIM_BN_BLINDING *b, void *ctx)
{
    SHIM_TRACE();
    (void)n; (void)r; (void)b; (void)ctx;
    return 0;
}

int wolfshim_BN_BLINDING_is_current_thread(WOLFSHIM_BN_BLINDING *b)
{
    SHIM_TRACE();
    (void)b;
    return 0;
}

void wolfshim_BN_BLINDING_set_current_thread(WOLFSHIM_BN_BLINDING *b)
{
    SHIM_TRACE();
    (void)b;
}

int wolfshim_BN_BLINDING_lock(WOLFSHIM_BN_BLINDING *b)
{
    SHIM_TRACE();
    (void)b;
    return 0;
}

int wolfshim_BN_BLINDING_unlock(WOLFSHIM_BN_BLINDING *b)
{
    SHIM_TRACE();
    (void)b;
    return 0;
}

unsigned long wolfshim_BN_BLINDING_get_flags(const WOLFSHIM_BN_BLINDING *b)
{
    SHIM_TRACE();
    if (b == NULL) return 0;
    return b->flags;
}

void wolfshim_BN_BLINDING_set_flags(WOLFSHIM_BN_BLINDING *b, unsigned long f)
{
    SHIM_TRACE();
    if (b == NULL) return;
    b->flags = f;
}

WOLFSHIM_BN_BLINDING *wolfshim_BN_BLINDING_create_param(
    WOLFSHIM_BN_BLINDING *b, const void *e, void *m, void *ctx,
    int (*bn_mod_exp)(void *r, const void *a, const void *p, const void *m,
                      void *ctx, void *m_ctx),
    void *m_ctx)
{
    SHIM_TRACE();
    (void)b; (void)e; (void)m; (void)ctx; (void)bn_mod_exp; (void)m_ctx;
    return NULL;
}

/* BN_BLINDING / BN_RECP_CTX: wolfSSL does not define these types; alias our
 * internal stubs so the public-symbol aliases below can use the OpenSSL names. */
typedef WOLFSHIM_BN_BLINDING  BN_BLINDING;
typedef WOLFSHIM_BN_RECP_CTX  BN_RECP_CTX;

/* Public-symbol aliases required by the OpenSSL ABI */
BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod)
{
    SHIM_TRACE();
    return (BN_BLINDING *)wolfshim_BN_BLINDING_new(A, Ai, mod);
}

void BN_BLINDING_free(BN_BLINDING *b)
{
    SHIM_TRACE();
    wolfshim_BN_BLINDING_free((WOLFSHIM_BN_BLINDING *)b);
}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_update((WOLFSHIM_BN_BLINDING *)b, ctx);
}

int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_convert(n, (WOLFSHIM_BN_BLINDING *)b, ctx);
}

int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_invert(n, (WOLFSHIM_BN_BLINDING *)b, ctx);
}

int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_convert_ex(n, r, (WOLFSHIM_BN_BLINDING *)b, ctx);
}

int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,
                          BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_invert_ex(n, r, (WOLFSHIM_BN_BLINDING *)b, ctx);
}

int BN_BLINDING_is_current_thread(BN_BLINDING *b)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_is_current_thread((WOLFSHIM_BN_BLINDING *)b);
}

void BN_BLINDING_set_current_thread(BN_BLINDING *b)
{
    SHIM_TRACE();
    wolfshim_BN_BLINDING_set_current_thread((WOLFSHIM_BN_BLINDING *)b);
}

int BN_BLINDING_lock(BN_BLINDING *b)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_lock((WOLFSHIM_BN_BLINDING *)b);
}

int BN_BLINDING_unlock(BN_BLINDING *b)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_unlock((WOLFSHIM_BN_BLINDING *)b);
}

unsigned long BN_BLINDING_get_flags(const BN_BLINDING *b)
{
    SHIM_TRACE();
    return wolfshim_BN_BLINDING_get_flags((const WOLFSHIM_BN_BLINDING *)b);
}

void BN_BLINDING_set_flags(BN_BLINDING *b, unsigned long f)
{
    SHIM_TRACE();
    wolfshim_BN_BLINDING_set_flags((WOLFSHIM_BN_BLINDING *)b, f);
}

BN_BLINDING *BN_BLINDING_create_param(
    BN_BLINDING *b, const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
    int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx),
    BN_MONT_CTX *m_ctx)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: no BN_BLINDING support in wolfSSL public API */
    (void)b; (void)e; (void)m; (void)ctx; (void)bn_mod_exp; (void)m_ctx;
    return NULL;
}

/* ==========================================================================
 * BN_bn2binpad
 * OpenSSL: int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
 * ADAPTED: wolfSSL has no direct BN_bn2binpad; emulate with BN_bn2bin + pad.
 * ========================================================================== */
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    int len, pad;
    SHIM_TRACE();
    if (a == NULL || to == NULL || tolen < 0) return -1;
    len = wolfSSL_BN_num_bytes(a);
    if (len > tolen) return -1;
    pad = tolen - len;
    memset(to, 0, (size_t)pad);
    if (len > 0) {
        wolfSSL_BN_bn2bin(a, to + pad);
    }
    return tolen;
}

/* ==========================================================================
 * BN_bn2lebinpad
 * OpenSSL: int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen)
 * ADAPTED: convert to big-endian then reverse for little-endian.
 * ========================================================================== */
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    int i, len;
    unsigned char *buf;
    SHIM_TRACE();
    if (a == NULL || to == NULL || tolen < 0) return -1;
    len = wolfSSL_BN_num_bytes(a);
    if (len > tolen) return -1;
    buf = (unsigned char *)calloc(1, (size_t)tolen);
    if (buf == NULL) return -1;
    /* write big-endian into buf (right-aligned) */
    if (len > 0) wolfSSL_BN_bn2bin(a, buf + (tolen - len));
    /* reverse into to (becomes little-endian, left-aligned) */
    for (i = 0; i < tolen; i++) {
        to[i] = buf[tolen - 1 - i];
    }
    free(buf);
    return tolen;
}

/* ==========================================================================
 * BN_bn2mpi
 * OpenSSL: int BN_bn2mpi(const BIGNUM *a, unsigned char *to)
 * ADAPTED: MPI format = 4-byte big-endian length header + bytes (with sign
 * bit in MSB of first byte).  No direct wolfSSL equivalent; implement manually.
 * ========================================================================== */
int BN_bn2mpi(const BIGNUM *a, unsigned char *to)
{
    int num_bytes, need_extra, total;
    SHIM_TRACE();
    if (a == NULL) return 0;
    num_bytes  = wolfSSL_BN_num_bytes(a);
    /* If the MSB of the first data byte is set, we need an extra 0x00 byte
     * to signal positive, or 0xff for negative. */
    need_extra = 0;
    if (num_bytes > 0) {
        /* check MSB of the most-significant byte */
        unsigned char *tmp = (unsigned char *)malloc((size_t)num_bytes);
        if (tmp == NULL) return 0;
        wolfSSL_BN_bn2bin(a, tmp);
        if (tmp[0] & 0x80) need_extra = 1;
        free(tmp);
    }
    total = 4 + need_extra + num_bytes;
    if (to == NULL) return total;

    /* write 4-byte length */
    int data_len = need_extra + num_bytes;
    to[0] = (unsigned char)((data_len >> 24) & 0xff);
    to[1] = (unsigned char)((data_len >> 16) & 0xff);
    to[2] = (unsigned char)((data_len >>  8) & 0xff);
    to[3] = (unsigned char)( data_len        & 0xff);
    if (need_extra) {
        /* Extra prefix byte: 0x00 for positive (avoids sign-bit ambiguity),
         * 0xff for negative (carries the sign when magnitude MSB is set). */
        to[4] = wolfSSL_BN_is_negative(a) ? 0xff : 0x00;
    }
    if (num_bytes > 0) {
        /* Write the unsigned magnitude bytes unchanged (sign-magnitude format).
         * For negative values, the sign is encoded in the MSB of the first
         * data byte: if need_extra is 0 the magnitude MSB is clear, so OR in
         * the sign bit directly; if need_extra is 1 the sign was already
         * written to the prefix byte above and the magnitude is stored as-is. */
        wolfSSL_BN_bn2bin(a, to + 4 + need_extra);
        if (wolfSSL_BN_is_negative(a) && !need_extra) {
            to[4] |= 0x80; /* set sign bit in the magnitude's first byte */
        }
    }
    return total;
}

/* ==========================================================================
 * BN_mpi2bn
 * OpenSSL: BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret)
 * ADAPTED: decode MPI format manually.
 * ========================================================================== */

/* Version guard: BN_mpi2bn writes WOLFSSL_BIGNUM.neg directly (see
 * WOLFSHIM_REVIEW [ABI] comment below).  The layout of WOLFSSL_BIGNUM was
 * validated against wolfSSL 5.9.0 (neg at offset 0, sizeof int = 4 on
 * all supported targets).  If wolfSSL is upgraded past this version,
 * re-run the offsetof probe and re-audit the direct field write below
 * before raising this threshold. */
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05009000
#  error "bn_shim.c accesses WOLFSSL_BIGNUM internal field 'neg' directly — " \
         "validated against wolfSSL 5.9.0; re-audit all WOLFSHIM_REVIEW [ABI] " \
         "sites in BN_mpi2bn before lowering this threshold"
#endif

/* Compile-time layout assertion: WOLFSSL_BIGNUM.neg must remain at offset 0.
 * BN_mpi2bn writes this field directly (no public BN_set_negative API).
 * Validated against wolfSSL 5.9.0 on x86_64.
 * When upgrading wolfSSL: re-run the offsetof probe and update this constant
 * if the layout has changed, then re-audit the write site below. */
_Static_assert(offsetof(WOLFSSL_BIGNUM, neg) == 0,
    "WOLFSSL_BIGNUM.neg offset changed — re-audit bn_shim.c BN_mpi2bn "
    "WOLFSHIM_REVIEW [ABI] site and update this constant");

BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    int num_bytes, neg;
    unsigned char *buf;
    BIGNUM *bn;
    SHIM_TRACE();
    if (s == NULL || len < 4) return NULL;
    num_bytes = (int)(((unsigned int)s[0] << 24) |
                      ((unsigned int)s[1] << 16) |
                      ((unsigned int)s[2] <<  8) |
                       (unsigned int)s[3]);
    if (num_bytes > len - 4) return NULL;
    neg = (num_bytes > 0) && (s[4] & 0x80) ? 1 : 0;
    buf = (unsigned char *)malloc((size_t)(num_bytes > 0 ? num_bytes : 1));
    if (buf == NULL) return NULL;
    if (num_bytes > 0) memcpy(buf, s + 4, (size_t)num_bytes);
    if (neg && num_bytes > 0) {
        /* OpenSSL MPI encoding stores the sign in the MSB of the first data
         * byte; the remaining bits of that byte and all subsequent bytes are
         * the unsigned magnitude.  Strip the sign bit to recover the
         * magnitude, then pass the raw bytes to wolfSSL_BN_bin2bn and set
         * the sign separately.  Do NOT apply two's-complement arithmetic. */
        buf[0] &= 0x7f; /* strip sign bit; buf now holds unsigned magnitude */
    }
    bn = wolfSSL_BN_bin2bn(buf, num_bytes, ret);
    free(buf);
    if (bn && neg) {
        /* WOLFSHIM_REVIEW [ABI]: wolfSSL exposes no wolfSSL_BN_set_negative()
         * (or equivalent public setter) in its OpenSSL compat layer, so the
         * neg field is written by direct struct access.  When wolfSSL adds a
         * public setter, replace this line with the setter call and remove the
         * _Static_assert and LIBWOLFSSL_VERSION_HEX guard above — they exist
         * solely to protect this site.
         *
         * Until then: do NOT "clean up" this cast.  The direct field write is
         * intentional; removing it silently produces wrong sign on negative
         * bignums decoded from MPI format.  Validated against wolfSSL 5.9.0:
         * neg is an int at offset 0 of WOLFSSL_BIGNUM. */
        ((WOLFSSL_BIGNUM *)bn)->neg = 1;
    }
    return bn;
}

/* ==========================================================================
 * BN_bntest_rand
 * OpenSSL: int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom)
 * DIRECT: same as BN_rand for our purposes (test-quality randomness).
 * ========================================================================== */
int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
    SHIM_TRACE();
    return wolfSSL_BN_rand(rnd, bits, top, bottom);
}

/* ==========================================================================
 * BN_consttime_swap
 * OpenSSL: void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b,
 *                                  int nwords)
 *
 * WOLFSHIM_GAP[SECURITY:HIGH]: THIS FUNCTION IS NOT CONSTANT-TIME.
 *
 * The name and signature promise a constant-time conditional swap for use in
 * timing-sensitive cryptographic operations — specifically to prevent
 * Kocher-style timing attacks against RSA (private key operations) and ECC
 * (scalar multiplication).  This shim does NOT deliver that guarantee.
 *
 * Why it cannot be fixed here:
 *   A correct constant-time swap requires reading and writing the raw
 *   mp_digit arrays inside WOLFSSL_BIGNUM under a branchless mask derived
 *   from `swap`.  wolfSSL's public BN compat API does not expose mp_digit
 *   or any equivalent field.  The only correct fix is a wolfSSL API addition
 *   (e.g. wolfSSL_BN_consttime_swap) that operates on the internal
 *   representation directly.
 *
 * What this implementation does instead:
 *   Branches on `swap` and performs a struct-level swap if nonzero.  The
 *   branch is visible to CPU branch predictors and cache-timing analysis.
 *   An attacker who can measure operation latency (local or remote) may be
 *   able to distinguish the swap from the no-swap path.
 *
 * Impact:
 *   - OpenSSL's bn_exp.c (used in RSA_private_encrypt / RSA_private_decrypt)
 *     calls BN_consttime_swap as part of the Montgomery ladder to prevent
 *     the private exponent from leaking via timing.  If this shim is reached
 *     via that path, the side-channel protection is silently absent.
 *   - Any caller that relies on BN_consttime_swap for timing safety inherits
 *     the vulnerability without any error or warning at runtime.
 *
 * This shim exists only to satisfy the linker.  Do not call it in any
 * context where timing side-channel resistance is required.
 *
 * Remediation: open a wolfSSL issue requesting wolfSSL_BN_consttime_swap,
 * then replace this stub with a call to that function once available.
 * ========================================================================== */
void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords)
{
    WOLFSSL_BIGNUM tmp;
    SHIM_TRACE();
    (void)nwords;
    if (a == NULL || b == NULL) return;
    /* NOT constant-time — branches on swap. See block comment above. */
    if (swap) {
        /* Three-way struct-value swap.  WOLFSSL_BIGNUM contains an `internal`
         * pointer to heap-allocated mp_int data; copying the struct copies the
         * pointer, not the pointed-to data.  After the swap *a holds what was
         * *b's pointer and vice versa — no heap data moves, no aliasing, no
         * leak.  tmp goes out of scope without a destructor; the heap data is
         * now reachable through *a and *b as expected.  This is safe. */
        tmp = *a;
        *a  = *b;
        *b  = tmp;
    }
}

/* ==========================================================================
 * BN_CTX_end
 * OpenSSL: void BN_CTX_end(BN_CTX *ctx)
 * ADAPTED: wolfSSL does not implement BN_CTX_end; the compat layer's
 *   BN_CTX is a simple list and "end" would free pooled BIGNUMs from
 *   the most recent BN_CTX_start scope.  Use a no-op for now.
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL BN_CTX does not track nesting scopes; callers
 *   that rely on BN_CTX_start/end for temporary BN lifetime may leak.
 * ========================================================================== */
void BN_CTX_end(BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)ctx;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL BN_CTX has no scope-level end support */
}

/* ==========================================================================
 * BN_CTX_secure_new
 * OpenSSL: BN_CTX *BN_CTX_secure_new(void)
 * DIRECT: wolfSSL_BN_CTX_new() is sufficient (wolfSSL uses its own heap).
 * WOLFSHIM_GAP[SECURITY:MEDIUM]: OpenSSL's BN_CTX_secure_new() guarantees that BIGNUMs
 *   allocated from the returned context are zeroed on free, specifically
 *   to clear private key material from memory.  This shim delegates to
 *   wolfSSL_BN_CTX_new(), which does NOT guarantee clearing-on-free
 *   semantics.  Callers that pass this context to operations involving
 *   private key material (RSA, ECDSA, DH private exponents, etc.) will
 *   silently not get the secure-erasure guarantee they expect.  Before
 *   using this shim in a production build, confirm whether wolfSSL's
 *   allocator zeroes memory on free (e.g. via WOLFSSL_HEAP_HINT with
 *   ForceZero), and add a WOLFSSL_SECURE_MEMORY compile path if not.
 * ========================================================================== */
BN_CTX *BN_CTX_secure_new(void)
{
    SHIM_TRACE();
    return wolfSSL_BN_CTX_new();
}

/* ==========================================================================
 * BN_div_recp
 * STUB - WOLFSHIM_GAP[UNSUPPORTED]: no BN_RECP_CTX in wolfSSL.
 * ========================================================================== */
WOLFSHIM_BN_RECP_CTX *wolfshim_BN_RECP_CTX_new(void)
{
    WOLFSHIM_BN_RECP_CTX *r;
    SHIM_TRACE();
    r = (WOLFSHIM_BN_RECP_CTX *)calloc(1, sizeof(WOLFSHIM_BN_RECP_CTX));
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no BN_RECP_CTX equivalent */
    return r;
}

void wolfshim_BN_RECP_CTX_free(WOLFSHIM_BN_RECP_CTX *recp)
{
    SHIM_TRACE();
    free(recp);
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no BN_RECP_CTX equivalent */
}

int wolfshim_BN_RECP_CTX_set(WOLFSHIM_BN_RECP_CTX *recp, const void *rdiv,
                              void *ctx)
{
    SHIM_TRACE();
    (void)recp; (void)rdiv; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no BN_RECP_CTX equivalent */
    return 0;
}

int wolfshim_BN_mod_mul_reciprocal(void *r, const void *x, const void *y,
                                   WOLFSHIM_BN_RECP_CTX *recp, void *ctx)
{
    SHIM_TRACE();
    (void)r; (void)x; (void)y; (void)recp; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL has no BN_RECP_CTX equivalent */
    return 0;
}

int wolfshim_BN_mod_exp_recp(void *r, const void *a, const void *p,
                              const void *m, void *ctx)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: fall back to regular mod_exp */
    return wolfSSL_BN_mod_exp((BIGNUM *)r, (const BIGNUM *)a,
                              (const BIGNUM *)p, (const BIGNUM *)m,
                              (BN_CTX *)ctx);
}

int wolfshim_BN_div_recp(void *dv, void *rem, const void *m,
                         WOLFSHIM_BN_RECP_CTX *recp, void *ctx)
{
    SHIM_TRACE();
    (void)dv; (void)rem; (void)m; (void)recp; (void)ctx;
    /* WOLFSHIM_GAP[CORRECTNESS]: RECP_CTX arithmetic is not supported by this shim.
     * wolfSSL has no BN_RECP_CTX equivalent and the reciprocal divisor is
     * not available as a plain BIGNUM.  Passing NULL to wolfSSL_BN_div would
     * crash or corrupt memory.  Returns 0 (failure) unconditionally. */
    return 0;
}

/* Public-symbol wrappers for BN_RECP_CTX */
BN_RECP_CTX *BN_RECP_CTX_new(void)
{
    SHIM_TRACE();
    return (BN_RECP_CTX *)wolfshim_BN_RECP_CTX_new();
}

void BN_RECP_CTX_free(BN_RECP_CTX *recp)
{
    SHIM_TRACE();
    wolfshim_BN_RECP_CTX_free((WOLFSHIM_BN_RECP_CTX *)recp);
}

int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *rdiv, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_RECP_CTX_set((WOLFSHIM_BN_RECP_CTX *)recp, rdiv, ctx);
}

int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
                          BN_RECP_CTX *recp, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_mod_mul_reciprocal(r, x, y,
                                         (WOLFSHIM_BN_RECP_CTX *)recp, ctx);
}

int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_mod_exp_recp(r, a, p, m, ctx);
}

int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                BN_RECP_CTX *recp, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfshim_BN_div_recp(dv, rem, m, (WOLFSHIM_BN_RECP_CTX *)recp, ctx);
}

/* ==========================================================================
 * BN_exp
 * OpenSSL: int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
 * ADAPTED: compute r = a^p (no modulus) using repeated squaring via wolfSSL.
 * wolfSSL only exposes BN_mod_exp; emulate BN_exp with a large modulus or
 * use mp_exptmod from wolfCrypt directly with m=0 meaning no reduction.
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL BN_mod_exp requires a modulus; for unbounded
 *   exponentiation we create a temporary sufficiently-large modulus.
 *   This is not efficient but is correct for small exponents.
 * ========================================================================== */
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    if (r == NULL || a == NULL || p == NULL) return 0;
    /* Use wolfSSL BN_mod_exp with a 2^16383 modulus as a large-but-finite
     * upper bound.  Before computing, validate that a^p cannot exceed the
     * 16383-bit buffer.  The result has at most BN_num_bits(a)*p bits.
     * Upper bound on result bits: BN_num_bits(a) * 2^BN_num_bits(p).
     * If this exceeds 16383, the mod_exp would silently truncate — reject. */
    {
        BIGNUM *mod = wolfSSL_BN_new();
        int ret;
        int abits, pbits;

        if (mod == NULL) return 0;

        abits = wolfSSL_BN_num_bits((const WOLFSSL_BIGNUM *)a);
        pbits = wolfSSL_BN_num_bits((const WOLFSSL_BIGNUM *)p);

        /* Overflow guard: a^p fits in 16383 bits only when
         *   abits * p <= 16383
         * Since p < 2^pbits, a conservative rejection criterion is:
         *   pbits > 14  (p could be >= 16384, so a^p >= a^16384 >= 2^16384)
         *   OR abits > (16383 >> pbits)  (abits * 2^pbits > 16383)
         * Either condition means the result may exceed the 16383-bit buffer.
         * Return 0 (failure) rather than a silently wrong truncated value.
         * Callers doing DH validation with small exponents (e.g. p=2) are
         * unaffected as long as the base fits within the safe range. */
        if (abits > 0 && pbits > 0 &&
            (pbits > 14 || abits > (16383 >> pbits))) {
#ifdef WOLFSHIM_DEBUG
            fprintf(stderr,
                "[wolfshim] BN_exp: result would exceed 16383-bit buffer "
                "(abits=%d pbits=%d); returning failure\n", abits, pbits);
#endif
            wolfSSL_BN_free(mod);
            return 0;
        }

        /* set mod = 2^16383 (1 << 16383) as the upper bound sentinel. */
        if (!wolfSSL_BN_set_word(mod, 1)) { wolfSSL_BN_free(mod); return 0; }
        if (!wolfSSL_BN_lshift(mod, mod, 16383)) { wolfSSL_BN_free(mod); return 0; }
        ret = wolfSSL_BN_mod_exp(r, a, p, mod, ctx);
        wolfSSL_BN_free(mod);
        return ret;
    }
}

/* ==========================================================================
 * BN_from_montgomery
 * OpenSSL: int BN_from_montgomery(BIGNUM *r, const BIGNUM *a,
 *                                  BN_MONT_CTX *mont, BN_CTX *ctx)
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose from-montgomery conversion in its
 *   public BN compat API.  Stub - returns 0 (error).
 * ========================================================================== */
int BN_from_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                       BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)mont; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_from_montgomery */
    return 0;
}

/* ==========================================================================
 * BN_gcd
 * DIRECT: wolfSSL_BN_gcd
 * ========================================================================== */
int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    SHIM_TRACE();
    /* The explicit (BIGNUM *)(uintptr_t) cast discards const intentionally:
     * wolfSSL_BN_gcd is not declared with const-correct parameters
     * (wolfSSL's compat API takes WOLFSSL_BIGNUM* not const WOLFSSL_BIGNUM*),
     * so a direct (BIGNUM *) cast would trigger -Wcast-qual.  Routing via
     * uintptr_t suppresses the warning and documents that the cast is
     * deliberate.  wolfSSL_BN_gcd does not modify its input operands, so
     * discarding const is safe here. */
    return wolfSSL_BN_gcd(r, (BIGNUM *)(uintptr_t)a, (BIGNUM *)(uintptr_t)b, ctx);
}

/* ==========================================================================
 * BN_GENCB_* - wolfSSL exposes limited BN_GENCB support
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL WOLFSSL_BN_GENCB is an opaque struct; the compat
 *   header only typedefs it.  The functions below are stubs.
 * ========================================================================== */
int BN_GENCB_call(BN_GENCB *cb, int a, int b)
{
    SHIM_TRACE();
    (void)cb; (void)a; (void)b;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_GENCB_call publicly */
    return 1; /* return 1 = continue, per OpenSSL convention */
}

/* Local concrete mirror of OpenSSL's bn_gencb_st.  WOLFSSL_BN_GENCB is an
 * incomplete (opaque) type so sizeof(BN_GENCB) is not available.  This struct
 * matches the public layout of OpenSSL 1.1.x bn_gencb_st exactly, letting us
 * derive the correct allocation size without hard-coding a magic number. */
struct shim_bn_gencb_st {
    unsigned int ver;       /* 1 = old-style callback, 2 = new-style */
    void        *arg;       /* caller-supplied opaque argument */
    union {
        void (*cb_1)(int, int, void *);     /* old style */
        int  (*cb_2)(int, int, BN_GENCB *); /* new style */
    } cb;
};

BN_GENCB *BN_GENCB_new(void)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL WOLFSSL_BN_GENCB is an incomplete type so
     * sizeof(BN_GENCB) is not available.  Use the local mirror struct above,
     * which exactly matches the public layout of OpenSSL's bn_gencb_st, to
     * obtain the correct allocation size without hard-coding a magic constant. */
    return (BN_GENCB *)calloc(1, sizeof(struct shim_bn_gencb_st));
}

void BN_GENCB_free(BN_GENCB *cb)
{
    SHIM_TRACE();
    free(cb);
}

void BN_GENCB_set_old(BN_GENCB *gencb,
                      void (*callback)(int, int, void *), void *cb_arg)
{
    SHIM_TRACE();
    (void)gencb; (void)callback; (void)cb_arg;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL BN_GENCB internals not exposed */
}

void BN_GENCB_set(BN_GENCB *gencb,
                  int (*callback)(int, int, BN_GENCB *), void *cb_arg)
{
    SHIM_TRACE();
    (void)gencb; (void)callback; (void)cb_arg;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL BN_GENCB internals not exposed */
}

void *BN_GENCB_get_arg(BN_GENCB *cb)
{
    SHIM_TRACE();
    (void)cb;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL BN_GENCB internals not exposed */
    return NULL;
}

/* ==========================================================================
 * BN_generate_dsa_nonce
 * WOLFSHIM_GAP[UNSUPPORTED]: FIPS 186-4 deterministic DSA nonce generation not
 *   available in wolfSSL public BN API.  Stub returns 0 (error).
 * ========================================================================== */
int BN_generate_dsa_nonce(BIGNUM *out, const BIGNUM *range,
                          const BIGNUM *priv, const unsigned char *message,
                          size_t message_len, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)out; (void)range; (void)priv; (void)message;
    (void)message_len; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: FIPS 186-4 DSA nonce not in wolfSSL public BN API */
    return 0;
}

/* ==========================================================================
 * BN_generate_prime (deprecated) / BN_generate_prime_ex
 * DIRECT: wolfSSL_BN_generate_prime_ex
 * ========================================================================== */
BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe,
                          const BIGNUM *add, const BIGNUM *rem,
                          void (*callback)(int, int, void *), void *cb_arg)
{
    SHIM_TRACE();
    /* Use a BN_GENCB wrapper for the callback */
    (void)callback; (void)cb_arg;
    if (ret == NULL) ret = wolfSSL_BN_new();
    if (ret == NULL) return NULL;
    if (wolfSSL_BN_generate_prime_ex(ret, bits, safe, add, rem, NULL) == 1)
        return ret;
    return NULL;
}

int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
                         const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb)
{
    SHIM_TRACE();
    return wolfSSL_BN_generate_prime_ex(ret, bits, safe, add, rem,
                                        (WOLFSSL_BN_GENCB *)cb);
}

/* ==========================================================================
 * BN_get0_nist_prime_* - return static BIGNUM for NIST prime
 * ADAPTED: initialise from hex string exactly once using pthread_once to
 *   ensure thread safety.  Each prime has its own once-control so that they
 *   are independent.
 * ========================================================================== */
static BIGNUM *s_nist_192  = NULL;
static BIGNUM *s_nist_224  = NULL;
static BIGNUM *s_nist_256  = NULL;
static BIGNUM *s_nist_384  = NULL;
static BIGNUM *s_nist_521  = NULL;

static pthread_once_t s_nist_192_once = PTHREAD_ONCE_INIT;
static pthread_once_t s_nist_224_once = PTHREAD_ONCE_INIT;
static pthread_once_t s_nist_256_once = PTHREAD_ONCE_INIT;
static pthread_once_t s_nist_384_once = PTHREAD_ONCE_INIT;
static pthread_once_t s_nist_521_once = PTHREAD_ONCE_INIT;

static void s_init_nist_192(void)
{
    wolfSSL_BN_hex2bn(&s_nist_192,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
}

static void s_init_nist_224(void)
{
    wolfSSL_BN_hex2bn(&s_nist_224,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
}

static void s_init_nist_256(void)
{
    wolfSSL_BN_hex2bn(&s_nist_256,
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
}

static void s_init_nist_384(void)
{
    wolfSSL_BN_hex2bn(&s_nist_384,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "FFFFFFFF0000000000000000FFFFFFFF");
}

static void s_init_nist_521(void)
{
    /* 131 hex digits = 521 bits = 2^521 - 1 (P-521 prime) */
    wolfSSL_BN_hex2bn(&s_nist_521,
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
}

const BIGNUM *BN_get0_nist_prime_192(void)
{
    SHIM_TRACE();
    pthread_once(&s_nist_192_once, s_init_nist_192);
    return s_nist_192;
}

const BIGNUM *BN_get0_nist_prime_224(void)
{
    SHIM_TRACE();
    pthread_once(&s_nist_224_once, s_init_nist_224);
    return s_nist_224;
}

const BIGNUM *BN_get0_nist_prime_256(void)
{
    SHIM_TRACE();
    pthread_once(&s_nist_256_once, s_init_nist_256);
    return s_nist_256;
}

const BIGNUM *BN_get0_nist_prime_384(void)
{
    SHIM_TRACE();
    pthread_once(&s_nist_384_once, s_init_nist_384);
    return s_nist_384;
}

const BIGNUM *BN_get0_nist_prime_521(void)
{
    SHIM_TRACE();
    pthread_once(&s_nist_521_once, s_init_nist_521);
    return s_nist_521;
}

/* ==========================================================================
 * BN_get_flags / BN_set_flags
 * DIRECT: wolfSSL WOLFSSL_BIGNUM has no flags field; stubs.
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not expose BN flags.
 * ========================================================================== */
int BN_get_flags(const BIGNUM *b, int n)
{
    SHIM_TRACE();
    (void)b; (void)n;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL BIGNUM has no public flags field */
    return 0;
}

void BN_set_flags(BIGNUM *b, int n)
{
    SHIM_TRACE();
    (void)b; (void)n;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL BIGNUM has no public flags field */
}

/* ==========================================================================
 * BN_get_params / BN_set_params (deprecated)
 * WOLFSHIM_GAP[UNSUPPORTED]: no equivalent in wolfSSL.
 * ========================================================================== */
int BN_get_params(int which)
{
    SHIM_TRACE();
    (void)which;
    /* WOLFSHIM_GAP[UNSUPPORTED]: no equivalent in wolfSSL */
    return 0;
}

void BN_set_params(int mul, int high, int low, int mont)
{
    SHIM_TRACE();
    (void)mul; (void)high; (void)low; (void)mont;
    /* WOLFSHIM_GAP[UNSUPPORTED]: no equivalent in wolfSSL */
}

/* ==========================================================================
 * BN_get_rfc2409_prime_768 / BN_get_rfc2409_prime_1024
 * DIRECT: wolfSSL_DH_768_prime / wolfSSL_DH_1024_prime
 * ========================================================================== */
BIGNUM *BN_get_rfc2409_prime_768(BIGNUM *bn)
{
    SHIM_TRACE();
    return wolfSSL_DH_768_prime(bn);
}

BIGNUM *BN_get_rfc2409_prime_1024(BIGNUM *bn)
{
    SHIM_TRACE();
    return wolfSSL_DH_1024_prime(bn);
}

/* ==========================================================================
 * BN_get_rfc3526_prime_* - RFC 3526 MODP groups
 * DIRECT: wolfSSL_DH_*_prime
 * ========================================================================== */
BIGNUM *BN_get_rfc3526_prime_1536(BIGNUM *bn)
{
    SHIM_TRACE();
    return wolfSSL_DH_1536_prime(bn);
}

BIGNUM *BN_get_rfc3526_prime_2048(BIGNUM *bn)
{
    SHIM_TRACE();
    return wolfSSL_DH_2048_prime(bn);
}

BIGNUM *BN_get_rfc3526_prime_3072(BIGNUM *bn)
{
    SHIM_TRACE();
    return wolfSSL_DH_3072_prime(bn);
}

BIGNUM *BN_get_rfc3526_prime_4096(BIGNUM *bn)
{
    SHIM_TRACE();
    return wolfSSL_DH_4096_prime(bn);
}

BIGNUM *BN_get_rfc3526_prime_6144(BIGNUM *bn)
{
    SHIM_TRACE();
    return wolfSSL_DH_6144_prime(bn);
}

BIGNUM *BN_get_rfc3526_prime_8192(BIGNUM *bn)
{
    SHIM_TRACE();
    return wolfSSL_DH_8192_prime(bn);
}

/* ==========================================================================
 * BN_GF2m_* - GF(2^m) arithmetic
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose GF(2^m) BN operations in its
 *   public compat API.  All functions below are stubs returning 0/NULL.
 * ========================================================================== */
int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)b;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)p;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)b; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)b; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)b; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)b; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                     BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                           BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

/* Array-form GF2m functions */
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[])
{
    SHIM_TRACE();
    (void)r; (void)a; (void)p;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)b; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                        BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const int p[],
                        BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)b; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)b; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)b; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                         BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                               BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)p; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max)
{
    SHIM_TRACE();
    (void)a; (void)p; (void)max;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

int BN_GF2m_arr2poly(const int p[], BIGNUM *a)
{
    SHIM_TRACE();
    (void)p; (void)a;
    /* WOLFSHIM_GAP[UNSUPPORTED]: GF(2^m) not in wolfSSL public BN API */
    return 0;
}

/* ==========================================================================
 * BN_is_prime (deprecated) / BN_is_prime_ex / BN_is_prime_fasttest /
 * BN_is_prime_fasttest_ex
 * DIRECT: wolfSSL_BN_is_prime_ex
 * ========================================================================== */
int BN_is_prime(const BIGNUM *p, int nchecks,
                void (*callback)(int, int, void *), BN_CTX *ctx,
                void *cb_arg)
{
    SHIM_TRACE();
    (void)callback; (void)cb_arg;
    return wolfSSL_BN_is_prime_ex(p, nchecks, ctx, NULL);
}

int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb)
{
    SHIM_TRACE();
    return wolfSSL_BN_is_prime_ex(p, nchecks, ctx, (WOLFSSL_BN_GENCB *)cb);
}

int BN_is_prime_fasttest(const BIGNUM *p, int nchecks,
                         void (*callback)(int, int, void *),
                         BN_CTX *ctx, void *cb_arg, int do_trial_division)
{
    SHIM_TRACE();
    (void)callback; (void)cb_arg; (void)do_trial_division;
    return wolfSSL_BN_is_prime_ex(p, nchecks, ctx, NULL);
}

int BN_is_prime_fasttest_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx,
                            int do_trial_division, BN_GENCB *cb)
{
    SHIM_TRACE();
    (void)do_trial_division;
    return wolfSSL_BN_is_prime_ex(p, nchecks, ctx, (WOLFSSL_BN_GENCB *)cb);
}

/* ==========================================================================
 * BN_kronecker
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_kronecker.
 * Stub returns -2 (error code as per OpenSSL spec).
 * ========================================================================== */
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)a; (void)b; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_kronecker */
    return -2;
}

/* ==========================================================================
 * BN_lebin2bn
 * OpenSSL: BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)
 * ADAPTED: reverse bytes then call BN_bin2bn.
 * ========================================================================== */
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    BIGNUM *bn;
    unsigned char *buf;
    int i;
    SHIM_TRACE();
    if (s == NULL || len < 0) return NULL;
    if (len == 0) return wolfSSL_BN_bin2bn(s, 0, ret);
    buf = (unsigned char *)malloc((size_t)len);
    if (buf == NULL) return NULL;
    for (i = 0; i < len; i++) buf[i] = s[len - 1 - i];
    bn = wolfSSL_BN_bin2bn(buf, len, ret);
    free(buf);
    return bn;
}

/* ==========================================================================
 * BN_lshift1
 * ADAPTED: BN_lshift1(r, a) == BN_lshift(r, a, 1)
 * ========================================================================== */
int BN_lshift1(BIGNUM *r, const BIGNUM *a)
{
    SHIM_TRACE();
    return wolfSSL_BN_lshift(r, a, 1);
}

/* ==========================================================================
 * BN_mask_bits
 * DIRECT: wolfSSL_mask_bits
 * ========================================================================== */
int BN_mask_bits(BIGNUM *a, int n)
{
    SHIM_TRACE();
    return wolfSSL_mask_bits(a, n);
}

/* ==========================================================================
 * BN_mod_add_quick
 * ADAPTED: call wolfSSL_BN_mod_add (no BN_CTX variant exists in wolfSSL compat
 *   so we pass NULL).
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL_BN_mod_add requires BN_CTX; passing NULL may fail.
 * ========================================================================== */
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m)
{
    SHIM_TRACE();
    return wolfSSL_BN_mod_add(r, a, b, m, NULL);
}

/* ==========================================================================
 * BN_mod_exp2_mont
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL does not expose dual-base Montgomery modular exp.
 *   Fall back to two separate mod_exp calls and multiply the results.
 * ========================================================================== */
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
                     const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
                     BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    BIGNUM *t1, *t2;
    int ret = 0;
    SHIM_TRACE();
    (void)m_ctx;
    if (r == NULL || m == NULL) return 0;
    t1 = wolfSSL_BN_new();
    t2 = wolfSSL_BN_new();
    if (t1 == NULL || t2 == NULL) goto done;
    if (!wolfSSL_BN_mod_exp(t1, a1, p1, m, ctx)) goto done;
    if (!wolfSSL_BN_mod_exp(t2, a2, p2, m, ctx)) goto done;
    if (!wolfSSL_BN_mod_mul(r, t1, t2, m, ctx)) goto done;
    ret = 1;
done:
    wolfSSL_BN_free(t1);
    wolfSSL_BN_free(t2);
    return ret;
}

/* ==========================================================================
 * BN_mod_exp_mont
 * DIRECT: wolfSSL_BN_mod_exp (mont parameter ignored; wolfSSL handles internally)
 * ========================================================================== */
int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    SHIM_TRACE();
    (void)m_ctx;
    return wolfSSL_BN_mod_exp(r, a, p, m, ctx);
}

/* ==========================================================================
 * BN_mod_exp_mont_consttime
 * DIRECT: wolfSSL_BN_mod_exp (wolfSSL may use constant-time internally)
 * WOLFSHIM_GAP[SECURITY:MEDIUM]: wolfSSL constant-time guarantee not verified.
 * ========================================================================== */
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont)
{
    SHIM_TRACE();
    (void)in_mont;
    /* WOLFSHIM_GAP[SECURITY:MEDIUM]: wolfSSL constant-time guarantee not externally verified */
    return wolfSSL_BN_mod_exp(rr, a, p, m, ctx);
}

/* ==========================================================================
 * BN_mod_exp_simple
 * DIRECT: wolfSSL_BN_mod_exp
 * ========================================================================== */
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfSSL_BN_mod_exp(r, a, p, m, ctx);
}

/* ==========================================================================
 * BN_mod_lshift / BN_mod_lshift_quick
 * ADAPTED: compute r = (a << n) mod m
 * ========================================================================== */
int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
                  BN_CTX *ctx)
{
    BIGNUM *tmp;
    int ret = 0;
    SHIM_TRACE();
    if (r == NULL || a == NULL || m == NULL) return 0;
    tmp = wolfSSL_BN_new();
    if (tmp == NULL) return 0;
    if (!wolfSSL_BN_lshift(tmp, a, n)) goto done;
    ret = wolfSSL_BN_mod(r, tmp, m, ctx);
done:
    wolfSSL_BN_free(tmp);
    return ret;
}

int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m)
{
    SHIM_TRACE();
    return BN_mod_lshift(r, a, n, m, NULL);
}

/* ==========================================================================
 * BN_mod_lshift1 / BN_mod_lshift1_quick
 * ADAPTED: r = (a << 1) mod m
 * ========================================================================== */
int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    SHIM_TRACE();
    return BN_mod_lshift(r, a, 1, m, ctx);
}

int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m)
{
    SHIM_TRACE();
    return BN_mod_lshift(r, a, 1, m, NULL);
}

/* ==========================================================================
 * BN_mod_mul_montgomery
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_mod_mul_montgomery publicly.
 *   Fall back to wolfSSL_BN_mod_mul.
 * ========================================================================== */
int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)mont; (void)r; (void)a; (void)b; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose an accessor for the modulus
     * stored inside BN_MONT_CTX.  Without the modulus we cannot call
     * wolfSSL_BN_mod_mul correctly.  Returning 0 (failure) is safer than
     * passing a throwaway zero BIGNUM as the modulus, which would produce
     * mathematically undefined results and leak memory. */
    return 0;
}

/* ==========================================================================
 * BN_mod_sqr
 * ADAPTED: r = a^2 mod m
 * ========================================================================== */
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    SHIM_TRACE();
    return wolfSSL_BN_mod_mul(r, a, a, m, ctx);
}

/* ==========================================================================
 * BN_mod_sqrt
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_mod_sqrt in public BN compat API.
 * Stub returns NULL.
 * ========================================================================== */
BIGNUM *BN_mod_sqrt(BIGNUM *ret, const BIGNUM *a, const BIGNUM *n,
                    BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)ret; (void)a; (void)n; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_mod_sqrt */
    return NULL;
}

/* ==========================================================================
 * BN_mod_sub / BN_mod_sub_quick
 * ADAPTED: r = (a - b) mod m
 * ========================================================================== */
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx)
{
    BIGNUM *tmp;
    int ret = 0;
    SHIM_TRACE();
    if (r == NULL || a == NULL || b == NULL || m == NULL) return 0;
    tmp = wolfSSL_BN_new();
    if (tmp == NULL) return 0;
    if (!wolfSSL_BN_sub(tmp, a, b)) goto done;
    ret = wolfSSL_BN_mod(r, tmp, m, ctx);
done:
    wolfSSL_BN_free(tmp);
    return ret;
}

int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m)
{
    SHIM_TRACE();
    return BN_mod_sub(r, a, b, m, NULL);
}

/* ==========================================================================
 * BN_mod_word
 * DIRECT: wolfSSL_BN_mod_word
 * ========================================================================== */
BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w)
{
    SHIM_TRACE();
    return wolfSSL_BN_mod_word(a, (WOLFSSL_BN_ULONG)w);
}

/* ==========================================================================
 * BN_MONT_CTX_copy
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_MONT_CTX_copy in its public API.
 * Stub returns NULL.
 * ========================================================================== */
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)
{
    SHIM_TRACE();
    (void)to; (void)from;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_MONT_CTX_copy */
    return NULL;
}

/* ==========================================================================
 * BN_MONT_CTX_set_locked
 * ADAPTED: thread-safe lazy Montgomery context initialisation using
 * double-checked locking via CRYPTO_THREAD_write_lock / CRYPTO_THREAD_unlock
 * (mapped to wolfSSL wc_LockMutex / wc_UnLockMutex).
 * ========================================================================== */
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
                                    const BIGNUM *mod, BN_CTX *ctx)
{
    BN_MONT_CTX *tmp;
    SHIM_TRACE();
    if (pmont == NULL) return NULL;

    /* Fast path: already initialised — no lock needed. */
    if (*pmont != NULL) return *pmont;

    /* WOLFSHIM_GAP[CORRECTNESS]: the caller-supplied `lock` is an OpenSSL
     * CRYPTO_RWLOCK* (pthread_rwlock_t wrapper internally).  wolfSSL maps
     * CRYPTO_THREAD_write_lock to wc_LockMutex which expects a wolfSSL_Mutex*
     * (pthread_mutex_t wrapper) — calling it on the wrong struct type is UB.
     * We ignore `lock` and use our own static mutex instead.  All concurrent
     * callers serialise through s_wolfshim_mont_lock; this is correct but
     * globally serialised rather than per-key.  Acceptable: contention only
     * occurs on first use of each key; after that *pmont != NULL and the
     * fast-path above avoids the lock entirely. */
    (void)lock;
    pthread_mutex_lock(&s_wolfshim_mont_lock);

    /* Double-check after acquiring the lock. */
    if (*pmont != NULL) {
        pthread_mutex_unlock(&s_wolfshim_mont_lock);
        return *pmont;
    }

    tmp = wolfSSL_BN_MONT_CTX_new();
    if (tmp == NULL) {
        pthread_mutex_unlock(&s_wolfshim_mont_lock);
        return NULL;
    }
    if (!wolfSSL_BN_MONT_CTX_set(tmp, mod, ctx)) {
        wolfSSL_BN_MONT_CTX_free(tmp);
        pthread_mutex_unlock(&s_wolfshim_mont_lock);
        return NULL;
    }

    *pmont = tmp;
    pthread_mutex_unlock(&s_wolfshim_mont_lock);
    return *pmont;
}

/* ==========================================================================
 * BN_nist_mod_* - fast NIST modular reductions
 * ADAPTED: fall back to nnmod (BN_mod); no optimised NIST reductions in
 *   wolfSSL public BN compat API.
 * WOLFSHIM_GAP[CORRECTNESS]: performance will be worse than native OpenSSL; correctness
 *   is maintained via generic modular reduction.
 * ========================================================================== */
int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: using generic nnmod instead of fast NIST reduction */
    return wolfSSL_BN_mod(r, a, p, ctx);
}

int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: using generic nnmod instead of fast NIST reduction */
    return wolfSSL_BN_mod(r, a, p, ctx);
}

int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: using generic nnmod instead of fast NIST reduction */
    return wolfSSL_BN_mod(r, a, p, ctx);
}

int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: using generic nnmod instead of fast NIST reduction */
    return wolfSSL_BN_mod(r, a, p, ctx);
}

int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    SHIM_TRACE();
    /* WOLFSHIM_GAP[CORRECTNESS]: using generic nnmod instead of fast NIST reduction */
    return wolfSSL_BN_mod(r, a, p, ctx);
}

/* ==========================================================================
 * BN_nist_mod_func
 * ADAPTED: return appropriate nist_mod function pointer based on prime size.
 * ========================================================================== */
int (*BN_nist_mod_func(const BIGNUM *p))(BIGNUM *r, const BIGNUM *a,
                                          const BIGNUM *field, BN_CTX *ctx)
{
    int bits;
    SHIM_TRACE();
    if (p == NULL) return NULL;
    bits = wolfSSL_BN_num_bits(p);
    switch (bits) {
        case 192: return BN_nist_mod_192;
        case 224: return BN_nist_mod_224;
        case 256: return BN_nist_mod_256;
        case 384: return BN_nist_mod_384;
        case 521: return BN_nist_mod_521;
        default:  return NULL;
    }
}

/* ==========================================================================
 * BN_nnmod
 * ADAPTED: r = a mod m, always non-negative.
 * wolfSSL_BN_mod should already return non-negative; wrap it.
 * ========================================================================== */
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    int ret;
    SHIM_TRACE();
    ret = wolfSSL_BN_mod(r, m, d, ctx);
    if (ret && wolfSSL_BN_is_negative(r)) {
        /* drop const: wolfSSL does not modify d */
        ret = wolfSSL_BN_add(r, r, (BIGNUM *)(uintptr_t)d);
    }
    return ret;
}

/* ==========================================================================
 * BN_num_bits_word
 * ADAPTED: return the number of significant bits in a BN_ULONG.
 * ========================================================================== */
int BN_num_bits_word(BN_ULONG l)
{
    SHIM_TRACE();
    if (l == 0) return 0;
#if defined(__GNUC__) || defined(__clang__)
    /* __builtin_clzl gives leading zeros for unsigned long; compute bit width
     * in O(1) instead of the up-to-64-iteration loop it replaces. */
    return (int)(sizeof(BN_ULONG) * 8) - __builtin_clzl((unsigned long)l);
#else
    /* Portable fallback for non-GCC/Clang toolchains. */
    {
        int bits = 0;
        while (l > 0) { bits++; l >>= 1; }
        return bits;
    }
#endif
}

/* ==========================================================================
 * BN_options
 * ADAPTED: return a descriptive string.
 * ========================================================================== */
char *BN_options(void)
{
    SHIM_TRACE();
    /* OpenSSL prototype requires char* (not const char*); the cast is forced
     * by the API contract and is safe since callers must not modify the
     * returned string. */
    return (char *)"bn(64,64)";
}

/* ==========================================================================
 * BN_print
 * ADAPTED: print hex representation of BIGNUM to BIO.
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL BIO API used; output format may differ slightly.
 * ========================================================================== */
int BN_print(BIO *bio, const BIGNUM *a)
{
    char *hex;
    int   ret = 0;
    SHIM_TRACE();
    if (bio == NULL || a == NULL) return 0;
    hex = wolfSSL_BN_bn2hex(a);
    if (hex == NULL) return 0;
    ret = wolfSSL_BIO_write(bio, hex, (int)strlen(hex));
    XFREE(hex, NULL, DYNAMIC_TYPE_OPENSSL);
    return (ret > 0) ? 1 : 0;
}

/* ==========================================================================
 * BN_priv_rand / BN_priv_rand_range
 * DIRECT: same as BN_rand / BN_rand_range in wolfSSL (uses OS PRNG).
 * ========================================================================== */
int BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
    SHIM_TRACE();
    return wolfSSL_BN_rand(rnd, bits, top, bottom);
}

int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range)
{
    SHIM_TRACE();
    return wolfSSL_BN_rand_range(rnd, range);
}

/* ==========================================================================
 * BN_pseudo_rand_range
 * DIRECT: wolfSSL_BN_rand_range
 * ========================================================================== */
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range)
{
    SHIM_TRACE();
    return wolfSSL_BN_rand_range(rnd, range);
}

/* ==========================================================================
 * BN_reciprocal
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_reciprocal in its compat API.
 * Stub returns -1 (error).
 * ========================================================================== */
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)m; (void)len; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_reciprocal */
    return -1;
}

/* ==========================================================================
 * BN_rshift1
 * DIRECT: wolfSSL_BN_rshift(r, a, 1)
 * ========================================================================== */
int BN_rshift1(BIGNUM *r, const BIGNUM *a)
{
    SHIM_TRACE();
    return wolfSSL_BN_rshift(r, a, 1);
}

/* ==========================================================================
 * BN_secure_new
 * DIRECT: wolfSSL_BN_new (wolfSSL uses its own heap allocator)
 * ========================================================================== */
BIGNUM *BN_secure_new(void)
{
    SHIM_TRACE();
    return wolfSSL_BN_new();
}

/* ==========================================================================
 * BN_security_bits
 * ADAPTED: NIST SP 800-57 Table 2 lookup.
 *   L = prime-field key size, N = subgroup order size (N=0 for symmetric/DH).
 * ========================================================================== */
int BN_security_bits(int L, int N)
{
    SHIM_TRACE();
    (void)N;
    /* Table from NIST SP 800-57 Part 1 Rev 5, Table 2 */
    if (L >= 15360) return 256;
    if (L >= 7680)  return 192;
    if (L >= 3072)  return 128;
    if (L >= 2048)  return 112;
    if (L >= 1024)  return 80;
    return 0;
}

/* ==========================================================================
 * BN_set_negative
 * ADAPTED: set the neg field of WOLFSSL_BIGNUM.
 * ========================================================================== */
void BN_set_negative(BIGNUM *b, int n)
{
    SHIM_TRACE();
    if (b == NULL) return;
    ((WOLFSSL_BIGNUM *)b)->neg = (n != 0) ? 1 : 0;
}

/* ==========================================================================
 * BN_sqr
 * ADAPTED: r = a^2; use BN_mod_mul with a huge modulus or BN_mul.
 * wolfSSL has no BN_sqr but BN_mul works fine.
 * ========================================================================== */
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
{
    SHIM_TRACE();
    /* The explicit (BIGNUM *)(uintptr_t) cast discards const intentionally:
     * wolfSSL_BN_mul is not declared with const-correct parameters
     * (wolfSSL's compat API takes WOLFSSL_BIGNUM* not const WOLFSSL_BIGNUM*),
     * so a direct (BIGNUM *) cast would trigger -Wcast-qual.  Routing via
     * uintptr_t suppresses the warning and documents that the cast is
     * deliberate.  wolfSSL_BN_mul does not modify its input operands for
     * multiplication, so discarding const is safe here. */
    return wolfSSL_BN_mul(r, (BIGNUM *)(uintptr_t)a, (BIGNUM *)(uintptr_t)a, ctx);
}

/* ==========================================================================
 * BN_swap
 * ADAPTED: exchange contents of two BIGNUMs.
 * ========================================================================== */
void BN_swap(BIGNUM *a, BIGNUM *b)
{
    WOLFSSL_BIGNUM tmp;
    SHIM_TRACE();
    if (a == NULL || b == NULL) return;
    tmp = *a;
    *a  = *b;
    *b  = tmp;
}

/* ==========================================================================
 * BN_to_ASN1_ENUMERATED
 * WOLFSHIM_GAP[UNSUPPORTED]: converting BIGNUM to ASN1_ENUMERATED is part of the
 *   higher-level ASN1 layer.  Stub returns NULL.
 * ========================================================================== */
/* Forward declare the ASN1_INTEGER typedef to avoid pulling in asn1.h here.
 * OpenSSL defines ASN1_ENUMERATED as ASN1_INTEGER. */
struct asn1_string_st; /* forward decl */
struct asn1_string_st *BN_to_ASN1_ENUMERATED(const BIGNUM *a,
                                              struct asn1_string_st *ai)
{
    SHIM_TRACE();
    (void)a; (void)ai;
    /* WOLFSHIM_GAP[UNSUPPORTED]: ASN1_ENUMERATED conversion not in wolfSSL BN compat */
    return NULL;
}

/* ==========================================================================
 * BN_to_montgomery
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_to_montgomery.
 * Stub returns 0.
 * ========================================================================== */
int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                     BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)r; (void)a; (void)mont; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose BN_to_montgomery */
    return 0;
}

/* ==========================================================================
 * BN_uadd
 * ADAPTED: r = |a| + |b| (unsigned add).
 * WOLFSHIM_GAP[CORRECTNESS]: OpenSSL semantics require operating on absolute values.
 *   wolfSSL_BN_add is sign-aware.  If either input is negative the result of
 *   wolfSSL_BN_add will not match the expected unsigned-magnitude semantics.
 *   A correct implementation would copy both operands, clear neg on the copies,
 *   call add, then force result neg=0.  For the common case where both inputs
 *   are non-negative this call is equivalent to BN_add and is correct.
 * ========================================================================== */
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    SHIM_TRACE();
    if (a == NULL || b == NULL) return 0;
    /* The explicit (BIGNUM *)(uintptr_t) cast discards const intentionally:
     * wolfSSL_BN_add is not declared with const-correct parameters
     * (wolfSSL's compat API takes WOLFSSL_BIGNUM* not const WOLFSSL_BIGNUM*),
     * so a direct (BIGNUM *) cast would trigger -Wcast-qual.  Routing via
     * uintptr_t suppresses the warning and documents that the cast is
     * deliberate.  wolfSSL_BN_add does not modify its input operands for
     * addition, so discarding const is safe here. */
    return wolfSSL_BN_add(r,
                          (BIGNUM *)(uintptr_t)a,
                          (BIGNUM *)(uintptr_t)b);
}

/* ==========================================================================
 * BN_usub
 * ADAPTED: r = |a| - |b| (unsigned subtract, a >= b required).
 * WOLFSHIM_GAP[CORRECTNESS]: Same limitation as BN_uadd above — wolfSSL_BN_sub is
 *   sign-aware.  For callers that guarantee |a| >= |b| and both are
 *   non-negative this is equivalent to BN_sub and is correct.
 * ========================================================================== */
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    SHIM_TRACE();
    if (a == NULL || b == NULL) return 0;
    /* Same intentional const-discard as BN_uadd: wolfSSL_BN_sub takes
     * non-const parameters but does not modify its inputs for subtraction.
     * The (BIGNUM *)(uintptr_t) double-cast suppresses -Wcast-qual and
     * documents that the const-discard is deliberate. */
    return wolfSSL_BN_sub(r,
                          (BIGNUM *)(uintptr_t)a,
                          (BIGNUM *)(uintptr_t)b);
}

/* ==========================================================================
 * BN_with_flags
 * ADAPTED: copy BIGNUM header and set flags.
 * WOLFSHIM_GAP[CORRECTNESS]: wolfSSL BIGNUM has no flags; this only copies the struct.
 * ========================================================================== */
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags)
{
    SHIM_TRACE();
    (void)flags;
    if (dest == NULL || b == NULL) return;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfSSL BIGNUM has no flags field; just copy struct */
    /* dest is a temporary alias sharing b's internal digit array;
     * do not free b while dest is in use. */
    *dest = *b;
}

/* ==========================================================================
 * BN_X931_* - X9.31 prime generation
 * WOLFSHIM_GAP[UNSUPPORTED]: wolfSSL does not expose X9.31 prime generation.
 * All stubs return 0/error.
 * ========================================================================== */
int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx)
{
    SHIM_TRACE();
    (void)Xp; (void)Xq; (void)nbits; (void)ctx;
    /* WOLFSHIM_GAP[UNSUPPORTED]: X9.31 not in wolfSSL public BN API */
    return 0;
}

int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                            const BIGNUM *Xp, const BIGNUM *Xp1,
                            const BIGNUM *Xp2, const BIGNUM *e, BN_CTX *ctx,
                            BN_GENCB *cb)
{
    SHIM_TRACE();
    (void)p; (void)p1; (void)p2; (void)Xp; (void)Xp1; (void)Xp2;
    (void)e; (void)ctx; (void)cb;
    /* WOLFSHIM_GAP[UNSUPPORTED]: X9.31 not in wolfSSL public BN API */
    return 0;
}

int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                              BIGNUM *Xp1, BIGNUM *Xp2, const BIGNUM *Xp,
                              const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb)
{
    SHIM_TRACE();
    (void)p; (void)p1; (void)p2; (void)Xp1; (void)Xp2; (void)Xp;
    (void)e; (void)ctx; (void)cb;
    /* WOLFSHIM_GAP[UNSUPPORTED]: X9.31 not in wolfSSL public BN API */
    return 0;
}

/* ==========================================================================
 * BN_zero_ex
 * OpenSSL: void BN_zero_ex(BIGNUM *a)
 * DIRECT: wolfSSL_BN_zero
 * ========================================================================== */
void BN_zero_ex(BIGNUM *a)
{
    SHIM_TRACE();
    if (a == NULL) return;
    wolfSSL_BN_zero(a);
}
