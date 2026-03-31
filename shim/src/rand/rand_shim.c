/*
 * rand_shim.c - OpenSSL 1.1.1 RAND/RAND_DRBG API shims dispatching to wolfCrypt
 *
 * Copyright (c) wolfSSL shim project contributors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implementation strategy
 * -----------------------
 * OpenSSL 1.1.1 exposes two layers of randomness API:
 *
 *   1. The legacy RAND_* interface (RAND_bytes, RAND_priv_bytes, etc.) which
 *      is backed by a RAND_METHOD dispatch table.
 *
 *   2. The RAND_DRBG_* subsystem (new in 1.1.1) which manages a hierarchy of
 *      deterministic random bit generators per thread.
 *
 * wolfCrypt provides a single WC_RNG context (random.h) whose implementation
 * is a Hash-DRBG seeded from OS entropy.  There is no matching RAND_DRBG
 * hierarchy.  The shim maps RAND_DRBG objects to a plain struct containing
 * one WC_RNG plus bookkeeping fields.
 *
 * Thread safety: each RAND_DRBG owns its own WC_RNG; no global locking is
 * needed for the DRBG lifecycle functions.  The global-default fields
 * (s_rand_method_override, g_default_flags, g_*_reseed_*) are protected by
 * s_wolfshim_rand_globals_lock (a static pthread_mutex_t).
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

/* wolfCrypt random number generator */
#include <wolfssl/wolfcrypt/random.h>

#ifdef WC_NO_RNG
# error "wolfSSL must be built with RNG support to use rand_shim.c"
#endif

/* wolfSSL OpenSSL compat for RAND_bytes / wolfSSL_RAND_bytes */
#include <wolfssl/ssl.h>
/* wolfSSL_RAND_seed is declared in wolfssl/openssl/rand.h but that header
 * conflicts with our rand_shim.h RAND_METHOD definition; forward-declare. */
extern int wolfSSL_RAND_seed(const void *seed, int len);

#include "rand_shim.h"

/*
 * ERR_put_error support — forward-declare rather than including
 * <wolfssl/openssl/err.h> to avoid potential header conflicts.
 */
#ifndef ERR_LIB_RAND
# define ERR_LIB_RAND 36
#endif
#ifndef ERR_R_FATAL
# define ERR_R_FATAL 64
#endif
#ifndef ERR_R_UNSUPPORTED
# define ERR_R_UNSUPPORTED (7 | ERR_R_FATAL)
#endif
#ifndef ERR_R_PASSED_NULL_POINTER
# define ERR_R_PASSED_NULL_POINTER 90   /* openssl/err.h: ERR_R_PASSED_NULL_POINTER */
#endif

extern void ERR_put_error(int lib, int func, int reason,
                          const char *file, int line);

/* Maximum bytes per single wc_RNG_GenerateBlock call.
 *
 * wolfCrypt's Hash-DRBG enforces RNG_MAX_BLOCK_LEN = 0x10000 (65536) and
 * returns BAD_FUNC_ARG for any request larger than that.  This constant
 * matches that limit so the loop in wolfshim_RAND_DRBG_generate splits
 * large requests into compliant chunks.
 *
 * There is NO pre-generation or buffering overhead for small requests.
 * wolfCrypt's wc_RNG_GenerateBlock generates exactly the number of bytes
 * requested via an on-demand SHA256 Hash-DRBG loop (32-byte output blocks,
 * only as many as needed).  A RAND_bytes(buf, 16) call passes chunk=16 to
 * wc_RNG_GenerateBlock, which runs one SHA256 compression and copies 16
 * bytes — it does not generate 64 KB internally.
 *
 * See wolfcrypt/src/random.c: Hash_gen(), RNG_MAX_BLOCK_LEN. */
#define RAND_DRBG_CHUNK_SIZE  0x10000u

/* =========================================================================
 * Two-layer architecture — why RAND uses wolfshim_* prefix
 * =========================================================================
 * This file is structured in two layers:
 *
 *   Layer 1 — wolfshim_* functions (lines below through the "Core RAND_*
 *              symbols" section).  These are the primary implementations.
 *              Each function contains the real logic, error checking, and
 *              WOLFSHIM_DEBUG trace calls.  The wolfshim_* names allow unit
 *              tests (e.g. tests/rand_shim_test.c) to call the shim
 *              implementations directly without going through the OpenSSL
 *              symbol namespace.
 *
 *   Layer 2 — OpenSSL-named aliases (the "Public symbol aliases" section
 *              near the end of the file).  These are thin one-line wrappers
 *              that forward every call to the corresponding wolfshim_*
 *              function.  They exist so that any application linked against
 *              this shim resolves the standard OpenSSL symbol names
 *              (RAND_bytes, RAND_DRBG_new, etc.) without requiring any
 *              renaming at the call site.  The #undef guards in that section
 *              strip wolfSSL's ssl.h macro aliases before the alias function
 *              definitions so the compiler sees function definitions rather
 *              than macro expansions.
 *
 * Why RAND uses this pattern but AES/SHA/DES do not
 * -------------------------------------------------
 * The wolfshim_* prefix is a design choice for testability, NOT a
 * requirement imposed by the wolfSSL macro system.
 *
 * All shim modules face the same problem: wolfSSL's headers #define many
 * OpenSSL symbol names as macro aliases (e.g. #define RAND_bytes
 * wolfSSL_RAND_bytes).  If left in place, these macros cause a function
 * definition like "int RAND_bytes(...)" to expand to "int wolfSSL_RAND_bytes
 * (...)", silently redefining the wrong symbol.
 *
 * AES/SHA/DES (and BN/RSA) handle this with a targeted #undef immediately
 * before each function definition.  That is the simpler pattern, and it
 * works equally well.
 *
 * RAND chose the wolfshim_* prefix so that the Layer 1 implementations are
 * callable by name from unit tests without depending on linker symbol
 * interposition.  The trade-off is maintenance cost: every function needs
 * two entries (wolfshim_* impl + alias), and a maintainer adding a new
 * function must remember to add both.
 *
 * Guidance for maintainers
 * -----------------------
 * When adding a new function to rand_shim.c: add a wolfshim_* impl in
 * Layer 1 and a one-line alias in the "Public symbol aliases" section with
 * the matching #undef guard.
 *
 * When adding a new module elsewhere in the shim: use the #undef pattern
 * (as in aes_shim.c, des_shim.c, bn_shim.c) unless you also have unit
 * tests that need to call the implementation by a stable internal name.
 * ========================================================================= */

/* =========================================================================
 * Internal RAND_DRBG stub definition
 * ========================================================================= */

struct wolfshim_RAND_DRBG_st {
    WC_RNG  rng;
    int     rng_inited;     /* 1 after wc_InitRng succeeds */

    /* 1 when allocated via RAND_DRBG_secure_new: causes explicit_bzero on
     * free so that RNG state (potential key material) is not left in heap
     * memory after the DRBG is released. */
    int     secure;

    /* 1 for the process-lifetime singleton returned by get0_master/public/private.
     * wolfshim_RAND_DRBG_free skips the free() call for singletons so that a
     * caller which incorrectly frees the returned pointer does not corrupt the
     * global state. */
    int     is_singleton;

    /* 1 when RAND_DRBG_set_callbacks() was called with at least one non-NULL
     * callback that could not be honoured.  wolfCrypt provides no hook for
     * application-supplied entropy; the callbacks will never be invoked.
     * We mark the DRBG poisoned so that subsequent generate/instantiate calls
     * fail with an ERR entry — those return values *are* checked by callers,
     * unlike the set_callbacks return value. */
    int     callbacks_rejected;

    /* Configuration recorded from set/new calls (informational only) */
    int          type;
    unsigned int flags;
    RAND_DRBG   *parent;    /* not used for seeding; stored for callers */

    /* WOLFSHIM_GAP[CORRECTNESS]: reseed interval fields are absent.
     * wolfCrypt manages Hash-DRBG reseeding internally; there is no API to
     * supply or query a reseed interval.  RAND_DRBG_set_reseed_interval() and
     * RAND_DRBG_set_reseed_time_interval() warn the caller and return 1 (to
     * avoid breaking boilerplate init sequences) but the values are discarded
     * immediately — storing them here would only mislead future readers into
     * thinking they are consulted somewhere. */

    /* NOTE: entropy/nonce callback fields are intentionally absent.
     * RAND_DRBG_set_callbacks() rejects non-NULL callbacks immediately with
     * ERR_R_UNSUPPORTED and returns 0 (failure).  Storing rejected callbacks
     * would give callers false confidence that their entropy source is active.
     * wolfCrypt uses OS entropy exclusively; application-supplied entropy is
     * never invoked regardless of what callbacks are registered. */

    /* Flat ex_data array */
    void *ex_data[WOLFSHIM_DRBG_EX_DATA_MAX];
};

/* =========================================================================
 * Global defaults for RAND_DRBG_set_defaults / RAND_DRBG_set_reseed_defaults
 * ========================================================================= */

/* These globals are protected by s_wolfshim_rand_globals_lock below.
 * All reads and writes go through that mutex.
 * Note: there is no g_default_type — RAND_DRBG_set_defaults() rejects any
 * non-zero type NID with ERR_R_UNSUPPORTED, so the only accepted type is 0
 * (wolfCrypt's default Hash-DRBG), which is already the implicit default. */
static unsigned int  g_default_flags = 0;

/* Override set by RAND_set_rand_method(); NULL means use the default wolfshim
 * method table.  Must be declared before wolfshim_RAND_get_rand_method(). */
static const RAND_METHOD *s_rand_method_override = NULL;

/* Single mutex protecting all global mutable state in this file:
 *   s_rand_method_override, g_default_flags.
 * These are set-at-init / read-throughout globals.  Using one coarse mutex
 * is correct and the performance cost is negligible (these paths are not
 * called per-byte). */
static pthread_mutex_t s_wolfshim_rand_globals_lock = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================================
 * Static RAND_METHOD wrapping wolfSSL functions
 * ========================================================================= */

static int wolfshim_rand_seed(const void *buf, int num)
{
    /* wolfSSL_RAND_seed is a no-op when wolfSSL manages seeding internally */
    wolfSSL_RAND_seed(buf, num);
    return 1;
}

static int wolfshim_rand_bytes(unsigned char *buf, int num)
{
    if (!buf || num <= 0)
        return 0;
    return wolfSSL_RAND_bytes(buf, num);
}

static void wolfshim_rand_cleanup(void)
{
    /* no-op; wolfSSL cleans up on wolfSSL_Cleanup() */
}

static int wolfshim_rand_add(const void *buf, int num, double randomness)
{
    (void)buf;
    (void)num;
    (void)randomness;
    /* wolfSSL_RAND_add is available but does nothing on most builds */
    return 1;
}

static int wolfshim_rand_pseudorand(unsigned char *buf, int num)
{
    if (!buf || num <= 0)
        return 0;
    return wolfSSL_RAND_bytes(buf, num);
}

static int wolfshim_rand_status(void)
{
    return 1; /* always "seeded" */
}

static RAND_METHOD s_wolfshim_rand_method = {
    wolfshim_rand_seed,
    wolfshim_rand_bytes,
    wolfshim_rand_cleanup,
    wolfshim_rand_add,
    wolfshim_rand_pseudorand,
    wolfshim_rand_status
};

/* =========================================================================
 * Helper: allocate and zero-init a RAND_DRBG stub
 * ========================================================================= */

/* =========================================================================
 * get_rand_override — read s_rand_method_override under the global lock.
 *
 * Returns the installed override or NULL.  The returned pointer is valid
 * as long as the caller does not call RAND_set_rand_method() concurrently;
 * callers are responsible for that contract (same as OpenSSL).
 * ========================================================================= */
static const RAND_METHOD *get_rand_override(void)
{
    const RAND_METHOD *m;
    pthread_mutex_lock(&s_wolfshim_rand_globals_lock);
    m = s_rand_method_override;
    pthread_mutex_unlock(&s_wolfshim_rand_globals_lock);
    return m;
}

static RAND_DRBG *alloc_drbg(int type, unsigned int flags, RAND_DRBG *parent)
{
    RAND_DRBG *d = (RAND_DRBG *)calloc(1, sizeof(struct wolfshim_RAND_DRBG_st));
    if (!d)
        return NULL;

    /* WOLFSHIM_GAP[CORRECTNESS]: wolfCrypt always uses its internal Hash-DRBG
     * (SHA-256 based) regardless of the NID passed here.  We succeed without
     * pushing an error: returning NULL would break existing code that calls
     * RAND_DRBG_new(NID_aes_256_ctr, 0, NULL) as boilerplate and doesn't
     * care which DRBG type it gets.  Pushing an error on a successful return
     * is an anti-pattern — callers that check ERR_get_error() after a non-NULL
     * return would incorrectly treat the DRBG as failed.
     *
     * For callers that genuinely require a specific algorithm, RAND_DRBG_set()
     * is the correct gate: it fails hard (returns 0, pushes ERR_R_UNSUPPORTED)
     * on any non-zero type NID, making the mismatch explicit at the point where
     * the caller is asserting a requirement rather than providing a hint. */
#ifdef WOLFSHIM_DEBUG
    if (type != 0)
        fprintf(stderr, "[wolfshim] RAND_DRBG_new: type %d ignored "
                "— wolfCrypt uses Hash-DRBG internally.\n", type);
#endif

    d->type   = type;
    d->flags  = flags;
    d->parent = parent;
    return d;
}

/* =========================================================================
 * RAND_DRBG lifecycle
 * ========================================================================= */

RAND_DRBG *wolfshim_RAND_DRBG_new(int type, unsigned int flags,
                                   RAND_DRBG *parent)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    return alloc_drbg(type, flags, parent);
}

RAND_DRBG *wolfshim_RAND_DRBG_secure_new(int type, unsigned int flags,
                                          RAND_DRBG *parent)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    /* wolfCrypt has no separate secure-heap allocator; this uses the standard
     * heap.  The `secure` flag causes explicit_bzero() in wolfshim_RAND_DRBG_free
     * so that RNG state (potential key material) is cleared before the memory
     * is returned to the heap allocator. */
    RAND_DRBG *d = alloc_drbg(type, flags, parent);
    if (d)
        d->secure = 1;
    return d;
}

void wolfshim_RAND_DRBG_free(RAND_DRBG *drbg)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!drbg)
        return;
    if (drbg->is_singleton)
        return;  /* process-lifetime singleton; never freed */
    if (drbg->rng_inited) {
        wc_FreeRng(&drbg->rng);  /* zeroises WC_RNG internals */
        drbg->rng_inited = 0;
    }
    if (drbg->secure) {
        /* Belt-and-suspenders: clear the entire struct (pointers, flags,
         * ex_data slots) before returning the allocation to the heap.
         * wc_FreeRng above has already zeroed the WC_RNG portion; this
         * clears the surrounding bookkeeping fields. */
        explicit_bzero(drbg, sizeof(struct wolfshim_RAND_DRBG_st));
    }
    free(drbg);
}

int wolfshim_RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!drbg) {
        ERR_put_error(ERR_LIB_RAND, 0, ERR_R_PASSED_NULL_POINTER, __FILE__, __LINE__);
        return 0;
    }
    if (drbg->is_singleton)
        return 1;  /* no-op on process-lifetime singleton; same policy as wolfshim_RAND_DRBG_free */

    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfCrypt always uses its internal Hash-DRBG
     * regardless of the NID.  For RAND_DRBG_new() we warn but succeed so
     * that boilerplate callers are not broken; here the caller is explicitly
     * requesting a type change on an existing DRBG, which we cannot honour.
     * Return 0 so the caller knows the reconfiguration did not take effect. */
    if (type != 0) {
        ERR_put_error(ERR_LIB_RAND, 0, ERR_R_UNSUPPORTED, __FILE__, __LINE__);
#ifdef WOLFSHIM_DEBUG
        fprintf(stderr, "[wolfshim] rand: RAND_DRBG_set: DRBG type NID %d is "
                "not supported — wolfCrypt uses Hash-DRBG only. "
                "Call fails to prevent silent algorithm mismatch.\n", type);
#endif
        return 0;
    }
    drbg->flags = flags;
    return 1;
}

int wolfshim_RAND_DRBG_set_defaults(int type, unsigned int flags)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    /* WOLFSHIM_GAP[UNSUPPORTED]: wolfCrypt uses Hash-DRBG; no NID-based type
     * selection is available.  Fail explicitly so callers that configure
     * a specific DRBG type (e.g. NID_aes_256_ctr for FIPS CTR-DRBG) learn
     * immediately that the configuration was not applied. */
    if (type != 0) {
        ERR_put_error(ERR_LIB_RAND, 0, ERR_R_UNSUPPORTED, __FILE__, __LINE__);
#ifdef WOLFSHIM_DEBUG
        fprintf(stderr, "[wolfshim] rand: RAND_DRBG_set_defaults: DRBG type "
                "NID %d is not supported — wolfCrypt uses Hash-DRBG only. "
                "Call fails to prevent silent algorithm mismatch.\n", type);
#endif
        return 0;
    }
    pthread_mutex_lock(&s_wolfshim_rand_globals_lock);
    g_default_flags = flags;
    pthread_mutex_unlock(&s_wolfshim_rand_globals_lock);
    return 1;
}

/* =========================================================================
 * RAND_DRBG state transitions
 * ========================================================================= */

int wolfshim_RAND_DRBG_instantiate(RAND_DRBG *drbg,
                                    const unsigned char *pers, size_t perslen)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    int ret;

    if (!drbg)
        return 0;

    if (drbg->callbacks_rejected) {
        ERR_put_error(ERR_LIB_RAND, 0, ERR_R_UNSUPPORTED, __FILE__, __LINE__);
#ifdef WOLFSHIM_DEBUG
        fprintf(stderr,
                "[wolfshim] RAND_DRBG_instantiate: DRBG is poisoned — "
                "RAND_DRBG_set_callbacks() was called with non-NULL callbacks "
                "that cannot be honoured.  Refusing to instantiate without "
                "the required entropy source.\n");
#endif
        return 0;
    }

    /* Ignore personalisation string: wolfCrypt seeds from OS entropy. */
    (void)pers;
    (void)perslen;

    if (drbg->rng_inited) {
        /* Already instantiated; uninstantiate first, then re-init. */
        wc_FreeRng(&drbg->rng);
        drbg->rng_inited = 0;
    }

    ret = wc_InitRng(&drbg->rng);
    if (ret != 0)
        return 0;

    drbg->rng_inited = 1;
    return 1;
}

int wolfshim_RAND_DRBG_uninstantiate(RAND_DRBG *drbg)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!drbg)
        return 0;
    if (drbg->rng_inited) {
        wc_FreeRng(&drbg->rng);
        drbg->rng_inited = 0;
    }
    return 1;
}

int wolfshim_RAND_DRBG_reseed(RAND_DRBG *drbg,
                               const unsigned char *adin, size_t adinlen,
                               int prediction_resistance)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    (void)adin;
    (void)adinlen;
    (void)prediction_resistance;

    if (!drbg)
        return 0;

    if (!drbg->rng_inited)
        return 0;

    /* wolfCrypt reseeds automatically; we honour an explicit reseed request
     * by tearing down and reinitialising the WC_RNG, which causes wolfCrypt
     * to draw fresh entropy from the OS. */
    wc_FreeRng(&drbg->rng);
    drbg->rng_inited = 0;
    if (wc_InitRng(&drbg->rng) != 0)
        return 0;
    drbg->rng_inited = 1;
    return 1;
}

/* =========================================================================
 * RAND_DRBG output
 * ========================================================================= */

int wolfshim_RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out,
                                 size_t outlen, int prediction_resistance,
                                 const unsigned char *adin, size_t adinlen)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    (void)prediction_resistance;
    (void)adin;
    (void)adinlen;

    if (!drbg || !out || outlen == 0)
        return 0;

    if (drbg->callbacks_rejected) {
        ERR_put_error(ERR_LIB_RAND, 0, ERR_R_UNSUPPORTED, __FILE__, __LINE__);
#ifdef WOLFSHIM_DEBUG
        fprintf(stderr,
                "[wolfshim] RAND_DRBG_generate: DRBG is poisoned — "
                "RAND_DRBG_set_callbacks() was called with non-NULL callbacks "
                "that cannot be honoured.  Refusing to generate bytes without "
                "the required entropy source.\n");
#endif
        return 0;
    }

    if (!drbg->rng_inited) {
        /* OpenSSL 1.1.1 RAND_DRBG_generate returns 0 if the DRBG is not
         * instantiated; it does not auto-instantiate.  We match that behaviour.
         *
         * The previous auto-instantiate path (wc_InitRng here on first generate)
         * had an unguarded race: two threads sharing the same DRBG object could
         * both observe rng_inited == 0 and call wc_InitRng on the same WC_RNG
         * simultaneously, producing interleaved writes into the struct.  There
         * is no per-DRBG lock because the thread-safety contract (each thread
         * should use its own DRBG) makes one unnecessary in normal usage — but
         * the auto-init path violated that contract by allowing concurrent first
         * use on a shared DRBG to race.
         *
         * Callers must call RAND_DRBG_instantiate() before RAND_DRBG_generate().
         * The get0_master/public/private singletons are pre-instantiated at
         * first access, so they are unaffected. */
        ERR_put_error(ERR_LIB_RAND, 0, ERR_R_FATAL, __FILE__, __LINE__);
        return 0;
    }

    /* wc_RNG_GenerateBlock accepts word32 length; split into chunks if needed */
    {
        size_t  remaining = outlen;
        unsigned char *ptr = out;

        while (remaining > 0) {
            word32 chunk = (remaining > RAND_DRBG_CHUNK_SIZE) ? RAND_DRBG_CHUNK_SIZE : (word32)remaining;
            if (wc_RNG_GenerateBlock(&drbg->rng, ptr, chunk) != 0)
                return 0;
            ptr       += chunk;
            remaining -= chunk;
        }
    }
    return 1;
}

int wolfshim_RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    return wolfshim_RAND_DRBG_generate(drbg, out, outlen,
                                        0 /* no prediction resistance */,
                                        NULL, 0);
}

/* =========================================================================
 * RAND_DRBG reseed parameters
 * ========================================================================= */

int wolfshim_RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg,
                                            unsigned int interval)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!drbg)
        return 0;
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfCrypt manages its Hash-DRBG reseed counter
     * internally and provides no API to supply a reseed interval.  The value
     * is discarded.  Warn unconditionally so FIPS/compliance deployments that
     * configure reseed policy detect at runtime that the policy is not enforced. */
    fprintf(stderr,
        "[wolfshim] WARNING: RAND_DRBG_set_reseed_interval(%u): NOT enforced "
        "— wolfCrypt manages reseeding internally and does not honour "
        "application-supplied reseed intervals.\n", interval);
    return 1;
}

int wolfshim_RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg,
                                                 time_t interval)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!drbg)
        return 0;
    /* WOLFSHIM_GAP[CORRECTNESS]: same as set_reseed_interval — discarded.
     * Warn unconditionally for the same reason. */
    fprintf(stderr,
        "[wolfshim] WARNING: RAND_DRBG_set_reseed_time_interval(%ld): NOT "
        "enforced — wolfCrypt manages reseeding internally and does not honour "
        "application-supplied reseed time intervals.\n", (long)interval);
    return 1;
}

int wolfshim_RAND_DRBG_set_reseed_defaults(
        unsigned int master_reseed_interval,
        unsigned int slave_reseed_interval,
        time_t master_reseed_time_interval,
        time_t slave_reseed_time_interval)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    /* WOLFSHIM_GAP[CORRECTNESS]: wolfCrypt does not consult reseed intervals;
     * values are discarded.  Warn unconditionally — same reasoning as
     * set_reseed_interval above. */
    fprintf(stderr,
        "[wolfshim] WARNING: RAND_DRBG_set_reseed_defaults: reseed intervals "
        "(master=%u slave=%u master_time=%ld slave_time=%ld) NOT enforced "
        "— wolfCrypt manages reseeding internally.\n",
        master_reseed_interval, slave_reseed_interval,
        (long)master_reseed_time_interval, (long)slave_reseed_time_interval);
    (void)master_reseed_interval;
    (void)slave_reseed_interval;
    (void)master_reseed_time_interval;
    (void)slave_reseed_time_interval;
    return 1;
}

/* =========================================================================
 * RAND_DRBG callbacks
 * ========================================================================= */

int wolfshim_RAND_DRBG_set_callbacks(
        RAND_DRBG *drbg,
        RAND_DRBG_get_entropy_fn     get_entropy,
        RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
        RAND_DRBG_get_nonce_fn       get_nonce,
        RAND_DRBG_cleanup_nonce_fn   cleanup_nonce)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    /*
     * WOLFSHIM_GAP[SECURITY:MEDIUM]: Callbacks cannot be honoured.
     *
     * wolfCrypt seeds exclusively from OS entropy (/dev/urandom or platform
     * equivalent) and provides no hook for application-supplied entropy or
     * nonce sources.  The installed callbacks will NEVER be invoked regardless
     * of what the caller passes here.
     *
     * When non-NULL callbacks are provided we push an OpenSSL error so that
     * callers checking ERR_get_error() can detect the unsupported operation,
     * and emit a diagnostic to stderr.
     *
     * Returning 0 (failure) so the caller is not given false assurance that
     * its custom entropy source is active.  An application that requires
     * hardware RNG or test-vector entropy MUST NOT use this shim.
     */
    (void)cleanup_entropy;
    (void)cleanup_nonce;

    if (get_entropy != NULL || get_nonce != NULL) {
        ERR_put_error(ERR_LIB_RAND, 0 /* func */, ERR_R_UNSUPPORTED,
                      __FILE__, __LINE__);
        fprintf(stderr,
                "[wolfshim] RAND_DRBG_set_callbacks: application-supplied "
                "entropy/nonce callbacks are NOT supported — wolfCrypt uses "
                "OS entropy exclusively and provides no callback hook.\n"
                "  This DRBG is now POISONED: generate/instantiate will fail "
                "so the missing HSM entropy is detected at the call site that "
                "is actually checked.\n"
                "  Applications requiring hardware RNG MUST NOT use this shim.\n");
        if (drbg)
            drbg->callbacks_rejected = 1;
        return 0;
    }

    /* All four callback pointers are NULL — the OpenSSL API treats this as
     * "clear custom callbacks" (a valid no-op).  Return 1 for success. */
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s: all callbacks NULL — returning success\n",
            __func__);
#endif
    return 1;
}

/* =========================================================================
 * RAND_DRBG hierarchy accessors
 * =========================================================================
 *
 * WOLFSHIM_GAP[CORRECTNESS]: OpenSSL 1.1.1 maintains a three-DRBG hierarchy
 * (master / public / private) so that private key material is generated from
 * a different RNG state than public nonces.  wolfCrypt has no equivalent
 * hierarchy; there is a single global WC_RNG backed by OS entropy.
 *
 * Implementation: all three get0 variants return the same process-lifetime
 * singleton DRBG.  The singleton is a fully functional wolfshim_RAND_DRBG_st
 * backed by a real WC_RNG, so callers that use it for RAND_DRBG_generate()
 * or RAND_DRBG_reseed() get genuine random bytes.  The public/private
 * separation documented in the OpenSSL RAND_DRBG(7) man page is absent;
 * see "Security Limitations" in ../README.md (project root).
 *
 * The singleton is never freed (is_singleton = 1 guards wolfshim_RAND_DRBG_free).
 * If wc_InitRng fails at startup, all three return NULL and push ERR_R_UNSUPPORTED.
 */

static struct wolfshim_RAND_DRBG_st s_global_drbg;
static int                          s_global_drbg_ready = 0;
static pthread_once_t               s_global_drbg_once  = PTHREAD_ONCE_INIT;

static void init_global_drbg(void)
{
    memset(&s_global_drbg, 0, sizeof(s_global_drbg));
    s_global_drbg.is_singleton = 1;
    if (wc_InitRng(&s_global_drbg.rng) == 0) {
        s_global_drbg.rng_inited   = 1;
        s_global_drbg_ready        = 1;
    }
    /* If wc_InitRng fails, s_global_drbg_ready stays 0 and get0_* return NULL. */
}

static RAND_DRBG *get_global_drbg(void)
{
    pthread_once(&s_global_drbg_once, init_global_drbg);
    if (!s_global_drbg_ready) {
        ERR_put_error(ERR_LIB_RAND, 0, ERR_R_UNSUPPORTED, __FILE__, __LINE__);
        return NULL;
    }
    return (RAND_DRBG *)&s_global_drbg;
}

RAND_DRBG *wolfshim_RAND_DRBG_get0_master(void)
{
    return get_global_drbg();
}

RAND_DRBG *wolfshim_RAND_DRBG_get0_public(void)
{
    return get_global_drbg();
}

RAND_DRBG *wolfshim_RAND_DRBG_get0_private(void)
{
    return get_global_drbg();
}

/* =========================================================================
 * RAND_DRBG ex_data
 * ========================================================================= */

int wolfshim_RAND_DRBG_set_ex_data(RAND_DRBG *drbg, int idx, void *arg)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!drbg || idx < 0 || idx >= WOLFSHIM_DRBG_EX_DATA_MAX)
        return 0;
    drbg->ex_data[idx] = arg;
    return 1;
}

void *wolfshim_RAND_DRBG_get_ex_data(const RAND_DRBG *drbg, int idx)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!drbg || idx < 0 || idx >= WOLFSHIM_DRBG_EX_DATA_MAX)
        return NULL;
    return drbg->ex_data[idx];
}

/* =========================================================================
 * Legacy RAND_METHOD / engine helpers
 * ========================================================================= */

const RAND_METHOD *wolfshim_RAND_get_rand_method(void)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    const RAND_METHOD *m;
    pthread_mutex_lock(&s_wolfshim_rand_globals_lock);
    m = s_rand_method_override ? s_rand_method_override : &s_wolfshim_rand_method;
    pthread_mutex_unlock(&s_wolfshim_rand_globals_lock);
    return m;
}

RAND_METHOD *wolfshim_RAND_OpenSSL(void)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    /* In OpenSSL this returns the default software RAND_METHOD; we return the
     * same wolfShim method table. */
    return &s_wolfshim_rand_method;
}

int wolfshim_RAND_set_rand_engine(void *engine)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    /* wolfSSL does not support ENGINE-backed random sources; ignore and
     * succeed so callers that set a default engine don't fail initialisation. */
    (void)engine;
    return 1;
}

void wolfshim_RAND_keep_random_devices_open(int keep)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    /* wolfCrypt manages its own OS entropy file descriptor; this hint is
     * not needed and is silently ignored. */
    (void)keep;
}

int wolfshim_RAND_priv_bytes(unsigned char *buf, int num)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!buf || num <= 0)
        return 0;
    /* WOLFSHIM_GAP[SECURITY:MEDIUM]: wolfCrypt has no separate private randomness pool.
     * OpenSSL's RAND_priv_bytes uses a dedicated per-thread private DRBG
     * separate from the public DRBG so that compromise of public nonces does
     * not reveal private key material.  We dispatch through any installed
     * method override (same as RAND_bytes) but cannot provide the
     * public/private pool separation.  See ../README.md §Security Limitations
     * (project root) and shim/RELEASE-NOTES.md. */
    const RAND_METHOD *override = get_rand_override();
    if (override && override->bytes)
        return override->bytes(buf, num);
    return wolfSSL_RAND_bytes(buf, num);
}

/* =========================================================================
 * Core RAND_* symbols (legacy RAND interface)
 *
 * These wolfshim_* functions implement the RAND_* logic dispatching to
 * wolfSSL_RAND_* equivalents.  The exported OpenSSL-named symbols
 * (RAND_bytes, RAND_seed, etc.) are defined below in the "Public symbol
 * aliases" section, where the #undef guards are actually needed to prevent
 * wolfSSL macro expansion of those OpenSSL-named tokens.
 * ========================================================================= */

int wolfshim_RAND_bytes(unsigned char *buf, int num)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    if (!buf || num <= 0)
        return 0;
    /* Dispatch through any installed RAND_METHOD override (e.g. hardware RNG,
     * test vectors).  Falls through to wolfCrypt when no override is set. */
    const RAND_METHOD *override = get_rand_override();
    if (override && override->bytes)
        return override->bytes(buf, num);
    return wolfSSL_RAND_bytes(buf, num);
}

int wolfshim_RAND_seed(const void *buf, int num)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    const RAND_METHOD *override = get_rand_override();
    if (override && override->seed)
        return override->seed(buf, num);
    /* wolfSSL_RAND_seed is a no-op when wolfSSL manages seeding internally */
    wolfSSL_RAND_seed(buf, num);
    return 1;
}

int wolfshim_RAND_add(const void *buf, int num, double randomness)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    const RAND_METHOD *override = get_rand_override();
    if (override && override->add)
        return override->add(buf, num, randomness);
    (void)buf;
    (void)num;
    (void)randomness;
    /* wolfSSL_RAND_add does nothing on most builds; no-op here */
    return 1;
}

int wolfshim_RAND_status(void)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    const RAND_METHOD *override = get_rand_override();
    if (override && override->status)
        return override->status();
    return 1; /* wolfCrypt is always seeded */
}

int wolfshim_RAND_poll(void)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    return 1; /* wolfCrypt seeds from OS entropy automatically */
}

int wolfshim_RAND_set_rand_method(const RAND_METHOD *meth)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] rand: %s called\n", __func__);
#endif
    /* WOLFSHIM_GAP[CORRECTNESS]: The stored method is returned by RAND_get_rand_method
     * but the wolfSSL dispatch layer does not consult it for actual random
     * generation; wolfCrypt uses its own entropy path regardless. */
    pthread_mutex_lock(&s_wolfshim_rand_globals_lock);
    s_rand_method_override = meth;
    pthread_mutex_unlock(&s_wolfshim_rand_globals_lock);
    return 1;
}

/* =========================================================================
 * Public symbol aliases matching the exact OpenSSL 1.1.1 names
 *
 * These allow the shim to be linked in place of the real OpenSSL shared
 * object without renaming call sites.  Each alias is a thin wrapper that
 * calls the wolfshim_* implementation above.
 * ========================================================================= */

RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return wolfshim_RAND_DRBG_new(type, flags, parent);
}

RAND_DRBG *RAND_DRBG_secure_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return wolfshim_RAND_DRBG_secure_new(type, flags, parent);
}

void RAND_DRBG_free(RAND_DRBG *drbg)
{
    wolfshim_RAND_DRBG_free(drbg);
}

int RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags)
{
    return wolfshim_RAND_DRBG_set(drbg, type, flags);
}

int RAND_DRBG_set_defaults(int type, unsigned int flags)
{
    return wolfshim_RAND_DRBG_set_defaults(type, flags);
}

int RAND_DRBG_instantiate(RAND_DRBG *drbg,
                           const unsigned char *pers, size_t perslen)
{
    return wolfshim_RAND_DRBG_instantiate(drbg, pers, perslen);
}

int RAND_DRBG_uninstantiate(RAND_DRBG *drbg)
{
    return wolfshim_RAND_DRBG_uninstantiate(drbg);
}

int RAND_DRBG_reseed(RAND_DRBG *drbg,
                     const unsigned char *adin, size_t adinlen,
                     int prediction_resistance)
{
    return wolfshim_RAND_DRBG_reseed(drbg, adin, adinlen, prediction_resistance);
}

int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    return wolfshim_RAND_DRBG_generate(drbg, out, outlen,
                                        prediction_resistance, adin, adinlen);
}

int RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    return wolfshim_RAND_DRBG_bytes(drbg, out, outlen);
}

int RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg, unsigned int interval)
{
    return wolfshim_RAND_DRBG_set_reseed_interval(drbg, interval);
}

int RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg, time_t interval)
{
    return wolfshim_RAND_DRBG_set_reseed_time_interval(drbg, interval);
}

int RAND_DRBG_set_reseed_defaults(
        unsigned int master_reseed_interval,
        unsigned int slave_reseed_interval,
        time_t master_reseed_time_interval,
        time_t slave_reseed_time_interval)
{
    return wolfshim_RAND_DRBG_set_reseed_defaults(master_reseed_interval,
                                                   slave_reseed_interval,
                                                   master_reseed_time_interval,
                                                   slave_reseed_time_interval);
}

RAND_DRBG *RAND_DRBG_get0_master(void)
{
    return wolfshim_RAND_DRBG_get0_master();
}

RAND_DRBG *RAND_DRBG_get0_public(void)
{
    return wolfshim_RAND_DRBG_get0_public();
}

RAND_DRBG *RAND_DRBG_get0_private(void)
{
    return wolfshim_RAND_DRBG_get0_private();
}

int RAND_DRBG_set_ex_data(RAND_DRBG *drbg, int idx, void *arg)
{
    return wolfshim_RAND_DRBG_set_ex_data(drbg, idx, arg);
}

void *RAND_DRBG_get_ex_data(const RAND_DRBG *drbg, int idx)
{
    return wolfshim_RAND_DRBG_get_ex_data(drbg, idx);
}

int RAND_DRBG_set_callbacks(RAND_DRBG *drbg,
                             RAND_DRBG_get_entropy_fn     get_entropy,
                             RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
                             RAND_DRBG_get_nonce_fn       get_nonce,
                             RAND_DRBG_cleanup_nonce_fn   cleanup_nonce)
{
    return wolfshim_RAND_DRBG_set_callbacks(drbg, get_entropy, cleanup_entropy,
                                             get_nonce, cleanup_nonce);
}

const RAND_METHOD *RAND_get_rand_method(void)
{
    return wolfshim_RAND_get_rand_method();
}

RAND_METHOD *RAND_OpenSSL(void)
{
    return wolfshim_RAND_OpenSSL();
}

int RAND_set_rand_engine(void *engine)
{
    return wolfshim_RAND_set_rand_engine(engine);
}

void RAND_keep_random_devices_open(int keep)
{
    wolfshim_RAND_keep_random_devices_open(keep);
}

int RAND_priv_bytes(unsigned char *buf, int num)
{
    return wolfshim_RAND_priv_bytes(buf, num);
}

/* =========================================================================
 * OpenSSL-named aliases for the core RAND_* symbols added in this shim.
 *
 * wolfSSL's ssl.h may define these as macros; the #undef guards below ensure
 * the compiler sees function definitions rather than macro expansions.
 * ========================================================================= */

#ifdef RAND_bytes
#undef RAND_bytes
#endif
int RAND_bytes(unsigned char *buf, int num)
{
    return wolfshim_RAND_bytes(buf, num);
}

#ifdef RAND_seed
#undef RAND_seed
#endif
int RAND_seed(const void *buf, int num)
{
    return wolfshim_RAND_seed(buf, num);
}

#ifdef RAND_add
#undef RAND_add
#endif
int RAND_add(const void *buf, int num, double randomness)
{
    return wolfshim_RAND_add(buf, num, randomness);
}

#ifdef RAND_status
#undef RAND_status
#endif
int RAND_status(void)
{
    return wolfshim_RAND_status();
}

#ifdef RAND_poll
#undef RAND_poll
#endif
int RAND_poll(void)
{
    return wolfshim_RAND_poll();
}

#ifdef RAND_set_rand_method
#undef RAND_set_rand_method
#endif
int RAND_set_rand_method(const RAND_METHOD *meth)
{
    return wolfshim_RAND_set_rand_method(meth);
}
