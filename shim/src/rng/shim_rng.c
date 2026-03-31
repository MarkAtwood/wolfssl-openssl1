/*
 * shim_rng.c - Shared per-thread WC_RNG for wolfShim translation units.
 *
 * This file is the single authoritative implementation of the per-thread
 * WC_RNG lifecycle.  rsa_shim.c and pkey_meth_shim.c (and any future shim
 * TUs that need random bytes) include shim_rng.h and call shim_rng_generate
 * instead of maintaining their own copies of this code.
 *
 * Design:
 *   Each thread gets its own WC_RNG seeded independently from the OS.
 *   wc_InitRng() is called once per thread (not per operation), so the
 *   /dev/urandom syscall cost is amortised.  The key destructor calls
 *   wc_FreeRng + free when a thread exits, preventing leaks.
 *
 *   pthread_once guarantees the TLS key is created exactly once even under
 *   concurrent first-callers.  After that first call, pthread_once is a
 *   single compare-and-branch — effectively free on all modern platforms.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "shim_rng.h"

/* =========================================================================
 * Per-thread WC_RNG via pthread TLS key.
 * ========================================================================= */
static pthread_key_t   s_rng_key;
static pthread_once_t  s_rng_key_once = PTHREAD_ONCE_INIT;

static void rng_tls_destructor(void *ptr)
{
    WC_RNG *rng = (WC_RNG *)ptr;
    if (rng) {
        wc_FreeRng(rng);
        free(rng);
    }
}

static void rng_key_init(void)
{
    /* Failure here means PTHREAD_KEYS_MAX (~1024) is exhausted.  We cannot
     * recover: without a valid TLS key every thread will malloc a fresh WC_RNG
     * on every call, fail to register it for cleanup, and leak both the
     * allocation and its open /dev/urandom fd.  Abort immediately so the
     * failure is visible rather than silently degrading into a resource leak. */
    if (pthread_key_create(&s_rng_key, rng_tls_destructor) != 0) {
        fprintf(stderr,
            "[wolfshim] FATAL: pthread_key_create failed in rng_key_init.\n"
            "  PTHREAD_KEYS_MAX is likely exhausted.\n"
            "  Cannot initialise per-thread WC_RNG; aborting rather than\n"
            "  leaking RNG allocations and file descriptors on every call.\n");
        abort();
    }
}

/* Returns the calling thread's WC_RNG, creating and seeding it on
 * first call from this thread.  Returns NULL on allocation/init failure. */
static WC_RNG *get_thread_rng(void)
{
    WC_RNG *rng;
    pthread_once(&s_rng_key_once, rng_key_init);
    rng = (WC_RNG *)pthread_getspecific(s_rng_key);
    if (!rng) {
        rng = (WC_RNG *)malloc(sizeof(WC_RNG));
        if (!rng)
            return NULL;
        if (wc_InitRng(rng) != 0) {
            free(rng);
            return NULL;
        }
        pthread_setspecific(s_rng_key, rng);
    }
    return rng;
}

/* =========================================================================
 * shim_get_thread_rng — public API declared in shim_rng.h
 *
 * Returns the calling thread's WC_RNG directly.  Use only when a wolfCrypt
 * API requires a WC_RNG pointer (e.g. wc_RsaPad_ex).
 * ========================================================================= */
WC_RNG *shim_get_thread_rng(void)
{
    return get_thread_rng();
}

/* =========================================================================
 * shim_rng_generate — public API declared in shim_rng.h
 * ========================================================================= */
int shim_rng_generate(byte *buf, word32 len)
{
    WC_RNG *rng = get_thread_rng();
    if (!rng) return -1;
    return wc_RNG_GenerateBlock(rng, buf, len);
}
