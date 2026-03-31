/*
 * rand_shim.h - OpenSSL 1.1.1 RAND/RAND_DRBG API shims dispatching to wolfCrypt
 *
 * Symbols covered:
 *   RAND_add
 *   RAND_bytes
 *   RAND_DRBG_bytes
 *   RAND_DRBG_free
 *   RAND_DRBG_generate
 *   RAND_DRBG_get0_master
 *   RAND_DRBG_get0_private
 *   RAND_DRBG_get0_public
 *   RAND_DRBG_get_ex_data
 *   RAND_DRBG_instantiate
 *   RAND_DRBG_new
 *   RAND_DRBG_reseed
 *   RAND_DRBG_secure_new
 *   RAND_DRBG_set
 *   RAND_DRBG_set_callbacks
 *   RAND_DRBG_set_defaults
 *   RAND_DRBG_set_ex_data
 *   RAND_DRBG_set_reseed_defaults
 *   RAND_DRBG_set_reseed_interval
 *   RAND_DRBG_set_reseed_time_interval
 *   RAND_DRBG_uninstantiate
 *   RAND_get_rand_method
 *   RAND_keep_random_devices_open
 *   RAND_OpenSSL
 *   RAND_poll
 *   RAND_priv_bytes
 *   RAND_seed
 *   RAND_set_rand_engine
 *   RAND_set_rand_method
 *   RAND_status
 *
 * Known gaps (not implemented):
 *   RAND_DRBG_get_ex_new_index (macro wrapper around CRYPTO_get_ex_new_index)
 *   RAND_DRBG_get0_master / get0_public / get0_private return the same
 *     process-lifetime singleton DRBG; master/public/private domain separation
 *     is not implemented (all three share one WC_RNG).
 *   RAND_DRBG_set_callbacks returns 0 (failure) unconditionally when non-NULL
 *     entropy or nonce callbacks are provided.  An OpenSSL error
 *     (ERR_R_UNSUPPORTED) is pushed to the error stack so that callers
 *     checking ERR_get_error() can detect the unsupported operation.
 *     wolfCrypt manages entropy internally via OS sources exclusively.
 *     Applications requiring custom entropy sources (hardware RNG,
 *     test-vector entropy) MUST NOT use this shim.
 */

#ifndef WOLFSHIM_RAND_SHIM_H
#define WOLFSHIM_RAND_SHIM_H

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Internal stub structure for RAND_DRBG.
 *
 * OpenSSL's RAND_DRBG is an opaque pointer in the public API; we define our
 * own layout here.  The type name wolfshim_RAND_DRBG_st is private to the
 * shim; callers use RAND_DRBG* from openssl/rand_drbg.h which in our build
 * resolves to this struct via the forward declaration below.
 * ------------------------------------------------------------------------- */

#define WOLFSHIM_DRBG_EX_DATA_MAX 16

/* Forward declaration matching OpenSSL's opaque RAND_DRBG */
typedef struct wolfshim_RAND_DRBG_st RAND_DRBG;

/* Callback typedefs mirroring openssl/rand_drbg.h */
typedef size_t (*RAND_DRBG_get_entropy_fn)(RAND_DRBG *drbg,
                                           unsigned char **pout,
                                           int entropy, size_t min_len,
                                           size_t max_len,
                                           int prediction_resistance);
typedef void (*RAND_DRBG_cleanup_entropy_fn)(RAND_DRBG *ctx,
                                             unsigned char *out, size_t outlen);
typedef size_t (*RAND_DRBG_get_nonce_fn)(RAND_DRBG *drbg, unsigned char **pout,
                                         int entropy, size_t min_len,
                                         size_t max_len);
typedef void (*RAND_DRBG_cleanup_nonce_fn)(RAND_DRBG *drbg,
                                           unsigned char *out, size_t outlen);

/* -------------------------------------------------------------------------
 * RAND_METHOD structure (mirrors openssl/rand.h rand_meth_st).
 * Also available through the OpenSSL header but redeclared here for
 * consumers that only include rand_shim.h.
 * ------------------------------------------------------------------------- */
struct rand_meth_st {
    int (*seed)(const void *buf, int num);
    int (*bytes)(unsigned char *buf, int num);
    void (*cleanup)(void);
    int (*add)(const void *buf, int num, double randomness);
    int (*pseudorand)(unsigned char *buf, int num);
    int (*status)(void);
};
typedef struct rand_meth_st RAND_METHOD;

/* =========================================================================
 * RAND_DRBG lifecycle
 * ========================================================================= */

/*
 * RAND_DRBG_new - allocate and partially initialise a DRBG stub.
 *
 * OpenSSL 1.1.1 signature:
 *   RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent);
 *
 * Returns a new RAND_DRBG object, or NULL on allocation failure.
 * 'parent' is stored but unused; wolfCrypt manages seeding internally.
 */
RAND_DRBG *wolfshim_RAND_DRBG_new(int type, unsigned int flags,
                                   RAND_DRBG *parent);

/*
 * RAND_DRBG_secure_new - same as RAND_DRBG_new; wolfCrypt has no separate
 * secure-memory allocator distinction at this level.
 *
 * OpenSSL 1.1.1 signature:
 *   RAND_DRBG *RAND_DRBG_secure_new(int type, unsigned int flags,
 *                                    RAND_DRBG *parent);
 */
RAND_DRBG *wolfshim_RAND_DRBG_secure_new(int type, unsigned int flags,
                                          RAND_DRBG *parent);

/*
 * RAND_DRBG_free - destroy and deallocate a DRBG.
 *
 * OpenSSL 1.1.1 signature:
 *   void RAND_DRBG_free(RAND_DRBG *drbg);
 */
void wolfshim_RAND_DRBG_free(RAND_DRBG *drbg);

/*
 * RAND_DRBG_set - reconfigure type/flags on an existing DRBG.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags);
 *
 * Returns 1.
 * WOLFSHIM_KNOWN_GAP: type and flags are stored but not acted upon; wolfCrypt
 * always uses its internal Hash-DRBG regardless of the requested NID.
 */
int wolfshim_RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags);

/*
 * RAND_DRBG_set_defaults - set global default type/flags for new DRBGs.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_set_defaults(int type, unsigned int flags);
 *
 * Returns 1.
 * Thread-safe: protected by s_wolfshim_rand_globals_lock.
 * WOLFSHIM_KNOWN_GAP: recorded but not enforced; see wolfshim_RAND_DRBG_set.
 */
int wolfshim_RAND_DRBG_set_defaults(int type, unsigned int flags);

/* =========================================================================
 * RAND_DRBG state transitions
 * ========================================================================= */

/*
 * RAND_DRBG_instantiate - initialise the embedded WC_RNG.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_instantiate(RAND_DRBG *drbg,
 *                             const unsigned char *pers, size_t perslen);
 *
 * Returns 1 on success, 0 on failure.
 * 'pers'/'perslen' personalisation string is accepted but not forwarded;
 * wolfCrypt seeds from OS entropy.
 */
int wolfshim_RAND_DRBG_instantiate(RAND_DRBG *drbg,
                                    const unsigned char *pers, size_t perslen);

/*
 * RAND_DRBG_uninstantiate - free the embedded WC_RNG without freeing the DRBG.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_uninstantiate(RAND_DRBG *drbg);
 *
 * Returns 1 on success, 0 on failure.
 */
int wolfshim_RAND_DRBG_uninstantiate(RAND_DRBG *drbg);

/*
 * RAND_DRBG_reseed - trigger a reseed.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_reseed(RAND_DRBG *drbg,
 *                        const unsigned char *adin, size_t adinlen,
 *                        int prediction_resistance);
 *
 * Returns 1.
 * Additional input 'adin' is accepted but ignored; wolfCrypt reseeds
 * automatically from OS entropy.
 */
int wolfshim_RAND_DRBG_reseed(RAND_DRBG *drbg,
                               const unsigned char *adin, size_t adinlen,
                               int prediction_resistance);

/* =========================================================================
 * RAND_DRBG output
 * ========================================================================= */

/*
 * RAND_DRBG_generate - generate random bytes.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
 *                          int prediction_resistance,
 *                          const unsigned char *adin, size_t adinlen);
 *
 * Returns 1 on success, 0 on failure.
 */
int wolfshim_RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out,
                                 size_t outlen, int prediction_resistance,
                                 const unsigned char *adin, size_t adinlen);

/*
 * RAND_DRBG_bytes - generate random bytes (simplified interface).
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen);
 *
 * Returns 1 on success, 0 on failure.
 */
int wolfshim_RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out,
                              size_t outlen);

/* =========================================================================
 * RAND_DRBG reseed parameters
 * ========================================================================= */

/*
 * RAND_DRBG_set_reseed_interval - set generate-count between reseeds.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg, unsigned int interval);
 *
 * Returns 1.  Stored in stub; not enforced.
 * Thread-safe: protected by s_wolfshim_rand_globals_lock.
 */
int wolfshim_RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg,
                                            unsigned int interval);

/*
 * RAND_DRBG_set_reseed_time_interval - set time-based reseed interval.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg, time_t interval);
 *
 * Returns 1.  Stored in stub; not enforced.
 * Thread-safe: protected by s_wolfshim_rand_globals_lock.
 */
int wolfshim_RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg,
                                                 time_t interval);

/*
 * RAND_DRBG_set_reseed_defaults - set global reseed interval defaults.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_set_reseed_defaults(
 *       unsigned int master_reseed_interval,
 *       unsigned int slave_reseed_interval,
 *       time_t master_reseed_time_interval,
 *       time_t slave_reseed_time_interval);
 *
 * Returns 1.  Values recorded but not enforced.
 * NOT thread-safe: call only before spawning threads.
 */
int wolfshim_RAND_DRBG_set_reseed_defaults(
        unsigned int master_reseed_interval,
        unsigned int slave_reseed_interval,
        time_t master_reseed_time_interval,
        time_t slave_reseed_time_interval);

/* =========================================================================
 * RAND_DRBG callbacks
 * ========================================================================= */

/*
 * RAND_DRBG_set_callbacks - register entropy/nonce callbacks.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_set_callbacks(RAND_DRBG *drbg,
 *       RAND_DRBG_get_entropy_fn get_entropy,
 *       RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
 *       RAND_DRBG_get_nonce_fn get_nonce,
 *       RAND_DRBG_cleanup_nonce_fn cleanup_nonce);
 *
 * Returns 0 (callbacks not supported; wolfCrypt manages entropy internally —
 * see WOLFSHIM_REVIEW comment in .c file).
 * WOLFSHIM_KNOWN_GAP: Callbacks are never called; wolfCrypt performs its own
 * seeding from OS entropy exclusively.  Applications that require custom
 * entropy sources MUST NOT use this shim.
 */
int wolfshim_RAND_DRBG_set_callbacks(
        RAND_DRBG *drbg,
        RAND_DRBG_get_entropy_fn get_entropy,
        RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
        RAND_DRBG_get_nonce_fn get_nonce,
        RAND_DRBG_cleanup_nonce_fn cleanup_nonce);

/* =========================================================================
 * RAND_DRBG hierarchy accessors
 *
 * WOLFSHIM_GAP[CORRECTNESS]: OpenSSL 1.1.1 maintains a three-DRBG hierarchy
 * (master / public / private) for domain separation between public nonces and
 * private key material.  wolfCrypt has no equivalent hierarchy.
 *
 * All three functions return the same process-lifetime singleton DRBG, which
 * is backed by a real WC_RNG and produces genuine random bytes.  The
 * public/private separation is absent — both domains draw from the same RNG
 * state.
 *
 * Return value: the singleton DRBG pointer on success; NULL (with
 * ERR_R_UNSUPPORTED pushed) only if wc_InitRng failed at process startup.
 * Under normal conditions these functions do not return NULL.
 *
 * The singleton is never freed; passing the returned pointer to
 * RAND_DRBG_free() is a no-op (is_singleton guard prevents the free).
 * ========================================================================= */

/*
 * RAND_DRBG_get0_master - return the global master DRBG.
 *
 * OpenSSL 1.1.1 signature:
 *   RAND_DRBG *RAND_DRBG_get0_master(void);
 *
 * Returns the process-lifetime singleton DRBG, or NULL if wc_InitRng failed
 * at startup (ERR_R_UNSUPPORTED is pushed in that case).
 * WOLFSHIM_GAP[CORRECTNESS]: all three get0 variants return the same singleton;
 * master/public/private domain separation is not implemented.
 */
RAND_DRBG *wolfshim_RAND_DRBG_get0_master(void);

/*
 * RAND_DRBG_get0_public - return the per-thread public DRBG.
 *
 * OpenSSL 1.1.1 signature:
 *   RAND_DRBG *RAND_DRBG_get0_public(void);
 *
 * Returns the process-lifetime singleton DRBG (same object as get0_master).
 * See wolfshim_RAND_DRBG_get0_master for return-value contract.
 */
RAND_DRBG *wolfshim_RAND_DRBG_get0_public(void);

/*
 * RAND_DRBG_get0_private - return the per-thread private DRBG.
 *
 * OpenSSL 1.1.1 signature:
 *   RAND_DRBG *RAND_DRBG_get0_private(void);
 *
 * Returns the process-lifetime singleton DRBG (same object as get0_master).
 * See wolfshim_RAND_DRBG_get0_master for return-value contract.
 */
RAND_DRBG *wolfshim_RAND_DRBG_get0_private(void);

/* =========================================================================
 * RAND_DRBG ex_data
 * ========================================================================= */

/*
 * RAND_DRBG_set_ex_data - store a pointer in the DRBG's ex_data slot.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_DRBG_set_ex_data(RAND_DRBG *drbg, int idx, void *arg);
 *
 * Returns 1 on success, 0 if idx is out of range or drbg is NULL.
 */
int wolfshim_RAND_DRBG_set_ex_data(RAND_DRBG *drbg, int idx, void *arg);

/*
 * RAND_DRBG_get_ex_data - retrieve a pointer from the DRBG's ex_data slot.
 *
 * OpenSSL 1.1.1 signature:
 *   void *RAND_DRBG_get_ex_data(const RAND_DRBG *drbg, int idx);
 *
 * Returns the stored pointer, or NULL on error.
 */
void *wolfshim_RAND_DRBG_get_ex_data(const RAND_DRBG *drbg, int idx);

/* =========================================================================
 * Legacy RAND_METHOD / engine helpers
 * ========================================================================= */

/*
 * RAND_get_rand_method - return the active RAND_METHOD table.
 *
 * OpenSSL 1.1.1 signature:
 *   const RAND_METHOD *RAND_get_rand_method(void);
 *
 * Returns a pointer to the wolfShim RAND_METHOD that wraps wolfSSL functions.
 */
const RAND_METHOD *wolfshim_RAND_get_rand_method(void);

/*
 * RAND_OpenSSL - return the default OpenSSL RAND_METHOD.
 *
 * OpenSSL 1.1.1 signature:
 *   RAND_METHOD *RAND_OpenSSL(void);
 *
 * Returns the same wolfShim RAND_METHOD as wolfshim_RAND_get_rand_method().
 */
RAND_METHOD *wolfshim_RAND_OpenSSL(void);

/*
 * RAND_set_rand_engine - select an ENGINE as the RAND source.
 *
 * OpenSSL 1.1.1 signature (guarded by !OPENSSL_NO_ENGINE):
 *   int RAND_set_rand_engine(ENGINE *engine);
 *
 * wolfSSL ignores ENGINE; always returns 1.
 */
int wolfshim_RAND_set_rand_engine(void *engine);

/*
 * RAND_keep_random_devices_open - hint to keep OS entropy fd open.
 *
 * OpenSSL 1.1.1 signature:
 *   void RAND_keep_random_devices_open(int keep);
 *
 * No-op on wolfSSL.
 */
void wolfshim_RAND_keep_random_devices_open(int keep);

/*
 * RAND_priv_bytes - generate cryptographically strong private random bytes.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_priv_bytes(unsigned char *buf, int num);
 *
 * Implemented identically to RAND_bytes (wolfSSL has no separate private pool).
 */
int wolfshim_RAND_priv_bytes(unsigned char *buf, int num);

/* =========================================================================
 * Core RAND_* symbols (legacy RAND interface)
 * ========================================================================= */

/*
 * RAND_bytes - fill buf with num cryptographically strong random bytes.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_bytes(unsigned char *buf, int num);
 *
 * Maps to wolfSSL_RAND_bytes.  Returns 1 on success, 0 on failure.
 */
int wolfshim_RAND_bytes(unsigned char *buf, int num);

/*
 * RAND_seed - seed the RNG with additional entropy (no-op in this shim).
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_seed(const void *buf, int num);
 *
 * wolfSSL manages its own seeding; this is a no-op returning 1.
 */
int wolfshim_RAND_seed(const void *buf, int num);

/*
 * RAND_add - add additional entropy (no-op in this shim).
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_add(const void *buf, int num, double randomness);
 *
 * Returns 1.  wolfSSL does not consume externally supplied entropy here.
 */
int wolfshim_RAND_add(const void *buf, int num, double randomness);

/*
 * RAND_status - report whether the RNG is seeded.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_status(void);
 *
 * Always returns 1 (wolfCrypt is always seeded from OS entropy).
 */
int wolfshim_RAND_status(void);

/*
 * RAND_poll - poll for OS entropy (no-op; wolfCrypt does this internally).
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_poll(void);
 *
 * Always returns 1.
 */
int wolfshim_RAND_poll(void);

/*
 * RAND_set_rand_method - install a custom RAND_METHOD dispatch table.
 *
 * OpenSSL 1.1.1 signature:
 *   int RAND_set_rand_method(const RAND_METHOD *meth);
 *
 * Stores meth; RAND_bytes, RAND_seed, RAND_add, and RAND_status dispatch
 * through the installed method's callbacks.  RAND_DRBG_generate() does NOT
 * dispatch through RAND_METHOD — it uses wolfCrypt's internal WC_RNG directly.
 * Thread-safe: protected by s_wolfshim_rand_globals_lock.
 */
int wolfshim_RAND_set_rand_method(const RAND_METHOD *meth);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSHIM_RAND_SHIM_H */
