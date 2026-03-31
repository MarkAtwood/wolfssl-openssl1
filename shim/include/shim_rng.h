#ifndef WOLFSHIM_RNG_H
#define WOLFSHIM_RNG_H
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
/* Generate len cryptographically random bytes into buf using the calling
 * thread's per-thread WC_RNG.  The RNG is seeded on first call from each
 * thread and freed when the thread exits.
 * Returns 0 on success, non-zero on failure. */
int shim_rng_generate(byte *buf, word32 len);
/* Return the calling thread's WC_RNG directly.  Use this only when a
 * wolfCrypt API requires a WC_RNG pointer (e.g. wc_RsaPad_ex).  Prefer
 * shim_rng_generate for all other random-byte needs.
 * Returns NULL on allocation or initialisation failure. */
WC_RNG *shim_get_thread_rng(void);
#endif
