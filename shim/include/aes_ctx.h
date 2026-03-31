/*
 * aes_ctx.h — internal AES context pointer helpers (wolfCrypt back-end)
 *
 * Problem: wolfCrypt's Aes struct (~1104 bytes) is larger than the original
 * OpenSSL struct aes_key_st (244 bytes: rd_key[60] + rounds).  We cannot store
 * Aes inline without enlarging the public struct, which breaks the ABI.
 *
 * Solution: store a heap-allocated Aes* in the first two pointer-sized slots
 * of the AES_KEY buffer.  Both the customer's struct aes_key_st (244 bytes)
 * and wolfSSL's WOLFSSL_AES_KEY (void*[N]) have at least 2*sizeof(void*)
 * writable bytes from offset 0, so neither overflows.
 *
 * Buffer layout (byte offsets, pointer-size portable):
 *   [0 .. sizeof(void*)-1]            : Aes* pointer (heap-allocated)
 *   [sizeof(void*) .. 2*sizeof(void*)-1] : WOLFSHIM_AES_CTX_MAGIC sentinel
 *
 * All access is via memcpy to avoid alignment assumptions.
 *
 * Requirements for includers:
 *   wolfssl/wolfcrypt/settings.h must be included before this header.
 *   wolfssl/wolfcrypt/aes.h      must be included before this header.
 *   wolfssl/wolfcrypt/types.h    must be included before this header.
 */

/*
 * AES_KEY MEMORY MODEL — READ BEFORE MODIFYING
 *
 * The OpenSSL AES_KEY struct (aes_key_st) is 244 bytes in OpenSSL 1.1.1 but
 * wolfCrypt's Aes struct is ~1292 bytes.  We cannot store Aes inline.
 *
 * Solution: AES_set_encrypt_key / AES_set_decrypt_key allocate a wolfCrypt Aes
 * object on the heap and store a pointer (plus a magic sentinel) in the first
 * two pointer-slots of the AES_KEY buffer.  aes_ctx_get() reads that pointer.
 *
 * KNOWN LEAK: OpenSSL has no AES_KEY_free() call.  Stack-allocated AES_KEY
 * objects (the dominant usage pattern) cannot be freed.  Each such object
 * leaks one ~1292-byte Aes allocation when it goes out of scope.  At TLS
 * server scale (1000 conn/s), this is approximately 1 MB/s of key-material-
 * containing heap leaks.
 *
 * The Aes structs contain live key schedules.  On Linux, they will be returned
 * to glibc's heap and may be reused for other allocations, effectively leaking
 * key material to the heap.  For FIPS deployments, consider:
 *   (a) calling AES_set_encrypt_key only for long-lived keys (not per-record),
 *   (b) using EVP_CIPHER paths instead (which manage context lifetime), or
 *   (c) wrapping with explicit explicit_bzero before the AES_KEY goes out of scope.
 *
 * This is not fixable without adding AES_KEY_free() to the public API, which
 * would require patching all callers.
 *
 * PERFORMANCE REGRESSION WARNING
 * --------------------------------
 * Every AES_set_encrypt_key call does a malloc.  In a TLS server, key setup
 * happens at least twice per handshake (client-write and server-write keys),
 * so this is a per-connection allocator hit that does not exist in stock OpenSSL.
 *
 * If this overhead is unacceptable, the correct remediation is NOT to modify
 * this shim — the heap-allocation is load-bearing given the OpenSSL 1.1.1 ABI.
 *
 * The correct remediation is to migrate to OpenSSL 3 + wolfProvider.
 * OpenSSL 3's provider API was designed for exactly this substitution pattern:
 * provider implementations manage their own context memory and are not
 * constrained to fit inside a fixed-size public struct.  wolfProvider
 * (https://github.com/wolfSSL/wolfProvider) implements the OpenSSL 3 provider
 * interface backed by wolfCrypt and does not have the struct-size mismatch
 * problem that forces heap indirection here.
 */

#ifndef WOLFSHIM_AES_CTX_H
#define WOLFSHIM_AES_CTX_H

#include <stdint.h>
#include <string.h>

/* Sentinel stored in the second pointer-slot.
 * Chosen to be non-NULL and implausible as a real pointer. */
#if UINTPTR_MAX > 0xFFFFFFFFU
# define WOLFSHIM_AES_CTX_MAGIC ((void *)(uintptr_t)0x574F4C4657534844ULL) /* "WOLFWSHD" */
#else
# define WOLFSHIM_AES_CTX_MAGIC ((void *)(uintptr_t)0x574F4C46UL)           /* "WOLF"     */
#endif

/*
 * CALLER CONTRACT: the AES_KEY buffer must not be zeroed (memset, bzero,
 * explicit_bzero) between AES_set_encrypt_key() and any encrypt/decrypt call.
 * Zeroing destroys the sentinel and the heap Aes* pointer, making the wolfCrypt
 * context unreachable (leaked) and the key unusable.  To wipe a key, call
 * OPENSSL_cleanse(key, sizeof(AES_KEY)) — the shim hooks that to free the heap
 * context before zeroing the buffer.
 */

/*
 * aes_ctx_appears_zeroed — returns nonzero if both pointer slots are NULL,
 * which is the signature of a buffer wiped with memset/bzero after init.
 * Used to produce a more specific diagnostic in abort paths.
 * A freshly stack-allocated (never-initialised) buffer may also read as zero;
 * we treat that as the same class of programmer error.
 */
static inline int aes_ctx_appears_zeroed(const void *key)
{
    void *ptr = NULL, *magic = NULL;
    if (!key) return 0;
    memcpy(&ptr,   key,                              sizeof(void *));
    memcpy(&magic, (const char *)key + sizeof(void *), sizeof(void *));
    return (ptr == NULL && magic == NULL);
}

/*
 * aes_ctx_get — retrieve the Aes* stored in a wolfshim-managed AES_KEY.
 * Returns NULL if key is NULL or was not initialized by wolfshim.
 */
static inline Aes *aes_ctx_get(const void *key)
{
    Aes  *ctx   = NULL;
    void *magic = NULL;
    if (!key) return NULL;
    memcpy(&magic, (const char *)key + sizeof(void *), sizeof(void *));
    if (magic != WOLFSHIM_AES_CTX_MAGIC) return NULL;
    memcpy(&ctx, key, sizeof(Aes *));
    return ctx;
}

/*
 * aes_ctx_alloc — allocate a new Aes context and store it in the AES_KEY buffer.
 * If the key already holds a context it is freed first (handles re-init).
 * Returns the new Aes* on success, NULL on allocation failure.
 */
static inline Aes *aes_ctx_alloc(void *key)
{
    Aes  *old;
    Aes  *ctx;
    void *magic;

    if (!key) return NULL;

    old = aes_ctx_get(key);
    if (old) {
        wc_AesFree(old);
        XFREE(old, NULL, DYNAMIC_TYPE_AES);
    }

    ctx = (Aes *)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_AES);
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(Aes));

    memcpy(key, &ctx, sizeof(Aes *));
    magic = WOLFSHIM_AES_CTX_MAGIC;
    memcpy((char *)key + sizeof(void *), &magic, sizeof(void *));
    return ctx;
}

/*
 * aes_ctx_free — release the Aes* stored in an AES_KEY buffer.
 * Safe to call on keys that were never initialized or already freed.
 */
static inline void aes_ctx_free(void *key)
{
    Aes *ctx = aes_ctx_get(key);
    if (ctx) {
        wc_AesFree(ctx);
        XFREE(ctx, NULL, DYNAMIC_TYPE_AES);
        memset(key, 0, 2 * sizeof(void *));
    }
}

#endif /* WOLFSHIM_AES_CTX_H */
