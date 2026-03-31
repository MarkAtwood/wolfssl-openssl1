/*
 * evp_wolf_bridge.h — interface between OpenSSL and wolfSSL EVP digest layers
 *
 * This header is included by both the wolfSSL-side bridge (evp_wolf_bridge.c)
 * and the OpenSSL-side shim (evp_digest_shim.c).  It contains no wolfSSL or
 * OpenSSL type references — only C integers and void pointers.
 */

#ifndef EVP_WOLF_BRIDGE_H
#define EVP_WOLF_BRIDGE_H

#include <stddef.h>

/* Algorithm IDs — correspond to wolfSSL_EVP_sha1() etc. */
#define WOLF_MD_SHA1       1
#define WOLF_MD_SHA224     2
#define WOLF_MD_SHA256     3
#define WOLF_MD_SHA384     4
#define WOLF_MD_SHA512     5
#define WOLF_MD_SHA512_224 6
#define WOLF_MD_SHA512_256 7
#define WOLF_MD_MD4        8
#define WOLF_MD_MD5        9
#define WOLF_MD_RMD160     10
#define WOLF_MD_SHA3_224   11
#define WOLF_MD_SHA3_256   12
#define WOLF_MD_SHA3_384   13
#define WOLF_MD_SHA3_512   14
#define WOLF_MD_SHAKE128   15
#define WOLF_MD_SHAKE256   16
#define WOLF_MD_MDC2       17

#ifdef __cplusplus
extern "C" {
#endif

/*
 * wolf_md_ptr_size: returns sizeof(WOLFSSL_EVP_MD_CTX*).
 * Used as ctx_size in the OpenSSL EVP_MD struct.
 */
size_t wolf_md_ptr_size(void);

/*
 * wolf_md_init: initialise digest context for algo_id.
 * md_data_ptr: pointer to sizeof(void*) bytes allocated by OpenSSL.
 */
int wolf_md_init(void *md_data_ptr, int algo_id);

/*
 * wolf_md_update: feed data into the digest.
 */
int wolf_md_update(void *md_data_ptr, const void *data, size_t count);

/*
 * wolf_md_final: produce digest output.
 */
int wolf_md_final(void *md_data_ptr, unsigned char *out);

/*
 * wolf_md_copy: deep-copy from src to dst.
 */
int wolf_md_copy(void *dst_md_data_ptr, const void *src_md_data_ptr);

/*
 * wolf_md_cleanup: free resources.
 */
int wolf_md_cleanup(void *md_data_ptr);

/*
 * wolf_md_final_xof: produce variable-length XOF output (SHAKE128/256).
 * md_data_ptr points to a void* slot holding a WOLFSSL_EVP_MD_CTX*.
 */
int wolf_md_final_xof(void *md_data_ptr, unsigned char *out, size_t len);

/*
 * Native RIPEMD-160 via wolfCrypt wc_* API.
 * wolfSSL_EVP_ripemd160() is a stub (returns NULL), so we call the
 * low-level wc_InitRipeMd / wc_RipeMdUpdate / wc_RipeMdFinal directly.
 * md_data_ptr stores a heap-allocated RipeMd * pointer (sizeof(void*)).
 */
int wolf_rmd160_init(void *md_data_ptr);
int wolf_rmd160_update(void *md_data_ptr, const void *data, size_t count);
int wolf_rmd160_final(void *md_data_ptr, unsigned char *out);
int wolf_rmd160_copy(void *dst_md_data_ptr, const void *src_md_data_ptr);
int wolf_rmd160_cleanup(void *md_data_ptr);

/*
 * MD5+SHA1 combined digest for TLS 1.0/1.1 client certificate authentication.
 * Output is MD5(data) || SHA1(data) — 36 bytes total.
 * md_data points directly to a struct md5_sha1_ctx (no heap indirection).
 */
/* Returns sizeof(struct md5_sha1_ctx) — used as app_datasize in the EVP_MD. */
size_t wolf_md5sha1_ctx_size(void);

int wolf_md5sha1_init(void *md_data);
int wolf_md5sha1_update(void *md_data, const void *data, size_t len);
int wolf_md5sha1_final(void *md_data, unsigned char *out);
int wolf_md5sha1_copy(void *dst, const void *src);
int wolf_md5sha1_cleanup(void *md_data);

#ifdef __cplusplus
}
#endif

#endif /* EVP_WOLF_BRIDGE_H */
