/*
 * bn_shim.h - OpenSSL 1.1.1 BN (Big Number) API shims dispatching to wolfCrypt
 *
 * This header declares all shim functions for the BN group symbols.
 * The actual BIGNUM, BN_CTX, BN_MONT_CTX, BN_GENCB typedefs come from
 * including the wolfSSL OpenSSL compatibility header:
 *   wolfssl/openssl/bn.h
 *
 * Consumers should include wolfssl/openssl/bn.h (or openssl/bn.h in an
 * OpenSSL build) before including this header.
 */

#ifndef WOLFSHIM_BN_SHIM_H
#define WOLFSHIM_BN_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Forward declarations / opaque types
 * ------------------------------------------------------------------------- */

/* BN_BLINDING: wolfSSL does not expose BN_BLINDING publicly.
 * We define a minimal opaque struct here for ABI compatibility.
 * All BN_BLINDING_* functions are stubs.
 * WOLFSHIM_KNOWN_GAP: wolfSSL has no public BN_BLINDING equivalent; RSA blinding
 *   is handled internally. These stubs allow link-time compatibility only.
 */
typedef struct wolfshim_bn_blinding {
    void         *A;          /* blinding factor (BIGNUM*) - unused */
    void         *Ai;         /* inverse blinding factor - unused  */
    void         *mod;        /* modulus - unused                  */
    unsigned long flags;
    int           is_locked;
} WOLFSHIM_BN_BLINDING;

/* BN_RECP_CTX: reciprocal context - stub.
 * WOLFSHIM_KNOWN_GAP: wolfSSL has no BN_RECP_CTX equivalent.
 */
typedef struct wolfshim_bn_recp_ctx {
    void *N;          /* divisor BIGNUM* - unused */
    void *Nr;         /* reciprocal - unused       */
    int   num_bits;
    int   shift;
    int   flags;
} WOLFSHIM_BN_RECP_CTX;

/* ---------------------------------------------------------------------------
 * BN_BLINDING shims
 * All functions return error/NULL stubs because wolfSSL does not expose
 * BN_BLINDING in its public API.
 * ------------------------------------------------------------------------- */

WOLFSHIM_BN_BLINDING *wolfshim_BN_BLINDING_new(const void *A, const void *Ai,
                                                void *mod);
void wolfshim_BN_BLINDING_free(WOLFSHIM_BN_BLINDING *b);
int  wolfshim_BN_BLINDING_update(WOLFSHIM_BN_BLINDING *b, void *ctx);
int  wolfshim_BN_BLINDING_convert(void *n, WOLFSHIM_BN_BLINDING *b, void *ctx);
int  wolfshim_BN_BLINDING_invert(void *n, WOLFSHIM_BN_BLINDING *b, void *ctx);
int  wolfshim_BN_BLINDING_convert_ex(void *n, void *r, WOLFSHIM_BN_BLINDING *b,
                                     void *ctx);
int  wolfshim_BN_BLINDING_invert_ex(void *n, const void *r,
                                    WOLFSHIM_BN_BLINDING *b, void *ctx);
int  wolfshim_BN_BLINDING_is_current_thread(WOLFSHIM_BN_BLINDING *b);
void wolfshim_BN_BLINDING_set_current_thread(WOLFSHIM_BN_BLINDING *b);
int  wolfshim_BN_BLINDING_lock(WOLFSHIM_BN_BLINDING *b);
int  wolfshim_BN_BLINDING_unlock(WOLFSHIM_BN_BLINDING *b);
unsigned long wolfshim_BN_BLINDING_get_flags(const WOLFSHIM_BN_BLINDING *b);
void wolfshim_BN_BLINDING_set_flags(WOLFSHIM_BN_BLINDING *b, unsigned long f);
WOLFSHIM_BN_BLINDING *wolfshim_BN_BLINDING_create_param(
    WOLFSHIM_BN_BLINDING *b, const void *e, void *m, void *ctx,
    int (*bn_mod_exp)(void *r, const void *a, const void *p, const void *m,
                      void *ctx, void *m_ctx),
    void *m_ctx);

/* ---------------------------------------------------------------------------
 * BN_RECP_CTX shims (stub - wolfSSL has no equivalent)
 * ------------------------------------------------------------------------- */

WOLFSHIM_BN_RECP_CTX *wolfshim_BN_RECP_CTX_new(void);
void wolfshim_BN_RECP_CTX_free(WOLFSHIM_BN_RECP_CTX *recp);
int  wolfshim_BN_RECP_CTX_set(WOLFSHIM_BN_RECP_CTX *recp, const void *rdiv,
                               void *ctx);
int  wolfshim_BN_mod_mul_reciprocal(void *r, const void *x, const void *y,
                                    WOLFSHIM_BN_RECP_CTX *recp, void *ctx);
int  wolfshim_BN_mod_exp_recp(void *r, const void *a, const void *p,
                               const void *m, void *ctx);
int  wolfshim_BN_div_recp(void *dv, void *rem, const void *m,
                           WOLFSHIM_BN_RECP_CTX *recp, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSHIM_BN_SHIM_H */
