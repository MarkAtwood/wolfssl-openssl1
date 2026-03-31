/*
 * evp_digest_shim.c — OpenSSL 1.1.1 EVP digest shim (OpenSSL public API only)
 *
 * Compiled with OpenSSL public headers only; uses EVP_MD_meth_new() to build
 * EVP_MD objects at runtime — no need for internal "crypto/evp.h".
 *
 * Calls into evp_wolf_bridge.c (compiled separately with wolfSSL headers)
 * for the actual digest operations.
 *
 * Provides:
 *   EVP_sha1(), EVP_sha224(), EVP_sha256(), EVP_sha384(), EVP_sha512()
 *   EVP_sha512_224(), EVP_sha512_256()
 *   EVP_md4(), EVP_md5(), EVP_md5_sha1() (MD5||SHA1, 36 bytes)
 *   EVP_mdc2(), EVP_ripemd160(), EVP_whirlpool() (returns NULL)
 *   EVP_sha3_224(), EVP_sha3_256(), EVP_sha3_384(), EVP_sha3_512()
 *   EVP_shake128(), EVP_shake256()
 *   openssl_add_all_digests_int()   (replaces c_alld.o)
 *
 * Naming: new functions use #undef before each definition, not a wolfshim_
 * prefix. See ARCHITECTURE.md §8 for why rand_shim.c looks different.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef WOLFSHIM_DEBUG
# include <stdio.h>
#endif

/* OpenSSL public headers only — no internal crypto/evp.h needed */
#include <openssl/evp.h>
#include <openssl/objects.h>

/* Bridge API — no wolfSSL types, only void* and ints */
#include <evp_wolf_bridge.h>

/* ------------------------------------------------------------------ */
/* Context size: we store one void* (wolfSSL ctx ptr) in md_data      */
/* ------------------------------------------------------------------ */
#define SHIM_CTX_SIZE  ((int)sizeof(void *))

/* Layout of md_data for SHAKE128/256 digests.
 *
 * wolf_md_final_xof() receives a pointer to this struct, which equals a
 * pointer to the wctx slot, so the bridge's WOLFSSL_EVP_MD_CTX** cast works.
 */
struct shake_md_data {
    void     *wctx;         /* WOLFSSL_EVP_MD_CTX*, opaque to this TU */
    int       xof_output_len; /* requested XOF output length in bytes */
    int       xof_len_set;  /* 1 if xof_output_len has been set by the caller */
};
#define SHAKE_CTX_SIZE  ((int)sizeof(struct shake_md_data))

/* ------------------------------------------------------------------ */
/* Per-context EVP_MD callbacks                                        */
/* ------------------------------------------------------------------ */

static int shim_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return wolf_md_update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int shim_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return wolf_md_final(EVP_MD_CTX_md_data(ctx), md);
}

static int shim_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    return wolf_md_copy(EVP_MD_CTX_md_data(to),
                        /* const_cast: EVP_MD_CTX_md_data has no const overload
                         * in OpenSSL 1.1.1; the pointer is not written through */
                        EVP_MD_CTX_md_data((EVP_MD_CTX *)(void *)from));
}

static int shim_cleanup(EVP_MD_CTX *ctx)
{
    return wolf_md_cleanup(EVP_MD_CTX_md_data(ctx));
}

/* ------------------------------------------------------------------ */
/* Per-algorithm init callbacks                                        */
/* ------------------------------------------------------------------ */

#define DEFINE_INIT(name, algo_id)                          \
static int shim_init_##name(EVP_MD_CTX *ctx)               \
{                                                           \
    return wolf_md_init(EVP_MD_CTX_md_data(ctx), algo_id); \
}

DEFINE_INIT(sha1,       WOLF_MD_SHA1)
DEFINE_INIT(sha224,     WOLF_MD_SHA224)
DEFINE_INIT(sha256,     WOLF_MD_SHA256)
DEFINE_INIT(sha384,     WOLF_MD_SHA384)
DEFINE_INIT(sha512,     WOLF_MD_SHA512)
DEFINE_INIT(sha512_224, WOLF_MD_SHA512_224)
DEFINE_INIT(sha512_256, WOLF_MD_SHA512_256)
DEFINE_INIT(md4,        WOLF_MD_MD4)
DEFINE_INIT(md5,        WOLF_MD_MD5)
/* ripemd160 uses native wc_* API — no DEFINE_INIT needed here */
DEFINE_INIT(sha3_224,   WOLF_MD_SHA3_224)
DEFINE_INIT(sha3_256,   WOLF_MD_SHA3_256)
DEFINE_INIT(sha3_384,   WOLF_MD_SHA3_384)
DEFINE_INIT(sha3_512,   WOLF_MD_SHA3_512)
DEFINE_INIT(shake128,   WOLF_MD_SHAKE128)
DEFINE_INIT(shake256,   WOLF_MD_SHAKE256)
DEFINE_INIT(mdc2,       WOLF_MD_MDC2)

/* ------------------------------------------------------------------ */
/* SHAKE XOF callbacks (use struct shake_md_data in md_data)          */
/* ------------------------------------------------------------------ */

static int shake_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    (void)p2;
    if (cmd == EVP_MD_CTRL_XOF_LEN) {
        struct shake_md_data *sd =
            (struct shake_md_data *)EVP_MD_CTX_md_data(ctx);
        if (sd) {
            sd->xof_output_len = p1;
            sd->xof_len_set    = 1;
        }
        return 1;
    }
    return -2; /* not handled */
}

/* final for SHAKE128: use stored xof_output_len if set, else default 16 bytes */
static int shake128_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct shake_md_data *sd =
        (struct shake_md_data *)EVP_MD_CTX_md_data(ctx);
    size_t len = sd->xof_len_set ? (size_t)sd->xof_output_len : 16;
    /* Pass &sd->wctx so the bridge receives a WOLFSSL_EVP_MD_CTX** */
    return wolf_md_final_xof(&sd->wctx, md, len);
}

/* final for SHAKE256: use stored xof_output_len if set, else default 32 bytes */
static int shake256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct shake_md_data *sd =
        (struct shake_md_data *)EVP_MD_CTX_md_data(ctx);
    size_t len = sd->xof_len_set ? (size_t)sd->xof_output_len : 32;
    return wolf_md_final_xof(&sd->wctx, md, len);
}

/* ------------------------------------------------------------------ */
/* Build an EVP_MD via public meth API                                */
/* ------------------------------------------------------------------ */

/* EVP_MD_meth_* are the correct public API for OpenSSL 1.1.1 even though
 * wolfSSL headers may mark them deprecated — suppress those warnings. */
#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

static const EVP_MD *make_shim_md(int nid, int pkey_nid,
                                   int md_size, int block_size,
                                   int (*init_fn)(EVP_MD_CTX *))
{
    EVP_MD *md = EVP_MD_meth_new(nid, pkey_nid);
    if (!md) return NULL;
    EVP_MD_meth_set_result_size(md, md_size);
    EVP_MD_meth_set_input_blocksize(md, block_size);
    EVP_MD_meth_set_app_datasize(md, SHIM_CTX_SIZE);
    EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT);
    EVP_MD_meth_set_init(md, init_fn);
    EVP_MD_meth_set_update(md, shim_update);
    EVP_MD_meth_set_final(md, shim_final);
    EVP_MD_meth_set_copy(md, shim_copy);
    EVP_MD_meth_set_cleanup(md, shim_cleanup);
    return md;
}

/* SHAKE-specific copy: deep-copies the wolfSSL context AND preserves
 * xof_output_len/xof_len_set.  shim_copy (used by non-XOF digests) only handles wctx. */
static int shake_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct shake_md_data *dst =
        (struct shake_md_data *)EVP_MD_CTX_md_data(to);
    const struct shake_md_data *src =
        (const struct shake_md_data *)EVP_MD_CTX_md_data(
            (EVP_MD_CTX *)(void *)from);
    if (!dst || !src)
        return 1; /* nothing to copy */
    /* Deep-copy the wolfSSL context via the bridge */
    if (!wolf_md_copy(&dst->wctx, &src->wctx))
        return 0;
    /* Preserve the XOF output length setting */
    dst->xof_output_len = src->xof_output_len;
    dst->xof_len_set    = src->xof_len_set;
    return 1;
}

/* SHAKE-specific cleanup: free wolfSSL context via bridge */
static int shake_cleanup(EVP_MD_CTX *ctx)
{
    struct shake_md_data *sd =
        (struct shake_md_data *)EVP_MD_CTX_md_data(ctx);
    if (!sd)
        return 1;
    return wolf_md_cleanup(&sd->wctx);
}

/* XOF variant for SHAKE128/256: adds EVP_MD_FLAG_XOF, larger ctx, ctrl */
static const EVP_MD *make_shim_md_xof(int nid, int md_size, int block_size,
                                       int (*init_fn)(EVP_MD_CTX *),
                                       int (*final_fn)(EVP_MD_CTX *, unsigned char *))
{
    EVP_MD *md = EVP_MD_meth_new(nid, NID_undef);
    if (!md) return NULL;
    EVP_MD_meth_set_result_size(md, md_size);
    EVP_MD_meth_set_input_blocksize(md, block_size);
    EVP_MD_meth_set_app_datasize(md, SHAKE_CTX_SIZE);
    EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT | EVP_MD_FLAG_XOF);
    EVP_MD_meth_set_init(md, init_fn);
    EVP_MD_meth_set_update(md, shim_update);
    EVP_MD_meth_set_final(md, final_fn);
    EVP_MD_meth_set_copy(md, shake_copy);
    EVP_MD_meth_set_cleanup(md, shake_cleanup);
    EVP_MD_meth_set_ctrl(md, shake_ctrl);
    return md;
}

#ifdef __clang__
# pragma clang diagnostic pop
#elif defined(__GNUC__)
# pragma GCC diagnostic pop
#endif

/* ------------------------------------------------------------------ */
/* MD5+SHA1 callbacks — struct md5_sha1_ctx stored directly in        */
/* md_data (no pointer indirection); ctx_size set via bridge.         */
/* ------------------------------------------------------------------ */

static int md5sha1_init(EVP_MD_CTX *ctx)
    { return wolf_md5sha1_init(EVP_MD_CTX_md_data(ctx)); }
static int md5sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
    { return wolf_md5sha1_update(EVP_MD_CTX_md_data(ctx), data, count); }
static int md5sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
    { return wolf_md5sha1_final(EVP_MD_CTX_md_data(ctx), md); }
static int md5sha1_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
    { return wolf_md5sha1_copy(EVP_MD_CTX_md_data(to),
                               EVP_MD_CTX_md_data((EVP_MD_CTX *)(void *)from)); }
static int md5sha1_cleanup(EVP_MD_CTX *ctx)
    { return wolf_md5sha1_cleanup(EVP_MD_CTX_md_data(ctx)); }

/* ------------------------------------------------------------------ */
/* RIPEMD-160 callbacks — defined early so the constructor can use    */
/* them without a forward declaration.                                */
/* ------------------------------------------------------------------ */

static int rmd160_init(EVP_MD_CTX *ctx)
    { return wolf_rmd160_init(EVP_MD_CTX_md_data(ctx)); }
static int rmd160_update(EVP_MD_CTX *ctx, const void *data, size_t count)
    { return wolf_rmd160_update(EVP_MD_CTX_md_data(ctx), data, count); }
static int rmd160_final(EVP_MD_CTX *ctx, unsigned char *md)
    { return wolf_rmd160_final(EVP_MD_CTX_md_data(ctx), md); }
static int rmd160_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
    { return wolf_rmd160_copy(EVP_MD_CTX_md_data(to),
                              EVP_MD_CTX_md_data((EVP_MD_CTX *)(void *)from)); }
static int rmd160_cleanup(EVP_MD_CTX *ctx)
    { return wolf_rmd160_cleanup(EVP_MD_CTX_md_data(ctx)); }

/* ------------------------------------------------------------------ */
/* Module-level EVP_MD pointers — initialised once by the constructor */
/* All accessor functions below simply return these stable pointers.  */
/* No lazy init, no data races.                                        */
/* ------------------------------------------------------------------ */

static const EVP_MD *md_md5sha1    = NULL;
static const EVP_MD *md_sha1       = NULL;
static const EVP_MD *md_sha224     = NULL;
static const EVP_MD *md_sha256     = NULL;
static const EVP_MD *md_sha384     = NULL;
static const EVP_MD *md_sha512     = NULL;
static const EVP_MD *md_sha512_224 = NULL;
static const EVP_MD *md_sha512_256 = NULL;
static const EVP_MD *md_md4        = NULL;
static const EVP_MD *md_md5        = NULL;
static const EVP_MD *md_ripemd160  = NULL;
static const EVP_MD *md_sha3_224   = NULL;
static const EVP_MD *md_sha3_256   = NULL;
static const EVP_MD *md_sha3_384   = NULL;
static const EVP_MD *md_sha3_512   = NULL;
static const EVP_MD *md_shake128   = NULL;
static const EVP_MD *md_shake256   = NULL;
static const EVP_MD *md_mdc2       = NULL;

/* Undefine any wolfSSL macro aliases that might redirect these names */
#ifdef EVP_sha1
# undef EVP_sha1
#endif
#ifdef EVP_sha224
# undef EVP_sha224
#endif
#ifdef EVP_sha256
# undef EVP_sha256
#endif
#ifdef EVP_sha384
# undef EVP_sha384
#endif
#ifdef EVP_sha512
# undef EVP_sha512
#endif
#ifdef EVP_sha512_224
# undef EVP_sha512_224
#endif
#ifdef EVP_sha512_256
# undef EVP_sha512_256
#endif
#ifdef EVP_md4
# undef EVP_md4
#endif
#ifdef EVP_md5
# undef EVP_md5
#endif
#ifdef EVP_md5_sha1
# undef EVP_md5_sha1
#endif
#ifdef EVP_ripemd160
# undef EVP_ripemd160
#endif
#ifdef EVP_sha3_224
# undef EVP_sha3_224
#endif
#ifdef EVP_sha3_256
# undef EVP_sha3_256
#endif
#ifdef EVP_sha3_384
# undef EVP_sha3_384
#endif
#ifdef EVP_sha3_512
# undef EVP_sha3_512
#endif
#ifdef EVP_shake128
# undef EVP_shake128
#endif
#ifdef EVP_shake256
# undef EVP_shake256
#endif
#ifdef EVP_mdc2
# undef EVP_mdc2
#endif
#ifdef EVP_whirlpool
# undef EVP_whirlpool
#endif

/* ------------------------------------------------------------------ */
/* Constructor: runs once at library load (single-threaded)           */
/* Initialises all module-level EVP_MD pointers.                      */
/* ------------------------------------------------------------------ */

/* EVP_MD_meth_* deprecation warnings suppressed for the constructor  */
#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/* Helper: abort with a diagnostic if a required EVP_MD failed to allocate.
 * Only called for digests that are hard requirements (SHA-1, SHA-256, etc.);
 * optional/legacy digests (MDC2, RIPEMD-160) use the softer if(m) guard. */
#define REQUIRE_MD(ptr, name) \
    do { \
        if (!(ptr)) { \
            fprintf(stderr, \
                "[wolfshim] FATAL: evp_digest_shim_init: failed to allocate " \
                "EVP_MD for " name " — out of memory at library load.\n" \
                "  EVP_" name "() will return NULL; all digest operations " \
                "using this algorithm will crash or fail silently.\n"); \
            abort(); \
        } \
    } while (0)

static void __attribute__((constructor)) evp_digest_shim_init(void)
{
    /* MD5+SHA1 combined digest for TLS 1.0/1.1 client certificate auth */
    {
        EVP_MD *m = EVP_MD_meth_new(NID_md5_sha1, NID_md5_sha1);
        if (!m) {
            fprintf(stderr,
                "[wolfshim] FATAL: evp_digest_shim_init: failed to allocate "
                "EVP_MD for md5_sha1 — out of memory at library load.\n"
                "  EVP_md5_sha1() will return NULL; TLS 1.0/1.1 client "
                "certificate authentication will fail.\n");
            abort();
        }
        EVP_MD_meth_set_result_size(m, 36);
        EVP_MD_meth_set_input_blocksize(m, 64);
        EVP_MD_meth_set_app_datasize(m, (int)wolf_md5sha1_ctx_size());
        EVP_MD_meth_set_flags(m, EVP_MD_FLAG_DIGALGID_ABSENT);
        EVP_MD_meth_set_init(m, md5sha1_init);
        EVP_MD_meth_set_update(m, md5sha1_update);
        EVP_MD_meth_set_final(m, md5sha1_final);
        EVP_MD_meth_set_copy(m, md5sha1_copy);
        EVP_MD_meth_set_cleanup(m, md5sha1_cleanup);
        md_md5sha1 = m;
    }

    /* Standard hash digests — these underpin TLS and certificate handling;
     * failure here means the library cannot function. */
    md_sha1       = make_shim_md(NID_sha1,       NID_sha1WithRSAEncryption,       20,  64, shim_init_sha1);
    REQUIRE_MD(md_sha1,       "sha1");
    md_sha224     = make_shim_md(NID_sha224,     NID_sha224WithRSAEncryption,     28,  64, shim_init_sha224);
    REQUIRE_MD(md_sha224,     "sha224");
    md_sha256     = make_shim_md(NID_sha256,     NID_sha256WithRSAEncryption,     32,  64, shim_init_sha256);
    REQUIRE_MD(md_sha256,     "sha256");
    md_sha384     = make_shim_md(NID_sha384,     NID_sha384WithRSAEncryption,     48, 128, shim_init_sha384);
    REQUIRE_MD(md_sha384,     "sha384");
    md_sha512     = make_shim_md(NID_sha512,     NID_sha512WithRSAEncryption,     64, 128, shim_init_sha512);
    REQUIRE_MD(md_sha512,     "sha512");
    md_sha512_224 = make_shim_md(NID_sha512_224, NID_sha512_224WithRSAEncryption, 28, 128, shim_init_sha512_224);
    REQUIRE_MD(md_sha512_224, "sha512_224");
    md_sha512_256 = make_shim_md(NID_sha512_256, NID_sha512_256WithRSAEncryption, 32, 128, shim_init_sha512_256);
    REQUIRE_MD(md_sha512_256, "sha512_256");
    md_md4        = make_shim_md(NID_md4,        NID_md4WithRSAEncryption,        16,  64, shim_init_md4);
    REQUIRE_MD(md_md4,        "md4");
    md_md5        = make_shim_md(NID_md5,        NID_md5WithRSAEncryption,        16,  64, shim_init_md5);
    REQUIRE_MD(md_md5,        "md5");

    /* SHA-3 family */
    md_sha3_224   = make_shim_md(NID_sha3_224,   NID_undef,  28, 144, shim_init_sha3_224);
    REQUIRE_MD(md_sha3_224,   "sha3_224");
    md_sha3_256   = make_shim_md(NID_sha3_256,   NID_undef,  32, 136, shim_init_sha3_256);
    REQUIRE_MD(md_sha3_256,   "sha3_256");
    md_sha3_384   = make_shim_md(NID_sha3_384,   NID_undef,  48, 104, shim_init_sha3_384);
    REQUIRE_MD(md_sha3_384,   "sha3_384");
    md_sha3_512   = make_shim_md(NID_sha3_512,   NID_undef,  64,  72, shim_init_sha3_512);
    REQUIRE_MD(md_sha3_512,   "sha3_512");

    /* SHAKE XOF digests */
    md_shake128   = make_shim_md_xof(NID_shake128, 16, 168, shim_init_shake128, shake128_final);
    REQUIRE_MD(md_shake128,   "shake128");
    md_shake256   = make_shim_md_xof(NID_shake256, 32, 136, shim_init_shake256, shake256_final);
    REQUIRE_MD(md_shake256,   "shake256");

    /* MDC2 — legacy, not a hard requirement; NULL is tolerated */
    md_mdc2       = make_shim_md(NID_mdc2, NID_mdc2WithRSA, 8, 8, shim_init_mdc2);

    /* RIPEMD-160: uses native wolfCrypt wc_* API callbacks */
    {
        EVP_MD *m = EVP_MD_meth_new(NID_ripemd160, NID_ripemd160WithRSA);
        if (m) {
            EVP_MD_meth_set_result_size(m, 20);
            EVP_MD_meth_set_input_blocksize(m, 64);
            EVP_MD_meth_set_app_datasize(m, SHIM_CTX_SIZE);
            EVP_MD_meth_set_flags(m, EVP_MD_FLAG_DIGALGID_ABSENT);
            EVP_MD_meth_set_init(m, rmd160_init);
            EVP_MD_meth_set_update(m, rmd160_update);
            EVP_MD_meth_set_final(m, rmd160_final);
            EVP_MD_meth_set_copy(m, rmd160_copy);
            EVP_MD_meth_set_cleanup(m, rmd160_cleanup);
            md_ripemd160 = m;
        }
    }
}

#ifdef __clang__
# pragma clang diagnostic pop
#elif defined(__GNUC__)
# pragma GCC diagnostic pop
#endif

/* ------------------------------------------------------------------ */
/* Public EVP_xxx() accessor functions — no lazy init, no data race   */
/* ------------------------------------------------------------------ */

const EVP_MD *EVP_sha1(void)       { return md_sha1; }
const EVP_MD *EVP_sha224(void)     { return md_sha224; }
const EVP_MD *EVP_sha256(void)     { return md_sha256; }
const EVP_MD *EVP_sha384(void)     { return md_sha384; }
const EVP_MD *EVP_sha512(void)     { return md_sha512; }
const EVP_MD *EVP_sha512_224(void) { return md_sha512_224; }
const EVP_MD *EVP_sha512_256(void) { return md_sha512_256; }
const EVP_MD *EVP_md4(void)        { return md_md4; }
const EVP_MD *EVP_md5(void)        { return md_md5; }
const EVP_MD *EVP_ripemd160(void)  { return md_ripemd160; }
const EVP_MD *EVP_sha3_224(void)   { return md_sha3_224; }
const EVP_MD *EVP_sha3_256(void)   { return md_sha3_256; }
const EVP_MD *EVP_sha3_384(void)   { return md_sha3_384; }
const EVP_MD *EVP_sha3_512(void)   { return md_sha3_512; }
const EVP_MD *EVP_shake128(void)   { return md_shake128; }
const EVP_MD *EVP_shake256(void)   { return md_shake256; }
const EVP_MD *EVP_mdc2(void)       { return md_mdc2; }

/* MD5+SHA1 combined digest — TLS 1.0/1.1 client certificate authentication */
const EVP_MD *EVP_md5_sha1(void)  { return md_md5sha1; }

/* Not supported */
const EVP_MD *EVP_whirlpool(void) { return NULL; }

/* ------------------------------------------------------------------ */
/* openssl_add_all_digests_int — replaces c_alld.o                    */
/* ------------------------------------------------------------------ */
void openssl_add_all_digests_int(void)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr, "[wolfshim] evp_digest: openssl_add_all_digests_int\n");
#endif
    EVP_add_digest(EVP_md4());
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "ssl3-md5");
    EVP_add_digest(EVP_sha1());
    EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
    EVP_add_digest(EVP_mdc2());
    EVP_add_digest(EVP_ripemd160());
    EVP_add_digest_alias(SN_ripemd160, "ripemd");
    EVP_add_digest_alias(SN_ripemd160, "rmd160");
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
    EVP_add_digest(EVP_sha512_224());
    EVP_add_digest(EVP_sha512_256());
    EVP_add_digest(EVP_sha3_224());
    EVP_add_digest(EVP_sha3_256());
    EVP_add_digest(EVP_sha3_384());
    EVP_add_digest(EVP_sha3_512());
    EVP_add_digest(EVP_shake128());
    EVP_add_digest(EVP_shake256());
}
