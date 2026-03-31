# wolfshim Architecture Decision Record

This document records the key architectural decisions behind the wolfshim.
It answers the "why" questions that are not obvious from reading the code.

**Target audience:** Maintainers, not end-users. If you are about to refactor
something and it feels unnecessary, read the relevant section here first.

---

## Table of contents

**Memory and context management**
1. [Why does AES use heap allocation?](#1-aes-heap-allocation)
2. [Why does SHA_Final keep the allocation alive?](#2-sha-final-keeps-the-allocation-alive-for-reuse)
3. [Why does OPENSSL_cleanse have destructor hooks?](#3-openssl_cleanse-destructor-hooks)

**Build and linking**
4. [Why is WOLFCRYPT_EXCLUDE=1 mandatory?](#4-wolfcrypt_exclude-is-mandatory)
5. [Why are EC, BN, and RSA not in libwolfshim.a?](#5-ec-bn-and-rsa-not-in-libwolfshima)
6. [Which OpenSSL object files does the shim replace?](#6-which-openssl-object-files-does-the-shim-replace)

**Header and naming conventions**
7. [What is the two-header problem? (RSA, BN)](#7-the-two-header-problem)
8. [Why does RAND use a wolfshim_ prefix but AES/SHA/DES do not?](#8-rand-naming-prefix)
9. [Why is AES_ENCRYPT=1 but wolfCrypt's AES_ENCRYPTION=0?](#9-aes-direction-constant-inversion)

**EVP layer**
10. [How does the EVP digest layer work?](#10-evp-digest-layer)
11. [Why does RIPEMD-160 use wc_* directly instead of the EVP bridge?](#11-ripemd-160-direct-wc-api)
12. [Why are EVP_MD objects initialized with a constructor?](#12-evp_md-constructor-initialization)

**Random number generation**
13. [Why does shim_rng.c exist separately from rand_shim.c?](#13-shim_rngc-vs-rand_shimc)
14. [What does the RAND_DRBG hierarchy actually do?](#14-rand_drbg-hierarchy)

**Thread safety**
15. [Per-thread WC_RNG design](#15-per-thread-wc_rng)
16. [Why is there a global mutex for BN_MONT_CTX_set_locked?](#16-global-mont-mutex)

**Cryptographic correctness**
17. [Why is BN_consttime_swap not constant-time?](#17-bn_consttime_swap-is-not-constant-time)
18. [Why does DES ECB use CBC with a zero IV?](#18-des-ecb-as-cbc-with-zero-iv)
19. [Why does ChaCha20_ctr32 call explicit_bzero on a stack context?](#19-chacha20-explicit_bzero)
20. [Why does Poly1305_ctx_size exist?](#20-poly1305_ctx_size)

**Code maintenance**
21. [The WOLFSHIM_GAP tagging system](#21-the-wolfshim_gap-tagging-system)
22. [The _Static_assert + version guard pattern](#22-_static_assert--version-guard-pattern)

---

## 1. AES heap allocation

**Decision:** `AES_set_encrypt_key` allocates a `wolfCrypt Aes` on the heap and
stores a pointer to it inside the caller's `AES_KEY` buffer. A magic sentinel is
written alongside the pointer so that `aes_ctx_get` can detect uninitialized or
zeroed keys.

**Why:** wolfCrypt's `Aes` struct is ~1104 bytes (varies by build flags). OpenSSL's `AES_KEY`
struct is 244 bytes. The shim cannot store `Aes` inline in `AES_KEY` — there is
not enough room. The only available space is the caller's buffer itself, so the
first two pointer-width slots of `AES_KEY` are repurposed to hold a heap pointer
and a magic sentinel (`WOLFSHIM_AES_CTX_MAGIC = 0x574F4C4657534844`).

**Consequence for callers:** Stack-allocated `AES_KEY` objects (the dominant
pattern in OpenSSL code) will leak one `Aes` allocation per key setup unless the
caller explicitly calls `OPENSSL_cleanse()` (which invokes the internal
`aes_ctx_free()` destructor hook — see §3). OpenSSL's own implementation stores the
key schedule inline and has nothing to free; `AES_KEY_free` does not exist in the
OpenSSL 1.1.1 public API. This is a fundamental tension with the OpenSSL ABI that
cannot be resolved without changing the API. See `shim/include/aes_ctx.h` for the
full accounting of the leak rate and a pointer to the migration path.

**wolfshim extension:** `AES_KEY_new()` / `AES_KEY_free()` in `aes_shim.h` and
`aes_shim.c` provide a heap-allocation pair that eliminates the leak for callers
willing to adopt explicit lifetime management.  These are wolfshim-specific
extensions not present in any version of OpenSSL prior to OpenSSL 3; guard on
`#ifdef WOLFSHIM_HAS_AES_KEY_FREE` when building against both stacks.
See `shim/RELEASE-NOTES.md §"wolfshim extensions"` for usage guidance.

**What to do if you want to fix this more broadly:** See `../README.md` §Path
forward (project root).

**Guard:** `aes_ctx_get` aborts with a detailed message if the sentinel is absent
or the buffer appears to have been zeroed after initialization. Do not remove the
sentinel check — it turns silent wrong-ciphertext failures into immediate visible
crashes.

---

## 2. SHA_Final keeps the allocation alive for reuse

**Decision:** `SHA1_Final` / `SHA256_Final` / etc. zero the wolfSSL context with
`explicit_bzero` and re-set the sentinel, but **keep the heap allocation alive**.
The pointer in the caller's buffer remains valid. A subsequent `SHA*_Init` sees
a non-NULL pointer with a valid sentinel and reinitialises the existing allocation
in-place via `wolfSSL_SHA*_Init`, with no malloc.

**Why:** The wolfSSL SHA context (`WOLFSSL_SHA_CTX` etc.) is larger than
OpenSSL's `SHA_CTX` / `SHA256_CTX` structs, for the same reason as AES. The shim
stores a heap pointer in the first pointer-width slot of the caller's SHA context
buffer (sentinels: `WOLFSHIM_SHA1_CTX_MAGIC = "WSH1CONT"`,
`WOLFSHIM_SHA256_CTX_MAGIC = "WSH2CONT"`, `WOLFSHIM_SHA512_CTX_MAGIC =
"WSH5CONT"`).

**How Init distinguishes a reusable allocation from garbage:** The sentinel in
the second pointer slot is the signal. `SHA*_Init` checks `if (*pp && sentinel_ok)`:
if both are true it calls `wolfSSL_SHA*_Init(*pp)` to reset in place; if either
is absent it allocates fresh. After `Final`, `*pp` is non-NULL and the sentinel
is set, so the reuse path fires on the next `Init`. After `OPENSSL_cleanse`, both
slots are zeroed, so the allocation path fires — no use-after-free.

**Why Final zeroes the wolfSSL context rather than just leaving it:** The wolfSSL
context contains the intermediate hash state, which may be derived from HMAC key
material on the inner/outer hashing paths. `explicit_bzero` wipes that state
before the allocation is reused. The sentinel is re-written after the bzero so
that `Init` can still find and reuse the allocation.

**Behavioral difference from OpenSSL:** OpenSSL's `SHA_Final` leaves the context
in a finalised-but-allocated state. Calling `SHA_Update` after `SHA_Final` without
a new `SHA_Init` produces garbage in OpenSSL; in this shim it reinitialises the
context (because the sentinel and pointer are still set). Either way, relying on
`Update` after `Final` without an intervening `Init` is incorrect.

**Lifetime and cleanup:** The allocation outlives `Final` and is freed only when
`OPENSSL_cleanse` is called on the caller's buffer (the normal cleanup path for
stack-allocated SHA contexts), or when the next `SHA*_Init` call on that buffer
is preceded by a `OPENSSL_cleanse`. Stack-allocated `SHA_CTX` objects that go
out of scope without `OPENSSL_cleanse` leak one wolfSSL context — see
`wolfshim.supp` for the Valgrind suppression.

**wolfshim extension:** `SHA_CTX_new()` / `SHA_CTX_free()`,
`SHA256_CTX_new()` / `SHA256_CTX_free()`, and `SHA512_CTX_new()` /
`SHA512_CTX_free()` in `sha_shim.h` and `sha_shim.c` provide a heap-allocation
pair that eliminates the leak for callers willing to adopt explicit lifetime
management.  These are wolfshim-specific extensions not present in any version
of OpenSSL prior to OpenSSL 3; guard on `#ifdef WOLFSHIM_HAS_SHA_CTX_FREE`
when building against both stacks.
See `shim/RELEASE-NOTES.md §"wolfshim extensions"` for usage guidance.

---

## 3. OPENSSL_cleanse destructor hooks

**Decision:** The shim overrides `OPENSSL_cleanse` to check for wolfshim magic
sentinels before zeroing. If a sentinel is found, the heap context is freed and
zeroed before the caller's buffer is wiped.

**Why:** OpenSSL's `AES_KEY` and `SHA_CTX` are plain structs with inline storage;
zeroing them with `OPENSSL_cleanse` destroys everything in one pass. This shim
stores only a heap pointer and sentinel in those buffers. A plain `explicit_bzero`
would zero the pointer without freeing or zeroing the underlying allocation —
leaking key material and hash state to the heap.

OpenSSL itself calls `OPENSSL_cleanse` on these buffers in two situations:

1. **Direct caller cleanup:** Code like `AES_set_encrypt_key(..., &actx); ...;
   OPENSSL_cleanse(&actx, sizeof(actx));` is the standard pattern for wiping a
   stack-allocated key. Without the hook this leaks the heap `Aes` struct
   containing the round-key schedule.

2. **EVP teardown path:** `EVP_CIPHER_CTX_free` / `EVP_CIPHER_CTX_reset` calls
   `OPENSSL_cleanse(c->cipher_data, c->cipher->ctx_size)`. The `BLOCK_CIPHER_generic`
   macro registers `NULL` as the cleanup callback for CBC/ECB/CFB/OFB modes;
   `OPENSSL_cleanse` is the only teardown they get.

**How it works:** Before calling `explicit_bzero`, the shim calls `aes_ctx_free`
and `sha_ctx_free_any` on the buffer. Both are no-ops unless the magic sentinel at
`offset sizeof(void*)` matches one of the four known values. The `len >=
2*sizeof(void*)` guard prevents reading past the end of small buffers.

**Sentinel values** (all 64-bit, checked sequentially):
- AES: `0x574F4C4657534844` ("WOLFWSHD")
- SHA-1: `0x57534831434F4E54` ("WSH1CONT")
- SHA-256: `0x57534832434F4E54` ("WSH2CONT")
- SHA-512: `0x57534835434F4E54` ("WSH5CONT")

**Residual leak:** Stack-allocated contexts that go out of scope *without* an
`OPENSSL_cleanse` call — for example, code that uses `goto` to exit a function
before cleanup — still leak. This is the caller's fault in the OpenSSL contract
too, but the leak consequence is worse here because the leaked block contains live
key material. Document this to customers.

---

## 4. WOLFCRYPT_EXCLUDE is mandatory

**Decision:** The build flag `WOLFCRYPT_EXCLUDE=1` must always be set. It is not
optional or a performance toggle.

**Why:** When `WOLFCRYPT_EXCLUDE=0` (or absent), OpenSSL's AES object files are
included in the link. On x86 without AES-NI, OpenSSL's BSAES (bit-sliced AES)
assembly path may be selected at runtime. BSAES reads the AES round-key schedule
directly from `AES_KEY.rd_key[]`. But this shim does not populate `rd_key[]` — it
stores a `wolfCrypt Aes*` pointer there instead. BSAES will silently interpret
that pointer as a round-key schedule and produce wrong ciphertext with no error
signal.

`WOLFCRYPT_EXCLUDE=1` excludes OpenSSL's AES object files from the build,
preventing BSAES from being compiled in at all. This is the only mitigation.
There is no runtime check that can catch this; the corruption is silent.

**Why the rounds-field mitigation was not applied:** An alternative would be to
set `AES_KEY.rounds` to the correct value (`6 + bits/32`) so that BSAES would at
least use the right round count. This was investigated but is not applicable:
`WOLFSSL_AES_KEY` exposes no public `rounds` field. The mitigation cannot be
written.

**Where enforced:** `patches/Makefile.wolfshim` and `build.sh`. The comments at
both sites explain the BSAES mechanism. Do not remove or conditionalize this flag.

---

## 5. EC, BN, and RSA not in libwolfshim.a

**Decision:** `ec_shim.c`, `bn_shim.c`, and `rsa_shim.c` are NOT compiled into
`libwolfshim.a`. They have standalone `CMakeLists.txt` files that build separate
static libraries (`libwolfshim_ec.a`, `libwolfshim_bn.a`, `libwolfshim_rsa.a`).
Those libraries are not wired into the main `Makefile.wolfshim` build.

**Why:** In the shipping configuration, EC/BN/RSA public symbols are provided by
wolfSSL's own OpenSSL compatibility layer (`libwolfssl.so`, built with
`OPENSSL_EXTRA`). wolfSSL's compat layer already implements `EC_KEY_new`,
`BN_new`, `RSA_new`, etc. The shim does not need to override them in the default
build.

The shim source files for EC/BN/RSA exist as alternative override implementations
for cases where wolfSSL's built-in compat layer is insufficient (e.g. missing
functions, signature mismatches, or behavior divergences discovered in testing).
They can be enabled by linking `libwolfshim_ec.a` etc. before `libwolfssl.so`.

**How to confirm what's in the archive:**
```
ar t shim/lib/libwolfshim.a
```
EC, BN, and RSA object files will not appear.

---

## 6. Which OpenSSL object files does the shim replace?

Several shim modules are designed as drop-in replacements for specific OpenSSL
object files. This is the mechanism by which the shim intercepts crypto
operations — the shim objects are linked before the OpenSSL objects, preempting
them.

| Shim file | Replaces OpenSSL object(s) |
|-----------|---------------------------|
| `chacha_shim.c` | `crypto/chacha/chacha-x86_64.o`, `crypto/poly1305/poly1305.o`, `crypto/poly1305/poly1305-x86_64.o` |
| `des_modes_bridge.c` | `cfb64ede.o`, `cfb64enc.o`, `cfb_enc.o`, `ecb3_enc.o`, `ofb64ede.o`, `ofb64enc.o`, `ofb_enc.o`, `pcbc_enc.o`, `qud_cksm.o`, `str2key.o`, `xcbc_enc.o` |
| `aesni_shim.c` | `aesni-x86_64.o` (the hardware AES-NI assembly path) |
| `evp_digest_shim.c` | `c_alld.o` (digest algorithm registration: `openssl_add_all_digests_int`) |
| `rand_shim.c` | The RAND_DRBG subsystem in `crypto/rand/` |

`des_modes_bridge.c` replaces eleven OpenSSL object files because wolfCrypt
provides no ECB primitive — see §18 for the zero-IV-CBC design. The replacement
is compiled with wolfSSL headers only to avoid mixing header namespaces.

---

## 7. The two-header problem

**Affected files:** `shim/src/rsa/rsa_shim.c`, `shim/src/bn/bn_shim.c`

**Decision:** When an OpenSSL `BIGNUM*` must be passed to a wolfSSL API, serialize
it to a raw byte buffer using the real OpenSSL BN functions, then reconstruct a
`WOLFSSL_BIGNUM` via `wolfSSL_BN_bin2bn`. Do NOT cast an OpenSSL `BIGNUM*` to
`WOLFSSL_BIGNUM*` directly.

**Why:** Both OpenSSL and wolfSSL define `struct bignum_st`, and they are
different structs with incompatible internal layouts. When `rsa_shim.c` includes
wolfSSL's headers, wolfSSL `#define BIGNUM WOLFSSL_BIGNUM` — so within that
translation unit, the name `BIGNUM` refers to `WOLFSSL_BIGNUM`. But a caller
passing in a `const BIGNUM *e` to `RSA_generate_key_ex` is passing a pointer to
an OpenSSL `struct bignum_st`, not a `WOLFSSL_BIGNUM`. Both headers must be in
scope simultaneously because `rsa_shim.c` must include wolfSSL headers for the
wolfSSL types it uses, and also implement the OpenSSL function signatures. There
is no way to avoid the include conflict without splitting the translation unit.

**Solution:** `rsa_shim.c` undefines `BN_num_bits` and `BN_bn2bin` (wolfSSL macro
aliases), forward-declares the real OpenSSL implementations from
`crypto/bn/bn_lib.c` (which is linked because `WOLFCRYPT_EXCLUDE` does not
exclude the BN layer), and uses those to serialize the exponent. The
`ossl_exponent_to_wolf_bn` helper encapsulates this pattern.

**Rule for new code:** Any function in `rsa_shim.c` or `bn_shim.c` that accepts
a `BIGNUM*` from an external caller and needs to pass it to a wolfSSL API must
use the same serialize-and-reconstruct pattern. Do not cast. The structs are
incompatible and the cast produces silent memory corruption.

---

## 8. RAND naming prefix

**Decision:** RAND functions are implemented as `wolfshim_RAND_*` (Layer 1) with
thin one-line aliases under the public OpenSSL names (Layer 2). AES, SHA, DES,
BN, and RSA do NOT use this two-layer pattern — they define the OpenSSL name
directly using targeted `#undef` before each function definition.

**Why the two layers for RAND:** The wolfshim_ prefix is a design choice for
testability, not a requirement imposed by the wolfSSL macro system. The Layer 1
functions have stable internal names that unit tests in `shim/tests/` can call
directly without depending on linker symbol interposition. The `#undef` approach
(used by all other modules) would have worked equally well for build correctness.

**Why the #undef approach for everything else:** wolfSSL's headers `#define` many
OpenSSL symbol names as macro aliases (e.g. `#define AES_cbc_encrypt
wolfSSL_AES_cbc_encrypt`). A `#undef` immediately before a function definition
strips the alias so the compiler sees a definition of the OpenSSL symbol, not the
wolfSSL one. This is simpler than the two-layer approach and produces no extra
symbols in the `.so`.

**Guidance for new functions:** Add new functions to `rand_shim.c` using both
layers (wolfshim_ impl + alias). Add new functions to all other modules using
`#undef` before the definition (as in `aes_shim.c`, `des_shim.c`, `bn_shim.c`).
Do not introduce the two-layer pattern to other modules unless you also have a
unit-test infrastructure that needs to call those functions by a stable internal
name.

---

## 9. AES direction constant inversion

**Decision:** Every AES direction check in the shim must use OpenSSL's integer
constants (`AES_ENCRYPT=1`, `AES_DECRYPT=0`) and explicitly map them to wolfCrypt
before passing to any `wc_Aes*` call.

**Why:** OpenSSL and wolfCrypt use opposite integer values for the direction flag:
- OpenSSL: `AES_ENCRYPT=1`, `AES_DECRYPT=0`
- wolfCrypt: `AES_ENCRYPTION=0`, `AES_DECRYPTION=1`

They are inverted. Passing an OpenSSL direction constant directly to a wolfCrypt
API silently reverses encrypt/decrypt. The correct mapping is:
```c
wc_enc = (openssl_enc == AES_DECRYPT) ? 1 : 0;   /* NOT a direct assignment */
```

wolfSSL's headers remap `AES_ENCRYPT`/`AES_DECRYPT` to its own enum values via
macros. `wolfshim_preinclude.h` undefines those macros and restores the OpenSSL
integer constants so that all shim code using `enc == AES_ENCRYPT` works
correctly regardless of include order.

**Where guarded:** `wolfshim_preinclude.h` (canonical definition), `aliases.c`,
and `aes_shim.c` each document this. If you see an `#undef AES_ENCRYPT` followed
by `#define AES_ENCRYPT 1` — do not remove it. That is not a redundant guard; it
is restoring the constant after wolfSSL clobbered it.

---

## 10. EVP digest layer

**Decision:** The EVP digest implementation is split across two translation units
with different header sets:

- `evp_wolf_bridge.c` — compiled with **wolfSSL headers only**. Contains the
  actual init/update/final/copy/cleanup callbacks using `wolfSSL_EVP_MD_CTX_*`.
  Exports a header-only API (`evp_wolf_bridge.h`) that uses only `void*` and
  integer types — no wolfSSL types leak across the boundary.

- `evp_digest_shim.c` — compiled with **OpenSSL public headers only**. Uses
  `EVP_MD_meth_new` / `EVP_MD_meth_set_*` to build `EVP_MD` objects. Calls into
  `evp_wolf_bridge.c` through the opaque bridge API. Has no knowledge of wolfSSL
  types.

**Why the split:** Mixing wolfSSL and OpenSSL headers in one translation unit
causes macro aliasing conflicts (the two-header problem, §7). The split ensures
each TU has a clean namespace.

**EVP_MD context sizing:** Every `EVP_MD` object sets `ctx_size =
wolf_md_ptr_size()` which returns `sizeof(WOLFSSL_EVP_MD_CTX*)`. OpenSSL
allocates exactly that many bytes in `EVP_MD_CTX.md_data`. The bridge stores a
single pointer there (to a heap-allocated `WOLFSSL_EVP_MD_CTX`). This indirection
is intentional: it avoids an ABI dependency on the size of `WOLFSSL_EVP_MD_CTX`
at compile time. The runtime wolfSSL library allocates the context at the correct
size internally via `wolfSSL_EVP_MD_CTX_new()`.

**Exception — MD5+SHA1:** The combined MD5+SHA1 digest (36 bytes, used for TLS
1.0/1.1 client certificate authentication) stores its context *inline* rather
than via heap pointer. It has a fixed struct (`wolf_md5sha1_ctx`) containing both
hash states, sized via `wolf_md5sha1_ctx_size()`. This is safe because MD5+SHA1
is only ever used through the EVP path (not stored in a caller-visible buffer),
so there is no size mismatch problem.

---

## 11. RIPEMD-160 direct wc_* API

**Decision:** RIPEMD-160 does not go through the `wolfSSL_EVP_*` path like other
digests. Its init/update/final callbacks call `wc_InitRipeMd` / `wc_RipeMdUpdate`
/ `wc_RipeMdFinal` directly.

**Why:** `wolfSSL_EVP_ripemd160()` returns NULL in wolfSSL's compat layer —
wolfSSL has not implemented RIPEMD-160 in its EVP bridge. The only working path
is the low-level `wc_*` API. The `evp_wolf_bridge.c` dispatch table has a
`WOLF_MD_RMD160` case that hits this path; `algo_to_wssl_md()` returns the result
of `wolfSSL_EVP_ripemd160()` which is NULL, so `rmd160_init` skips the EVP path
entirely and uses `wc_InitRipeMd` directly.

**When wolfSSL fixes this:** If wolfSSL implements `EVP_ripemd160()`, the direct
`wc_*` callbacks can be removed and RIPEMD-160 can follow the same path as SHA-2.
Until then, do not remove the direct path.

---

## 12. EVP_MD constructor initialization

**Decision:** All `EVP_MD` objects are initialized once at library load time in
a `__attribute__((constructor))` function (`evp_digest_shim_init`), not lazily
on first call.

**Why:** Lazy init of `EVP_MD*` module-level pointers requires a double-checked
lock on every `EVP_sha256()` call (a very hot path). A constructor runs before
`main` and before any threads are spawned, so it is guaranteed single-threaded
and needs no lock. After the constructor runs, the `EVP_*()` accessor functions
are just pointer returns — zero branch overhead, no data races.

**Practical implication:** If `EVP_MD_meth_new` fails during the constructor (OOM
at startup), the corresponding `EVP_*()` function returns NULL. This is an
unrecoverable startup failure and any subsequent `EVP_DigestInit` using that
digest will crash. This is acceptable — if we cannot allocate a few `EVP_MD`
structs at startup, we cannot do cryptography.

---

## 13. shim_rng.c vs rand_shim.c

**Decision:** Per-thread `WC_RNG` lifecycle management lives in `shim/src/rng/shim_rng.c`
as a single authoritative implementation. `rsa_shim.c` and `pkey_meth_shim.c`
call `shim_rng_generate()` / `shim_get_thread_rng()` rather than maintaining
their own copies.

**Why a separate file:** Both `rsa_shim.c` and `pkey_meth_shim.c` need
per-thread `WC_RNG` (for RSA key generation and EVP_PKEY keygen respectively).
Previously each had an identical copy of the pthread TLS key management code
(`s_rng_key`, `s_rng_key_once`, `rng_tls_destructor`, `rng_key_init`,
`get_thread_rng`). Duplicating security-sensitive random number management code
is a maintenance trap: a bug found in one copy would not be fixed in the other.
`shim_rng.c` is the single canonical copy.

**Why shim_rng.c is not the same as rand_shim.c:** `rand_shim.c` implements the
OpenSSL `RAND_*` / `RAND_DRBG_*` public API. `shim_rng.c` is an internal
library: it provides `WC_RNG*` pointers and raw byte generation for wolfCrypt
APIs that need a `WC_RNG` argument directly (e.g. `wc_RsaPad_ex`). The two are
separate concerns.

**Design:** Each thread gets its own `WC_RNG` seeded independently from the OS.
`wc_InitRng()` is called once per thread (not per operation), amortizing the
`/dev/urandom` cost. A `pthread_key_t` destructor calls `wc_FreeRng` + `free`
when a thread exits, preventing leaks. `pthread_once` guarantees the TLS key is
created exactly once under concurrent first-callers; after that it is a single
compare-and-branch.

---

## 14. RAND_DRBG hierarchy

**Decision:** The `RAND_DRBG` API is partially implemented. Specific limitations:

**RAND_DRBG_get0_master/public/private return a process-lifetime singleton.**
wolfCrypt has no DRBG hierarchy (no concept of master/public/private DRBGs per
thread). All three functions return the same `wolfshim_RAND_DRBG_st` singleton,
initialized once via `pthread_once` at first call. The singleton is backed by a
real `WC_RNG` seeded from OS entropy, so callers that use it for
`RAND_DRBG_generate()` or `RAND_DRBG_reseed()` get genuine random bytes.
The public/private separation in the OpenSSL hierarchy is absent — all three
draw from the same entropy state. See `../README.md` "Security Limitations"
(project root) for the implications.

NULL is returned only if `wc_InitRng()` fails during the singleton init (OOM or
no OS entropy source), which also prevents all other RNG operations. OpenSSL's
own internal callers in `crypto/rand/rand_lib.c` already NULL-check the return
value; external callers should do the same.

**RAND_DRBG_set_callbacks always fails for non-NULL callbacks.** wolfCrypt
manages entropy internally from OS sources exclusively. Applications cannot
provide custom entropy. `RAND_DRBG_set_callbacks` returns 0 and pushes
`ERR_R_UNSUPPORTED` for any non-NULL callback. Applications requiring custom
entropy sources (hardware RNG, deterministic test vectors) must not use this shim.

**RAND_DRBG type selection fails hard for non-zero NIDs.** `RAND_DRBG_set` and
`RAND_DRBG_set_defaults` return 0 and push `ERR_R_UNSUPPORTED` for any non-zero
type NID. `RAND_DRBG_new` with a non-zero type pushes an error but succeeds —
it still creates a functioning wolfCrypt Hash-DRBG and does not return NULL, so
boilerplate callers that ignore the type are not broken. All DRBGs use
wolfCrypt's Hash-DRBG internally regardless of the requested NID; flags are
stored but have no effect on entropy generation.

**RAND_METHOD and RAND_DRBG_generate are isolated.** A custom `RAND_METHOD`
installed via `RAND_set_rand_method` affects the legacy `RAND_*` symbols but does
NOT affect `RAND_DRBG_generate`, which always uses wolfCrypt's internal `WC_RNG`
directly. An application that overrides `RAND_METHOD` to mock entropy in tests
will not affect the DRBG path.

---

## 15. Per-thread WC_RNG

See §13 for the architectural motivation. The implementation in `shim_rng.c`:

- Uses `pthread_once` + `pthread_key_create` for one-time TLS key setup
- Stores a heap-allocated `WC_RNG*` in the TLS slot, initialized via `wc_InitRng`
  on first access from each thread
- The key destructor calls `wc_FreeRng(rng); free(rng)` when a thread exits
- `shim_get_thread_rng()` returns the raw `WC_RNG*` for APIs like `wc_RsaPad_ex`
  that take a `WC_RNG*` argument
- `shim_rng_generate(buf, len)` wraps `wc_RNG_GenerateBlock` for callers that
  only need random bytes

---

## 16. Global Mont mutex

**File:** `shim/src/bn/bn_shim.c`, `s_wolfshim_mont_lock`

**Decision:** `BN_MONT_CTX_set_locked` uses a global `pthread_mutex_t` rather
than a per-context lock.

**Why:** wolfSSL's `CRYPTO_RWLOCK` type is incompatible with OpenSSL's
`CRYPTO_RWLOCK` type. OpenSSL passes its own `CRYPTO_RWLOCK*` into
`BN_MONT_CTX_set_locked`. The shim cannot use that lock object because the type
layouts differ. A global mutex is the only way to provide mutual exclusion without
depending on the OpenSSL lock's internal layout.

**Consequence:** All RSA operations that require Montgomery context setup (first
use per key) serialize on this one mutex. Under burst load from many threads
simultaneously performing their first RSA operation with a new key, this becomes
a contention point.

See `../README.md` §Path forward (project root).

---

## 17. BN_consttime_swap is not constant-time

**File:** `shim/src/bn/bn_shim.c`

**Decision:** `BN_consttime_swap` is implemented as a branching conditional swap.
It is tagged `WOLFSHIM_GAP[SECURITY:HIGH]`.

**Why not fixed:** wolfSSL does not expose a `wolfSSL_BN_consttime_swap` or
equivalent. The only way to implement constant-time conditional swap on wolfSSL
`BIGNUM` is to access internal struct fields (the limb array and its length),
which is a deeper ABI dependency than any other access in this shim. The risk of
getting that wrong exceeds the risk of leaving the function non-constant-time
with a documented gap.

**Impact:** `BN_consttime_swap` is called by OpenSSL's Montgomery ladder RSA
implementation (`bn_exp.c`) for blinding. A timing side-channel on this function
is exploitable via Kocher-style timing attacks against RSA private operations.

**Remediation:** File a wolfSSL issue requesting `wolfSSL_BN_consttime_swap`.
When that function is available, replace the current implementation with a call
to it and remove the `WOLFSHIM_GAP[SECURITY:HIGH]` tag. Do not attempt to
implement this directly against internal wolfSSL struct fields.

**Customer-facing impact:** See `../README.md` §Security Limitations ("RSA
private-key operations have a timing side-channel") (project root) for the
deployment advisory and interim mitigations. See `shim/RELEASE-NOTES.md` for
the release-level security advisory.

---

## 18. DES ECB as CBC with zero IV

**File:** `shim/src/des/des_modes_bridge.c`

**Decision:** Single-block DES ECB operations are implemented as CBC with a
zero IV: `ECB_k(in) = CBC_k(in ⊕ 0) = CBC_k(in)`.

**Why:** wolfCrypt provides `wc_Des_CbcEncrypt` / `wc_Des_CbcDecrypt` but no
single-block ECB primitive. CBC with a zero IV applied to a single block is
mathematically identical to ECB because the IV XOR cancels:
`E_k(in XOR 0) = E_k(in)`. The equivalence holds only for a single block; do
not extend this to multi-block data (CBC would then chain blocks, ECB would not).

**Scope:** This equivalence is used only in `des_ecb_enc`, `des_ecb_dec`,
`des3_ecb_enc`, and `des3_ecb_dec` in `des_modes_bridge.c`. All other DES mode
operations (CFB64, OFB64, CBC) pass a real IV.

---

## 19. ChaCha20 explicit_bzero

**File:** `shim/src/chacha/chacha_shim.c`

**Decision:** `ChaCha20_ctr32` calls `explicit_bzero(&ctx, sizeof(ctx))` on its
stack-allocated `ChaCha` context before every return, including error returns.

**Why:** The `ChaCha` context contains the full 32-byte key and 12-byte nonce. If
the function returns without zeroing, the key material persists on the stack until
the next function call overwrites it. On a system where an attacker can read stack
memory (via an adjacent buffer overflow, a speculative execution side-channel, or
a debug interface), this extends the window for key extraction.

`explicit_bzero` (as opposed to `memset`) is required here because optimizing
compilers will elide a `memset` of a local variable that is not used after the
wipe. `explicit_bzero` is marked to prevent this optimization.

---

## 20. Poly1305_ctx_size

**File:** `shim/src/chacha/chacha_shim.c`

**Decision:** `Poly1305_ctx_size()` returns `sizeof(wolfCrypt Poly1305)` so
OpenSSL's ChaCha20-Poly1305 AEAD engine allocates enough space.

**Why:** OpenSSL's `e_chacha20_poly1305.c` calls `Poly1305_ctx_size()` at runtime
to determine the heap allocation size for `EVP_CHACHA_AEAD_CTX + Poly1305 context`.
The function is a deliberate seam: by returning the wolfCrypt struct size here,
OpenSSL allocates enough memory for wolfCrypt's `Poly1305` struct, and the
subsequent `Poly1305_Init` / `Poly1305_Update` / `Poly1305_Final` calls can treat
that allocation as a `Poly1305` struct without overflow. If this function returned
the OpenSSL struct size instead, the wolfCrypt struct would write past the end of
the allocation.

---

## 21. The WOLFSHIM_GAP tagging system

Every known behavioral gap in the shim is tagged with a searchable marker:

| Tag | Meaning |
|-----|---------|
| `WOLFSHIM_GAP[SECURITY:HIGH]` | Broken security invariant, no mitigation |
| `WOLFSHIM_GAP[SECURITY:MEDIUM]` | Degraded security property; exploitability depends on usage |
| `WOLFSHIM_GAP[SECURITY:MITIGATED]` | Acknowledged gap with documented mitigation (e.g. WOLFCRYPT_EXCLUDE=1) |
| `WOLFSHIM_GAP[CORRECTNESS]` | Behavioral gap that may produce wrong output |
| `WOLFSHIM_GAP[UNSUPPORTED]` | Feature not implemented; returns ERR_R_DISABLED or 0/NULL with no side-effects |
| `WOLFSHIM_REVIEW [ABI]` | Accesses wolfSSL internal struct fields; must be re-audited on every wolfSSL upgrade |

Run `shim/audit-gaps.sh` to enumerate all tagged sites. Run
`shim/audit-gaps.sh HIGH` to list only the broken invariants. Every
`WOLFSHIM_GAP[SECURITY:*]` and `WOLFSHIM_REVIEW [ABI]` site must be manually
reviewed before shipping a wolfSSL upgrade.

---

## 22. _Static_assert + version guard pattern

**Decision:** Every site that accesses wolfSSL internal struct fields directly
(tagged `WOLFSHIM_REVIEW [ABI]`) is protected by two guards:

1. A `LIBWOLFSSL_VERSION_HEX` compile-time check that fails the build if wolfSSL
   is upgraded past the validated version without re-auditing the site.
2. A `_Static_assert` on the specific field offset that was validated.

**Why both:** The version guard catches an upgrade before any code runs. The
`_Static_assert` catches a struct layout change even within the same wolfSSL
version (e.g. if wolfSSL is rebuilt with different compile flags that change
padding). Together they ensure that a wolfSSL change that breaks a direct struct
access produces a build error rather than silent memory corruption or wrong
ciphertext.

**When upgrading wolfSSL:** Search for `LIBWOLFSSL_VERSION_HEX` in the shim
source. At each site, re-run the offsetof probe (documented in the comment at that
site), update the offset constant if it changed, and raise the version threshold.
Do not raise the threshold without re-running the probe. The threshold is not a
ceiling to bump mechanically — it records the last validated version.

**Highest-volume ABI sites by module** (approximate, as of wolfSSL 5.9.0):

| Module | Sites | What is accessed |
|--------|-------|-----------------|
| `bn_shim.c` | ~1 | `WOLFSSL_BIGNUM.neg` flag only (`BN_mpi2bn`) |
| `ec_shim.c` | ~25 | `WOLFSSL_EC_GROUP.curve_idx`, `.curve_nid`, `.curve_oid`; `WOLFSSL_EC_KEY.priv_key` |
| `rsa_shim.c` | ~6 | RSA key components via struct fields: `->n`, `->e`, `->d`, `->dmp1`, `->dmq1`, `->iqmp` |
| `aes_shim.c` | ~16 | `Aes.reg` (IV), `Aes.left` (streaming mode byte offset) |
| `des_shim.c` | ~4 | DES key schedule: raw 8-byte key at offset 0 of `DES_key_schedule` |
| `pkey_meth_shim.c` | 1 | `EVP_PKEY_METHOD` slot count (must equal 31) |
