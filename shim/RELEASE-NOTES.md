# wolfshim Release Notes

## Security advisory: RSA timing side-channel

> **CRITICAL — read this before deploying in any networked service.**
> **Default build: NOT affected. See build configuration note below.**

This shim's `bn_shim.c` override implements `BN_consttime_swap` as a plain
branching conditional swap.
OpenSSL's RSA Montgomery-ladder calls this function as a blinding step against
Kocher-style timing attacks. The constant-time guarantee is absent, leaving a
measurable timing side-channel on RSA private-key operations (decrypt, sign).

An attacker who can observe many RSA operation timings and drive the operation
repeatedly can exploit this to recover the private key.

**You are affected if all of the following are true:**
- Your service performs RSA private-key operations (RSA decryption, RSA signing).
- Untrusted parties can trigger those operations (e.g. by initiating a TLS
  handshake or submitting data for signing).
- Untrusted parties can observe response latency (local network, same host,
  or sufficiently low-latency remote access).

**Common affected deployments:** HTTPS servers configured with RSA key exchange
(`TLS_RSA_WITH_*` cipher suites), TLS servers using RSA certificates for
authentication when the client observes handshake timing, any signing service
where the caller can submit arbitrary inputs and measure response time.

**Not affected:** offline RSA signing on an air-gapped host, RSA key generation
(keygen does not use `BN_consttime_swap`), ECDSA/ECDH operations (unrelated
code path), deployments where RSA cipher suites are disabled and only ECDHE is
offered.

**This cannot be fixed within the OpenSSL 1.1.1 + wolfCrypt architecture.**
See `../README.md` §Path forward (project root) for the remediation path and
`ARCHITECTURE.md` §17 for technical detail and interim mitigations.

---

> **Build configuration note:** `shim/src/bn/bn_shim.c` — the file that
> contains the branching `BN_consttime_swap` — is **not compiled into the
> default build**.
>
> In the default build, `BN_consttime_swap` is provided by **OpenSSL's own
> `openssl/crypto/bn/bn_lib.c`**, which is not excluded by `WOLFCRYPT_EXCLUDE`
> and contains a proper constant-time XOR-masking implementation (no branch on
> `condition`). wolfSSL's compat layer does not define `BN_consttime_swap` at
> all; the OpenSSL symbol is the only definition present at link time.
>
> **Default build: the RSA timing side-channel described above is NOT present.**
> The advisory applies only if `libwolfshim_bn.a` is linked in to override the
> OpenSSL BN layer. See the full build note below.

---

## Compatibility gap: RAND_DRBG_get0_master / get0_public / get0_private

These three functions have two differences from standard OpenSSL that require
an audit of any application code calling them directly.

**All three return the same singleton.** wolfCrypt has no DRBG hierarchy.
`RAND_DRBG_get0_master()`, `RAND_DRBG_get0_public()`, and
`RAND_DRBG_get0_private()` all return the same `wolfshim_RAND_DRBG_st`
singleton. The master/public/private distinction is structural only; all three
draw from the same entropy state. This is also covered in the RAND_priv_bytes
security limitation — see `../README.md` §Security Limitations (project root).

**Can return NULL.** Standard OpenSSL guarantees these functions return non-NULL
after library initialisation. This shim returns NULL if `wc_InitRng()` fails at
singleton init (out-of-memory or no OS entropy source). Application code written
against the OpenSSL guarantee will crash with a NULL dereference if that
condition occurs.

OpenSSL's own retained callers — `drbg_bytes` and `drbg_add` in
`crypto/rand/drbg_lib.c`, `RAND_poll` and `RAND_priv_bytes` in
`crypto/rand/rand_lib.c` — all NULL-check. The risk is in application code.

**Required audit:** grep your application for `RAND_DRBG_get0_` and confirm
every call site handles a NULL return:

```c
RAND_DRBG *drbg = RAND_DRBG_get0_public();
if (drbg == NULL) { /* handle RNG init failure */ }
```

See `../README.md` §Known Limitations (project root) and `ARCHITECTURE.md` §14
for detail.

---

## Security gap: RAND_priv_bytes does not use a separate private pool

OpenSSL's `RAND_priv_bytes` is specified to draw from a dedicated per-thread
private DRBG, separate from the public DRBG used by `RAND_bytes`. The separation
ensures that compromise of public nonces (e.g. via a nonce-reuse attack or
observable RNG output) does not reveal private key material.

This shim has no separate private pool. `RAND_priv_bytes` dispatches through
the same wolfCrypt `WC_RNG` as `RAND_bytes`. There are two consequences:

1. **No pool separation.** Private key material and public nonces draw from the
   same entropy state. A side-channel that reveals public RNG output also reveals
   what private key operations received.

2. **RAND_METHOD override uses `bytes` for both public and private randomness.**
   If a `RAND_METHOD` override is installed via `RAND_set_rand_method()`,
   `RAND_priv_bytes` dispatches to `override->bytes` — the same function as
   `RAND_bytes`. OpenSSL 1.1.1's `RAND_METHOD` struct has no `private_bytes`
   field; there is no hook for a custom method to supply separate private-pool
   generation. The caller has no indication that pool separation was not applied.

**Impact:** Deployments that rely on `RAND_priv_bytes` for private key generation
or signing nonces do not get the isolation OpenSSL's API implies. This is a
weakened guarantee, not an outright failure — wolfCrypt's `WC_RNG` is a seeded
Hash-DRBG and produces cryptographically strong output. The concern is the absent
*separation* between public and private use.

**Tagged:** `WOLFSHIM_GAP[SECURITY:MEDIUM]` in `shim/src/rand/rand_shim.c`.
See `ARCHITECTURE.md` §15 and `../README.md` §Security Limitations (project root).

---

## Security gap: BN_CTX_secure_new does not provide secure erasure

`BN_CTX_secure_new()` in OpenSSL allocates a BN context from a heap segment that
is guaranteed to be zeroed on free, specifically to clear private key material
(RSA/ECDSA/DH private exponents) from memory before the allocation is returned
to the OS. This shim delegates to `wolfSSL_BN_CTX_new()`, which provides no such
zeroing-on-free guarantee.

**Impact:** Code that calls `BN_CTX_secure_new()` and then uses the context for
private-key operations (RSA decrypt/sign, ECDSA sign, DH exponentiation) will
not get the secure-erasure behaviour it expects. Private-key material may remain
in heap memory after the context is freed, where it can be recovered by a
subsequent allocation, a heap dump, or a memory-scraping side-channel.

**Workaround:** Confirm whether your wolfSSL build is compiled with
`WOLFSSL_HEAP_HINT` and `ForceZero`-on-free semantics. If not, treat all BN
contexts from this shim as non-secure and ensure private key material is cleared
by other means (e.g. explicit `wolfSSL_BN_clear` calls on sensitive BIGNUMs).

See `ARCHITECTURE.md` for tagging: `WOLFSHIM_GAP[SECURITY:MEDIUM]` in
`shim/src/bn/bn_shim.c`.

---

## Known limitation: BN_CTX_end is a no-op — temporary BIGNUMs are not freed

OpenSSL's `BN_CTX_start` / `BN_CTX_get` / `BN_CTX_end` pattern is used to
manage the lifetime of temporary BIGNUMs: `BN_CTX_start` opens a scope,
`BN_CTX_get` allocates temporaries from the context pool, and `BN_CTX_end`
returns all temporaries from that scope to the pool.

wolfSSL's `BN_CTX` does not implement scope tracking. `BN_CTX_end` is a no-op
in this shim. Any temporary BIGNUMs allocated via `BN_CTX_get` after a
`BN_CTX_start` are not returned to the pool when `BN_CTX_end` is called; they
accumulate for the lifetime of the `BN_CTX` object.

**Impact:** Code that uses this pattern in a loop will grow the `BN_CTX`
unboundedly. OpenSSL's own internal RSA and EC code uses this pattern; the
leaking BIGNUMs may contain intermediate private-key values.

**Scope:** This affects application code that calls `BN_CTX_start` /
`BN_CTX_end` directly. The OpenSSL test suite passes because the affected paths
do not exercise the leak in a way that causes test failures; the leak is silent.

---

## Known limitation: AES_KEY key-material leak

Applications using `AES_set_encrypt_key` or `AES_set_decrypt_key` with
stack-allocated `AES_KEY` objects will leak one wolfCrypt `Aes` context
(~1–1.3 KB of heap-allocated key material) per call unless `OPENSSL_cleanse`
is called before the key goes out of scope.

This is a structural consequence of the OpenSSL 1.1.1 ABI: the `AES_KEY` struct
is too small to hold wolfCrypt's expanded key schedule, so the shim allocates on
the heap, and there is no `AES_KEY_free()` to call. The shim intercepts
`OPENSSL_cleanse()` to free the allocation — callers that do not call it will
leak.

**Scale:** Each leaked `Aes` struct is ~1292 bytes of heap-allocated key
material. At TLS server scale (1000 new connections/sec, two key-setup calls per
handshake), this is approximately **1 MB/s of key-material-containing heap
leaks**. On Linux the freed `malloc` blocks are returned to glibc's free list and
may be reused for unrelated allocations, effectively making live key schedules
visible across the heap. This is a memory-safety concern in addition to a
resource-exhaustion concern.

**FIPS deployments:** If you are operating under FIPS zeroization requirements,
the leaked key schedules may be irrecoverable for secure erasure. Mitigations:

- **(a)** Call `AES_set_encrypt_key` only for long-lived keys, not per-record.
- **(b)** Use `EVP_CIPHER_CTX` paths instead — `EVP_CIPHER_CTX_free()` calls
  `OPENSSL_cleanse` internally and will free the wolfCrypt context.
- **(c)** For callers that cannot switch to EVP, call `OPENSSL_cleanse(&key,
  sizeof(key))` explicitly before the `AES_KEY` goes out of scope (see pattern
  below).

**Callers that are safe without changes:**
- Code using `EVP_CIPHER_CTX` — `EVP_CIPHER_CTX_free()` calls `OPENSSL_cleanse`
  internally.
- Code that reinitialises the same `AES_KEY` via another `AES_set_*_key` call —
  the previous allocation is freed before the new one is made.

**wolfshim extension — preferred mitigation for new code:** use
`AES_KEY_new()` / `AES_KEY_free()` (declared in `aes_shim.h`) to manage
`AES_KEY` lifetime explicitly:

```c
AES_KEY *key = AES_KEY_new();
AES_set_encrypt_key(raw, 128, key);
/* ... use key ... */
AES_KEY_free(key);   /* frees inner wolfCrypt context + outer struct */
```

See §"wolfshim extensions" below for compile-time guards and details.

**Callers that must add `OPENSSL_cleanse` (existing code):** any code that
declares a stack-allocated `AES_KEY` and returns or abandons it without one of
the above.  The pattern is:

```c
AES_KEY key;
AES_set_encrypt_key(raw, 128, &key);
/* ... use key ... */
OPENSSL_cleanse(&key, sizeof(key));   /* frees the wolfCrypt heap context */
```

**Valgrind:** the leak appears as `malloc ← aes_ctx_alloc ← AES_set_encrypt_key`.
A suppression is provided in `shim/wolfshim.supp`:

```
valgrind --suppressions=shim/wolfshim.supp --leak-check=full ./binary
```

**Performance note:** Because wolfCrypt's `Aes` struct (~1.1 KB) is larger than
OpenSSL's `AES_KEY` (244 bytes), every `AES_set_encrypt_key` /
`AES_set_decrypt_key` call performs a `malloc`. In stock OpenSSL the key
schedule is stored inline and there is no allocator hit. In a TLS server where
key setup occurs at least twice per handshake (client-write and server-write
keys), this adds two `malloc`/`free` pairs per connection that stock OpenSSL
does not pay. At 10,000 TLS connections/sec that is 20,000 extra allocator
operations per second. Profile before deploying in throughput-critical
environments.

See `../README.md` §Known Limitations ("AES_KEY memory") and `aes_ctx.h`
(project root) for full detail including FIPS zeroization implications.

---

## Known limitation: SHA_CTX / SHA256_CTX / SHA512_CTX key-material leak

Applications using stack-allocated `SHA_CTX`, `SHA256_CTX`, or `SHA512_CTX`
objects will leak one wolfSSL digest context per object per first-use unless
`OPENSSL_cleanse` is called before the context goes out of scope.

The cause is identical to the `AES_KEY` leak above: wolfSSL's SHA context
structs are larger than OpenSSL's equivalents (e.g. `WOLFSSL_SHA512_CTX` ≥288 B
vs OpenSSL's `SHA512_CTX` 216 B), so the shim heap-allocates a wolfSSL context
and stores only a pointer in the caller's buffer. There is no `SHA_CTX_free()`
in the OpenSSL 1.1.1 ABI. The shim intercepts `OPENSSL_cleanse()` to free the
allocation; stack-allocated contexts that go out of scope without it leak.

**Scale:** Each leaked wolfSSL SHA context is ~112–288 bytes depending on
variant. SHA contexts are used on every TLS record (handshake transcript hash,
record MAC). A TLS server handling 1,000 connections/sec with ~10 record-hash
operations per handshake leaks approximately **1–3 MB/s** of heap-allocated
digest state. The allocations contain intermediate hash state that may include
partial plaintext or key-derivation inputs.

**Reuse mitigates the leak on the hot path:** the shim keeps the heap allocation
alive after `SHA*_Final()` and reuses it on the next `SHA*_Init()` without a
`malloc`. The leak only materialises when the `SHA_CTX` itself is abandoned
(goes out of scope or is overwritten) without a preceding `OPENSSL_cleanse`.

**Mitigations:**

- **(a)** Use `EVP_MD_CTX` paths — `EVP_MD_CTX_free()` / `EVP_MD_CTX_reset()`
  call `OPENSSL_cleanse` internally.
- **(b) wolfshim extension — preferred mitigation for new code:** use
  `SHA_CTX_new()` / `SHA_CTX_free()` (and the `SHA256` / `SHA512` variants)
  declared in `sha_shim.h`:

  ```c
  SHA256_CTX *ctx = SHA256_CTX_new();
  SHA256_Init(ctx);
  /* ... */
  SHA256_Final(digest, ctx);
  SHA256_CTX_free(ctx);   /* frees inner wolfSSL context + outer struct */
  ```

  See §"wolfshim extensions" below for compile-time guards and details.

- **(c)** For callers that cannot switch to EVP or adopt the extension, call
  `OPENSSL_cleanse` before abandoning the context:

```c
SHA256_CTX ctx;
SHA256_Init(&ctx);
/* ... */
SHA256_Final(digest, &ctx);
OPENSSL_cleanse(&ctx, sizeof(ctx));   /* frees the wolfSSL heap context */
```

**Valgrind:** leaks appear as `malloc ← sha*_ctx_alloc ← SHA*_Init`.
A suppression is provided in `shim/wolfshim.supp`.

---

## wolfshim extensions: AES_KEY_new / AES_KEY_free / SHA_CTX_new / SHA_CTX_free (and SHA256 / SHA512)

The leak problems described in the two preceding sections both stem from the same
root cause: OpenSSL 1.1.1 has no `_free` function for `AES_KEY` or `SHA_CTX`
because its native implementations store all state inline and have nothing to
free.  wolfshim must heap-allocate behind these structs, making a `_free` call
necessary — but the OpenSSL 1.1.1 API does not provide one.

These extensions add the missing half of the lifecycle:

| Function | Type | Notes |
|----------|------|-------|
| `AES_KEY_new()` | wolfshim extension | allocates + zeros a heap `AES_KEY` |
| `AES_KEY_free(key)` | wolfshim extension | frees inner wolfCrypt `Aes` + outer struct |
| `SHA_CTX_new()` | wolfshim extension | allocates + zeros a heap `SHA_CTX` (SHA-1) |
| `SHA_CTX_free(ctx)` | wolfshim extension | frees inner wolfSSL SHA-1 context + outer struct |
| `SHA256_CTX_new()` | wolfshim extension | allocates + zeros a heap `SHA256_CTX` (SHA-224/256) |
| `SHA256_CTX_free(ctx)` | wolfshim extension | frees inner wolfSSL SHA-224/256 context + outer struct |
| `SHA512_CTX_new()` | wolfshim extension | allocates + zeros a heap `SHA512_CTX` (SHA-384/512) |
| `SHA512_CTX_free(ctx)` | wolfshim extension | frees inner wolfSSL SHA-384/512 context + outer struct |

**Why these were not in OpenSSL 1.1.1:** OpenSSL's native `AES_KEY` stores the
key schedule inline in 244 bytes; `SHA_CTX` stores hash state inline in 96 bytes.
When there is no heap allocation, there is nothing to free.  The absence of a
`_free` function is not an oversight — it is a consequence of the inline-storage
design.  OpenSSL 3 resolved this for all context types by moving to an opaque
provider API where every context type has a `_new` / `_free` pair.  wolfshim
back-fills the missing half for OpenSSL 1.1.1 callers who cannot yet port to
OpenSSL 3.

**Migration path without porting to OpenSSL 3:** Replace stack allocation with
`_new` / `_free`:

```c
/* AES — before (leaks if OPENSSL_cleanse is omitted) */
AES_KEY key;
AES_set_encrypt_key(raw, 128, &key);
AES_ecb_encrypt(in, out, &key, AES_ENCRYPT);
OPENSSL_cleanse(&key, sizeof(key));   /* required with wolfshim, easy to miss */

/* AES — after (no leak, familiar lifetime model) */
AES_KEY *key = AES_KEY_new();
AES_set_encrypt_key(raw, 128, key);
AES_ecb_encrypt(in, out, key, AES_ENCRYPT);
AES_KEY_free(key);
```

```c
/* SHA-256 — before */
SHA256_CTX ctx;
SHA256_Init(&ctx);
SHA256_Update(&ctx, data, len);
SHA256_Final(digest, &ctx);
OPENSSL_cleanse(&ctx, sizeof(ctx));   /* required with wolfshim */

/* SHA-256 — after */
SHA256_CTX *ctx = SHA256_CTX_new();
SHA256_Init(ctx);
SHA256_Update(ctx, data, len);
SHA256_Final(digest, ctx);
SHA256_CTX_free(ctx);
```

**Building against both wolfshim and stock OpenSSL 1.1.1:** Guard on the
compile-time feature macros that wolfshim defines:

```c
#ifdef WOLFSHIM_HAS_AES_KEY_FREE
    AES_KEY_free(key);
#else
    OPENSSL_cleanse(key, sizeof(*key));
    /* (stock OpenSSL: no heap allocation, OPENSSL_cleanse is still good practice) */
#endif
```

```c
#ifdef WOLFSHIM_HAS_SHA_CTX_FREE
    SHA256_CTX_free(ctx);
#else
    OPENSSL_cleanse(ctx, sizeof(*ctx));
#endif
```

The macros `WOLFSHIM_HAS_AES_KEY_FREE` and `WOLFSHIM_HAS_SHA_CTX_FREE` are
defined in `shim/include/aes_shim.h` and `shim/include/sha_shim.h` respectively.

**Declaration headers:**
- `#include "aes_shim.h"` — declares `AES_KEY_new` / `AES_KEY_free`
- `#include "sha_shim.h"` — declares all six SHA extension functions

These headers are wolfshim-specific and are not present in stock OpenSSL.

**Note on `_free` and stack-allocated contexts:** `AES_KEY_free` and
`SHA*_CTX_free` call `free()` on the outer struct, so they must only be used
with heap-allocated contexts (i.e., those returned by the corresponding `_new`).
Calling them on a stack-allocated context is undefined behaviour.  For
stack-allocated contexts, continue to use `OPENSSL_cleanse`.

See `ARCHITECTURE.md` §1 and §2 for the full technical detail.

---

## Behaviour change: OPENSSL_cleanse frees heap in addition to zeroing

In stock OpenSSL, `OPENSSL_cleanse(ptr, len)` is a secure memset — it zeroes
`len` bytes at `ptr` and returns. Nothing is freed.

In this shim, `OPENSSL_cleanse` additionally checks whether `ptr` contains a
wolfshim sentinel (indicating a heap-allocated wolfCrypt context stored inside
an `AES_KEY` or `SHA_CTX` buffer) and, if so, **frees that heap allocation
before zeroing the buffer**.

**This is a breaking semantic change for any code that:**

1. Calls `OPENSSL_cleanse` on a buffer that holds a wolfshim context, then
2. Reuses that buffer without reinitialising it via `AES_set_encrypt_key` /
   `SHA*_Init`.

After step 1 the stored pointer is freed. Step 2 will dereference the freed
pointer, producing a use-after-free.

The pattern is uncommon in well-written code — `OPENSSL_cleanse` signals "I am
done with this object" — but it can appear in object-pool implementations that
cleanse and return contexts to a pool for reuse without re-init.

**Required audit:** grep your codebase for `OPENSSL_cleanse` calls on
`AES_KEY` or `SHA*_CTX` objects and confirm each one is a final wipe before
abandonment, not a mid-life reset followed by reuse.

---

## Performance note: RSA first-use serialization (BN_MONT_CTX global mutex)

The override BN shim (`shim/src/bn/bn_shim.c`, not in the default build)
serializes all concurrent RSA Montgomery-precomputation first-uses on a single
global `pthread_mutex_t` (`s_wolfshim_mont_lock`).

The critical section is short — one Montgomery precomputation per key, after
which the fast path (`*pmont != NULL`) is taken without a lock. Under normal
steady-state operation this is not a bottleneck.

**When this matters:** a burst of new connections against many *different* RSA
keys simultaneously (e.g. a TLS server doing client-certificate authentication
against a large fleet, where each client presents a distinct certificate). In
that pattern all threads serialise on this mutex until each key has been seen
once.

The correct remediation is migration to OpenSSL 3 + wolfProvider, where
wolfCrypt's thread-safe Montgomery precomputation is used directly without a
shim-level lock. Adding per-key locking or a CAS scheme within this shim would
add significant complexity for code that must stay compatible with the OpenSSL
1.1.1 ABI. See `ARCHITECTURE.md` §16 and `../README.md` §Path forward
(project root).

---

## Build note: EC, BN, and RSA symbols come from wolfSSL's compat layer by default

`shim/src/ec/ec_shim.c`, `shim/src/bn/bn_shim.c`, and `shim/src/rsa/rsa_shim.c`
exist as alternative override implementations but are **not compiled into
`libwolfshim.a`** in the default build. They build as separate static libraries
(`libwolfshim_ec.a`, `libwolfshim_bn.a`, `libwolfshim_rsa.a`) that are not
wired into the main link.

In the default shipping configuration, `EC_*`, `BN_*`, and `RSA_*` public symbols
are provided by wolfSSL's own OpenSSL compatibility layer (`libwolfssl`, built
with `OPENSSL_EXTRA`). The shim override files are available for cases where
wolfSSL's built-in compat layer is insufficient, but they carry their own gap
tags (including `WOLFSHIM_GAP[SECURITY:HIGH]` for `BN_consttime_swap`) and are
not validated by the OpenSSL test suite run described below.

If you are using the default build: the `BN_consttime_swap` RSA timing advisory
above applies to wolfSSL's own `BN_consttime_swap` implementation in that case —
verify the behaviour of the wolfSSL version you are deploying.

---

## Test coverage

### OpenSSL test suite

The shim is validated by running OpenSSL 1.1.1's own test suite (`make test`)
against a linked binary that replaces the default crypto primitives with the
shim. This exercises the full OpenSSL protocol and API surface — TLS handshakes,
certificate parsing, cipher-suite negotiation — with wolfCrypt as the back-end.
Passing this suite is the primary correctness signal for the AES, SHA, DES,
ChaCha20, HMAC, and random number paths.

To run it:

```
make -C openssl test TESTS='-exclude fuzz'
```

Expected result: all tests pass. Any failure is a regression.

### Wycheproof

The shim is also tested against
[Wycheproof](https://github.com/google/wycheproof) test vectors using the
`wychcheck` harness in `shim/wychcheck_builds/`. Wycheproof covers edge cases
and known-bad inputs that the OpenSSL test suite does not — weak keys, invalid
encodings, small-subgroup attacks, signature malleability.

Results below were produced against **wolfSSL 5.9.0** on x86_64 Linux.

#### Passing suites (vectors executed)

| Algorithm | Suites | Vectors |
|-----------|--------|---------|
| AES-CBC (PKCS5 padding) | 1 | 216 |
| AES-GCM | 1 | 316 |
| ECDH P-256 / P-384 / P-521 | 3 | 2575 |
| ECDSA P-224 / P-256 / P-384 / P-521 (DER + P1363, multiple hashes) | 24 | ~11 000 |
| HKDF SHA-1 / SHA-256 / SHA-384 / SHA-512 | 4 | 339 |
| HMAC SHA-224 / SHA-256 / SHA-384 / SHA-512 / SHA3-224 / SHA3-256 / SHA3-384 / SHA3-512 | 8 | 1388 |
| RSA-PSS 2048 / 3072 / 4096 (multiple salt/hash variants) | 10 | ~1200 |

Suites not listed above either have no compiled runner in the harness or test
algorithms not enabled in this wolfSSL build (brainpool curves, ARIA, XDH
non-P256, etc.) and are skipped in their entirety.

#### Known failures

| Algorithm | Affected vectors | Error | Notes |
|-----------|-----------------|-------|-------|
| ChaCha20-Poly1305 | tcId=2, tcId=3 (2 of 325) | `BAD_FUNC_ARG` (-173) | Two edge-case decrypt vectors. The remaining 323 pass. |
| RSA PKCS1v1.5 verify | tcId=1 in every suite (1 per suite, 22 total) | `BAD_FUNC_ARG` (-173) | Systematic single-vector failure across all key sizes and hash variants. All other vectors in each suite pass. |

These failures are present in wolfSSL 5.9.0 and are tracked as known gaps. They
do not affect any TLS cipher suite or certificate operation used in production.

#### Re-running

The test harness is `test/wychcheck_gitref_test.sh` in the project root.
It requires a local clone of the `wychcheck` repository pointed to via the
`WYCHCHECK_REPO` environment variable:

```sh
git clone https://github.com/wolfSSL/wychcheck.git /tmp/wychcheck
WYCHCHECK_REPO=/tmp/wychcheck ./test/wychcheck_gitref_test.sh HEAD
```

The `shim/wychcheck_builds/` directory is the default output location for
build artifacts and result logs; it is excluded from version control via
`.gitignore`.
