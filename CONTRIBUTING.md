# Contributing to wolfCrypt/OpenSSL Shim

## Code Annotation Conventions

Three tags are used throughout the shim source to mark non-obvious decisions.
They are searchable (`grep -r WOLFSHIM_GAP shim/src/`) and each carries
a specific contract.

---

### `WOLFSHIM_GAP[<category>]`

Three severity categories are used:

```c
/* WOLFSHIM_GAP[UNSUPPORTED]: wolfCrypt has no equivalent for this operation.
 * <one sentence on what the caller loses and what they should do instead> */

/* WOLFSHIM_GAP[CORRECTNESS]: behavioural difference that may produce wrong output.
 * <explanation> */

/* WOLFSHIM_GAP[SECURITY]: behavioural gap with a security implication.
 * <explanation of the risk> */
```

**Meaning:** The OpenSSL API is present and links cleanly, but the underlying
behaviour is intentionally reduced or absent because wolfCrypt does not expose
an equivalent primitive.

**Contract:**
- The function must not crash or produce undefined behaviour **unless** it
  is a `void` function that would silently produce incorrect output bytes.
- If it returns a value, that value must be a documented failure sentinel
  (`NULL`, `0`, `-1`) — never a silently wrong success.
- If it is `void` and produces output bytes (e.g. `AES_ecb_encrypt` decrypt),
  it **must call `abort()`** after writing to `stderr` via `WOLFSHIM_FATAL`.
  Silently zeroing output is a confidentiality failure: the caller cannot
  detect the error and will treat the zero bytes as valid ciphertext or
  plaintext.  The `abort()` makes the gap immediately visible during
  development or integration testing.
- The gap must be listed in the **Known Gaps** table in `README.md`.
- If the gap is security-relevant (entropy source, constant-time guarantee,
  etc.), use `WOLFSHIM_GAP[SECURITY]` and mark it in the README Known Gaps
  table.

**When to add:** When you stub a function because wolfSSL provides no
equivalent and there is no reasonable work-around within the shim.

---

### `WOLFSHIM_REVIEW`

```c
/*
 * WOLFSHIM_REVIEW [CATEGORY]: <description of what needs expert validation>
 *
 * <Why it was done this way, what could go wrong, what a reviewer should
 * check, and what wolfSSL version / commit this was validated against.>
 */
```

**Meaning:** The code is functional and has passed basic tests, but it touches
an area where correctness is hard to verify without domain expertise or access
to the wolfSSL internals.  A reviewer should actively check this before a
production deployment.

Common categories:
- `[SECURITY]` — touches key material, padding, side-channel behaviour
- `[ABI]` — directly accesses internal wolfSSL struct fields
- `[THREAD SAFETY]` — involves shared state or locking

**Contract:**
- Code marked `WOLFSHIM_REVIEW` must pass the existing test suite.
- It must include the wolfSSL version it was validated against.
- When a new wolfSSL version is adopted, all `WOLFSHIM_REVIEW [ABI]` sites
  must be re-audited before the first release against that version.

**When to add:** When you access internal wolfSSL struct fields directly,
implement a non-trivial crypto algorithm by hand (e.g. IGE mode), or choose
a behaviour that may surprise a security reviewer.

---

### Interaction between tags

A function may carry both tags on different aspects:

```c
void AES_ige_encrypt(...)
{
#ifdef WOLFSSL_AES_DIRECT
    {
        /*
         * WOLFSHIM_REVIEW [ABI]: copies Aes struct to avoid mutating the
         * caller's key state.  Validated against wolfSSL 5.9.0 struct layout.
         */
        Aes aes_local;
        XMEMCPY(&aes_local, aes_ptr, sizeof(Aes));
        ...
    }
#else
    /* WOLFSHIM_GAP[UNSUPPORTED]: WOLFSSL_AES_DIRECT not enabled; IGE unavailable.
     * abort() rather than silently produce zero ciphertext. */
    WOLFSHIM_FATAL("AES_ige_encrypt requires WOLFSSL_AES_DIRECT");
#endif
}
```

---

## Thread Safety Policy

The shim targets server deployments where correctness matters more than
throughput.  The policy is: **use `pthread_mutex_t` for infrequently-written
global state; use per-thread resources (e.g. per-thread RNG) for hot paths
where mutex serialisation would be unacceptable**.  Applications that find
this too slow should migrate to OpenSSL 3.x.

Shared mutable state that is protected:
- `s_rand_method_override` and RAND globals — `s_wolfshim_rand_globals_lock`
  in `rand_shim.c`
- `BN_MONT_CTX_set_locked` — `s_wolfshim_mont_lock` in `bn_shim.c`
- RSA/pkey per-thread RNG — `shim_rng.c` uses `pthread_key_t` +
  `pthread_once_t`; no mutex on the generation path — see
  `shim/src/rng/shim_rng.c`

When adding new global mutable state, add a `pthread_mutex_t` at the same
scope with `PTHREAD_MUTEX_INITIALIZER`.  Where the state is accessed on a hot
path (e.g. per-request crypto operations), consider per-thread resources
instead.  Do not use `pthread_rwlock_t` unless you have a measured
read-heavy workload to justify it.

---

## Wolfssl Version Guards

Any code that directly accesses internal wolfSSL struct fields (e.g.
`aes->reg`, `aes->left`, `ec_key->group->curve_idx`) must be guarded:

```c
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05009000
#  error "This file accesses wolfSSL internals validated against 5.9.0 — " \
         "re-audit all WOLFSHIM_REVIEW [ABI] sites before lowering this threshold"
#endif
```

When adopting a new wolfSSL version, follow this checklist **in order**:

### wolfSSL upgrade checklist

1. **Run the offset probe.**  Compile and run the probe fragment in
   `tools/struct_probe.c` (or write an equivalent) to get the current
   `sizeof` and `offsetof` values for:
   - `Aes` (fields: `reg`, `left`)
   - `WOLFSSL_EC_GROUP` (fields: `curve_idx`, `curve_nid`, `curve_oid`)
   - `WOLFSSL_EC_KEY` (field: `priv_key`)
   - `WOLFSSL_BIGNUM` (field: `neg`)

2. **Update `_Static_assert` constants.**  In `aes_shim.c`, `ec_shim.c`, and
   `bn_shim.c`, update every `_Static_assert` with the new measured values.
   A build failure here is the sign you need to do this step — do not silence
   the assertion; fix the value or re-audit the access.

3. **Audit `WOLFSHIM_REVIEW [ABI]` sites.**  Run:
   ```
   grep -rn 'WOLFSHIM_REVIEW \[ABI\]' shim/src/
   ```
   For each hit, verify the surrounding code is correct against the new
   wolfSSL struct layout.  Pay special attention to field accesses that
   are NOT covered by a `_Static_assert` (e.g. pointer member reads).

4. **Update version guards.**  In each file with a
   `LIBWOLFSSL_VERSION_HEX < 0x0...` guard, raise the minimum version to
   the new wolfSSL release.

5. **Run the full test suite.**
   ```
   ./test.sh
   ```
   Verify that EVP, TLS, NIST KAT, and Wycheproof pass counts do not
   decrease from the previous baseline.

6. **Update `DEV_HISTORY.md`** with a one-line entry recording the new
   wolfSSL version, the date, and any struct layout changes found.

---

## Adding a New Shim Function

1. Find the OpenSSL 1.1.1 signature in `openssl/include/openssl/`.
2. Find the closest wolfSSL equivalent in `wolfssl/wolfssl/openssl/` or
   `wolfssl/wolfssl/wolfcrypt/`.
3. Implement the function in the appropriate `shim/src/<subsystem>/` file.
4. If wolfSSL provides a direct equivalent, add an entry to
   `shim/src/aliases/aliases.c` following the existing pattern.
5. If the function requires hand-rolled logic, mark it `WOLFSHIM_REVIEW [<category>]`.
6. If wolfSSL has no equivalent, mark it `WOLFSHIM_GAP[<category>]` where
   category is `UNSUPPORTED`, `CORRECTNESS`, or `SECURITY`.
   - If the function returns a value: return a failure sentinel and push
     `ERR_put_error`.
   - If the function is `void` and writes output bytes: use `WOLFSHIM_FATAL(msg)`
     — do NOT zero the output silently.
   - Add the gap to the Known Gaps table in `README.md`.
7. Run `./test.sh` and verify the test count does not decrease.
